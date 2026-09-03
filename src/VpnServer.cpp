//  ──────────────────────────────────────────────────────────────────────────────
//  VpnServer.cpp  (TrueTunnel, multi-client, framed packets)
//  FULL SOURCE — no omissions
//  ──────────────────────────────────────────────────────────────────────────────

#include <array>


// ——— System / library ——————————————————————————————————————————
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <iphlpapi.h>

#include "secure/SecureSocket.h"
#include "secure/SharedSecret.h"

#include <string>
#include <memory>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <atomic>
#include <chrono>
#include <exception>
#include <iostream>
#include <cstring>
#include <limits>
#include <span>
#include <stdexcept>
#include <utility>
#include <system_error>

// ——— Project headers ——————————————————————————————————————————
#include "VpnServer.h"
#include "IpPoolManager.h"
#include "utils.hpp"
#include "vpn.hpp"
#include "Networking.h"


// ——— Pragmas ————————————————————————————————————————————————
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace {
std::string peer_source_from_addr(const sockaddr_storage& addr, int len);
}

// ───────────────────────────────────────────────────────────────────────────────
//  ctor / dtor
// ───────────────────────────────────────────────────────────────────────────────
VpnServer::VpnServer(int                port,
                     const std::string& real_adapter,
                     const std::string& password,
                     const std::string& adaptername,
                     secure::CipherSuite,
                     TransportProtocol transport,
                     secure::TrafficKeyRotationPolicy rotation_policy,
                     const std::uint64_t expected_real_adapter_luid)
    : port_{port},
      real_adapter_{real_adapter},
      password_{password},
      adaptername_{adaptername},
      cipher_suite_{secure::CipherSuite::Aes256Gcm},
      transport_{transport},
      rotation_policy_{rotation_policy},
      expected_real_adapter_luid_{expected_real_adapter_luid},
      listen_sock_{INVALID_SOCKET},
      running_{false}
{
    if (port_ <= 0 || port_ > 65'535) {
        throw std::invalid_argument("VPN server port is out of range");
    }
    secure::require_valid_shared_secret(password_);
}

VpnServer::~VpnServer() { stop(); }

// ───────────────────────────────────────────────────────────────────────────────
//  public API
// ───────────────────────────────────────────────────────────────────────────────
void VpnServer::start()
{
    std::unique_lock<std::mutex> lifecycle_guard(lifecycle_mutex_);
    if (start_called_) return;
    start_called_ = true;
    if (stop_requested_.load(std::memory_order_acquire)) return;
    running_ = true;

    std::cout << "[INFO] Starting VPN server on port " << port_
              << " using " << to_string(transport_) << "\n";

    try {
        LoadWintun();
        setupServer();
    } catch (...) {
        // Release the lifecycle lock before using the normal, complete
        // teardown path. This rolls back partially-created adapters, routes,
        // listeners, firewall state, events, and threads.
        lifecycle_guard.unlock();
        stop();
        throw;
    }
}

void VpnServer::stop()
{
    stop_requested_.store(true, std::memory_order_release);
    running_.store(false, std::memory_order_release);
    std::lock_guard<std::mutex> lifecycle_guard(lifecycle_mutex_);
    std::cout << "[INFO] Stopping VPN server; notifying clients\n";
    running_ = false;

    const auto close_authenticated_clients = [this]() {
        std::vector<std::shared_ptr<secure::SecureSocket>> clients;
        {
            std::shared_lock<std::shared_mutex> lock(client_map_mutex_);
            clients.reserve(client_map_.size());
            for (const auto& [_, entry] : client_map_) {
                if (entry.tls) clients.push_back(entry.tls);
            }
        }
        // close() waits for active I/O to quiesce. Never hold
        // client_map_mutex_ here: receive and failure paths need it while they
        // unwind.
        for (const auto& tls : clients) {
            tls->close();
        }
    };
    close_authenticated_clients();

    // Authenticated clients live in client_map_. A TCP peer can also be blocked
    // inside the TLS handshake or configuration exchange, so keep those sockets
    // separately reachable and interrupt them during shutdown as well.
    std::vector<std::shared_ptr<secure::SecureSocket>> pending_tcp_clients;
    {
        std::lock_guard<std::mutex> lock(pending_tcp_clients_mutex_);
        pending_tcp_clients.assign(pending_tcp_clients_.begin(),
                                   pending_tcp_clients_.end());
    }
    for (const auto& tls : pending_tcp_clients) {
        if (tls) {
            tls->close();
        }
    }

    {
        std::lock_guard<std::mutex> lock(tcp_workers_mutex_);
        for (auto& worker : tcp_workers_) {
            if (worker.alive) {
                worker.alive->store(false);
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(udp_workers_mutex_);
        for (auto& worker : udp_workers_) {
            if (worker.alive) {
                worker.alive->store(false);
            }
        }
    }

    {
        std::vector<std::shared_ptr<UdpPeerState>> states;
        {
            std::lock_guard<std::mutex> lock(udp_peers_mutex_);
            for (const auto& [_, state] : udp_peers_) {
                if (state) states.push_back(state);
            }
        }
        for (const auto& state : states) {
            std::lock_guard<std::mutex> state_lock(state->mutex);
            state->closed = true;
            state->cv.notify_all();
        }
    }

    if (cancellation_event_) {
        ::SetEvent(cancellation_event_);
    }

    if (tun_reader_thread_.joinable()) tun_reader_thread_.join();
    if (cancellation_event_) {
        ::CloseHandle(cancellation_event_);
        cancellation_event_ = nullptr;
    }

    if (transport_ == TransportProtocol::Tcp) {
        if (accept_thread_.joinable()) accept_thread_.join();
    } else {
        if (udp_dispatch_thread_.joinable()) udp_dispatch_thread_.join();
    }

    // The listener may have admitted a final TCP peer between the first
    // pending-client snapshot and accept-thread shutdown.  Interrupt that
    // complete, now-stable set before joining workers.
    if (transport_ == TransportProtocol::Tcp) {
        std::vector<std::shared_ptr<secure::SecureSocket>> late_pending_clients;
        {
            std::lock_guard<std::mutex> lock(pending_tcp_clients_mutex_);
            late_pending_clients.assign(pending_tcp_clients_.begin(),
                                        pending_tcp_clients_.end());
        }
        for (const auto& tls : late_pending_clients) {
            if (tls) tls->close();
        }
    }

    // The dispatch thread may have registered one final worker after the first
    // shutdown pass. With the producer joined, mark the complete worker set and
    // wake every UDP queue before joining it below.
    {
        std::lock_guard<std::mutex> lock(tcp_workers_mutex_);
        for (auto& worker : tcp_workers_) {
            if (worker.alive) {
                worker.alive->store(false);
            }
        }
    }
    {
        std::lock_guard<std::mutex> lock(udp_workers_mutex_);
        for (auto& worker : udp_workers_) {
            if (worker.alive) {
                worker.alive->store(false);
            }
        }
    }
    {
        std::vector<std::shared_ptr<UdpPeerState>> states;
        {
            std::lock_guard<std::mutex> lock(udp_peers_mutex_);
            for (const auto& [_, state] : udp_peers_) {
                if (state) states.push_back(state);
            }
        }
        for (const auto& state : states) {
            std::lock_guard<std::mutex> state_lock(state->mutex);
            state->closed = true;
            state->cv.notify_all();
        }
    }

    // No producer can register another worker now. A handshake that began
    // before running_ was cleared may have published just after the first
    // snapshot, so close the now-stable authenticated set before joining.
    close_authenticated_clients();

    pruneWorkers(tcp_workers_, tcp_workers_mutex_);
    pruneWorkers(udp_workers_, udp_workers_mutex_);

    // The accept/dispatch producers and every peer sender have now stopped.
    // Destroy the stateless wolfSSL listener before closing the socket captured
    // by its send callback.
    if (udp_cookie_gate_) {
        const auto stats = udp_cookie_gate_->stats();
        std::cout << "[INFO] UDP admission: " << stats.datagrams_processed
                  << " unknown datagrams, " << stats.cookie_challenges
                  << " cookie challenges, " << stats.sessions_admitted
                  << " admitted sessions, " << stats.authentication_failures
                  << " authentication failures, " << stats.malformed_datagrams
                  << " rejected malformed datagrams, "
                  << stats.cookie_secret_rotations
                  << " cookie-secret rotations\n";
        udp_cookie_gate_.reset();
    }
    {
        std::lock_guard<std::mutex> admission_lock(udp_admission_mutex_);
        if (udp_pending_handshakes_ != 0U) {
            std::cerr << "[!] UDP handshake admission accounting was nonzero "
                         "after all workers joined\n";
        }
        udp_pending_handshakes_ = 0U;
        udp_pending_by_source_.clear();
        udp_global_attempts_ = 0U;
        udp_source_attempts_.clear();
        udp_rate_window_ = {};
    }

    // No Winsock call can overlap closesocket or observe a reused handle.
    const SOCKET listening_socket = listen_sock_.exchange(
        INVALID_SOCKET, std::memory_order_acq_rel);
    if (listening_socket != INVALID_SOCKET) {
        (void)::shutdown(listening_socket, SD_BOTH);
        (void)::closesocket(listening_socket);
    }
    firewall_rule_.reset();
    icmp_firewall_rule_.reset();

    {
        std::lock_guard<std::mutex> session_guard(session_mutex_);
        session_.reset();
    }

    // Remove interface-bound state while the Wintun adapter still exists.
    cleanupNetwork();

    if (adapter_) {
        adapter_->Reset();
        adapter_.reset();
    }

    {
        std::unique_lock<std::shared_mutex> lk(client_map_mutex_);
        client_map_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(pending_tcp_clients_mutex_);
        pending_tcp_clients_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(udp_peers_mutex_);
        udp_peers_.clear();
    }

    const auto tcp_attempts = tcp_attempt_limiter_.stats();
    const auto chat_attempts = chat_limiter_.stats();
    const auto chat_fanout = chat_fanout_limiter_.stats();
    std::cout << "[INFO] TCP admission: " << tcp_attempts.allowed
              << " allowed, " << tcp_attempts.rejected << " rate-limited; "
              << "authenticated chat: " << chat_attempts.allowed
              << " allowed, " << chat_attempts.rejected << " rate-limited; "
              << "chat fanout: " << chat_fanout.allowed << " allowed, "
              << chat_fanout.rejected << " rate-limited\n";

    if (!password_.empty()) {
        ::SecureZeroMemory(password_.data(), password_.size());
        password_.clear();
        password_.shrink_to_fit();
    }
    std::cout << "[✓] Server shutdown complete\n";
}

bool VpnServer::send_chat(const std::string& text)
{
    if (text.empty()) return false;
    return broadcast_message("server", text, "server-console") ==
           BroadcastStatus::Delivered;
}

// ───────────────────────────────────────────────────────────────────────────────
//  private – setup / teardown
// ───────────────────────────────────────────────────────────────────────────────
void VpnServer::setupServer()
{
    local_ip_   = "10.10.100.1";
    subnetmask_ = "255.255.255.0";
    gateway_    = "10.10.100.1";

	adaptername_  = validate_wintun_adapter_name(adaptername_);
	real_adapter_ = sanitize_shell_string(real_adapter_);
	real_adapter_luid_ = ResolveNetworkAdapterLuid(
		real_adapter_, expected_real_adapter_luid_);
	real_adapter_luid_pinned_ = true;
	real_adapter_ = GetNetworkAdapterAlias(real_adapter_luid_);
	std::cout << "[INFO] Pinned physical uplink identity: "
	          << real_adapter_ << " (LUID "
	          << real_adapter_luid_.Value << ")\n";

    CHECK(port_ > 0 && port_ <= 65'535, "VPN server port is out of range");
    CHECK(running_.load(), "server start cancelled");
    createAdapter();
    CHECK(running_.load(), "server start cancelled");
    createListener();
    CHECK(running_.load(), "server start cancelled");

    const std::string listen_ip = get_ipv4_for_adapter(real_adapter_luid_);
    CHECK(!listen_ip.empty(), "Unable to resolve server listener address");
    firewall_rule_.emplace(AddVpnInboundFirewallRule(
        static_cast<std::uint16_t>(port_),
        transport_ == TransportProtocol::Udp,
        listen_ip));
    std::cout << "[INFO] Opened a scoped Windows Firewall rule for "
              << to_string(transport_) << ' ' << listen_ip << ':' << port_ << '\n';

    auto sess = WintunStartSession(adapter_->get(), 0x400000);
    CHECK(sess != nullptr, "WintunStartSession failed");
    session_ = std::make_unique<WintunSessionGuard>(sess);
    cancellation_event_ = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    CHECK(cancellation_event_ != nullptr, "CreateEvent(cancellation) failed");

    // ——— Threads ——————————————————————————————————————————————
    tun_reader_thread_ = std::thread(&VpnServer::tunReaderEntry, this);
    if (transport_ == TransportProtocol::Tcp) {
        accept_thread_ = std::thread(&VpnServer::acceptLoop, this);
    } else {
        udp_dispatch_thread_ = std::thread(&VpnServer::udpDispatchLoop, this);
    }

    if (!SetNetworkCategoryPrivate(adapter_->luid())) {
        std::cerr << "[!] Windows did not expose the Wintun network profile in time; "
                     "its firewall category was not changed\n";
    }

    icmp_firewall_rule_.emplace(AddIcmpV4FirewallRule(adaptername_));


}

void VpnServer::createAdapter()
{
	adapter_.emplace(adaptername_);

    SetStaticIPv4Address(adapter_->luid(), local_ip_, subnetmask_);
    // The /24 connected route is created with the address by NetIO. Keep it
    // active-only and let Wintun adapter teardown remove it automatically.
    SetInterfaceMtu(adapter_->luid(), 1380U);

    // Preserve RRAS NAT bindings owned by the administrator or another
    // service. cleanupNetwork() removes only bindings successfully added here.
    CHECK(running_.load(), "server start cancelled");

    nat_public_alias_ = sanitize_shell_string(
        GetNetworkAdapterAlias(real_adapter_luid_));
    CHECK(NetworkAdapterAliasMatchesLuid(
              nat_public_alias_, real_adapter_luid_),
          "Physical adapter alias changed before RRAS NAT configuration");
    const std::string nat_public_cmd =
        "netsh routing ip nat add interface \"" + nat_public_alias_ +
        "\" mode=full";
    if (run_command_hidden(nat_public_cmd, &running_)) {
        nat_public_installed_ = true;
        std::cout << "[INFO] Enabled NAT on uplink interface '"
                  << nat_public_alias_ << "'\n";
    } else {
        nat_public_alias_.clear();
        std::cerr << "[!] Failed to enable NAT on uplink interface '" << real_adapter_ << "'\n"
                  << "      -> Install/enable the 'Routing and Remote Access' feature on Windows." << std::endl;
    }

    CHECK(running_.load(), "server start cancelled");

    nat_private_alias_ = sanitize_shell_string(
        GetNetworkAdapterAlias(adapter_->luid()));
    CHECK(NetworkAdapterAliasMatchesLuid(
              nat_private_alias_, adapter_->luid()),
          "Tunnel adapter alias changed before RRAS NAT configuration");
    const std::string nat_private_cmd =
        "netsh routing ip nat add interface \"" + nat_private_alias_ +
        "\" mode=private";
    if (run_command_hidden(nat_private_cmd, &running_)) {
        nat_private_installed_ = true;
        std::cout << "[INFO] Enabled NAT on tunnel interface '"
                  << nat_private_alias_ << "'\n";
    } else {
        nat_private_alias_.clear();
        std::cerr << "[!] Failed to enable NAT on tunnel interface '" << adaptername_ << "'\n"
                  << "      -> Install/enable the 'Routing and Remote Access' feature on Windows." << std::endl;
    }
}

void VpnServer::createListener() {
    if (transport_ == TransportProtocol::Tcp) {
        createTcpListener();
    } else {
        createUdpListener();
    }
}

void VpnServer::createTcpListener()
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(s != INVALID_SOCKET, "socket");
    SocketGuard socket_guard{s};

    BOOL exclusive = TRUE;
    CHECK(setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                     reinterpret_cast<const char*>(&exclusive),
                     sizeof(exclusive)) != SOCKET_ERROR,
          "setsockopt(SO_EXCLUSIVEADDRUSE)");

    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(static_cast<uint16_t>(port_));
    std::string ip = get_ipv4_for_adapter(real_adapter_luid_);
    CHECK(!ip.empty(), "bind ip empty");

    CHECK(inet_pton(AF_INET, ip.c_str(), &a.sin_addr) == 1, "bind ip invalid");
    CHECK(bind(s, (sockaddr*)&a, sizeof(a)) != SOCKET_ERROR, "bind");
    CHECK(listen(s, SOMAXCONN)              != SOCKET_ERROR, "listen");

    u_long nonblocking = 1UL;
    CHECK(ioctlsocket(s, FIONBIO, &nonblocking) != SOCKET_ERROR,
          "ioctlsocket(FIONBIO listener)");

    listen_sock_ = socket_guard.release();
    std::cout << "[*] Listening (TCP) on " << ip << ':' << port_ << '\n';
}

void VpnServer::createUdpListener()
{
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(s != INVALID_SOCKET, "socket");
    SocketGuard socket_guard{s};

    BOOL exclusive = TRUE;
    CHECK(setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                     reinterpret_cast<const char*>(&exclusive),
                     sizeof(exclusive)) != SOCKET_ERROR,
          "setsockopt(SO_EXCLUSIVEADDRUSE)");
    BOOL report_udp_resets = FALSE;
    DWORD bytes_returned = 0U;
    CHECK(WSAIoctl(s, SIO_UDP_CONNRESET,
                   &report_udp_resets, sizeof(report_udp_resets),
                   nullptr, 0U, &bytes_returned, nullptr, nullptr) != SOCKET_ERROR,
          "WSAIoctl(SIO_UDP_CONNRESET)");

    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(static_cast<uint16_t>(port_));
    std::string ip = get_ipv4_for_adapter(real_adapter_luid_);
    CHECK(!ip.empty(), "bind ip empty");
    CHECK(inet_pton(AF_INET, ip.c_str(), &a.sin_addr) == 1, "bind ip invalid");

    CHECK(bind(s, (sockaddr*)&a, sizeof(a)) != SOCKET_ERROR, "bind");

    // A receive timeout lets stop() join the dispatcher before closing the
    // shared UDP socket. A bounded send timeout likewise prevents a peer
    // worker from indefinitely delaying orderly shutdown.
    constexpr DWORD kDispatcherPollMilliseconds = 200U;
    constexpr DWORD kDatagramSendTimeoutMilliseconds = 2'000U;
    CHECK(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                     reinterpret_cast<const char*>(&kDispatcherPollMilliseconds),
                     sizeof(kDispatcherPollMilliseconds)) != SOCKET_ERROR,
          "setsockopt(SO_RCVTIMEO UDP listener)");
    CHECK(setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
                     reinterpret_cast<const char*>(&kDatagramSendTimeoutMilliseconds),
                     sizeof(kDatagramSendTimeoutMilliseconds)) != SOCKET_ERROR,
          "setsockopt(SO_SNDTIMEO UDP listener)");

    auto send_to = [s](const std::uint8_t* const data,
                       const std::size_t length,
                       const sockaddr_storage& peer,
                       const int peer_length) -> bool {
        if (data == nullptr || length == 0U ||
            length > static_cast<std::size_t>((std::numeric_limits<int>::max)()) ||
            peer_length <= 0) {
            return false;
        }
        const int sent = ::sendto(
            s,
            reinterpret_cast<const char*>(data),
            static_cast<int>(length),
            0,
            reinterpret_cast<const sockaddr*>(&peer),
            peer_length);
        return sent == static_cast<int>(length);
    };
    const auto password = std::span<const std::uint8_t>{
        reinterpret_cast<const std::uint8_t*>(password_.data()),
        password_.size()};
    udp_cookie_gate_ = std::make_unique<secure::WolfSslStatelessServer>(
        std::move(send_to), password, cipher_suite_);

    listen_sock_ = socket_guard.release();
    std::cout << "[*] Listening (UDP) on " << ip << ':' << port_ << '\n';
}

void VpnServer::addWorker(std::vector<ThreadBundle>& workers,
                          std::mutex& mutex,
                          std::shared_ptr<std::atomic<bool>> alive,
                          std::thread&& worker)
{
    std::lock_guard<std::mutex> lock(mutex);
    workers.emplace_back(std::move(alive), std::move(worker));
}

bool VpnServer::tryAcquireTcpAdmission() {
    std::lock_guard<std::mutex> lock(tcp_workers_mutex_);
    if (!running_.load(std::memory_order_acquire) ||
        tcp_admissions_ >= kMaximumTcpWorkers) {
        return false;
    }
    ++tcp_admissions_;
    return true;
}

void VpnServer::releaseTcpAdmission() {
    std::lock_guard<std::mutex> lock(tcp_workers_mutex_);
    if (tcp_admissions_ != 0U) --tcp_admissions_;
}

bool VpnServer::allowClientChat(const std::string& client_id,
                                const std::size_t bytes) {
    return chat_limiter_.allow(client_id, bytes);
}

void VpnServer::closeAndEraseUdpPeerIfOwned(
    const std::string& peer_key,
    const std::shared_ptr<UdpPeerState>& state) noexcept {
    if (!state) return;
    {
        std::lock_guard<std::mutex> state_lock(state->mutex);
        state->closed = true;
        state->cv.notify_all();
    }
    std::lock_guard<std::mutex> map_lock(udp_peers_mutex_);
    const auto it = udp_peers_.find(peer_key);
    if (it != udp_peers_.end() && it->second == state) {
        udp_peers_.erase(it);
    }
}

VpnServer::UdpHandshakeReservation::~UdpHandshakeReservation() {
    release();
}

void VpnServer::UdpHandshakeReservation::release() noexcept {
    if (!held) return;
    held = false;
    if (owner != nullptr) {
        owner->releaseUdpHandshake(source);
    }
}

bool VpnServer::allowUdpStatelessAttempt(const std::string& source) {
    constexpr std::size_t kMaximumGlobalAttemptsPerSecond = 2'048U;
    constexpr std::size_t kMaximumSourceAttemptsPerSecond = 64U;
    constexpr std::size_t kMaximumTrackedSources = 1'024U;

    const auto now = std::chrono::steady_clock::now();
    std::lock_guard lock{udp_admission_mutex_};
    if (udp_rate_window_ == std::chrono::steady_clock::time_point{} ||
        now - udp_rate_window_ >= std::chrono::seconds{1}) {
        udp_rate_window_ = now;
        udp_global_attempts_ = 0U;
        udp_source_attempts_.clear();
    }
    if (udp_global_attempts_ >= kMaximumGlobalAttemptsPerSecond) {
        return false;
    }

    auto source_it = udp_source_attempts_.find(source);
    if (source_it == udp_source_attempts_.end()) {
        if (udp_source_attempts_.size() >= kMaximumTrackedSources) {
            return false;
        }
        source_it = udp_source_attempts_.emplace(source, 0U).first;
    }
    if (source_it->second >= kMaximumSourceAttemptsPerSecond) {
        return false;
    }
    ++udp_global_attempts_;
    ++source_it->second;
    return true;
}

std::shared_ptr<VpnServer::UdpHandshakeReservation>
VpnServer::tryReserveUdpHandshake(const std::string& source) {
    constexpr std::size_t kMaximumPendingHandshakes = 64U;
    constexpr std::size_t kMaximumPendingHandshakesPerSource = 8U;

    std::lock_guard lock{udp_admission_mutex_};
    auto source_it = udp_pending_by_source_.find(source);
    const std::size_t source_pending =
        source_it == udp_pending_by_source_.end() ? 0U : source_it->second;
    if (!running_.load(std::memory_order_acquire) ||
        udp_pending_handshakes_ >= kMaximumPendingHandshakes ||
        source_pending >= kMaximumPendingHandshakesPerSource) {
        return {};
    }

    ++udp_pending_handshakes_;
    if (source_it == udp_pending_by_source_.end()) {
        udp_pending_by_source_.emplace(source, 1U);
    } else {
        ++source_it->second;
    }

    try {
        return std::make_shared<UdpHandshakeReservation>(this, source);
    } catch (...) {
        --udp_pending_handshakes_;
        auto rollback = udp_pending_by_source_.find(source);
        if (rollback != udp_pending_by_source_.end()) {
            if (--rollback->second == 0U) udp_pending_by_source_.erase(rollback);
        }
        throw;
    }
}

void VpnServer::releaseUdpHandshake(const std::string& source) noexcept {
    std::lock_guard lock{udp_admission_mutex_};
    if (udp_pending_handshakes_ != 0U) {
        --udp_pending_handshakes_;
    }
    auto source_it = udp_pending_by_source_.find(source);
    if (source_it != udp_pending_by_source_.end()) {
        if (source_it->second <= 1U) {
            udp_pending_by_source_.erase(source_it);
        } else {
            --source_it->second;
        }
    }
}

void VpnServer::pruneWorkers(std::vector<ThreadBundle>& workers, std::mutex& mutex)
{
    std::vector<std::thread> to_join;
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto it = workers.begin();
        while (it != workers.end()) {
            if (!it->alive || !*(it->alive)) {
                if (it->thread.joinable()) {
                    to_join.emplace_back(std::move(it->thread));
                }
                it = workers.erase(it);
            } else {
                ++it;
            }
        }
    }

    for (auto& thread : to_join) {
        if (thread.joinable()) {
            thread.join();
        }
    }
}

void VpnServer::cleanupNetwork() {
    if (nat_public_installed_) {
        if (real_adapter_luid_pinned_ &&
            NetworkAdapterAliasMatchesLuid(
                nat_public_alias_, real_adapter_luid_)) {
            run_command_hidden(
                "netsh routing ip nat delete interface \"" +
                nat_public_alias_ + "\" >nul 2>&1");
        } else {
            std::cerr << "[!] Skipped uplink NAT cleanup because its pinned "
                         "adapter alias no longer matches\n";
        }
        nat_public_installed_ = false;
        nat_public_alias_.clear();
    }
    if (nat_private_installed_) {
        if (adapter_ && NetworkAdapterAliasMatchesLuid(
                            nat_private_alias_, adapter_->luid())) {
            run_command_hidden(
                "netsh routing ip nat delete interface \"" +
                nat_private_alias_ + "\" >nul 2>&1");
        } else {
            std::cerr << "[!] Skipped tunnel NAT cleanup because its pinned "
                         "adapter alias no longer matches\n";
        }
        nat_private_installed_ = false;
        nat_private_alias_.clear();
    }
}

// ───────────────────────────────────────────────────────────────────────────────
//  private – thread entry points
// ───────────────────────────────────────────────────────────────────────────────
void VpnServer::tunReaderEntry()
{
    // Elevate this pump
    ::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    // Proper event usage: wait only when ring is empty
    WINTUN_SESSION_HANDLE session_handle = session_ ? session_->get() : nullptr;
    if (!session_handle) return;
    const HANDLE ev = WintunGetReadWaitEvent ? WintunGetReadWaitEvent(session_handle) : nullptr;

    while (running_) {
        // Drain all available packets
        for (;;) {
            UINT  size = 0;
            BYTE* pkt  = static_cast<BYTE*>(WintunReceivePacket(session_handle, &size));
            if (!pkt) break;
            if (is_well_formed_ipv4_packet(pkt, size)) {
                try {
                    (void)forward_to_client_if_known(pkt, size);
                } catch (const std::exception& error) {
                    std::cerr << "[!] Failed to route Wintun packet: "
                              << error.what() << '\n';
                } catch (...) {
                    std::cerr << "[!] Failed to route Wintun packet\n";
                }
            }
            WintunReleaseReceivePacket(session_handle, pkt);
        }
        if (!running_) break;
        const DWORD err = ::GetLastError();
        if (err == ERROR_NO_MORE_ITEMS) {
            if (ev) {
                DWORD wait_rc;
                if (cancellation_event_ != nullptr) {
                    const HANDLE events[] = {cancellation_event_, ev};
                    wait_rc = ::WaitForMultipleObjects(2U, events, FALSE, INFINITE);
                    if (wait_rc == WAIT_OBJECT_0) break;
                } else {
                    wait_rc = ::WaitForSingleObject(ev, INFINITE);
                }
                if (wait_rc == WAIT_FAILED) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        } else if (err == ERROR_HANDLE_EOF) {
            break;
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
}


void VpnServer::acceptLoop() {
    // Make accept loop responsive under load
    ::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

    if (transport_ != TransportProtocol::Tcp) return;
    while (running_) {
        const SOCKET listener = listen_sock_.load(std::memory_order_acquire);
        if (listener == INVALID_SOCKET) break;

        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(listener, &readable);
        timeval wait{};
        wait.tv_usec = 200'000L;
        const int ready = select(0, &readable, nullptr, nullptr, &wait);
        if (ready == 0) continue;
        if (ready == SOCKET_ERROR) {
            if (!running_) break;
            std::cerr << "[!] listener select: " << WSAGetLastError() << '\n';
            continue;
        }

        sockaddr_storage peer{};
        int peer_length = sizeof(peer);
        SOCKET c = accept(listener,
                          reinterpret_cast<sockaddr*>(&peer),
                          &peer_length);
        if (c == INVALID_SOCKET) {
            if (!running_) break;
            const int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK) {
                std::cerr << "[!] accept: " << error << '\n';
            }
            continue;
        }
        const std::string source = peer_source_from_addr(peer, peer_length);
        if (source.empty() || !tcp_attempt_limiter_.allow(source)) {
            closesocket(c);
            continue;
        }
        u_long blocking = 0UL;
        if (ioctlsocket(c, FIONBIO, &blocking) == SOCKET_ERROR) {
            closesocket(c);
            continue;
        }
        if (!tryAcquireTcpAdmission()) {
            closesocket(c);
            continue;
        }
        auto alive = std::make_shared<std::atomic<bool>>(true);
        std::thread worker;
        bool worker_started = false;
        try {
            worker = std::thread([this, c, alive]() {
                try {
                    handleClient(c, alive);
                } catch (...) {
                    // handleClient owns and closes the descriptor on every
                    // exit path. Never close this captured numeric value here:
                    // it may already have been released and reused by Winsock.
                    alive->store(false);
                }
                releaseTcpAdmission();
            });
            worker_started = true;
            addWorker(tcp_workers_, tcp_workers_mutex_, alive, std::move(worker));
        } catch (const std::system_error& ex) {
            std::cerr << "[!] failed to launch client worker: " << ex.what() << '\n';
            alive->store(false);
            if (worker.joinable()) worker.join();
            if (!worker_started) {
                releaseTcpAdmission();
                closesocket(c);
            }
        } catch (...) {
            std::cerr << "[!] failed to launch client worker\n";
            alive->store(false);
            if (worker.joinable()) worker.join();
            if (!worker_started) {
                releaseTcpAdmission();
                closesocket(c);
            }
        }
        pruneWorkers(tcp_workers_, tcp_workers_mutex_);
    }
}

namespace {
constexpr std::string_view kConfigRequest = "VPN_REQUEST_CONFIG";
constexpr DWORD kPreAuthenticationTimeoutMilliseconds = 15'000U;
constexpr std::size_t kMaximumUdpPeers = 256U;
constexpr std::size_t kMaximumQueuedDatagramsPerPeer = 64U;
constexpr std::size_t kMaximumDtlsDatagram = 2048U;

void set_socket_timeouts(const SOCKET socket, const DWORD milliseconds) {
    if (::setsockopt(socket,
                     SOL_SOCKET,
                     SO_RCVTIMEO,
                     reinterpret_cast<const char*>(&milliseconds),
                     sizeof(milliseconds)) == SOCKET_ERROR ||
        ::setsockopt(socket,
                     SOL_SOCKET,
                     SO_SNDTIMEO,
                     reinterpret_cast<const char*>(&milliseconds),
                     sizeof(milliseconds)) == SOCKET_ERROR) {
        throw std::system_error(::WSAGetLastError(),
                                std::system_category(),
                                "setsockopt(TLS timeout)");
    }
}

std::string peer_key_from_addr(const sockaddr_storage& addr, int len) {
    char host[NI_MAXHOST]{};
    char serv[NI_MAXSERV]{};
    if (getnameinfo(reinterpret_cast<const sockaddr*>(&addr), len,
                    host, sizeof(host), serv, sizeof(serv),
                    NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        return {};
    }
    std::string key(host);
    key.push_back(':');
    key.append(serv);
    return key;
}

std::string peer_source_from_addr(const sockaddr_storage& addr, int len) {
    char host[NI_MAXHOST]{};
    if (getnameinfo(reinterpret_cast<const sockaddr*>(&addr), len,
                    host, sizeof(host), nullptr, 0, NI_NUMERICHOST) != 0) {
        return {};
    }
    return host;
}
} // namespace

void VpnServer::udpDispatchLoop() {
    // Dispatcher is latency sensitive
    ::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

    std::vector<uint8_t> buffer(kMaximumDtlsDatagram);

    while (running_) {
        sockaddr_storage addr{};
        int addr_len = sizeof(addr);
        int got = recvfrom(listen_sock_.load(std::memory_order_acquire), reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0,
                           reinterpret_cast<sockaddr*>(&addr), &addr_len);
        if (got <= 0) {
            if (!running_) break;
            int err = WSAGetLastError();
            if (err == WSAEINTR) continue;
            if (err == WSAETIMEDOUT || err == WSAEWOULDBLOCK) continue;
            if (err == WSAEMSGSIZE) {
                std::cerr << "[!] recvfrom truncated datagram\n";
                continue;
            }
            std::cerr << "[!] recvfrom error: " << err << '\n';
            continue;
        }

        auto key = peer_key_from_addr(addr, addr_len);
        auto source = peer_source_from_addr(addr, addr_len);
        if (key.empty() || source.empty()) {
            std::cerr << "[!] Unable to format peer address\n";
            continue;
        }

        std::shared_ptr<UdpPeerState> state;
        {
            std::lock_guard<std::mutex> lock(udp_peers_mutex_);
            if (running_.load(std::memory_order_acquire)) {
                auto it = udp_peers_.find(key);
                if (it != udp_peers_.end()) {
                    state = it->second;
                }
            }
        }

        if (state) {
            std::vector<uint8_t> packet(static_cast<std::size_t>(got));
            std::memcpy(packet.data(), buffer.data(),
                        static_cast<std::size_t>(got));
            std::lock_guard<std::mutex> lock(state->mutex);
            if (state->closed ||
                state->queue.size() >= kMaximumQueuedDatagramsPerPeer) {
                continue;
            }
            state->queue.emplace_back(std::move(packet));
            state->cv.notify_one();
            continue;
        }

        // Unknown tuples stay allocation-light until wolfSSL verifies a
        // peer-address-bound HRR cookie and the TLS 1.3 PSK ClientHello.
        if (!allowUdpStatelessAttempt(source) || !udp_cookie_gate_) {
            continue;
        }

        std::optional<secure::PreparedWolfSslServerSession> prepared;
        try {
            prepared = udp_cookie_gate_->process_datagram(
                std::span<const std::uint8_t>{buffer.data(),
                                              static_cast<std::size_t>(got)},
                addr,
                addr_len);
        } catch (const std::exception& error) {
            std::cerr << "[!] DTLS stateless admission failed: "
                      << error.what() << '\n';
            continue;
        }
        if (!prepared) {
            continue;
        }

        auto reservation = tryReserveUdpHandshake(source);
        if (!reservation) {
            continue;
        }

        state = std::make_shared<UdpPeerState>();
        state->addr = addr;
        state->addr_len = addr_len;
        {
            std::lock_guard<std::mutex> lock(udp_peers_mutex_);
            if (!running_.load(std::memory_order_acquire) ||
                udp_peers_.size() >= kMaximumUdpPeers ||
                !udp_peers_.emplace(key, state).second) {
                continue;
            }
        }

        auto alive = std::make_shared<std::atomic<bool>>(true);
        std::thread worker;
        try {
            worker = std::thread(&VpnServer::handleUdpClient,
                                 this,
                                 state,
                                 key,
                                 alive,
                                 std::move(*prepared),
                                 reservation);
            addWorker(udp_workers_, udp_workers_mutex_, alive, std::move(worker));
        } catch (const std::system_error& ex) {
            std::cerr << "[!] failed to launch UDP worker: " << ex.what() << '\n';
            alive->store(false);
            if (worker.joinable()) worker.join();
            closeAndEraseUdpPeerIfOwned(key, state);
        } catch (...) {
            std::cerr << "[!] failed to launch UDP worker\n";
            alive->store(false);
            if (worker.joinable()) worker.join();
            closeAndEraseUdpPeerIfOwned(key, state);
        }
        pruneWorkers(udp_workers_, udp_workers_mutex_);
    }
}

// ───────────────────────────────────────────────────────────────────────────────
//  private – per-client handling
// ───────────────────────────────────────────────────────────────────────────────
void VpnServer::handleClient(SOCKET sock,
                             std::shared_ptr<std::atomic<bool>> alive)
{
    if (!alive) {
        alive = std::make_shared<std::atomic<bool>>(true);
    }

    std::string cid;
    std::string remote_ip = "unknown";
    std::shared_ptr<secure::SecureSocket> tls;
    bool tls_pending = false;
    const auto unregister_pending_tls = [this, &tls, &tls_pending]() {
        if (!tls_pending || !tls) {
            return;
        }
        std::lock_guard<std::mutex> lock(pending_tcp_clients_mutex_);
        pending_tcp_clients_.erase(tls);
        tls_pending = false;
    };
    try {
        sockaddr_storage peer{};
        int peer_len = sizeof(peer);
        if (getpeername(sock, reinterpret_cast<sockaddr*>(&peer), &peer_len) == 0 &&
            peer.ss_family == AF_INET) {
            char buf[INET_ADDRSTRLEN] = {};
            const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(&peer);
            if (inet_ntop(AF_INET, &ipv4->sin_addr, buf, sizeof(buf))) {
                remote_ip = buf;
            }
        }

        set_socket_timeouts(sock, kPreAuthenticationTimeoutMilliseconds);
        tls = std::make_shared<secure::SecureSocket>(sock,
                                                     password_,
                                                     /*is_server=*/true,
                                                     cipher_suite_,
                                                     rotation_policy_);
        {
            std::lock_guard<std::mutex> lock(pending_tcp_clients_mutex_);
            CHECK(running_.load(), "server stopping");
            const bool inserted = pending_tcp_clients_.insert(tls).second;
            CHECK(inserted, "TLS connection already pending");
            tls_pending = true;
        }
        tls->handshake();
        std::cout << "[🔐] Client authenticated with native TLS 1.3 "
                     "(TLS_AES_256_GCM_SHA384, exporter-bound password authentication)\n";

        int flag = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));  // ✅ actual client socket

        uint8_t typ=0; std::array<uint8_t,kConfigRequest.size()> req{};
        int rn = tls->recv_record(typ, req.data(), req.size());
        CHECK(rn == static_cast<int>(kConfigRequest.size()), "cfg read");
        CHECK(typ == PACKET_TYPE_MSG &&
              std::memcmp(req.data(), kConfigRequest.data(), kConfigRequest.size()) == 0,
              "bad cfg tag");

        cid = std::to_string(reinterpret_cast<uintptr_t>(tls.get()));
        auto ip_opt     = ip_pool.assignTentative(cid);
        CHECK(ip_opt, "no free IPs");
        std::string ip = *ip_opt;

        std::string cfg = "VPN_CFG:IP=" + ip + ";GW=10.10.100.1;MASK=255.255.255.255";
        if (tls->send_record(PACKET_TYPE_MSG, (const uint8_t*)cfg.data(), (uint16_t)cfg.size()) < 0) {
            throw std::runtime_error("Failed to deliver config to client");
        }
        set_socket_timeouts(sock, 0U);

        ip_pool.confirm(cid);

        {
            std::unique_lock<std::shared_mutex> ul(client_map_mutex_);
            CHECK(running_.load(std::memory_order_acquire), "server stopping");
            const bool inserted = client_map_.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(ip),
                std::forward_as_tuple(tls, cid)).second;
            CHECK(inserted, "assigned IP already registered");
        }
        unregister_pending_tls();

        std::cout << "[+] Client " << remote_ip << " assigned " << ip << "\n";

        tlsClientEntry(tls,
                       ip,
                       cid,
                       alive,
                       std::shared_ptr<UdpPeerState>{},
                       std::string{});
    }
    catch (const std::exception& e) {
        std::cerr << "[!] client: " << e.what() << '\n';
        if (!cid.empty()) {
            ip_pool.release(cid);
        }
        if (tls) {
            tls->close();
            unregister_pending_tls();
        } else {
            closesocket(sock);
        }
    }
    catch (...) {
        std::cerr << "[!] client: unknown failure\n";
        if (!cid.empty()) {
            ip_pool.release(cid);
        }
        if (tls) {
            tls->close();
            unregister_pending_tls();
        } else {
            closesocket(sock);
        }
    }

    if (alive) {
        alive->store(false);
    }

    if (!cid.empty()) {
        std::cout << "[-] Client " << cid << " disconnected\n";
    }
}

void VpnServer::handleUdpClient(std::shared_ptr<UdpPeerState> state,
                                std::string peer_key,
                                std::shared_ptr<std::atomic<bool>> alive,
                                secure::PreparedWolfSslServerSession prepared,
                                std::shared_ptr<UdpHandshakeReservation> reservation)
{
    if (!state || !prepared || !reservation) return;
    if (!alive) {
        alive = std::make_shared<std::atomic<bool>>(true);
    }
    // Per-peer processing thread
    ::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_HIGHEST);


    std::string cid;

    auto cleanup_peer = [this, state, peer = peer_key]() {
        closeAndEraseUdpPeerIfOwned(peer, state);
    };

    try {
        sockaddr_storage addr_copy{};
        int addr_len = 0;
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            addr_copy = state->addr;
            addr_len = state->addr_len;
        }

        SOCKET sock_handle = listen_sock_.load(std::memory_order_acquire);
        auto send_fn = [sock_handle, addr_copy, addr_len](
                           const uint8_t* data,
                           std::size_t len) -> secure::DatagramSendResult {
            int sent = sendto(sock_handle,
                              reinterpret_cast<const char*>(data),
                              static_cast<int>(len),
                              0,
                              reinterpret_cast<const sockaddr*>(&addr_copy),
                              addr_len);
            if (sent == static_cast<int>(len)) {
                return secure::DatagramSendResult::Sent;
            }
            switch (WSAGetLastError()) {
                case WSAEWOULDBLOCK:
                case WSAETIMEDOUT:
                    return secure::DatagramSendResult::WouldBlock;
                case WSAESHUTDOWN:
                case WSAENOTSOCK:
                    return secure::DatagramSendResult::Closed;
                default:
                    return secure::DatagramSendResult::Error;
            }
        };

        auto recv_fn = [state, this](
                               std::vector<uint8_t>& out,
                               const std::chrono::milliseconds timeout)
            -> secure::DatagramReceiveResult {
            std::unique_lock<std::mutex> lock(state->mutex);
            const bool signaled = state->cv.wait_for(lock, timeout, [&]() {
                return !state->queue.empty() || state->closed || !this->running_;
            });
            if (state->queue.empty()) {
                return signaled
                           ? secure::DatagramReceiveResult::Closed
                           : secure::DatagramReceiveResult::Timeout;
            }
            out = std::move(state->queue.front());
            state->queue.pop_front();
            return secure::DatagramReceiveResult::Received;
        };

        auto close_fn = [state]() noexcept {
            {
                std::lock_guard<std::mutex> lock(state->mutex);
                state->closed = true;
            }
            state->cv.notify_all();
        };

        auto transport = std::make_unique<secure::DatagramTransport>(
            std::move(send_fn), std::move(recv_fn), std::move(close_fn));
        auto tls = std::make_shared<secure::SecureSocket>(listen_sock_.load(std::memory_order_acquire),
                                                          std::move(transport),
                                                          std::move(prepared),
                                                          /*owns_socket=*/false,
                                                          rotation_policy_);
        tls->handshake();
        // The expensive/full handshake slot protects only unauthenticated
        // work. Release it immediately once the DTLS peer is authenticated.
        reservation->release();
        std::cout << "[🔐] UDP client authenticated with wolfSSL DTLS 1.3 "
                     "(TLS_AES_256_GCM_SHA384, P-256 ECDHE-PSK)\n";

        uint8_t typ = 0; std::array<uint8_t,kConfigRequest.size()> req{};
        int rn = tls->recv_record(typ, req.data(), req.size());
        CHECK(rn == static_cast<int>(kConfigRequest.size()), "cfg read");
        CHECK(typ == PACKET_TYPE_MSG &&
              std::memcmp(req.data(), kConfigRequest.data(), kConfigRequest.size()) == 0,
              "bad cfg tag");

        cid = std::to_string(reinterpret_cast<uintptr_t>(tls.get()));
        auto ip_opt = ip_pool.assignTentative(cid);
        CHECK(ip_opt, "no free IPs");
        std::string ip = *ip_opt;

        std::string cfg = "VPN_CFG:IP=" + ip + ";GW=10.10.100.1;MASK=255.255.255.255";
        const int config_bytes = tls->send_record(
            PACKET_TYPE_MSG,
            reinterpret_cast<const uint8_t*>(cfg.data()),
            static_cast<uint16_t>(cfg.size()));
        CHECK(config_bytes == static_cast<int>(cfg.size()),
              "Failed to deliver config to UDP client");

        cid = std::to_string(reinterpret_cast<uintptr_t>(tls.get()));
        ip_pool.confirm(cid);

        {
            std::unique_lock<std::shared_mutex> ul(client_map_mutex_);
            CHECK(running_.load(std::memory_order_acquire), "server stopping");
            const bool inserted = client_map_.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(ip),
                std::forward_as_tuple(tls, cid)).second;
            CHECK(inserted, "assigned IP already registered");
        }

        std::cout << "[+] UDP client " << peer_key << " assigned " << ip << "\n";

        tlsClientEntry(tls,
                       ip,
                       cid,
                       alive,
                       state,
                       peer_key);
    }
    catch (const std::exception& e) {
        std::cerr << "[!] udp-client: " << e.what() << '\n';
        cleanup_peer();
        if (!cid.empty()) {
            ip_pool.release(cid);
        }
        if (alive) {
            alive->store(false);
        }
        std::cout << "[-] UDP client " << peer_key << " disconnected\n";
        return;
    }

    if (alive) {
        alive->store(false);
    }

    std::cout << "[-] UDP client " << peer_key << " disconnected\n";
}

VpnServer::BroadcastStatus VpnServer::broadcast_payload(
    const std::string& payload,
    const std::string_view budget_key,
    const std::string* skip_client_id) {
    if (payload.empty() ||
        payload.size() > secure::kMaximumDatagramPayloadSize) {
        return BroadcastStatus::DeliveryFailed;
    }

    struct ClientSnapshot {
        std::string ip;
        std::string id;
        std::shared_ptr<secure::SecureSocket> tls;
        std::shared_ptr<std::timed_mutex> write_mutex;
    };

    std::vector<ClientSnapshot> clients;
    {
        std::shared_lock<std::shared_mutex> lock(client_map_mutex_);
        if (client_map_.empty()) return BroadcastStatus::NoRecipients;
        clients.reserve(client_map_.size());
        for (const auto& [ip, entry] : client_map_) {
            if (skip_client_id && entry.client_id == *skip_client_id) {
                continue;
            }
            clients.push_back(ClientSnapshot{
                ip, entry.client_id, entry.tls, entry.write_mutex});
        }
    }

    if (clients.empty()) return BroadcastStatus::NoRecipients;
    if (clients.size() >
        (std::numeric_limits<std::size_t>::max)() / payload.size()) {
        return BroadcastStatus::RateLimited;
    }
    const std::size_t aggregate_bytes = payload.size() * clients.size();
    if (!chat_fanout_limiter_.allow(budget_key, aggregate_bytes)) {
        return BroadcastStatus::RateLimited;
    }

    bool all_ok = true;
    std::vector<ClientSnapshot> dead;
    const auto fanout_deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds{5};
    for (const auto& client : clients) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= fanout_deadline) {
            all_ok = false;
            break;
        }

        std::unique_lock<std::timed_mutex> write_guard{
            *client.write_mutex, std::defer_lock};
        const auto lock_deadline = (std::min)(
            fanout_deadline, now + std::chrono::milliseconds{100});
        if (!write_guard.try_lock_until(lock_deadline)) {
            // A busy writer does not prove the recipient is dead. Drop this
            // chat delivery rather than queueing an attacker-amplified backlog.
            all_ok = false;
            continue;
        }

        std::string failure_text;
        try {
            const int sent = client.tls->send_record(
                PACKET_TYPE_MSG,
                reinterpret_cast<const uint8_t*>(payload.data()),
                static_cast<uint16_t>(payload.size()));
            if (sent != static_cast<int>(payload.size())) {
                throw std::runtime_error("short secure-record write");
            }
        } catch (const std::exception& error) {
            failure_text = error.what();
        } catch (...) {
            failure_text = "unknown secure-record failure";
        }
        if (!failure_text.empty()) {
            std::cerr << "[!] Send to client " << client.ip
                      << " failed: " << failure_text << '\n';
            all_ok = false;
            dead.push_back(client);
        }
    }
    if (!dead.empty()) {
        std::unique_lock<std::shared_mutex> ul(client_map_mutex_);
        for (const auto& failed : dead) {
            auto it = client_map_.find(failed.ip);
            if (it != client_map_.end() &&
                it->second.client_id == failed.id &&
                it->second.tls == failed.tls) {
                client_map_.erase(it);
                ip_pool.release(failed.id);
                std::cout << "[-] Dropped unresponsive client "
                          << failed.ip << '\n';
            }
        }
        ul.unlock();
        for (const auto& failed : dead) {
            if (failed.tls) {
                failed.tls->close();
            }
        }
    }
    return all_ok ? BroadcastStatus::Delivered
                  : BroadcastStatus::DeliveryFailed;
}

VpnServer::BroadcastStatus VpnServer::broadcast_message(
    const std::string& from,
    const std::string& text,
    const std::string_view budget_key,
    const std::string* skip_client_id) {
    if (text.empty() || text.size() > kMaximumChatMessageSize) {
        return BroadcastStatus::DeliveryFailed;
    }
    std::string payload = from + "|" + text;
    const BroadcastStatus status =
        broadcast_payload(payload, budget_key, skip_client_id);
    if (status == BroadcastStatus::Delivered ||
        status == BroadcastStatus::NoRecipients) {
        std::cout << "[📨] " << from << ": " << text << '\n';
    }
    return status;
}

void VpnServer::handle_client_message(secure::SecureSocket* tls, std::string_view message) {
    auto info_opt = find_client_info_for_tls(tls);
    if (!info_opt) {
        throw std::runtime_error("Chat sender is not an authenticated client");
    }
    if (!allowClientChat(info_opt->second, message.size())) {
        std::cerr << "[!] Disconnecting client " << info_opt->first
                  << " after exceeding the authenticated chat rate limit\n";
        throw std::runtime_error("Authenticated chat rate limit exceeded");
    }
    const std::string& sender = info_opt->first;
    const std::string* skip_id = &info_opt->second;
    std::string body(message.begin(), message.end());
    const BroadcastStatus status =
        broadcast_message(sender, body, info_opt->second, skip_id);
    if (status == BroadcastStatus::RateLimited) {
        std::cerr << "[!] Disconnecting client " << sender
                  << " after exceeding the authenticated chat fanout budget\n";
        throw std::runtime_error("Authenticated chat fanout limit exceeded");
    }
}

std::optional<std::pair<std::string, std::string>> VpnServer::find_client_info_for_tls(secure::SecureSocket* tls) const {
    std::shared_lock<std::shared_mutex> rlk(client_map_mutex_);
    for (const auto& [ip, entry] : client_map_) {
        if (entry.tls.get() == tls) {
            return std::make_pair(ip, entry.client_id);
        }
    }
    return std::nullopt;
}

void VpnServer::tlsClientEntry(std::shared_ptr<secure::SecureSocket> tls,
                               const std::string&                 src_ip,
                               const std::string&                 client_id,
                               std::shared_ptr<std::atomic<bool>> alive,
                               std::shared_ptr<UdpPeerState>      udp_state,
                               std::string                        peer_key)
{
    std::exception_ptr forwarding_error;
    try {
        tls_to_tun_server(this,
                          session_->get(),
                          tls.get(),
                          src_ip,
                          *alive,
                          session_mutex_);
    } catch (...) {
        forwarding_error = std::current_exception();
    }

    bool release_client_id = false;
    {
        std::lock_guard<std::shared_mutex> lg(client_map_mutex_);
        auto it = client_map_.find(src_ip);
        if (it != client_map_.end() &&
            it->second.client_id == client_id &&
            it->second.tls == tls) {
            client_map_.erase(it);
            release_client_id = true;
        }
    }
    if (release_client_id) {
        ip_pool.release(client_id);
    }

    if (udp_state && !peer_key.empty()) {
        closeAndEraseUdpPeerIfOwned(peer_key, udp_state);
    }

    if (alive) {
        alive->store(false);
    }

    if (forwarding_error) {
        std::rethrow_exception(forwarding_error);
    }
}

// ───────────────────────────────────────────────────────────────────────────────
bool VpnServer::forward_to_client_if_known(const BYTE* packet, UINT size)
{
    if (!is_well_formed_ipv4_packet(packet, size)) {
        return false;
    }
    std::string dst = extract_ipv4_string(packet + 16);

    std::shared_ptr<secure::SecureSocket> destination_tls;
    std::shared_ptr<std::timed_mutex> destination_write_mutex;
    std::string destination_id;
    {
        std::shared_lock<std::shared_mutex> rlk(client_map_mutex_);
        auto it = client_map_.find(dst);
        if (it == client_map_.end()) {
            return false;                   // not a VPN peer
        }

        destination_tls = it->second.tls;
        destination_write_mutex = it->second.write_mutex;
        destination_id = it->second.client_id;
    }

    {
        std::unique_lock<std::timed_mutex> lg{
            *destination_write_mutex, std::defer_lock};
        if (!lg.try_lock_for(std::chrono::milliseconds{100})) {
            // A congested destination is still a known VPN peer. Drop this
            // packet instead of building an unbounded queue behind its writer.
            return true;
        }
        try {
            const int sent = destination_tls->send_record(
                PACKET_TYPE_IP,
                reinterpret_cast<const uint8_t*>(packet),
                static_cast<uint16_t>(size));
            if (sent == static_cast<int>(size)) {
                return true;
            }
        } catch (const std::exception& error) {
            std::cerr << "[!] Send to VPN client " << dst
                      << " failed: " << error.what() << '\n';
        } catch (...) {
            std::cerr << "[!] Send to VPN client " << dst << " failed\n";
        }
    }

    {
        std::unique_lock<std::shared_mutex> lock(client_map_mutex_);
        auto it = client_map_.find(dst);
        if (it != client_map_.end() &&
            it->second.client_id == destination_id &&
            it->second.tls == destination_tls) {
            client_map_.erase(it);
            ip_pool.release(destination_id);
        }
    }
    if (destination_tls) {
        destination_tls->close();
    }
    // The destination was a VPN peer. Treat the packet as consumed even when
    // the failed peer had to be removed, rather than injecting it into Wintun.
    return true;
}
