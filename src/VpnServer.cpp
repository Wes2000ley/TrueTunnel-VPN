//  ──────────────────────────────────────────────────────────────────────────────
//  VpnServer.cpp  (TrueTunnel, multi-client, framed packets)
//  FULL SOURCE — no omissions
//  ──────────────────────────────────────────────────────────────────────────────

#include <array>
#include <algorithm>


// ——— System / library ——————————————————————————————————————————
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <iphlpapi.h>

#include "secure/SecureSocket.h"
#include "secure/SharedSecret.h"
#include "secure/CngUtils.h"

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
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <system_error>

// ——— Project headers ——————————————————————————————————————————
#include "VpnServer.h"
#include "IpPoolManager.h"
#include "core/ConnectionRecovery.h"
#include "utils.hpp"
#include "vpn.hpp"
#include "Networking.h"


// ——— Pragmas ————————————————————————————————————————————————
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace {
std::string peer_source_from_addr(const sockaddr_storage& addr, int len);

constexpr std::size_t kMaximumPendingHandoffRecords = 256U;
constexpr std::size_t kMaximumPendingHandoffBytes =
    256U * secure::kMaximumDatagramPayloadSize;
// FREEZE starts this single finite server-side budget before NEW is accepted.
// The client has the same 450 ms outer bound and reserves its final 50 ms for
// authenticated ABORT/local publication.  No phase may extend this deadline.
constexpr auto kTcpHandoffServerBudget = std::chrono::milliseconds{450};
constexpr auto kTcpHandoffRecoveryFlushBudget =
    std::chrono::milliseconds{50};

[[nodiscard]] bool enqueue_pending_handoff_record(
    const std::shared_ptr<VpnServerPendingOutbound>& pending,
    const std::uint8_t type,
    const std::uint8_t* payload,
    const std::size_t payload_size) noexcept {
    if (!pending || (payload_size != 0U && payload == nullptr) ||
        payload_size > secure::kMaximumDatagramPayloadSize) {
        return false;
    }
    try {
        std::lock_guard lock{pending->mutex};
        if (pending->records.size() >= kMaximumPendingHandoffRecords ||
            pending->bytes > kMaximumPendingHandoffBytes - payload_size) {
            return false;
        }
        VpnServerPendingRecord record{};
        record.type = type;
        if (payload_size != 0U) {
            record.payload.assign(payload, payload + payload_size);
        }
        pending->bytes += payload_size;
        pending->records.push_back(std::move(record));
        return true;
    } catch (...) {
        return false;
    }
}

[[nodiscard]] bool flush_pending_handoff_records(
    const std::shared_ptr<VpnServerPendingOutbound>& pending,
    const std::shared_ptr<secure::SecureSocket>& tls,
    const std::optional<std::chrono::steady_clock::time_point> deadline =
        std::nullopt) noexcept {
    if (!pending || !tls) return true;
    try {
        // Keep the bounded queue locked while flushing. Every caller already
        // owns the per-client write mutex, so producers cannot enqueue behind
        // this barrier. Remove each record only after its send succeeds; if a
        // write fails, the unsent suffix remains available to the rollback.
        std::lock_guard lock{pending->mutex};
        while (!pending->records.empty()) {
            if (deadline && std::chrono::steady_clock::now() >= *deadline) {
                return false;
            }
            const auto& record = pending->records.front();
            const int sent = deadline
                ? tls->send_record_until(
                      record.type, record.payload.data(),
                      static_cast<std::uint16_t>(record.payload.size()),
                      *deadline)
                : tls->send_record(
                      record.type, record.payload.data(),
                      static_cast<std::uint16_t>(record.payload.size()));
            if (sent !=
                static_cast<int>(record.payload.size())) {
                return false;
            }
            pending->bytes -= record.payload.size();
            pending->records.pop_front();
        }
        // bytes is decremented with each successful record; retain the
        // invariant explicitly in case the queue representation changes.
        pending->bytes = 0U;
    } catch (...) {
        return false;
    }
    return true;
}
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
    if (transport_ == TransportProtocol::Tcp &&
        !secure::is_valid_tcp_rotation_policy(rotation_policy_)) {
        throw std::invalid_argument(
            "VPN server TCP rotation policy leaves no usable handoff reserve");
    }
    password_page_locked_ = !password_.empty() &&
        ::VirtualLock(password_.data(), password_.size()) != FALSE;
    if (!password_.empty() && !password_page_locked_) {
        // A server must retain the group credential to authenticate future
        // peers and replacement sessions. Wiping remains guaranteed even on
        // systems where the working-set privilege prevents page locking.
        try {
            std::cerr << "[WARN] Could not page-lock the server VPN credential; "
                         "shutdown will still wipe it securely\n";
        } catch (...) {
        }
    }
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
    heartbeat_watchdog_cv_.notify_all();
    std::lock_guard<std::mutex> lifecycle_guard(lifecycle_mutex_);
    std::cout << "[INFO] Stopping VPN server; notifying clients\n";
    running_ = false;

    // Wake replacement handlers that are waiting on a per-client drain
    // condition before joining TCP workers. The running predicate is checked
    // by those waits, so shutdown does not incur the normal three-second
    // handoff deadline.
    {
        std::vector<std::shared_ptr<std::condition_variable>> handoff_waiters;
        {
            std::shared_lock<std::shared_mutex> map_lock(client_map_mutex_);
            handoff_waiters.reserve(client_map_.size());
            for (const auto& [_, entry] : client_map_) {
                if (entry.handoff_cv) handoff_waiters.push_back(entry.handoff_cv);
            }
        }
        for (const auto& cv : handoff_waiters) {
            cv->notify_all();
        }
    }

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
    if (heartbeat_watchdog_thread_.joinable()) {
        heartbeat_watchdog_thread_.join();
    }
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
        char* const password_bytes = password_.data();
        const std::size_t password_size = password_.size();
        ::SecureZeroMemory(password_bytes, password_size);
        if (password_page_locked_) {
            (void)::VirtualUnlock(password_bytes, password_size);
        }
        password_page_locked_ = false;
        std::string{}.swap(password_);
    }
    std::cout << "[✓] Server shutdown complete\n";
}

bool VpnServer::send_chat(const std::string& text)
{
    if (text.empty()) return false;
    return broadcast_message("server", text, "server-console") ==
           BroadcastStatus::Delivered;
}

#ifdef TRUETUNNEL_INTEGRATION_TEST
void VpnServer::set_integration_drop_heartbeat_acknowledgements(
    const bool drop) noexcept {
    integration_drop_heartbeat_acknowledgements_.store(
        drop, std::memory_order_release);
}

void VpnServer::set_integration_reject_authenticated_clients(
    const std::uint32_t count) noexcept {
    integration_reject_authenticated_clients_.store(
        count, std::memory_order_release);
}

void VpnServer::set_integration_fail_next_session_replacement_commit(
    const bool fail) noexcept {
    integration_fail_next_session_replacement_commit_.store(
        fail, std::memory_order_release);
}

void VpnServer::set_integration_fail_next_session_replacement_after_activate(
    const bool fail) noexcept {
    integration_fail_next_session_replacement_after_activate_.store(
        fail, std::memory_order_release);
}

void VpnServer::set_integration_session_replacement_freeze_delay(
    const std::chrono::milliseconds delay) noexcept {
    const auto bounded = (std::clamp)(
        delay, std::chrono::milliseconds::zero(),
        kTcpHandoffServerBudget - std::chrono::milliseconds{100});
    integration_session_replacement_freeze_delay_ms_.store(
        bounded.count(), std::memory_order_release);
}

void VpnServer::integration_disconnect_all_clients() noexcept {
    std::vector<std::shared_ptr<secure::SecureSocket>> clients;
    try {
        {
            std::shared_lock<std::shared_mutex> map_lock(client_map_mutex_);
            clients.reserve(client_map_.size());
            for (const auto& [_, entry] : client_map_) {
                if (entry.tls) clients.push_back(entry.tls);
            }
        }
        for (const auto& client : clients) {
            try {
                client->close();
            } catch (...) {
            }
        }
    } catch (...) {
        // Integration fault injection must remain safe in cleanup paths.
    }
}

std::uint64_t VpnServer::integration_heartbeat_requests() const noexcept {
    return heartbeat_requests_.load(std::memory_order_acquire);
}

std::uint32_t
VpnServer::integration_rejected_authenticated_clients() const noexcept {
    return integration_rejected_authenticated_clients_.load(
        std::memory_order_acquire);
}

std::size_t VpnServer::integration_connected_client_count() const {
    std::shared_lock<std::shared_mutex> map_lock(client_map_mutex_);
    return client_map_.size();
}

bool VpnServer::consume_integration_authenticated_rejection() noexcept {
    std::uint32_t remaining = integration_reject_authenticated_clients_.load(
        std::memory_order_acquire);
    while (remaining != 0U) {
        if (integration_reject_authenticated_clients_.compare_exchange_weak(
                remaining, remaining - 1U,
                std::memory_order_acq_rel, std::memory_order_acquire)) {
            integration_rejected_authenticated_clients_.fetch_add(
                1U, std::memory_order_relaxed);
            return true;
        }
    }
    return false;
}
#endif

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
    heartbeat_watchdog_thread_ =
        std::thread(&VpnServer::heartbeatWatchdogEntry, this);
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

} // namespace

void VpnServer::heartbeatWatchdogEntry() {
    struct Snapshot {
        std::string ip;
        std::shared_ptr<secure::SecureSocket> tls;
        std::shared_ptr<std::timed_mutex> write_mutex;
        std::shared_ptr<PeerHeartbeatState> heartbeat;
        std::shared_ptr<std::atomic<bool>> replacement_preparing;
        std::shared_ptr<std::atomic<bool>> draining;
        std::shared_ptr<std::atomic<bool>> drain_barrier_sent;
        std::shared_ptr<std::atomic<std::int64_t>> drain_deadline_ticks;
        std::shared_ptr<std::mutex> handoff_mutex;
        std::shared_ptr<std::condition_variable> handoff_cv;
        std::shared_ptr<VpnServerPendingOutbound> pending_outbound;
    };

    while (running_.load(std::memory_order_acquire)) {
        std::unique_lock<std::mutex> wait_lock(heartbeat_watchdog_mutex_);
        if (heartbeat_watchdog_cv_.wait_for(
                wait_lock, std::chrono::milliseconds{100},
                [this]() { return !running_.load(std::memory_order_acquire); })) {
            return;
        }
        wait_lock.unlock();

        std::vector<Snapshot> clients;
        {
            std::shared_lock<std::shared_mutex> map_lock(client_map_mutex_);
            clients.reserve(client_map_.size());
            for (const auto& [ip, entry] : client_map_) {
                clients.push_back(Snapshot{ip, entry.tls, entry.write_mutex,
                                           entry.heartbeat,
                                           entry.replacement_preparing,
                                           entry.draining,
                                           entry.drain_barrier_sent,
                                           entry.drain_deadline_ticks,
                                           entry.handoff_mutex,
                                           entry.handoff_cv,
                                           entry.pending_outbound});
            }
        }

        const auto now = std::chrono::steady_clock::now();
        const auto now_ticks = std::chrono::duration_cast<std::chrono::nanoseconds>(
            now.time_since_epoch()).count();
        for (const auto& client : clients) {
            if (!client.tls || !client.heartbeat) continue;
            const bool preparation_active =
                client.replacement_preparing &&
                client.replacement_preparing->load(
                    std::memory_order_acquire);
            const bool drain_active = client.draining &&
                client.draining->load(std::memory_order_acquire);
            if ((preparation_active || drain_active) &&
                client.drain_deadline_ticks &&
                client.drain_deadline_ticks->load(std::memory_order_acquire) > 0 &&
                now_ticks >= client.drain_deadline_ticks->load(
                                  std::memory_order_acquire)) {
                bool drain_still_owned = false;
                {
                    std::shared_lock<std::shared_mutex> map_lock(
                        client_map_mutex_);
                    const auto it = client_map_.find(client.ip);
                    drain_still_owned =
                        it != client_map_.end() &&
                        it->second.tls == client.tls &&
                        it->second.write_mutex == client.write_mutex &&
                        it->second.pending_outbound == client.pending_outbound &&
                        it->second.replacement_preparing ==
                            client.replacement_preparing &&
                        it->second.draining == client.draining &&
                        it->second.drain_deadline_ticks ==
                            client.drain_deadline_ticks &&
                        it->second.handoff_mutex == client.handoff_mutex &&
                        (it->second.replacement_preparing->load(
                             std::memory_order_acquire) ||
                         it->second.draining->load(
                             std::memory_order_acquire));
                }
                if (drain_still_owned && client.handoff_mutex &&
                    client.handoff_cv) {
                    std::unique_lock<std::timed_mutex> drain_lock{
                        *client.write_mutex, std::defer_lock};
                    if (!drain_lock.try_lock_for(
                            std::chrono::milliseconds{100})) {
                        continue;
                    }
                    // Revalidate after taking the write lock; a replacement
                    // may have committed while the watchdog was acquiring it.
                    std::unique_lock handoff_lock{*client.handoff_mutex};
                    std::unique_lock<std::shared_mutex> map_lock(
                        client_map_mutex_);
                    const auto current = client_map_.find(client.ip);
                    const auto revalidated_now_ticks =
                        std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::steady_clock::now().time_since_epoch())
                            .count();
                    if (current != client_map_.end() &&
                        current->second.tls == client.tls &&
                        current->second.write_mutex == client.write_mutex &&
                        current->second.pending_outbound ==
                            client.pending_outbound &&
                        current->second.replacement_preparing ==
                            client.replacement_preparing &&
                        current->second.draining == client.draining &&
                        current->second.drain_deadline_ticks ==
                            client.drain_deadline_ticks &&
                        current->second.handoff_mutex ==
                            client.handoff_mutex &&
                        (current->second.replacement_preparing->load(
                             std::memory_order_acquire) ||
                         current->second.draining->load(
                             std::memory_order_acquire)) &&
                        current->second.drain_deadline_ticks->load(
                            std::memory_order_acquire) > 0 &&
                        revalidated_now_ticks >=
                            current->second.drain_deadline_ticks->load(
                                std::memory_order_acquire)) {
                        current->second.drain_nonce.fill(0U);
                        current->second.drain_deadline_ticks->store(
                            0, std::memory_order_release);
                        current->second.replacement_preparing->store(
                            false, std::memory_order_release);
                        current->second.draining->store(
                            false, std::memory_order_release);
                        current->second.drain_barrier_sent->store(
                            false, std::memory_order_release);
                        if (current->second.heartbeat) {
                            std::lock_guard heartbeat_lock{
                                current->second.heartbeat->mutex};
                            current->second.heartbeat->handoff_deadline = {};
                            if (current->second.heartbeat->participating) {
                                const auto timeout =
                                    current->second.heartbeat->timeout;
                                current->second.heartbeat->deadline =
                                    std::chrono::steady_clock::now() +
                                    (timeout >
                                             std::chrono::milliseconds::zero()
                                         ? timeout
                                         : std::chrono::seconds{1});
                            }
                        }
                        handoff_lock.unlock();
                        client.handoff_cv->notify_all();
                        map_lock.unlock();
                        if (!flush_pending_handoff_records(
                                client.pending_outbound, client.tls,
                                std::chrono::steady_clock::now() +
                                    kTcpHandoffRecoveryFlushBudget)) {
                            std::cerr << "[!] Failed to flush queued records "
                                         "after expired TCP/TLS handoff\n";
                            client.tls->close();
                        }
                    }
                }
            }
            bool expired = false;
            {
                std::lock_guard<std::mutex> heartbeat_lock(
                    client.heartbeat->mutex);
                if (client.heartbeat->participating &&
                    !client.heartbeat->closing &&
                    now >= client.heartbeat->deadline) {
                    client.heartbeat->closing = true;
                    expired = true;
                }
            }
            if (!expired) continue;

            std::cerr << "[!] Authenticated heartbeat expired for client "
                      << client.ip << "; closing stale session\n";
            try {
                client.tls->close();
            } catch (...) {
            }
        }
    }
}

namespace {

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
bool VpnServer::acceptTcpSessionReplacement(
    const std::shared_ptr<secure::SecureSocket>& tls,
    const std::span<const std::uint8_t> payload,
    std::string& assigned_ip,
    std::string& client_id) {
    if (!tls) return false;

    struct SensitiveBytesGuard final {
        std::uint8_t* bytes;
        std::size_t size;
        ~SensitiveBytesGuard() noexcept {
            if (bytes != nullptr && size != 0U) {
                ::SecureZeroMemory(bytes, size);
            }
        }
    };

    SessionReplacementRequest request{};
    SensitiveBytesGuard request_nonce_guard{
        request.nonce.data(), request.nonce.size()};
    SensitiveBytesGuard request_proof_guard{
        request.proof.data(), request.proof.size()};
    if (!decode_session_replacement_request(payload, request)) return false;

    char ip_text[INET_ADDRSTRLEN]{};
    IN_ADDR assigned_address{};
    std::memcpy(&assigned_address.S_un.S_addr,
                request.assigned_ipv4.data(), request.assigned_ipv4.size());
    if (::inet_ntop(AF_INET, &assigned_address, ip_text,
                    sizeof(ip_text)) == nullptr) {
        return false;
    }
    assigned_ip = ip_text;

    std::shared_ptr<secure::SecureSocket> old_tls;
    std::shared_ptr<std::timed_mutex> old_write_mutex;
    std::shared_ptr<std::shared_timed_mutex> old_ingress_gate;
    std::shared_ptr<std::atomic<bool>> old_replacement_preparing;
    std::shared_ptr<std::atomic<bool>> old_draining;
    std::shared_ptr<std::atomic<bool>> old_drain_barrier_sent;
    std::shared_ptr<std::atomic<std::int64_t>> old_drain_deadline_ticks;
    std::shared_ptr<std::mutex> old_handoff_mutex;
    std::shared_ptr<std::condition_variable> old_handoff_cv;
    std::shared_ptr<PeerHeartbeatState> old_heartbeat;
    std::shared_ptr<VpnServerPendingOutbound> pending_outbound;
    std::array<std::uint8_t, 32> old_binding{};
    std::array<std::uint8_t, 32> new_binding{};
    SensitiveBytesGuard old_binding_guard{
        old_binding.data(), old_binding.size()};
    SensitiveBytesGuard new_binding_guard{
        new_binding.data(), new_binding.size()};
    {
        std::shared_lock<std::shared_mutex> map_lock(client_map_mutex_);
        const auto it = client_map_.find(assigned_ip);
        if (it == client_map_.end() || !it->second.tls ||
            it->second.tls == tls) {
            return false;
        }
        old_tls = it->second.tls;
        old_write_mutex = it->second.write_mutex;
        old_ingress_gate = it->second.ingress_gate;
        old_replacement_preparing = it->second.replacement_preparing;
        old_draining = it->second.draining;
        old_drain_barrier_sent = it->second.drain_barrier_sent;
        old_drain_deadline_ticks = it->second.drain_deadline_ticks;
        old_handoff_mutex = it->second.handoff_mutex;
        old_handoff_cv = it->second.handoff_cv;
        old_heartbeat = it->second.heartbeat;
        pending_outbound = it->second.pending_outbound;
        client_id = it->second.client_id;
        old_binding = it->second.continuity_binding;
    }

    // The replacement TLS handshake has already completed before this point.
    // Binding the proof to both exporters prevents a peer that knows the group
    // credential from transplanting a valid OLD proof onto its own NEW TLS
    // connection.
    new_binding = tls->continuity_binding();
    auto expected_proof = secure::SecureSocket::replacement_proof(
        old_binding, new_binding, request.nonce, request.assigned_ipv4);
    SensitiveBytesGuard expected_proof_guard{
        expected_proof.data(), expected_proof.size()};
    if (secure::ct_memcmp(expected_proof.data(), request.proof.data(),
                          expected_proof.size()) != 0) {
        return false;
    }

    if (!old_write_mutex || !old_ingress_gate ||
        !old_replacement_preparing || !old_draining ||
        !old_drain_deadline_ticks || !old_drain_barrier_sent ||
        !old_handoff_mutex || !old_handoff_cv || !old_heartbeat ||
        !pending_outbound) {
        return false;
    }

    // NEW is admissible only after this exact OLD generation authenticated a
    // FREEZE carrying the same nonce.  That freeze already serialized and
    // queued server egress before the NEW handshake could consume OLD receive
    // headroom.  PREP is not allowed to create or extend the deadline.
    std::int64_t preparation_deadline_ticks = 0;
    bool preparation_owned = false;
    {
        std::unique_lock handoff_lock{*old_handoff_mutex};
        std::shared_lock<std::shared_mutex> map_lock(client_map_mutex_);
        const auto it = client_map_.find(assigned_ip);
        if (it == client_map_.end() || it->second.tls != old_tls ||
            it->second.write_mutex != old_write_mutex ||
            it->second.ingress_gate != old_ingress_gate ||
            it->second.replacement_preparing != old_replacement_preparing ||
            it->second.draining != old_draining ||
            it->second.drain_barrier_sent != old_drain_barrier_sent ||
            it->second.drain_deadline_ticks != old_drain_deadline_ticks ||
            it->second.handoff_mutex != old_handoff_mutex ||
            it->second.handoff_cv != old_handoff_cv ||
            it->second.pending_outbound != pending_outbound ||
            !old_replacement_preparing->load(std::memory_order_acquire) ||
            old_draining->load(std::memory_order_acquire) ||
            secure::ct_memcmp(it->second.drain_nonce.data(),
                              request.nonce.data(), request.nonce.size()) != 0 ||
            !running_.load(std::memory_order_acquire)) {
            return false;
        }
        preparation_deadline_ticks = old_drain_deadline_ticks->load(
            std::memory_order_acquire);
        const auto now_ticks =
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
        if (preparation_deadline_ticks <= now_ticks) return false;
        preparation_owned = true;
    }
    const auto preparation_deadline = std::chrono::steady_clock::time_point{
        std::chrono::duration_cast<std::chrono::steady_clock::duration>(
            std::chrono::nanoseconds{preparation_deadline_ticks})};

    const auto clear_preparation = [&]() noexcept {
        if (!preparation_owned) return;
        std::unique_lock<std::timed_mutex> write_lock{
            *old_write_mutex, std::defer_lock};
        if (!write_lock.try_lock_for(kTcpHandoffRecoveryFlushBudget)) {
            preparation_owned = false;
            try { old_tls->close(); } catch (...) {}
            return;
        }
        bool still_owned = false;
        {
            std::unique_lock handoff_lock{*old_handoff_mutex};
            std::unique_lock<std::shared_mutex> map_lock(client_map_mutex_);
            const auto it = client_map_.find(assigned_ip);
            still_owned = it != client_map_.end() &&
                it->second.tls == old_tls &&
                it->second.replacement_preparing ==
                    old_replacement_preparing &&
                it->second.pending_outbound == pending_outbound &&
                old_replacement_preparing->load(
                    std::memory_order_acquire) &&
                secure::ct_memcmp(it->second.drain_nonce.data(),
                                  request.nonce.data(),
                                  request.nonce.size()) == 0;
            if (still_owned) {
                it->second.drain_nonce.fill(0U);
                old_replacement_preparing->store(
                    false, std::memory_order_release);
                old_drain_barrier_sent->store(
                    false, std::memory_order_release);
                old_drain_deadline_ticks->store(
                    0, std::memory_order_release);
                if (it->second.heartbeat) {
                    std::lock_guard heartbeat_lock{
                        it->second.heartbeat->mutex};
                    it->second.heartbeat->handoff_deadline = {};
                    if (it->second.heartbeat->participating) {
                        const auto timeout = it->second.heartbeat->timeout;
                        it->second.heartbeat->deadline =
                            std::chrono::steady_clock::now() +
                            (timeout > std::chrono::milliseconds::zero()
                                 ? timeout
                                 : std::chrono::seconds{1});
                    }
                }
            }
        }
        old_handoff_cv->notify_all();
        if (still_owned &&
            !flush_pending_handoff_records(
                pending_outbound, old_tls,
                std::chrono::steady_clock::now() +
                    kTcpHandoffRecoveryFlushBudget)) {
            try { old_tls->close(); } catch (...) {}
        }
        preparation_owned = false;
    };

    const auto acknowledgement = encode_session_replacement_ack(request.nonce);
    bool drain_pending = false;
    try {
        if (tls->send_record_until(
                PACKET_TYPE_SESSION_REPLACEMENT_ACK,
                acknowledgement.data(),
                static_cast<std::uint16_t>(acknowledgement.size()),
                preparation_deadline) !=
            static_cast<int>(acknowledgement.size())) {
            clear_preparation();
            return false;
        }
        {
            std::unique_lock handoff_lock{*old_handoff_mutex};
            drain_pending = old_handoff_cv->wait_until(
                handoff_lock, preparation_deadline, [&]() {
                    if (!running_.load(std::memory_order_acquire)) return true;
                    const auto now_ticks =
                        std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::steady_clock::now().time_since_epoch())
                            .count();
                    std::shared_lock<std::shared_mutex> map_lock(
                        client_map_mutex_);
                    const auto it = client_map_.find(assigned_ip);
                    return it != client_map_.end() &&
                        it->second.tls == old_tls &&
                        it->second.write_mutex == old_write_mutex &&
                        it->second.ingress_gate == old_ingress_gate &&
                        it->second.handoff_mutex == old_handoff_mutex &&
                        it->second.handoff_cv == old_handoff_cv &&
                        it->second.replacement_preparing ==
                            old_replacement_preparing &&
                        it->second.draining == old_draining &&
                        it->second.drain_barrier_sent ==
                            old_drain_barrier_sent &&
                        it->second.drain_deadline_ticks ==
                            old_drain_deadline_ticks &&
                        !old_replacement_preparing->load(
                            std::memory_order_acquire) &&
                        old_draining->load(std::memory_order_acquire) &&
                        old_drain_deadline_ticks->load(
                            std::memory_order_acquire) > now_ticks &&
                        secure::ct_memcmp(it->second.drain_nonce.data(),
                                          request.nonce.data(),
                                          request.nonce.size()) == 0;
                });
        }
        if (!drain_pending || !running_.load(std::memory_order_acquire)) {
            clear_preparation();
            return false;
        }
    } catch (...) {
        clear_preparation();
        throw;
    }
    preparation_owned = false;
    const auto published_deadline_ticks = old_drain_deadline_ticks->load(
        std::memory_order_acquire);
    const auto handoff_deadline = std::chrono::steady_clock::time_point{
        std::chrono::duration_cast<std::chrono::steady_clock::duration>(
            std::chrono::nanoseconds{published_deadline_ticks})};
    if (published_deadline_ticks <= 0 ||
        std::chrono::steady_clock::now() >= handoff_deadline) {
        return false;
    }

    // The exclusive ingress lease and stable OLD write lock span the entire
    // decision.  No decrypted OLD record or outbound application record can
    // overtake the barrier, publication, COMMIT, or final receipt.
    std::unique_lock<std::shared_timed_mutex> ingress_lock{
        *old_ingress_gate, std::defer_lock};
    if (!ingress_lock.try_lock_until(handoff_deadline)) return false;
    std::unique_lock<std::timed_mutex> write_lock{
        *old_write_mutex, std::defer_lock};
    if (!write_lock.try_lock_until(handoff_deadline)) return false;

    bool old_state_ready = false;
    {
        std::unique_lock handoff_lock{*old_handoff_mutex};
        std::unique_lock<std::shared_mutex> map_lock(client_map_mutex_);
        const auto it = client_map_.find(assigned_ip);
        old_state_ready =
            it != client_map_.end() && it->second.tls == old_tls &&
            it->second.ingress_gate == old_ingress_gate &&
            it->second.replacement_preparing == old_replacement_preparing &&
            it->second.draining == old_draining &&
            it->second.drain_barrier_sent == old_drain_barrier_sent &&
            it->second.handoff_mutex == old_handoff_mutex &&
            it->second.handoff_cv == old_handoff_cv &&
            it->second.drain_deadline_ticks == old_drain_deadline_ticks &&
            it->second.pending_outbound == pending_outbound &&
            secure::ct_memcmp(it->second.continuity_binding.data(),
                              old_binding.data(), old_binding.size()) == 0 &&
            secure::ct_memcmp(it->second.drain_nonce.data(),
                              request.nonce.data(), request.nonce.size()) == 0 &&
            !old_replacement_preparing->load(std::memory_order_acquire) &&
            old_draining->load(std::memory_order_acquire) &&
            !old_drain_barrier_sent->load(std::memory_order_acquire) &&
            running_.load(std::memory_order_acquire);
    }
    if (!old_state_ready) return false;

    // Records queued after PREP belong after the OLD barrier. They are kept
    // unsent until NEW is committed; flushing them on OLD here would consume
    // the client's receive reserve and defeat the egress freeze.
    const auto barrier_frame = encode_session_drain_frame(request.nonce);
    if (old_tls->send_record_until(
            PACKET_TYPE_SESSION_DRAIN_BARRIER,
            barrier_frame.data(), static_cast<std::uint16_t>(barrier_frame.size()),
            handoff_deadline) != static_cast<int>(barrier_frame.size())) {
        return false;
    }

    {
        std::unique_lock handoff_lock{*old_handoff_mutex};
        std::unique_lock<std::shared_mutex> map_lock(client_map_mutex_);
        const auto it = client_map_.find(assigned_ip);
        if (it == client_map_.end() || it->second.tls != old_tls ||
            it->second.pending_outbound != pending_outbound ||
            secure::ct_memcmp(it->second.drain_nonce.data(), request.nonce.data(),
                              request.nonce.size()) != 0) {
            return false;
        }
        it->second.drain_barrier_sent->store(true, std::memory_order_release);
    }
    old_handoff_cv->notify_all();

#ifdef TRUETUNNEL_INTEGRATION_TEST
    // The fault hook is intentionally pre-decision.  It exercises the
    // authenticated ABORT rollback path without creating a split-brain map.
    if (integration_fail_next_session_replacement_commit_.exchange(
            false, std::memory_order_acq_rel)) {
        throw std::runtime_error(
            "integration-injected pre-activate TCP replacement failure");
    }
#endif

    // READY is a reversible checkpoint.  The client must explicitly send
    // ACTIVATE before this function may publish NEW.
    if (tls->send_record_until(
            PACKET_TYPE_SESSION_REPLACEMENT_READY,
            acknowledgement.data(),
            static_cast<std::uint16_t>(acknowledgement.size()),
            handoff_deadline) != static_cast<int>(acknowledgement.size())) {
        return false;
    }
    std::array<std::uint8_t, kSessionReplacementAckSize> activation{};
    SensitiveBytesGuard activation_guard{
        activation.data(), activation.size()};
    std::uint8_t activation_type = 0U;
    const int activation_size = tls->recv_record_until(
        activation_type, activation.data(), activation.size(), handoff_deadline);
    if (activation_size != static_cast<int>(activation.size()) ||
        activation_type != PACKET_TYPE_SESSION_REPLACEMENT_ACTIVATE) {
        return false;
    }
    std::array<std::uint8_t, kSessionReplacementNonceSize> activation_nonce{};
    SensitiveBytesGuard activation_nonce_guard{
        activation_nonce.data(), activation_nonce.size()};
    if (!decode_session_replacement_ack(activation, activation_nonce) ||
        secure::ct_memcmp(activation_nonce.data(), request.nonce.data(),
                          request.nonce.size()) != 0) {
        return false;
    }

    std::shared_ptr<PeerHeartbeatState> new_heartbeat;
    std::shared_ptr<std::shared_timed_mutex> new_ingress_gate;

    // ACTIVATE has been sent and accepted.  From here on, failure is
    // irreversible: erase only this exact map entry and release the IP once.
    const auto fail_after_activate = [&]() noexcept {
        bool release_ip = false;
        {
            std::unique_lock<std::shared_mutex> map_lock(client_map_mutex_);
            const auto it = client_map_.find(assigned_ip);
            if (it != client_map_.end() && it->second.tls == tls &&
                it->second.client_id == client_id) {
                ::SecureZeroMemory(it->second.continuity_binding.data(),
                                   it->second.continuity_binding.size());
                client_map_.erase(it);
                release_ip = true;
            }
        }
        if (release_ip) ip_pool.release(client_id);
        try { old_tls->close(); } catch (...) {}
        try { tls->close(); } catch (...) {}
    };

    try {
#ifdef TRUETUNNEL_INTEGRATION_TEST
        if (integration_fail_next_session_replacement_after_activate_.exchange(
                false, std::memory_order_acq_rel)) {
            throw std::runtime_error(
                "integration-injected post-activate TCP replacement failure");
        }
#endif
        new_heartbeat = std::make_shared<PeerHeartbeatState>();
        new_ingress_gate = std::make_shared<std::shared_timed_mutex>();
        {
            std::lock_guard heartbeat_lock{old_heartbeat->mutex};
            new_heartbeat->participating = old_heartbeat->participating;
            new_heartbeat->closing = old_heartbeat->closing;
            new_heartbeat->timeout = old_heartbeat->timeout;
            if (new_heartbeat->participating) {
                new_heartbeat->last_request = std::chrono::steady_clock::now();
                // Keep the same finite grace through COMMIT_ACK.  The NEW map
                // is published before that receipt, so a 100/200 ms watchdog
                // must not close a healthy handoff still inside the 450 ms
                // server budget.
                new_heartbeat->handoff_deadline = handoff_deadline;
                new_heartbeat->deadline = handoff_deadline +
                    (new_heartbeat->timeout > std::chrono::milliseconds::zero()
                         ? new_heartbeat->timeout
                         : std::chrono::seconds{1});
            }
        }
        {
            std::unique_lock handoff_lock{*old_handoff_mutex};
            std::unique_lock<std::shared_mutex> map_lock(client_map_mutex_);
            const auto it = client_map_.find(assigned_ip);
            if (it == client_map_.end() || it->second.tls != old_tls ||
                it->second.ingress_gate != old_ingress_gate ||
                it->second.pending_outbound != pending_outbound ||
                !it->second.drain_barrier_sent->load(
                    std::memory_order_acquire) ||
                secure::ct_memcmp(it->second.drain_nonce.data(),
                                  request.nonce.data(), request.nonce.size()) != 0 ||
                !running_.load(std::memory_order_acquire)) {
                throw std::runtime_error(
                    "TCP/TLS handoff state changed before activation");
            }
            ::SecureZeroMemory(it->second.continuity_binding.data(),
                               it->second.continuity_binding.size());
            it->second.tls = tls;
            it->second.ingress_gate = new_ingress_gate;
            it->second.heartbeat = new_heartbeat;
            it->second.continuity_binding = new_binding;
            it->second.drain_nonce.fill(0U);
            it->second.replacement_preparing->store(
                false, std::memory_order_release);
            it->second.drain_barrier_sent->store(false,
                                                 std::memory_order_release);
            it->second.draining->store(false, std::memory_order_release);
            it->second.drain_deadline_ticks->store(0,
                                                   std::memory_order_release);
        }
        old_handoff_cv->notify_all();

        if (tls->send_record_until(
                PACKET_TYPE_SESSION_REPLACEMENT_COMMIT,
                acknowledgement.data(),
                static_cast<std::uint16_t>(acknowledgement.size()),
                handoff_deadline) != static_cast<int>(acknowledgement.size())) {
            throw std::runtime_error("TLS replacement commit write failed");
        }
        std::array<std::uint8_t, kSessionReplacementAckSize> commit_ack{};
        SensitiveBytesGuard commit_ack_guard{
            commit_ack.data(), commit_ack.size()};
        std::uint8_t commit_ack_type = 0U;
        const int commit_ack_size = tls->recv_record_until(
            commit_ack_type, commit_ack.data(), commit_ack.size(),
            handoff_deadline);
        if (commit_ack_size != static_cast<int>(commit_ack.size()) ||
            commit_ack_type != PACKET_TYPE_SESSION_REPLACEMENT_COMMIT_ACK ||
            !decode_session_replacement_ack(commit_ack, activation_nonce) ||
            secure::ct_memcmp(activation_nonce.data(), request.nonce.data(),
                              request.nonce.size()) != 0) {
            throw std::runtime_error(
                "TLS replacement commit receipt was invalid or lost");
        }
        // write_lock is the same per-client mutex retained across publication.
        // Flush every PREP/DRAIN-queued application record to NEW before any
        // later sender can acquire it, preserving order without spending OLD's
        // two reserved receive-control slots.
        if (!flush_pending_handoff_records(pending_outbound, tls,
                                           handoff_deadline)) {
            throw std::runtime_error(
                "TLS replacement could not flush queued records on NEW");
        }
        {
            std::shared_ptr<PeerHeartbeatState> completed_heartbeat;
            {
                std::shared_lock<std::shared_mutex> map_lock(
                    client_map_mutex_);
                const auto it = client_map_.find(assigned_ip);
                if (it != client_map_.end() && it->second.tls == tls) {
                    completed_heartbeat = it->second.heartbeat;
                }
            }
            if (completed_heartbeat) {
                std::lock_guard heartbeat_lock{completed_heartbeat->mutex};
                completed_heartbeat->handoff_deadline = {};
                if (completed_heartbeat->participating) {
                    completed_heartbeat->deadline =
                        std::chrono::steady_clock::now() +
                        (completed_heartbeat->timeout >
                                 std::chrono::milliseconds::zero()
                             ? completed_heartbeat->timeout
                             : std::chrono::seconds{1});
                }
            }
        }
        old_tls->close();
        return true;
    } catch (...) {
        // ACTIVATE has already been authenticated.  There is no safe rollback
        // to OLD after this point, even if publication itself failed; closing
        // both generations is the only way to avoid split-brain state.
        fail_after_activate();
        return false;
    }
}

void VpnServer::handleClient(SOCKET sock,
                             std::shared_ptr<std::atomic<bool>> alive)
{
    if (!alive) {
        alive = std::make_shared<std::atomic<bool>>(true);
    }

    std::string cid;
    std::string leased_ip;
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
    const auto release_client_lease_if_owned = [this, &cid, &leased_ip,
                                                  &tls]() noexcept {
        if (cid.empty()) return;
        bool release_lease = leased_ip.empty();
        {
            std::unique_lock<std::shared_mutex> map_lock(client_map_mutex_);
            if (!leased_ip.empty()) {
                const auto it = client_map_.find(leased_ip);
                if (it == client_map_.end()) {
                    release_lease = true;
                } else if (it->second.client_id == cid && it->second.tls == tls) {
                    client_map_.erase(it);
                    release_lease = true;
                } else if (it->second.client_id == cid) {
                    // The logical client/IP may already belong to a replacement
                    // TLS generation. Never release that generation's lease.
                    release_lease = false;
                } else {
                    // A conflicting map entry belongs to somebody else. Release
                    // only this handler's tentative/confirmed pool assignment.
                    release_lease = true;
                }
            }
            if (release_lease) ip_pool.release(cid);
        }
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
#ifdef TRUETUNNEL_INTEGRATION_TEST
        if (consume_integration_authenticated_rejection()) {
            throw std::runtime_error(
                "integration-injected rejection after TCP authentication");
        }
#endif

        int flag = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));  // ✅ actual client socket

        uint8_t typ = 0;
        std::array<std::uint8_t, 256U> req{};
        const int rn = tls->recv_record(typ, req.data(), req.size());
        CHECK(rn > 0, "empty initial client control record");
        if (typ == PACKET_TYPE_SESSION_REPLACEMENT) {
            std::string replacement_ip;
            std::string replacement_client_id;
            CHECK(acceptTcpSessionReplacement(
                      tls,
                  std::span<const std::uint8_t>{req.data(),
                                                static_cast<std::size_t>(rn)},
                  replacement_ip,
                  replacement_client_id),
                  "TLS session replacement was rejected");
            set_socket_timeouts(sock, 0U);
            unregister_pending_tls();
            tlsClientEntry(tls,
                           replacement_ip,
                           replacement_client_id,
                           alive,
                           std::shared_ptr<UdpPeerState>{},
                           std::string{});
            return;
        }
        CHECK(rn == static_cast<int>(kConfigRequest.size()) &&
                  typ == PACKET_TYPE_MSG &&
                  std::memcmp(req.data(), kConfigRequest.data(),
                              kConfigRequest.size()) == 0,
              "bad initial config request");

        cid = std::to_string(reinterpret_cast<uintptr_t>(tls.get()));
        auto ip_opt     = ip_pool.assignTentative(cid);
        CHECK(ip_opt, "no free IPs");
        std::string ip = *ip_opt;
        leased_ip = ip;

        std::string cfg = "VPN_CFG:IP=" + ip + ";GW=10.10.100.1;MASK=255.255.255.255";
        if (tls->send_record(PACKET_TYPE_MSG, (const uint8_t*)cfg.data(), (uint16_t)cfg.size()) < 0) {
            throw std::runtime_error("Failed to deliver config to client");
        }
        set_socket_timeouts(sock, 0U);

        ip_pool.confirm(cid);

        {
            auto continuity_binding = tls->continuity_binding();
            std::unique_lock<std::shared_mutex> ul(client_map_mutex_);
            CHECK(running_.load(std::memory_order_acquire), "server stopping");
            const bool inserted = client_map_.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(ip),
                std::forward_as_tuple(tls, cid,
                                      std::move(continuity_binding))).second;
            CHECK(inserted, "assigned IP already registered");
            ::SecureZeroMemory(continuity_binding.data(),
                               continuity_binding.size());
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
        release_client_lease_if_owned();
        if (tls) {
            tls->close();
            unregister_pending_tls();
        } else {
            closesocket(sock);
        }
    }
    catch (...) {
        std::cerr << "[!] client: unknown failure\n";
        release_client_lease_if_owned();
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
#ifdef TRUETUNNEL_INTEGRATION_TEST
        if (consume_integration_authenticated_rejection()) {
            throw std::runtime_error(
                "integration-injected rejection after UDP authentication");
        }
#endif

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
        std::shared_ptr<VpnServerPendingOutbound> pending_outbound;
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
                ip, entry.client_id, entry.tls, entry.write_mutex,
                entry.pending_outbound});
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
        std::shared_ptr<secure::SecureSocket> destination_tls;
        bool current_client = false;
        bool egress_paused = false;
        {
            std::shared_lock map_lock{client_map_mutex_};
            const auto it = client_map_.find(client.ip);
            current_client = it != client_map_.end() &&
                it->second.client_id == client.id &&
                it->second.write_mutex == client.write_mutex &&
                it->second.pending_outbound == client.pending_outbound;
            if (current_client) destination_tls = it->second.tls;
            egress_paused = current_client &&
                ((it->second.replacement_preparing &&
                  it->second.replacement_preparing->load(
                      std::memory_order_acquire)) ||
                 (it->second.draining &&
                  it->second.draining->load(std::memory_order_acquire)));
        }
        if (!current_client || !destination_tls) continue;
        if (egress_paused) {
            if (!enqueue_pending_handoff_record(
                    client.pending_outbound, PACKET_TYPE_MSG,
                    reinterpret_cast<const std::uint8_t*>(payload.data()),
                    payload.size())) {
                std::cerr << "[!] Handoff queue full for client " << client.ip
                          << "; dropping chat delivery\n";
                all_ok = false;
            }
            continue;
        }

        std::string failure_text;
        try {
            const int sent = destination_tls->send_record(
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
            auto failed = client;
            failed.tls = std::move(destination_tls);
            dead.push_back(std::move(failed));
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

bool VpnServer::handle_control_record(
    secure::SecureSocket* tls,
    const std::string& assigned_ip,
    const std::uint8_t type,
    const std::span<const std::uint8_t> payload) {
    if (tls == nullptr) return false;

    if (type == PACKET_TYPE_SESSION_REPLACEMENT_FREEZE ||
        type == PACKET_TYPE_SESSION_DRAIN_REQUEST ||
        type == PACKET_TYPE_SESSION_DRAIN_ABORT) {
        std::array<std::uint8_t, kSessionReplacementNonceSize> nonce{};
        if (!decode_session_drain_frame(payload, nonce)) {
            // A malformed control record must not tear down the still-valid
            // generation; it is simply ignored after TLS authentication.
            return true;
        }

        std::shared_ptr<secure::SecureSocket> authenticated_tls;
        std::shared_ptr<std::timed_mutex> write_mutex;
        std::shared_ptr<std::atomic<bool>> replacement_preparing;
        std::shared_ptr<std::atomic<bool>> draining;
        std::shared_ptr<std::atomic<bool>> drain_barrier_sent;
        std::shared_ptr<std::atomic<std::int64_t>> drain_deadline_ticks;
        std::shared_ptr<std::mutex> handoff_mutex;
        std::shared_ptr<std::condition_variable> handoff_cv;
        std::shared_ptr<VpnServerPendingOutbound> pending_outbound;
        std::shared_ptr<PeerHeartbeatState> heartbeat;
        bool already_draining = false;
        bool already_preparing = false;
        bool prepared_nonce_matches = false;
        bool abort_nonce_matches = false;
        {
            std::shared_lock<std::shared_mutex> map_lock(client_map_mutex_);
            const auto it = client_map_.find(assigned_ip);
            if (it != client_map_.end() && it->second.tls.get() == tls)
                handoff_mutex = it->second.handoff_mutex;
        }
        // drain_nonce is protected by handoff_mutex (the atomic state flags
        // alone are not sufficient). Re-read the map after taking that lock
        // so an ABORT cannot race a concurrent drain publication.
        if (handoff_mutex) {
            std::lock_guard handoff_lock{*handoff_mutex};
            std::shared_lock<std::shared_mutex> map_lock(client_map_mutex_);
            const auto it = client_map_.find(assigned_ip);
            if (it != client_map_.end() && it->second.tls.get() == tls &&
                it->second.handoff_mutex == handoff_mutex) {
                authenticated_tls = it->second.tls;
                write_mutex = it->second.write_mutex;
                replacement_preparing =
                    it->second.replacement_preparing;
                draining = it->second.draining;
                drain_barrier_sent = it->second.drain_barrier_sent;
                drain_deadline_ticks = it->second.drain_deadline_ticks;
                handoff_cv = it->second.handoff_cv;
                pending_outbound = it->second.pending_outbound;
                heartbeat = it->second.heartbeat;
                already_draining = draining &&
                    draining->load(std::memory_order_acquire);
                already_preparing = replacement_preparing &&
                    replacement_preparing->load(
                        std::memory_order_acquire);
                if (type == PACKET_TYPE_SESSION_DRAIN_REQUEST &&
                    replacement_preparing &&
                    replacement_preparing->load(
                        std::memory_order_acquire) &&
                    secure::ct_memcmp(it->second.drain_nonce.data(),
                                      nonce.data(), nonce.size()) == 0) {
                    prepared_nonce_matches = true;
                }
                if (type == PACKET_TYPE_SESSION_DRAIN_ABORT &&
                    secure::ct_memcmp(it->second.drain_nonce.data(),
                                      nonce.data(), nonce.size()) == 0) {
                    abort_nonce_matches = true;
                }
            }
        }
        if (!authenticated_tls || !write_mutex || !replacement_preparing ||
            !draining ||
            !drain_barrier_sent || !drain_deadline_ticks ||
            !handoff_mutex || !handoff_cv) {
            ::SecureZeroMemory(nonce.data(), nonce.size());
            return true;
        }
        if (type == PACKET_TYPE_SESSION_REPLACEMENT_FREEZE) {
            if (already_preparing || already_draining || !pending_outbound ||
                !heartbeat) {
                ::SecureZeroMemory(nonce.data(), nonce.size());
                return true;
            }

            const auto freeze_deadline =
                std::chrono::steady_clock::now() + kTcpHandoffServerBudget;
#ifdef TRUETUNNEL_INTEGRATION_TEST
            const auto integration_freeze_received =
                std::chrono::steady_clock::now();
#endif
            const auto freeze_deadline_ticks =
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    freeze_deadline.time_since_epoch()).count();
            std::unique_lock<std::timed_mutex> freeze_lock{
                *write_mutex, std::defer_lock};
            if (!freeze_lock.try_lock_until(freeze_deadline)) {
                ::SecureZeroMemory(nonce.data(), nonce.size());
                return true;
            }
#ifdef TRUETUNNEL_INTEGRATION_TEST
            std::cout << "[E2E][FREEZE] server writer acquired after "
                      << std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock::now() -
                             integration_freeze_received)
                             .count()
                      << " ms\n";
#endif

            // After receiving FREEZE, OLD must still carry FREEZE_ACK,
            // DRAIN_ACK, and BARRIER in the server-to-client direction.  It
            // must also accept DRAIN followed by a possible ABORT.  Check the
            // exact prospective reserve before publishing the egress gate.
            {
                constexpr std::uint64_t kRequiredSentRecords = 3U;
                constexpr std::uint64_t kRequiredReceivedRecords = 2U;
                constexpr std::uint64_t kRequiredSentBytes =
                    3U * static_cast<std::uint64_t>(kSessionDrainFrameSize);
                constexpr std::uint64_t kRequiredReceivedBytes =
                    2U * static_cast<std::uint64_t>(kSessionDrainFrameSize);
                const auto stats = authenticated_tls->rotation_stats();
                const auto insufficient = [](
                    const std::uint64_t value, const std::uint64_t limit,
                    const std::uint64_t required) noexcept {
                    return limit != 0U &&
                        (value >= limit || limit - value < required);
                };
                const auto age_limit =
                    secure::rotation_age_limit_microseconds(
                        rotation_policy_.max_age);
                const auto required_age = static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::microseconds>(
                        kTcpHandoffServerBudget).count());
                if (insufficient(stats.sent_records,
                                 rotation_policy_.max_records,
                                 kRequiredSentRecords) ||
                    insufficient(stats.received_records,
                                 rotation_policy_.max_records,
                                 kRequiredReceivedRecords) ||
                    insufficient(stats.sent_bytes,
                                 rotation_policy_.max_bytes,
                                 kRequiredSentBytes) ||
                    insufficient(stats.received_bytes,
                                 rotation_policy_.max_bytes,
                                 kRequiredReceivedBytes) ||
                    (age_limit != 0U &&
                     (stats.age_microseconds >= age_limit ||
                      age_limit - stats.age_microseconds < required_age))) {
                    ::SecureZeroMemory(nonce.data(), nonce.size());
                    authenticated_tls->close();
                    return false;
                }
            }

            bool freeze_owned = false;
            {
                std::unique_lock handoff_lock{*handoff_mutex};
                std::unique_lock<std::shared_mutex> map_lock(
                    client_map_mutex_);
                const auto it = client_map_.find(assigned_ip);
                if (it == client_map_.end() ||
                    it->second.tls != authenticated_tls ||
                    it->second.tls.get() != tls ||
                    it->second.write_mutex != write_mutex ||
                    it->second.replacement_preparing !=
                        replacement_preparing ||
                    it->second.draining != draining ||
                    it->second.drain_barrier_sent != drain_barrier_sent ||
                    it->second.drain_deadline_ticks != drain_deadline_ticks ||
                    it->second.handoff_mutex != handoff_mutex ||
                    it->second.handoff_cv != handoff_cv ||
                    it->second.pending_outbound != pending_outbound ||
                    replacement_preparing->load(std::memory_order_acquire) ||
                    draining->load(std::memory_order_acquire) ||
                    !running_.load(std::memory_order_acquire)) {
                    ::SecureZeroMemory(nonce.data(), nonce.size());
                    return true;
                }
                {
                    std::lock_guard heartbeat_lock{heartbeat->mutex};
                    if (heartbeat->closing) {
                        ::SecureZeroMemory(nonce.data(), nonce.size());
                        return true;
                    }
                    const auto timeout = heartbeat->timeout >
                            std::chrono::milliseconds::zero()
                        ? heartbeat->timeout
                        : std::chrono::seconds{1};
                    heartbeat->handoff_deadline = freeze_deadline;
                    heartbeat->deadline = freeze_deadline + timeout;
                }
                it->second.drain_nonce = nonce;
                drain_barrier_sent->store(false, std::memory_order_release);
                drain_deadline_ticks->store(
                    freeze_deadline_ticks, std::memory_order_release);
                replacement_preparing->store(
                    true, std::memory_order_release);
                freeze_owned = true;
            }

            const auto clear_failed_freeze = [&]() noexcept {
                if (!freeze_owned) return;
                // The FREEZE gate is already published, so ordinary egress
                // takes this writer only long enough to enqueue. Reacquire it
                // before clearing the gate and flushing to preserve the same
                // serialization used by a successful handoff.
                std::unique_lock<std::timed_mutex> recovery_lock{
                    *write_mutex, std::defer_lock};
                if (!recovery_lock.try_lock_for(
                        kTcpHandoffRecoveryFlushBudget)) {
                    freeze_owned = false;
                    authenticated_tls->close();
                    return;
                }
                bool still_owned = false;
                {
                    std::unique_lock handoff_lock{*handoff_mutex};
                    std::unique_lock<std::shared_mutex> map_lock(
                        client_map_mutex_);
                    const auto it = client_map_.find(assigned_ip);
                    still_owned = it != client_map_.end() &&
                        it->second.tls == authenticated_tls &&
                        it->second.pending_outbound == pending_outbound &&
                        replacement_preparing->load(
                            std::memory_order_acquire) &&
                        !draining->load(std::memory_order_acquire) &&
                        secure::ct_memcmp(it->second.drain_nonce.data(),
                                          nonce.data(), nonce.size()) == 0;
                    if (still_owned) {
                        it->second.drain_nonce.fill(0U);
                        replacement_preparing->store(
                            false, std::memory_order_release);
                        draining->store(false, std::memory_order_release);
                        drain_barrier_sent->store(
                            false, std::memory_order_release);
                        drain_deadline_ticks->store(
                            0, std::memory_order_release);
                        std::lock_guard heartbeat_lock{heartbeat->mutex};
                        heartbeat->handoff_deadline = {};
                        if (heartbeat->participating) {
                            const auto timeout = heartbeat->timeout;
                            heartbeat->deadline =
                                std::chrono::steady_clock::now() +
                                (timeout > std::chrono::milliseconds::zero()
                                     ? timeout
                                     : std::chrono::seconds{1});
                        }
                    }
                }
                handoff_cv->notify_all();
                if (still_owned &&
                    !flush_pending_handoff_records(
                        pending_outbound, authenticated_tls,
                        std::chrono::steady_clock::now() +
                            kTcpHandoffRecoveryFlushBudget)) {
                    authenticated_tls->close();
                }
                freeze_owned = false;
            };

            // Publishing replacement_preparing while holding the stable writer
            // places every already-started application write before FREEZE_ACK.
            // Release the writer after publication: later egress revalidates the
            // gate and enters pending_outbound, avoiding packet loss from its
            // normal 100 ms congestion budget while this control is in flight.
            freeze_lock.unlock();
            try {
#ifdef TRUETUNNEL_INTEGRATION_TEST
                const auto injected_delay = std::chrono::milliseconds{
                    integration_session_replacement_freeze_delay_ms_.exchange(
                        0, std::memory_order_acq_rel)};
                if (injected_delay > std::chrono::milliseconds::zero()) {
                    std::this_thread::sleep_for(injected_delay);
                }
#endif
                const auto frame = encode_session_drain_frame(nonce);
                if (authenticated_tls->send_record_until(
                        PACKET_TYPE_SESSION_REPLACEMENT_FREEZE_ACK,
                        frame.data(),
                        static_cast<std::uint16_t>(frame.size()),
                        freeze_deadline) != static_cast<int>(frame.size())) {
                    clear_failed_freeze();
                } else {
#ifdef TRUETUNNEL_INTEGRATION_TEST
                    std::cout << "[E2E][FREEZE] acknowledgement sent after "
                              << std::chrono::duration_cast<
                                     std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() -
                                     integration_freeze_received)
                                     .count()
                              << " ms\n";
#endif
                    handoff_cv->notify_all();
                }
            } catch (...) {
                clear_failed_freeze();
            }
            ::SecureZeroMemory(nonce.data(), nonce.size());
            return true;
        }
        if (type == PACKET_TYPE_SESSION_DRAIN_ABORT) {
#ifdef TRUETUNNEL_INTEGRATION_TEST
            std::cout << "[E2E][ABORT] server received rollback; nonce "
                      << (abort_nonce_matches ? "matched" : "mismatched")
                      << '\n';
#endif
            if (abort_nonce_matches) {
                std::unique_lock<std::timed_mutex> abort_lock{
                    *write_mutex, std::defer_lock};
                if (abort_lock.try_lock_for(kTcpHandoffRecoveryFlushBudget)) {
                    bool still_owned = false;
                    {
                        std::unique_lock handoff_lock{*handoff_mutex};
                        std::unique_lock<std::shared_mutex> map_lock(
                            client_map_mutex_);
                        const auto it = client_map_.find(assigned_ip);
                        still_owned =
                            it != client_map_.end() &&
                            it->second.tls.get() == tls &&
                            it->second.pending_outbound == pending_outbound &&
                            secure::ct_memcmp(it->second.drain_nonce.data(),
                                              nonce.data(), nonce.size()) == 0;
                        if (still_owned) {
                            it->second.drain_nonce.fill(0U);
                            it->second.replacement_preparing->store(
                                false, std::memory_order_release);
                            it->second.drain_barrier_sent->store(
                                false, std::memory_order_release);
                            it->second.draining->store(
                                false, std::memory_order_release);
                            it->second.drain_deadline_ticks->store(
                                0, std::memory_order_release);
                            if (it->second.heartbeat) {
                                std::lock_guard heartbeat_lock{
                                    it->second.heartbeat->mutex};
                                it->second.heartbeat->handoff_deadline = {};
                                if (it->second.heartbeat->participating) {
                                    const auto timeout =
                                        it->second.heartbeat->timeout;
                                    it->second.heartbeat->deadline =
                                        std::chrono::steady_clock::now() +
                                        (timeout > std::chrono::milliseconds::zero()
                                             ? timeout
                                             : std::chrono::seconds{1});
                                }
                            }
                        }
                        handoff_lock.unlock();
                        handoff_cv->notify_all();
                    }
                    const bool flushed = !still_owned ||
                        flush_pending_handoff_records(
                            pending_outbound, authenticated_tls,
                            std::chrono::steady_clock::now() +
                                kTcpHandoffRecoveryFlushBudget);
#ifdef TRUETUNNEL_INTEGRATION_TEST
                    std::cout << "[E2E][ABORT] server rollback ownership="
                              << (still_owned ? "current" : "stale")
                              << ", queued flush="
                              << (flushed ? "complete" : "failed") << '\n';
#endif
                    if (still_owned && !flushed) {
                        std::cerr << "[!] Failed to flush queued records after "
                                     "TCP/TLS replacement abort\n";
                        authenticated_tls->close();
                    }
#ifdef TRUETUNNEL_INTEGRATION_TEST
                } else {
                    std::cout << "[E2E][ABORT] server rollback writer lock timed out\n";
#endif
                }
            }
            ::SecureZeroMemory(nonce.data(), nonce.size());
            return true;
        }
        if (already_draining) {
            ::SecureZeroMemory(nonce.data(), nonce.size());
            return true;
        }
        if (!prepared_nonce_matches) {
            // DRAIN is valid only for the nonce that OLD authenticated during
            // FREEZE. The NEW handler separately proves continuity before it
            // can observe or commit this transition.
            ::SecureZeroMemory(nonce.data(), nonce.size());
            return true;
        }

        // Transition PREP within its original egress-freeze deadline. A late
        // DRAIN must not silently extend a preparation whose rollback may
        // already be restoring OLD traffic.
        const auto preparation_ticks = drain_deadline_ticks->load(
            std::memory_order_acquire);
        if (preparation_ticks <= 0) {
            ::SecureZeroMemory(nonce.data(), nonce.size());
            return true;
        }
        const auto preparation_transition_deadline =
            std::chrono::steady_clock::time_point{
                std::chrono::duration_cast<
                    std::chrono::steady_clock::duration>(
                    std::chrono::nanoseconds{preparation_ticks})};
        if (std::chrono::steady_clock::now() >=
            preparation_transition_deadline) {
            ::SecureZeroMemory(nonce.data(), nonce.size());
            return true;
        }
        std::unique_lock<std::timed_mutex> drain_lock{
            *write_mutex, std::defer_lock};
        if (!drain_lock.try_lock_until(preparation_transition_deadline)) {
            ::SecureZeroMemory(nonce.data(), nonce.size());
            return true;
        }
        // Acquire the outbound lock before publishing the drain. The
        // replacement waiter also needs this lock, so it cannot send BARRIER
        // or COMMIT until this handler has put DRAIN_ACK on OLD first.
        const auto handoff_deadline = preparation_transition_deadline;
        // Refuse to begin a handoff only when OLD cannot carry the exact
        // prospective controls still needed from this side.  DRAIN has
        // already consumed one OLD receive record here: server sends ACK and
        // BARRIER (2 records), while a client ABORT is the only remaining OLD
        // receive control (1 record).  Using <=4 here used to reject a safe
        // boundary and could strand the client after its emergency gate.
        {
            constexpr std::uint64_t kRequiredSentRecords = 2U;
            constexpr std::uint64_t kRequiredReceivedRecords = 1U;
            constexpr std::uint64_t kRequiredSentBytes =
                2U * static_cast<std::uint64_t>(kSessionDrainFrameSize);
            constexpr std::uint64_t kRequiredReceivedBytes =
                static_cast<std::uint64_t>(kSessionDrainFrameSize);
            const auto stats = authenticated_tls->rotation_stats();
            const auto insufficient = [](const std::uint64_t value,
                                         const std::uint64_t limit,
                                         const std::uint64_t required) noexcept {
                return limit != 0U &&
                    (value >= limit || limit - value < required);
            };
            if (insufficient(stats.sent_records, rotation_policy_.max_records,
                             kRequiredSentRecords) ||
                insufficient(stats.received_records,
                             rotation_policy_.max_records,
                             kRequiredReceivedRecords) ||
                insufficient(stats.sent_bytes, rotation_policy_.max_bytes,
                             kRequiredSentBytes) ||
                insufficient(stats.received_bytes, rotation_policy_.max_bytes,
                             kRequiredReceivedBytes)) {
                ::SecureZeroMemory(nonce.data(), nonce.size());
                authenticated_tls->close();
                return false;
            }
            if (rotation_policy_.max_age > std::chrono::seconds::zero()) {
                const auto age_limit = secure::rotation_age_limit_microseconds(
                    rotation_policy_.max_age);
                const auto now = std::chrono::steady_clock::now();
                const auto remaining = now < handoff_deadline
                    ? static_cast<std::uint64_t>(
                          std::chrono::duration_cast<std::chrono::microseconds>(
                              handoff_deadline - now).count())
                    : 0U;
                if (stats.age_microseconds >= age_limit ||
                    age_limit - stats.age_microseconds <
                        remaining) {
                    ::SecureZeroMemory(nonce.data(), nonce.size());
                    authenticated_tls->close();
                    return false;
                }
            }
        }
        {
            std::unique_lock handoff_lock{*handoff_mutex};
            std::unique_lock<std::shared_mutex> map_lock(client_map_mutex_);
            const auto it = client_map_.find(assigned_ip);
            if (it == client_map_.end() || it->second.tls.get() != tls ||
                it->second.replacement_preparing != replacement_preparing ||
                !it->second.replacement_preparing->load(
                    std::memory_order_acquire) ||
                !it->second.draining ||
                it->second.draining->load(std::memory_order_acquire) ||
                it->second.drain_deadline_ticks != drain_deadline_ticks ||
                drain_deadline_ticks->load(std::memory_order_acquire) !=
                    preparation_ticks ||
                std::chrono::steady_clock::now() >=
                    preparation_transition_deadline ||
                secure::ct_memcmp(it->second.drain_nonce.data(), nonce.data(),
                                  nonce.size()) != 0) {
                ::SecureZeroMemory(nonce.data(), nonce.size());
                return true;
            }
            it->second.replacement_preparing->store(
                false, std::memory_order_release);
            it->second.drain_barrier_sent->store(
                false, std::memory_order_release);
            it->second.draining->store(true, std::memory_order_release);
            // Heartbeat ACKs are intentionally not emitted while OLD is
            // draining.  Preserve a finite authenticated grace window so a
            // valid aggressive (100/200 ms) policy cannot kill a handoff that
            // is still inside the protocol's bounded server budget.
            if (it->second.heartbeat) {
                std::lock_guard heartbeat_lock{it->second.heartbeat->mutex};
                const auto timeout =
                    it->second.heartbeat->timeout >
                            std::chrono::milliseconds::zero()
                        ? it->second.heartbeat->timeout
                        : std::chrono::seconds{1};
                it->second.heartbeat->handoff_deadline = handoff_deadline;
                it->second.heartbeat->deadline = handoff_deadline + timeout;
            }
        }
        const auto frame = encode_session_drain_frame(nonce);
        const auto clear_failed_drain = [&]() noexcept {
            bool still_owned = false;
            {
                std::unique_lock handoff_lock{*handoff_mutex};
                std::unique_lock<std::shared_mutex> map_lock(
                    client_map_mutex_);
                const auto it = client_map_.find(assigned_ip);
                still_owned = it != client_map_.end() &&
                    it->second.tls.get() == tls &&
                    secure::ct_memcmp(it->second.drain_nonce.data(),
                                      nonce.data(), nonce.size()) == 0;
                if (still_owned) {
                    it->second.drain_nonce.fill(0U);
                    it->second.replacement_preparing->store(
                        false, std::memory_order_release);
                    it->second.drain_barrier_sent->store(
                        false, std::memory_order_release);
                    it->second.draining->store(false,
                                                std::memory_order_release);
                    it->second.drain_deadline_ticks->store(
                        0, std::memory_order_release);
                    if (it->second.heartbeat) {
                        std::lock_guard heartbeat_lock{
                            it->second.heartbeat->mutex};
                        it->second.heartbeat->handoff_deadline = {};
                        if (it->second.heartbeat->participating) {
                            const auto timeout =
                                it->second.heartbeat->timeout;
                            it->second.heartbeat->deadline =
                                std::chrono::steady_clock::now() +
                                (timeout > std::chrono::milliseconds::zero()
                                     ? timeout
                                     : std::chrono::seconds{1});
                        }
                    }
                }
                handoff_lock.unlock();
                handoff_cv->notify_all();
            }
            if (still_owned &&
                !flush_pending_handoff_records(pending_outbound,
                                               authenticated_tls,
                    std::chrono::steady_clock::now() +
                        kTcpHandoffRecoveryFlushBudget)) {
                authenticated_tls->close();
            }
        };
        try {
            const auto send_control = [&](const std::uint8_t control_type) {
                return authenticated_tls->send_record_until(
                           control_type, frame.data(),
                           static_cast<std::uint16_t>(frame.size()),
                           handoff_deadline) ==
                       static_cast<int>(frame.size());
            };
            // The replacement handler emits the final barrier while holding
            // the same write lock. Queued application records remain unsent
            // until NEW commits, making BARRIER the last OLD-generation record.
            if (!send_control(PACKET_TYPE_SESSION_DRAIN_ACK)) {
                clear_failed_drain();
            } else {
                // Publish only after the ACK write succeeds. Even a spurious
                // waiter wake is safe because drain_lock remains held until
                // this handler returns.
                handoff_cv->notify_all();
            }
        } catch (...) {
            clear_failed_drain();
        }
        ::SecureZeroMemory(nonce.data(), nonce.size());
        return true;
    }

    if (type != PACKET_TYPE_HEARTBEAT) return false;

    HeartbeatControlFrame frame{};
    if (!decode_heartbeat_control_frame(payload, frame)) return false;
    const auto requested_interval = std::chrono::milliseconds{frame.interval_ms};
    const auto requested_timeout = std::chrono::milliseconds{frame.timeout_ms};
    if (requested_interval < kMinimumHeartbeatInterval ||
        requested_interval > kMaximumHeartbeatInterval ||
        requested_timeout < requested_interval * 2 ||
        requested_timeout > kMaximumHeartbeatTimeout) {
        return false;
    }

    std::shared_ptr<secure::SecureSocket> authenticated_tls;
    std::shared_ptr<std::timed_mutex> write_mutex;
    std::shared_ptr<PeerHeartbeatState> heartbeat;
    std::string client_id;
    {
        std::shared_lock<std::shared_mutex> map_lock(client_map_mutex_);
        const auto it = client_map_.find(assigned_ip);
        if (it != client_map_.end() && it->second.tls.get() == tls) {
            authenticated_tls = it->second.tls;
            write_mutex = it->second.write_mutex;
            heartbeat = it->second.heartbeat;
            client_id = it->second.client_id;
        }
    }
    if (!authenticated_tls || !write_mutex || !heartbeat || client_id.empty()) {
        return false;
    }

    // The frame is already authenticated by TLS/DTLS, but a compromised peer
    // must not turn the acknowledgement path into unbounded CPU or lock work.
    // Silently drop excess requests so one burst does not immediately tear down
    // an otherwise valid session; normal liveness expiry remains fail-closed.
    if (!heartbeat_limiter_.allow(client_id, payload.size())) return true;

    {
        std::lock_guard<std::mutex> heartbeat_lock(heartbeat->mutex);
        if (heartbeat->closing) return false;
        const auto now = std::chrono::steady_clock::now();
        if (heartbeat->participating &&
            now - heartbeat->last_request < requested_interval / 2) {
            return true;
        }
        heartbeat->participating = true;
        heartbeat->last_request = now;
        heartbeat->timeout = requested_timeout;
        heartbeat->deadline = now + requested_timeout;
    }
    heartbeat_requests_.fetch_add(1U, std::memory_order_relaxed);

#ifdef TRUETUNNEL_INTEGRATION_TEST
    if (integration_drop_heartbeat_acknowledgements_.load(
            std::memory_order_acquire)) {
        return true;
    }
#endif

    std::unique_lock<std::timed_mutex> write_guard{
        *write_mutex, std::defer_lock};
    const auto acknowledgement_lock_budget = (std::min)(
        std::chrono::milliseconds{50}, requested_interval / 2);
    if (!write_guard.try_lock_for(acknowledgement_lock_budget)) {
        // A concurrent data-plane write can legitimately occupy this peer.
        // Dropping one acknowledgement is safer than blocking every reader;
        // the client has multiple heartbeat intervals before its timeout.
        return true;
    }
    bool current_generation = false;
    {
        std::shared_lock<std::shared_mutex> map_lock(client_map_mutex_);
        const auto it = client_map_.find(assigned_ip);
        current_generation = it != client_map_.end() &&
            it->second.tls.get() == tls && it->second.tls == authenticated_tls &&
            it->second.write_mutex == write_mutex &&
            (!it->second.replacement_preparing ||
             !it->second.replacement_preparing->load(
                 std::memory_order_acquire)) &&
            (!it->second.draining ||
             !it->second.draining->load(std::memory_order_acquire));
    }
    if (!current_generation) return true;
    const int sent = authenticated_tls->send_record(
        PACKET_TYPE_HEARTBEAT_ACK,
        payload.data(),
        static_cast<std::uint16_t>(payload.size()));
    if (sent != static_cast<int>(payload.size())) {
        throw std::runtime_error("short heartbeat acknowledgement write");
    }
    return true;
}

void VpnServer::note_authenticated_client_activity(
    secure::SecureSocket* const tls,
    const std::string& assigned_ip) {
    std::shared_ptr<PeerHeartbeatState> heartbeat;
    {
        std::shared_lock<std::shared_mutex> map_lock(client_map_mutex_);
        const auto it = client_map_.find(assigned_ip);
        if (it == client_map_.end() || it->second.tls.get() != tls) return;
        heartbeat = it->second.heartbeat;
    }
    if (!heartbeat) return;

    std::lock_guard heartbeat_lock{heartbeat->mutex};
    if (!heartbeat->participating || heartbeat->closing ||
        heartbeat->handoff_deadline !=
            std::chrono::steady_clock::time_point{}) {
        return;
    }
    const auto timeout = heartbeat->timeout;
    heartbeat->deadline = std::chrono::steady_clock::now() +
        (timeout > std::chrono::milliseconds::zero()
             ? timeout
             : std::chrono::seconds{1});
}

void VpnServer::handle_client_message(secure::SecureSocket* tls, std::string_view message) {
    std::string sender;
    std::string client_id;
    std::shared_ptr<std::shared_timed_mutex> ingress_gate;
    {
        std::shared_lock<std::shared_mutex> map_lock(client_map_mutex_);
        for (const auto& [ip, entry] : client_map_) {
            if (entry.tls.get() == tls) {
                sender = ip;
                client_id = entry.client_id;
                ingress_gate = entry.ingress_gate;
                break;
            }
        }
    }
    if (!ingress_gate || sender.empty() || client_id.empty()) {
        throw std::runtime_error("Chat sender is not an authenticated client");
    }

    std::shared_lock ingress_lock{*ingress_gate};
    {
        std::shared_lock<std::shared_mutex> map_lock(client_map_mutex_);
        const auto it = client_map_.find(sender);
        if (it == client_map_.end() || it->second.tls.get() != tls ||
            it->second.client_id != client_id ||
            it->second.ingress_gate != ingress_gate) {
            throw std::runtime_error("Chat sender used a retired TLS generation");
        }
    }

    note_authenticated_client_activity(tls, sender);
    if (!allowClientChat(client_id, message.size())) {
        std::cerr << "[!] Disconnecting client " << sender
                  << " after exceeding the authenticated chat rate limit\n";
        throw std::runtime_error("Authenticated chat rate limit exceeded");
    }
    const std::string* skip_id = &client_id;
    std::string body(message.begin(), message.end());
    const BroadcastStatus status =
        broadcast_message(sender, body, client_id, skip_id);
    if (status == BroadcastStatus::RateLimited) {
        std::cerr << "[!] Disconnecting client " << sender
                  << " after exceeding the authenticated chat fanout budget\n";
        throw std::runtime_error("Authenticated chat fanout limit exceeded");
    }
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
    bool retired_generation = false;
    {
        std::lock_guard<std::shared_mutex> lg(client_map_mutex_);
        auto it = client_map_.find(src_ip);
        if (it != client_map_.end() &&
            it->second.client_id == client_id &&
            it->second.tls == tls) {
            client_map_.erase(it);
            release_client_id = true;
        } else if (it != client_map_.end() &&
                   it->second.client_id == client_id &&
                   it->second.tls != tls) {
            // A successful make-before-break handoff deliberately closes OLD.
            // Its receive error belongs to the retired generation and must not
            // unwind into handleClient(), whose generic cleanup would otherwise
            // release the IP lease now owned by NEW.
            retired_generation = true;
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

    if (forwarding_error && !retired_generation) {
        std::rethrow_exception(forwarding_error);
    }
}

// ───────────────────────────────────────────────────────────────────────────────
bool VpnServer::route_authenticated_packet(
    secure::SecureSocket* const source_tls,
    const std::string& expected_source_ip,
    WINTUN_SESSION_HANDLE session,
    std::mutex& session_mutex,
    const BYTE* const packet,
    const UINT size) {
    if (source_tls == nullptr || session == nullptr ||
        !ipv4_source_matches(packet, size, expected_source_ip)) {
        return true;
    }

    std::string source_client_id;
    std::shared_ptr<std::shared_timed_mutex> ingress_gate;
    {
        std::shared_lock<std::shared_mutex> map_lock(client_map_mutex_);
        const auto source = client_map_.find(expected_source_ip);
        if (source == client_map_.end() ||
            source->second.tls.get() != source_tls) {
            return true;
        }
        source_client_id = source->second.client_id;
        ingress_gate = source->second.ingress_gate;
    }
    if (!ingress_gate || source_client_id.empty()) return true;

    // The replacement path takes this gate exclusively before its map commit.
    // Revalidate after acquiring it because OLD may have retired while this
    // callback was waiting behind the commit.
    std::shared_lock ingress_lock{*ingress_gate};
    {
        std::shared_lock<std::shared_mutex> map_lock(client_map_mutex_);
        const auto source = client_map_.find(expected_source_ip);
        if (source == client_map_.end() ||
            source->second.tls.get() != source_tls ||
            source->second.client_id != source_client_id ||
            source->second.ingress_gate != ingress_gate) {
            return true;
        }
    }

    note_authenticated_client_activity(source_tls, expected_source_ip);
    if (forward_to_client_if_known(packet, size)) return true;

    // Keep the ingress lease through local injection. Otherwise OLD could pass
    // its ownership check, lose the replacement race, and inject after commit.
    std::lock_guard<std::mutex> session_lock(session_mutex);
    void* const tunnel_packet = WintunAllocateSendPacket(session, size);
    if (tunnel_packet == nullptr) {
        throw std::runtime_error(
            "Wintun send ring is unavailable for an authenticated packet");
    }
    std::memcpy(tunnel_packet, packet, size);
    WintunSendPacket(session, static_cast<const BYTE*>(tunnel_packet));
    return true;
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
    std::shared_ptr<VpnServerPendingOutbound> destination_pending_outbound;
    std::string destination_id;
    {
        std::shared_lock<std::shared_mutex> rlk(client_map_mutex_);
        auto it = client_map_.find(dst);
        if (it == client_map_.end()) {
            return false;                   // not a VPN peer
        }

        destination_tls = it->second.tls;
        destination_write_mutex = it->second.write_mutex;
        destination_pending_outbound = it->second.pending_outbound;
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
        bool current_client = false;
        bool egress_paused = false;
        {
            std::shared_lock map_lock{client_map_mutex_};
            const auto it = client_map_.find(dst);
            current_client = it != client_map_.end() &&
                it->second.client_id == destination_id &&
                it->second.write_mutex == destination_write_mutex &&
                it->second.pending_outbound == destination_pending_outbound;
            if (current_client) destination_tls = it->second.tls;
            egress_paused = current_client &&
                ((it->second.replacement_preparing &&
                  it->second.replacement_preparing->load(
                      std::memory_order_acquire)) ||
                 (it->second.draining &&
                  it->second.draining->load(std::memory_order_acquire)));
        }
        if (!current_client || !destination_tls) return true;
        if (egress_paused) {
            if (!enqueue_pending_handoff_record(
                    destination_pending_outbound, PACKET_TYPE_IP,
                    reinterpret_cast<const std::uint8_t*>(packet), size)) {
                std::cerr << "[!] Handoff queue full for client " << dst
                          << "; dropping forwarded packet\n";
            }
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
