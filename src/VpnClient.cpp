#define NOMINMAX

#include "VpnClient.h"
#include "utils.hpp"
#include "vpn.hpp"
#include "secure/SecureSocket.h"
#include "secure/SharedSecret.h"
#include "secure/CngUtils.h"
#include <algorithm>
#include <iostream>
#include <regex>
#include <thread>
#include <chrono>
#include <array>
#include <cstring>
#include <limits>
#include <string_view>
#include <exception>
#include <stdexcept>
#include <system_error>
#include <utility>

#include "redirect_stream.hpp"

namespace {
constexpr const char* kClientCancelled = "vpn_client_cancelled";
constexpr auto kServerResolutionTimeout = std::chrono::seconds{10};
constexpr DWORD kServerResolutionPollMilliseconds = 100U;
// The drain and commit exchange consumes multiple records on each endpoint.
// Keep enough margin for that exchange even when an integration test uses a
// deliberately small record/byte limit; otherwise the guard could reject the
// barrier itself at the hard limit and leave the old generation unusable.
constexpr std::uint64_t kReplacementRecordHeadroom = 4U;
// Leave room for one MTU-sized application record plus all fixed control
// frames even if the scheduler wakes just after the threshold is crossed.
constexpr std::uint64_t kReplacementByteHeadroom = 16U * 1024U;
constexpr std::uint64_t kReplacementAgeHeadroomMicroseconds = 5'000'000U;
constexpr auto kTcpHandoffClientPauseBudget = std::chrono::milliseconds{450};
constexpr auto kTcpHandoffRollbackReserve = std::chrono::milliseconds{50};

class EventHandle final {
public:
    explicit EventHandle(HANDLE handle) noexcept : handle_(handle) {}
    ~EventHandle() {
        if (handle_ != nullptr) ::CloseHandle(handle_);
    }

    EventHandle(const EventHandle&) = delete;
    EventHandle& operator=(const EventHandle&) = delete;

    [[nodiscard]] HANDLE get() const noexcept { return handle_; }

private:
    HANDLE handle_ = nullptr;
};

struct AddrInfoExDeleter final {
    void operator()(ADDRINFOEXW* address_info) const noexcept {
        if (address_info != nullptr) ::FreeAddrInfoExW(address_info);
    }
};

struct ResolvedServerEndpoint {
    sockaddr_in address{};
    std::string numeric_ip;
};

std::wstring utf8_to_utf16(const std::string& value) {
    if (value.find('\0') != std::string::npos) {
        throw std::invalid_argument("VPN server address contains a NUL byte");
    }
    if (value.size() >
        static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
        throw std::length_error("VPN server address is too long");
    }

    const int value_size = static_cast<int>(value.size());
    const int required = ::MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), value_size, nullptr, 0);
    if (required <= 0) {
        throw std::system_error(
            static_cast<int>(::GetLastError()), std::system_category(),
            "MultiByteToWideChar(VPN server address)");
    }

    std::wstring wide_value(static_cast<std::size_t>(required), L'\0');
    const int converted = ::MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), value_size,
        wide_value.data(), required);
    if (converted != required) {
        throw std::system_error(
            static_cast<int>(::GetLastError()), std::system_category(),
            "MultiByteToWideChar(VPN server address)");
    }
    return wide_value;
}

std::vector<ResolvedServerEndpoint> resolve_server_ipv4_endpoints(
    const std::string& server_address,
    const std::uint16_t port,
    const TransportProtocol transport,
    const std::atomic<bool>* keep_running = nullptr) {
    if (server_address.empty()) {
        throw std::invalid_argument("VPN server address is empty");
    }
    if (port == 0U) {
        throw std::invalid_argument("VPN server port is zero");
    }

    if (keep_running != nullptr &&
        !keep_running->load(std::memory_order_acquire)) {
        throw std::runtime_error(kClientCancelled);
    }

    ADDRINFOEXW hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = transport == TransportProtocol::Tcp
        ? SOCK_STREAM : SOCK_DGRAM;
    hints.ai_protocol = transport == TransportProtocol::Tcp
        ? IPPROTO_TCP : IPPROTO_UDP;
    hints.ai_flags = AI_NUMERICSERV;

    const std::wstring wide_address = utf8_to_utf16(server_address);
    const std::wstring service = std::to_wstring(port);
    ADDRINFOEXW* raw_results = nullptr;
    OVERLAPPED overlapped{};
    EventHandle completion_event{
        ::CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    if (completion_event.get() == nullptr) {
        throw std::system_error(
            static_cast<int>(::GetLastError()), std::system_category(),
            "CreateEventW(VPN server resolution)");
    }
    overlapped.hEvent = completion_event.get();
    HANDLE cancel_handle = nullptr;

    int resolve_result = ::GetAddrInfoExW(
        wide_address.c_str(), service.c_str(), NS_DNS, nullptr, &hints,
        &raw_results, nullptr, &overlapped, nullptr, &cancel_handle);
    bool cancelled = false;
    bool timed_out = false;
    DWORD wait_error = ERROR_SUCCESS;
    if (resolve_result == WSA_IO_PENDING) {
        const auto deadline =
            std::chrono::steady_clock::now() + kServerResolutionTimeout;
        while (true) {
            if (keep_running != nullptr &&
                !keep_running->load(std::memory_order_acquire)) {
                cancelled = true;
                break;
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                timed_out = true;
                break;
            }

            const DWORD wait_result = ::WaitForSingleObject(
                completion_event.get(), kServerResolutionPollMilliseconds);
            if (wait_result == WAIT_OBJECT_0) break;
            if (wait_result != WAIT_TIMEOUT) {
                wait_error = ::GetLastError();
                break;
            }
        }

        if (cancelled || timed_out || wait_error != ERROR_SUCCESS) {
            // Microsoft requires waiting for asynchronous completion after
            // cancellation before the OVERLAPPED storage or Winsock lifetime
            // may end. GetAddrInfoExCancel signals this event immediately even
            // when a legacy provider must finish its private work later.
            (void)::GetAddrInfoExCancel(&cancel_handle);
            if (::WaitForSingleObject(completion_event.get(), INFINITE) !=
                    WAIT_OBJECT_0 &&
                wait_error == ERROR_SUCCESS) {
                wait_error = ::GetLastError();
            }
        }
        resolve_result = ::GetAddrInfoExOverlappedResult(&overlapped);
    }

    const std::unique_ptr<ADDRINFOEXW, AddrInfoExDeleter> results{raw_results};
    if (cancelled ||
        (keep_running != nullptr &&
         !keep_running->load(std::memory_order_acquire))) {
        throw std::runtime_error(kClientCancelled);
    }
    if (wait_error != ERROR_SUCCESS) {
        throw std::system_error(
            static_cast<int>(wait_error), std::system_category(),
            "WaitForSingleObject(VPN server resolution)");
    }
    if (timed_out) {
        throw std::system_error(
            WSAETIMEDOUT, std::system_category(),
            "GetAddrInfoExW(VPN server address timeout)");
    }
    if (resolve_result != 0) {
        throw std::system_error(
            resolve_result, std::system_category(),
            "GetAddrInfoExW(VPN server address)");
    }

    std::vector<ResolvedServerEndpoint> endpoints;
    for (const ADDRINFOEXW* entry = results.get(); entry != nullptr;
         entry = entry->ai_next) {
        if (entry->ai_family != AF_INET || entry->ai_addr == nullptr ||
            entry->ai_addrlen < sizeof(sockaddr_in)) {
            continue;
        }

        ResolvedServerEndpoint endpoint{};
        std::memcpy(&endpoint.address, entry->ai_addr, sizeof(sockaddr_in));
        endpoint.address.sin_family = AF_INET;
        endpoint.address.sin_port = ::htons(port);
        char numeric_ip[INET_ADDRSTRLEN]{};
        if (::inet_ntop(AF_INET, &endpoint.address.sin_addr, numeric_ip,
                        sizeof(numeric_ip)) == nullptr) {
            continue;
        }
        endpoint.numeric_ip = numeric_ip;
        const bool duplicate = std::ranges::any_of(
            endpoints, [&endpoint](const ResolvedServerEndpoint& existing) {
                return existing.numeric_ip == endpoint.numeric_ip;
            });
        if (!duplicate) endpoints.push_back(std::move(endpoint));
    }
    if (endpoints.empty()) {
        throw std::runtime_error(
            "VPN server address did not resolve to an IPv4 endpoint");
    }
    return endpoints;
}

std::int64_t steady_clock_ticks() noexcept {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}
}

VpnClient::VpnClient(const std::string& server_ip,
                     int port,
                     const std::string& password,
                     const std::string& adaptername,
                     const std::string& real_adapter,
                      secure::CipherSuite,
                      TransportProtocol transport,
                      secure::TrafficKeyRotationPolicy rotation_policy,
                      const std::uint64_t expected_real_adapter_luid,
                      ConnectionRecoveryOptions recovery,
                      const bool single_connect_attempt)
    : server_address_(server_ip),
      port_(port),
      password_(password),
      adaptername_(adaptername),
      real_adapter_(real_adapter),
      cipher_suite_(secure::CipherSuite::Aes256Gcm),
      transport_(transport),
      rotation_policy_(rotation_policy),
      recovery_(recovery),
      single_connect_attempt_(single_connect_attempt),
      expected_real_adapter_luid_(expected_real_adapter_luid) {
    if (port_ <= 0 || port_ > 65'535) {
        throw std::invalid_argument("VPN client port is out of range");
    }
    if (server_address_.empty()) {
        throw std::invalid_argument("VPN client server address is empty");
    }
    secure::require_valid_shared_secret(password_);
    if (!is_valid_connection_recovery_options(recovery_)) {
        throw std::invalid_argument("VPN client recovery timing policy is invalid");
    }
    if (transport_ == TransportProtocol::Tcp &&
        !secure::is_valid_tcp_rotation_policy(rotation_policy_)) {
        throw std::invalid_argument(
            "VPN client TCP rotation policy leaves no usable handoff reserve");
    }
    // TCP renewal needs the group credential until the tunnel stops. Keep
    // that storage page-locked when Windows permits it; UDP wipes its copy as
    // soon as the initial DTLS handshake succeeds.
    password_page_locked_ =
        transport_ == TransportProtocol::Tcp && !password_.empty() &&
        ::VirtualLock(password_.data(), password_.size()) != FALSE;
    if (transport_ == TransportProtocol::Tcp && !password_.empty() &&
        !password_page_locked_) {
        // VirtualLock can legitimately fail without SeLockMemoryPrivilege.
        // The credential is still wiped on every teardown path; only paging
        // resistance is unavailable in that Windows configuration.
        try {
            std::cerr << "[WARN] Could not page-lock the VPN credential; "
                         "teardown will still wipe it securely\n";
        } catch (...) {
            // Diagnostics must never strand a locked credential during
            // construction. The storage remains owned by this object and is
            // wiped/unlocked by clear_password().
        }
    }
}

VpnClient::~VpnClient() {
    stop();
}

void VpnClient::clear_password() noexcept {
    // This helper is intentionally idempotent: startup cancellation,
    // destructor teardown, and the UDP post-handshake path can all converge
    // here without double-unlocking or leaving a stale credential buffer.
    std::lock_guard password_lock{password_mutex_};
    char* const password_bytes = password_.empty() ? nullptr : password_.data();
    const std::size_t password_size = password_.size();
    if (password_bytes != nullptr && password_size != 0U) {
        ::SecureZeroMemory(password_bytes, password_size);
        if (password_page_locked_) {
            (void)::VirtualUnlock(password_bytes, password_size);
        }
    }
    password_page_locked_ = false;
    // swap avoids retaining the old allocation capacity. std::string's
    // destructor is non-throwing, so this remains safe from all teardown
    // paths, including exception handling.
    std::string{}.swap(password_);
}

void VpnClient::start() {
    {
        std::lock_guard<std::mutex> stop_guard(stop_mutex_);
        if (start_called_) {
            std::cout << "[!] VpnClient start may only be called once; request ignored\n";
            return;
        }
        start_called_ = true;
        if (stop_requested_.load(std::memory_order_acquire)) {
            std::cout << "[INFO] Client start cancelled before connection\n";
            return;
        }
        running_ = true;
    }

    if (transport_ == TransportProtocol::Tcp) {
        std::cout << "[INFO] Starting VPN client using native TLS 1.3 over TCP "
                     "(TLS_AES_256_GCM_SHA384)\n";
    } else {
        std::cout << "[INFO] Starting VPN client using wolfSSL DTLS 1.3 over UDP "
                     "(TLS_AES_256_GCM_SHA384, P-256 ECDHE-PSK)\n";
    }

    try {
        real_adapter_ = sanitize_shell_string(real_adapter_);
        real_adapter_luid_ = ResolveNetworkAdapterLuid(
            real_adapter_, expected_real_adapter_luid_);
        real_adapter_luid_pinned_ = true;
        real_adapter_ = GetNetworkAdapterAlias(real_adapter_luid_);
        std::cout << "[INFO] Pinned physical uplink identity: "
                  << real_adapter_ << " (LUID "
                  << real_adapter_luid_.Value << ")\n";
        connectToServer();
        requestConfig();
        LoadWintun();
        configureAdapter();
        std::cout << "[INFO] VPN client ready; forwarding packets\n";
    } catch (const std::exception& ex) {
        running_ = false;
        stop();
        if (std::string_view(ex.what()) == kClientCancelled) {
            std::cout << "[INFO] Client start cancelled\n";
            return;
        }
        throw;
    } catch (...) {
        running_ = false;
        stop();
        throw;
    }
}

void VpnClient::stop() {
    stop_requested_.store(true, std::memory_order_release);
    running_.store(false, std::memory_order_release);
    heartbeat_wait_cv_.notify_all();
    rotation_wait_cv_.notify_all();
    drain_wait_cv_.notify_all();
    std::lock_guard<std::mutex> stop_guard(stop_mutex_);
    std::cout << "[INFO] Stopping VPN client\n";
    running_ = false;

    const auto tls = tls_snapshot();
    const bool tls_owned_socket = static_cast<bool>(tls);
    if (tls) {
        try {
            tls->close();
            sock_.store(INVALID_SOCKET, std::memory_order_release);
        } catch (...) {
        }
    }
    std::shared_ptr<secure::SecureSocket> pending_replacement;
    {
        std::lock_guard pending_lock{pending_replacement_mutex_};
        pending_replacement = pending_replacement_tls_;
    }
    if (pending_replacement) {
        try {
            pending_replacement->close();
        } catch (...) {
        }
    }

    // Wake the packet reader without ending the Wintun session.  The session
    // remains owned until both workers have observed cancellation and joined.
    if (cancellation_event_) {
        ::SetEvent(cancellation_event_);
    }

    if (tun_thread_.joinable()) tun_thread_.join();
    if (tls_thread_.joinable()) tls_thread_.join();
    if (heartbeat_thread_.joinable()) heartbeat_thread_.join();
    if (heartbeat_watchdog_thread_.joinable()) {
        heartbeat_watchdog_thread_.join();
    }
    if (tcp_rotation_thread_.joinable()) {
        tcp_rotation_thread_.join();
    }

    if (cancellation_event_) {
        ::CloseHandle(cancellation_event_);
        cancellation_event_ = nullptr;
    }

    {
        std::lock_guard<std::mutex> session_guard(session_mutex_);
        if (session_) {
            try {
                session_->reset();
            } catch (...) {
            }
        }
    }

    {
        std::lock_guard<std::mutex> tls_guard(tls_mutex_);
        if (tls_ == tls) tls_.reset();
    }
    clear_password();

    // A connecting SocketGuard remains the owner until connectToServer has
    // returned.  Shutdown wakes it; only the owner performs closesocket.
    SOCKET pending = pending_socket_.exchange(INVALID_SOCKET);
    if (pending != INVALID_SOCKET) {
        if (transport_ == TransportProtocol::Tcp) {
            shutdown(pending, SD_BOTH);
        }
    }

    if (!tls_owned_socket) {
        SOCKET active = sock_.load(std::memory_order_acquire);
        if (active != INVALID_SOCKET) {
            shutdown(active, SD_BOTH);
            closesocket(active);
            sock_.store(INVALID_SOCKET, std::memory_order_release);
        }
    }

    // Remove only exact route rows created by this instance. Never delete by
    // destination alone: the server endpoint may be an address owned by this
    // machine, and a broad route delete removes Windows' local /32 route.
    protected_route_.reset();
    tunnel_route_.reset();
    icmp_firewall_rule_.reset();

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

    if (adapter_) {
        adapter_->Reset();
        adapter_.reset();
    }

    {
        std::lock_guard drain_lock{drain_wait_mutex_};
        ::SecureZeroMemory(drain_nonce_.data(), drain_nonce_.size());
        replacement_freeze_acknowledged_ = false;
        drain_acknowledged_ = false;
        drain_barrier_received_ = false;
    }

    std::cout << "[✓] VPN client stopped\n";
}


void VpnClient::connectToServer() {
    CHECK(real_adapter_luid_pinned_, "Physical adapter identity is not pinned");
    const std::string bind_ip = get_ipv4_for_adapter(real_adapter_luid_);
    CHECK(!bind_ip.empty(), "Could not find adapter IP");
    connectToServerFromBindIp(bind_ip, true);
}

void VpnClient::connectToServerFromBindIp(
    const std::string& bind_ip,
    const bool establish_secure_session) {
    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = 0;
    CHECK(inet_pton(AF_INET, bind_ip.c_str(), &bind_addr.sin_addr) == 1,
          "Invalid local adapter IPv4 address");

    constexpr auto kAttemptTimeout = std::chrono::seconds{10};
    constexpr auto kPollInterval = std::chrono::milliseconds{200};
    constexpr auto kRetryDelay = std::chrono::seconds{1};
    const auto wait_before_retry = [this, kPollInterval, kRetryDelay]() {
        const auto deadline = std::chrono::steady_clock::now() + kRetryDelay;
        while (running_ && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(kPollInterval);
        }
    };

    while (running_) {
        const int type =
            (transport_ == TransportProtocol::Tcp) ? SOCK_STREAM : SOCK_DGRAM;
        const int protocol =
            (transport_ == TransportProtocol::Tcp) ? IPPROTO_TCP : IPPROTO_UDP;
        std::vector<ResolvedServerEndpoint> endpoints;
        try {
            endpoints = resolve_server_ipv4_endpoints(
                server_address_, static_cast<std::uint16_t>(port_), transport_,
                &running_);
#ifdef TRUETUNNEL_INTEGRATION_TEST
            std::vector<std::string> endpoint_override;
            {
                std::lock_guard<std::mutex> observer_lock(
                    integration_observer_mutex_);
                endpoint_override = integration_resolved_ipv4_addresses_;
            }
            if (!endpoint_override.empty()) {
                endpoints.clear();
                for (const auto& numeric_ip : endpoint_override) {
                    ResolvedServerEndpoint endpoint{};
                    endpoint.address.sin_family = AF_INET;
                    endpoint.address.sin_port =
                        ::htons(static_cast<std::uint16_t>(port_));
                    if (::inet_pton(
                            AF_INET, numeric_ip.c_str(),
                            &endpoint.address.sin_addr) != 1) {
                        throw std::logic_error(
                            "integration endpoint override is not IPv4");
                    }
                    endpoint.numeric_ip = numeric_ip;
                    endpoints.push_back(std::move(endpoint));
                }
            }
#endif
        } catch (const std::exception& error) {
            if (!running_ || std::string_view(error.what()) == kClientCancelled) {
                throw std::runtime_error(kClientCancelled);
            }
            if (single_connect_attempt_) throw;
            std::cerr << "[!] Could not resolve VPN server address '"
                      << server_address_ << "': " << error.what()
                      << "; retrying\n";
            wait_before_retry();
            continue;
        }

        int last_connect_error = WSAHOST_NOT_FOUND;
        std::exception_ptr last_handshake_error;
        for (const auto& endpoint : endpoints) {
            if (!running_) throw std::runtime_error(kClientCancelled);
            SocketGuard sock{socket(AF_INET, type, protocol)};
            CHECK(sock.get() != INVALID_SOCKET, "socket() failed");

            int reuse = 1;
            setsockopt(sock.get(), SOL_SOCKET, SO_REUSEADDR,
                       reinterpret_cast<const char*>(&reuse), sizeof(reuse));
            if (transport_ == TransportProtocol::Tcp) {
                int flag = 1;
                setsockopt(sock.get(), IPPROTO_TCP, TCP_NODELAY,
                           reinterpret_cast<const char*>(&flag), sizeof(flag));
            }

            if (bind(sock.get(), reinterpret_cast<sockaddr*>(&bind_addr),
                     sizeof(bind_addr)) == SOCKET_ERROR) {
                const int error = WSAGetLastError();
                throw std::system_error(error, std::system_category(), "bind");
            }

            u_long nonblocking = 1UL;
            if (ioctlsocket(sock.get(), FIONBIO, &nonblocking) == SOCKET_ERROR) {
                const int error = WSAGetLastError();
                throw std::system_error(error, std::system_category(),
                                        "ioctlsocket(FIONBIO)");
            }

            std::cout << "[*] Connecting (" << to_string(transport_) << ") from "
                      << bind_ip << " to " << server_address_;
            if (server_address_ != endpoint.numeric_ip) {
                std::cout << " [" << endpoint.numeric_ip << ']';
            }
            std::cout << ':' << port_ << "...\n";
#ifdef TRUETUNNEL_INTEGRATION_TEST
            IntegrationEndpointAttemptObserver endpoint_attempt_observer;
            {
                std::lock_guard<std::mutex> observer_lock(
                    integration_observer_mutex_);
                endpoint_attempt_observer =
                    integration_endpoint_attempt_observer_;
            }
            if (endpoint_attempt_observer) {
                endpoint_attempt_observer(
                    endpoint.numeric_ip,
                    ::ntohs(endpoint.address.sin_port));
            }
#endif
            pending_socket_.store(sock.get(), std::memory_order_release);
            bool connected = connect(
                sock.get(),
                reinterpret_cast<const sockaddr*>(&endpoint.address),
                sizeof(endpoint.address)) == 0;
            int connect_error = connected ? 0 : WSAGetLastError();

            if (!connected &&
                (connect_error == WSAEWOULDBLOCK ||
                 connect_error == WSAEINPROGRESS ||
                 connect_error == WSAEALREADY)) {
                const auto deadline =
                    std::chrono::steady_clock::now() + kAttemptTimeout;
                while (running_ && std::chrono::steady_clock::now() < deadline) {
                    fd_set writable{};
                    fd_set exceptional{};
                    FD_ZERO(&writable);
                    FD_ZERO(&exceptional);
                    FD_SET(sock.get(), &writable);
                    FD_SET(sock.get(), &exceptional);
                    timeval timeout{};
                    timeout.tv_sec = 0;
                    timeout.tv_usec = static_cast<long>(
                        std::chrono::duration_cast<std::chrono::microseconds>(
                            kPollInterval).count());

                    const int selected = select(
                        0, nullptr, &writable, &exceptional, &timeout);
                    if (selected == SOCKET_ERROR) {
                        connect_error = WSAGetLastError();
                        break;
                    }
                    if (selected == 0) continue;

                    int socket_error = 0;
                    int error_size = sizeof(socket_error);
                    if (getsockopt(sock.get(), SOL_SOCKET, SO_ERROR,
                                   reinterpret_cast<char*>(&socket_error),
                                   &error_size) == SOCKET_ERROR) {
                        connect_error = WSAGetLastError();
                    } else {
                        connect_error = socket_error;
                        connected = socket_error == 0;
                    }
                    break;
                }
                if (!connected && std::chrono::steady_clock::now() >= deadline) {
                    connect_error = WSAETIMEDOUT;
                }
            }

            pending_socket_.store(INVALID_SOCKET, std::memory_order_release);
            if (!running_) {
                throw std::runtime_error(kClientCancelled);
            }

            if (connected) {
                u_long blocking = 0UL;
                if (ioctlsocket(sock.get(), FIONBIO, &blocking) == SOCKET_ERROR) {
                    const int error = WSAGetLastError();
                    throw std::system_error(error, std::system_category(),
                                            "ioctlsocket(blocking)");
                }
                if (transport_ == TransportProtocol::Udp) {
                    constexpr DWORD kDatagramSendTimeoutMilliseconds = 2'000U;
                    if (setsockopt(
                            sock.get(), SOL_SOCKET, SO_SNDTIMEO,
                            reinterpret_cast<const char*>(
                                &kDatagramSendTimeoutMilliseconds),
                            sizeof(kDatagramSendTimeoutMilliseconds)) ==
                        SOCKET_ERROR) {
                        const int error = WSAGetLastError();
                        throw std::system_error(
                            error, std::system_category(),
                            "setsockopt(SO_SNDTIMEO UDP client)");
                    }
                }
                resolved_server_ip_ = endpoint.numeric_ip;
                sock_.store(sock.release(), std::memory_order_release);
                if (establish_secure_session) {
                    try {
                        performHandshake();
                    } catch (const std::exception& error) {
                        last_handshake_error = std::current_exception();
                        std::cerr << "[!] Secure handshake with "
                                  << endpoint.numeric_ip << ':' << port_
                                  << " failed: " << error.what() << '\n';
                        discardTransportAttempt();
                        if (!running_) {
                            throw std::runtime_error(kClientCancelled);
                        }
                        continue;
                    } catch (...) {
                        last_handshake_error = std::current_exception();
                        std::cerr << "[!] Secure handshake with "
                                  << endpoint.numeric_ip << ':' << port_
                                  << " failed with an unknown error\n";
                        discardTransportAttempt();
                        if (!running_) {
                            throw std::runtime_error(kClientCancelled);
                        }
                        continue;
                    }
                }
#ifdef TRUETUNNEL_INTEGRATION_TEST
                IntegrationEndpointObserver endpoint_observer;
                {
                    std::lock_guard<std::mutex> observer_lock(
                        integration_observer_mutex_);
                    endpoint_observer = integration_endpoint_observer_;
                }
                if (endpoint_observer) {
                    endpoint_observer(
                        endpoint.numeric_ip,
                        ::ntohs(endpoint.address.sin_port));
                }
#endif
                std::cout << "[✓] Connected using " << to_string(transport_)
                          << " transport\n";
                return;
            }

            last_connect_error = connect_error;
            std::cerr << "[!] connect() to " << endpoint.numeric_ip << ':'
                      << port_ << " failed with Winsock error "
                      << connect_error << " ("
                      << std::error_code(connect_error, std::system_category()).message()
                      << ")\n";
        }

        if (last_handshake_error) {
            std::rethrow_exception(last_handshake_error);
        }
        if (single_connect_attempt_) {
            std::cerr << "[!] All resolved VPN server endpoints failed; "
                         "returning to the recovery scheduler\n";
            throw std::system_error(
                last_connect_error, std::system_category(), "connect");
        }
        std::cerr << "[!] All resolved VPN server endpoints failed; retrying\n";
        wait_before_retry();
    }

    throw std::runtime_error(kClientCancelled);
}

void VpnClient::discardTransportAttempt() noexcept {
    std::shared_ptr<secure::SecureSocket> failed_tls;
    {
        std::lock_guard<std::mutex> tls_guard(tls_mutex_);
        failed_tls = std::move(tls_);
    }

    const SOCKET failed_socket =
        sock_.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
    if (failed_tls) {
        failed_tls->close();
    } else if (failed_socket != INVALID_SOCKET) {
        (void)::shutdown(failed_socket, SD_BOTH);
        (void)::closesocket(failed_socket);
    }
    resolved_server_ip_.clear();
}

void VpnClient::performHandshake() {
    std::unique_lock<std::mutex> tls_guard(tls_mutex_);
    if (!running_) {
        throw std::runtime_error(kClientCancelled);
    }
    std::shared_ptr<secure::SecureSocket> tls;
    if (transport_ == TransportProtocol::Tcp) {
        std::lock_guard password_lock{password_mutex_};
        CHECK(running_.load(std::memory_order_acquire) && !password_.empty(),
              kClientCancelled);
        tls = std::make_shared<secure::SecureSocket>(
            sock_.load(std::memory_order_acquire), password_,
            /*is_server=*/false, cipher_suite_, rotation_policy_);
    } else {
        auto send_fn = [s = sock_.load(std::memory_order_acquire)](
                           const uint8_t* data,
                           std::size_t len) -> secure::DatagramSendResult {
            int sent = send(s, reinterpret_cast<const char*>(data), static_cast<int>(len), 0);
            if (sent == static_cast<int>(len)) {
                return secure::DatagramSendResult::Sent;
            }
            switch (WSAGetLastError()) {
                case WSAEWOULDBLOCK:
                case WSAETIMEDOUT:
                    return secure::DatagramSendResult::WouldBlock;
                case WSAESHUTDOWN:
                case WSAENOTSOCK:
                case WSAECONNRESET:
                    return secure::DatagramSendResult::Closed;
                default:
                    return secure::DatagramSendResult::Error;
            }
        };

        auto recv_fn = [s = sock_.load(std::memory_order_acquire)](
                               std::vector<uint8_t>& out,
                               const std::chrono::milliseconds timeout)
            -> secure::DatagramReceiveResult {
            fd_set readable;
            FD_ZERO(&readable);
            FD_SET(s, &readable);

            const auto timeout_count = (std::max)(0LL, timeout.count());
            timeval wait{};
            wait.tv_sec = static_cast<long>(timeout_count / 1000LL);
            wait.tv_usec = static_cast<long>((timeout_count % 1000LL) * 1000LL);
            const int ready = select(0, &readable, nullptr, nullptr, &wait);
            if (ready == 0) {
                return secure::DatagramReceiveResult::Timeout;
            }
            if (ready == SOCKET_ERROR) {
                return secure::DatagramReceiveResult::Error;
            }

            out.resize(2048U);
            const int got = recv(s,
                                 reinterpret_cast<char*>(out.data()),
                                 static_cast<int>(out.size()),
                                 0);
            if (got <= 0) {
                out.clear();
                return secure::DatagramReceiveResult::Error;
            }
            out.resize(static_cast<std::size_t>(got));
            return secure::DatagramReceiveResult::Received;
        };

        auto close_fn = [s = sock_.load(std::memory_order_acquire)]() noexcept {
            (void)::shutdown(s, SD_BOTH);
        };

        auto transport = std::make_unique<secure::DatagramTransport>(
            std::move(send_fn), std::move(recv_fn), std::move(close_fn));
        std::lock_guard password_lock{password_mutex_};
        CHECK(running_.load(std::memory_order_acquire) && !password_.empty(),
              kClientCancelled);
        tls = std::make_shared<secure::SecureSocket>(
            sock_.load(std::memory_order_acquire),
            std::move(transport),
            password_,
            /*is_server=*/false,
            cipher_suite_,
            /*owns_socket=*/true,
            rotation_policy_);
    }
    tls_ = tls;
    tls_guard.unlock();
    tls->handshake();
    tls_guard.lock();
    tls_guard.unlock();
    if (transport_ == TransportProtocol::Udp) {
        // DTLS uses the already-established wolfSSL session for in-place
        // record-key updates; it never needs the group password again.
        // TCP renewal intentionally retains it for the replacement handshake.
        clear_password();
    }
    if (transport_ == TransportProtocol::Tcp) {
        std::cout << "[🔒] Native TLS 1.3 established "
                     "(TLS_AES_256_GCM_SHA384, exporter-bound shared-key authentication)\n";
    } else {
        std::cout << "[🔒] wolfSSL DTLS 1.3 established "
                     "(TLS_AES_256_GCM_SHA384, P-256 ECDHE-PSK)\n";
    }
    if (!running_) {
        throw std::runtime_error(kClientCancelled);
    }
}

void VpnClient::requestConfig() {
    const auto tls = tls_snapshot();
    CHECK(tls != nullptr, "Secure transport is unavailable");
    constexpr std::string_view request = "VPN_REQUEST_CONFIG";
    tls->send_record(PACKET_TYPE_MSG,
                     reinterpret_cast<const uint8_t*>(request.data()),
                     static_cast<uint16_t>(request.size()));
    uint8_t type=0; std::array<uint8_t,256> buf{};
    int n = tls->recv_record(type, buf.data(), buf.size());
    if (n <= 0 || type != PACKET_TYPE_MSG) {
        throw std::runtime_error("Failed to receive config from server");
    }

    std::string config(reinterpret_cast<const char*>(buf.data()),
                       static_cast<std::size_t>(n));

    constexpr std::string_view prefix = "VPN_CFG:IP=";
    constexpr std::string_view gateway_marker = ";GW=";
    constexpr std::string_view mask_marker = ";MASK=";
    if (config.rfind(prefix, 0) != 0) {
        throw std::runtime_error("Invalid config prefix");
    }
    const std::size_t gateway_pos = config.find(gateway_marker, prefix.size());
    const std::size_t mask_pos = gateway_pos == std::string::npos
                                     ? std::string::npos
                                     : config.find(mask_marker, gateway_pos + gateway_marker.size());
    if (gateway_pos == std::string::npos || mask_pos == std::string::npos ||
        config.find(';', mask_pos + mask_marker.size()) != std::string::npos) {
        throw std::runtime_error("Invalid config format");
    }

    local_ip_ = config.substr(prefix.size(), gateway_pos - prefix.size());
    gateway_ = config.substr(gateway_pos + gateway_marker.size(),
                             mask_pos - gateway_pos - gateway_marker.size());
    subnetmask_ = config.substr(mask_pos + mask_marker.size());

    IN_ADDR local_addr{};
    IN_ADDR gateway_addr{};
    IN_ADDR mask_addr{};
    CHECK(inet_pton(AF_INET, local_ip_.c_str(), &local_addr) == 1,
          "Invalid assigned client IPv4 address");
    CHECK(inet_pton(AF_INET, gateway_.c_str(), &gateway_addr) == 1,
          "Invalid VPN gateway IPv4 address");
    CHECK(inet_pton(AF_INET, subnetmask_.c_str(), &mask_addr) == 1,
          "Invalid VPN subnet mask");
    CHECK(gateway_ == "10.10.100.1" && subnetmask_ == "255.255.255.255",
          "Unexpected VPN gateway or subnet mask");
    const uint32_t client_address = ntohl(local_addr.S_un.S_addr);
    const uint32_t expected_prefix = (10U << 24U) | (10U << 16U) | (100U << 8U);
    CHECK((client_address & 0xFFFFFF00U) == expected_prefix &&
              (client_address & 0xFFU) >= 2U && (client_address & 0xFFU) <= 254U,
          "Assigned client IPv4 address is outside the VPN pool");

    std::cout << "[*] VPN Config:\n"
              << "    IP   = " << local_ip_ << "\n"
              << "    GW   = " << gateway_ << "\n"
              << "    MASK = " << subnetmask_ << "\n";
    if (!running_) {
        throw std::runtime_error(kClientCancelled);
    }
}

void VpnClient::configureAdapter() {
    // Publish adapter/session state and both workers as one lifecycle
    // transaction. stop() therefore either cancels before configuration or
    // observes a complete worker set that it can safely close and join.
    std::lock_guard<std::mutex> lifecycle_guard(stop_mutex_);
    if (!running_) {
        throw std::runtime_error(kClientCancelled);
    }

	adaptername_ = validate_wintun_adapter_name(adaptername_);
    gateway_ = sanitize_ip(gateway_);

    nat_public_installed_ = false;
    nat_private_installed_ = false;
    protected_route_.reset();
    tunnel_route_.reset();

	std::cout << "[*] Creating stable Wintun adapter: " << adaptername_ << "\n";
	adapter_.emplace(adaptername_);
	std::cout << "[✓] Wintun adapter created with stable Windows identity\n";

    SetStaticIPv4Address(adapter_->luid(), local_ip_, subnetmask_);
    tunnel_route_ = AddIpv4Route(
        adapter_->luid(), "10.10.100.0", 24U, "10.10.100.1", 1U);
    SetInterfaceMtu(adapter_->luid(), 1380U);

    std::cout << "[✓] Adapter configured\n";
    if (!running_) {
        throw std::runtime_error(kClientCancelled);
    }


    WINTUN_SESSION_HANDLE session_handle = WintunStartSession(adapter_->get(), 0x400000);
    CHECK(session_handle != nullptr, "WintunStartSession failed");
    session_ = std::make_unique<WintunSessionGuard>(session_handle);
    cancellation_event_ = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    CHECK(cancellation_event_ != nullptr, "CreateEvent(cancellation) failed");

    // Ensure a remote server endpoint stays on the physical uplink once the
    // tunnel is active. A locally assigned endpoint is the same-host E2E case;
    // its Windows-owned host route must never be replaced or deleted.
    if (!resolved_server_ip_.empty()) {
        if (IsIpv4AddressAssignedLocally(resolved_server_ip_)) {
            std::cout << "[*] Server endpoint " << resolved_server_ip_
                      << " is local; preserving its Windows host route\n";
        } else if (auto gw = get_gateway_for_adapter(real_adapter_luid_);
                   gw && !gw->empty() && *gw != resolved_server_ip_) {
            protected_route_ = AddIpv4Route(
                real_adapter_luid_, resolved_server_ip_, 32U, *gw, 1U);
            std::cout << "[*] Keeping server " << resolved_server_ip_
                      << " on uplink via "
                      << *gw << "\n";
        } else {
            std::cerr << "[!] Unable to determine gateway for adapter '" << real_adapter_
                      << "'; server route not pinned\n"
                      << "      -> Ensure the adapter has a valid IPv4 gateway configured." << std::endl;
        }
    }

    // Preserve any RRAS NAT configuration owned by the administrator or
    // another service. Cleanup removes only bindings whose add succeeded here.
    if (!running_) throw std::runtime_error(kClientCancelled);

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
        std::cerr << "[!] Failed to enable NAT on uplink interface '"
                  << real_adapter_ << "'\n"
                  << "      -> Install/enable the 'Routing and Remote Access' feature on Windows." << std::endl;
    }

    if (!running_) throw std::runtime_error(kClientCancelled);

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
    if (!running_) {
        throw std::runtime_error(kClientCancelled);
    }

    WINTUN_SESSION_HANDLE raw_session = session_->get();
    auto tun_worker = [this, raw_session]() {
        try {
            const auto snapshot = [this]() {
                return tls_snapshot();
            };
            tun_to_tls(raw_session, snapshot, tls_write_mutex_,
                       std::ref(running_), &tcp_old_writes_blocked_,
                       &tcp_control_write_pending_,
                       cancellation_event_);
        } catch (const std::exception& ex) {
            std::cerr << "[!] tun_to_tls thread error: " << ex.what() << "\n";
            running_ = false;
        }
        heartbeat_wait_cv_.notify_all();
        rotation_wait_cv_.notify_all();
        drain_wait_cv_.notify_all();
        std::cout << "[INFO] Stopped forwarding Wintun -> TLS\n";
    };
    tun_thread_ = std::thread(std::move(tun_worker));

    const auto initial_tls = tls_snapshot();
    CHECK(initial_tls != nullptr, "Secure transport is unavailable");
    auto tls_worker = [this, raw_session, initial_tls]() {
        auto maybe_forward = [this](BYTE* packet, UINT size) {
            note_authenticated_receive();
#ifdef TRUETUNNEL_INTEGRATION_TEST
            IntegrationPacketObserver observer;
            {
                std::lock_guard<std::mutex> lock(integration_observer_mutex_);
                observer = integration_packet_observer_;
            }
            if (observer) {
                return observer(std::span<const std::uint8_t>{packet, size});
            }
#else
            (void)packet;
            (void)size;
#endif
            return false;
        };
        auto on_message = [this](std::string_view msg) {
            note_authenticated_receive();
            handle_incoming_message(msg);
        };
        auto on_control = [this](
                              const std::uint8_t type,
                              const std::span<const std::uint8_t> payload) {
            return handle_control_record(type, payload);
        };
        auto generation = initial_tls;
        while (running_.load(std::memory_order_acquire)) {
            std::atomic<bool> generation_running{true};
            std::string receive_error;
            try {
                tls_to_tun_common(raw_session,
                                  generation.get(),
                                  generation_running,
                                  session_mutex_,
                                  maybe_forward,
                                  on_message,
                                  on_control);
            } catch (const std::exception& ex) {
                receive_error = ex.what();
            } catch (...) {
                receive_error = "unknown secure-record failure";
            }
            if (!running_) break;
            auto current = tls_snapshot();
            if (current == generation &&
                tcp_old_writes_blocked_.load(std::memory_order_acquire)) {
                // The server retires OLD immediately after sending COMMIT on
                // NEW. That close can reach this reader a few instructions
                // before the replacement thread publishes NEW locally. Wait
                // for the bounded handoff decision instead of mistaking that
                // expected close for an outage.
                std::unique_lock wait_lock{rotation_wait_mutex_};
                rotation_wait_cv_.wait_for(
                    wait_lock, std::chrono::seconds{3},
                    [this, &generation]() {
                        return !running_.load(std::memory_order_acquire) ||
                            !tcp_old_writes_blocked_.load(
                                std::memory_order_acquire) ||
                            tls_snapshot() != generation;
                    });
                current = tls_snapshot();
            }
            if (!running_) break;
            if (!current || current == generation) {
                if (!receive_error.empty()) {
                    std::cerr << "[!] TLS receive thread error: "
                              << receive_error << "\n";
                } else {
                    std::cerr << "[!] Secure channel closed by peer; stopping client\n";
                }
                running_ = false;
                break;
            }
            // The old generation was closed after an authenticated handoff.
            // Continue the same receive worker on the new generation so there
            // is never a second competing receiver or a receive gap caused by
            // thread startup.
            generation = current;
        }
        heartbeat_wait_cv_.notify_all();
        rotation_wait_cv_.notify_all();
        drain_wait_cv_.notify_all();
    };
    last_authenticated_receive_ticks_.store(
        steady_clock_ticks(), std::memory_order_release);
    tls_thread_ = std::thread(std::move(tls_worker));
    if (recovery_.enabled) {
        heartbeat_thread_ = std::thread(
            &VpnClient::heartbeatLoop, this);
        heartbeat_watchdog_thread_ = std::thread(
            &VpnClient::heartbeatWatchdogLoop, this);
        std::cout << "[INFO] Automatic recovery enabled: authenticated heartbeat every "
                  << recovery_.heartbeat_interval.count() << " ms, "
                  << recovery_.heartbeat_timeout.count()
                  << " ms liveness timeout\n";
    }

    if (!SetNetworkCategoryPrivate(adapter_->luid())) {
        std::cerr << "[!] Windows did not expose the Wintun network profile in time; "
                     "its firewall category was not changed\n";
    }

    icmp_firewall_rule_.emplace(AddIcmpV4FirewallRule(adaptername_));

    if (transport_ == TransportProtocol::Tcp) {
        tcp_rotation_thread_ = std::thread(
            &VpnClient::tcpSessionReplacementLoop, this);
    }

}

void VpnClient::note_authenticated_receive() noexcept {
    last_authenticated_receive_ticks_.store(
        steady_clock_ticks(), std::memory_order_release);
    heartbeat_wait_cv_.notify_all();
    drain_wait_cv_.notify_all();
}

bool VpnClient::handle_control_record(
    const std::uint8_t type,
    const std::span<const std::uint8_t> payload) {
    if (type == PACKET_TYPE_SESSION_REPLACEMENT_FREEZE_ACK ||
        type == PACKET_TYPE_SESSION_DRAIN_ACK ||
        type == PACKET_TYPE_SESSION_DRAIN_BARRIER) {
        std::array<std::uint8_t, kSessionReplacementNonceSize> nonce{};
        if (!decode_session_drain_frame(payload, nonce)) return true;
        {
            std::lock_guard drain_lock{drain_wait_mutex_};
            const bool nonce_matches =
                secure::ct_memcmp(nonce.data(), drain_nonce_.data(),
                                  nonce.size()) == 0;
#ifdef TRUETUNNEL_INTEGRATION_TEST
            if (type == PACKET_TYPE_SESSION_REPLACEMENT_FREEZE_ACK) {
                std::cout << "[E2E][FREEZE] client received acknowledgement; "
                          << (nonce_matches ? "nonce matched" : "nonce mismatched")
                          << '\n';
            }
#endif
            if (!nonce_matches) {
                return true;
            }
            if (type == PACKET_TYPE_SESSION_REPLACEMENT_FREEZE_ACK) {
                replacement_freeze_acknowledged_ = true;
            } else if (type == PACKET_TYPE_SESSION_DRAIN_ACK) {
                drain_acknowledged_ = true;
            } else {
                drain_barrier_received_ = true;
            }
        }
        drain_wait_cv_.notify_all();
        ::SecureZeroMemory(nonce.data(), nonce.size());
        note_authenticated_receive();
        return true;
    }
    if (!recovery_.enabled || type != PACKET_TYPE_HEARTBEAT_ACK) {
        return false;
    }

    HeartbeatControlFrame frame{};
    if (!decode_heartbeat_control_frame(payload, frame) ||
        frame.interval_ms != static_cast<std::uint32_t>(
                                 recovery_.heartbeat_interval.count()) ||
        frame.timeout_ms != static_cast<std::uint32_t>(
                                recovery_.heartbeat_timeout.count())) {
        return false;
    }

    const std::uint64_t sent = heartbeat_sequence_.load(
        std::memory_order_acquire);
    if (frame.sequence > sent) {
        return false;
    }

    std::uint64_t acknowledged = heartbeat_last_ack_sequence_.load(
        std::memory_order_relaxed);
    while (frame.sequence > acknowledged &&
           !heartbeat_last_ack_sequence_.compare_exchange_weak(
               acknowledged, frame.sequence,
               std::memory_order_release, std::memory_order_relaxed)) {
    }
    if (frame.sequence > acknowledged) {
        heartbeat_acknowledgements_.fetch_add(1U, std::memory_order_relaxed);
    }
    note_authenticated_receive();
    return true;
}

void VpnClient::terminate_unresponsive_channel(const char* reason) noexcept {
    const bool was_running = running_.exchange(false, std::memory_order_acq_rel);
    heartbeat_wait_cv_.notify_all();
    rotation_wait_cv_.notify_all();
    drain_wait_cv_.notify_all();
    if (was_running && reason != nullptr) {
        std::cerr << "[!] " << reason << '\n';
    }
    if (cancellation_event_ != nullptr) {
        ::SetEvent(cancellation_event_);
    }
    const auto tls = tls_snapshot();
    if (tls) {
        try {
            tls->close();
        } catch (...) {
        }
    }
    std::shared_ptr<secure::SecureSocket> pending_replacement;
    {
        std::lock_guard pending_lock{pending_replacement_mutex_};
        pending_replacement = pending_replacement_tls_;
    }
    if (pending_replacement) {
        try {
            pending_replacement->close();
        } catch (...) {
        }
    }
}

SOCKET VpnClient::connectReplacementSocket(const std::string& bind_ip) {
    if (!running_.load(std::memory_order_acquire)) {
        throw std::runtime_error(kClientCancelled);
    }

    const auto endpoints = resolve_server_ipv4_endpoints(
        server_address_, static_cast<std::uint16_t>(port_),
        TransportProtocol::Tcp, &running_);
    int last_error = WSAHOST_NOT_FOUND;
    for (const auto& endpoint : endpoints) {
        SocketGuard candidate{::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
        CHECK(candidate.get() != INVALID_SOCKET,
              "replacement socket creation failed");

        int reuse = 1;
        (void)::setsockopt(candidate.get(), SOL_SOCKET, SO_REUSEADDR,
                           reinterpret_cast<const char*>(&reuse), sizeof(reuse));
        int nodelay = 1;
        (void)::setsockopt(candidate.get(), IPPROTO_TCP, TCP_NODELAY,
                           reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));

        sockaddr_in local{};
        local.sin_family = AF_INET;
        CHECK(::inet_pton(AF_INET, bind_ip.c_str(), &local.sin_addr) == 1,
              "invalid replacement bind address");
        if (::bind(candidate.get(), reinterpret_cast<const sockaddr*>(&local),
                   sizeof(local)) == SOCKET_ERROR) {
            last_error = ::WSAGetLastError();
            continue;
        }

        u_long nonblocking = 1UL;
        CHECK(::ioctlsocket(candidate.get(), FIONBIO, &nonblocking) != SOCKET_ERROR,
              "replacement socket nonblocking setup failed");
        // Publish the raw descriptor before connect/select so stop() can
        // interrupt the short make-before-break connect phase as well as the
        // registered SecureSocket handshake that follows it. SocketGuard
        // remains the sole owner; stop() only performs shutdown here.
        pending_socket_.store(candidate.get(), std::memory_order_release);
        bool connected = ::connect(
                             candidate.get(),
                             reinterpret_cast<const sockaddr*>(&endpoint.address),
                             sizeof(endpoint.address)) == 0;
        last_error = connected ? 0 : ::WSAGetLastError();
        if (!connected &&
            (last_error == WSAEWOULDBLOCK || last_error == WSAEINPROGRESS ||
             last_error == WSAEALREADY)) {
            const auto deadline =
                std::chrono::steady_clock::now() + std::chrono::seconds{10};
            while (running_.load(std::memory_order_acquire) &&
                   std::chrono::steady_clock::now() < deadline) {
                fd_set writable{};
                fd_set exceptional{};
                FD_ZERO(&writable);
                FD_ZERO(&exceptional);
                FD_SET(candidate.get(), &writable);
                FD_SET(candidate.get(), &exceptional);
                timeval timeout{};
                timeout.tv_usec = 50'000L;
                const int selected = ::select(
                    0, nullptr, &writable, &exceptional, &timeout);
                if (selected == SOCKET_ERROR) {
                    last_error = ::WSAGetLastError();
                    break;
                }
                if (selected == 0) continue;
                int socket_error = 0;
                int error_size = sizeof(socket_error);
                if (::getsockopt(candidate.get(), SOL_SOCKET, SO_ERROR,
                                 reinterpret_cast<char*>(&socket_error),
                                 &error_size) == SOCKET_ERROR) {
                    last_error = ::WSAGetLastError();
                } else {
                    last_error = socket_error;
                    connected = socket_error == 0;
                }
                break;
            }
            if (!connected && last_error == 0) last_error = WSAETIMEDOUT;
        }
        if (connected && running_.load(std::memory_order_acquire)) {
            // Keep the descriptor published until the caller has registered
            // the owning SecureSocket with stop(). This closes the otherwise
            // narrow shutdown race between connect() and pending TLS setup.
            return candidate.release();
        }
        pending_socket_.store(INVALID_SOCKET, std::memory_order_release);
        if (connected) {
            throw std::runtime_error(kClientCancelled);
        }
    }
    if (!running_.load(std::memory_order_acquire)) {
        throw std::runtime_error(kClientCancelled);
    }
    throw std::system_error(
        last_error, std::system_category(), "TCP session replacement connect");
}

void VpnClient::replaceTcpSession() {
    if (transport_ != TransportProtocol::Tcp ||
        !running_.load(std::memory_order_acquire)) {
        return;
    }

    session_replacement_attempts_.fetch_add(1U, std::memory_order_relaxed);
    const auto old_tls = tls_snapshot();
    if (!old_tls) {
        session_replacement_failures_.fetch_add(1U, std::memory_order_relaxed);
        return;
    }
    tcp_replacement_active_.store(true, std::memory_order_release);

    std::array<std::uint8_t, kSessionReplacementNonceSize> nonce{};
    std::array<std::uint8_t, kSessionReplacementRequestSize> encoded_request{};
    std::array<std::uint8_t, kSessionReplacementAckSize> ack{};
    std::array<std::uint8_t, kSessionReplacementNonceSize> ack_nonce{};
    std::array<std::uint8_t, 32> new_binding{};
    SessionReplacementRequest request{};
    std::shared_ptr<secure::SecureSocket> replacement;
    bool writes_paused = false;
    std::chrono::steady_clock::time_point handoff_start{};
    std::chrono::steady_clock::time_point handoff_deadline{};
    std::uint8_t ack_type = 0U;
    bool decision_attempted = false;
    std::atomic<bool> stop_timeout_monitor{false};
    std::atomic<bool> timeout_armed{false};
    std::thread timeout_monitor;
    const auto stop_timeout_monitor_thread = [&]() noexcept {
        timeout_armed.store(false, std::memory_order_release);
        stop_timeout_monitor.store(true, std::memory_order_release);
        tcp_replacement_active_.store(false, std::memory_order_release);
        if (timeout_monitor.joinable()) timeout_monitor.join();
    };
    const auto clear_drain_state = [this]() noexcept {
        std::lock_guard drain_lock{drain_wait_mutex_};
        ::SecureZeroMemory(drain_nonce_.data(), drain_nonce_.size());
        replacement_freeze_acknowledged_ = false;
        drain_acknowledged_ = false;
        drain_barrier_received_ = false;
    };
    const auto abort_drain = [&]() noexcept {
        if (!writes_paused || !old_tls ||
            !running_.load(std::memory_order_acquire)) return;
#ifdef TRUETUNNEL_INTEGRATION_TEST
        std::cout << "[E2E][ABORT] client attempting authenticated rollback\n";
#endif
        try {
            std::lock_guard write_guard{tls_write_mutex_};
            if (tls_snapshot() != old_tls) return;
            const auto frame = encode_session_drain_frame(nonce);
            if (handoff_deadline ==
                    std::chrono::steady_clock::time_point{} ||
                std::chrono::steady_clock::now() >= handoff_deadline) {
#ifdef TRUETUNNEL_INTEGRATION_TEST
                std::cout << "[E2E][ABORT] client rollback deadline expired "
                             "before write\n";
#endif
                return;
            }
            const int sent = old_tls->send_record_until(
                PACKET_TYPE_SESSION_DRAIN_ABORT,
                frame.data(), static_cast<std::uint16_t>(frame.size()),
                handoff_deadline);
#ifndef TRUETUNNEL_INTEGRATION_TEST
            (void)sent;
#endif
#ifdef TRUETUNNEL_INTEGRATION_TEST
            std::cout << "[E2E][ABORT] client rollback record sent; bytes="
                      << sent << '\n';
#endif
        } catch (const std::exception& error) {
#ifdef TRUETUNNEL_INTEGRATION_TEST
            std::cout << "[E2E][ABORT] client rollback write failed: "
                      << error.what() << '\n';
#else
            (void)error;
#endif
        } catch (...) {
#ifdef TRUETUNNEL_INTEGRATION_TEST
            std::cout << "[E2E][ABORT] client rollback write failed: unknown\n";
#endif
        }
    };
    const auto terminate_if_hard_limit = [this]() noexcept {
        const auto current = tls_snapshot();
        if (!current) return;
        const auto stats = current->rotation_stats();
        const bool hard_records =
            rotation_policy_.max_records != 0U &&
            (stats.sent_records >= rotation_policy_.max_records ||
             stats.received_records >= rotation_policy_.max_records);
        const bool hard_bytes =
            rotation_policy_.max_bytes != 0U &&
            (stats.sent_bytes >= rotation_policy_.max_bytes ||
             stats.received_bytes >= rotation_policy_.max_bytes);
        const bool hard_age =
            rotation_policy_.max_age > std::chrono::seconds::zero() &&
            stats.age_microseconds >= secure::rotation_age_limit_microseconds(
                rotation_policy_.max_age);
        if (hard_records || hard_bytes || hard_age) {
            terminate_unresponsive_channel(
                "TLS replacement could not complete before the hard policy limit");
        }
    };
    try {
        IN_ADDR assigned{};
        CHECK(::inet_pton(AF_INET, local_ip_.c_str(), &assigned) == 1,
              "invalid assigned IPv4 address during TLS replacement");
        std::memcpy(request.assigned_ipv4.data(), &assigned.S_un.S_addr,
                    request.assigned_ipv4.size());
        secure::random_bytes(nonce.data(), nonce.size());
        request.nonce = nonce;

        // Freeze application writes before asking OLD to freeze server
        // egress.  FREEZE_ACK is authenticated by OLD TLS and is serialized
        // after every earlier server application record.  From this point to
        // COMMIT_ACK, one absolute deadline bounds both the availability cost
        // and the amount of OLD-generation key material that can be used.
        const auto exchange_start = std::chrono::steady_clock::now();
        handoff_start = exchange_start;
        handoff_deadline = exchange_start + kTcpHandoffClientPauseBudget;
        const auto exchange_deadline =
            handoff_deadline - kTcpHandoffRollbackReserve;
        const auto handoff_deadline_ticks =
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                handoff_deadline.time_since_epoch()).count();
        {
            std::lock_guard write_guard{tls_write_mutex_};
            CHECK(running_.load(std::memory_order_acquire) &&
                      tls_snapshot() == old_tls,
                  "TLS session changed before TLS replacement freeze");
            {
                std::lock_guard drain_lock{drain_wait_mutex_};
                drain_nonce_ = nonce;
                replacement_freeze_acknowledged_ = false;
                drain_acknowledged_ = false;
                drain_barrier_received_ = false;
            }
            tcp_handoff_deadline_ticks_.store(
                handoff_deadline_ticks, std::memory_order_release);
            tcp_handoff_decision_attempted_.store(
                false, std::memory_order_release);
            tcp_old_writes_blocked_.store(true, std::memory_order_release);
            writes_paused = true;
            heartbeat_wait_cv_.notify_all();
            rotation_wait_cv_.notify_all();

            const auto freeze_frame = encode_session_drain_frame(nonce);
            CHECK(old_tls->send_record_until(
                      PACKET_TYPE_SESSION_REPLACEMENT_FREEZE,
                      freeze_frame.data(),
                      static_cast<std::uint16_t>(freeze_frame.size()),
                      exchange_deadline) ==
                      static_cast<int>(freeze_frame.size()),
                  "TLS replacement freeze request write failed");
        }

        timeout_armed.store(true, std::memory_order_release);
        timeout_monitor = std::thread(
            [this, handoff_deadline, handoff_deadline_ticks,
             &stop_timeout_monitor, &timeout_armed]() {
                while (!stop_timeout_monitor.load(std::memory_order_acquire)) {
                    if (std::chrono::steady_clock::now() >= handoff_deadline) {
                        if (timeout_armed.exchange(
                                false, std::memory_order_acq_rel) &&
                            tcp_replacement_active_.load(
                                std::memory_order_acquire) &&
                            tcp_old_writes_blocked_.load(
                                std::memory_order_acquire) &&
                            tcp_handoff_deadline_ticks_.load(
                                std::memory_order_acquire) ==
                                handoff_deadline_ticks) {
                            terminate_unresponsive_channel(
                                "TLS replacement exceeded the bounded "
                                "handoff pause");
                        }
                        return;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds{2});
                }
            });

        {
            std::unique_lock drain_lock{drain_wait_mutex_};
            const bool frozen = drain_wait_cv_.wait_until(
                drain_lock, exchange_deadline, [this]() {
                    return replacement_freeze_acknowledged_ ||
                           !running_.load(std::memory_order_acquire);
                });
            CHECK(frozen && replacement_freeze_acknowledged_,
                  "TLS replacement freeze acknowledgement timed out");
        }

        const std::string bind_ip = get_ipv4_for_adapter(real_adapter_luid_);
        CHECK(!bind_ip.empty(),
              "could not resolve pinned uplink for TLS replacement");
        SocketGuard replacement_socket{connectReplacementSocket(bind_ip)};
        {
            std::lock_guard password_lock{password_mutex_};
            CHECK(running_.load(std::memory_order_acquire) && !password_.empty(),
                  kClientCancelled);
            replacement = std::make_shared<secure::SecureSocket>(
                replacement_socket.get(), password_, false, cipher_suite_,
                rotation_policy_);
        }
        replacement_socket.release();
        {
            std::lock_guard pending_lock{pending_replacement_mutex_};
            CHECK(running_.load(std::memory_order_acquire), kClientCancelled);
            pending_replacement_tls_ = replacement;
        }
        const SOCKET published_socket = replacement->native();
        SOCKET expected_socket = published_socket;
        (void)pending_socket_.compare_exchange_strong(
            expected_socket, INVALID_SOCKET, std::memory_order_acq_rel,
            std::memory_order_acquire);
        CHECK(running_.load(std::memory_order_acquire), kClientCancelled);
        replacement->handshake();
        CHECK(running_.load(std::memory_order_acquire) &&
                  std::chrono::steady_clock::now() < exchange_deadline,
              "TLS replacement handshake exceeded the bounded handoff deadline");

        // Proof construction is intentionally after the NEW handshake.  Both
        // exporters are then authenticated and the proof binds the exact pair
        // of TLS generations, nonce, and assigned address.
        new_binding = replacement->continuity_binding();
        request.proof = old_tls->replacement_proof(
            nonce, request.assigned_ipv4,
            std::span<const std::uint8_t>{new_binding.data(), new_binding.size()});

        // PREP is deliberately sent only on NEW after the authenticated OLD
        // freeze has been acknowledged.  Its proof binds both TLS exporters,
        // the nonce, and the assigned address.
        encoded_request = encode_session_replacement_request(request);
        CHECK(running_.load(std::memory_order_acquire), kClientCancelled);
        CHECK(replacement->send_record_until(
                  PACKET_TYPE_SESSION_REPLACEMENT,
                  encoded_request.data(),
                  static_cast<std::uint16_t>(encoded_request.size()),
                  exchange_deadline) ==
                  static_cast<int>(encoded_request.size()),
              "TLS replacement request write failed");

        CHECK(replacement->recv_record_until(
                  ack_type, ack.data(), ack.size(), exchange_deadline) ==
                  static_cast<int>(ack.size()) &&
                  ack_type == PACKET_TYPE_SESSION_REPLACEMENT_ACK,
              "TLS replacement preparation acknowledgement was invalid");
        CHECK(decode_session_replacement_ack(ack, ack_nonce) &&
                  secure::ct_memcmp(ack_nonce.data(), nonce.data(), nonce.size()) == 0,
              "TLS replacement preparation nonce mismatch");

        // FREEZE already covers every application sender.  DRAIN now marks
        // the last accepted OLD ingress and obtains the authenticated barrier
        // without extending the original deadline.
        {
            std::lock_guard write_guard{tls_write_mutex_};
            CHECK(running_.load(std::memory_order_acquire) &&
                      tls_snapshot() == old_tls,
                  "TLS session changed before TLS handoff drain");
            const auto drain_frame = encode_session_drain_frame(nonce);
            CHECK(old_tls->send_record_until(
                      PACKET_TYPE_SESSION_DRAIN_REQUEST,
                      drain_frame.data(),
                      static_cast<std::uint16_t>(drain_frame.size()),
                      exchange_deadline) ==
                  static_cast<int>(drain_frame.size()),
                  "TLS drain request write failed");
        }
        {
            std::unique_lock drain_lock{drain_wait_mutex_};
            const bool drained = drain_wait_cv_.wait_until(
                drain_lock, exchange_deadline, [this]() {
                    return (drain_acknowledged_ && drain_barrier_received_) ||
                           !running_.load(std::memory_order_acquire);
                });
            CHECK(drained && drain_acknowledged_ && drain_barrier_received_,
                  "TLS old-generation drain barrier timed out");
        }

        // READY is a reversible checkpoint.  ACTIVATE is the explicit,
        // authenticated decision that makes rollback unsafe.
        CHECK(replacement->recv_record_until(
                  ack_type, ack.data(), ack.size(), exchange_deadline) ==
                  static_cast<int>(ack.size()) &&
                  ack_type == PACKET_TYPE_SESSION_REPLACEMENT_READY &&
                  decode_session_replacement_ack(ack, ack_nonce) &&
                  secure::ct_memcmp(ack_nonce.data(), nonce.data(), nonce.size()) == 0,
              "TLS replacement ready acknowledgement was invalid");

        const auto activate = encode_session_replacement_ack(nonce);
        tcp_handoff_decision_attempted_.store(
            true, std::memory_order_release);
        decision_attempted = true;
        CHECK(replacement->send_record_until(
                  PACKET_TYPE_SESSION_REPLACEMENT_ACTIVATE,
                  activate.data(), static_cast<std::uint16_t>(activate.size()),
                  exchange_deadline) == static_cast<int>(activate.size()),
              "TLS replacement activation write failed");

        CHECK(replacement->recv_record_until(
                  ack_type, ack.data(), ack.size(), exchange_deadline) ==
                  static_cast<int>(ack.size()) &&
                  ack_type == PACKET_TYPE_SESSION_REPLACEMENT_COMMIT &&
                  decode_session_replacement_ack(ack, ack_nonce) &&
                  secure::ct_memcmp(ack_nonce.data(), nonce.data(), nonce.size()) == 0,
              "TLS replacement commit acknowledgement was invalid");

        const SOCKET new_socket = replacement->native();
        {
            std::lock_guard write_guard{tls_write_mutex_};
            std::lock_guard tls_guard{tls_mutex_};
            CHECK(running_.load(std::memory_order_acquire) && tls_ == old_tls,
                  "TLS session stopped during replacement handoff");
            tls_ = replacement;
            sock_.store(new_socket, std::memory_order_release);
            const auto commit_ack = encode_session_replacement_ack(nonce);
            CHECK(replacement->send_record_until(
                      PACKET_TYPE_SESSION_REPLACEMENT_COMMIT_ACK,
                      commit_ack.data(),
                      static_cast<std::uint16_t>(commit_ack.size()),
                      exchange_deadline) == static_cast<int>(commit_ack.size()),
                  "TLS replacement commit receipt write failed");
        }
        // COMMIT is an authenticated NEW-generation receive.  Refresh the
        // liveness clock before removing the bounded handoff grace so an
        // aggressive 100/200 ms watchdog does not close a successful switch.
        note_authenticated_receive();
        // Disarm the finite timeout before publishing the unblocked state.
        // Successful network phases finish by exchange_deadline, leaving the
        // rollback reserve for these local publication steps.
        stop_timeout_monitor_thread();
        tcp_old_writes_blocked_.store(false, std::memory_order_release);
        tcp_handoff_deadline_ticks_.store(0, std::memory_order_release);
        tcp_handoff_decision_attempted_.store(false, std::memory_order_release);
        heartbeat_wait_cv_.notify_all();
        writes_paused = false;
        clear_drain_state();
        {
            std::lock_guard pending_lock{pending_replacement_mutex_};
            if (pending_replacement_tls_ == replacement) {
                pending_replacement_tls_.reset();
            }
        }
        rotation_wait_cv_.notify_all();
        const auto handoff_pause = std::chrono::duration_cast<
            std::chrono::microseconds>(std::chrono::steady_clock::now() -
                                       handoff_start).count();
        last_handoff_pause_microseconds_.store(
            static_cast<std::uint64_t>(
                (std::max<std::int64_t>)(1, handoff_pause)),
            std::memory_order_release);
        session_replacement_successes_.fetch_add(1U, std::memory_order_relaxed);
        old_tls->close();
        std::cout << "[INFO] Replaced TCP/TLS session without replacing the VPN adapter\n";
    } catch (const std::exception& error) {
        pending_socket_.store(INVALID_SOCKET, std::memory_order_release);
        if (!decision_attempted) abort_drain();
        stop_timeout_monitor_thread();
        if (replacement) {
            try { replacement->close(); } catch (...) {}
        }
        {
            std::lock_guard pending_lock{pending_replacement_mutex_};
            if (pending_replacement_tls_ == replacement) {
                pending_replacement_tls_.reset();
            }
        }
        if (!decision_attempted &&
            (writes_paused || tcp_old_writes_blocked_.load(
                                  std::memory_order_acquire))) {
            tcp_old_writes_blocked_.store(false, std::memory_order_release);
            rotation_wait_cv_.notify_all();
        }
        tcp_handoff_deadline_ticks_.store(0, std::memory_order_release);
        tcp_handoff_decision_attempted_.store(false, std::memory_order_release);
        heartbeat_wait_cv_.notify_all();
        clear_drain_state();
        session_replacement_failures_.fetch_add(1U, std::memory_order_relaxed);
        if (decision_attempted) {
            if (old_tls) {
                try { old_tls->close(); } catch (...) {}
            }
            terminate_unresponsive_channel(
                "TLS replacement decision became ambiguous; closed both generations");
        } else {
            std::cerr << "[!] TCP/TLS session replacement failed: " << error.what()
                      << " (authenticated OLD session resumed)\n";
            terminate_if_hard_limit();
        }
    } catch (...) {
        pending_socket_.store(INVALID_SOCKET, std::memory_order_release);
        if (!decision_attempted) abort_drain();
        stop_timeout_monitor_thread();
        if (replacement) {
            try { replacement->close(); } catch (...) {}
        }
        {
            std::lock_guard pending_lock{pending_replacement_mutex_};
            if (pending_replacement_tls_ == replacement) {
                pending_replacement_tls_.reset();
            }
        }
        if (!decision_attempted &&
            (writes_paused || tcp_old_writes_blocked_.load(
                                  std::memory_order_acquire))) {
            tcp_old_writes_blocked_.store(false, std::memory_order_release);
            rotation_wait_cv_.notify_all();
        }
        tcp_handoff_deadline_ticks_.store(0, std::memory_order_release);
        tcp_handoff_decision_attempted_.store(false, std::memory_order_release);
        heartbeat_wait_cv_.notify_all();
        clear_drain_state();
        session_replacement_failures_.fetch_add(1U, std::memory_order_relaxed);
        if (decision_attempted) {
            if (old_tls) {
                try { old_tls->close(); } catch (...) {}
            }
            terminate_unresponsive_channel(
                "TLS replacement decision became ambiguous; closed both generations");
        } else {
            std::cerr << "[!] TCP/TLS session replacement failed (authenticated OLD session resumed)\n";
            terminate_if_hard_limit();
        }
    }
    stop_timeout_monitor_thread();
    tcp_old_writes_blocked_.store(false, std::memory_order_release);
    tcp_handoff_deadline_ticks_.store(0, std::memory_order_release);
    tcp_handoff_decision_attempted_.store(false, std::memory_order_release);
    ::SecureZeroMemory(nonce.data(), nonce.size());
    ::SecureZeroMemory(encoded_request.data(), encoded_request.size());
    ::SecureZeroMemory(ack.data(), ack.size());
    ::SecureZeroMemory(ack_nonce.data(), ack_nonce.size());
    ::SecureZeroMemory(request.nonce.data(), request.nonce.size());
    ::SecureZeroMemory(request.proof.data(), request.proof.size());
    ::SecureZeroMemory(new_binding.data(), new_binding.size());
}

void VpnClient::tcpSessionReplacementLoop() {
    std::chrono::milliseconds retry_delay{250};
    auto retry_at = std::chrono::steady_clock::now();
    while (running_.load(std::memory_order_acquire)) {
        {
            std::unique_lock wait_lock{rotation_wait_mutex_};
            rotation_wait_cv_.wait_for(
                wait_lock, std::chrono::milliseconds{100}, [this]() {
                    if (!running_.load(std::memory_order_acquire)) return true;
#ifdef TRUETUNNEL_INTEGRATION_TEST
                    return integration_force_tcp_session_replacement_.load(
                        std::memory_order_acquire);
#else
                    return false;
#endif
                });
        }
        if (!running_.load(std::memory_order_acquire)) break;
        const auto tls = tls_snapshot();
        if (!tls) continue;
        const auto stats = tls->rotation_stats();
        const auto due_before = [](const std::uint64_t value,
                                   const std::uint64_t limit,
                                   const std::uint64_t minimum_margin) noexcept {
            if (limit == 0U) return false;
            const auto margin = (std::max)(minimum_margin, limit / 5U);
            return value >= (limit > margin ? limit - margin : 0U);
        };
        const auto age_limit_us = secure::rotation_age_limit_microseconds(
            rotation_policy_.max_age);
        const bool policy_due =
            due_before(stats.sent_records, rotation_policy_.max_records,
                       kReplacementRecordHeadroom) ||
            due_before(stats.received_records, rotation_policy_.max_records,
                       kReplacementRecordHeadroom) ||
            due_before(stats.sent_bytes, rotation_policy_.max_bytes,
                       kReplacementByteHeadroom) ||
            due_before(stats.received_bytes, rotation_policy_.max_bytes,
                       kReplacementByteHeadroom) ||
            due_before(stats.age_microseconds, age_limit_us,
                       kReplacementAgeHeadroomMicroseconds);
#ifdef TRUETUNNEL_INTEGRATION_TEST
        const bool forced = integration_force_tcp_session_replacement_.exchange(
            false, std::memory_order_acq_rel);
#else
        constexpr bool forced = false;
#endif
        if ((!policy_due && !forced) ||
            (!forced && std::chrono::steady_clock::now() < retry_at)) {
            continue;
        }

        const auto before = tls_snapshot();
        replaceTcpSession();
        const auto after = tls_snapshot();
        if (after && after != before) {
            retry_delay = std::chrono::milliseconds{250};
            retry_at = std::chrono::steady_clock::now();
        } else {
            retry_at = std::chrono::steady_clock::now() + retry_delay;
            retry_delay = (std::min)(retry_delay * 2,
                                     std::chrono::milliseconds{30'000});
        }
    }
}

void VpnClient::heartbeatLoop() {
    const auto timeout_ms = static_cast<std::uint32_t>(
        recovery_.heartbeat_timeout.count());
    const auto interval_ms = static_cast<std::uint32_t>(
        recovery_.heartbeat_interval.count());

    while (running_.load(std::memory_order_acquire)) {
        std::unique_lock<std::mutex> wait_lock(heartbeat_wait_mutex_);
        if (heartbeat_wait_cv_.wait_for(
                wait_lock, recovery_.heartbeat_interval,
                [this]() { return !running_.load(std::memory_order_acquire); })) {
            return;
        }
        wait_lock.unlock();

        std::uint64_t sequence = heartbeat_sequence_.fetch_add(
                                     1U, std::memory_order_acq_rel) +
                                 1U;
        if (sequence == 0U) {
            heartbeat_sequence_.store(1U, std::memory_order_release);
            sequence = 1U;
        }
        const auto frame = encode_heartbeat_control_frame(
            HeartbeatControlFrame{sequence, interval_ms, timeout_ms});

        try {
            if (tcp_old_writes_blocked_.load(std::memory_order_acquire)) {
                continue;
            }
            tcp_control_write_pending_.store(true, std::memory_order_release);
            rotation_wait_cv_.notify_all();
            struct ControlWritePendingGuard final {
                VpnClient* client;
                ~ControlWritePendingGuard() noexcept {
                    client->tcp_control_write_pending_.store(
                        false, std::memory_order_release);
                    client->rotation_wait_cv_.notify_all();
                }
            } control_pending_guard{this};
            std::lock_guard<std::mutex> write_guard(tls_write_mutex_);
            if (!running_.load(std::memory_order_acquire)) return;
            // Once NEW asks the server to reserve OLD egress, heartbeat ACKs
            // are intentionally suppressed there. Use the same finite
            // replacement deadline instead of spending OLD control capacity.
            if (tcp_old_writes_blocked_.load(std::memory_order_acquire)) {
                continue;
            }
            const auto tls = tls_snapshot();
            if (!tls) return;
            const int sent = tls->send_record(
                PACKET_TYPE_HEARTBEAT,
                frame.data(),
                static_cast<std::uint16_t>(frame.size()));
            if (sent != static_cast<int>(frame.size())) {
                throw std::runtime_error("short heartbeat record write");
            }
        } catch (const std::exception& error) {
            const std::string message =
                std::string{"Authenticated heartbeat send failed: "} +
                error.what();
            terminate_unresponsive_channel(message.c_str());
            return;
        } catch (...) {
            terminate_unresponsive_channel(
                "Authenticated heartbeat send failed");
            return;
        }
    }
}

void VpnClient::heartbeatWatchdogLoop() {
    const auto timeout = std::chrono::duration_cast<std::chrono::nanoseconds>(
        recovery_.heartbeat_timeout);

    while (running_.load(std::memory_order_acquire)) {
        const std::int64_t observed_receive =
            last_authenticated_receive_ticks_.load(std::memory_order_acquire);
        const std::int64_t now = steady_clock_ticks();
        const auto elapsed = std::chrono::nanoseconds{
            now > observed_receive ? now - observed_receive : 0};
        const std::int64_t handoff_ticks =
            tcp_handoff_deadline_ticks_.load(std::memory_order_acquire);
        const bool handoff_active =
            tcp_replacement_active_.load(std::memory_order_acquire) &&
            handoff_ticks > 0;
        const std::int64_t timeout_ticks = timeout.count();
        const bool within_handoff_grace =
            handoff_active &&
            now < handoff_ticks + timeout_ticks;
        if (elapsed >= timeout && !within_handoff_grace) {
            // This watchdog is deliberately separate from the heartbeat sender.
            // A congested application write can therefore never postpone the
            // configured liveness deadline; SecureSocket::close() interrupts the
            // blocked TLS/DTLS write before waiting for its I/O locks.
            terminate_unresponsive_channel(
                "Authenticated heartbeat timed out; closing stale secure session");
            return;
        }

        const std::int64_t grace_deadline_ticks =
            handoff_active ? handoff_ticks + timeout_ticks : 0;
        const std::int64_t heartbeat_deadline_ticks =
            observed_receive + timeout_ticks;
        // A timeout that has already elapsed is still covered by the bounded
        // handoff grace.  Use wait_until on the later deadline instead of a
        // negative wait_for duration (which would otherwise busy-spin).
        std::int64_t wake_ticks = heartbeat_deadline_ticks;
        if (grace_deadline_ticks > wake_ticks) {
            wake_ticks = grace_deadline_ticks;
        }
        if (wake_ticks <= now) wake_ticks = now + 1;
        const auto wake_time = std::chrono::steady_clock::time_point{
            std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                std::chrono::nanoseconds{wake_ticks})};
        const auto observed_handoff_ticks = handoff_ticks;
        const bool observed_replacement = tcp_replacement_active_.load(
            std::memory_order_acquire);
        std::unique_lock<std::mutex> wait_lock(heartbeat_wait_mutex_);
        heartbeat_wait_cv_.wait_until(
            wait_lock, wake_time,
            [this, observed_receive, observed_handoff_ticks,
             observed_replacement]() {
                return !running_.load(std::memory_order_acquire) ||
                       last_authenticated_receive_ticks_.load(
                           std::memory_order_acquire) != observed_receive ||
                       tcp_handoff_deadline_ticks_.load(
                           std::memory_order_acquire) != observed_handoff_ticks ||
                       tcp_replacement_active_.load(
                           std::memory_order_acquire) != observed_replacement;
            });
    }
}

bool VpnClient::send_chat_message(const std::string& text) {
    if (!running_) {
        std::cerr << "[!] Cannot send message: client inactive\n";
        return false;
    }
    if (text.empty()) return false;
    if (text.size() > kMaximumChatMessageSize) {
        std::cerr << "[!] Chat message exceeds the selected transport limit\n";
        return false;
    }
    std::unique_lock<std::mutex> lock(tls_write_mutex_, std::defer_lock);
    for (;;) {
        lock.lock();
        if (!tcp_old_writes_blocked_.load(std::memory_order_acquire) &&
            !tcp_control_write_pending_.load(std::memory_order_acquire)) {
            break;
        }
        lock.unlock();
        std::unique_lock wait_lock{rotation_wait_mutex_};
        rotation_wait_cv_.wait_for(
            wait_lock, std::chrono::milliseconds{50}, [this]() {
                return !running_.load(std::memory_order_acquire) ||
                       (!tcp_old_writes_blocked_.load(
                            std::memory_order_acquire) &&
                        !tcp_control_write_pending_.load(
                            std::memory_order_acquire));
            });
        if (!running_.load(std::memory_order_acquire)) return false;
    }
    const auto tls = tls_snapshot();
    if (!tls) return false;
    try {
        int rc = tls->send_record(PACKET_TYPE_MSG,
                                  reinterpret_cast<const uint8_t*>(text.data()),
                                  static_cast<uint16_t>(text.size()));
        if (rc < 0) {
            std::cerr << "[!] Failed to send chat message\n";
            running_ = false;
            heartbeat_wait_cv_.notify_all();
            rotation_wait_cv_.notify_all();
            drain_wait_cv_.notify_all();
            return false;
        }
    } catch (const std::exception& ex) {
        std::cerr << "[!] Exception sending chat message: " << ex.what() << "\n";
        running_ = false;
        heartbeat_wait_cv_.notify_all();
        rotation_wait_cv_.notify_all();
        drain_wait_cv_.notify_all();
        return false;
    }
    return true;
}

#ifdef TRUETUNNEL_INTEGRATION_TEST
void VpnClient::set_integration_packet_observer(
    IntegrationPacketObserver observer) {
    std::lock_guard<std::mutex> lock(integration_observer_mutex_);
    integration_packet_observer_ = std::move(observer);
}

void VpnClient::set_integration_endpoint_observer(
    IntegrationEndpointObserver observer) {
    std::lock_guard<std::mutex> lock(integration_observer_mutex_);
    integration_endpoint_observer_ = std::move(observer);
}

void VpnClient::set_integration_endpoint_attempt_observer(
    IntegrationEndpointAttemptObserver observer) {
    std::lock_guard<std::mutex> lock(integration_observer_mutex_);
    integration_endpoint_attempt_observer_ = std::move(observer);
}

void VpnClient::set_integration_resolved_ipv4_addresses(
    std::vector<std::string> addresses) {
    std::lock_guard<std::mutex> lock(integration_observer_mutex_);
    integration_resolved_ipv4_addresses_ = std::move(addresses);
}

void VpnClient::integration_connect_endpoint_only(
    const std::string& bind_ip) {
    {
        std::lock_guard<std::mutex> stop_guard(stop_mutex_);
        if (start_called_ || stop_requested_.load(std::memory_order_acquire)) {
            throw std::logic_error(
                "integration endpoint client may connect only once");
        }
        start_called_ = true;
        running_.store(true, std::memory_order_release);
    }
    try {
        connectToServerFromBindIp(bind_ip, false);
    } catch (...) {
        running_.store(false, std::memory_order_release);
        stop();
        throw;
    }
}

void VpnClient::integration_connect_secure_endpoint_only(
    const std::string& bind_ip) {
    {
        std::lock_guard<std::mutex> stop_guard(stop_mutex_);
        if (start_called_ || stop_requested_.load(std::memory_order_acquire)) {
            throw std::logic_error(
                "integration secure endpoint client may connect only once");
        }
        start_called_ = true;
        running_.store(true, std::memory_order_release);
    }
    try {
        connectToServerFromBindIp(bind_ip, true);
    } catch (...) {
        running_.store(false, std::memory_order_release);
        stop();
        throw;
    }
}

bool VpnClient::integration_send_endpoint_probe(
    const std::span<const std::uint8_t> payload) const {
    const SOCKET socket = sock_.load(std::memory_order_acquire);
    if (socket == INVALID_SOCKET || payload.empty() ||
        payload.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
        return false;
    }
    return ::send(
               socket,
               reinterpret_cast<const char*>(payload.data()),
               static_cast<int>(payload.size()), 0) ==
           static_cast<int>(payload.size());
}

std::pair<std::string, std::uint16_t>
VpnClient::integration_resolve_server_endpoint(
    const std::string& server_address,
    const std::uint16_t port,
    const TransportProtocol transport) {
    const auto endpoints =
        resolve_server_ipv4_endpoints(server_address, port, transport);
    return {endpoints.front().numeric_ip,
            ::ntohs(endpoints.front().address.sin_port)};
}

bool VpnClient::send_integration_ipv4_packet(
    const std::span<const std::uint8_t> packet) {
    if (!running_ ||
        !is_well_formed_ipv4_packet(packet.data(), packet.size()) ||
        packet.size() > (std::numeric_limits<std::uint16_t>::max)()) {
        return false;
    }

    std::unique_lock<std::mutex> lock(tls_write_mutex_, std::defer_lock);
    for (;;) {
        lock.lock();
        if (!tcp_old_writes_blocked_.load(std::memory_order_acquire) &&
            !tcp_control_write_pending_.load(std::memory_order_acquire)) {
            break;
        }
        lock.unlock();
        std::unique_lock wait_lock{rotation_wait_mutex_};
        rotation_wait_cv_.wait_for(wait_lock, std::chrono::milliseconds{50},
                                   [this]() {
                                        return !running_.load(
                                                   std::memory_order_acquire) ||
                                               (!tcp_old_writes_blocked_.load(
                                                    std::memory_order_acquire) &&
                                                !tcp_control_write_pending_.load(
                                                    std::memory_order_acquire));
                                   });
        if (!running_.load(std::memory_order_acquire)) return false;
    }
    const auto tls = tls_snapshot();
    if (!tls) return false;
    try {
        return tls->send_record(
                   PACKET_TYPE_IP,
                   packet.data(),
                   static_cast<std::uint16_t>(packet.size())) ==
               static_cast<int>(packet.size());
    } catch (const std::exception& error) {
        std::cerr << "[!] Integration packet send failed: "
                  << error.what() << '\n';
        return false;
    }
}

void VpnClient::force_integration_tcp_session_replacement() noexcept {
    integration_force_tcp_session_replacement_.store(
        true, std::memory_order_release);
    rotation_wait_cv_.notify_all();
}

secure::TrafficKeyRotationStats VpnClient::integration_rotation_stats() {
    const auto tls = tls_snapshot();
    auto stats = tls ? tls->rotation_stats() : secure::TrafficKeyRotationStats{};
    stats.session_replacement_attempts =
        session_replacement_attempts_.load(std::memory_order_acquire);
    stats.session_replacement_successes =
        session_replacement_successes_.load(std::memory_order_acquire);
    stats.session_replacement_failures =
        session_replacement_failures_.load(std::memory_order_acquire);
    stats.last_handoff_pause_microseconds =
        last_handoff_pause_microseconds_.load(std::memory_order_acquire);
    return stats;
}
#endif

std::shared_ptr<secure::SecureSocket> VpnClient::tls_snapshot() const {
    std::lock_guard<std::mutex> tls_guard(tls_mutex_);
    return tls_;
}

void VpnClient::handle_incoming_message(std::string_view message) {
    std::string sender = "peer";
    std::string body;
    if (auto pos = message.find('|'); pos != std::string_view::npos) {
        sender = std::string(message.substr(0, pos));
        body = std::string(message.substr(pos + 1));
    } else {
        body.assign(message.begin(), message.end());
    }

    std::cout << "[📨] " << sender << ": " << body << '\n';

    std::string retained = sender + "|" + body;
    constexpr std::size_t kMaximumRetainedMessages = 1024U;
    constexpr std::size_t kMaximumRetainedBytes = 1024U * 1024U;
    {
        std::lock_guard<std::mutex> lock(message_mutex_);
        if (retained.size() > kMaximumRetainedBytes) return;
        while (!received_messages_.empty() &&
               (received_messages_.size() >= kMaximumRetainedMessages ||
                received_message_bytes_ + retained.size() > kMaximumRetainedBytes)) {
            received_message_bytes_ -= received_messages_.front().size();
            received_messages_.erase(received_messages_.begin());
        }
        received_message_bytes_ += retained.size();
        received_messages_.push_back(std::move(retained));
    }
}

std::vector<std::string> VpnClient::drain_messages() {
    std::lock_guard<std::mutex> lock(message_mutex_);
    auto copy = received_messages_;
    received_messages_.clear();
    received_message_bytes_ = 0;
    return copy;
}
