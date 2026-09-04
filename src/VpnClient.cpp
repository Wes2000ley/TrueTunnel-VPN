#define NOMINMAX

#include "VpnClient.h"
#include "utils.hpp"
#include "vpn.hpp"
#include "secure/SecureSocket.h"
#include "secure/SharedSecret.h"
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
}

VpnClient::~VpnClient() {
    stop();
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
        if (!password_.empty()) {
            ::SecureZeroMemory(password_.data(), password_.size());
            password_.clear();
            password_.shrink_to_fit();
        }
    }

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
    if (!password_.empty()) {
        ::SecureZeroMemory(password_.data(), password_.size());
        password_.clear();
        password_.shrink_to_fit();
    }
    tls_guard.unlock();
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

    const auto tls = tls_snapshot();
    CHECK(tls != nullptr, "Secure transport is unavailable");
    WINTUN_SESSION_HANDLE raw_session = session_->get();
    auto tun_worker = [this, raw_session, tls]() {
        try {
            tun_to_tls(raw_session, tls.get(), std::ref(running_), cancellation_event_);
        } catch (const std::exception& ex) {
            std::cerr << "[!] tun_to_tls thread error: " << ex.what() << "\n";
            running_ = false;
        }
        std::cout << "[INFO] Stopped forwarding Wintun -> TLS\n";
    };
    tun_thread_ = std::thread(std::move(tun_worker));

    auto tls_worker = [this, raw_session, tls]() {
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
            try {
                tls_to_tun_common(raw_session,
                                  tls.get(),
                                  running_,
                                  session_mutex_,
                                  maybe_forward,
                                  on_message,
                                  on_control);
            } catch (const std::exception& ex) {
                if (running_) {
                    std::cerr << "[!] TLS receive thread error: " << ex.what() << "\n";
                }
                running_ = false;
            } catch (...) {
                running_ = false;
            }
        if (running_) {
            std::cerr << "[!] Secure channel closed by peer; stopping client\n";
        }
        running_ = false;
        heartbeat_wait_cv_.notify_all();
    };
    last_authenticated_receive_ticks_.store(
        steady_clock_ticks(), std::memory_order_release);
    tls_thread_ = std::thread(std::move(tls_worker));
    if (recovery_.enabled) {
        heartbeat_thread_ = std::thread(
            &VpnClient::heartbeatLoop, this, tls);
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

}

void VpnClient::note_authenticated_receive() noexcept {
    last_authenticated_receive_ticks_.store(
        steady_clock_ticks(), std::memory_order_release);
    heartbeat_wait_cv_.notify_all();
}

bool VpnClient::handle_control_record(
    const std::uint8_t type,
    const std::span<const std::uint8_t> payload) {
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
}

void VpnClient::heartbeatLoop(std::shared_ptr<secure::SecureSocket> tls) {
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
            std::lock_guard<std::mutex> write_guard(tls_write_mutex_);
            if (!running_.load(std::memory_order_acquire)) return;
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
        if (elapsed >= timeout) {
            // This watchdog is deliberately separate from the heartbeat sender.
            // A congested application write can therefore never postpone the
            // configured liveness deadline; SecureSocket::close() interrupts the
            // blocked TLS/DTLS write before waiting for its I/O locks.
            terminate_unresponsive_channel(
                "Authenticated heartbeat timed out; closing stale secure session");
            return;
        }

        std::unique_lock<std::mutex> wait_lock(heartbeat_wait_mutex_);
        heartbeat_wait_cv_.wait_for(
            wait_lock, timeout - elapsed,
            [this, observed_receive]() {
                return !running_.load(std::memory_order_acquire) ||
                       last_authenticated_receive_ticks_.load(
                           std::memory_order_acquire) != observed_receive;
            });
    }
}

bool VpnClient::send_chat_message(const std::string& text) {
    if (!running_) {
        std::cerr << "[!] Cannot send message: client inactive\n";
        return false;
    }
    const auto tls = tls_snapshot();
    if (!tls || text.empty()) return false;
    if (text.size() > kMaximumChatMessageSize) {
        std::cerr << "[!] Chat message exceeds the selected transport limit\n";
        return false;
    }
    std::lock_guard<std::mutex> lock(tls_write_mutex_);
    try {
        int rc = tls->send_record(PACKET_TYPE_MSG,
                                  reinterpret_cast<const uint8_t*>(text.data()),
                                  static_cast<uint16_t>(text.size()));
        if (rc < 0) {
            std::cerr << "[!] Failed to send chat message\n";
            running_ = false;
            return false;
        }
    } catch (const std::exception& ex) {
        std::cerr << "[!] Exception sending chat message: " << ex.what() << "\n";
        running_ = false;
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
    const auto tls = tls_snapshot();
    if (!running_ || !tls ||
        !is_well_formed_ipv4_packet(packet.data(), packet.size()) ||
        packet.size() > (std::numeric_limits<std::uint16_t>::max)()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(tls_write_mutex_);
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

secure::TrafficKeyRotationStats VpnClient::integration_rotation_stats() {
    const auto tls = tls_snapshot();
    return tls ? tls->rotation_stats() : secure::TrafficKeyRotationStats{};
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
