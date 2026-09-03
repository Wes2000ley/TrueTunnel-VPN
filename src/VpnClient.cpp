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
#include <limits>
#include <string_view>
#include <exception>
#include <stdexcept>
#include <system_error>
#include <utility>

#include "redirect_stream.hpp"

namespace {
constexpr const char* kClientCancelled = "vpn_client_cancelled";
}

VpnClient::VpnClient(const std::string& server_ip,
                     int port,
                     const std::string& password,
                     const std::string& adaptername,
                     const std::string& real_adapter,
                      const std::string& public_ip,
                      secure::CipherSuite,
                      TransportProtocol transport,
                      secure::TrafficKeyRotationPolicy rotation_policy,
                      const std::uint64_t expected_real_adapter_luid)
    : server_ip_(server_ip),
      port_(port),
      password_(password),
      adaptername_(adaptername),
      real_adapter_(real_adapter),
      public_ip_(public_ip),
      cipher_suite_(secure::CipherSuite::Aes256Gcm),
      transport_(transport),
      rotation_policy_(rotation_policy),
      expected_real_adapter_luid_(expected_real_adapter_luid) {
    if (port_ <= 0 || port_ > 65'535) {
        throw std::invalid_argument("VPN client port is out of range");
    }
    secure::require_valid_shared_secret(password_);
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
        performHandshake();
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
    std::string bind_ip = get_ipv4_for_adapter(real_adapter_luid_);
    CHECK(!bind_ip.empty(), "Could not find adapter IP");

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = 0;
    CHECK(inet_pton(AF_INET, bind_ip.c_str(), &bind_addr.sin_addr) == 1,
          "Invalid local adapter IPv4 address");

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port_));
    IN_ADDR public_addr{};
    CHECK(inet_pton(AF_INET, public_ip_.c_str(), &public_addr) == 1,
          "Invalid server IPv4 address");
    char canonical_public_ip[INET_ADDRSTRLEN]{};
    CHECK(inet_ntop(AF_INET, &public_addr, canonical_public_ip,
                    sizeof(canonical_public_ip)) != nullptr,
          "Failed to canonicalize server IPv4 address");
    public_ip_ = canonical_public_ip;
    addr.sin_addr = public_addr;

    constexpr auto kAttemptTimeout = std::chrono::seconds{10};
    constexpr auto kPollInterval = std::chrono::milliseconds{200};
    constexpr auto kRetryDelay = std::chrono::seconds{1};

    while (running_) {
        const int type =
            (transport_ == TransportProtocol::Tcp) ? SOCK_STREAM : SOCK_DGRAM;
        const int protocol =
            (transport_ == TransportProtocol::Tcp) ? IPPROTO_TCP : IPPROTO_UDP;
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
                  << bind_ip << " to " << public_ip_ << ':' << port_ << "...\n";

        pending_socket_.store(sock.get(), std::memory_order_release);
        bool connected =
            connect(sock.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
        int connect_error = connected ? 0 : WSAGetLastError();

        if (!connected &&
            (connect_error == WSAEWOULDBLOCK || connect_error == WSAEINPROGRESS ||
             connect_error == WSAEALREADY)) {
            const auto deadline = std::chrono::steady_clock::now() + kAttemptTimeout;
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
                        sizeof(kDatagramSendTimeoutMilliseconds)) == SOCKET_ERROR) {
                    const int error = WSAGetLastError();
                    throw std::system_error(
                        error, std::system_category(),
                        "setsockopt(SO_SNDTIMEO UDP client)");
                }
            }
            sock_.store(sock.release(), std::memory_order_release);
            std::cout << "[✓] Connected using " << to_string(transport_)
                      << " transport\n";
            return;
        }

        std::cerr << "[!] connect() failed with Winsock error " << connect_error
                  << " (" << std::error_code(connect_error, std::system_category()).message()
                  << "); retrying\n";
        const auto retry_deadline = std::chrono::steady_clock::now() + kRetryDelay;
        while (running_ && std::chrono::steady_clock::now() < retry_deadline) {
            std::this_thread::sleep_for(kPollInterval);
        }
    }

    throw std::runtime_error(kClientCancelled);
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
    if (!password_.empty()) {
        ::SecureZeroMemory(password_.data(), password_.size());
        password_.clear();
        password_.shrink_to_fit();
    }
    tls_guard.unlock();
    tls->handshake();
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
    if (!public_ip_.empty()) {
        if (IsIpv4AddressAssignedLocally(public_ip_)) {
            std::cout << "[*] Server endpoint " << public_ip_
                      << " is local; preserving its Windows host route\n";
        } else if (auto gw = get_gateway_for_adapter(real_adapter_luid_);
                   gw && !gw->empty() && *gw != public_ip_) {
            protected_route_ = AddIpv4Route(
                real_adapter_luid_, public_ip_, 32U, *gw, 1U);
            std::cout << "[*] Keeping server " << public_ip_ << " on uplink via "
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
            handle_incoming_message(msg);
        };
            try {
                tls_to_tun_common(raw_session,
                                  tls.get(),
                                  running_,
                                  session_mutex_,
                                  maybe_forward,
                                  on_message);
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
    };
    tls_thread_ = std::thread(std::move(tls_worker));

    if (!SetNetworkCategoryPrivate(adapter_->luid())) {
        std::cerr << "[!] Windows did not expose the Wintun network profile in time; "
                     "its firewall category was not changed\n";
    }

    icmp_firewall_rule_.emplace(AddIcmpV4FirewallRule(adaptername_));

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
