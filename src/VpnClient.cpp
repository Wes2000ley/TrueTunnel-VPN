#define NOMINMAX

#include "VpnClient.h"
#include "utils.hpp"
#include "vpn.hpp"
#include "secure/SecureSocket.h"
#include <iostream>
#include <regex>
#include <thread>
#include <chrono>
#include <array>
#include <limits>
#include <string_view>
#include <exception>

#include "redirect_stream.hpp"

VpnClient::VpnClient(const std::string& server_ip,
                     int port,
                     const std::string& password,
                     const std::string& adaptername,
                     const std::string& real_adapter,
                     const std::string& public_ip,
                     secure::CipherSuite cipher,
                     TransportProtocol transport)
    : server_ip_(server_ip),
      port_(port),
      password_(password),
      adaptername_(adaptername),
      real_adapter_(real_adapter),
      public_ip_(public_ip),
      cipher_suite_(cipher),
      transport_(transport) {}

VpnClient::~VpnClient() {
    stop();
}

void VpnClient::start() {
    if (running_) {
        std::cout << "[!] VpnClient already running; start request ignored\n";
        return;
    }

    std::cout << "[INFO] Starting VPN client using " << to_string(transport_)
              << " and cipher " << secure::to_string(cipher_suite_) << "\n";

    running_ = true;

    try {
        connectToServer();
        performHandshake();
        requestConfig();
        LoadWintun();
        configureAdapter();
        std::cout << "[INFO] VPN client ready; forwarding packets\n";
    } catch (...) {
        running_ = false;
        stop();
        throw;
    }
}

void VpnClient::stop() {
    std::cout << "[INFO] Stopping VPN client\n";
    running_ = false;

    if (tls_) {
        tls_->close();
    }

    if (session_) {
        session_->reset();
    }

    if (tun_thread_.joinable()) {
        tun_thread_.join();
    }
    if (tls_thread_.joinable()) {
        tls_thread_.join();
    }

    tls_.reset();

    if (sock_ != INVALID_SOCKET) {
        if (transport_ == TransportProtocol::Tcp) {
            shutdown(sock_, SD_BOTH);
        }
        closesocket(sock_);
        sock_ = INVALID_SOCKET;
    }

    session_.reset();

    if (adapter_) {
        adapter_->Reset();
        adapter_.reset();
    }

    if (network_configured_) {
        const std::string cmd_delete_route  = "route delete 10.10.100.0 mask 255.255.255.0 10.10.100.1";
        const std::string cmd_delete_route2 = "route delete 10.10.100.0 mask 255.255.255.0 10.10.100.2";
        const std::string cmd_delete_route3 = "route delete 10.10.100.0 mask 255.255.255.0";
        const std::string cmd_reset_ip      = "netsh interface ipv4 set address name=\"" + adaptername_ + "\" dhcp";
        const std::string cmd_clear_mtu     = "netsh interface ipv4 set subinterface \"" + adaptername_ +
                                              "\" mtu=1500 store=persistent";
        run_command_hidden(cmd_delete_route);
        run_command_hidden(cmd_delete_route2);
        run_command_hidden(cmd_delete_route3);
        run_command_hidden(cmd_reset_ip);
        run_command_hidden(cmd_clear_mtu);

        network_configured_ = false;
    }
    run_command_hidden("netsh interface ipv4 delete route prefix=10.10.100.0/24 interface=\"" + adaptername_ + "\" store=active >nul 2>&1");
    run_command_hidden("netsh interface ipv4 delete route prefix=10.10.100.0/24 interface=\"" + adaptername_ + "\" store=persistent >nul 2>&1");

    if (nat_public_installed_) {
        run_command_hidden("netsh routing ip nat delete interface \"" + real_adapter_ + "\" >nul 2>&1");
        nat_public_installed_ = false;
    }
    if (nat_private_installed_) {
        run_command_hidden("netsh routing ip nat delete interface \"" + adaptername_ + "\" >nul 2>&1");
        nat_private_installed_ = false;
    }
    if (protected_route_installed_) {
        run_command_hidden("route delete " + public_ip_ + " >nul 2>&1");
        protected_route_installed_ = false;
        protected_route_gateway_.clear();
    }

    std::cout << "[✓] VPN client stopped\n";
}


void VpnClient::connectToServer() {
    int type = (transport_ == TransportProtocol::Tcp) ? SOCK_STREAM : SOCK_DGRAM;
    SOCKET raw_sock = socket(AF_INET, type, 0);
    CHECK(raw_sock != INVALID_SOCKET, "socket() failed");

    SocketGuard sock(raw_sock);

    int reuse = 1;
    setsockopt(sock.get(), SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    if (transport_ == TransportProtocol::Tcp) {
        int flag = 1;
        setsockopt(sock.get(), IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));
    }

    std::string bind_ip = get_ipv4_for_adapter(real_adapter_);
    CHECK(!bind_ip.empty(), "Could not find adapter IP");

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = 0;
    inet_pton(AF_INET, bind_ip.c_str(), &bind_addr.sin_addr);
    CHECK(bind(sock.get(), reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) != SOCKET_ERROR,
          "bind() failed");

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port_));
    inet_pton(AF_INET, public_ip_.c_str(), &addr.sin_addr);

    std::cout << "[*] Connecting (" << to_string(transport_) << ") to "
              << public_ip_ << ":" << port_ << "...\n";

    while (connect(sock.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "[!] Connection failed, retrying...\n";
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }

    if (transport_ == TransportProtocol::Tcp) {
        int flag = 1;
        setsockopt(sock.get(), IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));
    }

    sock_ = sock.release();
    std::cout << "[✓] Connected using " << to_string(transport_) << " transport\n";
}

void VpnClient::performHandshake() {
    if (transport_ == TransportProtocol::Tcp) {
        tls_ = std::make_unique<secure::SecureSocket>(sock_, password_, /*is_server=*/false, cipher_suite_);
    } else {
        auto send_fn = [s = sock_](const uint8_t* data, std::size_t len) -> bool {
            int sent = send(s, reinterpret_cast<const char*>(data), static_cast<int>(len), 0);
            return sent == static_cast<int>(len);
        };

        auto recv_fn = [s = sock_](std::vector<uint8_t>& out) -> bool {
            out.resize(65535);
            int got = recv(s, reinterpret_cast<char*>(out.data()), static_cast<int>(out.size()), 0);
            if (got <= 0) return false;
            out.resize(static_cast<std::size_t>(got));
            return true;
        };

        auto transport = std::make_unique<secure::DatagramTransport>(std::move(send_fn), std::move(recv_fn));
        tls_ = std::make_unique<secure::SecureSocket>(sock_,
                                                      std::move(transport),
                                                      password_,
                                                      /*is_server=*/false,
                                                      cipher_suite_,
                                                      secure::TransportType::Datagram,
                                                      /*owns_socket=*/true);
    }
    tls_->handshake();
    std::cout << "[🔒] SecureTransport established (ECDHE+PSK, "
              << secure::to_string(cipher_suite_) << ")\n";
}

void VpnClient::requestConfig() {
    const char* request = "VPN_REQUEST_CONFIG";
    tls_->send_record(PACKET_TYPE_MSG, (const uint8_t*)request, (uint16_t)std::strlen(request));
    uint8_t type=0; std::array<uint8_t,256> buf{};
    int n = tls_->recv_record(type, buf.data(), buf.size());
    CHECK(n > 0, "Failed to receive config");

    buf[n] = 0;
    std::string config((char*)buf.data());

    std::smatch match;
    std::regex re("IP=(.*?);GW=(.*?);MASK=(.*?)(;|$)");
    CHECK(std::regex_search(config, match, re), "Invalid config format");

    local_ip_ = match[1];
    gateway_ = match[2];
    subnetmask_ = match[3];

    std::cout << "[*] VPN Config:\n"
              << "    IP   = " << local_ip_ << "\n"
              << "    GW   = " << gateway_ << "\n"
              << "    MASK = " << subnetmask_ << "\n";
}

void VpnClient::configureAdapter() {
    adaptername_ = sanitize_shell_string(adaptername_);
    real_adapter_ = sanitize_shell_string(real_adapter_);
    gateway_ = sanitize_ip(gateway_);

    nat_public_installed_ = false;
    nat_private_installed_ = false;
    protected_route_installed_ = false;
    protected_route_gateway_.clear();

    GUID guid;
    CHECK(CoCreateGuid(&guid) == S_OK, "CoCreateGuid failed");

    std::wstring wname(adaptername_.begin(), adaptername_.end());
    std::cout << "[*] Creating Wintun adapter: " << adaptername_ << "\n";

    WINTUN_ADAPTER_HANDLE raw = WintunCreateAdapter(wname.c_str(), L"Wintun", &guid);
    CHECK(raw != nullptr, "WintunCreateAdapter failed");

    adapter_.emplace(raw);
    std::cout << "[✓] Wintun adapter created\n";

    SetStaticIPv4Address(adaptername_, local_ip_, subnetmask_);

    run_command_hidden("netsh interface ipv4 delete route prefix=10.10.100.0/24 interface=\"" + adaptername_ + "\" store=active >nul 2>&1");
    run_command_hidden("netsh interface ipv4 delete route prefix=10.10.100.0/24 interface=\"" + adaptername_ + "\" store=persistent >nul 2>&1");

     std::string cmd1 = "netsh interface ipv4 add route prefix=10.10.100.0/24 "
                        "interface=\"" + adaptername_ + "\" "
                        "nexthop=10.10.100.1 metric=1";

    std::string cmd2 = "netsh interface ipv4 set subinterface \"" + adaptername_ + "\" mtu=1380 store=persistent";

    CHECK(run_command_hidden(cmd1), "route add failed");
    CHECK(run_command_hidden(cmd2), "set mtu failed");
    network_configured_ = true;

    std::cout << "[✓] Adapter configured\n";


    WINTUN_SESSION_HANDLE session_handle = WintunStartSession(adapter_->get(), 0x400000);
    CHECK(session_handle != nullptr, "WintunStartSession failed");
    session_ = std::make_unique<WintunSessionGuard>(session_handle);

    // Ensure the server endpoint always routes via the physical uplink once the tunnel is active
    if (!public_ip_.empty()) {
        run_command_hidden("route delete " + public_ip_ + " >nul 2>&1");
        if (auto gw = get_gateway_for_adapter(real_adapter_); gw && !gw->empty() && *gw != public_ip_) {
            protected_route_gateway_ = *gw;
            const std::string protect_cmd =
                "route add " + public_ip_ + " mask 255.255.255.255 " + protected_route_gateway_ + " metric 1";
            if (run_command_hidden(protect_cmd)) {
                protected_route_installed_ = true;
                std::cout << "[*] Keeping server " << public_ip_ << " on uplink via "
                          << protected_route_gateway_ << "\n";
            } else {
                std::cerr << "[!] Failed to protect route for server " << public_ip_ << "\n";
            }
        } else {
            std::cerr << "[!] Unable to determine gateway for adapter '" << real_adapter_
                      << "'; server route not pinned\n"
                      << "      -> Ensure the adapter has a valid IPv4 gateway configured." << std::endl;
        }
    }

    // Refresh NAT bindings so the tunnel can reach the internet
    run_command_hidden("netsh routing ip nat delete interface \"" + real_adapter_ + "\" >nul 2>&1");
    run_command_hidden("netsh routing ip nat delete interface \"" + adaptername_ + "\" >nul 2>&1");

    const std::string nat_public_cmd =
        "netsh routing ip nat add interface \"" + real_adapter_ + "\" mode=full";
    if (run_command_hidden(nat_public_cmd)) {
        nat_public_installed_ = true;
        std::cout << "[INFO] Enabled NAT on uplink interface '" << real_adapter_ << "'\n";
    } else {
        std::cerr << "[!] Failed to enable NAT on uplink interface '" << real_adapter_ << "'\n"
                  << "      -> Install/enable the 'Routing and Remote Access' feature on Windows." << std::endl;
    }

    const std::string nat_private_cmd =
        "netsh routing ip nat add interface \"" + adaptername_ + "\" mode=private";
    if (run_command_hidden(nat_private_cmd)) {
        nat_private_installed_ = true;
        std::cout << "[INFO] Enabled NAT on tunnel interface '" << adaptername_ << "'\n";
    } else {
        std::cerr << "[!] Failed to enable NAT on tunnel interface '" << adaptername_ << "'\n"
                  << "      -> Install/enable the 'Routing and Remote Access' feature on Windows." << std::endl;
    }

    secure::SecureSocket* raw_tls = tls_.get();
    WINTUN_SESSION_HANDLE raw_session = session_->get();
    auto tun_worker = [this, raw_session, raw_tls]() {
        try {
            tun_to_tls(raw_session, raw_tls, std::ref(running_));
        } catch (const std::exception& ex) {
            std::cerr << "[!] tun_to_tls thread error: " << ex.what() << "\n";
            running_ = false;
        }
        std::cout << "[INFO] Stopped forwarding Wintun -> TLS\n";
    };
    tun_thread_ = std::thread(std::move(tun_worker));

    auto tls_worker = [this, raw_session, raw_tls]() {
        auto noop = [](BYTE*, UINT) { return false; };
        auto on_message = [this](std::string_view msg) {
            handle_incoming_message(msg);
        };
        tls_to_tun_common(raw_session,
                          raw_tls,
                          running_,
                          session_mutex_,
                          noop,
                          on_message);
        if (running_) {
            std::cerr << "[!] Secure channel closed by peer; stopping client\n";
        }
        running_ = false;
    };
    tls_thread_ = std::thread(std::move(tls_worker));

    run_command_admin(
    "Get-NetConnectionProfile | "
    "Where-Object {$_.InterfaceAlias -eq '" + adaptername_ + "'} | "
    "Set-NetConnectionProfile -NetworkCategory Private"
);

    AddICMPv4Rule();

}

bool VpnClient::send_chat_message(const std::string& text) {
    if (!tls_ || text.empty()) return false;
    if (text.size() > std::numeric_limits<uint16_t>::max()) return false;
    std::lock_guard<std::mutex> lock(tls_write_mutex_);
    int rc = tls_->send_record(PACKET_TYPE_MSG,
                               reinterpret_cast<const uint8_t*>(text.data()),
                               static_cast<uint16_t>(text.size()));
    return rc >= 0;
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

    {
        std::lock_guard<std::mutex> lock(message_mutex_);
        received_messages_.push_back(sender + "|" + body);
    }
}

std::vector<std::string> VpnClient::drain_messages() {
    std::lock_guard<std::mutex> lock(message_mutex_);
    auto copy = received_messages_;
    received_messages_.clear();
    return copy;
}
