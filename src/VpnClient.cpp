#include "VpnClient.h"
#include "utils.hpp"
#include "vpn.hpp"
#include "secure/SecureSocket.h"
#include <iostream>
#include <regex>
#include <thread>
#include <chrono>
#include <array>

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
    running_ = true;
    connectToServer();
    performHandshake();
    requestConfig();
    LoadWintun();
    configureAdapter();
   // startPacketForwarding();
  //  startInputLoop();
}

void VpnClient::stop() {
    running_ = false;

    if (tls_) { tls_->close(); tls_.reset(); }

    if (sock_ != INVALID_SOCKET) {
        if (transport_ == TransportProtocol::Tcp) {
            shutdown(sock_, SD_BOTH);
        }
        closesocket(sock_);
        sock_ = INVALID_SOCKET;
    }

    // Delete route
    std::string cmd_delete_route = "route delete 10.10.100.0 mask 255.255.255.0 10.10.100.1";
    std::string cmd_delete_route2 = "route delete 10.10.100.0 mask 255.255.255.0 10.10.100.2";
    std::string cmd_delete_route3 = "route delete 10.10.100.0 mask 255.255.255.0";


    // Reset IP address (optional)
    std::string cmd_reset_ip = "netsh interface ipv4 set address name=\"" + adaptername_ + "\" dhcp";

    // Remove MTU override (optional but cleaner)
    std::string cmd_clear_mtu = "netsh interface ipv4 set subinterface \"" + adaptername_ +
                                "\" mtu=1500 store=persistent";

    run_command_hidden(cmd_delete_route);
    run_command_hidden(cmd_delete_route2);
    run_command_hidden(cmd_delete_route3);
    run_command_hidden(cmd_reset_ip);
    run_command_hidden(cmd_clear_mtu);


        std::cout << "[*] Removing NAT rules\n";
        std::string cmd_nat_pub = "netsh routing ip nat delete interface \"" + real_adapter_ + "\"";
        std::string cmd_nat_priv = "netsh routing ip nat delete interface \"" + adaptername_ + "\"";

        run_command_hidden(cmd_nat_pub);
        run_command_hidden(cmd_nat_priv);
        std::cout << "[*] Removing public IP route protection\n";
        std::string cmd_remove_protect = "route delete " + public_ip_ + " >nul 2>&1";
        run_command_hidden(cmd_remove_protect);
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

    GUID guid;
    CHECK(CoCreateGuid(&guid) == S_OK, "CoCreateGuid failed");

    std::wstring wname(adaptername_.begin(), adaptername_.end());
    std::cout << "[*] Creating Wintun adapter: " << adaptername_ << "\n";

    WINTUN_ADAPTER_HANDLE raw = WintunCreateAdapter(wname.c_str(), L"Wintun", &guid);
    CHECK(raw != nullptr, "WintunCreateAdapter failed");

    adapter_ = WintunAdapterGuard(raw);
    std::cout << "[✓] Wintun adapter created\n";

    SetStaticIPv4Address(adaptername_, local_ip_, subnetmask_);

     std::string cmd1 = "netsh interface ipv4 add route prefix=10.10.100.0/24 "
                        "interface=\"" + adaptername_ + "\" "
                        "nexthop=10.10.100.1 metric=1 store=persistent";

    std::string cmd2 = "netsh interface ipv4 set subinterface \"" + adaptername_ + "\" mtu=1380 store=persistent";

    run_command_hidden(cmd1);
    run_command_hidden(cmd2);

    std::cout << "[✓] Adapter configured\n";


    session_ = std::make_shared<WintunSessionGuard>(
        WintunStartSession(adapter_->get(), 0x400000)
    );
    CHECK(session_->get(), "WintunStartSession failed");
    std::cout << "Joining Threads\n";

    secure::SecureSocket* raw_tls = tls_.get();
    WINTUN_SESSION_HANDLE raw_session = session_->get();
    std::thread(tun_to_tls, raw_session, raw_tls, std::ref(running_)).detach();
    std::thread(tls_to_tun_client, raw_session, raw_tls, std::ref(running_), std::ref(session_mutex_)).detach();

    run_command_admin(
    "Get-NetConnectionProfile | "
    "Where-Object {$_.InterfaceAlias -eq '" + adaptername_ + "'} | "
    "Set-NetConnectionProfile -NetworkCategory Private"
);

    AddICMPv4Rule();

}
