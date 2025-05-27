#include "VpnClient.h"
#include "utils.hpp"
#include "vpn.hpp"
#include "HmacAuthenticator.h"
#include <iostream>
#include <regex>
#include <thread>
#include <chrono>

#include "redirect_stream.hpp"

VpnClient::VpnClient(const std::string& server_ip,
                     int port,
                     const std::string& password,
                     const std::string& adaptername,
                     const std::string& real_adapter,
                     const std::string& public_ip)
    : server_ip_(server_ip),
      port_(port),
      password_(password),
      adaptername_(adaptername),
      real_adapter_(real_adapter),
      public_ip_(public_ip) {}

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

    if (ssl_) {
        SSL_shutdown(ssl_.get());
        ssl_.reset();
    }

    if (sock_ != INVALID_SOCKET) {
        shutdown(sock_, SD_BOTH);
        closesocket(sock_);
        sock_ = INVALID_SOCKET;
    }

    // Delete route
    std::string cmd_delete_route = "route delete 10.10.100.0 mask 255.255.255.0 10.10.100.1";
    std::string cmd_delete_route2 = "route delete 10.10.100.0 mask 255.255.255.0 10.10.100.2";
     std::string cmd_delete_route3 =
+    "route delete 10.10.100.0 mask 255.255.255.0";


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
    SOCKET raw_sock = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(raw_sock != INVALID_SOCKET, "socket() failed");

    SocketGuard sock(raw_sock);

    int reuse = 1;
    setsockopt(sock.get(), SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    // ✅ 2.5 Disable Nagle's Algorithm to reduce latency on small packets
    int flag = 1;
    setsockopt(sock.get(), IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(flag));


    std::string bind_ip = get_ipv4_for_adapter(real_adapter_);
    CHECK(!bind_ip.empty(), "Could not find adapter IP");

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = 0;
    inet_pton(AF_INET, bind_ip.c_str(), &bind_addr.sin_addr);
    CHECK(bind(sock.get(), (sockaddr*)&bind_addr, sizeof(bind_addr)) != SOCKET_ERROR, "bind() failed");

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port_));
    inet_pton(AF_INET, public_ip_.c_str(), &addr.sin_addr);

    std::cout << "[*] Connecting to " << public_ip_ << ":" << port_ << "...\n";

    while (connect(sock.get(), (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "[!] Connection failed, retrying...\n";
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }

    sock_ = sock.release();
    std::cout << "[✓] Connected to server\n";
}

void VpnClient::performHandshake() {
    auto ctx = make_ssl_ctx(false);
    ssl_.reset(SSL_new(ctx.get()));
    CHECK(ssl_ != nullptr, "SSL_new failed");
    CHECK(SSL_set_fd(ssl_.get(), static_cast<int>(sock_)) == 1, "SSL_set_fd failed");
    CHECK(SSL_connect(ssl_.get()) > 0, "SSL_connect failed");

    HmacAuthenticator auth(ssl_.get(), password_, false);
    CHECK(auth.succeeded(), "HMAC authentication failed");

    std::cout << "[🔒] TLS: " << SSL_get_version(ssl_.get())
              << ", cipher: " << SSL_get_cipher(ssl_.get()) << "\n";
}

void VpnClient::requestConfig() {
    const char* request = "VPN_REQUEST_CONFIG";
    SSL_write(ssl_.get(), request, static_cast<int>(strlen(request)));

    char buf[256] = {};
    int n = SSL_read(ssl_.get(), buf, sizeof(buf) - 1);
    CHECK(n > 0, "Failed to receive config");

    buf[n] = 0;
    std::string config(buf);

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

    SSL *raw_ssl = ssl_.get();
    WINTUN_SESSION_HANDLE raw_session = session_->get();

    std::thread(tun_to_tls, raw_session, raw_ssl, std::ref(running_)).detach();
    std::thread(tls_to_tun_client, raw_session, raw_ssl, std::ref(running_), std::ref(session_mutex_)).detach();

    run_command_admin(
    "Get-NetConnectionProfile | "
    "Where-Object {$_.InterfaceAlias -eq '" + adaptername_ + "'} | "
    "Set-NetConnectionProfile -NetworkCategory Private"
);

    AddICMPv4Rule();

}
