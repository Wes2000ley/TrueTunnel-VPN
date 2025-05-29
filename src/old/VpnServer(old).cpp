#include "../VpnServer.h"

#include "../VpnController.h"
#include "../vpn.hpp"
#include "../utils.hpp"
#include "../redirect_stream.hpp"
#include "../raii.hpp"
#include "../Networking.h"
#include "../HmacAuthenticator.h"


#include <iostream>
#include <filesystem>
#include <ppltasks.h>
#include <stdexcept>
#include <thread>
#include <chrono>  //for using the function sleep
#include <iphlpapi.h>
#include <regex>


#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/provider.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>


#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "iphlpapi.lib")


VpnServer::VpnServer(int port,
                     const std::string& real_adapter,
                     const std::string& password,
                     const std::string& adaptername)
    : port_(port), real_adapter_(real_adapter), password_(password), adaptername_(adaptername) {
}

VpnServer::~VpnServer() {
    stop();

}

void VpnServer::start() {
    running_ = true;
    setupSocket();
    performHandshake();
    negotiateIp();
    LoadWintun();
    configureAdapter();
   // startPacketForwarding();
}

void VpnServer::stop() {
    std::cout << "[*] Stopping server\n";
    running_ = false;

    if (ssl_) {
        SSL_shutdown(ssl_.get());
        ssl_.reset();
    }
    if (client_sock_ != INVALID_SOCKET) {
        shutdown(client_sock_, SD_BOTH);
        closesocket(client_sock_);
        client_sock_ = INVALID_SOCKET;
    }
    if (listen_sock_ != INVALID_SOCKET) {
        shutdown(listen_sock_, SD_BOTH);
        closesocket(listen_sock_);
        listen_sock_ = INVALID_SOCKET;
    }
    // Delete route
    std::string cmd_delete_route = "route delete 10.10.100.0 mask 255.255.255.0 10.10.100.1";
    std::string cmd_delete_route2 = "route delete 10.10.100.0 mask 255.255.255.0 10.10.100.2";


    // Reset IP address (optional)
    std::string cmd_reset_ip = "netsh interface ipv4 set address name=\"" + adaptername_ + "\" dhcp";

    // Remove MTU override (optional but cleaner)
    std::string cmd_clear_mtu = "netsh interface ipv4 set subinterface \"" + adaptername_ +
                                "\" mtu=1500 store=persistent";

    run_command_hidden(cmd_delete_route);
    run_command_hidden(cmd_delete_route2);
    run_command_hidden(cmd_reset_ip);
    run_command_hidden(cmd_clear_mtu);


        std::cout << "[*] Removing NAT rules\n";
        std::string cmd_nat_pub = "netsh routing ip nat delete interface \"" + real_adapter_ + "\"";
        std::string cmd_nat_priv = "netsh routing ip nat delete interface \"" + adaptername_ + "\"";

        run_command_hidden(cmd_nat_pub);
        run_command_hidden(cmd_nat_priv);

        std::cout << "[*] Removing public IP route protection\n";

    std::cout << "[✓] Server shutdown complete\n";
}

void VpnServer::setupSocket() {
    SOCKET raw_sock = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(raw_sock != INVALID_SOCKET, "socket failed");

    SocketGuard sock(raw_sock);
    int reuse = 1;
    setsockopt(sock.get(), SOL_SOCKET, SO_REUSEADDR, (const char *) &reuse, sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port_));
    std::string bind_ip = get_ipv4_for_adapter(real_adapter_);
    CHECK(!bind_ip.empty(), "Adapter IP not found");

    inet_pton(AF_INET, bind_ip.c_str(), &addr.sin_addr);
    CHECK(bind(sock.get(), (sockaddr*)&addr, sizeof(addr)) != SOCKET_ERROR, "bind failed");
    CHECK(listen(sock.get(), 1) != SOCKET_ERROR, "listen failed");

    listen_sock_ = sock.get();
    std::cout << "[*] Waiting for client...\n";

    SOCKET client = accept(sock.get(), nullptr, nullptr);
    CHECK(client != INVALID_SOCKET, "accept failed");

    listen_sock_ = sock.release();  // Transfers ownership safely
    client_sock_ = client;
    std::cout << "[✓] Client connected\n";
}

void VpnServer::performHandshake() {
    util::logInfo("starting handshake");
    auto ctx = make_ssl_ctx(true);
    ssl_.reset(SSL_new(ctx.get()));
    CHECK(ssl_ != nullptr, "SSL_new failed");
    CHECK(SSL_set_fd(ssl_.get(), static_cast<int>(client_sock_)) == 1, "SSL_set_fd failed");
    CHECK(SSL_accept(ssl_.get()) > 0, "SSL_accept failed");

    HmacAuthenticator auth(ssl_.get(), password_, true);
    CHECK(auth.succeeded(), "HMAC authentication failed");

    std::cout << "[🔒] TLS: " << SSL_get_version(ssl_.get())
              << ", cipher: " << SSL_get_cipher(ssl_.get()) << "\n";
}

void VpnServer::negotiateIp() {
    char request_buf[64] = {};
    int bytes = SSL_read(ssl_.get(), request_buf, sizeof(request_buf) - 1);
    CHECK(bytes > 0, "Failed to read VPN config request");
    request_buf[bytes] = '\0';
    CHECK(strcmp(request_buf, "VPN_REQUEST_CONFIG") == 0, "Invalid config request");

    std::string client_id = std::to_string(reinterpret_cast<uintptr_t>(ssl_.get()));
    auto assigned_ip = ip_pool.assignTentative(client_id);
    CHECK(assigned_ip.has_value(), "No available IPs");

    std::string cfg = "VPN_CFG:IP=" + *assigned_ip + ";GW=10.10.100.1;MASK=255.255.255.0";
    SSL_write(ssl_.get(), cfg.c_str(), static_cast<int>(cfg.size()));

    std::cout << "[*] Assigned IP: " << *assigned_ip << "\n";
    local_ip_ = "10.10.100.1";
    subnetmask_ = "255.255.255.0";
    gateway_ = "10.10.100.1";
}

void VpnServer::configureAdapter() {
    adaptername_ = sanitize_shell_string(adaptername_);
    real_adapter_ = sanitize_shell_string(real_adapter_);
    gateway_ = sanitize_ip(gateway_);


    // Create adapter

    GUID guid;
    CHECK(CoCreateGuid(&guid) == S_OK, "CoCreateGuid failed");

    std::wstring wname(adaptername_.begin(), adaptername_.end());
    std::cout << "[*] Creating Wintun adapter: " << adaptername_ << "\n";

    WINTUN_ADAPTER_HANDLE raw = WintunCreateAdapter(wname.c_str(), L"Wintun", &guid);
    CHECK(raw != nullptr, "WintunCreateAdapter failed");

    WintunAdapterGuard adapter(raw);
    std::cout << "[✓] Wintun adapter created\n";



    // Configure adapter (silent netsh)
    {
        SetStaticIPv4Address(adaptername_, local_ip_, subnetmask_);


        std::string cmd1 = "netsh interface ipv4 add route prefix=10.10.100.0/24 "
                           "interface=\"" + adaptername_ + "\" nexthop=" + gateway_ +
                           " metric=1 store=persistent";

        std::string cmd2 = "netsh interface ipv4 set subinterface \"" + adaptername_ +
                           "\" mtu=1380 store=persistent";


        std::cout << "[CMD] " << cmd1 << "\n"
                << "[CMD] " << cmd2 << "\n";

        run_command_hidden(cmd1);
        run_command_hidden(cmd2);


        std::cout << "[✓] Adapter configuration complete\n";
    }



    WintunSessionGuard session(WintunStartSession(adapter.get(), 0x400000)); // 4MB ring
    CHECK(session.get(), "WintunStartSession failed");
    std::cout<<"Joining Threads";
    SSL *raw_ssl = ssl_.get();
    WINTUN_SESSION_HANDLE raw_session = session.get();
    std::thread t1(tun_to_tls, raw_session, raw_ssl, std::ref(running_));
    std::thread t2(tls_to_tun, raw_session, raw_ssl, std::ref(running_));
    t1.join();
    t2.join();
}
