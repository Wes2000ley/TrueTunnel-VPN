//  ──────────────────────────────────────────────────────────────────────────────
//  VpnServer.cpp  (TrueTunnel, multi-client, framed packets)
//  FULL SOURCE — no omissions
//  ──────────────────────────────────────────────────────────────────────────────

namespace std {
    class mutex;
}


// ——— System / library ——————————————————————————————————————————
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <string>
#include <memory>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <vector>
#include <atomic>
#include <chrono>
#include <iostream>

// ——— Project headers ——————————————————————————————————————————
#include "VpnServer.h"
#include "IpPoolManager.h"
#include "utils.hpp"
#include "vpn.hpp"
#include "HmacAuthenticator.h"
#include "Networking.h"


// ——— Pragmas ————————————————————————————————————————————————
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "iphlpapi.lib")

// ——— Packet framing constants ———————————————————————————————

// ───────────────────────────────────────────────────────────────────────────────
//  Helpers
// ───────────────────────────────────────────────────────────────────────────────
namespace {
struct ClientEntry {
    std::shared_ptr<SSL> ssl;
    std::mutex           write_mutex;
};
} // namespace

// ───────────────────────────────────────────────────────────────────────────────
//  ctor / dtor
// ───────────────────────────────────────────────────────────────────────────────
VpnServer::VpnServer(int                port,
                     const std::string& real_adapter,
                     const std::string& password,
                     const std::string& adaptername)
    : port_{port},
      real_adapter_{real_adapter},
      password_{password},
      adaptername_{adaptername},
      listen_sock_{INVALID_SOCKET},
      running_{false}
{
}

VpnServer::~VpnServer() { stop(); }

// ───────────────────────────────────────────────────────────────────────────────
//  public API
// ───────────────────────────────────────────────────────────────────────────────
void VpnServer::start()
{
    if (running_) return;
    running_ = true;

    LoadWintun();
    setupServer();
}

void VpnServer::stop()
{
    running_ = false;

    {   // tell every client thread to leave SSL_read()
        std::unique_lock lk(client_map_mutex_);
        for (auto& [_, e] : client_map_)
            SSL_shutdown(e.ssl.get());
    }

    if (listen_sock_ != INVALID_SOCKET) {
        shutdown(listen_sock_, SD_BOTH);
        closesocket(listen_sock_);
        listen_sock_ = INVALID_SOCKET;
    }

    if (tun_reader_thread_.joinable()) tun_reader_thread_.join();
    if (accept_thread_.joinable())     accept_thread_.join();

    cleanupNetwork();
    std::cout << "[✓] Server shutdown complete\n";
}

// ───────────────────────────────────────────────────────────────────────────────
//  private – setup / teardown
// ───────────────────────────────────────────────────────────────────────────────
void VpnServer::setupServer()
{
    local_ip_   = "10.10.100.1";
    subnetmask_ = "255.255.255.0";
    gateway_    = "10.10.100.1";

    adaptername_  = sanitize_shell_string(adaptername_);
    real_adapter_ = sanitize_shell_string(real_adapter_);

    createAdapter();
    createListener();

    auto sess = WintunStartSession(adapter_->get(), 0x400000);
    CHECK(sess != nullptr, "WintunStartSession failed");
    session_ = std::make_shared<WintunSessionGuard>(sess);

    // ——— Threads ——————————————————————————————————————————————
    tun_reader_thread_ = std::thread(&VpnServer::tunReaderEntry, this);
    accept_thread_     = std::thread(&VpnServer::acceptLoop,   this);

    run_command_admin(
        "Get-NetConnectionProfile | "
        "Where {$_.InterfaceAlias -eq '" + adaptername_ +
        "'} | Set-NetConnectionProfile -NetworkCategory Private");

    AddICMPv4Rule();

    // ─── NEW: turn Windows into a router ─────────────────────────
    try {
        set_global_ip_forwarding(true);
        set_interface_forwarding(adaptername_,  true);  // Wintun
        set_interface_forwarding(real_adapter_, true);  // public NIC
        std::cout << "[✓] IP forwarding enabled\n";
    }
    catch (const std::exception& ex) {
        std::cerr << "[!] Could not enable routing: " << ex.what()
                  << "\n    Run the server as Administrator.\n";
    }
}

void VpnServer::createAdapter()
{
    GUID g{};
    CHECK(CoCreateGuid(&g) == S_OK, "CoCreateGuid");

    std::wstring wname(adaptername_.begin(), adaptername_.end());
    WINTUN_ADAPTER_HANDLE raw = WintunCreateAdapter(wname.c_str(), L"Wintun", &g);
    CHECK(raw, "WintunCreateAdapter failed");
    adapter_.emplace(raw);

    SetStaticIPv4Address(adaptername_, local_ip_, subnetmask_);
    run_command_hidden("netsh interface ipv4 add route prefix=10.10.100.0/24 interface=\"" +
                   adaptername_ + "\" metric=1 store=persistent");
    run_command_hidden("netsh interface ipv4 set subinterface \"" + adaptername_ +
                       "\" mtu=1380 store=persistent");
}

void VpnServer::createListener()
{
SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
CHECK(s != INVALID_SOCKET, "socket");

int reuse = 1;
setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *) &reuse, sizeof(reuse));

int flag = 1;
setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(flag));

sockaddr_in a{};
a.sin_family = AF_INET;
a.sin_port = htons(static_cast<uint16_t>(port_));
std::string ip = get_ipv4_for_adapter(real_adapter_);
CHECK(!ip.empty(), "bind ip empty");

inet_pton(AF_INET, ip.c_str(), &a.sin_addr);
    CHECK(bind(s, (sockaddr*)&a, sizeof(a)) != SOCKET_ERROR, "bind");
    CHECK(listen(s, SOMAXCONN)              != SOCKET_ERROR, "listen");

    listen_sock_ = s;
    std::cout << "[*] Listening on " << ip << ':' << port_ << '\n';
}

void VpnServer::cleanupNetwork() {
    run_command_hidden("route delete 10.10.100.0 mask 255.255.255.0 10.10.100.1");
    run_command_hidden("route delete 10.10.100.0 mask 255.255.255.0 10.10.100.2");
    run_command_hidden("netsh interface ipv4 set address name=\"" + adaptername_ + "\" dhcp");
    run_command_hidden("netsh interface ipv4 set subinterface \"" + adaptername_ +
                       "\" mtu=1500 store=persistent");
    run_command_hidden("netsh routing ip nat delete interface \"" + real_adapter_ + '"');
    run_command_hidden("netsh routing ip nat delete interface \"" + adaptername_ + '"');

    // ─── NEW: disable forwarding we enabled at start ─────────────
    try {
        set_interface_forwarding(adaptername_, false);
        set_interface_forwarding(real_adapter_, false);
        set_global_ip_forwarding(false);
    } catch (...) {
        // best-effort; ignore if user disabled it manually
    }
}

// ───────────────────────────────────────────────────────────────────────────────
//  private – thread entry points
// ───────────────────────────────────────────────────────────────────────────────
void VpnServer::tunReaderEntry()
{
    while (running_) {
        UINT  size = 0;
        BYTE* pkt  = static_cast<BYTE*>(WintunReceivePacket(session_->get(), &size));
        if (!pkt) { std::this_thread::sleep_for(std::chrono::milliseconds(1)); continue; }
        if (size < 20) { WintunReleaseReceivePacket(session_->get(), pkt); continue; }

        std::string dst_ip = extract_ipv4_string(pkt + 16);

        std::shared_lock rlk(client_map_mutex_);
        auto it = client_map_.find(dst_ip);
        if (it != client_map_.end()) {
            std::lock_guard lg(it->second.write_mutex);

            /* --- build one contiguous buffer: 1-byte tag + payload --- */
            std::vector<uint8_t> frame(size + 1);
            frame[0] = PACKET_TYPE_IP;
            std::memcpy(frame.data() + 1, pkt, size);

            /* --- single TLS record --- */
            SSL_write(it->second.ssl.get(),
                      frame.data(),
                      static_cast<int>(frame.size()));
        }
        rlk.unlock();

        WintunReleaseReceivePacket(session_->get(), pkt);
    }
}



void VpnServer::acceptLoop()
{
    while (running_) {
        SOCKET c = accept(listen_sock_, nullptr, nullptr);
        if (c == INVALID_SOCKET) {
            if (running_)
                std::cerr << "[!] accept: " << WSAGetLastError() << '\n';
            continue;
        }
        std::thread(&VpnServer::handleClient, this, c).detach();
    }
}

// ───────────────────────────────────────────────────────────────────────────────
//  private – per-client handling
// ───────────────────────────────────────────────────────────────────────────────
void VpnServer::handleClient(SOCKET sock)
{
    try {
        auto ctx = make_ssl_ctx(true);
        SSL* raw = SSL_new(ctx.get());
        CHECK(raw, "SSL_new");
        CHECK(SSL_set_fd(raw, (int)sock) == 1, "SSL_set_fd");
        CHECK(SSL_accept(raw) > 0, "SSL_accept");

        HmacAuthenticator auth(raw, password_, true);
        CHECK(auth.succeeded(), "HMAC failed");

        char req[32]{};
        CHECK(SSL_read(raw, req, sizeof(req)-1) > 0, "cfg read");
        CHECK(std::strcmp(req, "VPN_REQUEST_CONFIG") == 0, "bad cfg tag");

        std::string cid = std::to_string(reinterpret_cast<uintptr_t>(raw));
        auto ip_opt     = ip_pool.assignTentative(cid);
        CHECK(ip_opt, "no free IPs");
        std::string ip = *ip_opt;

        std::string cfg = "VPN_CFG:IP=" + ip + ";GW=10.10.100.1;MASK=255.255.255.255";
        SSL_write(raw, cfg.c_str(), (int)cfg.size());

        auto ssl = std::shared_ptr<SSL>(raw, SSL_free);
        {
            std::unique_lock ul(client_map_mutex_);

            client_map_.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(ip),   // ← key
                std::forward_as_tuple(ssl)   // ← value
            );
        }

        auto alive = std::make_shared<std::atomic<bool>>(true);

        std::thread(&VpnServer::tlsClientEntry,
                    this, ssl, ip, alive)      // pass by value
              .detach();
    }
    catch (const std::exception& e) {
        std::cerr << "[!] client: " << e.what() << '\n';
        closesocket(sock);
    }
}

void VpnServer::tlsClientEntry(std::shared_ptr<SSL>               ssl,
                    const std::string&                 src_ip,
                    std::shared_ptr<std::atomic<bool>> alive)
{
    tls_to_tun(session_->get(), ssl.get(), *alive, session_mutex_);

    {   // remove client from map
        std::lock_guard lg(client_map_mutex_);
        client_map_.erase(src_ip);
    }
    ip_pool.release(src_ip);

}

// ───────────────────────────────────────────────────────────────────────────────
