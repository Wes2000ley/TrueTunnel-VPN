//  ──────────────────────────────────────────────────────────────────────────────
//  VpnServer.cpp  (TrueTunnel, multi-client, framed packets)
//  FULL SOURCE — no omissions
//  ──────────────────────────────────────────────────────────────────────────────

#include <array>


// ——— System / library ——————————————————————————————————————————
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include "secure/SecureSocket.h"

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
#include <cstring>
#include <utility>

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

// ───────────────────────────────────────────────────────────────────────────────
//  ctor / dtor
// ───────────────────────────────────────────────────────────────────────────────
VpnServer::VpnServer(int                port,
                     const std::string& real_adapter,
                     const std::string& password,
                     const std::string& adaptername,
                     secure::CipherSuite cipher,
                     TransportProtocol transport)
    : port_{port},
      real_adapter_{real_adapter},
      password_{password},
      adaptername_{adaptername},
      cipher_suite_{cipher},
      transport_{transport},
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

    {   // tell clients to leave recv()
        std::unique_lock<std::shared_mutex> lk(client_map_mutex_);
        for (auto& [_, e] : client_map_) e.tls->close();
    }

    if (listen_sock_ != INVALID_SOCKET) {
        if (transport_ == TransportProtocol::Tcp) {
            shutdown(listen_sock_, SD_BOTH);
        }
        closesocket(listen_sock_);
        listen_sock_ = INVALID_SOCKET;
    }

    if (tun_reader_thread_.joinable()) tun_reader_thread_.join();

    if (transport_ == TransportProtocol::Tcp) {
        if (accept_thread_.joinable()) accept_thread_.join();
    } else {
        {
            std::lock_guard<std::mutex> lock(udp_peers_mutex_);
            for (auto& [_, state] : udp_peers_) {
                if (!state) continue;
                std::lock_guard<std::mutex> slk(state->mutex);
                state->closed = true;
                state->cv.notify_all();
            }
        }
        if (udp_dispatch_thread_.joinable()) udp_dispatch_thread_.join();
        udp_peers_.clear();
    }

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
    if (transport_ == TransportProtocol::Tcp) {
        accept_thread_ = std::thread(&VpnServer::acceptLoop, this);
    } else {
        udp_dispatch_thread_ = std::thread(&VpnServer::udpDispatchLoop, this);
    }

    run_command_admin(
        "Get-NetConnectionProfile | "
        "Where {$_.InterfaceAlias -eq '" + adaptername_ +
        "'} | Set-NetConnectionProfile -NetworkCategory Private");

    AddICMPv4Rule();


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
    std::cout << "[*] Listening (TCP) on " << ip << ':' << port_ << '\n';
}

void VpnServer::createUdpListener()
{
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(s != INVALID_SOCKET, "socket");

    int reuse = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse));

    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(static_cast<uint16_t>(port_));
    std::string ip = get_ipv4_for_adapter(real_adapter_);
    CHECK(!ip.empty(), "bind ip empty");
    inet_pton(AF_INET, ip.c_str(), &a.sin_addr);

    CHECK(bind(s, (sockaddr*)&a, sizeof(a)) != SOCKET_ERROR, "bind");

    listen_sock_ = s;
    std::cout << "[*] Listening (UDP) on " << ip << ':' << port_ << '\n';
}

void VpnServer::cleanupNetwork() {
    run_command_hidden("route delete 10.10.100.0 mask 255.255.255.0 10.10.100.1");
    run_command_hidden("route delete 10.10.100.0 mask 255.255.255.0 10.10.100.2");
    run_command_hidden("netsh interface ipv4 set address name=\"" + adaptername_ + "\" dhcp");
    run_command_hidden("netsh interface ipv4 set subinterface \"" + adaptername_ +
                       "\" mtu=1500 store=persistent");
    run_command_hidden("netsh routing ip nat delete interface \"" + real_adapter_ + "\"");
    run_command_hidden("netsh routing ip nat delete interface \"" + adaptername_ + "\"");


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

        std::shared_lock<std::shared_mutex> rlk(client_map_mutex_);
        auto it = client_map_.find(dst_ip);
        if (it != client_map_.end()) {
            std::lock_guard<std::mutex> lg(it->second.write_mutex);

            /* --- single TLS record --- */
            it->second.tls->send_record(PACKET_TYPE_IP, (const uint8_t*)pkt, (uint16_t)size);
        }
        rlk.unlock();

        WintunReleaseReceivePacket(session_->get(), pkt);
    }
}


void VpnServer::acceptLoop() {
    if (transport_ != TransportProtocol::Tcp) return;
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
} // namespace

void VpnServer::udpDispatchLoop() {
    constexpr std::size_t kMaxDatagram = 65535;
    std::vector<uint8_t> buffer(kMaxDatagram);

    while (running_) {
        sockaddr_storage addr{};
        int addr_len = sizeof(addr);
        int got = recvfrom(listen_sock_, reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0,
                           reinterpret_cast<sockaddr*>(&addr), &addr_len);
        if (got <= 0) {
            if (!running_) break;
            int err = WSAGetLastError();
            if (err == WSAEINTR) continue;
            if (err == WSAEMSGSIZE) {
                std::cerr << "[!] recvfrom truncated datagram\n";
                continue;
            }
            std::cerr << "[!] recvfrom error: " << err << '\n';
            continue;
        }

        std::vector<uint8_t> packet(static_cast<std::size_t>(got));
        std::memcpy(packet.data(), buffer.data(), static_cast<std::size_t>(got));

        auto key = peer_key_from_addr(addr, addr_len);
        if (key.empty()) {
            std::cerr << "[!] Unable to format peer address\n";
            continue;
        }

        std::shared_ptr<UdpPeerState> state;
        bool new_peer = false;
        {
            std::lock_guard<std::mutex> lock(udp_peers_mutex_);
            auto it = udp_peers_.find(key);
            if (it == udp_peers_.end()) {
                state = std::make_shared<UdpPeerState>();
                udp_peers_.emplace(key, state);
                new_peer = true;
            } else {
                state = it->second;
            }
            if (state) {
                state->addr = addr;
                state->addr_len = addr_len;
            }
        }

        if (!state) continue;

        {
            std::lock_guard<std::mutex> lock(state->mutex);
            state->queue.emplace_back(std::move(packet));
            state->cv.notify_one();
        }

        if (new_peer) {
            std::thread(&VpnServer::handleUdpClient, this, state, std::move(key)).detach();
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────────
//  private – per-client handling
// ───────────────────────────────────────────────────────────────────────────────
void VpnServer::handleClient(SOCKET sock)
{
    try {
        auto tls = std::make_shared<secure::SecureSocket>(sock,
                                                          password_,
                                                          /*is_server=*/true,
                                                          cipher_suite_);
        tls->handshake();
        std::cout << "[🔐] Client handshake completed (" << secure::to_string(cipher_suite_) << ")\n";

        int flag = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));  // ✅ actual client socket

        uint8_t typ=0; std::array<uint8_t,64> req{};
        int rn = tls->recv_record(typ, req.data(), req.size());
        CHECK(rn > 0, "cfg read");
        req[rn]=0;
        CHECK(std::strcmp((char*)req.data(), "VPN_REQUEST_CONFIG") == 0, "bad cfg tag");

        std::string cid = std::to_string(reinterpret_cast<uintptr_t>(tls.get()));
        auto ip_opt     = ip_pool.assignTentative(cid);
        CHECK(ip_opt, "no free IPs");
        std::string ip = *ip_opt;

        std::string cfg = "VPN_CFG:IP=" + ip + ";GW=10.10.100.1;MASK=255.255.255.255";
        tls->send_record(PACKET_TYPE_MSG, (const uint8_t*)cfg.data(), (uint16_t)cfg.size());

        {
            std::unique_lock<std::shared_mutex> ul(client_map_mutex_);

            client_map_.emplace(std::piecewise_construct,
                                std::forward_as_tuple(ip),
                                std::forward_as_tuple(tls));
        }

        auto alive = std::make_shared<std::atomic<bool>>(true);

        // Launch client handler. Default arguments on member functions are not applied
        // when invoking through a pointer-to-member, so wrap in a lambda and pass them.
        std::thread([this, tls, ip, alive]() {
            this->tlsClientEntry(tls,
                                 ip,
                                 alive,
                                 std::shared_ptr<UdpPeerState>{},
                                 std::string{});
        }).detach();
    }
    catch (const std::exception& e) {
        std::cerr << "[!] client: " << e.what() << '\n';
        closesocket(sock);
    }
}

void VpnServer::handleUdpClient(std::shared_ptr<UdpPeerState> state,
                                std::string peer_key)
{
    if (!state) return;

    std::string allocated_ip;

    auto cleanup_peer = [this, state, peer = peer_key]() {
        {
            std::lock_guard<std::mutex> state_lock(state->mutex);
            state->closed = true;
            state->cv.notify_all();
        }
        std::lock_guard<std::mutex> map_lock(udp_peers_mutex_);
        udp_peers_.erase(peer);
    };

    try {
        sockaddr_storage addr_copy{};
        int addr_len = 0;
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            addr_copy = state->addr;
            addr_len = state->addr_len;
        }

        SOCKET sock_handle = listen_sock_;
        auto send_fn = [sock_handle, addr_copy, addr_len](const uint8_t* data, std::size_t len) -> bool {
            int sent = sendto(sock_handle,
                              reinterpret_cast<const char*>(data),
                              static_cast<int>(len),
                              0,
                              reinterpret_cast<const sockaddr*>(&addr_copy),
                              addr_len);
            return sent == static_cast<int>(len);
        };

        auto recv_fn = [state, this](std::vector<uint8_t>& out) -> bool {
            std::unique_lock<std::mutex> lock(state->mutex);
            state->cv.wait(lock, [&]() {
                return !state->queue.empty() || state->closed || !this->running_;
            });
            if (state->queue.empty()) {
                return false;
            }
            out = std::move(state->queue.front());
            state->queue.pop_front();
            return true;
        };

        auto transport = std::make_unique<secure::DatagramTransport>(std::move(send_fn), std::move(recv_fn));
        auto tls = std::make_shared<secure::SecureSocket>(listen_sock_,
                                                          std::move(transport),
                                                          password_,
                                                          /*is_server=*/true,
                                                          cipher_suite_,
                                                          secure::TransportType::Datagram,
                                                          /*owns_socket=*/false);
        tls->handshake();
        std::cout << "[🔐] UDP client handshake completed (" << secure::to_string(cipher_suite_) << ")\n";

        uint8_t typ = 0; std::array<uint8_t,64> req{};
        int rn = tls->recv_record(typ, req.data(), req.size());
        CHECK(rn > 0, "cfg read");
        req[rn] = 0;
        CHECK(std::strcmp(reinterpret_cast<char*>(req.data()), "VPN_REQUEST_CONFIG") == 0, "bad cfg tag");

        std::string cid = std::to_string(reinterpret_cast<uintptr_t>(tls.get()));
        auto ip_opt = ip_pool.assignTentative(cid);
        CHECK(ip_opt, "no free IPs");
        std::string ip = *ip_opt;

        allocated_ip = ip;

        std::string cfg = "VPN_CFG:IP=" + ip + ";GW=10.10.100.1;MASK=255.255.255.255";
        tls->send_record(PACKET_TYPE_MSG, reinterpret_cast<const uint8_t*>(cfg.data()), static_cast<uint16_t>(cfg.size()));

        {
            std::unique_lock<std::shared_mutex> ul(client_map_mutex_);
            client_map_.emplace(std::piecewise_construct,
                                std::forward_as_tuple(ip),
                                std::forward_as_tuple(tls));
        }

        auto alive = std::make_shared<std::atomic<bool>>(true);

        std::thread(&VpnServer::tlsClientEntry,
                    this,
                    tls,
                    ip,
                    alive,
                    state,
                    std::move(peer_key)).detach();
    }
    catch (const std::exception& e) {
        std::cerr << "[!] udp-client: " << e.what() << '\n';
        cleanup_peer();
        if (!allocated_ip.empty()) {
            ip_pool.release(allocated_ip);
        }
    }
}

void VpnServer::tlsClientEntry(std::shared_ptr<secure::SecureSocket> tls,
                               const std::string&                 src_ip,
                               std::shared_ptr<std::atomic<bool>> alive,
                               std::shared_ptr<UdpPeerState>      udp_state,
                               std::string                        peer_key)
{
    tls_to_tun_server(this, session_->get(), tls.get(), *alive, session_mutex_);

    {   // remove client from map
        std::lock_guard<std::shared_mutex> lg(client_map_mutex_);
        client_map_.erase(src_ip);
    }
    ip_pool.release(src_ip);

    if (udp_state) {
        {
            std::lock_guard<std::mutex> lock(udp_state->mutex);
            udp_state->closed = true;
            udp_state->cv.notify_all();
        }
        if (!peer_key.empty()) {
            std::lock_guard<std::mutex> lock(udp_peers_mutex_);
            udp_peers_.erase(peer_key);
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────────
bool VpnServer::forward_to_client_if_known(const BYTE* packet, UINT size)
{
    std::string dst = extract_ipv4_string(packet + 16);

    std::shared_lock<std::shared_mutex> rlk(client_map_mutex_);
    auto it = client_map_.find(dst);
    if (it == client_map_.end())
        return false;                       // not a VPN peer

    std::lock_guard<std::mutex> lg(it->second.write_mutex);
    it->second.tls->send_record(PACKET_TYPE_IP, (const uint8_t*)packet, (uint16_t)size);
    return true;
}
