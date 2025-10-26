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
#include <system_error>

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

    std::cout << "[INFO] Starting VPN server on port " << port_
              << " using " << to_string(transport_) << "\n";

    LoadWintun();
    setupServer();
}

void VpnServer::stop()
{
    std::cout << "[INFO] Stopping VPN server; notifying clients\n";
    running_ = false;

    {   // tell clients to leave recv()
        std::unique_lock<std::shared_mutex> lk(client_map_mutex_);
        for (auto& [_, e] : client_map_) e.tls->close();
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
        std::lock_guard<std::mutex> lock(udp_peers_mutex_);
        for (auto& [_, state] : udp_peers_) {
            if (!state) continue;
            std::lock_guard<std::mutex> slk(state->mutex);
            state->closed = true;
            state->cv.notify_all();
        }
    }

    if (listen_sock_ != INVALID_SOCKET) {
        if (transport_ == TransportProtocol::Tcp) {
            shutdown(listen_sock_, SD_BOTH);
        }
        closesocket(listen_sock_);
        listen_sock_ = INVALID_SOCKET;
    }

    if (session_) {
        session_->reset();
    }

    if (tun_reader_thread_.joinable()) tun_reader_thread_.join();

    if (transport_ == TransportProtocol::Tcp) {
        if (accept_thread_.joinable()) accept_thread_.join();
    } else {
        if (udp_dispatch_thread_.joinable()) udp_dispatch_thread_.join();
    }

    pruneWorkers(tcp_workers_, tcp_workers_mutex_);
    pruneWorkers(udp_workers_, udp_workers_mutex_);

    session_.reset();

    if (adapter_) {
        adapter_->Reset();
        adapter_.reset();
    }

    {
        std::unique_lock<std::shared_mutex> lk(client_map_mutex_);
        client_map_.clear();
    }
    udp_peers_.clear();

    cleanupNetwork();
    std::cout << "[✓] Server shutdown complete\n";
}

bool VpnServer::send_chat(const std::string& text)
{
    if (text.empty()) return false;
    return broadcast_message("server", text);
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
    session_ = std::make_unique<WintunSessionGuard>(sess);

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
    run_command_hidden("netsh interface ipv4 delete route prefix=10.10.100.0/24 interface=\"" +
                   adaptername_ + "\" store=active >nul 2>&1");
    run_command_hidden("netsh interface ipv4 delete route prefix=10.10.100.0/24 interface=\"" +
                   adaptername_ + "\" store=persistent >nul 2>&1");
    run_command_hidden("netsh interface ipv4 add route prefix=10.10.100.0/24 interface=\"" +
                   adaptername_ + "\" metric=1");
    run_command_hidden("netsh interface ipv4 set subinterface \"" + adaptername_ +
                       "\" mtu=1380 store=persistent");

    // Recreate NAT bindings for tunnel ⇄ uplink interfaces
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

void VpnServer::addWorker(std::vector<ThreadBundle>& workers,
                          std::mutex& mutex,
                          std::shared_ptr<std::atomic<bool>> alive,
                          std::thread&& worker)
{
    std::lock_guard<std::mutex> lock(mutex);
    workers.emplace_back(std::move(alive), std::move(worker));
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
    run_command_hidden("route delete 10.10.100.0 mask 255.255.255.0 10.10.100.1");
    run_command_hidden("route delete 10.10.100.0 mask 255.255.255.0 10.10.100.2");
    run_command_hidden("netsh interface ipv4 set address name=\"" + adaptername_ + "\" dhcp");
    run_command_hidden("netsh interface ipv4 set subinterface \"" + adaptername_ +
                       "\" mtu=1500 store=persistent");
    if (nat_public_installed_) {
        run_command_hidden("netsh routing ip nat delete interface \"" + real_adapter_ + "\" >nul 2>&1");
        nat_public_installed_ = false;
    }
    if (nat_private_installed_) {
        run_command_hidden("netsh routing ip nat delete interface \"" + adaptername_ + "\" >nul 2>&1");
        nat_private_installed_ = false;
    }
    run_command_hidden("netsh interface ipv4 delete route prefix=10.10.100.0/24 interface=\"" + adaptername_ + "\" store=active >nul 2>&1");
    run_command_hidden("netsh interface ipv4 delete route prefix=10.10.100.0/24 interface=\"" + adaptername_ + "\" store=persistent >nul 2>&1");


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
            if (size >= 20) {
                std::string dst_ip = extract_ipv4_string(pkt + 16);
                std::shared_lock<std::shared_mutex> rlk(client_map_mutex_);
                auto it = client_map_.find(dst_ip);
                if (it != client_map_.end()) {
                    std::lock_guard<std::mutex> lg(it->second.write_mutex);
                    it->second.tls->send_record(PACKET_TYPE_IP, pkt, static_cast<uint16_t>(size));
                }
                rlk.unlock();
            }
            WintunReleaseReceivePacket(session_handle, pkt);
        }
        if (!running_) break;
        const DWORD err = ::GetLastError();
        if (err == ERROR_NO_MORE_ITEMS) {
            if (ev) {
                DWORD wait_rc = ::WaitForSingleObject(ev, INFINITE);
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
        SOCKET c = accept(listen_sock_, nullptr, nullptr);
        if (c == INVALID_SOCKET) {
            if (!running_) break;
            std::cerr << "[!] accept: " << WSAGetLastError() << '\n';
            continue;
        }
        auto alive = std::make_shared<std::atomic<bool>>(true);
        try {
            std::thread worker(&VpnServer::handleClient, this, c, alive);
            addWorker(tcp_workers_, tcp_workers_mutex_, alive, std::move(worker));
        } catch (const std::system_error& ex) {
            std::cerr << "[!] failed to launch client worker: " << ex.what() << '\n';
            alive->store(false);
            closesocket(c);
        } catch (...) {
            std::cerr << "[!] failed to launch client worker\n";
            alive->store(false);
            closesocket(c);
        }
        pruneWorkers(tcp_workers_, tcp_workers_mutex_);
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
    // Dispatcher is latency sensitive
    ::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

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
            auto alive = std::make_shared<std::atomic<bool>>(true);
            try {
                std::thread worker(&VpnServer::handleUdpClient, this, state, key, alive);
                addWorker(udp_workers_, udp_workers_mutex_, alive, std::move(worker));
            } catch (const std::system_error& ex) {
                std::cerr << "[!] failed to launch UDP worker: " << ex.what() << '\n';
                alive->store(false);
                {
                    std::lock_guard<std::mutex> lock(udp_peers_mutex_);
                    udp_peers_.erase(key);
                }
                {
                    std::lock_guard<std::mutex> guard(state->mutex);
                    state->closed = true;
                    state->cv.notify_all();
                }
            } catch (...) {
                std::cerr << "[!] failed to launch UDP worker\n";
                alive->store(false);
                {
                    std::lock_guard<std::mutex> lock(udp_peers_mutex_);
                    udp_peers_.erase(key);
                }
                {
                    std::lock_guard<std::mutex> guard(state->mutex);
                    state->closed = true;
                    state->cv.notify_all();
                }
            }
            pruneWorkers(udp_workers_, udp_workers_mutex_);
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────────
//  private – per-client handling
// ───────────────────────────────────────────────────────────────────────────────
void VpnServer::handleClient(SOCKET sock,
                             std::shared_ptr<std::atomic<bool>> alive)
{
    if (!alive) {
        alive = std::make_shared<std::atomic<bool>>(true);
    }

    std::string cid;
    std::string remote_ip = "unknown";
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

        cid = std::to_string(reinterpret_cast<uintptr_t>(tls.get()));
        auto ip_opt     = ip_pool.assignTentative(cid);
        CHECK(ip_opt, "no free IPs");
        std::string ip = *ip_opt;

        std::string cfg = "VPN_CFG:IP=" + ip + ";GW=10.10.100.1;MASK=255.255.255.255";
        tls->send_record(PACKET_TYPE_MSG, (const uint8_t*)cfg.data(), (uint16_t)cfg.size());

        {
            std::unique_lock<std::shared_mutex> ul(client_map_mutex_);

            client_map_.emplace(std::piecewise_construct,
                                std::forward_as_tuple(ip),
                                std::forward_as_tuple(tls, cid));
        }

        ip_pool.confirm(cid);

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
        if (!cid.empty()) {
            ip_pool.release(cid);
        }
        closesocket(sock);
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
                                std::shared_ptr<std::atomic<bool>> alive)
{
    if (!state) return;
    if (!alive) {
        alive = std::make_shared<std::atomic<bool>>(true);
    }
    // Per-peer processing thread
    ::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_HIGHEST);


    std::string cid;

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

        cid = std::to_string(reinterpret_cast<uintptr_t>(tls.get()));
        auto ip_opt = ip_pool.assignTentative(cid);
        CHECK(ip_opt, "no free IPs");
        std::string ip = *ip_opt;

        std::string cfg = "VPN_CFG:IP=" + ip + ";GW=10.10.100.1;MASK=255.255.255.255";
        tls->send_record(PACKET_TYPE_MSG, reinterpret_cast<const uint8_t*>(cfg.data()), static_cast<uint16_t>(cfg.size()));

        cid = std::to_string(reinterpret_cast<uintptr_t>(tls.get()));
        ip_pool.confirm(cid);

        {
            std::unique_lock<std::shared_mutex> ul(client_map_mutex_);
            client_map_.emplace(std::piecewise_construct,
                                std::forward_as_tuple(ip),
                                std::forward_as_tuple(tls, cid));
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

bool VpnServer::broadcast_payload(const std::string& payload, const std::string* skip_client_id) {
    std::shared_lock<std::shared_mutex> rlk(client_map_mutex_);
    if (client_map_.empty()) return false;
    bool all_ok = true;
    for (auto& [ip, entry] : client_map_) {
        if (skip_client_id && entry.client_id == *skip_client_id) {
            continue;
        }
        std::lock_guard<std::mutex> lg(entry.write_mutex);
        int rc = entry.tls->send_record(PACKET_TYPE_MSG,
                                        reinterpret_cast<const uint8_t*>(payload.data()),
                                        static_cast<uint16_t>(payload.size()));
        if (rc < 0) {
            all_ok = false;
        }
    }
    return all_ok;
}

bool VpnServer::broadcast_message(const std::string& from,
                                  const std::string& text,
                                  const std::string* skip_client_id) {
    std::string payload = from + "|" + text;
    std::cout << "[📨] " << from << ": " << text << '\n';
    return broadcast_payload(payload, skip_client_id);
}

void VpnServer::handle_client_message(secure::SecureSocket* tls, std::string_view message) {
    auto info_opt = find_client_info_for_tls(tls);
    std::string sender = info_opt ? info_opt->first : std::string("peer");
    const std::string* skip_id = info_opt ? &info_opt->second : nullptr;
    std::string body(message.begin(), message.end());
    broadcast_message(sender, body, skip_id);
}

std::optional<std::pair<std::string, std::string>> VpnServer::find_client_info_for_tls(secure::SecureSocket* tls) const {
    std::shared_lock<std::shared_mutex> rlk(client_map_mutex_);
    for (const auto& [ip, entry] : client_map_) {
        if (entry.tls.get() == tls) {
            return std::make_pair(ip, entry.client_id);
        }
    }
    return std::nullopt;
}

void VpnServer::tlsClientEntry(std::shared_ptr<secure::SecureSocket> tls,
                               const std::string&                 src_ip,
                               const std::string&                 client_id,
                               std::shared_ptr<std::atomic<bool>> alive,
                               std::shared_ptr<UdpPeerState>      udp_state,
                               std::string                        peer_key)
{
    tls_to_tun_server(this, session_->get(), tls.get(), *alive, session_mutex_);

    std::string release_id = client_id;
    {
        std::lock_guard<std::shared_mutex> lg(client_map_mutex_);
        auto it = client_map_.find(src_ip);
        if (it != client_map_.end()) {
            release_id = it->second.client_id;
            client_map_.erase(it);
        }
    }
    ip_pool.release(release_id);

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

    if (alive) {
        alive->store(false);
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
