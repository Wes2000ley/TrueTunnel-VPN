#pragma once
// ──────────────────────────────────────────────────────────────────────────────
//  VpnServer.h
//  Header for the multiclient TrueTunnel VPN server
//  FULL SOURCE — no omissions
// ──────────────────────────────────────────────────────────────────────────────

//
//  External / system headers
//
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <openssl/ssl.h>

#include <string>
#include <memory>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <vector>
#include <atomic>

//
//  Project headers
//
#include "IpPoolManager.h"     // IpPoolManager (thread-safe /24 allocator)
#include "raii.hpp"

//
//  Pragmas
//
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "iphlpapi.lib")

// ──────────────────────────────────────────────────────────────────────────────
//  VpnServer
// ──────────────────────────────────────────────────────────────────────────────
class VpnServer
{
public:
    VpnServer(int                port,
              const std::string& real_adapter,
              const std::string& password,
              const std::string& adaptername);
    ~VpnServer();

    void start();   // idempotent
    void stop();    // blocks until fully shut down

private:
    // ───────── setup / teardown ─────────
    void setupServer();
    void cleanupNetwork();
    void createAdapter();
    void createListener();

    // ───────── thread entry-points ───────
    void acceptLoop();                    // accepts TCP and spawns handleClient
    void tunReaderEntry();                // single reader: tun → tls (calls tun_to_tls)

    // ───────── per-client handling ──────
    void handleClient(SOCKET client_sock);
    void tlsClientEntry(std::shared_ptr<SSL> ssl,
                        const std::string &src_ip,
                        std::shared_ptr<std::atomic<bool>> alive);

    // ───────── types / helpers ──────────
    using SSLPtr = std::unique_ptr<SSL, decltype(&::SSL_free)>;

    struct ClientEntry {
        std::shared_ptr<SSL> ssl;
        std::mutex           write_mutex;
        explicit ClientEntry(std::shared_ptr<SSL> s) : ssl(std::move(s)) {}
        ClientEntry(const ClientEntry&)            = delete;
        ClientEntry& operator=(const ClientEntry&) = delete;
        ClientEntry(ClientEntry&&)                 = default;
        ClientEntry& operator=(ClientEntry&&)      = default;
    };

    // ───────── configuration ─────────────
    int         port_;
    std::string real_adapter_;
    std::string password_;
    std::string adaptername_;

    std::string local_ip_   = "10.10.100.1";
    std::string subnetmask_ = "255.255.255.0";
    std::string gateway_    = "10.10.100.1";

    // ───────── sockets / wintun / ssl ───
    SOCKET                                  listen_sock_ = INVALID_SOCKET;
    std::optional<WintunAdapterGuard>       adapter_;
    std::shared_ptr<WintunSessionGuard>     session_;

    // ───────── global state ──────────────
    std::atomic<bool>                       running_{false};

    IpPoolManager                           ip_pool;

    std::unordered_map<std::string, ClientEntry> client_map_;
    mutable std::shared_mutex               client_map_mutex_;

    mutable std::mutex                      session_mutex_;   // protects WintunSendPacket

    std::thread tun_reader_thread_;   // tun → tls dispatcher
    std::thread accept_thread_;       // TCP accept loop
};
