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

#include "secure/SecureSocket.h"

#include <string>
#include <memory>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <vector>
#include <atomic>
#include <optional>
#include <deque>
#include <condition_variable>
#include <string_view>
#include <utility>

//
//  Project headers
//
#include "IpPoolManager.h"     // IpPoolManager (thread-safe /24 allocator)
#include "TransportProtocol.h"
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
              const std::string& adaptername,
              secure::CipherSuite cipher,
              TransportProtocol transport);
    ~VpnServer();

    void start();   // idempotent
    void stop();    // blocks until fully shut down
    bool send_chat(const std::string& text);

private:
    // ───────── setup / teardown ─────────
    void setupServer();
    void cleanupNetwork();
    void createAdapter();
    void createListener();
    void createTcpListener();
    void createUdpListener();

    // ───────── thread entry-points ───────
    void acceptLoop();                    // accepts TCP and spawns handleClient
    void tunReaderEntry();                // single reader: tun → tls (calls tun_to_tls)
    void udpDispatchLoop();


    // ───────── per-client handling ──────
    void handleClient(SOCKET client_sock);
    struct UdpPeerState;
    void tlsClientEntry(std::shared_ptr<secure::SecureSocket> tls,
                        const std::string &src_ip,
                        const std::string &client_id,
                        std::shared_ptr<std::atomic<bool>> alive,
                        std::shared_ptr<UdpPeerState> udp_state = std::shared_ptr<UdpPeerState>{},
                        std::string peer_key = std::string{});
    void handleUdpClient(std::shared_ptr<UdpPeerState> state,
                         std::string peer_key);
    void handle_client_message(secure::SecureSocket* tls, std::string_view message);
    std::optional<std::pair<std::string, std::string>> find_client_info_for_tls(secure::SecureSocket* tls) const;
    bool broadcast_payload(const std::string& payload, const std::string* skip_client_id = nullptr);
    bool broadcast_message(const std::string& from,
                           const std::string& text,
                           const std::string* skip_client_id = nullptr);

    // ───────── types / helpers ──────────
    using TLSPtr = std::unique_ptr<secure::SecureSocket>;
    bool forward_to_client_if_known(const BYTE *packet, UINT size);


    struct ClientEntry {
        std::shared_ptr<secure::SecureSocket> tls;
        std::mutex write_mutex;
        std::string client_id;
        explicit ClientEntry(std::shared_ptr<secure::SecureSocket> t,
                              std::string id)
            : tls(std::move(t)), client_id(std::move(id)) {}
        ClientEntry(ClientEntry&&) = default;
        ClientEntry& operator=(ClientEntry&&) = default;
    };

    struct UdpPeerState {
        sockaddr_storage addr{};
        int addr_len{0};
        std::mutex mutex;
        std::condition_variable cv;
        std::deque<std::vector<uint8_t>> queue;
        bool closed{false};
    };


    // ───────── configuration ─────────────
    int         port_;
    std::string real_adapter_;
    std::string password_;
    std::string adaptername_;
    secure::CipherSuite cipher_suite_{secure::CipherSuite::Aes256Gcm};
    TransportProtocol transport_{TransportProtocol::Tcp};

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
    std::thread udp_dispatch_thread_;
    std::unordered_map<std::string, std::shared_ptr<UdpPeerState>> udp_peers_;
    std::mutex udp_peers_mutex_;
    static void tls_to_tun_server(VpnServer *self,
                                  WINTUN_SESSION_HANDLE session,
                                  secure::SecureSocket *ssl,
                                  std::atomic<bool> &running,
                                  std::mutex &session_mutex)
    {
        auto fwd = [self](BYTE* pkt, UINT sz) {
            return self->forward_to_client_if_known(pkt, sz);
        };
        auto on_msg = [self, ssl](std::string_view text) {
            self->handle_client_message(ssl, text);
        };
        tls_to_tun_common(session, ssl, running, session_mutex, fwd, on_msg);
    }

};
