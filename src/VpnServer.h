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
#include <array>
#include <cstdint>
#include <cstddef>

#include "secure/SecureSocket.h"
#include "secure/WolfSslDatagramSocket.h"
#include "security/FixedWindowRateLimiter.h"

#include <string>
#include <memory>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <atomic>
#include <chrono>
#include <optional>
#include <deque>
#include <condition_variable>
#include <string_view>
#include <utility>
#include <limits>
#include <span>

//
//  Project headers
//
#include "IpPoolManager.h"     // IpPoolManager (thread-safe /24 allocator)
#include "Networking.h"
#include "TransportProtocol.h"
#include "raii.hpp"

//
//  Pragmas
//
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "iphlpapi.lib")

// During a make-before-break handoff the old stream is deliberately drained.
// Keep a small bounded queue for authenticated server-to-client records so
// packets arriving during that short window are delivered after the commit (or
// after an authenticated abort) instead of being silently discarded.
struct VpnServerPendingRecord {
    std::uint8_t type{0U};
    std::vector<std::uint8_t> payload;
};

struct VpnServerPendingOutbound {
    std::mutex mutex;
    std::deque<VpnServerPendingRecord> records;
    std::size_t bytes{0U};
};

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
              TransportProtocol transport,
              secure::TrafficKeyRotationPolicy rotation_policy = {},
              std::uint64_t expected_real_adapter_luid = 0U);
    ~VpnServer();

    void start();   // idempotent
    void stop();    // blocks until fully shut down
    bool send_chat(const std::string& text);
    [[nodiscard]] bool is_active() const { return running_.load(); }
#ifdef TRUETUNNEL_INTEGRATION_TEST
    void set_integration_drop_heartbeat_acknowledgements(bool drop) noexcept;
    void set_integration_reject_authenticated_clients(
        std::uint32_t count) noexcept;
    // Injects a reversible failure before ACTIVATE is accepted; OLD must
    // resume through the authenticated ABORT path.
    void set_integration_fail_next_session_replacement_commit(
        bool fail) noexcept;
    // Injects an irreversible failure after ACTIVATE; both generations must
    // be closed and the exact client/IP map entry reclaimed.
    void set_integration_fail_next_session_replacement_after_activate(
        bool fail) noexcept;
    void set_integration_session_replacement_freeze_delay(
        std::chrono::milliseconds delay) noexcept;
    void integration_disconnect_all_clients() noexcept;
    [[nodiscard]] std::uint64_t integration_heartbeat_requests() const noexcept;
    [[nodiscard]] std::uint32_t
    integration_rejected_authenticated_clients() const noexcept;
    [[nodiscard]] std::size_t integration_connected_client_count() const;
#endif

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
    void heartbeatWatchdogEntry();


    // ───────── per-client handling ──────
    void handleClient(SOCKET client_sock,
                      std::shared_ptr<std::atomic<bool>> alive);
    [[nodiscard]] bool acceptTcpSessionReplacement(
        const std::shared_ptr<secure::SecureSocket>& tls,
        std::span<const std::uint8_t> payload,
        std::string& assigned_ip,
        std::string& client_id);
    struct UdpPeerState;
    struct UdpHandshakeReservation;
    void tlsClientEntry(std::shared_ptr<secure::SecureSocket> tls,
                        const std::string &src_ip,
                        const std::string &client_id,
                        std::shared_ptr<std::atomic<bool>> alive,
                        std::shared_ptr<UdpPeerState> udp_state = std::shared_ptr<UdpPeerState>{},
                        std::string peer_key = std::string{});
    void handleUdpClient(std::shared_ptr<UdpPeerState> state,
                         std::string peer_key,
                         std::shared_ptr<std::atomic<bool>> alive,
                         secure::PreparedWolfSslServerSession prepared,
                         std::shared_ptr<UdpHandshakeReservation> reservation);
    void handle_client_message(secure::SecureSocket* tls, std::string_view message);
    void note_authenticated_client_activity(
        secure::SecureSocket* tls,
        const std::string& assigned_ip);
    [[nodiscard]] bool handle_control_record(
        secure::SecureSocket* tls,
        const std::string& assigned_ip,
        std::uint8_t type,
        std::span<const std::uint8_t> payload);
    enum class BroadcastStatus {
        Delivered,
        NoRecipients,
        RateLimited,
        DeliveryFailed,
    };
    BroadcastStatus broadcast_payload(
        const std::string& payload,
        std::string_view budget_key,
        const std::string* skip_client_id = nullptr);
    BroadcastStatus broadcast_message(
        const std::string& from,
        const std::string& text,
        std::string_view budget_key,
        const std::string* skip_client_id = nullptr);

    // ───────── types / helpers ──────────
    using TLSPtr = std::unique_ptr<secure::SecureSocket>;
    bool forward_to_client_if_known(const BYTE *packet, UINT size);
    bool route_authenticated_packet(
        secure::SecureSocket* source_tls,
        const std::string& expected_source_ip,
        WINTUN_SESSION_HANDLE session,
        std::mutex& session_mutex,
        const BYTE* packet,
        UINT size);


    struct PeerHeartbeatState {
        std::mutex mutex;
        bool participating{false};
        bool closing{false};
        std::chrono::steady_clock::time_point last_request{};
        std::chrono::steady_clock::time_point deadline{};
        std::chrono::milliseconds timeout{0};
        // A bounded renewal may suppress OLD heartbeat acknowledgements while
        // its authenticated drain is in progress.  This is an upper bound,
        // never an indefinite watchdog exemption.
        std::chrono::steady_clock::time_point handoff_deadline{};
    };

    struct ClientEntry {
        std::shared_ptr<secure::SecureSocket> tls;
        // The write lock has to outlive the map entry when a sender snapshots
        // the connection. This lets stop() acquire client_map_mutex_, close the
        // socket, and wake blocked I/O without allowing concurrent TLS writes.
        std::shared_ptr<std::timed_mutex> write_mutex;
        // A generation-specific gate. Receive callbacks hold a shared lease
        // through forwarding or Wintun injection; replacement takes the
        // exclusive lease before retiring OLD, so no decrypted OLD record can
        // cross the commit boundary after a check-then-swap race.
        std::shared_ptr<std::shared_timed_mutex> ingress_gate;
        std::shared_ptr<PeerHeartbeatState> heartbeat;
        // OLD has authenticated FREEZE and reserved this generation's control
        // budget before NEW negotiation starts, but DRAIN has not arrived yet.
        // Keeping this separate from draining makes rollback and heartbeat
        // rules explicit.
        std::shared_ptr<std::atomic<bool>> replacement_preparing;
        std::shared_ptr<std::atomic<bool>> draining;
        // Serializes handoff-state publication with the replacement waiter.
        // The condition variable avoids polling while the old generation
        // publishes the authenticated drain request/barrier.
        std::shared_ptr<std::mutex> handoff_mutex;
        std::shared_ptr<std::condition_variable> handoff_cv;
        // Set only after the replacement handler has flushed the bounded
        // handoff queue and serialized the final authenticated old-generation
        // barrier under write_mutex. A replacement must not commit merely
        // because a drain flag was observed.
        std::shared_ptr<std::atomic<bool>> drain_barrier_sent;
        std::shared_ptr<std::atomic<std::int64_t>> drain_deadline_ticks;
        std::array<std::uint8_t, kSessionReplacementNonceSize> drain_nonce{};
        std::shared_ptr<VpnServerPendingOutbound> pending_outbound;
        std::string client_id;
        std::array<std::uint8_t, 32> continuity_binding{};
        explicit ClientEntry(std::shared_ptr<secure::SecureSocket> t,
                              std::string id,
                              std::array<std::uint8_t, 32> binding = {})
            : tls(std::move(t)),
              write_mutex(std::make_shared<std::timed_mutex>()),
              ingress_gate(std::make_shared<std::shared_timed_mutex>()),
              heartbeat(std::make_shared<PeerHeartbeatState>()),
              replacement_preparing(
                  std::make_shared<std::atomic<bool>>(false)),
              draining(std::make_shared<std::atomic<bool>>(false)),
              handoff_mutex(std::make_shared<std::mutex>()),
              handoff_cv(std::make_shared<std::condition_variable>()),
              drain_barrier_sent(std::make_shared<std::atomic<bool>>(false)),
              drain_deadline_ticks(std::make_shared<std::atomic<std::int64_t>>(0)),
              drain_nonce{},
              pending_outbound(std::make_shared<VpnServerPendingOutbound>()),
              client_id(std::move(id)),
              continuity_binding(std::move(binding)) {}
        ~ClientEntry() {
            ::SecureZeroMemory(continuity_binding.data(),
                               continuity_binding.size());
            ::SecureZeroMemory(drain_nonce.data(), drain_nonce.size());
        }
        ClientEntry(const ClientEntry&) = delete;
        ClientEntry& operator=(const ClientEntry&) = delete;
        ClientEntry(ClientEntry&& other) noexcept
            : tls(std::move(other.tls)),
              write_mutex(std::move(other.write_mutex)),
              ingress_gate(std::move(other.ingress_gate)),
              heartbeat(std::move(other.heartbeat)),
              replacement_preparing(
                  std::move(other.replacement_preparing)),
              draining(std::move(other.draining)),
              handoff_mutex(std::move(other.handoff_mutex)),
              handoff_cv(std::move(other.handoff_cv)),
              drain_barrier_sent(std::move(other.drain_barrier_sent)),
              drain_deadline_ticks(std::move(other.drain_deadline_ticks)),
              drain_nonce(std::move(other.drain_nonce)),
              pending_outbound(std::move(other.pending_outbound)),
              client_id(std::move(other.client_id)),
              continuity_binding(std::move(other.continuity_binding)) {
            ::SecureZeroMemory(other.continuity_binding.data(),
                               other.continuity_binding.size());
            ::SecureZeroMemory(other.drain_nonce.data(), other.drain_nonce.size());
        }
        ClientEntry& operator=(ClientEntry&& other) noexcept {
            if (this == &other) return *this;
            ::SecureZeroMemory(continuity_binding.data(),
                               continuity_binding.size());
            tls = std::move(other.tls);
            write_mutex = std::move(other.write_mutex);
            ingress_gate = std::move(other.ingress_gate);
            heartbeat = std::move(other.heartbeat);
            replacement_preparing =
                std::move(other.replacement_preparing);
            draining = std::move(other.draining);
            handoff_mutex = std::move(other.handoff_mutex);
            handoff_cv = std::move(other.handoff_cv);
            drain_barrier_sent = std::move(other.drain_barrier_sent);
            drain_deadline_ticks = std::move(other.drain_deadline_ticks);
            drain_nonce = std::move(other.drain_nonce);
            pending_outbound = std::move(other.pending_outbound);
            client_id = std::move(other.client_id);
            continuity_binding = std::move(other.continuity_binding);
            ::SecureZeroMemory(other.continuity_binding.data(),
                               other.continuity_binding.size());
            ::SecureZeroMemory(other.drain_nonce.data(), other.drain_nonce.size());
            return *this;
        }
    };

    struct UdpPeerState {
        sockaddr_storage addr{};
        int addr_len{0};
        std::mutex mutex;
        std::condition_variable cv;
        std::deque<std::vector<uint8_t>> queue;
        bool closed{false};
    };

    struct UdpHandshakeReservation final {
        VpnServer* owner{nullptr};
        std::string source;
        bool held{false};

        UdpHandshakeReservation(VpnServer* owner_value,
                                std::string source_value) noexcept
            : owner{owner_value}, source{std::move(source_value)}, held{true} {}
        ~UdpHandshakeReservation();

        UdpHandshakeReservation(const UdpHandshakeReservation&) = delete;
        UdpHandshakeReservation& operator=(
            const UdpHandshakeReservation&) = delete;
        void release() noexcept;
    };

    struct ThreadBundle {
        std::shared_ptr<std::atomic<bool>> alive;
        std::thread thread;

        ThreadBundle(std::shared_ptr<std::atomic<bool>> flag, std::thread&& worker)
            : alive(std::move(flag)), thread(std::move(worker)) {}

        ThreadBundle(ThreadBundle&&) noexcept = default;
        ThreadBundle& operator=(ThreadBundle&&) noexcept = default;
        ThreadBundle(const ThreadBundle&) = delete;
        ThreadBundle& operator=(const ThreadBundle&) = delete;
    };

    // ───────── configuration ─────────────
    int         port_;
    std::string real_adapter_;
    std::string password_;
    bool password_page_locked_{false};
    std::string adaptername_;
    secure::CipherSuite cipher_suite_{secure::CipherSuite::Aes256Gcm};
    TransportProtocol transport_{TransportProtocol::Tcp};
    secure::TrafficKeyRotationPolicy rotation_policy_{};
    std::uint64_t expected_real_adapter_luid_{0U};
    NET_LUID real_adapter_luid_{};
    bool real_adapter_luid_pinned_{false};

    mutable std::mutex lifecycle_mutex_;
    bool start_called_ = false;
    std::atomic<bool> stop_requested_{false};

    std::string local_ip_   = "10.10.100.1";
    std::string subnetmask_ = "255.255.255.0";
    std::string gateway_    = "10.10.100.1";

    // ───────── sockets / wintun / ssl ───
    std::atomic<SOCKET>                    listen_sock_{INVALID_SOCKET};
    std::unique_ptr<secure::WolfSslStatelessServer> udp_cookie_gate_;
    std::optional<FirewallRuleGuard>        firewall_rule_;
    std::optional<FirewallRuleGuard>        icmp_firewall_rule_;
    std::optional<WintunAdapterLease>       adapter_;
    std::unique_ptr<WintunSessionGuard>     session_;
    HANDLE                                  cancellation_event_ = nullptr;

    // ───────── global state ──────────────
    std::atomic<bool>                       running_{false};

    IpPoolManager                           ip_pool;

    std::unordered_map<std::string, ClientEntry> client_map_;
    mutable std::shared_mutex               client_map_mutex_;
    std::unordered_set<std::shared_ptr<secure::SecureSocket>> pending_tcp_clients_;
    std::mutex                              pending_tcp_clients_mutex_;

    mutable std::mutex                      session_mutex_;   // protects WintunSendPacket

    std::thread tun_reader_thread_;   // tun → tls dispatcher
    std::thread accept_thread_;       // TCP accept loop
    std::thread udp_dispatch_thread_;
    std::thread heartbeat_watchdog_thread_;
    std::mutex heartbeat_watchdog_mutex_;
    std::condition_variable heartbeat_watchdog_cv_;
    std::atomic<std::uint64_t> heartbeat_requests_{0U};
    security::FixedWindowRateLimiter heartbeat_limiter_{
        {3'072U, 64U * 1'024U},
        {12U, 256U},
        256U,
        std::chrono::seconds{1}};
#ifdef TRUETUNNEL_INTEGRATION_TEST
    std::atomic<bool> integration_drop_heartbeat_acknowledgements_{false};
    std::atomic<std::uint32_t> integration_reject_authenticated_clients_{0U};
    std::atomic<std::uint32_t> integration_rejected_authenticated_clients_{0U};
    std::atomic<bool> integration_fail_next_session_replacement_commit_{false};
    std::atomic<bool>
        integration_fail_next_session_replacement_after_activate_{false};
    std::atomic<std::int64_t>
        integration_session_replacement_freeze_delay_ms_{0};
#endif
    std::unordered_map<std::string, std::shared_ptr<UdpPeerState>> udp_peers_;
    std::mutex udp_peers_mutex_;
    std::mutex udp_admission_mutex_;
    std::chrono::steady_clock::time_point udp_rate_window_{};
    std::size_t udp_global_attempts_{0};
    std::unordered_map<std::string, std::size_t> udp_source_attempts_;
    std::size_t udp_pending_handshakes_{0};
    std::unordered_map<std::string, std::size_t> udp_pending_by_source_;
    std::mutex tcp_workers_mutex_;
    std::vector<ThreadBundle> tcp_workers_;
    static constexpr std::size_t kMaximumTcpWorkers = 256U;
    std::size_t tcp_admissions_ = 0;
    security::FixedWindowRateLimiter tcp_attempt_limiter_{
        {128U, (std::numeric_limits<std::size_t>::max)()},
        {16U, (std::numeric_limits<std::size_t>::max)()},
        1'024U,
        std::chrono::seconds{1}};
    security::FixedWindowRateLimiter chat_limiter_{
        {128U, 128U * 1'024U},
        {16U, 16U * 1'024U},
        kMaximumTcpWorkers,
        std::chrono::seconds{1}};
    security::FixedWindowRateLimiter chat_fanout_limiter_{
        {128U, 8U * 1'024U * 1'024U},
        {16U, 2U * 1'024U * 1'024U},
        kMaximumTcpWorkers + 1U,
        std::chrono::seconds{1}};
    std::mutex udp_workers_mutex_;
    std::vector<ThreadBundle> udp_workers_;
    bool nat_public_installed_ = false;
    bool nat_private_installed_ = false;
    std::string nat_public_alias_;
    std::string nat_private_alias_;

    void addWorker(std::vector<ThreadBundle>& workers,
                   std::mutex& mutex,
                   std::shared_ptr<std::atomic<bool>> alive,
                   std::thread&& worker);
    void pruneWorkers(std::vector<ThreadBundle>& workers, std::mutex& mutex);
    bool tryAcquireTcpAdmission();
    void releaseTcpAdmission();
    bool allowClientChat(const std::string& client_id, std::size_t bytes);
    void closeAndEraseUdpPeerIfOwned(
        const std::string& peer_key,
        const std::shared_ptr<UdpPeerState>& state) noexcept;
    bool allowUdpStatelessAttempt(const std::string& source);
    std::shared_ptr<UdpHandshakeReservation> tryReserveUdpHandshake(
        const std::string& source);
    void releaseUdpHandshake(const std::string& source) noexcept;
#ifdef TRUETUNNEL_INTEGRATION_TEST
    [[nodiscard]] bool consume_integration_authenticated_rejection() noexcept;
#endif
    static void tls_to_tun_server(VpnServer *self,
                                  WINTUN_SESSION_HANDLE session,
                                  secure::SecureSocket *ssl,
                                  const std::string& expected_src_ip,
                                  std::atomic<bool> &running,
                                  std::mutex &session_mutex)
    {
        IN_ADDR expected_source{};
        const bool expected_source_valid =
            ::InetPtonA(AF_INET, expected_src_ip.c_str(), &expected_source) == 1;
        auto fwd = [self, ssl, expected_src_ip, expected_source,
                    expected_source_valid, session,
                    &session_mutex](BYTE* pkt, UINT sz) {
            // The authenticated transport identifies the peer, but the inner
            // IPv4 header is caller-controlled.  Consume spoofed packets here
            // so they can neither reach another client nor the local tunnel.
            if (!expected_source_valid ||
                !ipv4_source_matches(pkt, sz, expected_source)) {
                return true;
            }
            return self->route_authenticated_packet(
                ssl, expected_src_ip, session, session_mutex, pkt, sz);
        };
        auto on_msg = [self, ssl](std::string_view text) {
            self->handle_client_message(ssl, text);
        };
        auto on_control = [self, ssl, assigned_ip = expected_src_ip](
                                  const std::uint8_t type,
                                  const std::span<const std::uint8_t> payload) {
            return self->handle_control_record(
                ssl, assigned_ip, type, payload);
        };
        tls_to_tun_common(
            session, ssl, running, session_mutex, fwd, on_msg, on_control);
    }

};
