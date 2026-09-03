#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>

#include "CipherSuite.h"
#include "TrafficKeyRotation.h"
#include "Transport.h"

#include <cstddef>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>

namespace secure {

namespace detail {

// wolfSSL's TLS 1.3 PSK server callback supplies a NUL-terminated identity.
// Keep exact matching in a separately testable helper so short identities are
// never probed at an offset beyond their allocation.
[[nodiscard]] bool dtls_psk_identity_matches(const char* identity) noexcept;

} // namespace detail

// A ClientHello that has passed wolfSSL's peer-address-bound HelloRetryRequest
// cookie check and the stateful TLS 1.3 PSK-binder verification performed by
// wolfDTLS_accept_stateless. The object retains the already-parsed wolfSSL
// handshake state so the worker can continue without replaying the admitted
// datagram.
class PreparedWolfSslServerSession final {
public:
    PreparedWolfSslServerSession() noexcept;
    ~PreparedWolfSslServerSession();

    PreparedWolfSslServerSession(PreparedWolfSslServerSession&&) noexcept;
    PreparedWolfSslServerSession& operator=(
        PreparedWolfSslServerSession&&) noexcept;

    PreparedWolfSslServerSession(const PreparedWolfSslServerSession&) = delete;
    PreparedWolfSslServerSession& operator=(
        const PreparedWolfSslServerSession&) = delete;

    [[nodiscard]] explicit operator bool() const noexcept;

private:
    class Impl;
    explicit PreparedWolfSslServerSession(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;

    friend class WolfSslDatagramSocket;
    friend class WolfSslStatelessServer;
};

struct WolfSslStatelessServerStats final {
    std::uint64_t datagrams_processed{0};
    std::uint64_t cookie_challenges{0};
    std::uint64_t sessions_admitted{0};
    std::uint64_t authentication_failures{0};
    std::uint64_t malformed_datagrams{0};
    std::uint64_t cookie_secret_rotations{0};
};

// Single-threaded DTLS admission gate for a shared UDP listener. Unknown
// tuples are processed here before the application allocates a peer queue or
// worker thread. wolfSSL binds the cookie to the supplied sockaddr bytes.
class WolfSslStatelessServer final {
public:
    using SendTo = std::function<bool(const std::uint8_t*,
                                      std::size_t,
                                      const sockaddr_storage&,
                                      int)>;

    WolfSslStatelessServer(SendTo send_to,
                           std::span<const std::uint8_t> password,
                           CipherSuite suite,
                           std::chrono::milliseconds cookie_secret_lifetime =
                               std::chrono::hours{1});
    ~WolfSslStatelessServer();

    WolfSslStatelessServer(const WolfSslStatelessServer&) = delete;
    WolfSslStatelessServer& operator=(const WolfSslStatelessServer&) = delete;

    [[nodiscard]] std::optional<PreparedWolfSslServerSession> process_datagram(
        std::span<const std::uint8_t> datagram,
        const sockaddr_storage& peer,
        int peer_length);
    [[nodiscard]] WolfSslStatelessServerStats stats() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

class WolfSslDatagramSocket final {
public:
    // The Wintun interface is configured with this MTU. Keeping a complete
    // TrueTunnel record at or below it avoids outer-IP fragmentation.
    static constexpr std::size_t kMaximumPayloadSize =
        kMaximumDatagramPayloadSize;

    WolfSslDatagramSocket(std::unique_ptr<DatagramTransport> transport,
                          std::span<const std::uint8_t> password,
                          bool is_server,
                          CipherSuite suite,
                          TrafficKeyRotationPolicy rotation_policy = {});
    WolfSslDatagramSocket(std::unique_ptr<DatagramTransport> transport,
                          PreparedWolfSslServerSession prepared,
                          TrafficKeyRotationPolicy rotation_policy = {});
    ~WolfSslDatagramSocket();

    WolfSslDatagramSocket(const WolfSslDatagramSocket&) = delete;
    WolfSslDatagramSocket& operator=(const WolfSslDatagramSocket&) = delete;

    void handshake();
    int send_record(std::uint8_t type,
                    const std::uint8_t* data,
                    std::uint16_t length);
    int recv_record(std::uint8_t& type,
                    std::uint8_t* output,
                    std::size_t capacity);
    [[nodiscard]] TrafficKeyRotationStats rotation_stats() const noexcept;
    void shutdown() noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace secure
