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

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <array>

namespace secure {

// A blocking, TLS 1.3-only Schannel stream. Application records retain the
// existing TrueTunnel [type][length][payload] interface, but encryption,
// ordering, replay protection, TLS key scheduling, and close-notify are owned
// by Schannel rather than the legacy custom record layer. TrueTunnel replaces
// the full TLS session before its conservative traffic-key limits are reached.
class SchannelSocket final {
public:
    SchannelSocket(SOCKET socket,
                   std::span<const std::uint8_t> password,
                   bool is_server,
                   CipherSuite suite,
                   TrafficKeyRotationPolicy rotation_policy = {});
    ~SchannelSocket();

    SchannelSocket(const SchannelSocket&) = delete;
    SchannelSocket& operator=(const SchannelSocket&) = delete;
    SchannelSocket(SchannelSocket&&) = delete;
    SchannelSocket& operator=(SchannelSocket&&) = delete;

    void handshake();

    int send_record(std::uint8_t type,
                    const std::uint8_t* data,
                    std::uint16_t length);
    int send_record_until(
        std::uint8_t type,
        const std::uint8_t* data,
        std::uint16_t length,
        std::chrono::steady_clock::time_point deadline);
    int recv_record(std::uint8_t& type,
                    std::uint8_t* output,
                    std::size_t capacity);
    int recv_record_until(
        std::uint8_t& type,
        std::uint8_t* output,
        std::size_t capacity,
        std::chrono::steady_clock::time_point deadline);

    [[nodiscard]] TrafficKeyRotationStats rotation_stats() const noexcept;

    // A per-handshake, exporter-derived continuity secret used only to
    // authenticate a make-before-break replacement.  It is never sent on
    // the wire.  The caller owns and must wipe the returned copy.
    [[nodiscard]] std::array<std::uint8_t, 32> continuity_binding() const;

    // Construct a fixed-domain replacement proof authorizing the exact NEW
    // TLS continuity binding for the supplied random request nonce and
    // four-byte network-order assigned address.
    [[nodiscard]] std::array<std::uint8_t, 32> replacement_proof(
        std::span<const std::uint8_t> request_nonce,
        std::span<const std::uint8_t> assigned_ipv4,
        std::span<const std::uint8_t> new_binding) const;

    [[nodiscard]] static std::array<std::uint8_t, 32> replacement_proof(
        const std::array<std::uint8_t, 32>& old_binding,
        const std::array<std::uint8_t, 32>& new_binding,
        std::span<const std::uint8_t> request_nonce,
        std::span<const std::uint8_t> assigned_ipv4);

#ifdef TRUETUNNEL_SECURE_TRANSPORT_TEST
    void set_test_partial_write_failure_after(std::size_t ciphertext_bytes);
    void set_test_plaintext_chunk_pause_after(
        std::size_t completed_chunks,
        std::chrono::milliseconds pause);
#endif

    // Sends TLS close_notify on a best-effort basis. Socket ownership remains
    // with SecureSocket, which performs shutdown()/closesocket().
    void shutdown() noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace secure
