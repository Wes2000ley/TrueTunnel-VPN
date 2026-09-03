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

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace secure {

// A blocking, TLS 1.3-only Schannel stream. Application records retain the
// existing TrueTunnel [type][length][payload] interface, but encryption,
// ordering, replay protection, key updates, and close-notify are owned by
// Schannel rather than the legacy custom record layer.
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
    int recv_record(std::uint8_t& type,
                    std::uint8_t* output,
                    std::size_t capacity);

    [[nodiscard]] TrafficKeyRotationStats rotation_stats() const noexcept;

    // Sends TLS close_notify on a best-effort basis. Socket ownership remains
    // with SecureSocket, which performs shutdown()/closesocket().
    void shutdown() noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace secure
