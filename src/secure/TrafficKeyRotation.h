#pragma once

#include <chrono>
#include <cstdint>

namespace secure {

// Application-level guardrails for TLS 1.3 traffic-key epochs. The
// underlying providers retain their own AEAD limits; these lower limits
// request a fresh epoch before a long-lived VPN session approaches them.
struct TrafficKeyRotationPolicy {
    std::uint64_t max_records{1'000'000U};
    std::uint64_t max_bytes{1ULL << 30U};
    std::chrono::seconds max_age{std::chrono::hours{1}};
};

struct TrafficKeyRotationStats {
    std::uint64_t sent_records{};
    std::uint64_t sent_bytes{};
    std::uint64_t key_update_requests{};
    std::uint64_t rotation_failures{};
    // Schannel performs TLS 1.3 post-handshake processing internally and
    // does not expose an application-initiated KeyUpdate API.
    bool application_initiation_supported{};
};

} // namespace secure
