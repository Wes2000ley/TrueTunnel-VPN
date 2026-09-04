#pragma once

#include <chrono>
#include <cstdint>
#include <limits>

namespace secure {

// Application-level guardrails for TLS 1.3 traffic-key epochs. The
// underlying providers retain their own AEAD limits; these lower limits
// request a fresh epoch before a long-lived VPN session approaches them.
struct TrafficKeyRotationPolicy {
    std::uint64_t max_records{1'000'000U};
    std::uint64_t max_bytes{1ULL << 30U};
    std::chrono::seconds max_age{std::chrono::hours{1}};
};

// A full TCP renewal can queue at most 256 application records while OLD is
// frozen, then emits three authenticated controls in each NEW direction.
// Keeping a power-of-two envelope above that bound makes every accepted custom
// policy capable of completing the same transaction as the production default.
constexpr std::uint64_t kMinimumTcpRotationRecords = 512U;
constexpr std::uint64_t kMinimumTcpRotationBytes = 512U * 1024U;
constexpr auto kMinimumTcpRotationAge = std::chrono::seconds{30};

[[nodiscard]] constexpr bool is_valid_tcp_rotation_policy(
    const TrafficKeyRotationPolicy& policy) noexcept {
    return (policy.max_records == 0U ||
            policy.max_records >= kMinimumTcpRotationRecords) &&
           (policy.max_bytes == 0U ||
            policy.max_bytes >= kMinimumTcpRotationBytes) &&
           (policy.max_age == std::chrono::seconds::zero() ||
            policy.max_age >= kMinimumTcpRotationAge);
}

[[nodiscard]] constexpr std::uint64_t rotation_age_limit_microseconds(
    const std::chrono::seconds age) noexcept {
    if (age <= std::chrono::seconds::zero()) return 0U;
    constexpr std::uint64_t kMicrosecondsPerSecond = 1'000'000U;
    const auto seconds = static_cast<std::uint64_t>(age.count());
    constexpr auto kMaximum =
        (std::numeric_limits<std::uint64_t>::max)();
    return seconds > kMaximum / kMicrosecondsPerSecond
        ? kMaximum
        : seconds * kMicrosecondsPerSecond;
}

struct TrafficKeyRotationStats {
    std::uint64_t sent_records{};
    std::uint64_t sent_bytes{};
    std::uint64_t received_records{};
    std::uint64_t received_bytes{};
    std::uint64_t age_microseconds{};
    std::uint64_t key_update_requests{};
    std::uint64_t rotation_failures{};
    // TCP/Schannel cannot be asked to emit KeyUpdate through its supported
    // public API.  The counters below therefore describe a full-session
    // replacement (a new TLS handshake), never an in-place TLS KeyUpdate.
    std::uint64_t session_replacement_attempts{};
    std::uint64_t session_replacement_successes{};
    std::uint64_t session_replacement_failures{};
    std::uint64_t last_handoff_pause_microseconds{};
    // Schannel performs TLS 1.3 post-handshake processing internally and
    // does not expose an application-initiated KeyUpdate API.
    bool application_initiation_supported{};
};

} // namespace secure
