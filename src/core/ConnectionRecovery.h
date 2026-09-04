#pragma once

#include <chrono>
#include <cstdint>

struct ConnectionRecoveryOptions {
    bool enabled{false};
    std::chrono::milliseconds heartbeat_interval{std::chrono::seconds{5}};
    std::chrono::milliseconds heartbeat_timeout{std::chrono::seconds{15}};
    std::chrono::milliseconds initial_retry_delay{std::chrono::seconds{1}};
    std::chrono::milliseconds maximum_retry_delay{std::chrono::seconds{30}};
};

inline constexpr auto kMinimumHeartbeatInterval =
    std::chrono::milliseconds{100};
inline constexpr auto kMaximumHeartbeatInterval =
    std::chrono::minutes{5};
inline constexpr auto kMaximumHeartbeatTimeout =
    std::chrono::minutes{10};
inline constexpr auto kMinimumReconnectDelay =
    std::chrono::milliseconds{100};
inline constexpr auto kMaximumReconnectDelay =
    std::chrono::minutes{5};

[[nodiscard]] inline bool is_valid_connection_recovery_options(
    const ConnectionRecoveryOptions& options) noexcept {
    return options.heartbeat_interval >= kMinimumHeartbeatInterval &&
           options.heartbeat_interval <= kMaximumHeartbeatInterval &&
           options.heartbeat_timeout >= options.heartbeat_interval * 2 &&
           options.heartbeat_timeout <= kMaximumHeartbeatTimeout &&
           options.initial_retry_delay >= kMinimumReconnectDelay &&
           options.initial_retry_delay <= options.maximum_retry_delay &&
           options.maximum_retry_delay <= kMaximumReconnectDelay;
}

enum class ConnectionPhase : std::uint8_t {
    Idle,
    Connecting,
    Connected,
    Reconnecting,
    Listening,
};

struct ConnectionStatus {
    ConnectionPhase phase{ConnectionPhase::Idle};
    std::uint32_t retry_attempt{0U};
    std::chrono::milliseconds retry_delay{0};
};
