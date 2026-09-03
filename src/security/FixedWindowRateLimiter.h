#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>

namespace security {

class FixedWindowRateLimiter final {
public:
    using Clock = std::chrono::steady_clock;

    struct Limits {
        std::size_t events{0U};
        std::size_t bytes{(std::numeric_limits<std::size_t>::max)()};
    };

    struct Stats {
        std::uint64_t allowed{0U};
        std::uint64_t rejected{0U};
    };

    FixedWindowRateLimiter(Limits global_limits,
                           Limits per_key_limits,
                           std::size_t maximum_keys,
                           Clock::duration window)
        : global_limits_{global_limits},
          per_key_limits_{per_key_limits},
          maximum_keys_{maximum_keys},
          window_{window} {
        if (global_limits_.events == 0U || per_key_limits_.events == 0U ||
            maximum_keys_ == 0U || window_ <= Clock::duration::zero()) {
            throw std::invalid_argument("Rate limiter limits must be positive");
        }
    }

    [[nodiscard]] bool allow(
        const std::string_view key,
        const std::size_t bytes = 0U,
        const Clock::time_point now = Clock::now()) noexcept {
        if (key.empty()) return reject_without_lock();

        try {
            std::lock_guard lock{mutex_};
            roll_window(now);

            // Reject a saturated global budget before allocating or retaining
            // attacker-controlled source keys.
            if (would_exceed(global_, global_limits_, bytes)) {
                ++stats_.rejected;
                return false;
            }

            const std::string owned_key{key};
            auto it = per_key_.find(owned_key);
            if (it == per_key_.end()) {
                if (per_key_.size() >= maximum_keys_) {
                    ++stats_.rejected;
                    return false;
                }
                it = per_key_.emplace(owned_key, Usage{}).first;
            }

            if (would_exceed(it->second, per_key_limits_, bytes)) {
                ++stats_.rejected;
                return false;
            }

            ++global_.events;
            global_.bytes += bytes;
            ++it->second.events;
            it->second.bytes += bytes;
            ++stats_.allowed;
            return true;
        } catch (...) {
            // Allocation or synchronization failures must fail closed at an
            // unauthenticated/resource-admission boundary.
            return reject_without_lock();
        }
    }

    [[nodiscard]] Stats stats() const noexcept {
        try {
            std::lock_guard lock{mutex_};
            return stats_;
        } catch (...) {
            return {};
        }
    }

private:
    struct Usage {
        std::size_t events{0U};
        std::size_t bytes{0U};
    };

    [[nodiscard]] static bool would_exceed(const Usage& usage,
                                           const Limits& limits,
                                           const std::size_t bytes) noexcept {
        if (usage.events >= limits.events || usage.bytes > limits.bytes) {
            return true;
        }
        return bytes > limits.bytes - usage.bytes;
    }

    void roll_window(const Clock::time_point now) {
        if (window_started_ == Clock::time_point{} || now < window_started_ ||
            now - window_started_ >= window_) {
            window_started_ = now;
            global_ = {};
            per_key_.clear();
        }
    }

    [[nodiscard]] bool reject_without_lock() noexcept {
        // Statistics are diagnostic only. Avoid turning a failed lock or
        // allocation into an availability failure while still denying work.
        try {
            std::lock_guard lock{mutex_};
            ++stats_.rejected;
        } catch (...) {
        }
        return false;
    }

    Limits global_limits_;
    Limits per_key_limits_;
    std::size_t maximum_keys_;
    Clock::duration window_;

    mutable std::mutex mutex_;
    Clock::time_point window_started_{};
    Usage global_{};
    std::unordered_map<std::string, Usage> per_key_;
    Stats stats_{};
};

} // namespace security
