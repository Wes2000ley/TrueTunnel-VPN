#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

namespace secure {

// Matches the MTU configured on the Wintun interface. A DTLS application frame
// must not exceed this value.
inline constexpr std::size_t kMaximumDatagramPayloadSize = 1380U;

enum class DatagramReceiveResult {
    Received,
    Timeout,
    Closed,
    Error,
};

enum class DatagramSendResult {
    Sent,
    WouldBlock,
    Closed,
    Error,
};

// Preserves UDP packet boundaries for DTLS. The receive callback must return
// one complete datagram and honor the supplied timeout.
class DatagramTransport final {
public:
    using SendFn = std::function<DatagramSendResult(
        const std::uint8_t*, std::size_t)>;
    using ReceiveFn = std::function<DatagramReceiveResult(
        std::vector<std::uint8_t>&, std::chrono::milliseconds)>;
    using CloseFn = std::function<void()>;

    DatagramTransport(SendFn send_fn,
                      ReceiveFn receive_fn,
                      CloseFn close_fn = {});
    ~DatagramTransport();

    DatagramTransport(const DatagramTransport&) = delete;
    DatagramTransport& operator=(const DatagramTransport&) = delete;

    [[nodiscard]] DatagramSendResult send_datagram(
        const std::uint8_t* data,
        std::size_t length);
    [[nodiscard]] DatagramReceiveResult receive_datagram(
        std::vector<std::uint8_t>& output,
        std::chrono::milliseconds timeout);

    void close() noexcept;
    [[nodiscard]] bool is_closed() const noexcept;

private:
    SendFn send_fn_;
    ReceiveFn receive_fn_;
    CloseFn close_fn_;
    std::atomic<bool> closed_{false};
};

} // namespace secure
