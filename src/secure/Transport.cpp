#include "Transport.h"

#include <stdexcept>
#include <utility>

namespace secure {

DatagramTransport::DatagramTransport(SendFn send_fn,
                                     ReceiveFn receive_fn,
                                     CloseFn close_fn)
    : send_fn_{std::move(send_fn)},
      receive_fn_{std::move(receive_fn)},
      close_fn_{std::move(close_fn)} {
    if (!send_fn_ || !receive_fn_) {
        throw std::invalid_argument(
            "Datagram transport requires send and receive callbacks");
    }
}

DatagramTransport::~DatagramTransport() {
    close();
}

DatagramSendResult DatagramTransport::send_datagram(
    const std::uint8_t* const data,
    const std::size_t length) {
    if (closed_.load(std::memory_order_acquire)) {
        return DatagramSendResult::Closed;
    }
    if (length != 0U && data == nullptr) {
        return DatagramSendResult::Error;
    }
    return send_fn_(data, length);
}

DatagramReceiveResult DatagramTransport::receive_datagram(
    std::vector<std::uint8_t>& output,
    const std::chrono::milliseconds timeout) {
    output.clear();
    if (closed_.load(std::memory_order_acquire)) {
        return DatagramReceiveResult::Closed;
    }

    const auto result = receive_fn_(output, timeout);
    if (closed_.load(std::memory_order_acquire)) {
        output.clear();
        return DatagramReceiveResult::Closed;
    }
    if (result == DatagramReceiveResult::Received && output.empty()) {
        return DatagramReceiveResult::Error;
    }
    if (result != DatagramReceiveResult::Received) {
        output.clear();
    }
    return result;
}

void DatagramTransport::close() noexcept {
    if (closed_.exchange(true, std::memory_order_acq_rel)) {
        return;
    }
    if (close_fn_) {
        try {
            close_fn_();
        } catch (...) {
        }
    }
}

bool DatagramTransport::is_closed() const noexcept {
    return closed_.load(std::memory_order_acquire);
}

} // namespace secure
