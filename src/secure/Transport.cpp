#include "Transport.h"

#include <algorithm>
#include <cstring>
#include <utility>

namespace secure {

DatagramTransport::DatagramTransport(SendFn send_fn, ReceiveFn recv_fn)
    : send_fn_(std::move(send_fn)), recv_fn_(std::move(recv_fn)) {}

bool DatagramTransport::write_all(const uint8_t* data, std::size_t len) {
    if (!send_fn_) return false;
    return send_fn_(data, len);
}

bool DatagramTransport::read_all(uint8_t* data, std::size_t len) {
    if (!recv_fn_) return false;

    std::size_t copied = 0;
    while (copied < len) {
        if (offset_ >= current_.size()) {
            current_.clear();
            offset_ = 0;
            if (!recv_fn_(current_)) {
                current_.clear();
                return false;
            }
            if (current_.empty()) {
                return false;
            }
        }

        const std::size_t remaining = current_.size() - offset_;
        const std::size_t to_copy = std::min(len - copied, remaining);
        std::memcpy(data + copied, current_.data() + offset_, to_copy);
        copied += to_copy;
        offset_ += to_copy;
    }

    return true;
}

} // namespace secure
