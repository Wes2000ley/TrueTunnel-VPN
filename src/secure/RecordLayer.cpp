#include "RecordLayer.h"
#include <stdexcept>
#include <cstring>
#include <algorithm>

namespace secure {

int RecordLayer::send_record(uint8_t type, const uint8_t* data, uint16_t len) {
    if (!send_) throw std::runtime_error("send AEAD not set");
    if (!transport_) throw std::runtime_error("transport not set");
    // header in clear
    uint8_t hdr[11];
    hdr[0] = type;
    uint64_t be_seq = to_be64(send_seq_);
    std::memcpy(hdr+1, &be_seq, 8);
    uint16_t be_len = to_be16(len);
    std::memcpy(hdr+9, &be_len, 2);

    std::vector<uint8_t> ct;
    std::array<uint8_t,16> tag{};
    send_->seal(type, send_seq_, data, len, ct, tag);
    const size_t tag_len = std::min<size_t>(tag.size(), send_->tag_length());

    std::vector<uint8_t> packet;
    packet.reserve(sizeof(hdr) + ct.size() + tag_len);
    packet.insert(packet.end(), hdr, hdr + sizeof(hdr));
    packet.insert(packet.end(), ct.begin(), ct.end());
    packet.insert(packet.end(), tag.begin(), tag.begin() + static_cast<std::ptrdiff_t>(tag_len));

    if (!transport_->write_all(packet.data(), packet.size())) return -1;

    send_seq_++;
    return (int)len;
}

int RecordLayer::recv_record(uint8_t& type, uint8_t* out, size_t cap) {
    if (!recv_) throw std::runtime_error("recv AEAD not set");
    if (!transport_) throw std::runtime_error("transport not set");
    uint8_t hdr[11];
    if (!transport_->read_all(hdr, sizeof(hdr))) return -1;

    type = hdr[0];
    uint64_t be_seq;
    std::memcpy(&be_seq, hdr + 1, sizeof(be_seq));
    uint64_t seq = from_be64(be_seq);
    uint16_t be_len;
    std::memcpy(&be_len, hdr + 9, sizeof(be_len));
    uint16_t len = from_be16(be_len);

    if (seq != recv_seq_) return -1; // strict ordering (TCP)

    if (cap < len) return -1;

    std::vector<uint8_t> ct(len);
    if (!transport_->read_all(ct.data(), len)) return -1;

    std::array<uint8_t,16> tag{};
    const size_t tag_len = std::min<size_t>(tag.size(), recv_->tag_length());
    if (!transport_->read_all(tag.data(), tag_len)) return -1;

    std::vector<uint8_t> pt;
    if (!recv_->open(type, seq, ct.data(), len, tag, pt)) return -1;

    std::memcpy(out, pt.data(), len);
    recv_seq_++;
    return (int)len;
}

} // namespace secure
