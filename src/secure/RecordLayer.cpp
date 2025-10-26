#include "RecordLayer.h"
#include <stdexcept>
#include <cstring>
#include <algorithm>

namespace secure {

bool RecordLayer::write_all(SOCKET s, const uint8_t* p, size_t n) {
    size_t off = 0;
    while (off < n) {
        int chunk = (int)std::min<size_t>(n - off, 1 << 30);
        int sent = ::send(s, (const char*)p + off, chunk, 0);
        if (sent <= 0) return false;
        off += (size_t)sent;
    }
    return true;
}

bool RecordLayer::read_all(SOCKET s, uint8_t* p, size_t n) {
    size_t off = 0;
    while (off < n) {
        int got = ::recv(s, (char*)p + off, (int)(n - off), 0);
        if (got <= 0) return false;
        off += (size_t)got;
    }
    return true;
}

int RecordLayer::send_record(uint8_t type, const uint8_t* data, uint16_t len) {
    if (!send_) throw std::runtime_error("send AEAD not set");
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

    // write: hdr | ct | tag
    if (!write_all(s_, hdr, sizeof(hdr))) return -1;
    if (!write_all(s_, ct.data(), ct.size())) return -1;
    if (!write_all(s_, tag.data(), tag_len)) return -1;

    send_seq_++;
    return (int)len;
}

int RecordLayer::recv_record(uint8_t& type, uint8_t* out, size_t cap) {
    if (!recv_) throw std::runtime_error("recv AEAD not set");
    uint8_t hdr[11];
    if (!read_all(s_, hdr, sizeof(hdr))) return -1;

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
    if (!read_all(s_, ct.data(), len)) return -1;

    std::array<uint8_t,16> tag{};
    const size_t tag_len = std::min<size_t>(tag.size(), recv_->tag_length());
    if (!read_all(s_, tag.data(), tag_len)) return -1;

    std::vector<uint8_t> pt;
    if (!recv_->open(type, seq, ct.data(), len, tag, pt)) return -1;

    std::memcpy(out, pt.data(), len);
    recv_seq_++;
    return (int)len;
}

} // namespace secure
