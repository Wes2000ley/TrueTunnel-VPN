#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

namespace secure {

class ITransport {
public:
    virtual ~ITransport() = default;
    virtual bool write_all(const uint8_t* data, std::size_t len) = 0;
    virtual bool read_all(uint8_t* data, std::size_t len) = 0;
};

class DatagramTransport : public ITransport {
public:
    using SendFn    = std::function<bool(const uint8_t*, std::size_t)>;
    using ReceiveFn = std::function<bool(std::vector<uint8_t>&)>;

    DatagramTransport(SendFn send_fn, ReceiveFn recv_fn);

    bool write_all(const uint8_t* data, std::size_t len) override;
    bool read_all(uint8_t* data, std::size_t len) override;

private:
    SendFn    send_fn_;
    ReceiveFn recv_fn_;
    std::vector<uint8_t> current_;
    std::size_t offset_{0};
};

} // namespace secure
