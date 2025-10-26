#include <winsock2.h>

#include "SecureSocket.h"

#include <stdexcept>

namespace secure {

namespace {
class SocketTransport final : public ITransport {
public:
	explicit SocketTransport(SOCKET s) : s_(s) {}

	bool write_all(const uint8_t* data, std::size_t len) override {
		std::size_t off = 0;
		while (off < len) {
			const int sent = ::send(s_, reinterpret_cast<const char*>(data) + off,
			                        static_cast<int>(len - off), 0);
			if (sent <= 0) return false;
			off += static_cast<std::size_t>(sent);
		}
		return true;
	}

	bool read_all(uint8_t* data, std::size_t len) override {
		std::size_t off = 0;
		while (off < len) {
			const int got = ::recv(s_, reinterpret_cast<char*>(data) + off,
			                       static_cast<int>(len - off), 0);
			if (got <= 0) return false;
			off += static_cast<std::size_t>(got);
		}
		return true;
	}

private:
	SOCKET s_;
};
} // namespace

SecureSocket::SecureSocket(SOCKET s, const std::string& psk, bool is_server, CipherSuite suite)
	: SecureSocket(s,
	               std::make_unique<SocketTransport>(s),
	               psk,
	               is_server,
	               suite,
	               TransportType::Stream,
	               true) {}

SecureSocket::SecureSocket(SOCKET s,
                           std::unique_ptr<ITransport> transport,
                           const std::string& psk,
                           bool is_server,
                           CipherSuite suite,
                           TransportType type,
                           bool owns_socket)
	: s_(s),
	  owns_socket_(owns_socket),
	  is_server_(is_server),
	  transport_type_(type),
	  suite_(suite),
	  psk_(psk.begin(), psk.end()),
	  transport_(std::move(transport)),
	  layer_(transport_.get()) {
	if (!transport_) throw std::runtime_error("transport not provided");
	if (owns_socket_ && s_ == INVALID_SOCKET) throw std::runtime_error("Invalid socket");
}

SecureSocket::~SecureSocket() {
	close();
}

void SecureSocket::handshake() {
	if (handshook_) return;
	auto res = Handshake::run(is_server_, *transport_, psk_, suite_);
	send_aead_.init(res.suite, res.keys.k_send, res.keys.iv_send);
	recv_aead_.init(res.suite, res.keys.k_recv, res.keys.iv_recv);
	layer_.set_send(&send_aead_);
	layer_.set_recv(&recv_aead_);
	layer_.set_transport(transport_.get());
	handshook_ = true;
}

int SecureSocket::send_record(uint8_t type, const uint8_t* data, uint16_t len) {
	if (!handshook_) throw std::runtime_error("handshake not done");
	return layer_.send_record(type, data, len);
}

int SecureSocket::recv_record(uint8_t& type, uint8_t* out, size_t cap) {
	if (!handshook_) throw std::runtime_error("handshake not done");
	return layer_.recv_record(type, out, cap);
}

void SecureSocket::close() {
	if (!owns_socket_ || s_ == INVALID_SOCKET) {
		return;
	}

	if (transport_type_ == TransportType::Stream) {
		::shutdown(s_, SD_BOTH);
	}
	::closesocket(s_);
	s_ = INVALID_SOCKET;
}

} // namespace secure
