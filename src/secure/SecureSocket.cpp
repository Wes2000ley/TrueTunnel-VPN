#include "SecureSocket.h"
#include <stdexcept>

namespace secure {

	SecureSocket::SecureSocket(SOCKET s, const std::string& psk, bool is_server)
		: s_(s), is_server_(is_server), psk_(psk.begin(), psk.end()), layer_(s) {
		if (s_ == INVALID_SOCKET) throw std::runtime_error("Invalid socket");
	}

	SecureSocket::~SecureSocket() {
		close();
	}

	void SecureSocket::handshake() {
		if (handshook_) return;
		auto res = Handshake::run(is_server_, s_, psk_);
		send_aead_.init(res.keys.k_send, res.keys.iv_send);
		recv_aead_.init(res.keys.k_recv, res.keys.iv_recv);
		layer_.set_send(&send_aead_);
		layer_.set_recv(&recv_aead_);
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
		if (s_ != INVALID_SOCKET) {
			::shutdown(s_, SD_BOTH);
			::closesocket(s_);
			s_ = INVALID_SOCKET;
		}
	}

} // namespace secure
