#pragma once
#include "RecordLayer.h"
#include "Handshake.h"
#include <string>
#include <vector>
#include <cstdint>

namespace secure {

	class SecureSocket {
	public:
		SecureSocket(SOCKET s, const std::string& psk, bool is_server, CipherSuite suite);
		~SecureSocket();

		// 1) Perform handshake, derive keys
		void handshake();

		// 2) Send a framed, AEAD-protected record with an app-level type
		// Returns plaintext bytes sent, or -1 on error
		int send_record(uint8_t type, const uint8_t* data, uint16_t len);

		// 3) Receive a framed record, returns plaintext length or -1, sets 'type'
		int recv_record(uint8_t& type, uint8_t* out, size_t cap);

		// Graceful shutdown (half-close OK)
		void close();

		SOCKET native() const { return s_; }

	private:
		SOCKET s_{INVALID_SOCKET};
		bool is_server_{false};
		CipherSuite suite_{CipherSuite::Aes256Gcm};
		std::vector<uint8_t> psk_;

		AeadContext send_aead_;
		AeadContext recv_aead_;
		RecordLayer layer_;

		bool handshook_{false};
	};

} // namespace secure
