#pragma once
#include "CngUtils.h"
#include "CipherSuite.h"
#include <winsock2.h>
#include <vector>
#include <string>

namespace secure {

	// Material derived by handshake
	struct Keys {
		std::array<uint8_t,32> k_send;
		std::array<uint8_t,32> k_recv;
		std::array<uint8_t,4>  iv_send;
		std::array<uint8_t,4>  iv_recv;
	};

	struct HandshakeResult {
		Keys keys;
		CipherSuite suite{CipherSuite::Aes256Gcm};
	};

	// Performs ECDHE P-256 + PSK verification and derives traffic keys
	class Handshake {
	public:
		// psk = UTF-8 bytes of your shared password
		static HandshakeResult run(bool is_server,
		                           SOCKET s,
		                           const std::vector<uint8_t>& psk,
		                           CipherSuite suite);
	};

} // namespace secure
