#pragma once
#include "RecordLayer.h"
#include "Handshake.h"
#include <memory>
#include <string>
#include <vector>
#include <cstdint>

namespace secure {
	enum class TransportType {
		Stream,
		Datagram
	};

	class SecureSocket {
	public:
		SecureSocket(SOCKET s, const std::string& psk, bool is_server, CipherSuite suite);
		SecureSocket(SOCKET s,
		             std::unique_ptr<ITransport> transport,
		             const std::string& psk,
		             bool is_server,
		             CipherSuite suite,
		             TransportType type,
		             bool owns_socket);
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
		bool owns_socket_{true};
		bool is_server_{false};
		TransportType transport_type_{TransportType::Stream};
		CipherSuite suite_{CipherSuite::Aes256Gcm};
		std::vector<uint8_t> psk_;
		std::unique_ptr<ITransport> transport_;

		AeadContext send_aead_;
		AeadContext recv_aead_;
		RecordLayer layer_;

		bool handshook_{false};
	};

} // namespace secure
