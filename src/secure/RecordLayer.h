#pragma once
#include "AeadContext.h"
#include "Transport.h"
#include <vector>
#include <cstdint>

namespace secure {

	// Wire format (TCP):
	// [type:1][seq:8][len:2][ciphertext:len][tag:16]
	struct RecordLayer {
		explicit RecordLayer(ITransport* transport = nullptr)
			: transport_(transport) {}
		// sender
		void set_send(AeadContext* a){ send_ = a; }
		// receiver
		void set_recv(AeadContext* a){ recv_ = a; }
		void set_transport(ITransport* transport) { transport_ = transport; }

		// Send one record
		// returns bytes of plaintext sent
		int send_record(uint8_t type, const uint8_t* data, uint16_t len);

		// Receive one record into out (cap >= 65535). Returns plaintext len, sets type.
		int recv_record(uint8_t& type, uint8_t* out, size_t cap);

		uint64_t next_send_seq() const { return send_seq_; }
		uint64_t next_recv_seq() const { return recv_seq_; }

	private:
		ITransport* transport_{nullptr};
		AeadContext* send_{};
		AeadContext* recv_{};
		uint64_t send_seq_{0};
		uint64_t recv_seq_{0};
	};

} // namespace secure
