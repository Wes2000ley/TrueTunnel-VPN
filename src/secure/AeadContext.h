#pragma once
#include "CngUtils.h"
#include <vector>

namespace secure {

	// AES-256-GCM with 12-byte nonce = 4-byte salt || 8-byte seq
	class AeadContext {
	public:
		AeadContext(); // call init() next
		void init(const std::array<uint8_t,32>& key, const std::array<uint8_t,4>& iv_salt);
		// Encrypt: header (aad) = [type(1)][seq(8)][len(2)]
		void seal(uint8_t type, uint64_t seq, const uint8_t* pt, uint16_t pt_len,
				  std::vector<uint8_t>& ct, std::array<uint8_t,16>& tag);
		// Decrypt
		bool open(uint8_t type, uint64_t seq, const uint8_t* ct, uint16_t ct_len,
				  const std::array<uint8_t,16>& tag, std::vector<uint8_t>& out);

	private:
		Alg aes_;
		Key key_;
		std::array<uint8_t,4> salt_{};
		BCRYPT_AUTH_TAG_LENGTHS_STRUCT tagLens_{};
		bool ready_ = false;
	};

} // namespace secure
