#pragma once
#include "CngUtils.h"
#include "CipherSuite.h"
#include "AeadChaCha20Poly1305.h"
#include <vector>

namespace secure {

// AEAD with 12-byte nonce = 4-byte salt || 8-byte seq
class AeadContext {
public:
	AeadContext() = default;
	void init(CipherSuite suite,
	          const std::array<uint8_t,32>& key,
	          const std::array<uint8_t,4>& iv_salt);
	// Encrypt: header (aad) = [type(1)][seq(8)][len(2)]
	void seal(uint8_t type, uint64_t seq, const uint8_t* pt, uint16_t pt_len,
	          std::vector<uint8_t>& ct, std::array<uint8_t,16>& tag);
	// Decrypt
	bool open(uint8_t type, uint64_t seq, const uint8_t* ct, uint16_t ct_len,
	          const std::array<uint8_t,16>& tag, std::vector<uint8_t>& out);

	[[nodiscard]] size_t tag_length() const noexcept { return static_cast<size_t>(tag_len_); }


	enum class ChaChaImplOverride : uint8_t { Auto, Cng, Soft };
	static ChaChaImplOverride ch_override();

	[[nodiscard]] bool using_cng() const noexcept { return use_cng_; }
	[[nodiscard]] CipherSuite cipher() const noexcept { return suite_; }

private:
	void configure(CipherSuite suite);


	Alg alg_;
	Key key_;
	CipherSuite suite_{CipherSuite::Aes256Gcm};
	std::array<uint8_t,4> salt_{};
	BCRYPT_AUTH_TAG_LENGTHS_STRUCT tagLens_{};
	ULONG tag_len_{16};
	bool ready_ = false;
	bool use_cng_{true};                     // false => software path
    AeadChaCha20Poly1305 chacha_fallback_;   // used when CNG lacks ChaCha
};

} // namespace secure
