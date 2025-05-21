//
// Created by Skyri on 5/21/2025.
//

#ifndef HMACAUTHENTICATOR_H
#define HMACAUTHENTICATOR_H


#pragma warning(push)
#pragma warning(disable: 4702) // Disable "unreachable code" warning
#include "raii.hpp"
class HmacAuthenticator {
public:
	HmacAuthenticator(SSL* ssl, const std::string& password, bool is_server) {
		constexpr size_t NONCE_SIZE = 16;
		constexpr size_t HMAC_DATA_SIZE = 32;
		constexpr size_t MAX_HMAC_SIZE = EVP_MAX_MD_SIZE;

		// 1. Generate nonces
		OpenSSLSecurePtr<unsigned char> my_nonce(NONCE_SIZE);
		OpenSSLSecurePtr<unsigned char> peer_nonce(NONCE_SIZE);
		CHECK(my_nonce && peer_nonce, "Secure malloc failed");
		CHECK(RAND_bytes(my_nonce.get(), NONCE_SIZE) == 1, "RAND_bytes failed");

		// 2. Exchange nonces
		if (is_server) {
		CHECK(SSL_read(ssl, peer_nonce.get(), static_cast<int>(NONCE_SIZE)) == static_cast<int>(NONCE_SIZE), "read peer nonce");
		CHECK(SSL_write(ssl, my_nonce.get(), static_cast<int>(NONCE_SIZE)) == static_cast<int>(NONCE_SIZE), "send own nonce");
		} else {
		CHECK(SSL_write(ssl, my_nonce.get(), static_cast<int>(NONCE_SIZE)) == static_cast<int>(NONCE_SIZE), "send own nonce");
		CHECK(SSL_read(ssl, peer_nonce.get(), static_cast<int>(NONCE_SIZE)) == static_cast<int>(NONCE_SIZE), "read peer nonce");
		}

		// 3. Compose input data
		OpenSSLSecurePtr<unsigned char> data(HMAC_DATA_SIZE);
		CHECK(data, "Secure malloc failed");
		if (is_server) {
			memcpy(data.get(), peer_nonce.get(), NONCE_SIZE);
			memcpy(data.get() + NONCE_SIZE, my_nonce.get(), NONCE_SIZE);
		} else {
			memcpy(data.get(), my_nonce.get(), NONCE_SIZE);
			memcpy(data.get() + NONCE_SIZE, peer_nonce.get(), NONCE_SIZE);
		}

		// 4. Compute HMAC
		OpenSSLSecurePtr<unsigned char> my_hmac(MAX_HMAC_SIZE);
		CHECK(my_hmac, "Secure malloc failed");

		HmacCtx hmac(EVP_sha256(),
		             reinterpret_cast<const unsigned char*>(password.data()),
		             password.size());

		std::vector<unsigned char> mac_result = hmac.compute(data.get(), HMAC_DATA_SIZE);
		CHECK(mac_result.size() <= MAX_HMAC_SIZE, "HMAC overflow");

		std::memcpy(my_hmac.get(), mac_result.data(), mac_result.size());
		unsigned int hlen = static_cast<unsigned int>(mac_result.size());

		// 5. Exchange HMACs
		OpenSSLSecurePtr<unsigned char> peer_hmac(MAX_HMAC_SIZE);
		CHECK(peer_hmac, "Secure malloc failed");

		CHECK(SSL_write(ssl, my_hmac.get(), static_cast<int>(hlen)) == static_cast<int>(hlen), "send HMAC");
		CHECK(SSL_read(ssl, peer_hmac.get(), static_cast<int>(hlen)) == static_cast<int>(hlen), "receive HMAC");

		// 6. Constant-time compare
		success_ = (CRYPTO_memcmp(my_hmac.get(), peer_hmac.get(), hlen) == 0);
	}

	[[nodiscard]] bool succeeded() const { return success_; }

private:
	bool success_ = false;
};


#pragma warning(pop)

#endif //HMACAUTHENTICATOR_H
