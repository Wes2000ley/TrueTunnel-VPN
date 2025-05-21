/*
* TrueTunnel VPN - Secure FIPS-compliant VPN tunnel
 * Copyright (c) 2025 Wesley Atwell
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the MIT License OR GNU GPL v2.0 (at your option).
 *
 * You should have received a copy of both licenses in the LICENSE file.
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <objbase.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include "vpn.hpp"
#include "utils.hpp"

#include <iostream>
#include <filesystem>
#include <thread>
#include <stdexcept>
#include <string>
#include <functional>		  //  ← ask() validator
#include <mutex>

#include "termcolor.hpp"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/provider.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"iphlpapi.lib")

namespace std {
	class mutex;
}

using termcolor::bold;
using termcolor::green;
using termcolor::yellow;
using termcolor::red;
using termcolor::reset;

#define CHECK(cond,msg)  do{ if(!(cond)) throw std::runtime_error(msg);}while(0)

std::mutex ssl_read_mutex;
std::mutex ssl_write_mutex;



void LoadWintun() {
	static std::once_flag once;
	std::call_once(once, []() {
		hWintun = ::LoadLibraryW(L"wintun.dll");
		CHECK(hWintun, "LoadLibrary(wintun.dll) failed");

		auto load_fn = [](auto &fn, const char *name) {
			fn = reinterpret_cast<std::remove_reference_t<decltype(fn)>>(
				::GetProcAddress(hWintun, name));
			CHECK(fn, std::string("GetProcAddress failed: ") + name);
		};

		load_fn(WintunCreateAdapter, "WintunCreateAdapter");
		load_fn(WintunStartSession, "WintunStartSession");
		load_fn(WintunEndSession, "WintunEndSession");
		load_fn(WintunCloseAdapter, "WintunCloseAdapter");
		load_fn(WintunAllocateSendPacket, "WintunAllocateSendPacket");
		load_fn(WintunSendPacket, "WintunSendPacket");
		load_fn(WintunReceivePacket, "WintunReceivePacket");
		load_fn(WintunReleaseReceivePacket, "WintunReleaseReceivePacket");
	});
}


// ─── FIPS–compliant key + certificate helpers ──────────────────────────

EVPKeyPtr generate_fips_rsa_key() {
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", "provider=fips");
	CHECK(ctx, "EVP_PKEY_CTX_new_from_name (RSA/FIPS) failed");

	CHECK(EVP_PKEY_keygen_init(ctx) > 0, "keygen_init");
	CHECK(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072) > 0, "key bits");

	EVP_PKEY *raw = nullptr;
	CHECK(EVP_PKEY_keygen(ctx, &raw) > 0, "keygen");
	EVP_PKEY_CTX_free(ctx);
	return {raw, EVP_PKEY_free};
}

X509 *generate_self_signed_cert(EVP_PKEY *pkey,
                                const char *common_name) {
	X509 *crt = X509_new();
	CHECK(crt, "X509_new");
	CHECK(X509_set_version(crt, 2), "set version");
	CHECK(ASN1_INTEGER_set(X509_get_serialNumber(crt), 1), "serial");

	/* Valid for one year */
	CHECK(X509_gmtime_adj(X509_get_notBefore(crt), 0), "notBefore");
	CHECK(X509_gmtime_adj(X509_get_notAfter (crt), 60*60*24*365), "notAfter");

	CHECK(X509_set_pubkey(crt, pkey), "set pubkey");

	X509_NAME *name = X509_get_subject_name(crt);
	CHECK(name, "subj");
	CHECK(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
		      reinterpret_cast<const unsigned char *>(common_name), -1, -1, 0), "CN");
	CHECK(X509_set_issuer_name(crt, name), "issuer");

	/* FIPS-approved signature */
	CHECK(X509_sign(crt, pkey, EVP_sha256()) > 0, "sign");

	return crt;
}

/* Build a TLS context that only offers FIPS-approved suites */
SslCtxPtr make_ssl_ctx(bool is_server) {
	const SSL_METHOD* method = is_server ? TLS_server_method() : TLS_client_method();
	SSL_CTX* raw_ctx = SSL_CTX_new(method);
	CHECK(raw_ctx, "SSL_CTX_new failed");

	SslCtxPtr ctx(raw_ctx, SSL_CTX_free);

	CHECK(SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION) == 1, "set_min_proto_version");
	CHECK(SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION) == 1, "set_max_proto_version");

	// TLS 1.3 suites (FIPS-approved)
	CHECK(SSL_CTX_set_ciphersuites(ctx.get(),
		"TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256") == 1,
		"set_ciphersuites");

	// TLS 1.2 FIPS alias
	CHECK(SSL_CTX_set_cipher_list(ctx.get(), "FIPS") == 1, "set_cipher_list");

	// Key + cert
	EvpKeyPtr key(generate_fips_rsa_key().release(), EVP_PKEY_free);
	X509Ptr cert(generate_self_signed_cert(key.get(), is_server ? "MyVPN Server" : "MyVPN Client"), X509_free);

	CHECK(SSL_CTX_use_certificate(ctx.get(), cert.get()) == 1, "use cert");
	CHECK(SSL_CTX_use_PrivateKey(ctx.get(), key.get()) == 1, "use key");
	CHECK(SSL_CTX_check_private_key(ctx.get()) == 1, "check key");

	X509_STORE* store = SSL_CTX_get_cert_store(ctx.get());
	CHECK(store, "get_cert_store");
	CHECK(X509_STORE_add_cert(store, cert.get()) == 1, "add_cert_to_store");

	SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);

	return ctx;
}


void tun_to_tls(WINTUN_SESSION_HANDLE session, SSL *ssl, std::atomic<bool> &running) {
	while (running) {
		UINT32 size = 0;
		void *pkt = WintunReceivePacket(session, &size);
		if (!pkt) {
			Sleep(1);
			continue;
		}

		uint8_t type = PACKET_TYPE_IP;

		{
			std::lock_guard<std::mutex> lock(ssl_write_mutex);
			SSL_write(ssl, &type, 1);
			SSL_write(ssl, pkt, size);
		}


		WintunReleaseReceivePacket(session, pkt);
	}
}


void tls_to_tun(WINTUN_SESSION_HANDLE session, SSL *ssl, std::atomic<bool> &running) {
	char buf[1600] {};
	while (running) {
		uint8_t pkt_type = 0;
		{
			std::lock_guard<std::mutex> lock(ssl_read_mutex);
			if (SSL_read(ssl, &pkt_type, 1) <= 0) break;
		}


		if (pkt_type == PACKET_TYPE_IP) {
			int n = 0;
			{
				std::lock_guard<std::mutex> lock(ssl_read_mutex);
				n = SSL_read(ssl, buf, sizeof(buf));
			}
			if (n <= 0) break;

			void *pkt = WintunAllocateSendPacket(session, (UINT32) n);
			if (!pkt) break;
			memcpy(pkt, buf, n);
			WintunSendPacket(session, pkt, (UINT32) n);

		} else if (pkt_type == PACKET_TYPE_MSG) {
			char msg_buf[1024] = {};
			int n = 0;
			{
				std::lock_guard<std::mutex> lock(ssl_read_mutex);
				n = SSL_read(ssl, buf, sizeof(buf));
			}
			if (n > 0) {
				msg_buf[n] = '\0';

				std::cout << "[📨] Message from peer: " << msg_buf << "\n";

				if (std::string(msg_buf) == "/quit") {
					std::cout << "[!] Peer requested disconnect. Closing tunnel.\n";
					running = false;
					break;
				}
			}
		}
	}
}



std::mutex ssl_mutex;


void send_message(SSL *ssl, const std::string &msg) {
std::lock_guard<std::mutex> lock(ssl_write_mutex);
	uint8_t packet_type = PACKET_TYPE_MSG;
	SSL_write(ssl, &packet_type, 1);
	SSL_write(ssl, msg.c_str(), static_cast<int>(msg.size()));
}
