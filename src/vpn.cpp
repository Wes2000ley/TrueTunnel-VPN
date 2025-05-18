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

using termcolor::bold;
using termcolor::green;
using termcolor::yellow;
using termcolor::red;
using termcolor::reset;

#define CHECK(cond,msg)  do{ if(!(cond)) throw std::runtime_error(msg);}while(0)

void LoadWintun() {
	hWintun = ::LoadLibraryW(L"wintun.dll");
	CHECK(hWintun, "LoadLibrary(wintun.dll) failed");

	WintunCreateAdapter = reinterpret_cast<WINTUN_CREATE_ADAPTER_FUNC>(
		::GetProcAddress(hWintun, "WintunCreateAdapter"));
	WintunStartSession = reinterpret_cast<WINTUN_START_SESSION_FUNC>(
		::GetProcAddress(hWintun, "WintunStartSession"));
	WintunEndSession = reinterpret_cast<WINTUN_END_SESSION_FUNC>(
		::GetProcAddress(hWintun, "WintunEndSession"));
	WintunCloseAdapter = reinterpret_cast<WINTUN_CLOSE_ADAPTER_FUNC>(
		::GetProcAddress(hWintun, "WintunCloseAdapter"));
	WintunAllocateSendPacket = reinterpret_cast<WINTUN_ALLOCATE_SEND_PACKET_FUNC>(
		::GetProcAddress(hWintun, "WintunAllocateSendPacket"));
	WintunSendPacket = reinterpret_cast<WINTUN_SEND_PACKET_FUNC>(
		::GetProcAddress(hWintun, "WintunSendPacket"));
	WintunReceivePacket = reinterpret_cast<WINTUN_RECEIVE_PACKET_FUNC>(
		::GetProcAddress(hWintun, "WintunReceivePacket"));
	WintunReleaseReceivePacket = reinterpret_cast<WINTUN_RELEASE_RECEIVE_PACKET_FUNC>(
		::GetProcAddress(hWintun, "WintunReleaseReceivePacket"));

	CHECK(WintunCreateAdapter &&
		  WintunStartSession &&
		  WintunEndSession &&
		  WintunCloseAdapter &&
		  WintunAllocateSendPacket &&
		  WintunSendPacket &&
		  WintunReceivePacket &&
		  WintunReleaseReceivePacket,
		  "Failed to resolve one or more Wintun functions");
}


// ─── FIPS–compliant key + certificate helpers ──────────────────────────
EVP_PKEY *generate_fips_rsa_key()
{
    /* Use the global (default) library context – it already points at the
       FIPS provider once we enabled it in main(). */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA",
                                                   "provider=fips");
    CHECK(ctx, "EVP_PKEY_CTX_new_from_name (RSA/FIPS) failed");

    CHECK(EVP_PKEY_keygen_init(ctx)                      > 0, "keygen_init");
    /* §5.6.1 FIPS 140-3 – at least 3072 bits for RSA keys */
    CHECK(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072)    > 0, "key bits");
    EVP_PKEY *pkey = nullptr;
    CHECK(EVP_PKEY_keygen(ctx, &pkey)                    > 0, "keygen");

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

X509 *generate_self_signed_cert(EVP_PKEY *pkey,
                                       const char *common_name)
{
    X509 *crt = X509_new();                              CHECK(crt, "X509_new");
    CHECK(X509_set_version(crt, 2),                      "set version");
    CHECK(ASN1_INTEGER_set(X509_get_serialNumber(crt), 1),"serial");

    /* Valid for one year */
    CHECK(X509_gmtime_adj(X509_get_notBefore(crt), 0),            "notBefore");
    CHECK(X509_gmtime_adj(X509_get_notAfter (crt), 60*60*24*365), "notAfter");

    CHECK(X509_set_pubkey(crt, pkey),                    "set pubkey");

    X509_NAME *name = X509_get_subject_name(crt);        CHECK(name, "subj");
    CHECK(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
          (const unsigned char*)common_name, -1, -1, 0),          "CN");
    CHECK(X509_set_issuer_name(crt, name),               "issuer");

    /* FIPS-approved signature */
    CHECK(X509_sign(crt, pkey, EVP_sha256()) > 0,        "sign");

    return crt;
}

/* Build a TLS context that only offers FIPS-approved suites */
SSL_CTX *make_ssl_ctx(bool is_server)
{
    const SSL_METHOD *method = is_server ?
                               TLS_server_method() : TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);                  CHECK(ctx, "CTX new");

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);          // ≥TLS1.2
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    /* TLS 1.3 suites – AES-GCM only (both SHA-256 & SHA-384 are allowed) */
    CHECK(SSL_CTX_set_ciphersuites(ctx,
           "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256") == 1,
          "set_ciphersuites");

    /* TLS 1.2 “FIPS” alias is kept for backwards-compat – OK to use. */
    CHECK(SSL_CTX_set_cipher_list(ctx, "FIPS") == 1, "set_cipher_list");

    /* One ephemeral, self-signed cert per connection */
    EVP_PKEY *key  = generate_fips_rsa_key();
    X509     *cert = generate_self_signed_cert(
                         key, is_server ? "MyVPN Server" : "MyVPN Client");

    CHECK(SSL_CTX_use_certificate(ctx, cert)  == 1, "use cert");
    CHECK(SSL_CTX_use_PrivateKey(ctx, key)    == 1, "use key");
    CHECK(SSL_CTX_check_private_key(ctx)      == 1, "chk key");

    /* Self-trust (good enough for this demo) */
    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    CHECK(X509_STORE_add_cert(store, cert)    == 1, "add CA");

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    X509_free(cert);
    EVP_PKEY_free(key);
    return ctx;
}



void tun_to_tls(WINTUN_SESSION_HANDLE session, SSL *ssl, std::atomic<bool>& running) {
	while (running) {
		UINT32 size = 0;
		void *pkt = WintunReceivePacket(session, &size);
		if (!pkt) {
			Sleep(1);
			continue;
		}
		uint8_t type = PACKET_TYPE_IP;
		SSL_write(ssl, &type, 1);
		SSL_write(ssl, pkt, size);
		WintunReleaseReceivePacket(session, pkt);
	}
}

void tls_to_tun(WINTUN_SESSION_HANDLE session, SSL *ssl, std::atomic<bool>& running) {
	char buf[1600];
	while (running) {
		uint8_t pkt_type = 0;
		if (SSL_read(ssl, &pkt_type, 1) <= 0) break;

		if (pkt_type == PACKET_TYPE_IP) {
			int n = SSL_read(ssl, buf, sizeof(buf));
			if (n <= 0) break;
			void* pkt = WintunAllocateSendPacket(session, (UINT32)n);
			if (!pkt) break;
			memcpy(pkt, buf, n);
			WintunSendPacket(session, pkt, (UINT32)n);

		} else if (pkt_type == PACKET_TYPE_MSG) {
			char msg_buf[1024] = {};
			int n = SSL_read(ssl, msg_buf, sizeof(msg_buf) - 1);
			if (n > 0) {
				msg_buf[n] = '\0';

				std::cout << "[📨] Message from peer: " << msg_buf << "\n";

				// ADD THIS: if we receive "/quit", stop running
				if (std::string(msg_buf) == "/quit") {
					std::cout << "[!] Peer requested disconnect. Closing tunnel.\n";
					running = false;
					break;
				}
			}
		}
	}
}





void send_message(SSL *ssl, const std::string &msg) {
	uint8_t packet_type = PACKET_TYPE_MSG;
	SSL_write(ssl, &packet_type, 1);
	SSL_write(ssl, msg.c_str(), static_cast<int>(msg.size()));
}
