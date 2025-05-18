/*
* TrueTunnel VPN - Secure FIPS-compliant VPN tunnel
 * Copyright (c) 2025 Wesley Atwell
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the MIT License OR GNU GPL v2.0 (at your option).
 *
 * You should have received a copy of both licenses in the LICENSE file.
 */
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <objbase.h>
#include <iphlpapi.h>
#include <netioapi.h>


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

// ─── Wintun ABI typedefs ─────────────────────────────────────────────────────
typedef struct WINTUN_ADAPTER_   *WINTUN_ADAPTER_HANDLE;
typedef struct WINTUN_SESSION_   *WINTUN_SESSION_HANDLE;

typedef WINTUN_ADAPTER_HANDLE    (WINAPI *WINTUN_CREATE_ADAPTER_FUNC)(PCWSTR, PCWSTR, const GUID *);
typedef WINTUN_SESSION_HANDLE    (WINAPI *WINTUN_START_SESSION_FUNC)(WINTUN_ADAPTER_HANDLE, UINT32);
typedef void                    (WINAPI *WINTUN_END_SESSION_FUNC)(WINTUN_SESSION_HANDLE);
typedef void                    (WINAPI *WINTUN_CLOSE_ADAPTER_FUNC)(WINTUN_ADAPTER_HANDLE);
typedef void *                  (WINAPI *WINTUN_ALLOCATE_SEND_PACKET_FUNC)(WINTUN_SESSION_HANDLE, UINT32);
typedef BOOL                    (WINAPI *WINTUN_SEND_PACKET_FUNC)(WINTUN_SESSION_HANDLE, void *, UINT32);
typedef void *                  (WINAPI *WINTUN_RECEIVE_PACKET_FUNC)(WINTUN_SESSION_HANDLE, UINT32 *);
typedef void                    (WINAPI *WINTUN_RELEASE_RECEIVE_PACKET_FUNC)(WINTUN_SESSION_HANDLE, void *);

// ─── Inline globals ───────────────────────────────────────────────────────────
// C++17 inline variables: exactly one definition, external linkage
inline HMODULE                            hWintun                     = nullptr;
inline WINTUN_CREATE_ADAPTER_FUNC         WintunCreateAdapter         = nullptr;
inline WINTUN_START_SESSION_FUNC          WintunStartSession          = nullptr;
inline WINTUN_END_SESSION_FUNC            WintunEndSession            = nullptr;
inline WINTUN_CLOSE_ADAPTER_FUNC          WintunCloseAdapter          = nullptr;
inline WINTUN_ALLOCATE_SEND_PACKET_FUNC   WintunAllocateSendPacket    = nullptr;
inline WINTUN_SEND_PACKET_FUNC            WintunSendPacket            = nullptr;
inline WINTUN_RECEIVE_PACKET_FUNC         WintunReceivePacket         = nullptr;
inline WINTUN_RELEASE_RECEIVE_PACKET_FUNC WintunReleaseReceivePacket  = nullptr;

// ─── Load entry points ────────────────────────────────────────────────────────
void LoadWintun();


// ─── FIPS–compliant key + certificate helpers ──────────────────────────
EVP_PKEY *generate_fips_rsa_key();

X509 *generate_self_signed_cert(EVP_PKEY *pkey,
                                       const char *common_name);

/* Build a TLS context that only offers FIPS-approved suites */
SSL_CTX *make_ssl_ctx(bool is_server);

enum vpn_packet_type : uint8_t;


//— Packet pumps
void tun_to_tls(WINTUN_SESSION_HANDLE session, SSL *ssl, std::atomic<bool>& running);

void tls_to_tun(WINTUN_SESSION_HANDLE session, SSL *ssl, std::atomic<bool>& running);

void send_message(SSL *ssl, const std::string &msg);
enum vpn_packet_type : uint8_t {
	PACKET_TYPE_IP = 0x00,
	PACKET_TYPE_MSG = 0x01
};
