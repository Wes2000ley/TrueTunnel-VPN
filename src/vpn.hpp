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

#include <array>
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

class VpnServer;
using termcolor::bold;
using termcolor::green;
using termcolor::yellow;
using termcolor::red;
using termcolor::reset;

#define CHECK(cond,msg)  do{ if(!(cond)) throw std::runtime_error(msg);}while(0)

// ─── Wintun ABI typedefs ─────────────────────────────────────────────────────
typedef struct WINTUN_ADAPTER_ *WINTUN_ADAPTER_HANDLE;
typedef struct WINTUN_SESSION_ *WINTUN_SESSION_HANDLE;

typedef WINTUN_ADAPTER_HANDLE (WINAPI *WINTUN_CREATE_ADAPTER_FUNC)(PCWSTR, PCWSTR, const GUID *);

typedef WINTUN_SESSION_HANDLE (WINAPI *WINTUN_START_SESSION_FUNC)(WINTUN_ADAPTER_HANDLE, UINT32);

typedef void (WINAPI *WINTUN_END_SESSION_FUNC)(WINTUN_SESSION_HANDLE);

typedef void (WINAPI *WINTUN_CLOSE_ADAPTER_FUNC)(WINTUN_ADAPTER_HANDLE);

typedef void * (WINAPI *WINTUN_ALLOCATE_SEND_PACKET_FUNC)(WINTUN_SESSION_HANDLE, UINT32);

typedef BOOL (WINAPI *WINTUN_SEND_PACKET_FUNC)(WINTUN_SESSION_HANDLE, void *, UINT32);

typedef void * (WINAPI *WINTUN_RECEIVE_PACKET_FUNC)(WINTUN_SESSION_HANDLE, UINT32 *);

typedef void (WINAPI *WINTUN_RELEASE_RECEIVE_PACKET_FUNC)(WINTUN_SESSION_HANDLE, void *);


// ─── Inline globals ───────────────────────────────────────────────────────────
// C++17 inline variables: exactly one definition, external linkage
inline HMODULE hWintun = nullptr;
inline WINTUN_CREATE_ADAPTER_FUNC WintunCreateAdapter = nullptr;
inline WINTUN_START_SESSION_FUNC WintunStartSession = nullptr;
inline WINTUN_END_SESSION_FUNC WintunEndSession = nullptr;
inline WINTUN_CLOSE_ADAPTER_FUNC WintunCloseAdapter = nullptr;
inline WINTUN_ALLOCATE_SEND_PACKET_FUNC WintunAllocateSendPacket = nullptr;
inline WINTUN_SEND_PACKET_FUNC WintunSendPacket = nullptr;
inline WINTUN_RECEIVE_PACKET_FUNC WintunReceivePacket = nullptr;
inline WINTUN_RELEASE_RECEIVE_PACKET_FUNC WintunReleaseReceivePacket = nullptr;

// ─── Load entry points ────────────────────────────────────────────────────────
void LoadWintun();


// ─── FIPS–compliant key + certificate helpers ──────────────────────────
using EVPKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using SSL_CTX_Ptr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
EVPKeyPtr generate_fips_rsa_key();

X509 *generate_self_signed_cert(EVP_PKEY *pkey,
                                const char *common_name);

/* Build a TLS context that only offers FIPS-approved suites */
using SslCtxPtr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using EvpKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
SslCtxPtr make_ssl_ctx(bool is_server);

enum vpn_packet_type : uint8_t;



constexpr uint8_t PACKET_TYPE_IP  = 0x01;
constexpr uint8_t PACKET_TYPE_MSG = 0x02;


//— Packet pumps
void tun_to_tls(WINTUN_SESSION_HANDLE session, SSL *ssl, std::atomic<bool> &running);

void tls_to_tun(WINTUN_SESSION_HANDLE session, SSL *ssl, std::atomic<bool> &running, std::mutex &session_mutex) ;

void send_message(SSL *ssl, const std::string &msg);

template<typename ForwardFn>
// ─── single header / translation-unit ─────────────────────────────────────────
inline void tls_to_tun_common(WINTUN_SESSION_HANDLE session,
                              SSL*                  ssl,
                              std::atomic<bool>&    running,
                              std::mutex&           session_mutex,
                              ForwardFn&&           maybe_forward)   // ← perfect-fwd
{
    thread_local std::array<uint8_t, 1600> buf;          // re-usable RX buffer

    while (running)
    {
        uint8_t tag{};
        if (SSL_read(ssl, &tag, 1) <= 0)
            break;                                       // connection closed / error

        if (tag == PACKET_TYPE_IP)
        {
            int n = SSL_read(ssl,
                             buf.data(),
                             static_cast<int>(buf.size()));
            if (n <= 0)
            {
                int err = SSL_get_error(ssl, n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                    continue;
                break;
            }

            /* (1) server can short-circuit to the destination client */
            if (maybe_forward(reinterpret_cast<BYTE*>(buf.data()),
                              static_cast<UINT>(n)))
                continue;

            /* (2) otherwise inject into local Wintun */
            std::lock_guard<std::mutex> lg(session_mutex);
            void* pkt = WintunAllocateSendPacket(session,
                                                 static_cast<UINT>(n));
            if (!pkt) break;

            std::memcpy(pkt, buf.data(), n);
            WintunSendPacket(session, pkt, static_cast<UINT>(n));
        }
        else if (tag == PACKET_TYPE_MSG)
        {
            char msg_buf[1024]{};
            int  n = SSL_read(ssl, msg_buf,
                              static_cast<int>(sizeof(msg_buf) - 1));
            if (n > 0)
            {
                msg_buf[n] = '\0';
                std::cout << "[📨] Message from peer: "
                          << msg_buf << '\n';

                if (std::string_view(msg_buf) == "/quit")
                {
                    std::cout << "[!] Peer requested disconnect. "
                                 "Closing session.\n";
                    break;
                }
            }
        }
    }
}
