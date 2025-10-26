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
#include <string_view>


#include <windows.h>

#include "secure/SecureSocket.h"



#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"iphlpapi.lib")

class VpnServer;


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

// New: waitable read event for blocking receive
typedef HANDLE (WINAPI *WINTUN_GET_READ_WAIT_EVENT_FUNC)(WINTUN_SESSION_HANDLE);


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
inline WINTUN_GET_READ_WAIT_EVENT_FUNC WintunGetReadWaitEvent = nullptr;

// ─── Load entry points ────────────────────────────────────────────────────────
void LoadWintun();


enum vpn_packet_type : uint8_t;



constexpr uint8_t PACKET_TYPE_IP  = 0x01;
constexpr uint8_t PACKET_TYPE_MSG = 0x02;


//— Packet pumps
void tun_to_tls(WINTUN_SESSION_HANDLE session, secure::SecureSocket* tls, std::atomic<bool> &running);

void tls_to_tun(WINTUN_SESSION_HANDLE session, secure::SecureSocket* tls, std::atomic<bool> &running, std::mutex &session_mutex) ;

void send_message(secure::SecureSocket* tls, const std::string &msg);

template<typename ForwardFn, typename MessageFn>
// ─── single header / translation-unit ─────────────────────────────────────────
inline void tls_to_tun_common(WINTUN_SESSION_HANDLE session,
                              secure::SecureSocket* tls,
                              std::atomic<bool>&    running,
                              std::mutex&           session_mutex,
                              ForwardFn&&           maybe_forward,
                              MessageFn&&           on_message)   // ← perfect-fwd
{
    // elevate this data-plane thread
    ::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

    thread_local std::array<uint8_t, 1600> buf;          // re-usable RX buffer

    while (running)
    {
        uint8_t tag{};
        int r = tls->recv_record(tag, buf.data(), (uint16_t)buf.size());
        if (r <= 0) break;                                      // connection closed / error

        if (tag == PACKET_TYPE_IP)
        {
            int n = r;
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
            int n = r;
            if (n > 0 && n < (int)buf.size())
            {
                on_message(std::string_view(reinterpret_cast<char*>(buf.data()), n));
            }
        }
    }
}
