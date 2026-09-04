/*
* TrueTunnel VPN - Secure Windows VPN tunnel
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
#include <cstdint>
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
#include <span>
#include <string_view>
#include <utility>


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

typedef WINTUN_ADAPTER_HANDLE (WINAPI *WINTUN_OPEN_ADAPTER_FUNC)(PCWSTR);

typedef WINTUN_SESSION_HANDLE (WINAPI *WINTUN_START_SESSION_FUNC)(WINTUN_ADAPTER_HANDLE, UINT32);

typedef void (WINAPI *WINTUN_END_SESSION_FUNC)(WINTUN_SESSION_HANDLE);

typedef void (WINAPI *WINTUN_CLOSE_ADAPTER_FUNC)(WINTUN_ADAPTER_HANDLE);

typedef void (WINAPI *WINTUN_GET_ADAPTER_LUID_FUNC)(WINTUN_ADAPTER_HANDLE, NET_LUID *);

typedef void * (WINAPI *WINTUN_ALLOCATE_SEND_PACKET_FUNC)(WINTUN_SESSION_HANDLE, UINT32);

typedef void (WINAPI *WINTUN_SEND_PACKET_FUNC)(WINTUN_SESSION_HANDLE, const BYTE *);

typedef void * (WINAPI *WINTUN_RECEIVE_PACKET_FUNC)(WINTUN_SESSION_HANDLE, UINT32 *);

typedef void (WINAPI *WINTUN_RELEASE_RECEIVE_PACKET_FUNC)(WINTUN_SESSION_HANDLE, void *);

// New: waitable read event for blocking receive
typedef HANDLE (WINAPI *WINTUN_GET_READ_WAIT_EVENT_FUNC)(WINTUN_SESSION_HANDLE);


// ─── Inline globals ───────────────────────────────────────────────────────────
// C++17 inline variables: exactly one definition, external linkage
inline HMODULE hWintun = nullptr;
inline WINTUN_CREATE_ADAPTER_FUNC WintunCreateAdapter = nullptr;
inline WINTUN_OPEN_ADAPTER_FUNC WintunOpenAdapter = nullptr;
inline WINTUN_START_SESSION_FUNC WintunStartSession = nullptr;
inline WINTUN_END_SESSION_FUNC WintunEndSession = nullptr;
inline WINTUN_CLOSE_ADAPTER_FUNC WintunCloseAdapter = nullptr;
inline WINTUN_GET_ADAPTER_LUID_FUNC WintunGetAdapterLUID = nullptr;
inline WINTUN_ALLOCATE_SEND_PACKET_FUNC WintunAllocateSendPacket = nullptr;
inline WINTUN_SEND_PACKET_FUNC WintunSendPacket = nullptr;
inline WINTUN_RECEIVE_PACKET_FUNC WintunReceivePacket = nullptr;
inline WINTUN_RELEASE_RECEIVE_PACKET_FUNC WintunReleaseReceivePacket = nullptr;
inline WINTUN_GET_READ_WAIT_EVENT_FUNC WintunGetReadWaitEvent = nullptr;

// ─── Load entry points ────────────────────────────────────────────────────────
void LoadWintun();

// Wintun accepts at most MAX_ADAPTER_NAME - 1 UTF-16 characters. TrueTunnel's
// command boundary intentionally permits only a smaller ASCII subset, so the
// byte and character counts are identical here.
constexpr std::size_t kMaximumWintunAdapterNameLength = 127U;

[[nodiscard]] std::string validate_wintun_adapter_name(std::string_view name);
[[nodiscard]] GUID derive_wintun_adapter_guid(std::string_view adapter_name);
[[nodiscard]] std::string format_guid(const GUID& guid);

// Owns both the adapter and an interprocess identity lock. Construction checks
// for an existing interface before Wintun can suffix/rename it, creates the
// adapter with a deterministic GUID, and verifies the actual Windows identity.
class WintunAdapterLease final {
public:
	explicit WintunAdapterLease(std::string_view adapter_name);
	~WintunAdapterLease();

	WintunAdapterLease(const WintunAdapterLease&) = delete;
	WintunAdapterLease& operator=(const WintunAdapterLease&) = delete;
	WintunAdapterLease(WintunAdapterLease&& other) noexcept;
	WintunAdapterLease& operator=(WintunAdapterLease&& other) noexcept;

	void Reset() noexcept;
	[[nodiscard]] WINTUN_ADAPTER_HANDLE get() const noexcept { return adapter_; }
	[[nodiscard]] const GUID& guid() const noexcept { return guid_; }
	[[nodiscard]] const NET_LUID& luid() const noexcept { return luid_; }
	[[nodiscard]] const std::string& name() const noexcept { return name_; }
	explicit operator bool() const noexcept { return adapter_ != nullptr; }

private:
	void move_from(WintunAdapterLease&& other) noexcept;

	HANDLE identity_mutex_ = nullptr;
	bool owns_identity_mutex_ = false;
	WINTUN_ADAPTER_HANDLE adapter_ = nullptr;
	GUID guid_{};
	NET_LUID luid_{};
	std::string name_;
};


enum vpn_packet_type : uint8_t;



constexpr uint8_t PACKET_TYPE_IP  = 0x01;
constexpr uint8_t PACKET_TYPE_MSG = 0x02;
constexpr uint8_t PACKET_TYPE_HEARTBEAT = 0x03;
constexpr uint8_t PACKET_TYPE_HEARTBEAT_ACK = 0x04;
constexpr std::size_t kHeartbeatControlPayloadSize = 16U;

struct HeartbeatControlFrame {
    std::uint64_t sequence{0U};
    std::uint32_t interval_ms{0U};
    std::uint32_t timeout_ms{0U};
};

[[nodiscard]] inline std::array<std::uint8_t, kHeartbeatControlPayloadSize>
encode_heartbeat_control_frame(const HeartbeatControlFrame frame) noexcept {
    std::array<std::uint8_t, kHeartbeatControlPayloadSize> bytes{};
    for (std::size_t index = 0U; index < 8U; ++index) {
        bytes[index] = static_cast<std::uint8_t>(
            frame.sequence >> ((7U - index) * 8U));
    }
    for (std::size_t index = 0U; index < 4U; ++index) {
        bytes[8U + index] = static_cast<std::uint8_t>(
            frame.interval_ms >> ((3U - index) * 8U));
        bytes[12U + index] = static_cast<std::uint8_t>(
            frame.timeout_ms >> ((3U - index) * 8U));
    }
    return bytes;
}

[[nodiscard]] inline bool decode_heartbeat_control_frame(
    const std::span<const std::uint8_t> bytes,
    HeartbeatControlFrame& frame) noexcept {
    if (bytes.size() != kHeartbeatControlPayloadSize) return false;
    frame = {};
    for (std::size_t index = 0U; index < 8U; ++index) {
        frame.sequence = (frame.sequence << 8U) | bytes[index];
    }
    for (std::size_t index = 8U; index < 12U; ++index) {
        frame.interval_ms = (frame.interval_ms << 8U) | bytes[index];
    }
    for (std::size_t index = 12U; index < bytes.size(); ++index) {
        frame.timeout_ms = (frame.timeout_ms << 8U) | bytes[index];
    }
    return frame.sequence != 0U && frame.interval_ms != 0U &&
           frame.timeout_ms != 0U;
}

// Leave room for the longest textual IPv4 sender plus the protocol delimiter
// so a relayed chat record fits every supported transport and the receive
// buffer. Keeping one bound for TCP and UDP prevents an oversized TCP message
// from desynchronizing or terminating an otherwise healthy client.
constexpr std::size_t kMaximumChatMessageSize =
    secure::kMaximumDatagramPayloadSize - 16U;

inline bool is_well_formed_ipv4_packet(const BYTE* packet,
                                       const std::size_t packet_size) noexcept {
    if (packet == nullptr || packet_size < 20U ||
        packet_size > secure::kMaximumDatagramPayloadSize ||
        (packet[0] >> 4U) != 4U) {
        return false;
    }
    const std::size_t header_size =
        static_cast<std::size_t>(packet[0] & 0x0FU) * 4U;
    const std::size_t declared_size =
        (static_cast<std::size_t>(packet[2]) << 8U) |
        static_cast<std::size_t>(packet[3]);
    return header_size >= 20U && header_size <= packet_size &&
           declared_size == packet_size;
}

// The authenticated transport identifies the peer, while the IPv4 header is
// still caller-controlled. Keep the source-identity check byte-exact and
// independent of host byte order before a server routes or injects a packet.
inline bool ipv4_source_matches(const BYTE* packet,
                                const std::size_t packet_size,
                                const IN_ADDR& expected_source) noexcept {
    if (!is_well_formed_ipv4_packet(packet, packet_size)) {
        return false;
    }

    const auto* expected_bytes =
        reinterpret_cast<const BYTE*>(&expected_source);
    return packet[12] == expected_bytes[0] &&
           packet[13] == expected_bytes[1] &&
           packet[14] == expected_bytes[2] &&
           packet[15] == expected_bytes[3];
}

inline bool ipv4_source_matches(const BYTE* packet,
                                const std::size_t packet_size,
                                const std::string& expected_src_ip) noexcept {
    IN_ADDR expected_source{};
    return ::InetPtonA(AF_INET, expected_src_ip.c_str(), &expected_source) == 1 &&
           ipv4_source_matches(packet, packet_size, expected_source);
}


//— Packet pumps
void tun_to_tls(WINTUN_SESSION_HANDLE session,
                secure::SecureSocket* tls,
                std::atomic<bool>& running,
                HANDLE cancellation_event = nullptr);

void tls_to_tun(WINTUN_SESSION_HANDLE session, secure::SecureSocket* tls, std::atomic<bool> &running, std::mutex &session_mutex) ;

void send_message(secure::SecureSocket* tls, const std::string &msg);

template<typename ForwardFn, typename MessageFn, typename ControlFn>
// ─── single header / translation-unit ─────────────────────────────────────────
inline void tls_to_tun_common(WINTUN_SESSION_HANDLE session,
                              secure::SecureSocket* tls,
                              std::atomic<bool>&    running,
                              std::mutex&           session_mutex,
                              ForwardFn&&           maybe_forward,
                              MessageFn&&           on_message,
                              ControlFn&&           on_control)
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
            const auto packet_size = static_cast<std::size_t>(n);
            if (!is_well_formed_ipv4_packet(buf.data(), packet_size)) {
                std::cerr << "[secure_to_tun] rejected malformed IPv4 packet\n";
                continue;
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
            WintunSendPacket(session, static_cast<const BYTE*>(pkt));
        }
        else if (tag == PACKET_TYPE_MSG)
        {
            int n = r;
            if (n > 0 && n < (int)buf.size())
            {
                on_message(std::string_view(reinterpret_cast<char*>(buf.data()), n));
            }
        }
        else if (!on_control(
                     tag,
                     std::span<const std::uint8_t>{
                         buf.data(), static_cast<std::size_t>(r)}))
        {
            std::cerr << "[secure_to_tun] rejected unknown or malformed control record\n";
            break;
        }
    }

    running = false;
}
