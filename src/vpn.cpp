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
#include "VpnController.h"
#include "Networking.h"

#include <iostream>
#include <filesystem>
#include <thread>
#include <stdexcept>
#include <string>
#include <functional>		  //  ← ask() validator
#include <mutex>


#include <mmsystem.h>     // timeBeginPeriod/timeEndPeriod
#pragma comment(lib, "winmm.lib")


#include "secure/SecureSocket.h"

#include <ppltasks.h>

#include <regex>



#include "raii.hpp"

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"iphlpapi.lib")


#define CHECK(cond,msg)  do{ if(!(cond)) throw std::runtime_error(msg);}while(0)



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
		load_fn(WintunGetReadWaitEvent, "WintunGetReadWaitEvent");
	});
}


void tun_to_tls(WINTUN_SESSION_HANDLE session, secure::SecureSocket* tls, std::atomic<bool> &running) {
	std::cout << "[tun_to_tls] Started packet forwarding thread\n";

	// Raise priority for lower wake latency
	::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

	// Use Wintun read-wait event correctly (wait only when ring is empty)
	const HANDLE ev = WintunGetReadWaitEvent ? WintunGetReadWaitEvent(session) : nullptr;

	while (running) {
		// Drain all available packets
		for (;;) {
			UINT32 size = 0;
			BYTE *pkt = static_cast<BYTE*>(WintunReceivePacket(session, &size));
			if (!pkt) break;
			int rc = tls->send_record(PACKET_TYPE_IP, pkt, static_cast<uint16_t>(size));
			if (rc < 0) {
				std::cerr << "[tun_to_tls] send_record failed; stopping tunnel\n";
				running = false;
				WintunReleaseReceivePacket(session, pkt);
				break;
			}
			WintunReleaseReceivePacket(session, pkt);
		}
		if (!running) break;
		const DWORD err = ::GetLastError();
		if (err == ERROR_NO_MORE_ITEMS) {
			if (ev) {
				DWORD wait_rc = ::WaitForSingleObject(ev, INFINITE);
				if (wait_rc == WAIT_FAILED) {
					::Sleep(1);
				}
			} else {
				::Sleep(1);
			}
		} else if (err == ERROR_HANDLE_EOF) {
			break; // session ending
		} else {
			::Sleep(1); // transient/unknown
		}
	}
}


/*void tls_to_tun(WINTUN_SESSION_HANDLE session, SSL *ssl, std::atomic<bool> &running, std::mutex &session_mutex) {
	std::cout << "[tls_to_tun] Started packet receiving thread\n";
	char buf[1600] {};
	while (running) {
		uint8_t pkt_type = 0;
		{
			std::lock_guard<std::mutex> lock(ssl_read_mutex);
			if (SSL_read(ssl, &pkt_type, 1) <= 0) break;
		}

if (pkt_type == PACKET_TYPE_IP) {
	int n = 0; {
		std::lock_guard<std::mutex> lock(ssl_read_mutex);
		n = SSL_read(ssl, buf, sizeof(buf));
		if (n <= 0) {
			int err = SSL_get_error(ssl, n);
			if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
				continue;
			break;
		}
	}

	std::lock_guard<std::mutex> lock(session_mutex);  // ✅ protect Wintun write
			void *pkt = WintunAllocateSendPacket(session, (UINT32) n);
			if (!pkt) break;
			memcpy(pkt, buf, n);
		//	std::cout << "[tls_to_tun] Writing packet of size " << n << "\n";
			WintunSendPacket(session, pkt, (UINT32) n);

		} else if (pkt_type == PACKET_TYPE_MSG) {
			char msg_buf[1024] = {};
			int n = 0;
			{
				std::lock_guard<std::mutex> lock(ssl_read_mutex);
				n = SSL_read(ssl, msg_buf, sizeof(msg_buf) - 1);
			}
			if (n > 0) {
				msg_buf[n] = '\0';

				std::cout << "[📨] Message from peer: " << msg_buf << std::endl;

				if (std::string(msg_buf) == "/quit") {
					std::cout << "[!] Peer requested disconnect. Closing session.\n";
					break;
				}
			}
		}
	}
}*/




// void send_message(SSL *ssl, const std::string &msg) {
// std::lock_guard<std::mutex> lock(ssl_write_mutex);
// 	uint8_t packet_type = PACKET_TYPE_MSG;
// 	SSL_write(ssl, &packet_type, 1);
// 	SSL_write(ssl, msg.c_str(), static_cast<int>(msg.size()));
// }
