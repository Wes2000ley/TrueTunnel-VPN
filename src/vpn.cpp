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
	});
}


void tun_to_tls(WINTUN_SESSION_HANDLE session, secure::SecureSocket* tls, std::atomic<bool> &running) {
	std::cout << "[tun_to_tls] Started packet forwarding thread\n";

	while (running) {
		UINT32 size = 0;
		void *pkt = WintunReceivePacket(session, &size);
		if (!pkt) {
			Sleep(1);
			continue;
		}

	//	std::cout << "[tun_to_tls] Captured packet of size " << size << "\n";

		tls->send_record(PACKET_TYPE_IP, (const uint8_t*)pkt, (uint16_t)size);


		WintunReleaseReceivePacket(session, pkt);
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
