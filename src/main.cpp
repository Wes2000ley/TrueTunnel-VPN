// ──────────────────────────────────────────────────────────────
//	Mini TLS‑over‑Wintun VPN
// ──────────────────────────────────────────────────────────────
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <objbase.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <EASTL/vector.h>
#include "vpn.hpp"

#include <iostream>
#include <filesystem>
#include <thread>
#include <stdexcept>
#include <string>
#include <functional>		  //  ← ask() validator
#include "include/cxxopts.hpp"
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

int main(int argc, char *argv[]) {
	// Check for admin privileges first
	if (!is_running_as_admin()) {
		std::cerr << "[!] This program must be run as Administrator.\n";
		return 1;
	}

	try {
		/*───────────────────────────────────────────────────────────
		  1. Command‑line ─ use cxxopts   (vpn --help  for details)
		───────────────────────────────────────────────────────────*/
		cxxopts::Options opts("vpn", "Mini Wintun VPN");
		opts.add_options()
				("m,mode", "server | client", cxxopts::value<std::string>())
				("s,server-ip", "server IPv4 (client‑only)", cxxopts::value<std::string>())
				("p,port", "TCP port", cxxopts::value<int>()->default_value("5555"))
				("l,local-ip", "local adapter IPv4", cxxopts::value<std::string>())
				("mask", "subnet mask", cxxopts::value<std::string>()->default_value("255.255.255.0"))
				("a,adapter", "Wintun adapter name", cxxopts::value<std::string>()->default_value("MyVPN"))
				("g,gateway", "gateway IPv4", cxxopts::value<std::string>())
				("P,password", "shared pass‑phrase (min 12 chars)", cxxopts::value<std::string>())
				("h,help", "show this help");

		auto r = opts.parse(argc, argv);
		if (r.count("help")) {
			std::cout << opts.help() << "\n";
			return 0;
		}

		std::string mode = r.count("mode") ? r["mode"].as<std::string>() : "";
		std::string server_ip = r.count("server-ip") ? r["server-ip"].as<std::string>() : "";
		int port = r["port"].as<int>(); // has default_value
		std::string local_ip = r.count("local-ip") ? r["local-ip"].as<std::string>() : "";
		std::string mask = r["mask"].as<std::string>(); // has default_value
		std::string adaptername = r["adapter"].as<std::string>(); // has default_value
		std::string gateway = r.count("gateway") ? r["gateway"].as<std::string>() : "";
		std::string shared_pass = r.count("password") ? r["password"].as<std::string>() : "";

		/*───────────────────────────────────────────────────────────
		  2. Interactive fall‑back  (ask() only touches empty vars)
		───────────────────────────────────────────────────────────*/
		util::ask("Mode (server / client)", mode,
		    [](auto &v) { return v == "server" || v == "client"; });
		bool is_server = (mode == "server");

		if (!is_server)
			util::ask("Server IP", server_ip, util::looksLikeIp);

		util::ask("Local adapter IP", local_ip, util::looksLikeIp);
		util::ask("Gateway IP", gateway, util::looksLikeIp);
		util::ask("Shared password (min 12 chars)", shared_pass,
		    [](auto &s) { return !s.empty() && s.length() >= 12; });

		/*───────────────────────────────────────────────────────────
		  3. Echo config summary
		───────────────────────────────────────────────────────────*/
		std::cout << "\n";
		util::logInfo("Configuration");
		std::cout << "   mode	  = " << mode << "\n"
				<< "   port	  = " << port << "\n"
				<< "   adapter   = " << adaptername << "\n"
				<< "   local IP  = " << local_ip << "\n"
				<< "   gateway   = " << gateway << "\n";
		if (!is_server)
			std::cout << "   server IP = " << server_ip << "\n";
		std::cout << "-------------------------------------------\n";

		try {
			// 2) Load Wintun + COM
			LoadWintun();
			CHECK(CoInitializeEx(nullptr, COINIT_MULTITHREADED)==S_OK,
				  "CoInitializeEx failed");

			// 3) Create adapter (wide‐string)
			GUID guid;
			CHECK(CoCreateGuid(&guid) == S_OK, "CoCreateGuid failed");
			std::wstring wname(adaptername.begin(), adaptername.end());
			auto adapter = WintunCreateAdapter(wname.c_str(), L"Wintun", &guid);
			CHECK(adapter, "WintunCreateAdapter failed");

			// 4) Configure it with netsh
			{
				std::string cmd0 =
					"netsh interface ipv4 set address name=\"" + adaptername +
					"\" static " + local_ip + " " + mask + " " + gateway + " 1 store=persistent";

				std::string cmd1 =
					"netsh interface ipv4 add route prefix=0.0.0.0/0 "
					"interface=\"" + adaptername + "\" nexthop=" + gateway +
					" metric=1 store=persistent";

				std::string cmd2 =
					"netsh interface ipv4 set subinterface \"" + adaptername + "\" mtu=1380 store=persistent";

				std::cout << "[CMD] " << cmd0 << "\n"
						  << "[CMD] " << cmd1 << "\n"
						  << "[CMD] " << cmd2 << "\n"
						  << "Press Enter to run these…";
				std::cin.get();

				int rc0 = system(cmd0.c_str());
				int rc1 = system(cmd1.c_str());
				int rc2 = system(cmd2.c_str());

				if (rc1 != 0) {
					std::cerr << "[!] Warning: default route may already exist (code "
							  << rc1 << ")\n";
				}
				if (rc2 != 0) {
					std::cerr << "[!] Warning: MTU setting may have failed (code "
							  << rc2 << ")\n";
				}
			}


			// 5) Start session
			constexpr UINT32 RING_CAP = 0x400000;
			auto session = WintunStartSession(adapter, RING_CAP);
			CHECK(session, "WintunStartSession failed");

// 6) TLS + socket
			// Determine paths
			std::string exe_dir = std::filesystem::path(argv[0]).parent_path().string();
			std::string config_path = exe_dir + "\\fipsmodule.cnf";

			// Set environment so OpenSSL can find fips.dll
			_putenv(("OPENSSL_CONF=" + exe_dir + "\\openssl.cnf").c_str());
			_putenv(("OPENSSL_MODULES=" + exe_dir).c_str());

			// NOW initialize OpenSSL (after config is loaded)
			OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, nullptr);


			// Load FIPS provider first
			OSSL_PROVIDER *fips = OSSL_PROVIDER_load(nullptr, "fips");
			if (!fips) {
				ERR_print_errors_fp(stderr);
				CHECK(false, "Failed to load FIPS provider");
			}

			/* Option A – load “base” provider (3.1+) */
			OSSL_PROVIDER *base = OSSL_PROVIDER_load(nullptr, "base");
			CHECK(base, "Failed to load base provider");          // << new line

			/* Lock the *process* into FIPS-only mode (covers any future sub-contexts) */
			CHECK(EVP_default_properties_enable_fips(nullptr, 1) == 1,
				  "enable FIPS");

			// Enable FIPS mode
			if (EVP_default_properties_enable_fips(nullptr, 1) != 1) {
				ERR_print_errors_fp(stderr);
				CHECK(false, "Failed to enable FIPS mode");
			}

			// Verify FIPS mode is active
			if (!EVP_default_properties_is_fips_enabled(nullptr)) {
				ERR_print_errors_fp(stderr);
				CHECK(false, "FIPS mode is not enabled");
				CHECK(true, "FIPS mode is enabled");
			}

			// Initialize Winsock
			WSADATA ws;
			CHECK(WSAStartup(MAKEWORD(2,2), &ws)==0, "WSAStartup failed");
			// Create SSL context
			SSL_CTX *ctx = make_ssl_ctx(is_server);
			SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
			CHECK(sock != INVALID_SOCKET, "socket failed");

			int reuse = 1;
			setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *) &reuse, sizeof(reuse));

			sockaddr_in addr{};
			addr.sin_family = AF_INET;
			addr.sin_port = htons(port);
			addr.sin_addr.s_addr = is_server
									   ? INADDR_ANY
									   : inet_addr(server_ip.c_str());

			if (is_server) {
				CHECK(bind(sock,(sockaddr*)&addr,sizeof(addr)) != SOCKET_ERROR, "bind failed");
				CHECK(listen(sock,1) != SOCKET_ERROR, "listen failed");
				std::cout << "[*] Waiting for client on port " << port << "…\n";
				SOCKET client = accept(sock, nullptr, nullptr);
				CHECK(client != INVALID_SOCKET, "accept failed");
				closesocket(sock);
				sock = client;
			} else {
				std::cout << "[*] Connecting to " << server_ip << ":" << port << "…\n";
				CHECK(connect(sock,(sockaddr*)&addr,sizeof(addr)) != SOCKET_ERROR, "connect failed");
			}

// TLS handshake
			SSL *ssl = SSL_new(ctx);
			CHECK(ssl != nullptr, "SSL_new failed");
			CHECK(SSL_set_fd(ssl, (int)sock) == 1, "SSL_set_fd failed");

			if (is_server)
				CHECK(SSL_accept(ssl)>0, "SSL_accept failed");
			else
				CHECK(SSL_connect(ssl)>0, "SSL_connect failed");
			std::cout << "✅ TLS handshake done\n";

			// 1) Generate our nonce - use secure memory
			unsigned char *my_nonce = (unsigned char *) OPENSSL_secure_malloc(16);
			unsigned char *peer_nonce = (unsigned char *) OPENSSL_secure_malloc(16);
			CHECK(my_nonce && peer_nonce, "Secure malloc failed");
			CHECK(RAND_bytes(my_nonce, 16) == 1, "RAND_bytes failed");

			// 2) Exchange nonces
			if (is_server) {
				SSL_read(ssl, peer_nonce, 16); // client first
				SSL_write(ssl, my_nonce, 16); // then server
			} else {
				SSL_write(ssl, my_nonce, 16); // client first
				SSL_read(ssl, peer_nonce, 16); // then server
			}

			// 3) Build the data buffer (client||server) in secure memory
			unsigned char *data = (unsigned char *) OPENSSL_secure_malloc(32);
			CHECK(data, "Secure malloc failed");
			if (is_server) {
				memcpy(data, peer_nonce, 16);
				memcpy(data + 16, my_nonce, 16);
			} else {
				memcpy(data, my_nonce, 16);
				memcpy(data + 16, peer_nonce, 16);
			}

			// 4) Compute the HMAC-SHA256 over that buffer using shared_pass
			unsigned char *my_hmac = (unsigned char *) OPENSSL_secure_malloc(EVP_MAX_MD_SIZE);
			CHECK(my_hmac, "Secure malloc failed");
			unsigned int hlen;
			HMAC_CTX *hctx = HMAC_CTX_new();
			CHECK(hctx, "HMAC_CTX_new");
			CHECK(HMAC_Init_ex(hctx,
				      (unsigned char*)shared_pass.data(),
				      shared_pass.size(),
				      EVP_sha256(),
				      nullptr) == 1, "HMAC_Init");
			CHECK(HMAC_Update(hctx, data, 32) == 1, "HMAC_Update");
			CHECK(HMAC_Final(hctx, my_hmac, &hlen) == 1, "HMAC_Final");
			HMAC_CTX_free(hctx);

			// 5) Exchange HMACs
			SSL_write(ssl, my_hmac, hlen);
			unsigned char *peer_hmac = (unsigned char *) OPENSSL_secure_malloc(EVP_MAX_MD_SIZE);
			CHECK(peer_hmac, "Secure malloc failed");
			SSL_read(ssl, peer_hmac, hlen);

			// 6) Compare in constant time and cleanup
			int result = CRYPTO_memcmp(my_hmac, peer_hmac, hlen);

			// Secure cleanup
			OPENSSL_secure_clear_free(my_nonce, 16);
			OPENSSL_secure_clear_free(peer_nonce, 16);
			OPENSSL_secure_clear_free(data, 32);
			OPENSSL_secure_clear_free(my_hmac, EVP_MAX_MD_SIZE);
			OPENSSL_secure_clear_free(peer_hmac, EVP_MAX_MD_SIZE);

			if (result != 0) {
				throw std::runtime_error("Post-handshake HMAC verification failed");
			}


			// Log cipher & TLS version
			const char *version = SSL_get_version(ssl);
			const char *cipher = SSL_get_cipher(ssl);
			std::cout << "[🔒] TLS version: " << version
					<< ", cipher: " << cipher << "\n\n";

			// Shared‐secret check
			if (is_server) {
				// server reads
				char pwbuf[128] = {0};
				int pwlen = SSL_read(ssl, pwbuf, sizeof(pwbuf) - 1);
				CHECK(pwlen > 0, "SSL_read failed");
				if (shared_pass != std::string(pwbuf, pwlen)) {
					std::cerr << "[!] Authentication failed\n";
					SSL_shutdown(ssl);
					SSL_free(ssl);
					closesocket(sock);
					return 1;
				}
				std::cout << "[✔] Client authenticated\n\n";
			} else {
				// client writes
				CHECK(SSL_write(ssl, shared_pass.c_str(),
					      (int)shared_pass.size()) > 0, "Failed to send password");
				std::cout << "[✔] Password sent\n\n";
			}

			// Start interactive message input thread
			std::thread message_input_thread([ssl]() {
				std::string input;
				while (true) {
					std::cout << "[Type a message or /quit] > ";
					std::getline(std::cin, input);
					if (input == "/quit") break;
					if (!input.empty()) {
						send_message(ssl, input);
					}
				}
			});

			// Packet pump threads
			std::thread t1(tun_to_tls, session, ssl);
			std::thread t2(tls_to_tun, session, ssl);
			t1.join();
			t2.join();
			message_input_thread.join();


			// Cleanup
			SSL_shutdown(ssl);
			SSL_free(ssl);
			closesocket(sock);
			SSL_CTX_free(ctx);
			WSACleanup();
			WintunEndSession(session);
			WintunCloseAdapter(adapter);
			FreeLibrary(hWintun);
			CoUninitialize();
			return 0;
		} catch (...) {
			throw; // Re-throw to outer catch
		}
	} catch (const std::exception &ex) {
		std::cerr << "[!] " << ex.what() << "\n";
		return 1;
	}
}
