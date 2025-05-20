#include "VpnController.h"
#include "vpn.hpp"
#include "utils.hpp"
#include "redirect_stream.hpp"
#include "raii.hpp"


#include <iostream>
#include <filesystem>
#include <ppltasks.h>
#include <stdexcept>
#include <thread>
#include <chrono>>   //for using the function sleep
#include <iphlpapi.h>
#include <regex>


#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/provider.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>


#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "iphlpapi.lib")


// Sleeps for the specified number of milliseconds.
void SleepForMilliseconds(int milliseconds) {
	std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

VpnController::VpnController() : port(0), running(false), sock_(0) {
}

VpnController::~VpnController() {
	stop();
}

std::mutex ssl_sock_mutex;

bool VpnController::start(const std::string &mode, const std::string &server_ip, int port,
                          const std::string &local_ip, const std::string &gateway, const std::string &password,
                          const std::string &adaptername, const std::string &subnetmask,
                          const std::string &public_ip, const std::string &real_adapter) {
	if (running) return false;

	this->mode = mode;
	this->server_ip = server_ip; // UNUSED!!!
	this->port = port;
	this->local_ip = local_ip;
	this->gateway = gateway;
	this->password = password;
	this->adaptername = adaptername;
	this->subnetmask = subnetmask;
	this->public_ip = public_ip;
	this->real_adapter = real_adapter;

	running = true;
	vpn_thread = std::thread(&VpnController::vpn_thread_func, this);
	return true;
}

void VpnController::send_manual_message(const std::string &message) {
	std::lock_guard<std::mutex> lock(ssl_sock_mutex);

	if (ssl_ && running) {
		uint8_t packet_type = PACKET_TYPE_MSG;
		if (SSL_write(ssl_.get(), &packet_type, 1) <= 0 ||
		    SSL_write(ssl_.get(), message.c_str(), static_cast<int>(message.size())) <= 0) {
			if (log_callback) {
				log_callback("[!] Failed to send message over ssl");
			}
		}
	}
}


void VpnController::stop() {
	if (running) {
		running = false; {
			std::lock_guard<std::mutex> lock(ssl_sock_mutex);
			if (ssl_) {
				SSL_shutdown(ssl_.get());
				ssl_.reset(); // ✅ safe cleanup
			}
			if (sock_ != INVALID_SOCKET) {
				shutdown(sock_, SD_BOTH);
				closesocket(sock_);
				sock_ = INVALID_SOCKET;
			}
			if (listen_sock_ != INVALID_SOCKET) {
				shutdown(listen_sock_, SD_BOTH);
				closesocket(listen_sock_);
				listen_sock_ = INVALID_SOCKET;
			}
		}
		if (vpn_thread.joinable()) vpn_thread.join();
	}

	// Delete route
	std::string cmd_delete_route = "route delete 10.10.100.0 mask 255.255.255.252 10.10.100.1";
	std::string cmd_delete_route2 = "route delete 10.10.100.0 mask 255.255.255.252 10.10.100.2";


	// Reset IP address (optional)
	std::string cmd_reset_ip = "netsh interface ipv4 set address name=\"" + adaptername + "\" dhcp";

	// Remove MTU override (optional but cleaner)
	std::string cmd_clear_mtu = "netsh interface ipv4 set subinterface \"" + adaptername +
	                            "\" mtu=1500 store=persistent";

	run_command_hidden(cmd_delete_route);
	run_command_hidden(cmd_delete_route2);
	run_command_hidden(cmd_reset_ip);
	run_command_hidden(cmd_clear_mtu);

	if (mode == "server") {
		std::cout << "[*] Removing NAT rules\n";
		std::string cmd_nat_pub = "netsh routing ip nat delete interface \"" + real_adapter + "\"";
		std::string cmd_nat_priv = "netsh routing ip nat delete interface \"" + adaptername + "\"";

		run_command_hidden(cmd_nat_pub);
		run_command_hidden(cmd_nat_priv);
	} else {
		std::cout << "[*] Removing public IP route protection\n";
		std::string cmd_remove_protect = "route delete " + public_ip + " >nul 2>&1";
		run_command_hidden(cmd_remove_protect);
	}
}

void VpnController::cleanup_ssl_and_socket() {
	std::lock_guard<std::mutex> lock(ssl_sock_mutex);
	if (ssl_) {
		SSL_shutdown(ssl_.get());
		ssl_.reset();
	}
	if (sock_ != INVALID_SOCKET) {
		shutdown(sock_, SD_BOTH);
		closesocket(sock_);
		sock_ = INVALID_SOCKET;
	}
}

bool VpnController::is_running() const {
	return running;
}

void VpnController::vpn_thread_func() {
	dual_redirect_stream cout_redirect([this](const std::string &msg) {
		if (log_callback) {
			log_callback(msg);
		}
	});

	std::string exe_dir = std::filesystem::current_path().string();

	std::cout << "VPN thread started\n";
	util::logInfo("TLS handshake (expected later)");

	try {
		if (!is_running_as_admin()) {
			throw std::runtime_error("Administrator privileges required.");
		}

		const bool is_server = (mode == "server");

		std::cout << "TrueTunnel VPN v1.0.0\n"
				<< "Copyright (c) 2025 Wesley Atwell\n"
				<< "Licensed under MIT or GPLv2 — See LICENSE\n\n";

		ComInit com;
		WsaInit wsa;
		std::cout << "[*] Loading Wintun driver...\n";
		LoadWintun();
		std::cout << "[✓] Wintun driver loaded\n";

		// Create adapter
		GUID guid;
		CHECK(CoCreateGuid(&guid) == S_OK, "CoCreateGuid failed");

		std::wstring wname(adaptername.begin(), adaptername.end());
		std::cout << "[*] Creating Wintun adapter: " << adaptername << "\n";

		WINTUN_ADAPTER_HANDLE raw = WintunCreateAdapter(wname.c_str(), L"Wintun", &guid);
		CHECK(raw != nullptr, "WintunCreateAdapter failed");

		WintunAdapterGuard adapter(raw);
		std::cout << "[✓] Wintun adapter created\n";

		// use `adapter.get()` as needed (e.g., WintunStartSession)


		if (is_server) {
			gateway = "10.10.100.2";
			local_ip = "10.10.100.1";
			subnetmask = "255.255.255.252";
		} else {
			gateway = "10.10.100.1";
			local_ip = "10.10.100.2";
			subnetmask = "255.255.255.252";
		}

		adaptername = sanitize_shell_string(adaptername);
		real_adapter = sanitize_shell_string(real_adapter);
		gateway = sanitize_ip(gateway);
		public_ip = sanitize_ip(public_ip);


		// Configure adapter (silent netsh)
		{
			SetStaticIPv4Address(adaptername, local_ip, subnetmask);


			std::string cmd1 = "netsh interface ipv4 add route prefix=10.10.100.0/30 "
			                   "interface=\"" + adaptername + "\" nexthop=" + gateway +
			                   " metric=1 store=persistent";

			std::string cmd2 = "netsh interface ipv4 set subinterface \"" + adaptername +
			                   "\" mtu=1380 store=persistent";


			std::cout << "[CMD] " << cmd1 << "\n"
					<< "[CMD] " << cmd2 << "\n";

			bool rc1 = run_command_hidden(cmd1);
			bool rc2 = run_command_hidden(cmd2);


			std::cout << "[✓] Adapter configuration complete\n";
		}


		std::cout << "[*] Starting Wintun session...\n";
		WintunSessionGuard session(WintunStartSession(adapter.get(), 0x400000)); // 4MB ring
		CHECK(session.get(), "WintunStartSession failed");
		std::cout << "[✓] Wintun session started\n";


		// Openssl setup
		std::cout << "[*] Initializing Openssl FIPS providers...\n";

		_putenv(("OPENssl_CONF=" + exe_dir + "\\openssl.cnf").c_str());
		_putenv(("OPENssl_MODULES=" + exe_dir).c_str());
		OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, nullptr);

		CHECK(OSSL_PROVIDER_load(nullptr, "fips"), "load FIPS provider");
		CHECK(OSSL_PROVIDER_load(nullptr, "base"), "load base provider");
		CHECK(EVP_default_properties_enable_fips(nullptr, 1) == 1, "enable FIPS");


		if (!EVP_default_properties_is_fips_enabled(nullptr)) {
			ERR_print_errors_fp(stderr);
			throw std::runtime_error("FIPS mode is not enabled");
		}
		std::cout << "[✓] Openssl FIPS mode enabled\n";


		std::cout << "[*] Creating TCP socket...\n";

		// 1. Create raw socket
		auto temp_sock = INVALID_SOCKET;
		SSLPtr temp_ssl(nullptr, SSL_free);
		try {
			SOCKET raw_sock = socket(AF_INET, SOCK_STREAM, 0);
			CHECK(raw_sock != INVALID_SOCKET, "socket failed");
			SocketGuard sock(raw_sock);
			std::cout << "[✓] TCP socket created\n";

			// 2. Set SO_REUSEADDR
			int reuse = 1;
			setsockopt(sock.get(), SOL_SOCKET, SO_REUSEADDR, (const char *) &reuse, sizeof(reuse));

			// ✅ 2.5 Disable Nagle's Algorithm to reduce latency on small packets
			int flag = 1;
			setsockopt(sock.get(), IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(flag));

			// 3. Prepare address
			sockaddr_in addr{};
			addr.sin_family = AF_INET;
			addr.sin_port = htons(port);
			if (is_server) {
				std::string bind_ip = get_ipv4_for_adapter(real_adapter);
				if (bind_ip.empty()) {
					throw std::runtime_error("Could not find IP for adapter: " + real_adapter);
				}
				inet_pton(AF_INET, bind_ip.c_str(), &addr.sin_addr);
			} else {
				std::string local_bind_ip = get_ipv4_for_adapter(real_adapter);
				if (local_bind_ip.empty()) {
					throw std::runtime_error("Could not find IP for adapter: " + real_adapter);
				}

				sockaddr_in bind_addr{};
				bind_addr.sin_family = AF_INET;
				bind_addr.sin_port = 0; // 0 = let OS choose ephemeral port
				inet_pton(AF_INET, local_bind_ip.c_str(), &bind_addr.sin_addr);

				// ✅ Bind to the chosen adapter's IP
				CHECK(bind(sock.get(), (sockaddr*)&bind_addr, sizeof(bind_addr)) != SOCKET_ERROR, "client bind failed");

				// THEN connect to server
				inet_pton(AF_INET, public_ip.c_str(), &addr.sin_addr);
			}
			listen_sock_ = sock.get();

			run_command_admin(
				"Get-NetConnectionProfile | "
				"Where-Object {$_.InterfaceAlias -eq '" + adaptername + "'} | "
				"Set-NetConnectionProfile -NetworkCategory Private"
			);


			AddICMPv4Rule();


			// 4. Bind/listen/accept or connect
			if (is_server) {
				std::cout << "[*] Binding socket...\n";
				CHECK(bind(sock.get(), (sockaddr*)&addr, sizeof(addr)) != SOCKET_ERROR, "bind failed");

				std::cout << "[*] Listening...\n";
				CHECK(listen(sock.get(), 1) != SOCKET_ERROR, "listen failed");

				std::cout << "[*] Waiting for incoming TCP connection...\n";
				auto client = INVALID_SOCKET;
				while (running && (client = accept(sock.get(), nullptr, nullptr)) == INVALID_SOCKET) {
					int err = WSAGetLastError();
					if (!running || err == WSAEINTR || err == WSAENOTSOCK || err == WSAEINVAL) {
						std::cerr << "[!] connect() aborted or invalid socket\n";
						sock.reset(); // RAII-safe cleanup
						return;
					}
					std::this_thread::sleep_for(std::chrono::milliseconds(100)); // backoff
				}
				if (!running) return;

				closesocket(sock.get()); // Close the listening socket
				sock.reset(client); // ✅ Proper way to assign a new SOCKET to a SocketGuard
				std::cout << "[✓] Client connected\n";
			} else {
				std::cout << "[*] Connecting to " << public_ip << ":" << port << "...\n";
				while (connect(sock.get(), (sockaddr *) &addr, sizeof(addr)) == SOCKET_ERROR) {
					int err = WSAGetLastError();
					if (!running || err == WSAEINTR || err == WSAENOTSOCK || err == WSAEINVAL) {
						std::cerr << "[!] connect() aborted or invalid socket\n";
						closesocket(sock.get());
						return;
					}
					std::this_thread::sleep_for(std::chrono::milliseconds(5000));
					std::cout << "[!] Connection failed, retrying...\n";
				}

				std::cout << "[✓] Connected to server\n";
			}

			// 5. Create ssl_CTX
			using SslCtxPtr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
			SslCtxPtr ctx(make_ssl_ctx(is_server), SSL_CTX_free);


			// 6. Create ssl and bind to socket
			SSLPtr ssl(SSL_new(ctx.get()), SSL_free);
			CHECK(ssl != nullptr, "ssl_new failed");
			CHECK(SSL_set_fd(ssl.get(), static_cast<int>(sock.get())) == 1, "ssl_set_fd failed");


			// 7. Perform TLS handshake
			if (is_server) {
				CHECK(SSL_accept(ssl.get()) > 0, "ssl_accept failed");
			} else {
				CHECK(SSL_connect(ssl.get()) > 0, "ssl_connect failed");
			}

			std::cout << "✅ TLS handshake done\n";
			temp_sock = sock.release(); // ✅ Prevent SocketGuard from closing it
			temp_ssl = std::move(ssl); // ✅ Move SSL out
		} catch (const std::exception &ex) {
			std::cerr << "[!] Exception: " << ex.what() << "\n";
			cleanup_ssl_and_socket();
			running = false;
			return;
		}
		// 8. Store ssl and socket
		// Now outside the sock scope
		{
			std::lock_guard<std::mutex> lock(ssl_sock_mutex);
			sock_ = temp_sock;
			ssl_ = std::move(temp_ssl);
		}


		constexpr size_t NONCE_SIZE = 16;
		constexpr size_t HMAC_DATA_SIZE = 32;
		constexpr size_t MAX_HMAC_SIZE = EVP_MAX_MD_SIZE;
		constexpr size_t MAX_PASSWORD_SIZE = 128;

		// 1) Generate our nonce - use secure memory
		OpenSSLSecurePtr<unsigned char> my_nonce(NONCE_SIZE);
		OpenSSLSecurePtr<unsigned char> peer_nonce(NONCE_SIZE);
		CHECK(my_nonce && peer_nonce, "Secure malloc failed");
		CHECK(RAND_bytes(my_nonce.get(), NONCE_SIZE) == 1, "RAND_bytes failed");

		// 2) Exchange nonces
		if (is_server) {
			SSL_read(ssl_.get(), peer_nonce.get(), NONCE_SIZE); // client first
			SSL_write(ssl_.get(), my_nonce.get(), NONCE_SIZE); // then server
		} else {
			SSL_write(ssl_.get(), my_nonce.get(), NONCE_SIZE); // client first
			SSL_read(ssl_.get(), peer_nonce.get(), NONCE_SIZE); // then server
		}

		// 3) Build the data buffer (client||server) in secure memory
		OpenSSLSecurePtr<unsigned char> data(HMAC_DATA_SIZE);
		CHECK(data, "Secure malloc failed");
		if (is_server) {
			memcpy(data.get(), peer_nonce.get(), NONCE_SIZE);
			memcpy(data.get() + NONCE_SIZE, my_nonce.get(), NONCE_SIZE);
		} else {
			memcpy(data.get(), my_nonce.get(), NONCE_SIZE);
			memcpy(data.get() + NONCE_SIZE, peer_nonce.get(), NONCE_SIZE);
		}

		// 4) Compute the HMAC-SHA256 over that buffer using password
		OpenSSLSecurePtr<unsigned char> my_hmac(MAX_HMAC_SIZE);
		CHECK(my_hmac, "Secure malloc failed");
		unsigned int hlen;
		HMAC_CTX_ptr hctx(HMAC_CTX_new());
		CHECK(hctx, "HMAC_CTX_new");
		CHECK(HMAC_Init_ex(hctx.get(),
			      (unsigned char*)password.data(),
			      password.size(),
			      EVP_sha256(),
			      nullptr) == 1, "HMAC_Init");
		CHECK(HMAC_Update(hctx.get(), data.get(), HMAC_DATA_SIZE) == 1, "HMAC_Update");
		CHECK(HMAC_Final(hctx.get(), my_hmac.get(), &hlen) == 1, "HMAC_Final");

		// 5) Exchange HMACs
		SSL_write(ssl_.get(), my_hmac.get(), hlen);
		OpenSSLSecurePtr<unsigned char> peer_hmac(MAX_HMAC_SIZE);
		CHECK(peer_hmac, "Secure malloc failed");
		SSL_read(ssl_.get(), peer_hmac.get(), hlen);

		// 6) Compare in constant time
		int result = CRYPTO_memcmp(my_hmac.get(), peer_hmac.get(), hlen);

		if (result != 0) {
			throw std::runtime_error("Post-handshake HMAC verification failed");
		}

		// Log cipher & TLS version
		const char *version = SSL_get_version(ssl_.get());
		const char *cipher = SSL_get_cipher(ssl_.get());
		std::cout << "[🔒] TLS version: " << version
				<< ", cipher: " << cipher << "\n\n";

		// Shared‐secret check
		if (is_server) {
			// server reads
			char pwbuf[MAX_PASSWORD_SIZE] = {0};
			int pwlen = SSL_read(ssl_.get(), pwbuf, sizeof(pwbuf) - 1);
			CHECK(pwlen > 0, "ssl_read failed");
			if (password != std::string(pwbuf, pwlen)) {
				std::cerr << "[!] Authentication failed\n";
				cleanup_ssl_and_socket();
				return;
			}

			std::cout << "[✔] Client authenticated\n\n";
		} else {
			// client writes
			CHECK(SSL_write(ssl_.get(), password.c_str(),
				      (int)password.size()) > 0, "Failed to send password");
			std::cout << "[✔] Password sent\n\n";
		}

		std::cout << "\nType your message and press send.\nType /quit to exit.\n\n";


		std::thread message_input_thread([this]() {
			std::string input;
			while (running.load()) {
				if (!std::getline(std::cin, input)) break;
				if (input == "/quit") {
					send_manual_message("/quit");
					running = false;
					break;
				}
				if (!input.empty()) {
					send_manual_message(input);
					std::cout << "[You] " << input << "\n";
				}
			}
		});

		SSL *raw_ssl = ssl_.get();
		WINTUN_SESSION_HANDLE raw_session = session.get();
		std::thread t1(tun_to_tls, raw_session, raw_ssl, std::ref(running));
		std::thread t2(tls_to_tun, raw_session, raw_ssl, std::ref(running));
		t1.join();
		t2.join();
		message_input_thread.join();
	} catch (const std::exception &ex) {
		std::cerr << "[!] Exception: " << ex.what() << "\n";
		cleanup_ssl_and_socket();
		running = false;
	}
	running = false;
}
