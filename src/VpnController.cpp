#include "VpnController.h"
#include "vpn.hpp"
#include "utils.hpp"
#include "redirect_stream.hpp"
#include "raii.hpp"


#include <iostream>
#include <filesystem>
#include <stdexcept>
#include <thread>

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

#include "raii.hpp"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "iphlpapi.lib")

VpnController::VpnController() : running(false) {
}

VpnController::~VpnController() {
	stop();
}

std::mutex ssl_sock_mutex;

bool VpnController::start(const std::string &mode, const std::string &server_ip, int port,
                          const std::string &local_ip, const std::string &gateway, const std::string &password,
                          const std::string &adaptername, const std::string &subnetmask) {
	if (running) return false;

	this->mode = mode;
	this->server_ip = server_ip;
	this->port = port;
	this->local_ip = local_ip;
	this->gateway = gateway;
	this->password = password;
	this->adaptername = adaptername;
	this->subnetmask = subnetmask;

	running = true;
	vpn_thread = std::thread(&VpnController::vpn_thread_func, this);
	return true;
}

void VpnController::send_manual_message(const std::string& message) {
	std::lock_guard<std::mutex> lock(ssl_sock_mutex);

	if (ssl_ && running) {
	    uint8_t packet_type = PACKET_TYPE_MSG;
	    if (SSL_write(ssl_, &packet_type, 1) <= 0 ||
	        SSL_write(ssl_, message.c_str(), static_cast<int>(message.size())) <= 0) {
	        if (log_callback) {
	            log_callback("[!] Failed to send message over SSL");
	        }
	    }
	}
}



void VpnController::stop() {
	if (running) {
		running = false; {
			std::lock_guard<std::mutex> lock(ssl_sock_mutex);
			if (ssl_) {
				SSL_shutdown(ssl_);
				SSL_free(ssl_);
				ssl_ = nullptr;
			}
			if (sock_ != INVALID_SOCKET) {
				shutdown(sock_, SD_BOTH);
				closesocket(sock_);
				sock_ = INVALID_SOCKET;
			}
		}
		if (vpn_thread.joinable()) vpn_thread.join();
	}
}

bool VpnController::is_running() const {
	return running;
}

void VpnController::vpn_thread_func() {
    dual_redirect_stream cout_redirect([this](const std::string& msg) {
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
        ModuleGuard wintun(LoadLibraryW(L"wintun.dll"));
    	std::cout << "[*] Loading Wintun driver...\n";
    	LoadWintun();
    	std::cout << "[✓] Wintun driver loaded\n";

        // Create adapter
        GUID guid;
        CHECK(CoCreateGuid(&guid) == S_OK, "CoCreateGuid failed");
        std::wstring wname(adaptername.begin(), adaptername.end());
    	std::cout << "[*] Creating Wintun adapter: " << adaptername << "\n";
    	auto adapter = WintunCreateAdapter(wname.c_str(), L"Wintun", &guid);
    	if (!adapter) {
    		DWORD err = GetLastError();
    		throw std::runtime_error("WintunCreateAdapter failed, error code: " + std::to_string(err));
    	}
    	std::cout << "[✓] Wintun adapter created\n";


        // Configure adapter (silent netsh)
        {
            std::string cmd0 = "netsh interface ipv4 set address name=\"" + adaptername +
                               "\" static " + local_ip + " " + subnetmask + " " + gateway + " 1 store=persistent";
            std::string cmd1 = "netsh interface ipv4 add route prefix=0.0.0.0/0 "
                               "interface=\"" + adaptername + "\" nexthop=" + gateway +
                               " metric=1 store=persistent";
            std::string cmd2 = "netsh interface ipv4 set subinterface \"" + adaptername +
                               "\" mtu=1380 store=persistent";

            std::cout << "[CMD] " << cmd0 << "\n"
                      << "[CMD] " << cmd1 << "\n"
                      << "[CMD] " << cmd2 << "\n";

            bool rc0 = run_command_hidden(cmd0);
            bool rc1 = run_command_hidden(cmd1);
            bool rc2 = run_command_hidden(cmd2);

        	std::cout << "[✓] Adapter configuration complete\n";

        }

    	std::cout << "[*] Starting Wintun session...\n";
    	WintunSessionGuard session(WintunStartSession(adapter, 0x400000)); // 4MB ring
    	CHECK(session.get(), "WintunStartSession failed");
    	std::cout << "[✓] Wintun session started\n";



        // OpenSSL setup
    	std::cout << "[*] Initializing OpenSSL FIPS providers...\n";

        _putenv(("OPENSSL_CONF=" + exe_dir + "\\openssl.cnf").c_str());
        _putenv(("OPENSSL_MODULES=" + exe_dir).c_str());
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, nullptr);

        CHECK(OSSL_PROVIDER_load(nullptr, "fips"), "load FIPS provider");
        CHECK(OSSL_PROVIDER_load(nullptr, "base"), "load base provider");
        CHECK(EVP_default_properties_enable_fips(nullptr, 1) == 1, "enable FIPS");


        if (!EVP_default_properties_is_fips_enabled(nullptr)) {
            ERR_print_errors_fp(stderr);
            throw std::runtime_error("FIPS mode is not enabled");
        }
    	std::cout << "[✓] OpenSSL FIPS mode enabled\n";


    	std::cout << "[*] Creating TCP socket...\n";

    	// 1. Create raw socket
    	SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    	CHECK(sock != INVALID_SOCKET, "socket failed");
    	std::cout << "[✓] TCP socket created\n";

    	// 2. Set SO_REUSEADDR
    	int reuse = 1;
    	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    	// 3. Prepare address
    	sockaddr_in addr{};
    	addr.sin_family = AF_INET;
    	addr.sin_port = htons(port);
    	addr.sin_addr.s_addr = is_server ? INADDR_ANY : inet_addr(server_ip.c_str());

    	// 4. Bind/listen/accept or connect
    	if (is_server) {
    		std::cout << "[*] Binding socket...\n";
    		CHECK(bind(sock, (sockaddr*)&addr, sizeof(addr)) != SOCKET_ERROR, "bind failed");

    		std::cout << "[*] Listening...\n";
    		CHECK(listen(sock, 1) != SOCKET_ERROR, "listen failed");

    		std::cout << "[*] Waiting for incoming TCP connection...\n";
    		SOCKET client = accept(sock, nullptr, nullptr);
    		CHECK(client != INVALID_SOCKET, "accept failed");

    		closesocket(sock); // Close the listening socket
    		sock = client;     // Use the accepted client socket
    		std::cout << "[✓] Client connected\n";
    	} else {
    		std::cout << "[*] Connecting to " << server_ip << ":" << port << "...\n";
    		CHECK(connect(sock, (sockaddr*)&addr, sizeof(addr)) != SOCKET_ERROR, "connect failed");
    		std::cout << "[✓] Connected to server\n";
    	}

    	// 5. Create SSL_CTX
    	SSL_CTX* ctx = make_ssl_ctx(is_server);

    	// 6. Create SSL and bind to socket
    	SSL* ssl = SSL_new(ctx);
    	CHECK(ssl != nullptr, "SSL_new failed");
    	CHECK(SSL_set_fd(ssl, static_cast<int>(sock)) == 1, "SSL_set_fd failed");

    	// 7. Perform TLS handshake
    	if (is_server) {
    		CHECK(SSL_accept(ssl) > 0, "SSL_accept failed");
    	} else {
    		CHECK(SSL_connect(ssl) > 0, "SSL_connect failed");
    	}

    	std::cout << "✅ TLS handshake done\n";

    	// 8. Store SSL and socket
	    {
        	std::lock_guard<std::mutex> lock(ssl_sock_mutex);
        	sock_ = sock;
        	ssl_ = ssl;
	    }



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

			// 4) Compute the HMAC-SHA256 over that buffer using password
			unsigned char *my_hmac = (unsigned char *) OPENSSL_secure_malloc(EVP_MAX_MD_SIZE);
			CHECK(my_hmac, "Secure malloc failed");
			unsigned int hlen;
			HMAC_CTX *hctx = HMAC_CTX_new();
			CHECK(hctx, "HMAC_CTX_new");
			CHECK(HMAC_Init_ex(hctx,
				      (unsigned char*)password.data(),
				      password.size(),
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
				if (password != std::string(pwbuf, pwlen)) {
					std::cerr << "[!] Authentication failed\n";
					SSL_shutdown(ssl);
					SSL_free(ssl);
					closesocket(sock);
				}
				std::cout << "[✔] Client authenticated\n\n";
			} else {
				// client writes
				CHECK(SSL_write(ssl, password.c_str(),
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

        std::thread t1(tun_to_tls, session.get(), ssl_, std::ref(running));
        std::thread t2(tls_to_tun, session.get(), ssl_, std::ref(running));

        t1.join();
        t2.join();
        message_input_thread.join();

    } catch (const std::exception& ex) {
        std::cerr << "[!] Exception: " << ex.what() << "\n";
        running = false;
    }
}
