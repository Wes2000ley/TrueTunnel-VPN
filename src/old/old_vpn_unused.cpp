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

#include <iostream>
#include <filesystem>
#include <thread>
#include <stdexcept>
#include <string>
#include <functional>		  //  ← ask() validator
#include "../include/cxxopts.hpp"
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

//— Wintun ABI typedefs
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

//— Pointers to Wintun functions
static HMODULE hWintun = nullptr;
static WINTUN_CREATE_ADAPTER_FUNC WintunCreateAdapter = nullptr;
static WINTUN_START_SESSION_FUNC WintunStartSession = nullptr;
static WINTUN_END_SESSION_FUNC WintunEndSession = nullptr;
static WINTUN_CLOSE_ADAPTER_FUNC WintunCloseAdapter = nullptr;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC WintunAllocateSendPacket = nullptr;
static WINTUN_SEND_PACKET_FUNC WintunSendPacket = nullptr;
static WINTUN_RECEIVE_PACKET_FUNC WintunReceivePacket = nullptr;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC WintunReleaseReceivePacket = nullptr;

//— Dynamically load Wintun entry points
static void LoadWintun() {
	hWintun = ::LoadLibraryW(L"wintun.dll");
	CHECK(hWintun, "LoadLibrary(wintun.dll) failed");

	WintunCreateAdapter = (WINTUN_CREATE_ADAPTER_FUNC)
			::GetProcAddress(hWintun, "WintunCreateAdapter");
	WintunStartSession = (WINTUN_START_SESSION_FUNC)
			::GetProcAddress(hWintun, "WintunStartSession");
	WintunEndSession = (WINTUN_END_SESSION_FUNC)
			::GetProcAddress(hWintun, "WintunEndSession");
	WintunCloseAdapter = (WINTUN_CLOSE_ADAPTER_FUNC)
			::GetProcAddress(hWintun, "WintunCloseAdapter");
	WintunAllocateSendPacket = (WINTUN_ALLOCATE_SEND_PACKET_FUNC)
			::GetProcAddress(hWintun, "WintunAllocateSendPacket");
	WintunSendPacket = (WINTUN_SEND_PACKET_FUNC)
			::GetProcAddress(hWintun, "WintunSendPacket");
	WintunReceivePacket = (WINTUN_RECEIVE_PACKET_FUNC)
			::GetProcAddress(hWintun, "WintunReceivePacket");
	WintunReleaseReceivePacket = (WINTUN_RELEASE_RECEIVE_PACKET_FUNC)
			::GetProcAddress(hWintun, "WintunReleaseReceivePacket");

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


// ─── pretty logging helpers ───────────────────────────────────
namespace util {
	void logInfo(const std::string &s) { std::cout << bold << green << "[INFO] " << reset << s << "\n"; }
	void logWarn(const std::string &s) { std::cout << bold << yellow << "[WARN] " << reset << s << "\n"; }
	void logErr(const std::string &s) { std::cerr << bold << red << "[ERR ] " << reset << s << "\n"; }

	bool looksLikeIp(const std::string &v) {
		in_addr a{};
		return inet_pton(AF_INET, v.c_str(), &a) == 1;
	}

	void ask(const char *prompt, std::string &val,
	         std::function<bool(const std::string &)> ok = nullptr) {
		if (!val.empty()) return;
		for (;;) {
			std::cout << prompt << ": ";
			std::getline(std::cin, val);
			if (!ok || ok(val)) break;
			logWarn("Invalid value, try again");
			val.clear();
		}
	}
} // namespace

bool is_running_as_admin()
{
	BOOL is_admin = FALSE;
	PSID admin_group = nullptr;
	SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;

	if (AllocateAndInitializeSid(&nt_authority, 2,
								 SECURITY_BUILTIN_DOMAIN_RID,
								 DOMAIN_ALIAS_RID_ADMINS,
								 0, 0, 0, 0, 0, 0, &admin_group))
	{
		CheckTokenMembership(nullptr, admin_group, &is_admin);
		FreeSid(admin_group);
	}

	return is_admin;
}


// ─── FIPS–compliant key + certificate helpers ──────────────────────────
static EVP_PKEY *generate_fips_rsa_key()
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

static X509 *generate_self_signed_cert(EVP_PKEY *pkey,
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
static SSL_CTX *make_ssl_ctx(bool is_server)
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

enum vpn_packet_type : uint8_t {
	PACKET_TYPE_IP = 0x00,
	PACKET_TYPE_MSG = 0x01
};


//— Packet pumps
static void tun_to_tls(WINTUN_SESSION_HANDLE session, SSL *ssl) {
	while (true) {
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

static void tls_to_tun(WINTUN_SESSION_HANDLE session, SSL *ssl) {
	char buf[1600];
	while (true) {
		int8_t pkt_type = 0;
		if (SSL_read(ssl, (char *) &pkt_type, 1) <= 0) break;

		if (pkt_type == PACKET_TYPE_IP) {
			int n = SSL_read(ssl, buf, sizeof(buf));
			if (n <= 0) break;
			void *pkt = WintunAllocateSendPacket(session, (UINT32) n);
			if (!pkt) break;
			memcpy(pkt, buf, n);
			WintunSendPacket(session, pkt, (UINT32) n);
		} else if (pkt_type == PACKET_TYPE_MSG) {
			char msg_buf[1024] = {};
			int n = SSL_read(ssl, msg_buf, sizeof(msg_buf) - 1);
			if (n > 0) {
				std::cout << "[📨] Message from peer: " << msg_buf << "\n";
			}
		}
	}
}

void send_message(SSL *ssl, const std::string &msg) {
	uint8_t type = PACKET_TYPE_MSG;
	SSL_write(ssl, &type, 1);
	SSL_write(ssl, msg.c_str(), static_cast<int>(msg.size()));
}



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
		logInfo("Configuration");
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
