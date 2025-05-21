#ifndef TRUE_TUNNEL_RAII_HPP
#define TRUE_TUNNEL_RAII_HPP

#include <windows.h>
#include <winsock2.h>
#include <stdexcept>
#include <memory>
#include <openssl/ssl.h>

// ─────────────────────────────────────────────────────────────────────────────
// COM Initialization Guard (RAII for CoInitializeEx / CoUninitialize)
class ComInit {
public:
	ComInit() {
		HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
		already_initialized_ = (hr == RPC_E_CHANGED_MODE);
		if (FAILED(hr) && !already_initialized_) {
			throw std::runtime_error("CoInitializeEx failed");
		}
	}

	~ComInit() {
		if (!already_initialized_) {
			CoUninitialize();
		}
	}

private:
	bool already_initialized_ = false;
};


// ─────────────────────────────────────────────────────────────────────────────
// WSA Startup Guard (RAII for WSAStartup / WSACleanup)
class WsaInit {
public:
	WsaInit() {
		WSADATA wsaData;
		if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
			throw std::runtime_error("WSAStartup failed");
		}
	}

	~WsaInit() {
		WSACleanup();
	}
};

// ─────────────────────────────────────────────────────────────────────────────
// Dynamic Library Guard (RAII for LoadLibrary / FreeLibrary)
class ModuleGuard {
public:
	explicit ModuleGuard(HMODULE module) : module_(module) {
	}

	~ModuleGuard() {
		if (module_) {
			FreeLibrary(module_);
		}
	}

private:
	HMODULE module_;
};

// ─────────────────────────────────────────────────────────────────────────────
// WinSock Socket Guard (RAII for SOCKET / closesocket)
class SocketGuard {
public:
	explicit SocketGuard(SOCKET s = INVALID_SOCKET) : sock_(s) {
	}

	~SocketGuard() {
		if (sock_ != INVALID_SOCKET) {
			std::cerr << "[RAII] Closing socket " << sock_ << "\n";
			shutdown(sock_, SD_BOTH);
			closesocket(sock_);
		}
	}

	SocketGuard(const SocketGuard &) = delete;

	SocketGuard &operator=(const SocketGuard &) = delete;

	SocketGuard(SocketGuard &&other) noexcept : sock_(other.sock_) {
		other.sock_ = INVALID_SOCKET;
	}

	SocketGuard &operator=(SocketGuard &&other) noexcept {
		if (this != &other) {
			reset(other.sock_);
			other.sock_ = INVALID_SOCKET;
		}
		return *this;
	}

	SOCKET get() const { return sock_; }

	void reset(SOCKET s = INVALID_SOCKET) {
		if (sock_ != INVALID_SOCKET) {
			shutdown(sock_, SD_BOTH);
			closesocket(sock_);
		}
		sock_ = s;
	}

	SOCKET release() {
		SOCKET s = sock_;
		sock_ = INVALID_SOCKET;
		return s;
	}

private:
	SOCKET sock_;
};


// ─────────────────────────────────────────────────────────────────────────────
// Wintun Session Guard (RAII for WINTUN_SESSION_HANDLE)
class WintunSessionGuard {
public:
	explicit WintunSessionGuard(WINTUN_SESSION_HANDLE session) : session_(session) {
	}

	~WintunSessionGuard() {
		if (session_) {
			WintunEndSession(session_);
		}
	}

	WINTUN_SESSION_HANDLE get() const { return session_; }

private:
	WINTUN_SESSION_HANDLE session_;
};


// Wintun Adapter Guard (RAII wrapper for WINTUN_ADAPTER_HANDLE)
class WintunAdapterGuard {
public:
	explicit WintunAdapterGuard(WINTUN_ADAPTER_HANDLE adapter) : adapter_(adapter) {
	}

	// Disallow copy
	WintunAdapterGuard(const WintunAdapterGuard &) = delete;

	WintunAdapterGuard &operator=(const WintunAdapterGuard &) = delete;

	// Allow move
	WintunAdapterGuard(WintunAdapterGuard &&other) noexcept : adapter_(other.adapter_) {
		other.adapter_ = nullptr;
	}

	WintunAdapterGuard &operator=(WintunAdapterGuard &&other) noexcept {
		if (this != &other) {
			Reset();
			adapter_ = other.adapter_;
			other.adapter_ = nullptr;
		}
		return *this;
	}

	~WintunAdapterGuard() { Reset(); }

	void Reset() {
		if (adapter_) {
			WintunCloseAdapter(adapter_);
			adapter_ = nullptr;
		}
	}

	WINTUN_ADAPTER_HANDLE get() const { return adapter_; }
	explicit operator bool() const { return adapter_ != nullptr; }

private:
	WINTUN_ADAPTER_HANDLE adapter_ = nullptr;
};

// ─────────────────────────────────────────────────────────────────────────────
// OpenSSL SSL_CTX Smart Pointer
struct SSL_CTX_Deleter {
	void operator()(SSL_CTX *ctx) const {
		if (ctx) SSL_CTX_free(ctx);
	}
};

using SSL_CTX_ptr = std::unique_ptr<SSL_CTX, SSL_CTX_Deleter>;

// OpenSSL SSL Smart Pointer
struct SSL_Deleter {
	void operator()(SSL *ssl) const {
		if (ssl) SSL_free(ssl);
	}
};

using SSL_ptr = std::unique_ptr<SSL, SSL_Deleter>;

// ─────────────────────────────────────────────────────────────────────────────
// OpenSSL Secure Memory Smart Pointer
template<typename T>
class OpenSSLSecurePtr {
public:
	explicit OpenSSLSecurePtr(std::size_t count)
		: ptr_(static_cast<T *>(OPENSSL_secure_malloc(sizeof(T) * count))), size_(sizeof(T) * count) {
		if (!ptr_) {
			throw std::runtime_error("OPENSSL_secure_malloc failed");
		}
	}

	~OpenSSLSecurePtr() {
		if (ptr_) {
			OPENSSL_secure_clear_free(ptr_, size_);
		}
	}

	T *get() const { return ptr_; }
	T *operator->() const { return ptr_; }
	T &operator*() const { return *ptr_; }
	operator T *() const { return ptr_; }

private:
	T *ptr_;
	std::size_t size_;
};


class HmacCtx {
public:
	HmacCtx(const EVP_MD* md, const unsigned char* key, size_t key_len) {
		EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
		if (!mac) throw std::runtime_error("Failed to fetch HMAC");

		ctx = EVP_MAC_CTX_new(mac);
		EVP_MAC_free(mac); // safe after context creation

		if (!ctx) throw std::runtime_error("Failed to create HMAC context");

		const char* digest_name = EVP_MD_get0_name(md);
		if (!digest_name) throw std::runtime_error("Invalid digest");

		OSSL_PARAM params[] = {
			OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>(digest_name), 0),
			OSSL_PARAM_END
		};

		if (EVP_MAC_init(ctx, key, key_len, params) != 1)
			throw std::runtime_error("Failed to initialize HMAC");
	}

	std::vector<unsigned char> compute(const unsigned char* data, size_t len) {
		if (!ctx) throw std::runtime_error("HMAC context not initialized");

		std::vector<unsigned char> result(EVP_MAX_MD_SIZE);
		size_t out_len = 0;

		if (EVP_MAC_update(ctx, data, len) != 1)
			throw std::runtime_error("HMAC update failed");

		if (EVP_MAC_final(ctx, result.data(), &out_len, result.size()) != 1)
			throw std::runtime_error("HMAC final failed");

		result.resize(out_len);
		return result;
	}

	~HmacCtx() {
		if (ctx) EVP_MAC_CTX_free(ctx);
	}

	HmacCtx(const HmacCtx&) = delete;
	HmacCtx& operator=(const HmacCtx&) = delete;

private:
	EVP_MAC_CTX* ctx = nullptr;
};





#endif // TRUE_TUNNEL_RAII_HPP
