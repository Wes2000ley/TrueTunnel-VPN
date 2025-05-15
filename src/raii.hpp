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
        if (FAILED(hr)) {
            throw std::runtime_error("CoInitializeEx failed");
        }
    }
    ~ComInit() {
        CoUninitialize();
    }
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
    explicit ModuleGuard(HMODULE module) : module_(module) {}
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
    explicit SocketGuard(SOCKET s = INVALID_SOCKET) : sock_(s) {}
    ~SocketGuard() {
        if (sock_ != INVALID_SOCKET) {
            closesocket(sock_); // just close, don't bother shutdown
            sock_ = INVALID_SOCKET;
        }
    }
    SOCKET get() const { return sock_; }
    SOCKET release() { SOCKET old = sock_; sock_ = INVALID_SOCKET; return old; }
private:
    SOCKET sock_;
};

// ─────────────────────────────────────────────────────────────────────────────
// Wintun Session Guard (RAII for WINTUN_SESSION_HANDLE)
class WintunSessionGuard {
public:
    explicit WintunSessionGuard(WINTUN_SESSION_HANDLE session) : session_(session) {}
    ~WintunSessionGuard() {
        if (session_) {
            WintunEndSession(session_);
        }
    }
    WINTUN_SESSION_HANDLE get() const { return session_; }
private:
    WINTUN_SESSION_HANDLE session_;
};

// ─────────────────────────────────────────────────────────────────────────────
// Wintun Adapter Guard (RAII for WINTUN_ADAPTER_HANDLE)
class WintunAdapterGuard {
public:
    explicit WintunAdapterGuard(WINTUN_ADAPTER_HANDLE adapter) : adapter_(adapter) {}
    ~WintunAdapterGuard() {
        if (adapter_) {
            WintunCloseAdapter(adapter_);
        }
    }
    WINTUN_ADAPTER_HANDLE get() const { return adapter_; }
private:
    WINTUN_ADAPTER_HANDLE adapter_;
};

// ─────────────────────────────────────────────────────────────────────────────
// OpenSSL SSL_CTX Smart Pointer
struct SSL_CTX_Deleter {
    void operator()(SSL_CTX* ctx) const {
        if (ctx) SSL_CTX_free(ctx);
    }
};
using SSL_CTX_ptr = std::unique_ptr<SSL_CTX, SSL_CTX_Deleter>;

// OpenSSL SSL Smart Pointer
struct SSL_Deleter {
    void operator()(SSL* ssl) const {
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
        : ptr_(static_cast<T*>(OPENSSL_secure_malloc(sizeof(T) * count))), size_(sizeof(T) * count) {
        if (!ptr_) {
            throw std::runtime_error("OPENSSL_secure_malloc failed");
        }
    }
    ~OpenSSLSecurePtr() {
        if (ptr_) {
            OPENSSL_secure_clear_free(ptr_, size_);
        }
    }
    T* get() const { return ptr_; }
    T* operator->() const { return ptr_; }
    T& operator*() const { return *ptr_; }
    operator T*() const { return ptr_; }
private:
    T* ptr_;
    std::size_t size_;
};
struct HmacCtxDeleter {
    void operator()(HMAC_CTX* ctx) const {
        if (ctx) HMAC_CTX_free(ctx);
    }
};
using HMAC_CTX_ptr = std::unique_ptr<HMAC_CTX, HmacCtxDeleter>;


#endif // TRUE_TUNNEL_RAII_HPP
