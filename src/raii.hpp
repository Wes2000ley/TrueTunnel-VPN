#ifndef TRUE_TUNNEL_RAII_HPP
#define TRUE_TUNNEL_RAII_HPP

#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdexcept>
#include <memory>

#include "vpn.hpp"

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
// Wintun Adapter Guard (RAII wrapper for WINTUN_ADAPTER_HANDLE)
class WintunAdapterGuard {
public:
	explicit WintunAdapterGuard(WINTUN_ADAPTER_HANDLE adapter) : adapter_(adapter) {}

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





#endif // TRUE_TUNNEL_RAII_HPP
