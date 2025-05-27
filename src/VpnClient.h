#pragma once

#include "raii.hpp"
#include "Networking.h"
#include <winsock2.h>
#include <openssl/ssl.h>
#include <string>
#include <memory>

class VpnClient {
public:
	VpnClient(const std::string& server_ip,
			  int port,
			  const std::string& password,
			  const std::string& adaptername,
			  const std::string& real_adapter,
			  const std::string& public_ip);

	~VpnClient();

	void start();
	void stop();



private:
	void connectToServer();
	void performHandshake();
	void requestConfig();
	void configureAdapter();
	void startPacketForwarding();
	void startInputLoop();

	std::string server_ip_;
	int port_;
	std::string password_;
	std::string adaptername_;
	std::string real_adapter_;
	std::string public_ip_;
	std::string local_ip_;
	std::string subnetmask_;
	std::string gateway_;

	SOCKET sock_ = INVALID_SOCKET;
	using SSLPtr = std::unique_ptr<SSL, decltype(&SSL_free)>;
	SSLPtr ssl_{nullptr, SSL_free};
	std::atomic<bool> running_ = false;
	std::optional<WintunAdapterGuard> adapter_;
	std::shared_ptr<WintunSessionGuard> session_;  // <-- use shared_ptr to manage ownership
	std::mutex session_mutex_;

	static void tls_to_tun_client(WINTUN_SESSION_HANDLE session,
	                              SSL*                  ssl,
	                              std::atomic<bool>&    running,
	                              std::mutex&           session_mutex)
	{
		auto noop = [](BYTE*, UINT) { return false; };
		tls_to_tun_common(session, ssl, running, session_mutex, noop);
	}
};
