#ifndef VPNCONTROLLER_H
#define VPNCONTROLLER_H

#include <string>
#include <thread>
#include <functional>
#include <atomic>
#include <winsock2.h>
#include <openssl/ssl.h>

#include "vpn.hpp"


class VpnController {
public:
	VpnController();

	~VpnController();

	void send_manual_message(const std::string &message);

	bool start(const std::string &mode,
	           const std::string &server_ip,
	           int port,
	           const std::string &local_ip,
	           const std::string &gateway,
	           const std::string &password,
	           const std::string &adaptername,
	           const std::string &subnetmask,
	           const std::string &public_ip,
	           const std::string &real_adapter);


	void stop();

	bool is_running() const;

	void VpnController::cleanup_ssl_and_socket();

	void set_log_callback(std::function<void(const std::string &)> callback) {
		log_callback = std::move(callback);
	}

private:
	void vpn_thread_func();

	std::string mode;
	std::string server_ip;
	int port;
	std::string local_ip;
	std::string gateway;
	std::string password;
	std::string adaptername;
	std::string subnetmask;
	std::atomic<bool> running;
	std::thread vpn_thread;
	std::string public_ip;
	std::string real_adapter;

	WINTUN_ADAPTER_HANDLE wintun_adapter_ = nullptr;
	WINTUN_SESSION_HANDLE wintun_session_ = nullptr;


	SOCKET sock_;
	SOCKET listen_sock_ = INVALID_SOCKET;
	using SSLPtr = std::unique_ptr<SSL, decltype(&SSL_free)>;
	SSLPtr ssl_{nullptr, SSL_free};
	WINTUN_ADAPTER_HANDLE adapter_handle_ = nullptr;


	std::function<void(const std::string &)> log_callback;
};

#endif // VPNCONTROLLER_H
