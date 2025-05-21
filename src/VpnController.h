#ifndef VPNCONTROLLER_H
#define VPNCONTROLLER_H

#include <string>
#include <thread>
#include <functional>
#include <atomic>
#include <mutex>
#include <winsock2.h>
#include <openssl/ssl.h>

#include "vpn.hpp"


class VpnController {
public:
	VpnController();

	~VpnController();
	void cleanup_ssl_and_socket();

	void send_manual_message(const std::string &message);

	bool start(std::string mode,
			   std::string server_ip,
			   int port,
			   std::string local_ip,
			   std::string gateway,
			   std::string password,
			   std::string adaptername,
			   std::string subnetmask,
			   std::string public_ip,
			   std::string real_adapter);


	void stop();

	bool is_running() const;


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

	mutable std::mutex ssl_io_mutex;


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
