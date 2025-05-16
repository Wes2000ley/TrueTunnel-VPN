#ifndef VPNCONTROLLER_H
#define VPNCONTROLLER_H

#include <string>
#include <thread>
#include <functional>
#include <atomic>
#include <winsock2.h>
#include <openssl/ssl.h>

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

	SOCKET sock_;
	SSL *ssl_;

	std::function<void(const std::string &)> log_callback;
};

#endif // VPNCONTROLLER_H
