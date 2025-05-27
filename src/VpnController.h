#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <functional>

class VpnServer;
class VpnClient;

class VpnController {
public:
	VpnController();
	~VpnController();

	bool start(std::string m, std::string s_ip, int p, std::string l_ip,
							  std::string g, std::string pw, std::string a_name,
							  std::string mask, std::string pub_ip, std::string real_ad);


	void stop();
	bool is_running() const;

	std::function<void(const std::string&)> log_callback;
	void set_log_callback(std::function<void(const std::string&)> cb);


private:
	void vpn_thread_func();

	std::string mode;
	std::thread vpn_thread;
	std::atomic<bool> running;

	// user-provided fields
	std::string server_ip;
	int port;
	std::string local_ip;
	std::string gateway;
	std::string password;
	std::string adaptername;
	std::string subnetmask;
	std::string public_ip;
	std::string real_adapter;

	std::unique_ptr<VpnClient> client;
	std::unique_ptr<VpnServer> server;
};
