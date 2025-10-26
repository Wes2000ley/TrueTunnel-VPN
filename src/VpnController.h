#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <functional>
#include <memory>

#include "core/IVpnController.h"
#include "secure/CipherSuite.h"

class VpnServer;
class VpnClient;

class VpnController : public IVpnController {
public:
        VpnController();
        ~VpnController();

        bool start(std::string m, std::string s_ip, int p, std::string l_ip,
                   std::string g, std::string pw, std::string a_name,
                   std::string mask, std::string pub_ip, std::string real_ad,
                   secure::CipherSuite cipher) override;


        void stop() override;
        bool is_running() const override;

        void set_log_callback(std::function<void(const std::string&)> cb) override;


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
        secure::CipherSuite cipher_suite{secure::CipherSuite::Aes256Gcm};

        std::unique_ptr<VpnClient> client;
        std::unique_ptr<VpnServer> server;

        std::function<void(const std::string&)> log_callback;
};
