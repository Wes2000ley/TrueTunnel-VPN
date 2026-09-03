#pragma once

#include <string>
#include <cstdint>
#include <thread>
#include <atomic>
#include <mutex>
#include <functional>
#include <memory>

#include "TransportProtocol.h"
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
                   std::uint64_t real_adapter_luid,
                   secure::CipherSuite cipher,
                   TransportProtocol transport) override;

        bool send_message(const std::string& text) override;


        void stop() override;
        bool is_running() const override;

        void set_log_callback(std::function<void(const std::string&)> cb) override;


private:
        struct StartupConfig {
                std::string mode;
                std::string server_ip;
                int port{0};
                std::string password;
                std::string adaptername;
                std::string public_ip;
                std::string real_adapter;
                std::uint64_t real_adapter_luid{0U};
                secure::CipherSuite cipher_suite{secure::CipherSuite::Aes256Gcm};
                TransportProtocol transport{TransportProtocol::Tcp};

                ~StartupConfig();
                StartupConfig() = default;
                StartupConfig(const StartupConfig&) = delete;
                StartupConfig& operator=(const StartupConfig&) = delete;
        };

        void vpn_thread_func(std::unique_ptr<StartupConfig> config);

        std::mutex lifecycle_mutex_;
        mutable std::mutex resource_mutex_;
        mutable std::mutex callback_mutex_;

	std::thread vpn_thread;
	std::atomic<bool> running;

	std::shared_ptr<VpnClient> client;
	std::shared_ptr<VpnServer> server;

        std::function<void(const std::string&)> log_callback;
};
