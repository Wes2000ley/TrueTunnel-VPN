#pragma once

#include <string>
#include <cstdint>
#include <thread>
#include <atomic>
#include <mutex>
#include <functional>
#include <memory>
#include <condition_variable>

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
                   std::string mask, std::string real_ad,
                   std::uint64_t real_adapter_luid,
                   secure::CipherSuite cipher,
                   TransportProtocol transport,
                   ConnectionRecoveryOptions recovery = {}) override;

        bool send_message(const std::string& text) override;


        void stop() override;
        bool is_running() const override;
        [[nodiscard]] ConnectionStatus connection_status() const override;

        void set_log_callback(std::function<void(const std::string&)> cb) override;


private:
        struct StartupConfig {
                std::string mode;
                std::string server_ip;
                int port{0};
                std::string password;
                std::string adaptername;
                std::string real_adapter;
                std::uint64_t real_adapter_luid{0U};
                secure::CipherSuite cipher_suite{secure::CipherSuite::Aes256Gcm};
                TransportProtocol transport{TransportProtocol::Tcp};
                ConnectionRecoveryOptions recovery{};
                bool password_page_locked{false};

                ~StartupConfig();
                StartupConfig() = default;
                StartupConfig(const StartupConfig&) = delete;
                StartupConfig& operator=(const StartupConfig&) = delete;
                void lock_password_pages() noexcept;
                void clear_password() noexcept;
        };

        void vpn_thread_func(std::unique_ptr<StartupConfig> config);
        void set_connection_status(ConnectionPhase phase,
                                   std::uint32_t retry_attempt = 0U,
                                   std::chrono::milliseconds retry_delay =
                                       std::chrono::milliseconds{0}) noexcept;

        std::mutex lifecycle_mutex_;
        mutable std::mutex resource_mutex_;
        mutable std::mutex callback_mutex_;
        mutable std::mutex connection_status_mutex_;
        std::mutex reconnect_wait_mutex_;
        std::condition_variable reconnect_wait_cv_;

	std::thread vpn_thread;
	std::atomic<bool> running;
	ConnectionStatus connection_status_{};
	std::chrono::steady_clock::time_point reconnect_deadline_{};

	std::shared_ptr<VpnClient> client;
	std::shared_ptr<VpnServer> server;

        std::function<void(const std::string&)> log_callback;
};
