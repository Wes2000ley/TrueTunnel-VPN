#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

#include "TransportProtocol.h"
#include "core/IVpnController.h"
#include "secure/CipherSuite.h"

class VpnDaemon {
public:
        struct SessionConfig {
                std::string mode;
                std::string server_ip;
                int port = 0;
                std::string local_ip;
                std::string gateway;
                std::string password;
                std::string adapter_name;
                std::string subnet_mask;
                std::string public_ip;
                std::string real_adapter;
                secure::CipherSuite cipher_suite{secure::CipherSuite::Aes256Gcm};
                TransportProtocol transport{TransportProtocol::Tcp};
        };

        enum class State {
                Idle,
                Starting,
                Running,
                Stopping
        };

        enum class EventType {
                Started,
                Stopped,
                Log,
                Error
        };

        struct TelemetryEvent {
                EventType type;
                std::string message;
                std::chrono::system_clock::time_point timestamp;
        };

        using EventCallback = std::function<void(const TelemetryEvent&)>;
        using ControllerFactory = std::function<std::unique_ptr<IVpnController>()>;

#ifndef VPN_DAEMON_DISABLE_DEFAULT_FACTORY
        VpnDaemon();
#else
        VpnDaemon() = delete;
#endif
        explicit VpnDaemon(ControllerFactory factory);
        ~VpnDaemon();

        bool start(const SessionConfig& config);
        void stop();
        [[nodiscard]] bool is_running() const;
        [[nodiscard]] State state() const;

        void set_event_callback(EventCallback cb);
        bool send_message(const std::string& text);

private:
        void publish_event(EventType type, const std::string& message);
        void publish_event(const TelemetryEvent& event);
        void dispatch_event(const TelemetryEvent& event);
        void check_controller_health();
        void handle_log(const std::string& message);
        std::unique_ptr<IVpnController> make_controller();

        ControllerFactory factory_;
        std::unique_ptr<IVpnController> controller_;
        std::mutex controller_mutex_;

        std::mutex callback_mutex_;
        EventCallback event_callback_;

        std::atomic<State> state_;
};
