#include "core/VpnDaemon.h"

#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <utility>

class FakeVpnController : public IVpnController {
public:
        bool start(std::string mode,
                   std::string server_ip,
                   int port,
                   std::string local_ip,
                   std::string gateway,
                   std::string password,
                   std::string adapter_name,
                   std::string subnet_mask,
                   std::string public_ip,
                   std::string real_adapter) override {
                (void)mode;
                (void)server_ip;
                (void)port;
                (void)local_ip;
                (void)gateway;
                (void)password;
                (void)adapter_name;
                (void)subnet_mask;
                (void)public_ip;
                (void)real_adapter;

                running_ = true;
                if (log_callback_) {
                        log_callback_("fake-controller: start invoked");
                }
                return true;
        }

        void stop() override {
                if (running_ && log_callback_) {
                        log_callback_("fake-controller: stop invoked");
                }
                running_ = false;
        }

        [[nodiscard]] bool is_running() const override {
                return running_;
        }

        void set_log_callback(std::function<void(const std::string &)> cb) override {
                        log_callback_ = std::move(cb);
        }

private:
        bool running_ = false;
        std::function<void(const std::string &)> log_callback_;
};

int main() {
        auto factory = []() { return std::make_unique<FakeVpnController>(); };
        VpnDaemon daemon(factory);

        std::vector<VpnDaemon::EventType> events;
        daemon.set_event_callback([&](const VpnDaemon::TelemetryEvent &event) {
                events.push_back(event.type);
        });

        VpnDaemon::SessionConfig config{};
        config.mode = "test";
        config.port = 443;

        if (!daemon.start(config)) {
                std::cerr << "Failed to start daemon in harness" << std::endl;
                return 1;
        }

        if (!daemon.is_running()) {
                std::cerr << "Daemon should report running after start" << std::endl;
                return 1;
        }

        daemon.stop();

        if (daemon.is_running()) {
                std::cerr << "Daemon should not report running after stop" << std::endl;
                return 1;
        }

        bool saw_started = false;
        bool saw_stopped = false;
        int log_events = 0;
        for (auto type: events) {
                switch (type) {
                        case VpnDaemon::EventType::Started:
                                saw_started = true;
                                break;
                        case VpnDaemon::EventType::Stopped:
                                saw_stopped = true;
                                break;
                        case VpnDaemon::EventType::Log:
                                ++log_events;
                                break;
                        case VpnDaemon::EventType::Error:
                                std::cerr << "Unexpected error event emitted" << std::endl;
                                return 1;
                }
        }

        if (!saw_started || !saw_stopped) {
                std::cerr << "Missing expected start/stop events" << std::endl;
                return 1;
        }

        if (log_events < 2) {
                std::cerr << "Expected at least two log events from fake controller" << std::endl;
                return 1;
        }

        std::cout << "VpnDaemon harness completed successfully" << std::endl;
        return 0;
}
