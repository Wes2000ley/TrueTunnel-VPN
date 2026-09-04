#include "core/VpnDaemon.h"

#include <functional>
#include <atomic>
#include <chrono>
#include <iostream>
#include <memory>
#include <thread>
#include <string>
#include <vector>
#include <utility>

namespace {
constexpr std::string_view kHarnessSharedKey =
        "QbS8dV16wlVZZO8kchOpKO_HLQHLlNpzQZNi31KK1-U";
}

class FakeVpnController : public IVpnController {
public:
        explicit FakeVpnController(bool fail_send = false) : fail_send_(fail_send) {}
        ~FakeVpnController() override { stop(); }

        bool start(std::string mode,
                   std::string server_ip,
                   int port,
                   std::string local_ip,
                   std::string gateway,
                   std::string password,
                   std::string adapter_name,
                   std::string subnet_mask,
                   std::string real_adapter,
                   std::uint64_t real_adapter_luid,
                   secure::CipherSuite cipher_suite,
                   TransportProtocol transport,
                   ConnectionRecoveryOptions recovery = {}) override {
                (void)mode;
                (void)server_ip;
                (void)port;
                (void)local_ip;
                (void)gateway;
                (void)password;
                (void)adapter_name;
                (void)subnet_mask;
                (void)real_adapter;
                (void)real_adapter_luid;
                (void)cipher_suite;
                (void)transport;
                received_recovery_ = recovery;

                running_ = true;
                connection_status_.phase = mode == "server"
                        ? ConnectionPhase::Listening
                        : ConnectionPhase::Connected;
                start_seen_.store(true, std::memory_order_release);
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
                connection_status_ = {};
                if (worker_.joinable() && worker_.get_id() != std::this_thread::get_id()) {
                        worker_.join();
                }
        }

        [[nodiscard]] bool is_running() const override {
                return running_;
        }

        [[nodiscard]] ConnectionStatus connection_status() const override {
                return connection_status_;
        }

        void set_log_callback(std::function<void(const std::string &)> cb) override {
                log_callback_ = std::move(cb);
        }

        bool send_message(const std::string&) override {
                return !fail_send_;
        }

        void emit_async_shutdown_log() {
                worker_ = std::thread([this]() {
                        if (log_callback_) {
                                log_callback_("fake-controller: async shutdown");
                        }
                        running_ = false;
                });
        }

        [[nodiscard]] const ConnectionRecoveryOptions& received_recovery() const noexcept {
                return received_recovery_;
        }

        [[nodiscard]] bool start_seen() const noexcept {
                return start_seen_.load(std::memory_order_acquire);
        }

private:
        std::atomic<bool> running_{false};
        std::function<void(const std::string &)> log_callback_;
        bool fail_send_ = false;
        std::thread worker_;
        ConnectionRecoveryOptions received_recovery_{};
        ConnectionStatus connection_status_{};
        std::atomic<bool> start_seen_{false};
};

int main() {
        auto factory = []() { return std::make_unique<FakeVpnController>(); };
        VpnDaemon daemon(factory);

        std::vector<VpnDaemon::EventType> events;
        daemon.set_event_callback([&](const VpnDaemon::TelemetryEvent &event) {
                events.push_back(event.type);
        });

        VpnDaemon::SessionConfig config{};
        config.mode = "server";
        config.port = 443;
        config.password = kHarnessSharedKey;

        if (!daemon.start(config)) {
                std::cerr << "Failed to start daemon in harness" << std::endl;
                return 1;
        }

        if (!daemon.is_running()) {
                std::cerr << "Daemon should report running after start" << std::endl;
                return 1;
        }

        const ConnectionStatus initial_status = daemon.connection_status();
        if (initial_status.phase != ConnectionPhase::Listening) {
                std::cerr << "Daemon should report Listening for fake server\n";
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

        auto failing_factory = []() {
                return std::make_unique<FakeVpnController>(true);
        };
        VpnDaemon failing_daemon(failing_factory);
        int error_events = 0;
        failing_daemon.set_event_callback([&](const VpnDaemon::TelemetryEvent& event) {
                if (event.type == VpnDaemon::EventType::Error) ++error_events;
        });
        if (!failing_daemon.start(config)) {
                std::cerr << "Failed to start send-failure daemon test" << std::endl;
                return 1;
        }
        const auto send_start = std::chrono::steady_clock::now();
        if (failing_daemon.send_message("failure-test") ||
            std::chrono::steady_clock::now() - send_start > std::chrono::seconds(1) ||
            error_events != 1) {
                std::cerr << "Daemon send-failure reentry test failed" << std::endl;
                return 1;
        }
        failing_daemon.stop();

        VpnDaemon::SessionConfig retired_config = config;
        retired_config.password = "SuperStrongPassword123";
        if (daemon.start(retired_config) || daemon.state() != VpnDaemon::State::Idle) {
                std::cerr << "Retired default credential was accepted" << std::endl;
                return 1;
        }

        VpnDaemon::SessionConfig invalid_recovery = config;
        invalid_recovery.recovery.enabled = true;
        invalid_recovery.recovery.heartbeat_interval = std::chrono::milliseconds{99};
        if (daemon.start(invalid_recovery) ||
            daemon.state() != VpnDaemon::State::Idle) {
                std::cerr << "Invalid connection recovery timing was accepted\n";
                return 1;
        }
        invalid_recovery.recovery.heartbeat_interval =
                std::chrono::milliseconds{100};
        invalid_recovery.recovery.heartbeat_timeout =
                std::chrono::milliseconds{199};
        if (daemon.start(invalid_recovery)) {
                std::cerr << "Recovery timeout below two heartbeat intervals was accepted\n";
                return 1;
        }
        invalid_recovery.recovery.heartbeat_timeout =
                std::chrono::milliseconds{400};
        invalid_recovery.recovery.initial_retry_delay =
                std::chrono::milliseconds{301};
        invalid_recovery.recovery.maximum_retry_delay =
                std::chrono::milliseconds{300};
        if (daemon.start(invalid_recovery)) {
                std::cerr << "Inverted recovery backoff bounds were accepted\n";
                return 1;
        }

        FakeVpnController* recovery_controller = nullptr;
        auto recovery_factory = [&]() {
                auto controller = std::make_unique<FakeVpnController>();
                recovery_controller = controller.get();
                return controller;
        };
        VpnDaemon recovery_daemon(recovery_factory);
        VpnDaemon::SessionConfig recovery_config = config;
        recovery_config.mode = "client";
        recovery_config.server_ip = "127.0.0.1";
        recovery_config.recovery.enabled = true;
        recovery_config.recovery.heartbeat_interval = std::chrono::milliseconds{100};
        recovery_config.recovery.heartbeat_timeout = std::chrono::milliseconds{400};
        recovery_config.recovery.initial_retry_delay = std::chrono::milliseconds{100};
        recovery_config.recovery.maximum_retry_delay = std::chrono::milliseconds{300};
        if (!recovery_daemon.start(recovery_config) || recovery_controller == nullptr) {
                std::cerr << "Failed to start recovery propagation test\n";
                return 1;
        }
        const auto recovery_deadline =
                std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (!recovery_controller->start_seen() &&
               std::chrono::steady_clock::now() < recovery_deadline) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (!recovery_controller->start_seen()) {
                std::cerr << "Recovery fake controller did not enter start\n";
                return 1;
        }
        const auto& received = recovery_controller->received_recovery();
        if (!received.enabled || received.heartbeat_interval != std::chrono::milliseconds{100} ||
            received.heartbeat_timeout != std::chrono::milliseconds{400} ||
            received.initial_retry_delay != std::chrono::milliseconds{100} ||
            received.maximum_retry_delay != std::chrono::milliseconds{300} ||
            recovery_daemon.connection_status().phase != ConnectionPhase::Connected) {
                std::cerr << "Recovery options/status were not propagated\n";
                return 1;
        }
        recovery_daemon.stop();

        VpnDaemon::SessionConfig missing_endpoint = recovery_config;
        missing_endpoint.server_ip.clear();
        if (recovery_daemon.start(missing_endpoint) ||
            recovery_daemon.state() != VpnDaemon::State::Idle) {
                std::cerr << "Client mode accepted an empty server address\n";
                return 1;
        }

        VpnDaemon::SessionConfig weak_config = config;
        weak_config.password = "12345678901234567890";
        if (daemon.start(weak_config) || daemon.state() != VpnDaemon::State::Idle) {
                std::cerr << "Human-memorable 20-character credential was accepted"
                          << std::endl;
                return 1;
        }

        for (const int invalid_port : {-1, 0, 65'536}) {
                VpnDaemon::SessionConfig invalid_config = config;
                invalid_config.port = invalid_port;
                if (daemon.start(invalid_config) ||
                    daemon.state() != VpnDaemon::State::Idle) {
                        std::cerr << "Out-of-range VPN port was accepted: "
                                  << invalid_port << std::endl;
                        return 1;
                }
        }
        VpnDaemon::SessionConfig invalid_mode = config;
        invalid_mode.mode = "proxy";
        if (daemon.start(invalid_mode) ||
            daemon.state() != VpnDaemon::State::Idle) {
                std::cerr << "Invalid VPN mode was accepted" << std::endl;
                return 1;
        }

        FakeVpnController* reentrant_controller = nullptr;
        auto reentrant_factory = [&]() {
                auto controller = std::make_unique<FakeVpnController>();
                reentrant_controller = controller.get();
                return controller;
        };
        VpnDaemon reentrant_daemon(reentrant_factory);
        std::atomic<bool> async_log_seen{false};
        reentrant_daemon.set_event_callback(
            [&](const VpnDaemon::TelemetryEvent& event) {
                    if (event.type == VpnDaemon::EventType::Log &&
                        event.message == "fake-controller: async shutdown") {
                            async_log_seen = true;
                            reentrant_daemon.stop();
                    }
            });
        if (!reentrant_daemon.start(config) || reentrant_controller == nullptr) {
                std::cerr << "Failed to start reentrant-stop daemon test" << std::endl;
                return 1;
        }
        reentrant_controller->emit_async_shutdown_log();
        const auto reentrant_deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(2);
        bool reentrant_stop_completed = false;
        while (std::chrono::steady_clock::now() < reentrant_deadline) {
                if (async_log_seen.load() &&
                    reentrant_daemon.state() == VpnDaemon::State::Idle) {
                        reentrant_stop_completed = true;
                        break;
                }
                std::this_thread::yield();
        }
        if (!reentrant_stop_completed) {
                std::cerr << "Controller-callback stop was not completed safely" << std::endl;
                return 1;
        }

        std::cout << "VpnDaemon harness completed successfully" << std::endl;
        return 0;
}
