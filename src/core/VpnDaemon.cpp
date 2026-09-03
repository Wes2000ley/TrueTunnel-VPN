#include "core/VpnDaemon.h"
#include "secure/SharedSecret.h"

#include <stdexcept>
#include <utility>
#include <string_view>

#ifndef VPN_DAEMON_DISABLE_DEFAULT_FACTORY
#include "VpnController.h"
#endif

namespace {
// Controller log callbacks execute on controller-owned worker threads.  A
// callback is allowed to request stop(), but destroying the controller from
// that same thread would destroy a still-joinable std::thread and terminate the
// process.  Leave the controller owned until the next external health poll (or
// explicit stop), which can then join it safely.
thread_local const VpnDaemon* controller_callback_daemon = nullptr;

class ControllerCallbackScope final {
public:
        explicit ControllerCallbackScope(const VpnDaemon* daemon) noexcept
                : previous_{controller_callback_daemon} {
                controller_callback_daemon = daemon;
        }

        ~ControllerCallbackScope() {
                controller_callback_daemon = previous_;
        }

        ControllerCallbackScope(const ControllerCallbackScope&) = delete;
        ControllerCallbackScope& operator=(const ControllerCallbackScope&) = delete;

private:
        const VpnDaemon* previous_;
};

#ifndef VPN_DAEMON_DISABLE_DEFAULT_FACTORY
std::unique_ptr<IVpnController> default_controller_factory() {
        return std::make_unique<VpnController>();
}
#endif

VpnDaemon::TelemetryEvent make_event(VpnDaemon::EventType type, std::string message) {
        return VpnDaemon::TelemetryEvent{type, std::move(message), std::chrono::system_clock::now()};
}
} // namespace

#ifndef VPN_DAEMON_DISABLE_DEFAULT_FACTORY
VpnDaemon::VpnDaemon()
        : VpnDaemon(ControllerFactory{}) {}
#endif

VpnDaemon::VpnDaemon(ControllerFactory factory)
        : factory_(std::move(factory)), state_(State::Idle) {
#ifndef VPN_DAEMON_DISABLE_DEFAULT_FACTORY
        if (!factory_) {
                factory_ = []() { return default_controller_factory(); };
        }
#else
        if (!factory_) {
                throw std::invalid_argument("Controller factory must be provided when default factory is disabled");
        }
#endif
}

VpnDaemon::~VpnDaemon() {
        stop();
}

bool VpnDaemon::start(const SessionConfig &config) {
        if (!secure::is_valid_shared_secret(config.password)) {
                publish_event(
                    EventType::Error,
                    "Shared key must be a canonical 43-character generated 256-bit value");
                return false;
        }
        if (config.port <= 0 || config.port > 65'535) {
                publish_event(EventType::Error,
                              "VPN port must be between 1 and 65535");
                return false;
        }
        if (config.mode != "server" && config.mode != "client") {
                publish_event(EventType::Error,
                              "VPN mode must be 'server' or 'client'");
                return false;
        }
        State expected = State::Idle;
        if (!state_.compare_exchange_strong(expected, State::Starting)) {
                publish_event(EventType::Error, "VPN daemon is already running or starting");
                return false;
        }

        auto controller = make_controller();
        if (!controller) {
                state_.store(State::Idle);
                publish_event(EventType::Error, "Failed to create VPN controller instance");
                return false;
        }

        controller->set_log_callback([this](const std::string &msg) { handle_log(msg); });

        bool started = controller->start(config.mode,
                                         config.server_ip,
                                         config.port,
                                         config.local_ip,
                                         config.gateway,
                                         config.password,
                                         config.adapter_name,
                                         config.subnet_mask,
                                         config.public_ip,
                                         config.real_adapter,
                                         config.real_adapter_luid,
                                         config.cipher_suite,
                                         config.transport);

        if (!started) {
                state_.store(State::Idle);
                publish_event(EventType::Error, "Underlying VPN controller rejected start request");
                return false;
        }

        bool accepted = false;
        State observed = State::Starting;
        {
                std::lock_guard<std::mutex> guard(controller_mutex_);
                if (state_.compare_exchange_strong(observed, State::Running)) {
                        controller_ = std::move(controller);
                        accepted = true;
                }
        }

        if (!accepted) {
                controller->stop();
                if (observed != State::Stopping) {
                        state_.store(State::Idle);
                        publish_event(EventType::Log, "VPN daemon start aborted before completion");
                } else {
                        publish_event(EventType::Log, "VPN daemon stop requested during startup");
                }
                return false;
        }

        publish_event(EventType::Started, "VPN daemon started in " + config.mode + " mode");
        return true;
}

void VpnDaemon::stop() {
        State previous = state_.exchange(State::Stopping);
        if (previous == State::Idle) {
                state_.store(State::Idle);
                return;
        }

        if (controller_callback_daemon == this) {
                // The worker will unwind after its callback returns.  An
                // external is_running()/state()/stop() call completes teardown.
                return;
        }

        std::unique_ptr<IVpnController> controller;
        {
                std::lock_guard<std::mutex> guard(controller_mutex_);
                controller = std::move(controller_);
        }

        if (controller) {
                try {
                        controller->stop();
                } catch (...) {
                        // Destructors and shutdown paths must remain non-throwing.
                }
        }

        state_.store(State::Idle);
        publish_event(EventType::Stopped, "VPN daemon stopped");
}

bool VpnDaemon::is_running() const {
        const_cast<VpnDaemon*>(this)->check_controller_health();
        return state_.load() == State::Running;
}

VpnDaemon::State VpnDaemon::state() const {
        const_cast<VpnDaemon*>(this)->check_controller_health();
        return state_.load();
}

void VpnDaemon::set_event_callback(EventCallback cb) {
        std::lock_guard<std::mutex> lock(callback_mutex_);
        event_callback_ = std::move(cb);
}

void VpnDaemon::publish_event(EventType type, const std::string &message) {
        publish_event(make_event(type, message));
}

void VpnDaemon::publish_event(const TelemetryEvent &event) {
        dispatch_event(event);
        check_controller_health();
}

void VpnDaemon::handle_log(const std::string &message) {
        ControllerCallbackScope callback_scope{this};
        publish_event(EventType::Log, message);
}

std::unique_ptr<IVpnController> VpnDaemon::make_controller() {
        if (!factory_) {
                return nullptr;
        }
        return factory_();
}

bool VpnDaemon::send_message(const std::string& text) {
        bool ok = false;
        {
                // Keep the controller alive through the call, but do not hold
                // this mutex while publishing the failure event: event
                // dispatch performs health re-entry and may be user-reentrant.
                std::lock_guard<std::mutex> guard(controller_mutex_);
                if (!controller_ || !controller_->is_running()) {
                        return false;
                }
                ok = controller_->send_message(text);
        }
        if (!ok) {
                publish_event(EventType::Error, "Failed to send message");
        }
        return ok;
}

void VpnDaemon::dispatch_event(const TelemetryEvent& event) {
        EventCallback cb;
        {
                std::lock_guard<std::mutex> lock(callback_mutex_);
                cb = event_callback_;
        }

        if (!cb) {
                return;
        }

        try {
                cb(event);
        } catch (...) {
                // Swallow exceptions from user-provided callbacks to keep daemon stable
        }
}

void VpnDaemon::check_controller_health() {
        if (controller_callback_daemon == this) {
                return;
        }

        if (state_.load() == State::Stopping) {
                stop();
                return;
        }
        if (state_.load() != State::Running) return;

        std::unique_ptr<IVpnController> controller;
        {
                std::lock_guard<std::mutex> guard(controller_mutex_);
                if (!controller_ || controller_->is_running()) {
                        return;
                }
                controller = std::move(controller_);
        }

        if (controller) {
                try {
                        controller->stop();
                } catch (...) {
                }
        }

        state_.store(State::Idle);
        dispatch_event(make_event(EventType::Stopped, "VPN daemon detected controller shutdown"));
}
