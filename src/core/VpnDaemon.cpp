#include "core/VpnDaemon.h"

#include <stdexcept>
#include <utility>

#ifndef VPN_DAEMON_DISABLE_DEFAULT_FACTORY
#include "VpnController.h"
#endif

namespace {
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
                                         config.cipher_suite);

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

        std::unique_ptr<IVpnController> controller;
        {
                std::lock_guard<std::mutex> guard(controller_mutex_);
                controller = std::move(controller_);
        }

        if (controller) {
                controller->stop();
                controller.reset();
        }

        state_.store(State::Idle);
        publish_event(EventType::Stopped, "VPN daemon stopped");
}

bool VpnDaemon::is_running() const {
        return state_.load() == State::Running;
}

VpnDaemon::State VpnDaemon::state() const {
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

void VpnDaemon::handle_log(const std::string &message) {
        publish_event(EventType::Log, message);
}

std::unique_ptr<IVpnController> VpnDaemon::make_controller() {
        if (!factory_) {
                return nullptr;
        }
        return factory_();
}
