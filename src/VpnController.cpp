#include "VpnController.h"
#include "VpnClient.h"
#include "VpnServer.h"
#include "secure/SharedSecret.h"

#include <iostream>
#include <filesystem>
#include <chrono>
#include <algorithm>
#include <bcrypt.h>
#include <limits>
#include <optional>
#include <system_error>
#include <string_view>

#include "redirect_stream.hpp"
#include "utils.hpp"

namespace {
std::chrono::milliseconds reconnect_delay_with_jitter(
	const ConnectionRecoveryOptions& policy,
	const std::uint32_t attempt) noexcept {
	using Rep = std::chrono::milliseconds::rep;
	const Rep maximum = policy.maximum_retry_delay.count();
	Rep delay = policy.initial_retry_delay.count();
	for (std::uint32_t step = 1U; step < attempt && delay < maximum; ++step) {
		delay = (std::min)(maximum, delay > maximum / 2 ? maximum : delay * 2);
	}
	if (attempt <= 1U) {
		return std::chrono::milliseconds{delay};
	}

	std::uint32_t random_value = 0U;
	const NTSTATUS random_status = ::BCryptGenRandom(
		nullptr,
		reinterpret_cast<PUCHAR>(&random_value),
		static_cast<ULONG>(sizeof(random_value)),
		BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (random_status < 0 || delay <= 1) {
		return std::chrono::milliseconds{delay};
	}

	// Equal jitter avoids synchronized reconnect storms while retaining a
	// useful lower bound. The configured maximum remains a hard ceiling.
	const Rep lower_bound = (delay + 1) / 2;
	const auto range = static_cast<std::uint64_t>(delay - lower_bound + 1);
	return std::chrono::milliseconds{
		lower_bound + static_cast<Rep>(random_value % range)};
}
} // namespace

VpnController::StartupConfig::~StartupConfig() {
	clear_password();
}

void VpnController::StartupConfig::lock_password_pages() noexcept {
	if (password.empty() || password_page_locked) return;
	password_page_locked =
		::VirtualLock(password.data(), password.size()) != FALSE;
}

void VpnController::StartupConfig::clear_password() noexcept {
	if (password.empty()) {
		password_page_locked = false;
		return;
	}
	char* const bytes = password.data();
	const std::size_t byte_count = password.size();
	::SecureZeroMemory(bytes, byte_count);
	if (password_page_locked) {
		(void)::VirtualUnlock(bytes, byte_count);
	}
	password_page_locked = false;
	password.clear();
}

VpnController::VpnController() : running(false) {
}

VpnController::~VpnController() {
	stop();
}

bool VpnController::start(std::string m, std::string s_ip, int p, std::string l_ip,
                          std::string g, std::string pw, std::string a_name,
                          std::string mask, std::string real_ad,
                          const std::uint64_t real_adapter_luid,
                          secure::CipherSuite,
                          TransportProtocol transport,
                          ConnectionRecoveryOptions recovery) {
	std::lock_guard<std::mutex> lifecycle_guard(lifecycle_mutex_);
	if (running || vpn_thread.joinable()) return false;
	if (!secure::is_valid_shared_secret(pw) || p <= 0 || p > 65'535 ||
	    (m != "server" && m != "client") ||
	    (m == "client" && s_ip.empty()) ||
	    !is_valid_connection_recovery_options(recovery)) return false;

	// These legacy interface parameters are not consumed by either concrete
	// endpoint; each endpoint obtains its assigned tunnel configuration from the
	// authenticated protocol exchange.
	(void)l_ip;
	(void)g;
	(void)mask;

	auto config = std::make_unique<StartupConfig>();
	config->mode = std::move(m);
	config->server_ip = std::move(s_ip);
	config->port = p;
	config->password = std::move(pw);
	config->adaptername = std::move(a_name);
	config->real_adapter = std::move(real_ad);
	config->real_adapter_luid = real_adapter_luid;
	config->cipher_suite = secure::CipherSuite::Aes256Gcm;
	config->transport = transport;
	// Recovery is a client policy. A GUI role switch can leave its hidden client
	// toggle selected, so normalize server sessions defensively instead of
	// retaining an unnecessary reconnect credential.
	config->recovery = config->mode == "client"
		? recovery
		: ConnectionRecoveryOptions{};
	if (config->recovery.enabled) {
		config->lock_password_pages();
	}

	running = true;
	set_connection_status(ConnectionPhase::Connecting);
	try {
		vpn_thread = std::thread(
			&VpnController::vpn_thread_func, this, std::move(config));
	} catch (const std::exception& error) {
		running = false;
		set_connection_status(ConnectionPhase::Idle);
		std::cerr << "[!] Failed to start VPN worker: " << error.what() << '\n';
		return false;
	} catch (...) {
		running = false;
		set_connection_status(ConnectionPhase::Idle);
		std::cerr << "[!] Failed to start VPN worker\n";
		return false;
	}
	return true;
}

void VpnController::stop() {
	std::lock_guard<std::mutex> lifecycle_guard(lifecycle_mutex_);

	running = false;
	set_connection_status(ConnectionPhase::Idle);
	reconnect_wait_cv_.notify_all();

	std::shared_ptr<VpnClient> client_to_stop;
	std::shared_ptr<VpnServer> server_to_stop;
	{
		std::lock_guard<std::mutex> resource_guard(resource_mutex_);
		client_to_stop = std::move(client);
		server_to_stop = std::move(server);
	}
	if (client_to_stop) client_to_stop->stop();
	if (server_to_stop) server_to_stop->stop();

	if (vpn_thread.joinable() && vpn_thread.get_id() != std::this_thread::get_id()) {
		vpn_thread.join();
	}
	std::cout << "[*] VPN stopped\n";
}

bool VpnController::send_message(const std::string& text) {
    if (!running.load() || text.empty()) return false;

    std::shared_ptr<VpnClient> client_snapshot;
    std::shared_ptr<VpnServer> server_snapshot;
    {
        std::lock_guard<std::mutex> resource_guard(resource_mutex_);
        client_snapshot = client;
        server_snapshot = server;
    }

    // Network writes may wait for a slow peer. Shared endpoint ownership keeps
    // the object alive without blocking stop() on a controller lifecycle lock.
    if (client_snapshot) return client_snapshot->send_chat_message(text);
    if (server_snapshot) return server_snapshot->send_chat(text);
    return false;
}

void VpnController::set_log_callback(std::function<void(const std::string &)> cb) {
	std::lock_guard<std::mutex> callback_guard(callback_mutex_);
	log_callback = std::move(cb);
}

bool VpnController::is_running() const {
	return running;
}

ConnectionStatus VpnController::connection_status() const {
	std::lock_guard<std::mutex> status_guard(connection_status_mutex_);
	ConnectionStatus status = connection_status_;
	if (status.phase == ConnectionPhase::Reconnecting &&
	    reconnect_deadline_ != std::chrono::steady_clock::time_point{}) {
		const auto now = std::chrono::steady_clock::now();
		status.retry_delay = reconnect_deadline_ > now
			? std::chrono::duration_cast<std::chrono::milliseconds>(
				reconnect_deadline_ - now)
			: std::chrono::milliseconds{0};
	}
	return status;
}

void VpnController::set_connection_status(
	const ConnectionPhase phase,
	const std::uint32_t retry_attempt,
	const std::chrono::milliseconds retry_delay) noexcept {
	std::lock_guard<std::mutex> status_guard(connection_status_mutex_);
	if (phase != ConnectionPhase::Idle && !running.load()) {
		connection_status_ = {};
		reconnect_deadline_ = {};
		return;
	}
	connection_status_ = ConnectionStatus{phase, retry_attempt, retry_delay};
	reconnect_deadline_ =
		phase == ConnectionPhase::Reconnecting && retry_delay.count() > 0
			? std::chrono::steady_clock::now() + retry_delay
			: std::chrono::steady_clock::time_point{};
}

void VpnController::vpn_thread_func(std::unique_ptr<StartupConfig> config) {
	dual_redirect_stream cout_redirect([this](const std::string &msg) {
		std::function<void(const std::string&)> callback;
		{
			std::lock_guard<std::mutex> callback_guard(callback_mutex_);
			callback = log_callback;
		}
		if (callback) callback(msg);
	});

	std::cout << "VPN thread started\n";
	util::logInfo("Secure transport handshake will begin after the socket connects");
	if (config->recovery.enabled && !config->password_page_locked) {
		util::logWarn(
			"[!] Windows could not page-lock the reconnect credential; "
			"it will still be zeroized at shutdown");
	}

	try {
		if (!is_running_as_admin())
			throw std::runtime_error("Administrator privileges required.");

		ComInit com;
		WsaInit wsa;

		if (config->transport == TransportProtocol::Tcp) {
			std::cout << "[✓] Using Windows Schannel TLS 1.3 "
					  "(TLS_AES_256_GCM_SHA384, ephemeral ECDSA P-384 certificate)\n";
		} else {
			std::cout << "[✓] Using wolfSSL DTLS 1.3 "
					     "(TLS_AES_256_GCM_SHA384, P-256 ECDHE-PSK)\n";
		}

		util::logInfo(std::string("[*] Transport protocol: ") +
		              to_string(config->transport));

		if (config->mode == "server") {
			util::logInfo("[*] Launching in server mode");
			auto new_server = std::make_shared<VpnServer>(
				config->port, config->real_adapter, config->password,
				config->adaptername, config->cipher_suite, config->transport,
				secure::TrafficKeyRotationPolicy{}, config->real_adapter_luid);
			config->clear_password();
			bool keep_server = false;
			{
				std::lock_guard<std::mutex> resource_guard(resource_mutex_);
				if (running.load()) {
					// Publish before adapter and listener setup so stop() can cancel
					// time-bounded Windows networking helpers during startup.
					server = new_server;
					keep_server = true;
				}
			}
			if (!keep_server) {
				new_server->stop();
				return;
			}
			new_server->start();
			if (!running.load()) {
				new_server->stop();
				return;
			}
			set_connection_status(ConnectionPhase::Listening);
			util::logInfo("[✓] VpnServer started");

			while (running) {
				std::shared_ptr<VpnServer> inactive_server;
				{
					std::lock_guard<std::mutex> resource_guard(resource_mutex_);
					if (server && !server->is_active()) {
						inactive_server = std::move(server);
					}
				}
				if (inactive_server) {
					util::logWarn("[!] Server stopped unexpectedly; shutting down");
					inactive_server->stop();
					running = false;
					break;
				}
				std::unique_lock<std::mutex> wait_lock(reconnect_wait_mutex_);
				reconnect_wait_cv_.wait_for(
					wait_lock, std::chrono::milliseconds{100},
					[this]() { return !running.load(); });
			}
		} else {
			util::logInfo("[*] Launching in client mode");
			const bool recovery_enabled = config->recovery.enabled;
			bool has_connected = false;
			std::uint32_t retry_attempt = 0U;
			auto schedule_reconnect = [this, &config, &retry_attempt](
					const std::string_view reason) {
				if (retry_attempt < (std::numeric_limits<std::uint32_t>::max)()) {
					++retry_attempt;
				}
				const auto retry_delay = reconnect_delay_with_jitter(
					config->recovery, retry_attempt);
				set_connection_status(ConnectionPhase::Reconnecting,
				                      retry_attempt, retry_delay);
				util::logWarn(
					"[!] " + std::string{reason} + "; reconnect attempt " +
					std::to_string(retry_attempt) + " in " +
					std::to_string(retry_delay.count()) + " ms");
				return std::chrono::steady_clock::now() + retry_delay;
			};
			auto wait_for_reconnect = [this, &retry_attempt](
					const std::chrono::steady_clock::time_point deadline) {
				std::unique_lock<std::mutex> wait_lock(reconnect_wait_mutex_);
				if (reconnect_wait_cv_.wait_until(
						wait_lock, deadline,
						[this]() { return !running.load(); })) {
					return false;
				}
				set_connection_status(
					ConnectionPhase::Reconnecting, retry_attempt,
					std::chrono::milliseconds{0});
				return true;
			};

			while (running) {
				if (!has_connected) {
					set_connection_status(ConnectionPhase::Connecting);
				}

				auto new_client = std::make_shared<VpnClient>(
					config->server_ip, config->port, config->password,
					config->adaptername, config->real_adapter,
					config->cipher_suite, config->transport,
					secure::TrafficKeyRotationPolicy{}, config->real_adapter_luid,
					config->recovery,
					/*single_connect_attempt=*/has_connected);
				if (!recovery_enabled) {
					// A non-reconnecting endpoint owns its only remaining key copy.
					config->clear_password();
				}

				bool keep_client = false;
				{
					std::lock_guard<std::mutex> resource_guard(resource_mutex_);
					if (running.load()) {
						// Publish before connection/handshake so stop() can cancel it.
						client = new_client;
						keep_client = true;
					}
				}
				if (!keep_client) {
					new_client->stop();
					break;
				}

				try {
					new_client->start();
				} catch (const std::exception& error) {
					{
						std::lock_guard<std::mutex> resource_guard(resource_mutex_);
						if (client == new_client) client.reset();
					}
					new_client->stop();
					if (!running.load()) break;
					if (!recovery_enabled || !has_connected) throw;
					const auto retry_deadline = schedule_reconnect(
						std::string{"Reconnect attempt failed: "} + error.what());
					if (!wait_for_reconnect(retry_deadline)) break;
					continue;
				}

				if (!running.load()) {
					new_client->stop();
					break;
				}
				const bool was_reconnect = has_connected;
				has_connected = true;
				retry_attempt = 0U;
				set_connection_status(ConnectionPhase::Connected);
				util::logInfo(was_reconnect
					? "[✓] Secure tunnel reconnected with fresh session keys"
					: "[✓] Secure tunnel connected");

				while (running.load() && new_client->is_active()) {
					std::unique_lock<std::mutex> wait_lock(reconnect_wait_mutex_);
					reconnect_wait_cv_.wait_for(
						wait_lock, std::chrono::milliseconds{100},
						[this, &new_client]() {
							return !running.load() || !new_client->is_active();
						});
				}

				std::optional<std::chrono::steady_clock::time_point>
					retry_deadline;
				if (running.load() && recovery_enabled) {
					retry_deadline = schedule_reconnect("Secure session lost");
				}
				{
					std::lock_guard<std::mutex> resource_guard(resource_mutex_);
					if (client == new_client) client.reset();
				}
				new_client->stop();
				if (!running.load()) break;
				if (!recovery_enabled) {
					util::logWarn(
						"[!] Client session ended unexpectedly; automatic recovery is off");
					running = false;
					break;
				}
				if (retry_deadline && !wait_for_reconnect(*retry_deadline)) break;
			}
		}
	} catch (const std::exception &ex) {
		std::cerr << "[!] VPN error: " << ex.what() << "\n";
	}
	config.reset();

	running = false;
	set_connection_status(ConnectionPhase::Idle);
	reconnect_wait_cv_.notify_all();
	std::shared_ptr<VpnClient> client_to_stop;
	std::shared_ptr<VpnServer> server_to_stop;
	{
		std::lock_guard<std::mutex> resource_guard(resource_mutex_);
		client_to_stop = std::move(client);
		server_to_stop = std::move(server);
	}
	if (client_to_stop) client_to_stop->stop();
	if (server_to_stop) server_to_stop->stop();
}
