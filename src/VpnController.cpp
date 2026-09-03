#include "VpnController.h"
#include "VpnClient.h"
#include "VpnServer.h"
#include "secure/SharedSecret.h"

#include <iostream>
#include <filesystem>
#include <chrono>
#include <system_error>
#include <string_view>

#include "redirect_stream.hpp"
#include "utils.hpp"

namespace {
void wipe_string(std::string& value) noexcept {
	if (!value.empty()) {
		::SecureZeroMemory(value.data(), value.size());
		value.clear();
	}
}
} // namespace

VpnController::StartupConfig::~StartupConfig() {
	wipe_string(password);
}

VpnController::VpnController() : running(false) {
}

VpnController::~VpnController() {
	stop();
}

bool VpnController::start(std::string m, std::string s_ip, int p, std::string l_ip,
                          std::string g, std::string pw, std::string a_name,
                          std::string mask, std::string pub_ip, std::string real_ad,
                          const std::uint64_t real_adapter_luid,
                          secure::CipherSuite,
                          TransportProtocol transport) {
	std::lock_guard<std::mutex> lifecycle_guard(lifecycle_mutex_);
	if (running || vpn_thread.joinable()) return false;
	if (!secure::is_valid_shared_secret(pw) || p <= 0 || p > 65'535 ||
	    (m != "server" && m != "client")) return false;

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
	config->public_ip = std::move(pub_ip);
	config->real_adapter = std::move(real_ad);
	config->real_adapter_luid = real_adapter_luid;
	config->cipher_suite = secure::CipherSuite::Aes256Gcm;
	config->transport = transport;

	running = true;
	try {
		vpn_thread = std::thread(
			&VpnController::vpn_thread_func, this, std::move(config));
	} catch (const std::exception& error) {
		running = false;
		std::cerr << "[!] Failed to start VPN worker: " << error.what() << '\n';
		return false;
	} catch (...) {
		running = false;
		std::cerr << "[!] Failed to start VPN worker\n";
		return false;
	}
	return true;
}

void VpnController::stop() {
	std::lock_guard<std::mutex> lifecycle_guard(lifecycle_mutex_);

	running = false;

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
			wipe_string(config->password);
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
			util::logInfo("[✓] VpnServer started");
		} else {
			util::logInfo("[*] Launching in client mode");
			auto new_client = std::make_shared<VpnClient>(
				config->server_ip, config->port, config->password,
				config->adaptername, config->real_adapter, config->public_ip,
				config->cipher_suite, config->transport,
				secure::TrafficKeyRotationPolicy{}, config->real_adapter_luid);
			wipe_string(config->password);
			bool keep_client = false;
			{
				std::lock_guard<std::mutex> resource_guard(resource_mutex_);
				if (running.load()) {
					// Publish before the potentially unbounded connection retry loop
					// so stop() can cancel its pending socket and wait deterministically.
					client = new_client;
					keep_client = true;
				}
			}
			if (!keep_client) {
				new_client->stop();
				return;
			}
			new_client->start();
			if (!running.load()) {
				new_client->stop();
				return;
			}
		}

		while (running) {
			std::shared_ptr<VpnClient> inactive_client;
			std::shared_ptr<VpnServer> inactive_server;
			{
				std::lock_guard<std::mutex> resource_guard(resource_mutex_);
				if (client && !client->is_active()) inactive_client = std::move(client);
				if (server && !server->is_active()) inactive_server = std::move(server);
			}
			if (inactive_client) {
				util::logWarn("[!] Client session ended unexpectedly; shutting down");
				inactive_client->stop();
				running = false;
				break;
			}
			if (inactive_server) {
				util::logWarn("[!] Server stopped unexpectedly; shutting down");
				inactive_server->stop();
				running = false;
				break;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
	} catch (const std::exception &ex) {
		std::cerr << "[!] VPN error: " << ex.what() << "\n";
	}
	config.reset();

	running = false;
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
