#include "VpnController.h"
#include "VpnClient.h"
#include "VpnServer.h"

#include <iostream>
#include <filesystem>
#include <chrono>

#include "redirect_stream.hpp"
#include "utils.hpp"

VpnController::VpnController() : port(0), running(false) {
}

VpnController::~VpnController() {
	if (running) {
		stop();
	}
}

bool VpnController::start(std::string m, std::string s_ip, int p, std::string l_ip,
                          std::string g, std::string pw, std::string a_name,
                          std::string mask, std::string pub_ip, std::string real_ad,
                          secure::CipherSuite cipher,
                          TransportProtocol transport) {
	if (running) return false;

	mode = std::move(m);
	server_ip = std::move(s_ip);
	port = p;
	local_ip = std::move(l_ip);
	gateway = std::move(g);
	password = std::move(pw);
	adaptername = std::move(a_name);
	subnetmask = std::move(mask);
	public_ip = std::move(pub_ip);
	real_adapter = std::move(real_ad);
	cipher_suite = cipher;
	transport_ = transport;

	running = true;
	vpn_thread = std::thread(&VpnController::vpn_thread_func, this);
	return true;
}

void VpnController::stop() {
	if (!running) return;

	running = false;

	// Wait up to 5 seconds for graceful shutdown
	auto start = std::chrono::steady_clock::now();
	while (client || server) {
		if (std::chrono::steady_clock::now() - start > std::chrono::seconds(5)) {
			std::cerr << "[!] Force stopping VPN after timeout\n";
			break;
		}

		if (client) {
			client->stop();
			client.reset();
		}

		if (server) {
			server->stop();
			server.reset();
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}

	if (vpn_thread.joinable()) {
		try {
			if (vpn_thread.joinable()) {
				vpn_thread.join();
			}
		} catch (...) {
			// Ignore any thread join errors during shutdown
		}
	}

	std::cout << "[*] VPN stopped\n";
}

bool VpnController::send_message(const std::string& text) {
    if (!running || text.empty()) return false;
    if (client) return client->send_chat_message(text);
    if (server) return server->send_chat(text);
    return false;
}

void VpnController::set_log_callback(std::function<void(const std::string &)> cb) {
	log_callback = std::move(cb);
}

bool VpnController::is_running() const {
	return running;
}

void VpnController::vpn_thread_func() {
	dual_redirect_stream cout_redirect([this](const std::string &msg) {
		if (log_callback) {
			log_callback(msg);
		}
	});

	std::cout << "VPN thread started\n";
	util::logInfo("TLS handshake (expected later)");

	try {
		if (!is_running_as_admin())
			throw std::runtime_error("Administrator privileges required.");

		ComInit com;
		WsaInit wsa;

		// Detect actual backend for ChaCha
		bool using_chacha = (cipher_suite == secure::CipherSuite::ChaCha20Poly1305);
		bool using_cng = true;
		if (using_chacha) {
			auto impl = secure::AeadContext::ch_override();
			using_cng = (impl != secure::AeadContext::ChaChaImplOverride::Soft);
		}

		{
			// Do a small probe to determine actual backend.
			secure::AeadContext probe;
			std::array<uint8_t,32> zero_key{};
			std::array<uint8_t,4> zero_iv{};
			probe.init(cipher_suite, zero_key, zero_iv);

			std::cout << "[✓] Using "
					  << (probe.cipher() == secure::CipherSuite::ChaCha20Poly1305
							 ? (probe.using_cng() ? "Windows CNG ChaCha20-Poly1305" : "software ChaCha20-Poly1305")
							 : "Windows CNG AES-GCM")
					  << " (ECDH P-256, HMAC-SHA256)\n";
		}

		util::logInfo(std::string("[*] Transport protocol: ") + to_string(transport_));

		if (mode == "server") {
			util::logInfo("[*] Launching in server mode");
			server = std::make_unique<VpnServer>(port, real_adapter, password, adaptername, cipher_suite, transport_);
			server->start();
			util::logInfo("[✓] VpnServer started");
		} else {
			util::logInfo("[*] Launching in client mode");
			client = std::make_unique<VpnClient>(
				server_ip, port, password, adaptername, real_adapter, public_ip, cipher_suite, transport_);
			client->start();
		}

		while (running) {
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
	} catch (const std::exception &ex) {
		std::cerr << "[!] VPN error: " << ex.what() << "\n";
	}

	running = false;
}
