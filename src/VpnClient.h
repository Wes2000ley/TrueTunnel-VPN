#pragma once

#include "raii.hpp"
#include "Networking.h"
#include <winsock2.h>
#include "secure/SecureSocket.h"
#include <string>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>
#include <atomic>
#include <mutex>

#include "TransportProtocol.h"

class VpnClient {
public:
	VpnClient(const std::string& server_ip,
		  int port,
		  const std::string& password,
		  const std::string& adaptername,
		  const std::string& real_adapter,
		  const std::string& public_ip,
		  secure::CipherSuite cipher,
		  TransportProtocol transport);

	~VpnClient();

	void start();
	void stop();



private:
	void connectToServer();
	void performHandshake();
	void requestConfig();
	void configureAdapter();
	void startPacketForwarding();
	void startInputLoop();
	void handle_incoming_message(std::string_view message);

public:
	[[nodiscard]] std::string local_ip() const { return local_ip_; }
	[[nodiscard]] std::string adapter_name() const { return adaptername_; }
	[[nodiscard]] bool is_active() const { return running_.load(); }
	bool send_chat_message(const std::string& text);
	std::vector<std::string> drain_messages();

private:
	std::string server_ip_;
	int port_;
	std::string password_;
	std::string adaptername_;
	std::string real_adapter_;
	std::string public_ip_;
	std::string local_ip_;
	std::string subnetmask_;
	std::string gateway_;
	secure::CipherSuite cipher_suite_;
	TransportProtocol transport_{TransportProtocol::Tcp};

	SOCKET sock_ = INVALID_SOCKET;
	std::unique_ptr<secure::SecureSocket> tls_;
	std::atomic<bool> running_ = false;
	std::optional<WintunAdapterGuard> adapter_;
	std::shared_ptr<WintunSessionGuard> session_;  // <-- use shared_ptr to manage ownership
	std::mutex session_mutex_;
	std::mutex tls_write_mutex_;
	mutable std::mutex message_mutex_;
	std::vector<std::string> received_messages_;
};
