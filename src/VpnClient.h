#pragma once

#include "raii.hpp"
#include "Networking.h"
#include <winsock2.h>
#include "secure/SecureSocket.h"
#include <array>
#include <string>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <span>
#include <utility>
#ifdef TRUETUNNEL_INTEGRATION_TEST
#include <functional>
#endif

#include "TransportProtocol.h"
#include "core/ConnectionRecovery.h"

class VpnClient {
public:
	VpnClient(const std::string& server_ip,
		  int port,
		  const std::string& password,
		  const std::string& adaptername,
		  const std::string& real_adapter,
		  secure::CipherSuite cipher,
		  TransportProtocol transport,
		  secure::TrafficKeyRotationPolicy rotation_policy = {},
		  std::uint64_t expected_real_adapter_luid = 0U,
		  ConnectionRecoveryOptions recovery = {},
		  bool single_connect_attempt = false);

	~VpnClient();

	void start();
	void stop();



private:
	void connectToServer();
	void connectToServerFromBindIp(
		const std::string& bind_ip, bool establish_secure_session);
	void discardTransportAttempt() noexcept;
	void performHandshake();
	void requestConfig();
	void configureAdapter();
	void startPacketForwarding();
	void startInputLoop();
	void handle_incoming_message(std::string_view message);
	void heartbeatLoop();
	void heartbeatWatchdogLoop();
	void tcpSessionReplacementLoop();
	void replaceTcpSession();
	[[nodiscard]] SOCKET connectReplacementSocket(const std::string& bind_ip);
	[[nodiscard]] bool handle_control_record(
		std::uint8_t type, std::span<const std::uint8_t> payload);
	void note_authenticated_receive() noexcept;
	void terminate_unresponsive_channel(const char* reason) noexcept;
	void clear_password() noexcept;
	[[nodiscard]] std::shared_ptr<secure::SecureSocket> tls_snapshot() const;

public:
	[[nodiscard]] std::string local_ip() const { return local_ip_; }
	[[nodiscard]] std::string adapter_name() const { return adaptername_; }
	[[nodiscard]] bool is_active() const { return running_.load(); }
	bool send_chat_message(const std::string& text);
	std::vector<std::string> drain_messages();
#ifdef TRUETUNNEL_INTEGRATION_TEST
	using IntegrationPacketObserver =
		std::function<bool(std::span<const std::uint8_t>)>;
	using IntegrationEndpointObserver =
		std::function<void(std::string_view, std::uint16_t)>;
	using IntegrationEndpointAttemptObserver =
		std::function<void(std::string_view, std::uint16_t)>;
	void set_integration_packet_observer(IntegrationPacketObserver observer);
	void set_integration_endpoint_observer(IntegrationEndpointObserver observer);
	void set_integration_endpoint_attempt_observer(
		IntegrationEndpointAttemptObserver observer);
	void set_integration_resolved_ipv4_addresses(
		std::vector<std::string> addresses);
	void integration_connect_endpoint_only(const std::string& bind_ip);
	void integration_connect_secure_endpoint_only(const std::string& bind_ip);
	[[nodiscard]] bool integration_send_endpoint_probe(
		std::span<const std::uint8_t> payload) const;
	[[nodiscard]] static std::pair<std::string, std::uint16_t>
	integration_resolve_server_endpoint(
		const std::string& server_address,
		std::uint16_t port,
		TransportProtocol transport);
	bool send_integration_ipv4_packet(std::span<const std::uint8_t> packet);
	void force_integration_tcp_session_replacement() noexcept;
	secure::TrafficKeyRotationStats integration_rotation_stats();
#endif

private:
	std::string server_address_;
	std::string resolved_server_ip_;
	int port_;
	std::string password_;
	std::mutex password_mutex_;
	bool password_page_locked_{false};
	std::string adaptername_;
	std::string real_adapter_;
	std::string local_ip_;
	std::string subnetmask_;
	std::string gateway_;
	secure::CipherSuite cipher_suite_;
	TransportProtocol transport_{TransportProtocol::Tcp};
	secure::TrafficKeyRotationPolicy rotation_policy_{};
	ConnectionRecoveryOptions recovery_{};
	bool single_connect_attempt_{false};
	std::uint64_t expected_real_adapter_luid_{0U};
	NET_LUID real_adapter_luid_{};
	bool real_adapter_luid_pinned_{false};

	std::atomic<SOCKET> sock_{INVALID_SOCKET};
	std::atomic<SOCKET> pending_socket_{INVALID_SOCKET};
	std::mutex pending_replacement_mutex_;
	std::shared_ptr<secure::SecureSocket> pending_replacement_tls_;
	std::mutex stop_mutex_;
	bool start_called_ = false;
	std::atomic<bool> stop_requested_{false};
	mutable std::mutex tls_mutex_;
	std::shared_ptr<secure::SecureSocket> tls_;
	std::atomic<bool> running_ = false;
	std::optional<WintunAdapterLease> adapter_;
	std::unique_ptr<WintunSessionGuard> session_;
	HANDLE cancellation_event_ = nullptr;
	std::mutex session_mutex_;
	std::mutex tls_write_mutex_;
	// Gives bounded authenticated control traffic one turn between sustained
	// application writes so a full-rate tunnel cannot starve its heartbeat.
	std::atomic<bool> tcp_control_write_pending_{false};
	std::mutex heartbeat_wait_mutex_;
	std::condition_variable heartbeat_wait_cv_;
	std::mutex rotation_wait_mutex_;
	std::condition_variable rotation_wait_cv_;
	std::atomic<bool> tcp_old_writes_blocked_{false};
	// Set for the whole replacement attempt. The authenticated FREEZE phase
	// turns on the write gate before NEW negotiation can consume any reserved
	// old-generation control capacity.
	std::atomic<bool> tcp_replacement_active_{false};
	std::atomic<std::int64_t> tcp_handoff_deadline_ticks_{0};
	std::atomic<bool> tcp_handoff_decision_attempted_{false};
	std::mutex drain_wait_mutex_;
	std::condition_variable drain_wait_cv_;
	std::array<std::uint8_t, kSessionReplacementNonceSize> drain_nonce_{};
	bool replacement_freeze_acknowledged_{false};
	bool drain_acknowledged_{false};
	bool drain_barrier_received_{false};
	std::atomic<std::uint64_t> heartbeat_sequence_{0U};
	std::atomic<std::uint64_t> heartbeat_last_ack_sequence_{0U};
	std::atomic<std::uint64_t> heartbeat_acknowledgements_{0U};
	std::atomic<std::int64_t> last_authenticated_receive_ticks_{0};
	mutable std::mutex message_mutex_;
	std::vector<std::string> received_messages_;
	std::size_t received_message_bytes_ = 0;
#ifdef TRUETUNNEL_INTEGRATION_TEST
	std::mutex integration_observer_mutex_;
	IntegrationPacketObserver integration_packet_observer_;
	IntegrationEndpointObserver integration_endpoint_observer_;
	IntegrationEndpointAttemptObserver integration_endpoint_attempt_observer_;
	std::vector<std::string> integration_resolved_ipv4_addresses_;
	std::atomic<bool> integration_force_tcp_session_replacement_{false};
#endif
	std::thread tun_thread_;
	std::thread tls_thread_;
	std::thread heartbeat_thread_;
	std::thread heartbeat_watchdog_thread_;
	std::thread tcp_rotation_thread_;
	std::atomic<std::uint64_t> session_replacement_attempts_{0U};
	std::atomic<std::uint64_t> session_replacement_successes_{0U};
	std::atomic<std::uint64_t> session_replacement_failures_{0U};
	std::atomic<std::uint64_t> last_handoff_pause_microseconds_{0U};
	bool nat_public_installed_ = false;
	bool nat_private_installed_ = false;
	std::string nat_public_alias_;
	std::string nat_private_alias_;
	std::optional<Ipv4RouteGuard> tunnel_route_;
	std::optional<Ipv4RouteGuard> protected_route_;
	std::optional<FirewallRuleGuard> icmp_firewall_rule_;
};
