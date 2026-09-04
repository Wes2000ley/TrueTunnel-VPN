#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>

#include "CipherSuite.h"
#include "Transport.h"
#include "TrafficKeyRotation.h"

#include <atomic>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <span>

namespace secure {
	class SchannelSocket;
	class WolfSslDatagramSocket;
	class PreparedWolfSslServerSession;

	enum class TransportType {
		Stream,
		Datagram
	};

	class SecureSocket {
	public:
		SecureSocket(SOCKET s,
		             const std::string& password,
		             bool is_server,
		             CipherSuite suite,
		             TrafficKeyRotationPolicy rotation_policy = {});
		SecureSocket(SOCKET s,
		             std::unique_ptr<DatagramTransport> transport,
		             const std::string& password,
		             bool is_server,
		             CipherSuite suite,
		             bool owns_socket,
		             TrafficKeyRotationPolicy rotation_policy = {});
		SecureSocket(SOCKET s,
		             std::unique_ptr<DatagramTransport> transport,
		             PreparedWolfSslServerSession prepared,
		             bool owns_socket,
		             TrafficKeyRotationPolicy rotation_policy = {});
		~SecureSocket();

		// TCP negotiates native Schannel TLS 1.3 and exporter-bound password auth.
		// UDP negotiates wolfSSL DTLS 1.3 with forward-secret ECDHE-PSK.
		void handshake();

		// Send a framed, protected record with an app-level type.
		// Returns plaintext bytes sent; transport and protocol failures throw.
		int send_record(uint8_t type, const uint8_t* data, uint16_t len);
		// TCP-only absolute-deadline variants used by the bounded session
		// handoff. They include time spent waiting for this wrapper's I/O lock.
		int send_record_until(
			uint8_t type,
			const uint8_t* data,
			uint16_t len,
			std::chrono::steady_clock::time_point deadline);

		// Returns the plaintext length, or -1 for closure/rejection, and sets type.
		int recv_record(uint8_t& type, uint8_t* out, size_t cap);
		int recv_record_until(
			uint8_t& type,
			uint8_t* out,
			size_t cap,
			std::chrono::steady_clock::time_point deadline);

		[[nodiscard]] TrafficKeyRotationStats rotation_stats() const noexcept;

		// TCP-only exporter-derived continuity material used to authenticate a
		// make-before-break full-session replacement.  UDP has an in-place DTLS
		// KeyUpdate path and intentionally does not expose this API.
		[[nodiscard]] std::array<std::uint8_t, 32> continuity_binding() const;
		[[nodiscard]] std::array<std::uint8_t, 32> replacement_proof(
			std::span<const std::uint8_t> request_nonce,
			std::span<const std::uint8_t> assigned_ipv4,
			std::span<const std::uint8_t> new_binding) const;
		[[nodiscard]] static std::array<std::uint8_t, 32> replacement_proof(
			const std::array<std::uint8_t, 32>& old_binding,
			const std::array<std::uint8_t, 32>& new_binding,
			std::span<const std::uint8_t> request_nonce,
			std::span<const std::uint8_t> assigned_ipv4);

#ifdef TRUETUNNEL_SECURE_TRANSPORT_TEST
		void set_test_partial_write_failure_after(std::size_t ciphertext_bytes);
#endif

		// Best-effort graceful protocol shutdown followed by socket closure.
		// Safe to call concurrently with handshake/send/receive and idempotent
		// across concurrent callers.
		void close() noexcept;

		SOCKET native() const noexcept { return s_.load(std::memory_order_acquire); }

	private:
		std::atomic<SOCKET> s_{INVALID_SOCKET};
		bool owns_socket_{true};
		bool is_server_{false};
		TransportType transport_type_{TransportType::Stream};
		CipherSuite suite_{CipherSuite::Aes256Gcm};
		std::unique_ptr<SchannelSocket> schannel_;
		std::unique_ptr<WolfSslDatagramSocket> wolfssl_;

		std::mutex handshake_mutex_;
		std::timed_mutex send_mutex_;
		std::timed_mutex recv_mutex_;
		std::mutex close_mutex_;
		TrafficKeyRotationPolicy rotation_policy_{};
		bool handshake_attempted_{false};
		bool closed_{false};
		std::atomic<bool> closing_{false};
		std::atomic<bool> handshook_{false};
	};

} // namespace secure
