#include "SecureSocket.h"

#include "SchannelSocket.h"
#include "SharedSecret.h"
#include "WolfSslDatagramSocket.h"

#include <span>
#include <stdexcept>
#include <utility>

namespace secure {
namespace {

[[nodiscard]] std::span<const std::uint8_t> password_bytes(
    const std::string& password) noexcept {
    return {reinterpret_cast<const std::uint8_t*>(password.data()), password.size()};
}

} // namespace

SecureSocket::SecureSocket(const SOCKET socket,
                           const std::string& password,
                           const bool is_server,
                           const CipherSuite suite,
                           TrafficKeyRotationPolicy rotation_policy)
    : s_{socket},
      owns_socket_{true},
      is_server_{is_server},
      transport_type_{TransportType::Stream},
      suite_{suite},
      rotation_policy_{rotation_policy} {
    if (socket == INVALID_SOCKET) {
        throw std::invalid_argument("Invalid socket");
    }
    require_valid_shared_secret(password);
    schannel_ = std::make_unique<SchannelSocket>(
        socket, password_bytes(password), is_server_, suite_, rotation_policy_);
}

SecureSocket::SecureSocket(const SOCKET socket,
                           std::unique_ptr<DatagramTransport> transport,
                           const std::string& password,
                           const bool is_server,
                           const CipherSuite suite,
                           const bool owns_socket,
                           TrafficKeyRotationPolicy rotation_policy)
    : s_{socket},
      owns_socket_{owns_socket},
      is_server_{is_server},
      transport_type_{TransportType::Datagram},
      suite_{suite},
      rotation_policy_{rotation_policy} {
    if (owns_socket_ && socket == INVALID_SOCKET) {
        throw std::invalid_argument("Invalid socket");
    }
    require_valid_shared_secret(password);
    wolfssl_ = std::make_unique<WolfSslDatagramSocket>(
        std::move(transport), password_bytes(password), is_server_, suite_,
        rotation_policy_);
}

SecureSocket::SecureSocket(const SOCKET socket,
                           std::unique_ptr<DatagramTransport> transport,
                           PreparedWolfSslServerSession prepared,
                           const bool owns_socket,
                           TrafficKeyRotationPolicy rotation_policy)
    : s_{socket},
      owns_socket_{owns_socket},
      is_server_{true},
      transport_type_{TransportType::Datagram},
      suite_{CipherSuite::Aes256Gcm},
      rotation_policy_{rotation_policy} {
    if (owns_socket_ && socket == INVALID_SOCKET) {
        throw std::invalid_argument("Invalid socket");
    }
    if (!prepared) {
        throw std::invalid_argument("DTLS prepared server session is empty");
    }
    wolfssl_ = std::make_unique<WolfSslDatagramSocket>(
        std::move(transport), std::move(prepared), rotation_policy_);
}

SecureSocket::~SecureSocket() {
    close();
}

void SecureSocket::handshake() {
    std::lock_guard lock{handshake_mutex_};
    if (closing_.load(std::memory_order_acquire)) {
        throw std::runtime_error("SecureSocket is closing");
    }
    if (handshook_.load(std::memory_order_acquire)) {
        return;
    }
    if (handshake_attempted_) {
        throw std::runtime_error("SecureSocket handshake cannot be retried");
    }
    handshake_attempted_ = true;

    if (transport_type_ == TransportType::Stream) {
        if (!schannel_) {
            throw std::runtime_error("Schannel transport is not initialized");
        }
        schannel_->handshake();
    } else {
        if (!wolfssl_) {
            throw std::runtime_error("Datagram transport is not initialized");
        }
        wolfssl_->handshake();
    }

    handshook_.store(true, std::memory_order_release);
}

int SecureSocket::send_record(const std::uint8_t type,
                              const std::uint8_t* data,
                              const std::uint16_t length) {
    if (!handshook_.load(std::memory_order_acquire)) {
        throw std::runtime_error("handshake not done");
    }

    std::unique_lock<std::timed_mutex> lock{send_mutex_};
    if (closing_.load(std::memory_order_acquire) ||
        !handshook_.load(std::memory_order_acquire)) {
        throw std::runtime_error("SecureSocket is closing");
    }
    if (transport_type_ == TransportType::Stream) {
        try {
            return schannel_->send_record(type, data, length);
        } catch (...) {
            // A stream write can fail after emitting only part of one TLS
            // record. Reusing that byte stream would desynchronize the peer,
            // so make every TCP/TLS write failure terminal for this session.
            lock.unlock();
            close();
            throw;
        }
    }
    return wolfssl_->send_record(type, data, length);
}

int SecureSocket::send_record_until(
    const std::uint8_t type,
    const std::uint8_t* data,
    const std::uint16_t length,
    const std::chrono::steady_clock::time_point deadline) {
    if (transport_type_ != TransportType::Stream || !schannel_) {
        throw std::runtime_error(
            "Absolute record deadlines are only available for TCP/TLS");
    }
    if (!handshook_.load(std::memory_order_acquire)) {
        throw std::runtime_error("handshake not done");
    }
    if (std::chrono::steady_clock::now() >= deadline) {
        throw std::runtime_error("TCP/TLS application write deadline expired");
    }

    std::unique_lock<std::timed_mutex> lock{send_mutex_, std::defer_lock};
    if (!lock.try_lock_until(deadline)) {
        throw std::runtime_error("TCP/TLS application write deadline expired");
    }
    if (closing_.load(std::memory_order_acquire) ||
        !handshook_.load(std::memory_order_acquire)) {
        throw std::runtime_error("SecureSocket is closing");
    }
    try {
        return schannel_->send_record_until(type, data, length, deadline);
    } catch (...) {
        // The absolute deadline can expire after a partial ciphertext write.
        // Never resume a possibly truncated TLS stream.
        lock.unlock();
        close();
        throw;
    }
}

int SecureSocket::recv_record(std::uint8_t& type,
                              std::uint8_t* output,
                              const std::size_t capacity) {
    if (!handshook_.load(std::memory_order_acquire)) {
        throw std::runtime_error("handshake not done");
    }

    std::lock_guard lock{recv_mutex_};
    if (closing_.load(std::memory_order_acquire) ||
        !handshook_.load(std::memory_order_acquire)) {
        return -1;
    }
    if (transport_type_ == TransportType::Stream) {
        return schannel_->recv_record(type, output, capacity);
    }
    return wolfssl_->recv_record(type, output, capacity);
}

int SecureSocket::recv_record_until(
    std::uint8_t& type,
    std::uint8_t* output,
    const std::size_t capacity,
    const std::chrono::steady_clock::time_point deadline) {
    if (transport_type_ != TransportType::Stream || !schannel_) {
        throw std::runtime_error(
            "Absolute record deadlines are only available for TCP/TLS");
    }
    if (!handshook_.load(std::memory_order_acquire)) {
        throw std::runtime_error("handshake not done");
    }
    if (std::chrono::steady_clock::now() >= deadline) {
        throw std::runtime_error("TCP/TLS application read deadline expired");
    }

    std::unique_lock<std::timed_mutex> lock{recv_mutex_, std::defer_lock};
    if (!lock.try_lock_until(deadline)) {
        throw std::runtime_error("TCP/TLS application read deadline expired");
    }
    if (closing_.load(std::memory_order_acquire) ||
        !handshook_.load(std::memory_order_acquire)) {
        return -1;
    }
    return schannel_->recv_record_until(type, output, capacity, deadline);
}

TrafficKeyRotationStats SecureSocket::rotation_stats() const noexcept {
    if (transport_type_ == TransportType::Stream && schannel_) {
        return schannel_->rotation_stats();
    }
    if (transport_type_ == TransportType::Datagram && wolfssl_) {
        return wolfssl_->rotation_stats();
    }
    return {};
}

std::array<std::uint8_t, 32> SecureSocket::continuity_binding() const {
    if (transport_type_ != TransportType::Stream || !schannel_) {
        throw std::runtime_error(
            "Session continuity binding is only available for TCP/TLS");
    }
    return schannel_->continuity_binding();
}

std::array<std::uint8_t, 32> SecureSocket::replacement_proof(
    const std::span<const std::uint8_t> request_nonce,
    const std::span<const std::uint8_t> assigned_ipv4,
    const std::span<const std::uint8_t> new_binding) const {
    if (transport_type_ != TransportType::Stream || !schannel_) {
        throw std::runtime_error(
            "Session replacement proof is only available for TCP/TLS");
    }
    return schannel_->replacement_proof(
        request_nonce, assigned_ipv4, new_binding);
}

std::array<std::uint8_t, 32> SecureSocket::replacement_proof(
    const std::array<std::uint8_t, 32>& old_binding,
    const std::array<std::uint8_t, 32>& new_binding,
    const std::span<const std::uint8_t> request_nonce,
    const std::span<const std::uint8_t> assigned_ipv4) {
    return SchannelSocket::replacement_proof(
        old_binding, new_binding, request_nonce, assigned_ipv4);
}

#ifdef TRUETUNNEL_SECURE_TRANSPORT_TEST
void SecureSocket::set_test_partial_write_failure_after(
    const std::size_t ciphertext_bytes) {
    if (transport_type_ != TransportType::Stream || !schannel_) {
        throw std::runtime_error(
            "Partial-write injection is only available for TCP/TLS tests");
    }
    schannel_->set_test_partial_write_failure_after(ciphertext_bytes);
}
#endif

void SecureSocket::close() noexcept {
    std::lock_guard close_lock{close_mutex_};
    if (closed_) {
        return;
    }
    closing_.store(true, std::memory_order_release);

    // Provider shutdown is deliberately attempted before waiting on the
    // wrapper I/O locks. It closes the datagram transport and may send a
    // best-effort close_notify, while raw shutdown below wakes a blocked
    // Winsock handshake/read/write without invalidating the descriptor.
    if (transport_type_ == TransportType::Stream && schannel_) {
        schannel_->shutdown();
    } else if (transport_type_ == TransportType::Datagram && wolfssl_) {
        wolfssl_->shutdown();
    }

    const SOCKET socket = s_.load(std::memory_order_acquire);
    if (owns_socket_ && socket != INVALID_SOCKET) {
        (void)::shutdown(socket, SD_BOTH);
    }

    // No provider call can remain active when closesocket runs. This also
    // prevents a call that passed its initial handshake check from entering
    // after closure; send/receive recheck closing_ under their I/O lock.
    {
        std::scoped_lock io_locks{handshake_mutex_, send_mutex_, recv_mutex_};
        handshook_.store(false, std::memory_order_release);
        const SOCKET quiesced_socket =
            s_.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
        if (owns_socket_ && quiesced_socket != INVALID_SOCKET) {
            (void)::closesocket(quiesced_socket);
        }
    }
    closed_ = true;
}

} // namespace secure
