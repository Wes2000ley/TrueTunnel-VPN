#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#include "secure/SecureSocket.h"
#include "secure/SharedSecret.h"
#include "secure/WolfSslDatagramSocket.h"
#include "security/FixedWindowRateLimiter.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <exception>
#include <functional>
#include <future>
#include <iostream>
#include <memory>
#include <mutex>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {

constexpr DWORD kSocketTimeoutMilliseconds = 10'000;
constexpr std::string_view kPassword =
    "QbS8dV16wlVZZO8kchOpKO_HLQHLlNpzQZNi31KK1-U";
constexpr std::string_view kOtherPassword =
    "orquriBCRQKit5UrL4rjplxCYkLWl-Ibmfhe5pCSJ1o";

class Winsock final {
public:
    Winsock() {
        WSADATA data{};
        if (::WSAStartup(MAKEWORD(2, 2), &data) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
    }
    ~Winsock() { ::WSACleanup(); }

    Winsock(const Winsock&) = delete;
    Winsock& operator=(const Winsock&) = delete;
};

class SocketOwner final {
public:
    explicit SocketOwner(const SOCKET socket = INVALID_SOCKET) noexcept
        : socket_{socket} {}
    ~SocketOwner() {
        if (socket_ != INVALID_SOCKET) {
            ::closesocket(socket_);
        }
    }

    SocketOwner(const SocketOwner&) = delete;
    SocketOwner& operator=(const SocketOwner&) = delete;

    SocketOwner(SocketOwner&& other) noexcept : socket_{other.release()} {}
    SocketOwner& operator=(SocketOwner&& other) noexcept {
        if (this != &other) {
            if (socket_ != INVALID_SOCKET) {
                ::closesocket(socket_);
            }
            socket_ = other.release();
        }
        return *this;
    }

    [[nodiscard]] SOCKET get() const noexcept { return socket_; }
    [[nodiscard]] SOCKET release() noexcept {
        return std::exchange(socket_, INVALID_SOCKET);
    }

private:
    SOCKET socket_{INVALID_SOCKET};
};

[[noreturn]] void fail(const std::string_view message) {
    throw std::runtime_error(std::string(message));
}

void require(const bool condition, const std::string_view message) {
    if (!condition) {
        fail(message);
    }
}

[[nodiscard]] std::string exception_text(const std::exception_ptr& error) {
    if (!error) {
        return {};
    }
    try {
        std::rethrow_exception(error);
    } catch (const std::exception& exception) {
        return exception.what();
    } catch (...) {
        return "unknown exception";
    }
}

void set_socket_timeouts(const SOCKET socket) {
    const DWORD timeout = kSocketTimeoutMilliseconds;
    if (::setsockopt(socket,
                     SOL_SOCKET,
                     SO_RCVTIMEO,
                     reinterpret_cast<const char*>(&timeout),
                     sizeof(timeout)) == SOCKET_ERROR ||
        ::setsockopt(socket,
                     SOL_SOCKET,
                     SO_SNDTIMEO,
                     reinterpret_cast<const char*>(&timeout),
                     sizeof(timeout)) == SOCKET_ERROR) {
        fail("setsockopt timeout failed");
    }
}

struct Listener {
    SocketOwner socket;
    sockaddr_in address{};
};

[[nodiscard]] Listener make_listener() {
    Listener listener{SocketOwner{::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)}, {}};
    if (listener.socket.get() == INVALID_SOCKET) {
        fail("listener socket creation failed");
    }

    listener.address.sin_family = AF_INET;
    listener.address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    listener.address.sin_port = 0;
    if (::bind(listener.socket.get(),
               reinterpret_cast<const sockaddr*>(&listener.address),
               sizeof(listener.address)) == SOCKET_ERROR) {
        fail("bind failed");
    }
    if (::listen(listener.socket.get(), 1) == SOCKET_ERROR) {
        fail("listen failed");
    }

    int address_size = sizeof(listener.address);
    if (::getsockname(listener.socket.get(),
                      reinterpret_cast<sockaddr*>(&listener.address),
                      &address_size) == SOCKET_ERROR) {
        fail("getsockname failed");
    }
    return listener;
}

[[nodiscard]] SocketOwner connect_client(const sockaddr_in& address) {
    SocketOwner client{::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
    if (client.get() == INVALID_SOCKET) {
        fail("client socket creation failed");
    }
    set_socket_timeouts(client.get());
    if (::connect(client.get(),
                  reinterpret_cast<const sockaddr*>(&address),
                  sizeof(address)) == SOCKET_ERROR) {
        fail("connect failed");
    }
    return client;
}

using EndpointAction = std::function<void(secure::SecureSocket&)>;

void run_authenticated_session(const std::string& client_password,
                               const std::string& server_password,
                               EndpointAction server_action,
                               EndpointAction client_action) {
    Listener listener = make_listener();
    std::exception_ptr server_error;

    std::thread server_thread{[&]() {
        try {
            SocketOwner accepted{::accept(listener.socket.get(), nullptr, nullptr)};
            if (accepted.get() == INVALID_SOCKET) {
                fail("accept failed");
            }
            set_socket_timeouts(accepted.get());

            secure::SecureSocket tls{accepted.get(),
                                     server_password,
                                     true,
                                     secure::CipherSuite::Aes256Gcm};
            (void)accepted.release();
            tls.handshake();
            server_action(tls);
            tls.close();
        } catch (...) {
            server_error = std::current_exception();
        }
    }};

    std::exception_ptr client_error;
    try {
        SocketOwner client = connect_client(listener.address);
        secure::SecureSocket tls{client.get(),
                                 client_password,
                                 false,
                                 secure::CipherSuite::Aes256Gcm};
        (void)client.release();
        tls.handshake();
        client_action(tls);
        tls.close();
    } catch (...) {
        client_error = std::current_exception();
    }

    server_thread.join();
    if (client_error || server_error) {
        throw std::runtime_error(
            "loopback session failed (client: " + exception_text(client_error) +
            "; server: " + exception_text(server_error) + ")");
    }
}

void test_large_records_and_framing() {
    std::vector<std::uint8_t> expected(65'535U);
    for (std::size_t index = 0; index < expected.size(); ++index) {
        expected[index] = static_cast<std::uint8_t>((index * 131U + 17U) & 0xFFU);
    }

    run_authenticated_session(
        std::string{kPassword},
        std::string{kPassword},
        [&](secure::SecureSocket& server) {
            std::vector<std::uint8_t> received(expected.size());
            std::uint8_t type = 0;
            const int size = server.recv_record(type, received.data(), received.size());
            require(type == 0x31U, "large record type changed");
            require(size == static_cast<int>(expected.size()), "large record size changed");
            require(received == expected, "large record payload changed");

            std::array<std::uint8_t, 1> empty_output{};
            const int empty_size =
                server.recv_record(type, empty_output.data(), empty_output.size());
            require(type == 0x32U && empty_size == 0, "zero-length record failed");

            constexpr std::string_view acknowledgement = "native-tls-ok";
            require(server.send_record(
                        0x33U,
                        reinterpret_cast<const std::uint8_t*>(acknowledgement.data()),
                        static_cast<std::uint16_t>(acknowledgement.size())) ==
                        static_cast<int>(acknowledgement.size()),
                    "server acknowledgement send failed");
        },
        [&](secure::SecureSocket& client) {
            require(client.send_record(0x31U,
                                       expected.data(),
                                       static_cast<std::uint16_t>(expected.size())) ==
                        static_cast<int>(expected.size()),
                    "large record send failed");
            require(client.send_record(0x32U, nullptr, 0) == 0,
                    "zero-length send failed");

            std::array<std::uint8_t, 32> acknowledgement{};
            std::uint8_t type = 0;
            const int size =
                client.recv_record(type, acknowledgement.data(), acknowledgement.size());
            require(type == 0x33U, "acknowledgement type changed");
            require(std::string_view{
                        reinterpret_cast<const char*>(acknowledgement.data()),
                        static_cast<std::size_t>(size)} == "native-tls-ok",
                    "acknowledgement payload changed");
        });
}

void test_small_buffer_does_not_desynchronize_stream() {
    run_authenticated_session(
        std::string{kPassword},
        std::string{kPassword},
        [](secure::SecureSocket& server) {
            std::array<std::uint8_t, 4> too_small{};
            std::uint8_t type = 0;
            require(server.recv_record(type, too_small.data(), too_small.size()) == -1,
                    "undersized destination should reject the record");

            std::array<std::uint8_t, 16> next{};
            const int next_size = server.recv_record(type, next.data(), next.size());
            require(type == 0x42U, "stream did not recover after a small destination");
            require(std::string_view{reinterpret_cast<const char*>(next.data()),
                                     static_cast<std::size_t>(next_size)} == "next-record",
                    "record after small destination was corrupted");
        },
        [](secure::SecureSocket& client) {
            constexpr std::string_view first = "payload-too-large-for-destination";
            constexpr std::string_view second = "next-record";
            (void)client.send_record(
                0x41U,
                reinterpret_cast<const std::uint8_t*>(first.data()),
                static_cast<std::uint16_t>(first.size()));
            (void)client.send_record(
                0x42U,
                reinterpret_cast<const std::uint8_t*>(second.data()),
                static_cast<std::uint16_t>(second.size()));
        });
}

[[nodiscard]] std::vector<std::uint8_t> make_concurrent_payload(
    const std::uint8_t seed,
    const std::size_t message_index,
    const std::size_t payload_size = 32U * 1024U) {
    // Large enough to exceed ordinary TCP send buffers across the full test,
    // proving that a blocked writer does not prevent the receive path running.
    std::vector<std::uint8_t> payload(payload_size);
    for (std::size_t index = 0; index < payload.size(); ++index) {
        payload[index] = static_cast<std::uint8_t>(
            (static_cast<std::size_t>(seed) + message_index * 17U + index * 31U) &
            0xFFU);
    }
    return payload;
}

void exercise_concurrent_io(secure::SecureSocket& tls,
                            const std::uint8_t send_type,
                            const std::uint8_t receive_type,
                            const std::uint8_t send_seed,
                            const std::uint8_t receive_seed,
                            const std::size_t payload_size = 32U * 1024U,
                            const std::size_t message_count = 32U) {
    std::exception_ptr send_error;
    std::thread sender{[&]() {
        try {
            for (std::size_t index = 0; index < message_count; ++index) {
                const auto payload =
                    make_concurrent_payload(send_seed, index, payload_size);
                require(tls.send_record(send_type,
                                        payload.data(),
                                        static_cast<std::uint16_t>(payload.size())) ==
                            static_cast<int>(payload.size()),
                        "concurrent send failed");
            }
        } catch (...) {
            send_error = std::current_exception();
        }
    }};

    std::exception_ptr receive_error;
    try {
        for (std::size_t index = 0; index < message_count; ++index) {
            const auto expected =
                make_concurrent_payload(receive_seed, index, payload_size);
            std::vector<std::uint8_t> received(expected.size());
            std::uint8_t type = 0;
            const int size = tls.recv_record(type, received.data(), received.size());
            require(type == receive_type, "concurrent record type changed");
            require(size == static_cast<int>(expected.size()),
                    "concurrent record size changed");
            require(received == expected, "concurrent record payload changed");
        }
    } catch (...) {
        receive_error = std::current_exception();
    }

    sender.join();
    if (receive_error) {
        std::rethrow_exception(receive_error);
    }
    if (send_error) {
        std::rethrow_exception(send_error);
    }
}

void test_concurrent_bidirectional_io() {
    run_authenticated_session(
        std::string{kPassword},
        std::string{kPassword},
        [](secure::SecureSocket& server) {
            exercise_concurrent_io(server, 0x52U, 0x51U, 0xA0U, 0x10U);
        },
        [](secure::SecureSocket& client) {
            exercise_concurrent_io(client, 0x51U, 0x52U, 0x10U, 0xA0U);
        });
}

void test_wrong_password_is_rejected_by_both_peers() {
    Listener listener = make_listener();
    std::exception_ptr server_error;

    std::thread server_thread{[&]() {
        try {
            SocketOwner accepted{::accept(listener.socket.get(), nullptr, nullptr)};
            if (accepted.get() == INVALID_SOCKET) {
                fail("accept failed");
            }
            set_socket_timeouts(accepted.get());
            secure::SecureSocket tls{accepted.get(),
                                     std::string{kPassword},
                                     true,
                                     secure::CipherSuite::Aes256Gcm};
            (void)accepted.release();
            tls.handshake();
            fail("server accepted a wrong password");
        } catch (...) {
            server_error = std::current_exception();
        }
    }};

    std::exception_ptr client_error;
    try {
        SocketOwner client = connect_client(listener.address);
        secure::SecureSocket tls{client.get(),
                                 std::string{kOtherPassword},
                                 false,
                                 secure::CipherSuite::Aes256Gcm};
        (void)client.release();
        tls.handshake();
    } catch (...) {
        client_error = std::current_exception();
    }

    server_thread.join();
    require(client_error != nullptr, "client accepted a wrong password");
    require(server_error != nullptr, "server accepted a wrong password");
    require(exception_text(server_error).find("password authentication failed") !=
                std::string::npos,
            "server did not reject the mismatched password proof");
}

void test_strict_tcp_profile_validation() {
    SocketOwner socket{::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
    require(socket.get() != INVALID_SOCKET, "socket creation failed");

    bool cipher_rejected = false;
    try {
        secure::SecureSocket tls{socket.get(),
                                 std::string{kPassword},
                                 false,
                                 secure::CipherSuite::Aes128Gcm};
    } catch (const std::invalid_argument&) {
        cipher_rejected = true;
    }
    require(cipher_rejected, "TCP accepted a cipher outside the strict TLS profile");

    bool empty_password_rejected = false;
    try {
        secure::SecureSocket tls{socket.get(),
                                 "",
                                 false,
                                 secure::CipherSuite::Aes256Gcm};
    } catch (const std::invalid_argument&) {
        empty_password_rejected = true;
    }
    require(empty_password_rejected, "TCP accepted an empty password");

    bool human_password_rejected = false;
    try {
        secure::SecureSocket tls{socket.get(),
                                 "12345678901234567890",
                                 false,
                                 secure::CipherSuite::Aes256Gcm};
    } catch (const std::invalid_argument&) {
        human_password_rejected = true;
    }
    require(human_password_rejected,
            "TCP accepted a human-memorable password instead of a generated key");
}

void test_close_interrupts_stalled_handshake() {
    Listener listener = make_listener();
    SocketOwner client = connect_client(listener.address);
    SocketOwner accepted{::accept(listener.socket.get(), nullptr, nullptr)};
    require(accepted.get() != INVALID_SOCKET, "accept failed");
    set_socket_timeouts(accepted.get());

    secure::SecureSocket tls{accepted.get(),
                             std::string{kPassword},
                             true,
                             secure::CipherSuite::Aes256Gcm};
    (void)accepted.release();

    std::exception_ptr handshake_error;
    std::thread handshake_thread{[&]() {
        try {
            tls.handshake();
        } catch (...) {
            handshake_error = std::current_exception();
        }
    }};

    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    tls.close();
    handshake_thread.join();
    require(handshake_error != nullptr,
            "closing the socket did not interrupt a stalled TLS handshake");
}

void test_close_interrupts_authenticated_tls_receive() {
    std::atomic<bool> server_closed{false};
    run_authenticated_session(
        std::string{kPassword},
        std::string{kPassword},
        [&server_closed](secure::SecureSocket& server) {
            std::array<std::uint8_t, 32> buffer{};
            std::uint8_t type = 0;
            std::exception_ptr receive_error;
            int receive_result = 0;
            const auto started = std::chrono::steady_clock::now();
            std::thread first_closer{[&server]() {
                std::this_thread::sleep_for(std::chrono::milliseconds{50});
                server.close();
            }};
            std::thread second_closer{[&server]() {
                std::this_thread::sleep_for(std::chrono::milliseconds{50});
                server.close();
            }};
            try {
                receive_result =
                    server.recv_record(type, buffer.data(), buffer.size());
            } catch (...) {
                receive_error = std::current_exception();
            }
            first_closer.join();
            second_closer.join();
            const auto elapsed = std::chrono::steady_clock::now() - started;
            require(receive_result < 0 || receive_error != nullptr,
                    "TLS receive unexpectedly survived concurrent close");
            require(elapsed < std::chrono::seconds{2},
                    "TLS close did not promptly interrupt an authenticated receive");
            require(server.native() == INVALID_SOCKET,
                    "TLS close left the native socket reachable");
            server_closed.store(true, std::memory_order_release);
        },
        [&server_closed](secure::SecureSocket&) {
            const auto deadline =
                std::chrono::steady_clock::now() + std::chrono::seconds{3};
            while (!server_closed.load(std::memory_order_acquire) &&
                   std::chrono::steady_clock::now() < deadline) {
                std::this_thread::sleep_for(std::chrono::milliseconds{10});
            }
            require(server_closed.load(std::memory_order_acquire),
                    "TLS receive-close test did not finish");
        });
}

void test_short_dtls_psk_identities_are_rejected_safely() {
    const std::array<char, 1> empty_identity{'\0'};
    const std::array<char, 5> short_identity{'T', 'r', 'u', 'e', '\0'};
    const std::array<char, 20> exact_identity{
        'T', 'r', 'u', 'e', 'T', 'u', 'n', 'n', 'e', 'l', '-', 'D', 'T',
        'L', 'S', '-', 'v', '1', '\0', '\0'};
    const std::array<char, 21> overlong_identity{
        'T', 'r', 'u', 'e', 'T', 'u', 'n', 'n', 'e', 'l', '-', 'D', 'T',
        'L', 'S', '-', 'v', '1', 'X', '\0', '\0'};

    require(!secure::detail::dtls_psk_identity_matches(nullptr),
            "DTLS accepted a null PSK identity");
    require(!secure::detail::dtls_psk_identity_matches(empty_identity.data()),
            "DTLS accepted an empty PSK identity");
    require(!secure::detail::dtls_psk_identity_matches(short_identity.data()),
            "DTLS accepted a short PSK identity");
    require(secure::detail::dtls_psk_identity_matches(exact_identity.data()),
            "DTLS rejected its exact PSK identity");
    require(!secure::detail::dtls_psk_identity_matches(overlong_identity.data()),
            "DTLS accepted an overlong PSK identity");
}

struct DatagramQueue {
    std::mutex mutex;
    std::condition_variable ready;
    std::deque<std::vector<std::uint8_t>> packets;
    bool closed{false};
};

struct UdpSocketPair {
    SocketOwner client;
    SocketOwner server;
};

[[nodiscard]] bool same_socket_address(const sockaddr_storage& left,
                                       const int left_length,
                                       const sockaddr_storage& right,
                                       const int right_length) noexcept {
    if (left_length != right_length || left.ss_family != right.ss_family) {
        return false;
    }
    if (left.ss_family == AF_INET &&
        left_length >= static_cast<int>(sizeof(sockaddr_in))) {
        const auto& lhs = reinterpret_cast<const sockaddr_in&>(left);
        const auto& rhs = reinterpret_cast<const sockaddr_in&>(right);
        return lhs.sin_port == rhs.sin_port &&
               lhs.sin_addr.s_addr == rhs.sin_addr.s_addr;
    }
    if (left.ss_family == AF_INET6 &&
        left_length >= static_cast<int>(sizeof(sockaddr_in6))) {
        const auto& lhs = reinterpret_cast<const sockaddr_in6&>(left);
        const auto& rhs = reinterpret_cast<const sockaddr_in6&>(right);
        return lhs.sin6_port == rhs.sin6_port &&
               lhs.sin6_scope_id == rhs.sin6_scope_id &&
               std::memcmp(&lhs.sin6_addr, &rhs.sin6_addr,
                           sizeof(lhs.sin6_addr)) == 0;
    }
    return false;
}

[[nodiscard]] SocketOwner make_bound_udp_socket(sockaddr_in& address) {
    SocketOwner socket{::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)};
    if (socket.get() == INVALID_SOCKET) {
        fail("UDP socket creation failed");
    }

    BOOL report_udp_resets = FALSE;
    DWORD bytes_returned = 0U;
    if (::WSAIoctl(socket.get(),
                   SIO_UDP_CONNRESET,
                   &report_udp_resets,
                   sizeof(report_udp_resets),
                   nullptr,
                   0U,
                   &bytes_returned,
                   nullptr,
                   nullptr) == SOCKET_ERROR) {
        fail("WSAIoctl(SIO_UDP_CONNRESET) failed");
    }

    address = {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (::bind(socket.get(),
               reinterpret_cast<const sockaddr*>(&address),
               sizeof(address)) == SOCKET_ERROR) {
        fail("UDP bind failed");
    }

    int address_size = sizeof(address);
    if (::getsockname(socket.get(),
                      reinterpret_cast<sockaddr*>(&address),
                      &address_size) == SOCKET_ERROR) {
        fail("UDP getsockname failed");
    }
    return socket;
}

[[nodiscard]] UdpSocketPair make_udp_socket_pair() {
    sockaddr_in client_address{};
    sockaddr_in server_address{};
    SocketOwner client = make_bound_udp_socket(client_address);
    SocketOwner server = make_bound_udp_socket(server_address);

    if (::connect(client.get(),
                  reinterpret_cast<const sockaddr*>(&server_address),
                  sizeof(server_address)) == SOCKET_ERROR) {
        fail("UDP loopback connect failed");
    }
    return UdpSocketPair{std::move(client), std::move(server)};
}

[[nodiscard]] std::unique_ptr<secure::DatagramTransport>
make_udp_peer_transport(const SOCKET socket,
                        const sockaddr_storage peer,
                        const int peer_length) {
    auto send = [socket, peer, peer_length](const std::uint8_t* data,
                                            const std::size_t size) {
        const int sent = ::sendto(
            socket,
            reinterpret_cast<const char*>(data),
            static_cast<int>(size),
            0,
            reinterpret_cast<const sockaddr*>(&peer),
            peer_length);
        if (sent != static_cast<int>(size)) {
            std::cerr << "test UDP sendto failed: " << ::WSAGetLastError()
                      << " sent=" << sent << " expected=" << size << '\n';
        }
        return sent == static_cast<int>(size)
                   ? secure::DatagramSendResult::Sent
                   : secure::DatagramSendResult::Error;
    };
    auto receive = [socket, peer, peer_length](
                       std::vector<std::uint8_t>& output,
                       const std::chrono::milliseconds timeout) {
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(socket, &readable);
        const long long wait_count = (std::max)(0LL, timeout.count());
        timeval wait{};
        wait.tv_sec = static_cast<long>(wait_count / 1'000LL);
        wait.tv_usec = static_cast<long>((wait_count % 1'000LL) * 1'000LL);
        const int ready = ::select(0, &readable, nullptr, nullptr, &wait);
        if (ready == 0) return secure::DatagramReceiveResult::Timeout;
        if (ready == SOCKET_ERROR) {
            std::cerr << "test UDP select failed: " << ::WSAGetLastError() << '\n';
            return secure::DatagramReceiveResult::Error;
        }

        sockaddr_storage from{};
        int from_length = sizeof(from);
        output.resize(2'048U);
        const int received = ::recvfrom(
            socket,
            reinterpret_cast<char*>(output.data()),
            static_cast<int>(output.size()),
            0,
            reinterpret_cast<sockaddr*>(&from),
            &from_length);
        if (received <= 0 ||
            !same_socket_address(from, from_length, peer, peer_length)) {
            std::cerr << "test UDP recvfrom/peer check failed: wsa="
                      << ::WSAGetLastError() << " received=" << received
                      << " from_len=" << from_length
                      << " peer_len=" << peer_length;
            if (from.ss_family == AF_INET && peer.ss_family == AF_INET) {
                std::cerr << " from_port="
                          << ntohs(reinterpret_cast<const sockaddr_in&>(from).sin_port)
                          << " peer_port="
                          << ntohs(reinterpret_cast<const sockaddr_in&>(peer).sin_port);
            }
            std::cerr << '\n';
            output.clear();
            return secure::DatagramReceiveResult::Error;
        }
        output.resize(static_cast<std::size_t>(received));
        return secure::DatagramReceiveResult::Received;
    };
    auto close = [socket]() noexcept {
        (void)::shutdown(socket, SD_BOTH);
    };
    return std::make_unique<secure::DatagramTransport>(
        std::move(send), std::move(receive), std::move(close));
}

[[nodiscard]] std::unique_ptr<secure::DatagramTransport>
make_udp_socket_transport(const SOCKET socket) {
    auto send = [socket](const std::uint8_t* data, const std::size_t size) {
        const int sent = ::send(socket,
                                reinterpret_cast<const char*>(data),
                                static_cast<int>(size),
                                0);
        return sent == static_cast<int>(size)
                   ? secure::DatagramSendResult::Sent
                   : secure::DatagramSendResult::Error;
    };
    auto receive = [socket](std::vector<std::uint8_t>& output,
                            const std::chrono::milliseconds timeout) {
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(socket, &readable);

        const long long wait_count = (std::max)(0LL, timeout.count());
        timeval wait{};
        wait.tv_sec = static_cast<long>(wait_count / 1'000LL);
        wait.tv_usec = static_cast<long>((wait_count % 1'000LL) * 1'000LL);
        const int ready = ::select(0, &readable, nullptr, nullptr, &wait);
        if (ready == 0) {
            return secure::DatagramReceiveResult::Timeout;
        }
        if (ready == SOCKET_ERROR) {
            return secure::DatagramReceiveResult::Error;
        }

        output.resize(2'048U);
        const int received = ::recv(
            socket,
            reinterpret_cast<char*>(output.data()),
            static_cast<int>(output.size()),
            0);
        if (received <= 0) {
            output.clear();
            return secure::DatagramReceiveResult::Error;
        }
        output.resize(static_cast<std::size_t>(received));
        return secure::DatagramReceiveResult::Received;
    };
    auto close = [socket]() noexcept {
        (void)::shutdown(socket, SD_BOTH);
    };
    return std::make_unique<secure::DatagramTransport>(
        std::move(send), std::move(receive), std::move(close));
}

void test_dtls_over_real_udp_loopback() {
    UdpSocketPair sockets = make_udp_socket_pair();
    std::array<std::uint8_t, 1'024> expected{};
    for (std::size_t index = 0; index < expected.size(); ++index) {
        expected[index] = static_cast<std::uint8_t>((index * 29U + 7U) & 0xFFU);
    }

    std::exception_ptr server_error;
    std::promise<void> admission_gate_ready;
    std::future<void> admission_gate_ready_future =
        admission_gate_ready.get_future();
    std::thread server_thread{[&server_socket = sockets.server,
                               &expected,
                               &server_error,
                               &admission_gate_ready]() {
        bool gate_ready_signalled = false;
        try {
            const SOCKET raw_socket = server_socket.get();
            auto send_to = [raw_socket](const std::uint8_t* data,
                                        const std::size_t size,
                                        const sockaddr_storage& peer,
                                        const int peer_length) {
                const int sent = ::sendto(
                    raw_socket,
                    reinterpret_cast<const char*>(data),
                    static_cast<int>(size),
                    0,
                    reinterpret_cast<const sockaddr*>(&peer),
                    peer_length);
                return sent == static_cast<int>(size);
            };
            secure::WolfSslStatelessServer gate{
                std::move(send_to),
                std::span<const std::uint8_t>{
                    reinterpret_cast<const std::uint8_t*>(kPassword.data()),
                    kPassword.size()},
                secure::CipherSuite::Aes256Gcm};

            sockaddr_storage synthetic_peer{};
            auto* const synthetic_ipv4 =
                reinterpret_cast<sockaddr_in*>(&synthetic_peer);
            synthetic_ipv4->sin_family = AF_INET;
            synthetic_ipv4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            synthetic_ipv4->sin_port = htons(49'999U);
            std::array<std::uint8_t, 48> malformed{};
            for (std::size_t attempt = 0; attempt != 256U; ++attempt) {
                malformed[0] = static_cast<std::uint8_t>(attempt);
                require(!gate.process_datagram(
                             malformed,
                             synthetic_peer,
                             sizeof(sockaddr_in)),
                        "malformed DTLS flood admitted a session");
            }

            // The malformed-datagram stress is intentionally expensive under
            // sanitizers. Do not start the real client's retransmission clock
            // until the server has finished that independent preflight.
            admission_gate_ready.set_value();
            gate_ready_signalled = true;

            const auto receive_client_hello = [raw_socket](
                                                  std::vector<std::uint8_t>& packet,
                                                  sockaddr_storage& peer,
                                                  int& peer_length) {
                packet.resize(2'048U);
                peer_length = sizeof(peer);
                const int received = ::recvfrom(
                    raw_socket,
                    reinterpret_cast<char*>(packet.data()),
                    static_cast<int>(packet.size()),
                    0,
                    reinterpret_cast<sockaddr*>(&peer),
                    &peer_length);
                require(received > 0, "real UDP DTLS ClientHello receive failed");
                packet.resize(static_cast<std::size_t>(received));
            };

            std::vector<std::uint8_t> first_hello;
            sockaddr_storage peer{};
            int peer_length = 0;
            receive_client_hello(first_hello, peer, peer_length);
            require(!gate.process_datagram(first_hello, peer, peer_length),
                    "first DTLS ClientHello bypassed the cookie challenge");

            std::vector<std::uint8_t> cookie_hello;
            sockaddr_storage cookie_peer{};
            int cookie_peer_length = 0;
            receive_client_hello(cookie_hello, cookie_peer, cookie_peer_length);

            sockaddr_in spoof_sink_address{};
            SocketOwner spoof_sink = make_bound_udp_socket(spoof_sink_address);
            sockaddr_storage spoofed_peer{};
            std::memcpy(&spoofed_peer,
                        &spoof_sink_address,
                        sizeof(spoof_sink_address));
            require(!gate.process_datagram(
                         cookie_hello, spoofed_peer, cookie_peer_length),
                    "DTLS cookie was not bound to the peer address");

            auto prepared = gate.process_datagram(
                cookie_hello, cookie_peer, cookie_peer_length);
            require(prepared.has_value(),
                    "valid address-bound DTLS cookie was not admitted");
            const auto gate_stats = gate.stats();
            require(
                gate_stats.sessions_admitted == 1U &&
                    gate_stats.cookie_challenges >= 1U &&
                    gate_stats.datagrams_processed >= 259U,
                "stateless DTLS admission counters changed: processed=" +
                    std::to_string(gate_stats.datagrams_processed) +
                    ", challenges=" +
                    std::to_string(gate_stats.cookie_challenges) +
                    ", admitted=" +
                    std::to_string(gate_stats.sessions_admitted) +
                    ", malformed=" +
                    std::to_string(gate_stats.malformed_datagrams));

            secure::SecureSocket server{
                raw_socket,
                make_udp_peer_transport(raw_socket,
                                        cookie_peer,
                                        cookie_peer_length),
                std::move(*prepared),
                true};
            (void)server_socket.release();
            server.handshake();

            std::array<std::uint8_t, 1'024> received{};
            std::uint8_t type = 0;
            const int size =
                server.recv_record(type, received.data(), received.size());
            require(type == 0x81U, "real UDP DTLS record type changed");
            require(size == static_cast<int>(expected.size()),
                    "real UDP DTLS record size changed");
            require(received == expected,
                    "real UDP DTLS record payload changed");
            require(server.send_record(
                        0x82U, received.data(), static_cast<std::uint16_t>(size)) ==
                        size,
                    "real UDP DTLS echo failed");
        } catch (...) {
            server_error = std::current_exception();
            if (!gate_ready_signalled) {
                try {
                    admission_gate_ready.set_exception(server_error);
                } catch (...) {
                    // Preserve the original server exception.
                }
            }
        }
    }};

    std::exception_ptr client_error;
    try {
        admission_gate_ready_future.get();
        const SOCKET raw_socket = sockets.client.get();
        secure::SecureSocket client{
            raw_socket,
            make_udp_socket_transport(raw_socket),
            std::string{kPassword},
            false,
            secure::CipherSuite::Aes256Gcm,
            true};
        (void)sockets.client.release();
        client.handshake();
        require(client.send_record(
                    0x81U,
                    expected.data(),
                    static_cast<std::uint16_t>(expected.size())) ==
                    static_cast<int>(expected.size()),
                "real UDP DTLS send failed");

        std::array<std::uint8_t, 1'024> echoed{};
        std::uint8_t type = 0;
        const int size = client.recv_record(type, echoed.data(), echoed.size());
        require(type == 0x82U, "real UDP DTLS echo type changed");
        require(size == static_cast<int>(echoed.size()),
                "real UDP DTLS echo size changed");
        require(echoed == expected, "real UDP DTLS echo payload changed");
    } catch (...) {
        client_error = std::current_exception();
    }

    server_thread.join();
    if (client_error || server_error) {
        throw std::runtime_error(
            "real UDP DTLS session failed (client: " +
            exception_text(client_error) + "; server: " +
            exception_text(server_error) + ')');
    }
}

void test_stateless_dtls_cookie_secret_rotation() {
    secure::WolfSslStatelessServer gate{
        [](const std::uint8_t*,
           const std::size_t,
           const sockaddr_storage&,
           const int) { return true; },
        std::span<const std::uint8_t>{
            reinterpret_cast<const std::uint8_t*>(kPassword.data()),
            kPassword.size()},
        secure::CipherSuite::Aes256Gcm,
        std::chrono::milliseconds{1}};

    sockaddr_storage peer{};
    auto* const ipv4 = reinterpret_cast<sockaddr_in*>(&peer);
    ipv4->sin_family = AF_INET;
    ipv4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ipv4->sin_port = htons(48'001U);
    std::array<std::uint8_t, 48> malformed{};

    require(!gate.process_datagram(malformed, peer, sizeof(sockaddr_in)),
            "malformed packet unexpectedly passed the rotation gate");
    std::this_thread::sleep_for(std::chrono::milliseconds{5});
    malformed[0] = 0xFFU;
    require(!gate.process_datagram(malformed, peer, sizeof(sockaddr_in)),
            "malformed packet unexpectedly passed the rotated gate");
    require(gate.stats().cookie_secret_rotations >= 1U,
            "DTLS cookie secret did not rotate automatically");
}

void test_stateless_dtls_gate_rejects_wrong_password() {
    UdpSocketPair sockets = make_udp_socket_pair();
    const SOCKET client_socket = sockets.client.get();
    const SOCKET server_socket = sockets.server.get();

    secure::SecureSocket client{
        client_socket,
        make_udp_socket_transport(client_socket),
        std::string{kOtherPassword},
        false,
        secure::CipherSuite::Aes256Gcm,
        false};
    std::exception_ptr client_error;
    std::thread client_thread{[&]() {
        try {
            client.handshake();
        } catch (...) {
            client_error = std::current_exception();
        }
    }};

    auto send_to = [server_socket](const std::uint8_t* data,
                                   const std::size_t size,
                                   const sockaddr_storage& peer,
                                   const int peer_length) {
        const int sent = ::sendto(
            server_socket,
            reinterpret_cast<const char*>(data),
            static_cast<int>(size),
            0,
            reinterpret_cast<const sockaddr*>(&peer),
            peer_length);
        return sent == static_cast<int>(size);
    };
    secure::WolfSslStatelessServer gate{
        std::move(send_to),
        std::span<const std::uint8_t>{
            reinterpret_cast<const std::uint8_t*>(kPassword.data()),
            kPassword.size()},
        secure::CipherSuite::Aes256Gcm};

    bool admitted = false;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds{3};
    while (std::chrono::steady_clock::now() < deadline &&
           gate.stats().datagrams_processed < 2U) {
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(server_socket, &readable);
        timeval wait{};
        wait.tv_usec = 200'000L;
        const int ready = ::select(0, &readable, nullptr, nullptr, &wait);
        if (ready == SOCKET_ERROR) {
            client.close();
            client_thread.join();
            fail("wrong-password gate select failed");
        }
        if (ready == 0) continue;

        std::array<std::uint8_t, 2'048> packet{};
        sockaddr_storage peer{};
        int peer_length = sizeof(peer);
        const int received = ::recvfrom(
            server_socket,
            reinterpret_cast<char*>(packet.data()),
            static_cast<int>(packet.size()),
            0,
            reinterpret_cast<sockaddr*>(&peer),
            &peer_length);
        if (received <= 0) continue;
        auto prepared = gate.process_datagram(
            std::span<const std::uint8_t>{packet.data(),
                                          static_cast<std::size_t>(received)},
            peer,
            peer_length);
        if (prepared) admitted = true;
    }

    client.close();
    client_thread.join();
    const auto stats = gate.stats();
    require(!admitted && stats.sessions_admitted == 0U,
            "stateless DTLS gate admitted a wrong-password ClientHello");
    require(stats.datagrams_processed >= 2U &&
                stats.cookie_challenges >= 1U &&
                stats.authentication_failures >= 1U,
            "wrong-password client did not exercise the DTLS cookie gate");
    require(client_error != nullptr,
            "wrong-password DTLS client did not report authentication failure");
}

void close_datagram_queue(const std::shared_ptr<DatagramQueue>& queue) {
    std::lock_guard lock{queue->mutex};
    queue->closed = true;
    queue->ready.notify_all();
}

[[nodiscard]] std::unique_ptr<secure::DatagramTransport> make_datagram_endpoint(
    const std::shared_ptr<DatagramQueue>& outgoing,
    const std::shared_ptr<DatagramQueue>& incoming,
    const std::shared_ptr<std::atomic<unsigned int>>& drops_remaining = {},
    const std::shared_ptr<std::atomic<bool>>& write_would_block = {}) {
    auto send = [outgoing, drops_remaining, write_would_block](
                    const std::uint8_t* data,
                    const std::size_t size) {
        if (write_would_block &&
            write_would_block->load(std::memory_order_acquire)) {
            return secure::DatagramSendResult::WouldBlock;
        }
        if (drops_remaining) {
            unsigned int remaining =
                drops_remaining->load(std::memory_order_acquire);
            while (remaining != 0U) {
                if (drops_remaining->compare_exchange_weak(
                        remaining,
                        remaining - 1U,
                        std::memory_order_acq_rel,
                        std::memory_order_acquire)) {
                    return secure::DatagramSendResult::Sent;
                }
            }
        }

        std::lock_guard lock{outgoing->mutex};
        if (outgoing->closed) {
            return secure::DatagramSendResult::Closed;
        }
        outgoing->packets.emplace_back(data, data + size);
        outgoing->ready.notify_one();
        return secure::DatagramSendResult::Sent;
    };
    auto receive = [incoming](
                       std::vector<std::uint8_t>& output,
                       const std::chrono::milliseconds timeout)
        -> secure::DatagramReceiveResult {
        std::unique_lock lock{incoming->mutex};
        const bool signaled = incoming->ready.wait_for(lock, timeout, [&]() {
            return incoming->closed || !incoming->packets.empty();
        });
        if (incoming->packets.empty()) {
            return signaled ? secure::DatagramReceiveResult::Closed
                            : secure::DatagramReceiveResult::Timeout;
        }
        output = std::move(incoming->packets.front());
        incoming->packets.pop_front();
        return secure::DatagramReceiveResult::Received;
    };
    auto close = [incoming]() noexcept {
        close_datagram_queue(incoming);
    };
    return std::make_unique<secure::DatagramTransport>(
        std::move(send), std::move(receive), std::move(close));
}

void test_dtls_application_write_deadline() {
    auto client_to_server = std::make_shared<DatagramQueue>();
    auto server_to_client = std::make_shared<DatagramQueue>();
    auto client_write_would_block = std::make_shared<std::atomic<bool>>(false);
    std::atomic<bool> finish_server{false};
    std::exception_ptr server_error;

    std::thread server_thread{[&]() {
        try {
            secure::SecureSocket server{
                INVALID_SOCKET,
                make_datagram_endpoint(server_to_client, client_to_server),
                std::string{kPassword},
                true,
                secure::CipherSuite::Aes256Gcm,
                false};
            server.handshake();
            while (!finish_server.load(std::memory_order_acquire)) {
                std::this_thread::sleep_for(std::chrono::milliseconds{10});
            }
            server.close();
        } catch (...) {
            server_error = std::current_exception();
            close_datagram_queue(client_to_server);
            close_datagram_queue(server_to_client);
        }
    }};

    std::exception_ptr client_error;
    bool timed_out = false;
    std::chrono::steady_clock::duration elapsed{};
    try {
        secure::SecureSocket client{
            INVALID_SOCKET,
            make_datagram_endpoint(
                client_to_server, server_to_client, {},
                client_write_would_block),
            std::string{kPassword},
            false,
            secure::CipherSuite::Aes256Gcm,
            false};
        client.handshake();
        client_write_would_block->store(true, std::memory_order_release);

        const std::uint8_t payload = 0x5AU;
        const auto started = std::chrono::steady_clock::now();
        try {
            (void)client.send_record(0x7EU, &payload, 1U);
        } catch (const std::exception& error) {
            elapsed = std::chrono::steady_clock::now() - started;
            timed_out = std::string_view{error.what()}.find(
                            "application write timed out") !=
                        std::string_view::npos;
            if (!timed_out) throw;
        }
        client.close();
    } catch (...) {
        client_error = std::current_exception();
    }

    finish_server.store(true, std::memory_order_release);
    close_datagram_queue(client_to_server);
    close_datagram_queue(server_to_client);
    server_thread.join();
    if (client_error || server_error) {
        throw std::runtime_error(
            "DTLS write-deadline test failed (client: " +
            exception_text(client_error) + "; server: " +
            exception_text(server_error) + ")");
    }
    require(timed_out, "stalled DTLS application write did not time out");
    require(elapsed >= std::chrono::seconds{4} &&
                elapsed <= std::chrono::seconds{7},
            "DTLS application write deadline was outside its bounded window");
}

void test_dtls_record_path_and_handshake_retransmission() {
    auto client_to_server = std::make_shared<DatagramQueue>();
    auto server_to_client = std::make_shared<DatagramQueue>();
    auto client_drops = std::make_shared<std::atomic<unsigned int>>(1U);
    std::exception_ptr server_error;

    std::vector<std::uint8_t> expected(1380U);
    for (std::size_t index = 0; index < expected.size(); ++index) {
        expected[index] = static_cast<std::uint8_t>((index * 73U + 9U) & 0xFFU);
    }

    std::thread server_thread{[&]() {
        try {
            secure::SecureSocket server{
                INVALID_SOCKET,
                make_datagram_endpoint(server_to_client, client_to_server),
                std::string{kPassword},
                true,
                secure::CipherSuite::Aes256Gcm,
                false};
            server.handshake();

            std::vector<std::uint8_t> received(expected.size());
            std::uint8_t type = 0;
            const int size =
                server.recv_record(type, received.data(), received.size());
            require(type == 0x61U, "UDP record type changed");
            require(size == static_cast<int>(expected.size()),
                    "UDP record size changed");
            require(received == expected, "UDP record payload changed");
            require(server.send_record(0x62U,
                                       received.data(),
                                       static_cast<std::uint16_t>(received.size())) ==
                        static_cast<int>(received.size()),
                    "UDP echo failed");

            std::array<std::uint8_t, 32> discard_record{};
            discard_record.fill(0xA5U);
            require(server.send_record(0x63U,
                                       discard_record.data(),
                                       static_cast<std::uint16_t>(
                                           discard_record.size())) ==
                        static_cast<int>(discard_record.size()),
                    "DTLS discard record send failed");

            const std::array<std::uint8_t, 3> next_record{0x11U, 0x22U, 0x33U};
            require(server.send_record(0x64U,
                                       next_record.data(),
                                       static_cast<std::uint16_t>(next_record.size())) ==
                        static_cast<int>(next_record.size()),
                    "DTLS follow-up record send failed");
            require(server.send_record(0x65U, nullptr, 0U) == 0,
                    "DTLS empty record send failed");
        } catch (...) {
            server_error = std::current_exception();
            close_datagram_queue(client_to_server);
            close_datagram_queue(server_to_client);
        }
    }};

    std::exception_ptr client_error;
    try {
        secure::SecureSocket client{
            INVALID_SOCKET,
            make_datagram_endpoint(
                client_to_server, server_to_client, client_drops),
            std::string{kPassword},
            false,
            secure::CipherSuite::Aes256Gcm,
            false};
        client.handshake();

        std::vector<std::uint8_t> oversized(1381U, 0x5AU);
        bool oversized_rejected = false;
        try {
            (void)client.send_record(
                0x60U,
                oversized.data(),
                static_cast<std::uint16_t>(oversized.size()));
        } catch (const std::length_error&) {
            oversized_rejected = true;
        }
        require(oversized_rejected,
                "DTLS accepted a record larger than the Wintun MTU");

        require(client.send_record(0x61U,
                                   expected.data(),
                                   static_cast<std::uint16_t>(expected.size())) ==
                    static_cast<int>(expected.size()),
                "UDP send failed");

        std::vector<std::uint8_t> echoed(expected.size());
        std::uint8_t type = 0;
        const int size = client.recv_record(type, echoed.data(), echoed.size());
        require(type == 0x62U, "UDP echo type changed");
        require(size == static_cast<int>(expected.size()), "UDP echo size changed");
        require(echoed == expected, "UDP echo payload changed");

        std::array<std::uint8_t, 1> undersized{};
        require(client.recv_record(type, undersized.data(), undersized.size()) == -1,
                "DTLS undersized destination unexpectedly accepted a record");
        require(type == 0x63U, "DTLS discarded record type changed");

        std::array<std::uint8_t, 3> next{};
        require(client.recv_record(type, next.data(), next.size()) ==
                    static_cast<int>(next.size()),
                "DTLS did not recover after an undersized destination");
        require(type == 0x64U &&
                    next == std::array<std::uint8_t, 3>{0x11U, 0x22U, 0x33U},
                "DTLS follow-up record changed");
        require(client.recv_record(type, nullptr, 0U) == 0 && type == 0x65U,
                "DTLS empty record changed");
    } catch (...) {
        client_error = std::current_exception();
        close_datagram_queue(client_to_server);
        close_datagram_queue(server_to_client);
    }

    server_thread.join();
    close_datagram_queue(client_to_server);
    close_datagram_queue(server_to_client);
    if (client_error || server_error) {
        throw std::runtime_error(
            "DTLS secure transport session failed (client: " +
            exception_text(client_error) + "; server: " +
            exception_text(server_error) + ")");
    }
    require(client_drops->load(std::memory_order_acquire) == 0U,
            "DTLS retransmission test did not drop its first ClientHello");
}

void test_dtls_automatic_key_rotation() {
    auto client_to_server = std::make_shared<DatagramQueue>();
    auto server_to_client = std::make_shared<DatagramQueue>();
    secure::TrafficKeyRotationPolicy policy{};
    policy.max_records = 2U;
    policy.max_bytes = 1'000'000U;
    policy.max_age = std::chrono::hours{24};

    std::exception_ptr server_error;
    std::thread server_thread{[&]() {
        try {
            secure::SecureSocket server{
                INVALID_SOCKET,
                make_datagram_endpoint(server_to_client, client_to_server),
                std::string{kPassword},
                true,
                secure::CipherSuite::Aes256Gcm,
                false,
                policy};
            server.handshake();
            for (std::uint8_t index = 0; index != 8U; ++index) {
                std::array<std::uint8_t, 8> received{};
                std::uint8_t type = 0;
                require(server.recv_record(type, received.data(), received.size()) ==
                            static_cast<int>(received.size()),
                        "DTLS rotation receive failed");
                require(type == static_cast<std::uint8_t>(0x90U + index),
                        "DTLS rotation request type changed");
                require(server.send_record(
                            static_cast<std::uint8_t>(0xA0U + index),
                            received.data(),
                            static_cast<std::uint16_t>(received.size())) ==
                            static_cast<int>(received.size()),
                        "DTLS rotation response failed");
            }
            require(server.rotation_stats().key_update_requests >= 3U,
                    "DTLS server did not automatically rotate keys");
        } catch (...) {
            server_error = std::current_exception();
            close_datagram_queue(client_to_server);
            close_datagram_queue(server_to_client);
        }
    }};

    std::exception_ptr client_error;
    try {
        secure::SecureSocket client{
            INVALID_SOCKET,
            make_datagram_endpoint(client_to_server, server_to_client),
            std::string{kPassword},
            false,
            secure::CipherSuite::Aes256Gcm,
            false,
            policy};
        client.handshake();
        for (std::uint8_t index = 0; index != 8U; ++index) {
            const std::array<std::uint8_t, 8> payload{
                index, static_cast<std::uint8_t>(index + 1U), 0x11U, 0x22U,
                0x33U, 0x44U, 0x55U, 0x66U};
            require(client.send_record(
                        static_cast<std::uint8_t>(0x90U + index),
                        payload.data(),
                        static_cast<std::uint16_t>(payload.size())) ==
                        static_cast<int>(payload.size()),
                    "DTLS rotation request failed");
            std::array<std::uint8_t, 8> response{};
            std::uint8_t type = 0;
            require(client.recv_record(type, response.data(), response.size()) ==
                        static_cast<int>(response.size()),
                    "DTLS rotation response receive failed");
            require(type == static_cast<std::uint8_t>(0xA0U + index) &&
                        response == payload,
                    "DTLS rotation response changed");
        }
        require(client.rotation_stats().key_update_requests >= 3U,
                "DTLS client did not automatically rotate keys");
        require(client.rotation_stats().rotation_failures == 0U,
                "DTLS key rotation reported a failure");
    } catch (...) {
        client_error = std::current_exception();
        close_datagram_queue(client_to_server);
        close_datagram_queue(server_to_client);
    }

    server_thread.join();
    close_datagram_queue(client_to_server);
    close_datagram_queue(server_to_client);
    if (client_error || server_error) {
        throw std::runtime_error(
            "DTLS key rotation session failed (client: " +
            exception_text(client_error) + "; server: " +
            exception_text(server_error) + ")");
    }
}

void test_strict_dtls_profile_validation() {
    const auto make_transport = []() {
        return std::make_unique<secure::DatagramTransport>(
            [](const std::uint8_t*, std::size_t) {
                return secure::DatagramSendResult::Error;
            },
            [](std::vector<std::uint8_t>&, std::chrono::milliseconds) {
                return secure::DatagramReceiveResult::Error;
            });
    };

    bool cipher_rejected = false;
    try {
        secure::SecureSocket socket{INVALID_SOCKET,
                                    make_transport(),
                                    std::string{kPassword},
                                    false,
                                    secure::CipherSuite::ChaCha20Poly1305,
                                    false};
    } catch (const std::invalid_argument&) {
        cipher_rejected = true;
    }
    require(cipher_rejected,
            "UDP accepted a cipher outside the strict DTLS profile");

    bool empty_password_rejected = false;
    try {
        secure::SecureSocket socket{INVALID_SOCKET,
                                    make_transport(),
                                    "",
                                    false,
                                    secure::CipherSuite::Aes256Gcm,
                                    false};
    } catch (const std::invalid_argument&) {
        empty_password_rejected = true;
    }
    require(empty_password_rejected, "DTLS accepted an empty password");

    bool human_password_rejected = false;
    try {
        secure::SecureSocket socket{INVALID_SOCKET,
                                    make_transport(),
                                    "12345678901234567890",
                                    false,
                                    secure::CipherSuite::Aes256Gcm,
                                    false};
    } catch (const std::invalid_argument&) {
        human_password_rejected = true;
    }
    require(human_password_rejected,
            "DTLS accepted a human-memorable password instead of a generated key");
}

void test_dtls_wrong_password_is_rejected_by_both_peers() {
    auto client_to_server = std::make_shared<DatagramQueue>();
    auto server_to_client = std::make_shared<DatagramQueue>();
    std::exception_ptr server_error;
    bool server_succeeded = false;

    std::thread server_thread{[&]() {
        try {
            secure::SecureSocket server{
                INVALID_SOCKET,
                make_datagram_endpoint(server_to_client, client_to_server),
                std::string{kPassword},
                true,
                secure::CipherSuite::Aes256Gcm,
                false};
            server.handshake();
            server_succeeded = true;
        } catch (...) {
            server_error = std::current_exception();
            close_datagram_queue(client_to_server);
            close_datagram_queue(server_to_client);
        }
    }};

    std::exception_ptr client_error;
    bool client_succeeded = false;
    try {
        secure::SecureSocket client{
            INVALID_SOCKET,
            make_datagram_endpoint(client_to_server, server_to_client),
            std::string{kOtherPassword},
            false,
            secure::CipherSuite::Aes256Gcm,
            false};
        client.handshake();
        client_succeeded = true;
    } catch (...) {
        client_error = std::current_exception();
        close_datagram_queue(client_to_server);
        close_datagram_queue(server_to_client);
    }

    server_thread.join();
    close_datagram_queue(client_to_server);
    close_datagram_queue(server_to_client);
    require(!client_succeeded && !server_succeeded,
            "DTLS accepted mismatched passwords");
    require(client_error != nullptr && server_error != nullptr,
            "DTLS did not report password failure to both peers");
}

void test_dtls_concurrent_bidirectional_io() {
    auto client_to_server = std::make_shared<DatagramQueue>();
    auto server_to_client = std::make_shared<DatagramQueue>();
    std::exception_ptr server_error;

    std::thread server_thread{[&]() {
        try {
            secure::SecureSocket server{
                INVALID_SOCKET,
                make_datagram_endpoint(server_to_client, client_to_server),
                std::string{kPassword},
                true,
                secure::CipherSuite::Aes256Gcm,
                false};
            server.handshake();
            exercise_concurrent_io(
                server, 0x72U, 0x71U, 0xB0U, 0x20U, 512U, 64U);
        } catch (...) {
            server_error = std::current_exception();
            close_datagram_queue(client_to_server);
            close_datagram_queue(server_to_client);
        }
    }};

    std::exception_ptr client_error;
    try {
        secure::SecureSocket client{
            INVALID_SOCKET,
            make_datagram_endpoint(client_to_server, server_to_client),
            std::string{kPassword},
            false,
            secure::CipherSuite::Aes256Gcm,
            false};
        client.handshake();
        exercise_concurrent_io(
            client, 0x71U, 0x72U, 0x20U, 0xB0U, 512U, 64U);
    } catch (...) {
        client_error = std::current_exception();
        close_datagram_queue(client_to_server);
        close_datagram_queue(server_to_client);
    }

    server_thread.join();
    close_datagram_queue(client_to_server);
    close_datagram_queue(server_to_client);
    if (client_error || server_error) {
        throw std::runtime_error(
            "Concurrent DTLS session failed (client: " +
            exception_text(client_error) + "; server: " +
            exception_text(server_error) + ")");
    }
}

void test_close_interrupts_stalled_dtls_handshake() {
    auto client_to_server = std::make_shared<DatagramQueue>();
    auto server_to_client = std::make_shared<DatagramQueue>();
    secure::SecureSocket socket{
        INVALID_SOCKET,
        make_datagram_endpoint(server_to_client, client_to_server),
        std::string{kPassword},
        true,
        secure::CipherSuite::Aes256Gcm,
        false};

    std::exception_ptr handshake_error;
    std::thread handshake_thread{[&]() {
        try {
            socket.handshake();
        } catch (...) {
            handshake_error = std::current_exception();
        }
    }};

    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    socket.close();
    handshake_thread.join();
    close_datagram_queue(client_to_server);
    close_datagram_queue(server_to_client);
    require(handshake_error != nullptr,
            "closing DTLS did not interrupt a stalled handshake");
}

void test_close_interrupts_authenticated_dtls_receive() {
    auto client_to_server = std::make_shared<DatagramQueue>();
    auto server_to_client = std::make_shared<DatagramQueue>();
    std::atomic<bool> server_closed{false};
    std::exception_ptr server_error;

    std::thread server_thread{[&]() {
        try {
            secure::SecureSocket server{
                INVALID_SOCKET,
                make_datagram_endpoint(server_to_client, client_to_server),
                std::string{kPassword},
                true,
                secure::CipherSuite::Aes256Gcm,
                false};
            server.handshake();

            std::array<std::uint8_t, 32> buffer{};
            std::uint8_t type = 0;
            std::exception_ptr receive_error;
            int receive_result = 0;
            const auto started = std::chrono::steady_clock::now();
            std::thread first_closer{[&server]() {
                std::this_thread::sleep_for(std::chrono::milliseconds{50});
                server.close();
            }};
            std::thread second_closer{[&server]() {
                std::this_thread::sleep_for(std::chrono::milliseconds{50});
                server.close();
            }};
            try {
                receive_result =
                    server.recv_record(type, buffer.data(), buffer.size());
            } catch (...) {
                receive_error = std::current_exception();
            }
            first_closer.join();
            second_closer.join();
            const auto elapsed = std::chrono::steady_clock::now() - started;
            require(receive_result < 0 || receive_error != nullptr,
                    "DTLS receive unexpectedly survived concurrent close");
            require(elapsed < std::chrono::seconds{2},
                    "DTLS close did not promptly interrupt an authenticated receive");
            require(server.native() == INVALID_SOCKET,
                    "DTLS close left its wrapper socket reachable");
            server_closed.store(true, std::memory_order_release);
        } catch (...) {
            server_error = std::current_exception();
            close_datagram_queue(client_to_server);
            close_datagram_queue(server_to_client);
        }
    }};

    std::exception_ptr client_error;
    try {
        secure::SecureSocket client{
            INVALID_SOCKET,
            make_datagram_endpoint(client_to_server, server_to_client),
            std::string{kPassword},
            false,
            secure::CipherSuite::Aes256Gcm,
            false};
        client.handshake();
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds{3};
        while (!server_closed.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
        require(server_closed.load(std::memory_order_acquire),
                "DTLS receive-close test did not finish");
        client.close();
    } catch (...) {
        client_error = std::current_exception();
        close_datagram_queue(client_to_server);
        close_datagram_queue(server_to_client);
    }

    server_thread.join();
    close_datagram_queue(client_to_server);
    close_datagram_queue(server_to_client);
    if (client_error || server_error) {
        throw std::runtime_error(
            "Authenticated DTLS receive-close test failed (client: " +
            exception_text(client_error) + "; server: " +
            exception_text(server_error) + ")");
    }
}

void test_failed_handshake_cannot_retry_after_secret_cleanup() {
    auto transport = std::make_unique<secure::DatagramTransport>(
        [](const std::uint8_t*, std::size_t) {
            return secure::DatagramSendResult::Error;
        },
        [](std::vector<std::uint8_t>&, std::chrono::milliseconds) {
            return secure::DatagramReceiveResult::Error;
        });
    secure::SecureSocket socket{INVALID_SOCKET,
                                std::move(transport),
                                std::string{kPassword},
                                false,
                                secure::CipherSuite::Aes256Gcm,
                                false};

    bool first_attempt_failed = false;
    try {
        socket.handshake();
    } catch (const std::exception&) {
        first_attempt_failed = true;
    }
    require(first_attempt_failed, "test transport unexpectedly completed a handshake");

    bool retry_rejected = false;
    try {
        socket.handshake();
    } catch (const std::exception&) {
        retry_rejected = true;
    }
    require(retry_rejected,
            "handshake retried after its password copy had been cleared");
}

void test_generated_shared_key_policy() {
    require(secure::is_valid_shared_secret(kPassword),
            "canonical 32-byte base64url key was rejected");
    require(secure::is_valid_shared_secret(kOtherPassword),
            "second canonical 32-byte base64url key was rejected");

    require(secure::validate_shared_secret("TwentyCharactersOnly!") ==
                secure::SharedSecretValidationError::WrongLength,
            "human password length was accepted as a shared key");

    std::string invalid_character{kPassword};
    invalid_character[10] = '+';
    require(secure::validate_shared_secret(invalid_character) ==
                secure::SharedSecretValidationError::InvalidCharacter,
            "non-base64url shared key was accepted");

    std::string noncanonical{kPassword};
    noncanonical.back() = '_';
    require(secure::validate_shared_secret(noncanonical) ==
                secure::SharedSecretValidationError::NonCanonicalEncoding,
            "noncanonical final base64url quantum was accepted");

    const std::string repeated(secure::kSharedSecretTextLength, 'A');
    require(secure::validate_shared_secret(repeated) ==
                secure::SharedSecretValidationError::ObviousLowEntropyPattern,
            "obviously repetitive shared key was accepted");

    require(secure::validate_shared_secret(
                "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8") ==
                secure::SharedSecretValidationError::ObviousLowEntropyPattern,
            "sequential-byte shared key was accepted");
}

void test_fixed_window_rate_limiter() {
    using Limiter = security::FixedWindowRateLimiter;
    constexpr auto unlimited = (std::numeric_limits<std::size_t>::max)();
    Limiter limiter{{3U, unlimited}, {2U, 10U}, 2U,
                    std::chrono::seconds{1}};
    const auto first_window = Limiter::Clock::time_point{} +
                              std::chrono::seconds{1};

    require(limiter.allow("peer-a", 5U, first_window),
            "first peer event was rejected");
    require(limiter.allow("peer-a", 5U, first_window),
            "second peer event was rejected");
    require(!limiter.allow("peer-a", 1U, first_window),
            "per-peer event/byte budget was not enforced");
    require(limiter.allow("peer-b", 1U, first_window),
            "independent peer within the global budget was rejected");
    require(!limiter.allow("peer-c", 1U, first_window),
            "global/key-cardinality budget was not enforced");
    require(limiter.allow("peer-a", 10U,
                          first_window + std::chrono::seconds{1}),
            "rate budget did not recover in the next window");

    const auto stats = limiter.stats();
    require(stats.allowed == 4U && stats.rejected == 2U,
            "rate limiter accounting changed unexpectedly");
}

void test_schannel_application_write_deadline() {
    Listener listener = make_listener();
    std::exception_ptr server_error;
    bool timed_out = false;
    std::chrono::steady_clock::duration elapsed{};

    std::thread server_thread{[&]() {
        try {
            SocketOwner accepted{::accept(listener.socket.get(), nullptr, nullptr)};
            if (accepted.get() == INVALID_SOCKET) fail("accept failed");
            set_socket_timeouts(accepted.get());
            secure::SecureSocket tls{accepted.get(), std::string{kPassword}, true,
                                     secure::CipherSuite::Aes256Gcm};
            (void)accepted.release();
            tls.handshake();

            int send_buffer = 4'096;
            require(::setsockopt(tls.native(), SOL_SOCKET, SO_SNDBUF,
                                 reinterpret_cast<const char*>(&send_buffer),
                                 sizeof(send_buffer)) == 0,
                    "could not reduce the server send buffer");
            const std::vector<std::uint8_t> payload(65'535U, 0xA5U);
            const auto started = std::chrono::steady_clock::now();
            try {
                for (;;) {
                    (void)tls.send_record(0x7FU, payload.data(),
                                          static_cast<std::uint16_t>(payload.size()));
                }
            } catch (const std::exception& error) {
                elapsed = std::chrono::steady_clock::now() - started;
                timed_out = std::string_view{error.what()}.find(
                                "application write timed out") !=
                            std::string_view::npos;
                if (!timed_out) throw;
            }
            tls.close();
        } catch (...) {
            server_error = std::current_exception();
        }
    }};

    std::exception_ptr client_error;
    try {
        SocketOwner client = connect_client(listener.address);
        int receive_buffer = 4'096;
        require(::setsockopt(client.get(), SOL_SOCKET, SO_RCVBUF,
                             reinterpret_cast<const char*>(&receive_buffer),
                             sizeof(receive_buffer)) == 0,
                "could not reduce the client receive buffer");
        secure::SecureSocket tls{client.get(), std::string{kPassword}, false,
                                 secure::CipherSuite::Aes256Gcm};
        (void)client.release();
        tls.handshake();
        std::this_thread::sleep_for(std::chrono::milliseconds{6'500});
        tls.close();
    } catch (...) {
        client_error = std::current_exception();
    }

    server_thread.join();
    if (client_error || server_error) {
        throw std::runtime_error(
            "Schannel write-deadline test failed (client: " +
            exception_text(client_error) + "; server: " +
            exception_text(server_error) + ")");
    }
    require(timed_out, "stalled Schannel application write did not time out");
    require(elapsed >= std::chrono::seconds{4} &&
                elapsed <= std::chrono::seconds{7},
            "Schannel application write deadline was outside its bounded window");
}

} // namespace

int main() {
    try {
        const Winsock winsock;
        test_generated_shared_key_policy();
        test_fixed_window_rate_limiter();
        test_strict_tcp_profile_validation();
        test_close_interrupts_stalled_handshake();
        test_close_interrupts_authenticated_tls_receive();
        test_large_records_and_framing();
        test_small_buffer_does_not_desynchronize_stream();
        test_concurrent_bidirectional_io();
        test_wrong_password_is_rejected_by_both_peers();
        test_schannel_application_write_deadline();
        test_strict_dtls_profile_validation();
        test_short_dtls_psk_identities_are_rejected_safely();
        test_close_interrupts_stalled_dtls_handshake();
        test_close_interrupts_authenticated_dtls_receive();
        test_dtls_over_real_udp_loopback();
        test_stateless_dtls_cookie_secret_rotation();
        test_stateless_dtls_gate_rejects_wrong_password();
        test_dtls_record_path_and_handshake_retransmission();
        test_dtls_automatic_key_rotation();
        test_dtls_concurrent_bidirectional_io();
        test_dtls_wrong_password_is_rejected_by_both_peers();
        test_dtls_application_write_deadline();
        test_failed_handshake_cannot_retry_after_secret_cleanup();
        std::cout << "Secure transport tests passed\n";
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << "Secure transport test failed: " << exception.what() << '\n';
        return 1;
    }
}
