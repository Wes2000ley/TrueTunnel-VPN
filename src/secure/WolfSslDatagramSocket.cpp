#include "WolfSslDatagramSocket.h"
#include "SharedSecret.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <bcrypt.h>

#include <wolfssl/options.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace secure {
namespace {

using namespace std::chrono_literals;

constexpr std::string_view kPskIdentity{"TrueTunnel-DTLS-v1"};
constexpr char kWolfCipherName[] = "TLS13-AES256-GCM-SHA384";
constexpr std::string_view kExpectedCurveName{"SECP256R1"};
constexpr std::array<std::uint8_t, 29> kPasswordSalt{
    'T', 'r', 'u', 'e', 'T', 'u', 'n', 'n', 'e', 'l', '-', 'D', 'T', 'L', 'S',
    '-', '1', '.', '3', '-', 'P', 'S', 'K', '-', 'v', '1', '-', 'K', 'D'};
constexpr unsigned long long kPasswordKdfIterations = 200'000ULL;
constexpr std::chrono::seconds kHandshakeTimeout{15};
constexpr std::chrono::seconds kApplicationWriteTimeout{5};
constexpr std::chrono::milliseconds kApplicationReadPoll{1'000};
constexpr unsigned short kOuterUdpPayloadMtu = 1472U;
constexpr std::size_t kMaximumInjectedDatagramSize = 2'048U;

template <typename Container>
void wipe(Container& value) noexcept {
    if (!value.empty()) {
        ::SecureZeroMemory(value.data(), value.size());
    }
}

[[nodiscard]] std::string wolf_error_text(WOLFSSL* const ssl,
                                          const int result) {
    const int error = ssl == nullptr ? result : wolfSSL_get_error(ssl, result);
    std::array<char, 256> buffer{};
    wolfSSL_ERR_error_string(static_cast<unsigned long>(error), buffer.data());
    return std::string{buffer.data()} + " (" + std::to_string(error) + ')';
}

[[noreturn]] void throw_wolf_error(const char* const operation,
                                   WOLFSSL* const ssl,
                                   const int result) {
    throw std::runtime_error(std::string{operation} + " failed: " +
                             wolf_error_text(ssl, result));
}

class WolfSslRuntime final {
public:
    WolfSslRuntime() {
        if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
            throw std::runtime_error("wolfSSL global initialization failed");
        }
    }

    ~WolfSslRuntime() {
        wolfSSL_Cleanup();
    }

    WolfSslRuntime(const WolfSslRuntime&) = delete;
    WolfSslRuntime& operator=(const WolfSslRuntime&) = delete;
};

void ensure_wolfssl_runtime() {
    static const WolfSslRuntime runtime;
    (void)runtime;
}

[[nodiscard]] std::array<std::uint8_t, 32> derive_psk(
    const std::span<const std::uint8_t> password) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    const NTSTATUS open_status = ::BCryptOpenAlgorithmProvider(
        &algorithm,
        BCRYPT_SHA256_ALGORITHM,
        nullptr,
        BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(open_status)) {
        throw std::runtime_error("BCryptOpenAlgorithmProvider(PBKDF2) failed");
    }

    std::array<std::uint8_t, 32> psk{};
    const NTSTATUS derive_status = ::BCryptDeriveKeyPBKDF2(
        algorithm,
        const_cast<PUCHAR>(password.data()),
        static_cast<ULONG>(password.size()),
        const_cast<PUCHAR>(kPasswordSalt.data()),
        static_cast<ULONG>(kPasswordSalt.size()),
        kPasswordKdfIterations,
        psk.data(),
        static_cast<ULONG>(psk.size()),
        0);
    ::BCryptCloseAlgorithmProvider(algorithm, 0);

    if (!BCRYPT_SUCCESS(derive_status)) {
        wipe(psk);
        throw std::runtime_error("BCryptDeriveKeyPBKDF2(DTLS PSK) failed");
    }
    return psk;
}

struct WolfSslContextDeleter {
    void operator()(WOLFSSL_CTX* const context) const noexcept {
        if (context != nullptr) {
            wolfSSL_CTX_free(context);
        }
    }
};

struct WolfSslDeleter {
    void operator()(WOLFSSL* const ssl) const noexcept {
        if (ssl != nullptr) {
            wolfSSL_free(ssl);
        }
    }
};

using ContextPtr = std::shared_ptr<WOLFSSL_CTX>;
using SslPtr = std::unique_ptr<WOLFSSL, WolfSslDeleter>;

struct PskMaterial final {
    std::array<std::uint8_t, 32> bytes{};

    ~PskMaterial() {
        wipe(bytes);
    }

    PskMaterial() = default;
    PskMaterial(const PskMaterial&) = delete;
    PskMaterial& operator=(const PskMaterial&) = delete;
};

[[nodiscard]] ContextPtr make_context(const bool is_server) {
    WOLFSSL_METHOD* const method = is_server
                                      ? wolfDTLSv1_3_server_method()
                                      : wolfDTLSv1_3_client_method();
    if (method == nullptr) {
        throw std::runtime_error("wolfSSL DTLS 1.3 method is unavailable");
    }

    ContextPtr context{wolfSSL_CTX_new(method), WolfSslContextDeleter{}};
    if (!context) {
        throw std::runtime_error("wolfSSL_CTX_new(DTLS 1.3) failed");
    }
    if (wolfSSL_CTX_set_cipher_list(context.get(), kWolfCipherName) !=
        WOLFSSL_SUCCESS) {
        throw std::runtime_error(
            "wolfSSL rejected the strict AES-256-GCM DTLS cipher list");
    }
    if (wolfSSL_CTX_only_dhe_psk(context.get()) != 0) {
        throw std::runtime_error(
            "wolfSSL could not require forward-secret ECDHE-PSK");
    }
    if (is_server && wolfSSL_CTX_no_ticket_TLSv13(context.get()) != 0) {
        throw std::runtime_error("wolfSSL could not disable DTLS tickets");
    }
    return context;
}

void configure_ssl_profile(WOLFSSL* const ssl, PskMaterial* const psk) {
    if (ssl == nullptr || psk == nullptr) {
        throw std::invalid_argument("wolfSSL DTLS state is incomplete");
    }
    if (wolfSSL_set_psk_callback_ctx(ssl, psk) != WOLFSSL_SUCCESS) {
        throw std::runtime_error("wolfSSL could not attach the PSK context");
    }

    wolfSSL_dtls_set_using_nonblock(ssl, 1);
    if (wolfSSL_dtls_set_mtu(ssl, kOuterUdpPayloadMtu) != WOLFSSL_SUCCESS ||
        wolfSSL_dtls_set_timeout_max(ssl, 4) != WOLFSSL_SUCCESS ||
        wolfSSL_dtls_set_timeout_init(ssl, 1) != WOLFSSL_SUCCESS) {
        throw std::runtime_error("wolfSSL could not configure DTLS limits");
    }

    int group = WOLFSSL_ECC_SECP256R1;
    if (wolfSSL_UseKeyShare(ssl, WOLFSSL_ECC_SECP256R1) != WOLFSSL_SUCCESS ||
        wolfSSL_set_groups(ssl, &group, 1) != WOLFSSL_SUCCESS ||
        wolfSSL_only_dhe_psk(ssl) != 0) {
        throw std::runtime_error(
            "wolfSSL could not enforce the P-256 ECDHE-PSK profile");
    }
}

unsigned int client_psk_callback(
    WOLFSSL* const ssl,
    const char*,
    char* const identity,
    const unsigned int identity_capacity,
    unsigned char* const key,
    const unsigned int key_capacity,
    const char** const cipher_suite) noexcept {
    auto* const material =
        static_cast<PskMaterial*>(wolfSSL_get_psk_callback_ctx(ssl));
    if (material == nullptr || identity == nullptr || key == nullptr ||
        cipher_suite == nullptr || identity_capacity <= kPskIdentity.size() ||
        key_capacity < material->bytes.size()) {
        return 0U;
    }

    std::memcpy(identity, kPskIdentity.data(), kPskIdentity.size());
    identity[kPskIdentity.size()] = '\0';
    std::memcpy(key, material->bytes.data(), material->bytes.size());
    *cipher_suite = kWolfCipherName;
    return static_cast<unsigned int>(material->bytes.size());
}

unsigned int server_psk_callback(
    WOLFSSL* const ssl,
    const char* const identity,
    unsigned char* const key,
    const unsigned int key_capacity,
    const char** const cipher_suite) noexcept {
    auto* const material =
        static_cast<PskMaterial*>(wolfSSL_get_psk_callback_ctx(ssl));
    if (material == nullptr || key == nullptr || cipher_suite == nullptr ||
        key_capacity < material->bytes.size() ||
        !detail::dtls_psk_identity_matches(identity)) {
        return 0U;
    }

    std::memcpy(key, material->bytes.data(), material->bytes.size());
    *cipher_suite = kWolfCipherName;
    return static_cast<unsigned int>(material->bytes.size());
}

void configure_context_psk_callback(WOLFSSL_CTX* const context,
                                    const bool is_server) {
    if (is_server) {
        wolfSSL_CTX_set_psk_server_tls13_callback(context, &server_psk_callback);
    } else {
        wolfSSL_CTX_set_psk_client_tls13_callback(context, &client_psk_callback);
    }
}

void fill_random(std::span<std::uint8_t> output) {
    if (output.empty() || output.size() >
                              static_cast<std::size_t>((std::numeric_limits<ULONG>::max)())) {
        throw std::invalid_argument("invalid CNG random output length");
    }
    const NTSTATUS status = ::BCryptGenRandom(
        nullptr,
        output.data(),
        static_cast<ULONG>(output.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("BCryptGenRandom(DTLS cookie secret) failed");
    }
}

} // namespace

namespace detail {

bool dtls_psk_identity_matches(const char* const identity) noexcept {
    return identity != nullptr &&
           std::strcmp(identity, kPskIdentity.data()) == 0;
}

} // namespace detail

class PreparedWolfSslServerSession::Impl final {
public:
    Impl(ContextPtr context,
         SslPtr ssl,
         std::shared_ptr<PskMaterial> psk_material,
         const sockaddr_storage& peer,
         const int peer_length)
        : context_{std::move(context)},
          ssl_{std::move(ssl)},
          psk_material_{std::move(psk_material)},
          peer_{peer},
          peer_length_{peer_length} {}

public:
    ContextPtr context_;
    SslPtr ssl_;
    std::shared_ptr<PskMaterial> psk_material_;
    sockaddr_storage peer_{};
    int peer_length_{0};
};

PreparedWolfSslServerSession::PreparedWolfSslServerSession() noexcept = default;
PreparedWolfSslServerSession::~PreparedWolfSslServerSession() = default;
PreparedWolfSslServerSession::PreparedWolfSslServerSession(
    PreparedWolfSslServerSession&&) noexcept = default;
PreparedWolfSslServerSession& PreparedWolfSslServerSession::operator=(
    PreparedWolfSslServerSession&&) noexcept = default;

PreparedWolfSslServerSession::PreparedWolfSslServerSession(
    std::unique_ptr<Impl> impl) noexcept
    : impl_{std::move(impl)} {}

PreparedWolfSslServerSession::operator bool() const noexcept {
    return impl_ != nullptr;
}

class WolfSslStatelessServer::Impl final {
public:
    Impl(SendTo send_to,
         const std::span<const std::uint8_t> password,
         const CipherSuite suite,
         const std::chrono::milliseconds cookie_secret_lifetime)
        : send_to_{std::move(send_to)},
          cookie_secret_lifetime_{cookie_secret_lifetime} {
        if (!send_to_) {
            throw std::invalid_argument("DTLS stateless sender not provided");
        }
        require_valid_shared_secret(password);
        if (suite != CipherSuite::Aes256Gcm) {
            throw std::invalid_argument(
                "UDP is fixed to DTLS 1.3 with TLS_AES_256_GCM_SHA384");
        }
        if (cookie_secret_lifetime_ <= std::chrono::milliseconds::zero()) {
            throw std::invalid_argument(
                "DTLS cookie-secret lifetime must be positive");
        }

        ensure_wolfssl_runtime();
        psk_material_ = std::make_shared<PskMaterial>();
        psk_material_->bytes = derive_psk(password);
        context_ = make_context(true);
        configure_context_psk_callback(context_.get(), true);
        fill_random(cookie_secret_);
        last_cookie_rotation_ = std::chrono::steady_clock::now();
        listener_ = make_listener();
    }

    ~Impl() {
        wipe(cookie_secret_);
    }

    std::optional<PreparedWolfSslServerSession> process_datagram(
        const std::span<const std::uint8_t> datagram,
        const sockaddr_storage& peer,
        const int peer_length) {
        std::lock_guard lock{mutex_};
        ++stats_.datagrams_processed;

        const bool peer_length_valid =
            peer_length > 0 &&
            peer_length <= static_cast<int>(sizeof(sockaddr_storage));
        const bool family_valid =
            peer.ss_family == AF_INET || peer.ss_family == AF_INET6;
        if (datagram.empty() || datagram.size() > kMaximumInjectedDatagramSize ||
            datagram.size() >
                static_cast<std::size_t>((std::numeric_limits<int>::max)()) ||
            !peer_length_valid || !family_valid) {
            ++stats_.malformed_datagrams;
            return std::nullopt;
        }

        rotate_cookie_secret_if_due();
        current_peer_ = peer;
        current_peer_length_ = peer_length;

        if (wolfSSL_inject(listener_.get(), datagram.data(),
                           static_cast<int>(datagram.size())) != WOLFSSL_SUCCESS ||
            wolfSSL_dtls_set_peer(listener_.get(), &current_peer_,
                                  static_cast<unsigned int>(current_peer_length_)) !=
                WOLFSSL_SUCCESS) {
            ++stats_.malformed_datagrams;
            listener_ = make_listener();
            return std::nullopt;
        }

        // wolfDTLS_accept_stateless does more than validate the cookie before
        // returning WOLFSSL_SUCCESS. In wolfSSL 5.9.2 it lets ProcessReply
        // continue through the stateful ClientHello parser, where
        // CheckPreSharedKeys/DoPreSharedKeys constant-time verifies the PSK
        // binder. BAD_BINDER and PSK_KEY_ERROR therefore take the fatal path
        // below and never become a PreparedWolfSslServerSession. Keep this
        // property explicit: a cookie alone is not an authentication token.
        const int result = wolfDTLS_accept_stateless(listener_.get());
        if (result == WOLFSSL_SUCCESS) {
            SslPtr replacement = make_listener();
            auto admitted = std::make_unique<PreparedWolfSslServerSession::Impl>(
                context_, std::move(listener_), psk_material_, current_peer_,
                current_peer_length_);
            listener_ = std::move(replacement);
            ++stats_.sessions_admitted;
            return PreparedWolfSslServerSession{std::move(admitted)};
        }
        if (result == WOLFSSL_FAILURE) {
            ++stats_.cookie_challenges;
            // Keep only the cookie secret across unknown tuples. Rebuilding
            // the lightweight listener prevents one source's partial
            // transcript from influencing another source while preserving
            // validation of cookies issued by the prior listener.
            listener_ = make_listener();
            return std::nullopt;
        }

        const int error = wolfSSL_get_error(listener_.get(), result);
        if (error == BAD_BINDER || error == PSK_KEY_ERROR) {
            ++stats_.authentication_failures;
        } else {
            ++stats_.malformed_datagrams;
        }
        listener_ = make_listener();
        return std::nullopt;
    }

    [[nodiscard]] WolfSslStatelessServerStats stats() const noexcept {
        std::lock_guard lock{mutex_};
        return stats_;
    }

private:
    static int send_callback(WOLFSSL*,
                             char* const buffer,
                             const int length,
                             void* const context) noexcept {
        auto* const self = static_cast<Impl*>(context);
        if (self == nullptr || buffer == nullptr || length <= 0 ||
            self->current_peer_length_ <= 0) {
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
        try {
            return self->send_to_(
                       reinterpret_cast<const std::uint8_t*>(buffer),
                       static_cast<std::size_t>(length),
                       self->current_peer_,
                       self->current_peer_length_)
                       ? length
                       : WOLFSSL_CBIO_ERR_GENERAL;
        } catch (...) {
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }

    [[nodiscard]] SslPtr make_listener() {
        SslPtr listener{wolfSSL_new(context_.get())};
        if (!listener) {
            throw std::runtime_error(
                "wolfSSL_new(stateless DTLS listener) failed");
        }
        configure_ssl_profile(listener.get(), psk_material_.get());
        wolfSSL_SSLSetIOSend(listener.get(), &Impl::send_callback);
        wolfSSL_SetIOWriteCtx(listener.get(), this);
        if (wolfSSL_send_hrr_cookie(
                listener.get(), cookie_secret_.data(),
                static_cast<unsigned int>(cookie_secret_.size())) !=
            WOLFSSL_SUCCESS) {
            throw std::runtime_error(
                "wolfSSL could not enable address-bound DTLS cookies");
        }
        wolfSSL_SSLDisableRead(listener.get());
        return listener;
    }

    void rotate_cookie_secret_if_due() {
        const auto now = std::chrono::steady_clock::now();
        if (now - last_cookie_rotation_ < cookie_secret_lifetime_) {
            return;
        }

        std::array<std::uint8_t, 32> next_secret{};
        fill_random(next_secret);
        wipe(cookie_secret_);
        cookie_secret_ = next_secret;
        wipe(next_secret);
        last_cookie_rotation_ = now;
        listener_ = make_listener();
        ++stats_.cookie_secret_rotations;
    }

    SendTo send_to_;
    std::chrono::milliseconds cookie_secret_lifetime_;
    ContextPtr context_;
    std::shared_ptr<PskMaterial> psk_material_;
    SslPtr listener_;
    std::array<std::uint8_t, 32> cookie_secret_{};
    std::chrono::steady_clock::time_point last_cookie_rotation_{};
    sockaddr_storage current_peer_{};
    int current_peer_length_{0};
    mutable std::mutex mutex_;
    WolfSslStatelessServerStats stats_{};
};

WolfSslStatelessServer::WolfSslStatelessServer(
    SendTo send_to,
    const std::span<const std::uint8_t> password,
    const CipherSuite suite,
    const std::chrono::milliseconds cookie_secret_lifetime)
    : impl_{std::make_unique<Impl>(
          std::move(send_to), password, suite, cookie_secret_lifetime)} {}

WolfSslStatelessServer::~WolfSslStatelessServer() = default;

std::optional<PreparedWolfSslServerSession>
WolfSslStatelessServer::process_datagram(
    const std::span<const std::uint8_t> datagram,
    const sockaddr_storage& peer,
    const int peer_length) {
    return impl_->process_datagram(datagram, peer, peer_length);
}

WolfSslStatelessServerStats WolfSslStatelessServer::stats() const noexcept {
    return impl_->stats();
}

class WolfSslDatagramSocket::Impl final {
public:
    Impl(std::unique_ptr<DatagramTransport> transport,
         const std::span<const std::uint8_t> password,
         const bool is_server,
         const CipherSuite suite,
         const TrafficKeyRotationPolicy rotation_policy)
        : transport_{std::move(transport)},
          is_server_{is_server},
          rotation_policy_{rotation_policy} {
        if (!transport_) {
            throw std::invalid_argument("DTLS datagram transport not provided");
        }
        require_valid_shared_secret(password);
        if (suite != CipherSuite::Aes256Gcm) {
            throw std::invalid_argument(
                "UDP is fixed to DTLS 1.3 with TLS_AES_256_GCM_SHA384");
        }
        if (rotation_policy_.max_records == 0U ||
            rotation_policy_.max_bytes == 0U ||
            rotation_policy_.max_age <= std::chrono::seconds::zero()) {
            throw std::invalid_argument("TLS key rotation limits must be positive");
        }

        ensure_wolfssl_runtime();
        psk_material_ = std::make_shared<PskMaterial>();
        psk_material_->bytes = derive_psk(password);
        configure_context();
    }

    Impl(std::unique_ptr<DatagramTransport> transport,
         PreparedWolfSslServerSession prepared,
         const TrafficKeyRotationPolicy rotation_policy)
        : transport_{std::move(transport)},
          is_server_{true},
          rotation_policy_{rotation_policy} {
        if (!transport_) {
            throw std::invalid_argument("DTLS datagram transport not provided");
        }
        if (rotation_policy_.max_records == 0U ||
            rotation_policy_.max_bytes == 0U ||
            rotation_policy_.max_age <= std::chrono::seconds::zero()) {
            throw std::invalid_argument("TLS key rotation limits must be positive");
        }
        if (!prepared.impl_ || !prepared.impl_->context_ ||
            !prepared.impl_->ssl_ || !prepared.impl_->psk_material_) {
            throw std::invalid_argument("DTLS prepared server session is empty");
        }

        ensure_wolfssl_runtime();
        context_ = std::move(prepared.impl_->context_);
        read_ssl_ = std::move(prepared.impl_->ssl_);
        psk_material_ = std::move(prepared.impl_->psk_material_);
        if (prepared.impl_->peer_length_ <= 0 ||
            wolfSSL_dtls_set_peer(
                read_ssl_.get(),
                &prepared.impl_->peer_,
                static_cast<unsigned int>(prepared.impl_->peer_length_)) !=
                WOLFSSL_SUCCESS) {
            throw std::runtime_error(
                "wolfSSL could not preserve the admitted DTLS peer identity");
        }
        wolfSSL_SSLSetIORecv(read_ssl_.get(), &Impl::receive_callback);
        wolfSSL_SSLSetIOSend(read_ssl_.get(), &Impl::send_callback);
        wolfSSL_SetIOReadCtx(read_ssl_.get(), this);
        wolfSSL_SetIOWriteCtx(read_ssl_.get(), this);
        if (wolfSSL_set_psk_callback_ctx(read_ssl_.get(), psk_material_.get()) !=
            WOLFSSL_SUCCESS) {
            throw std::runtime_error("wolfSSL could not rebind the PSK context");
        }
        wolfSSL_SSLEnableRead(read_ssl_.get());
    }

    ~Impl() {
        shutdown();
    }

    void handshake() {
        std::lock_guard lock{handshake_mutex_};
        if (handshake_complete_.load(std::memory_order_acquire)) {
            return;
        }
        if (handshake_attempted_) {
            throw std::runtime_error("DTLS handshake cannot be retried");
        }
        handshake_attempted_ = true;

        try {
            perform_handshake();
            validate_profile();

            write_ssl_.reset(wolfSSL_write_dup(read_ssl_.get()));
            if (!write_ssl_) {
                throw std::runtime_error(
                    "wolfSSL could not create the concurrent DTLS write side");
            }
            wolfSSL_SSLSetIOSend(write_ssl_.get(), &Impl::send_callback);
            wolfSSL_SetIOWriteCtx(write_ssl_.get(), this);
            if (wolfSSL_set_psk_callback_ctx(write_ssl_.get(),
                                             psk_material_.get()) !=
                WOLFSSL_SUCCESS) {
                throw std::runtime_error(
                    "wolfSSL could not bind the DTLS write-side PSK context");
            }
            wolfSSL_dtls_set_using_nonblock(write_ssl_.get(), 1);
            if (wolfSSL_dtls_set_mtu(write_ssl_.get(), kOuterUdpPayloadMtu) !=
                WOLFSSL_SUCCESS) {
                throw std::runtime_error(
                    "wolfSSL could not configure the DTLS write-side MTU");
            }
            records_since_rotation_ = 0U;
            bytes_since_rotation_ = 0U;
            last_rotation_ = std::chrono::steady_clock::now();
            handshake_complete_.store(true, std::memory_order_release);
        } catch (...) {
            throw;
        }
    }

    int send_record(const std::uint8_t type,
                    const std::uint8_t* const data,
                    const std::uint16_t length) {
        require_ready();
        if (length > WolfSslDatagramSocket::kMaximumPayloadSize) {
            throw std::length_error(
                "DTLS record exceeds the configured Wintun MTU");
        }
        if (length != 0U && data == nullptr) {
            throw std::invalid_argument("send_record received a null payload");
        }

        std::vector<std::uint8_t> frame(3U + static_cast<std::size_t>(length));
        frame[0] = type;
        frame[1] = static_cast<std::uint8_t>(length >> 8U);
        frame[2] = static_cast<std::uint8_t>(length & 0xFFU);
        if (length != 0U) {
            std::memcpy(frame.data() + 3U, data, length);
        }

        try {
            const auto deadline = std::chrono::steady_clock::now() +
                                  kApplicationWriteTimeout;
            std::unique_lock lock{send_mutex_, deadline};
            if (!lock.owns_lock()) {
                throw std::runtime_error(
                    "DTLS application write timed out waiting for the sender");
            }
            maybe_rotate_keys();
            for (;;) {
                if (shutdown_started_.load(std::memory_order_acquire) ||
                    transport_->is_closed()) {
                    throw std::runtime_error(
                        "DTLS application write was cancelled");
                }
                if (std::chrono::steady_clock::now() >= deadline) {
                    throw std::runtime_error(
                        "DTLS application write timed out");
                }
                const int result = wolfSSL_write(
                    write_ssl_.get(), frame.data(), static_cast<int>(frame.size()));
                if (result == static_cast<int>(frame.size())) {
                    break;
                }
                const int error = wolfSSL_get_error(write_ssl_.get(), result);
                if (error == WOLFSSL_ERROR_WANT_WRITE) {
                    std::this_thread::sleep_for(1ms);
                    continue;
                }
                throw_wolf_error("wolfSSL_write(DTLS record)",
                                 write_ssl_.get(), result);
            }
            sent_records_.fetch_add(1U, std::memory_order_relaxed);
            sent_bytes_.fetch_add(frame.size(), std::memory_order_relaxed);
            records_since_rotation_++;
            bytes_since_rotation_ += frame.size();
        } catch (...) {
            wipe(frame);
            throw;
        }
        wipe(frame);
        return static_cast<int>(length);
    }

    int recv_record(std::uint8_t& type,
                    std::uint8_t* const output,
                    const std::size_t capacity) {
        require_ready();

        std::lock_guard lock{receive_mutex_};
        std::array<std::uint8_t,
                   WolfSslDatagramSocket::kMaximumPayloadSize + 3U> frame{};

        int received = 0;
        for (;;) {
            io_wait_milliseconds_.store(
                static_cast<long long>(kApplicationReadPoll.count()),
                std::memory_order_release);
            received = wolfSSL_read(
                read_ssl_.get(), frame.data(), static_cast<int>(frame.size()));
            if (received > 0) {
                break;
            }

            const int error = wolfSSL_get_error(read_ssl_.get(), received);
            if (error == WOLFSSL_ERROR_WANT_READ) {
                if (shutdown_started_.load(std::memory_order_acquire) ||
                    transport_->is_closed()) {
                    wipe(frame);
                    return -1;
                }
                continue;
            }
            if (error == WOLFSSL_ERROR_ZERO_RETURN ||
                shutdown_started_.load(std::memory_order_acquire) ||
                transport_->is_closed()) {
                wipe(frame);
                return -1;
            }
            wipe(frame);
            throw_wolf_error("wolfSSL_read(DTLS record)",
                             read_ssl_.get(), received);
        }

        if (received < 3) {
            wipe(frame);
            throw std::runtime_error("DTLS peer sent a truncated TrueTunnel frame");
        }

        type = frame[0];
        const auto length = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(frame[1]) << 8U) |
            static_cast<std::uint16_t>(frame[2]));
        if (length > WolfSslDatagramSocket::kMaximumPayloadSize ||
            received != static_cast<int>(3U + static_cast<std::size_t>(length))) {
            wipe(frame);
            throw std::runtime_error("DTLS peer sent an invalid TrueTunnel frame");
        }

        if (static_cast<std::size_t>(length) > capacity ||
            (length != 0U && output == nullptr)) {
            wipe(frame);
            return -1;
        }
        if (length != 0U) {
            std::memcpy(output, frame.data() + 3U, length);
        }
        wipe(frame);
        return static_cast<int>(length);
    }

    void shutdown() noexcept {
        if (shutdown_started_.exchange(true, std::memory_order_acq_rel)) {
            return;
        }

        if (handshake_complete_.load(std::memory_order_acquire) && write_ssl_) {
            try {
                std::unique_lock lock{send_mutex_, std::try_to_lock};
                if (lock.owns_lock()) {
                    (void)wolfSSL_shutdown(write_ssl_.get());
                }
            } catch (...) {
            }
        }
        handshake_complete_.store(false, std::memory_order_release);
        if (transport_) {
            transport_->close();
        }
    }

private:
    friend class WolfSslDatagramSocket;

    void maybe_rotate_keys() {
        const auto now = std::chrono::steady_clock::now();
        if (records_since_rotation_ < rotation_policy_.max_records &&
            bytes_since_rotation_ < rotation_policy_.max_bytes &&
            now - last_rotation_ < rotation_policy_.max_age) {
            return;
        }

        // wolfSSL 5.9.2 exposes wolfSSL_update_keys for TLS 1.3 and DTLS
        // 1.3. With non-blocking I/O, WANT_WRITE means the update is queued
        // and the following wolfSSL_write flushes it before application data.
        const int result = wolfSSL_update_keys(write_ssl_.get());
        if (result != WOLFSSL_SUCCESS && result != WOLFSSL_ERROR_WANT_WRITE) {
            rotation_failures_.fetch_add(1U, std::memory_order_relaxed);
            throw_wolf_error("wolfSSL_update_keys", write_ssl_.get(), result);
        }
        key_update_requests_.fetch_add(1U, std::memory_order_relaxed);
        records_since_rotation_ = 0U;
        bytes_since_rotation_ = 0U;
        last_rotation_ = now;
    }

    static int receive_callback(WOLFSSL*,
                                char* const buffer,
                                const int capacity,
                                void* const context) noexcept {
        auto* const self = static_cast<Impl*>(context);
        if (self == nullptr || buffer == nullptr || capacity <= 0) {
            return WOLFSSL_CBIO_ERR_GENERAL;
        }

        try {
            std::vector<std::uint8_t> datagram;
            const auto wait = std::chrono::milliseconds{
                std::max<long long>(1LL, self->io_wait_milliseconds_.load(
                                               std::memory_order_acquire))};
            const auto result =
                self->transport_->receive_datagram(datagram, wait);
            self->last_receive_result_.store(result, std::memory_order_release);

            switch (result) {
                case DatagramReceiveResult::Received:
                    if (datagram.size() > static_cast<std::size_t>(capacity) ||
                        datagram.size() >
                            static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
                        return WOLFSSL_CBIO_ERR_GENERAL;
                    }
                    std::memcpy(buffer, datagram.data(), datagram.size());
                    return static_cast<int>(datagram.size());
                case DatagramReceiveResult::Timeout:
                    return WOLFSSL_CBIO_ERR_WANT_READ;
                case DatagramReceiveResult::Closed:
                    return WOLFSSL_CBIO_ERR_CONN_CLOSE;
                case DatagramReceiveResult::Error:
                default:
                    return WOLFSSL_CBIO_ERR_GENERAL;
            }
        } catch (...) {
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }

    static int send_callback(WOLFSSL*,
                             char* const buffer,
                             const int length,
                             void* const context) noexcept {
        auto* const self = static_cast<Impl*>(context);
        if (self == nullptr || buffer == nullptr || length <= 0) {
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
        try {
            switch (self->transport_->send_datagram(
                reinterpret_cast<const std::uint8_t*>(buffer),
                static_cast<std::size_t>(length))) {
                case DatagramSendResult::Sent:
                    return length;
                case DatagramSendResult::WouldBlock:
                    return WOLFSSL_CBIO_ERR_WANT_WRITE;
                case DatagramSendResult::Closed:
                    return WOLFSSL_CBIO_ERR_CONN_CLOSE;
                case DatagramSendResult::Error:
                default:
                    return WOLFSSL_CBIO_ERR_GENERAL;
            }
        } catch (...) {
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }

    void configure_context() {
        context_ = make_context(is_server_);
        configure_context_psk_callback(context_.get(), is_server_);

        read_ssl_.reset(wolfSSL_new(context_.get()));
        if (!read_ssl_) {
            throw std::runtime_error("wolfSSL_new(DTLS 1.3) failed");
        }
        wolfSSL_SSLSetIORecv(read_ssl_.get(), &Impl::receive_callback);
        wolfSSL_SSLSetIOSend(read_ssl_.get(), &Impl::send_callback);
        wolfSSL_SetIOReadCtx(read_ssl_.get(), this);
        wolfSSL_SetIOWriteCtx(read_ssl_.get(), this);
        configure_ssl_profile(read_ssl_.get(), psk_material_.get());
    }

    void perform_handshake() {
        const auto deadline = std::chrono::steady_clock::now() +
                              kHandshakeTimeout;

        for (;;) {
            if (shutdown_started_.load(std::memory_order_acquire) ||
                transport_->is_closed()) {
                throw std::runtime_error("DTLS handshake was cancelled");
            }

            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) {
                throw std::runtime_error("DTLS handshake timed out");
            }

            const int timeout_seconds =
                std::max(1, wolfSSL_dtls_get_current_timeout(read_ssl_.get()));
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - now);
            const auto wait = std::min(
                remaining,
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::seconds{timeout_seconds}));
            io_wait_milliseconds_.store(
                std::max<long long>(1LL, wait.count()),
                std::memory_order_release);
            last_receive_result_.store(DatagramReceiveResult::Error,
                                       std::memory_order_release);

            const int result = is_server_ ? wolfSSL_accept(read_ssl_.get())
                                          : wolfSSL_connect(read_ssl_.get());
            if (result == WOLFSSL_SUCCESS) {
                return;
            }

            const int error = wolfSSL_get_error(read_ssl_.get(), result);
            if (error == WOLFSSL_ERROR_WANT_READ) {
                if (last_receive_result_.load(std::memory_order_acquire) ==
                    DatagramReceiveResult::Timeout) {
                    const int timeout_result =
                        wolfSSL_dtls_got_timeout(read_ssl_.get());
                    if (timeout_result != WOLFSSL_SUCCESS) {
                        throw_wolf_error("wolfSSL DTLS retransmission",
                                         read_ssl_.get(), timeout_result);
                    }
                }
                continue;
            }
            if (error == WOLFSSL_ERROR_WANT_WRITE) {
                continue;
            }
            throw_wolf_error(is_server_ ? "wolfSSL_accept(DTLS 1.3)"
                                        : "wolfSSL_connect(DTLS 1.3)",
                             read_ssl_.get(), result);
        }
    }

    void validate_profile() {
        if (wolfSSL_GetVersion(read_ssl_.get()) != WOLFSSL_DTLSV1_3) {
            throw std::runtime_error("wolfSSL negotiated a protocol other than DTLS 1.3");
        }

        const char* const cipher = wolfSSL_get_cipher_name(read_ssl_.get());
        if (cipher == nullptr || std::string_view{cipher} != kWolfCipherName) {
            throw std::runtime_error(
                "wolfSSL negotiated a cipher outside TLS_AES_256_GCM_SHA384");
        }

        const char* const curve = wolfSSL_get_curve_name(read_ssl_.get());
        if (curve == nullptr || std::string_view{curve} != kExpectedCurveName) {
            throw std::runtime_error(
                "wolfSSL negotiated a key exchange outside P-256 ECDHE");
        }
    }

    void require_ready() const {
        if (!handshake_complete_.load(std::memory_order_acquire) ||
            shutdown_started_.load(std::memory_order_acquire) || !write_ssl_) {
            throw std::runtime_error("DTLS handshake not complete");
        }
    }

    [[nodiscard]] TrafficKeyRotationStats rotation_stats() const noexcept {
        TrafficKeyRotationStats stats{};
        stats.sent_records = sent_records_.load(std::memory_order_relaxed);
        stats.sent_bytes = sent_bytes_.load(std::memory_order_relaxed);
        stats.key_update_requests =
            key_update_requests_.load(std::memory_order_relaxed);
        stats.rotation_failures =
            rotation_failures_.load(std::memory_order_relaxed);
        stats.application_initiation_supported = true;
        return stats;
    }

    std::unique_ptr<DatagramTransport> transport_;
    bool is_server_{false};
    std::shared_ptr<PskMaterial> psk_material_;
    ContextPtr context_;
    SslPtr read_ssl_;
    SslPtr write_ssl_;

    std::mutex handshake_mutex_;
    std::timed_mutex send_mutex_;
    std::mutex receive_mutex_;
    bool handshake_attempted_{false};
    std::atomic<bool> handshake_complete_{false};
    std::atomic<bool> shutdown_started_{false};
    std::atomic<long long> io_wait_milliseconds_{1'000LL};
    std::atomic<DatagramReceiveResult> last_receive_result_{
        DatagramReceiveResult::Error};
    TrafficKeyRotationPolicy rotation_policy_{};
    std::chrono::steady_clock::time_point last_rotation_{
        std::chrono::steady_clock::now()};
    std::uint64_t records_since_rotation_{0};
    std::uint64_t bytes_since_rotation_{0};
    std::atomic<std::uint64_t> sent_records_{0};
    std::atomic<std::uint64_t> sent_bytes_{0};
    std::atomic<std::uint64_t> key_update_requests_{0};
    std::atomic<std::uint64_t> rotation_failures_{0};
};

WolfSslDatagramSocket::WolfSslDatagramSocket(
    std::unique_ptr<DatagramTransport> transport,
    const std::span<const std::uint8_t> password,
    const bool is_server,
    const CipherSuite suite,
    const TrafficKeyRotationPolicy rotation_policy)
    : impl_{std::make_unique<Impl>(
          std::move(transport), password, is_server, suite, rotation_policy)} {}

WolfSslDatagramSocket::WolfSslDatagramSocket(
    std::unique_ptr<DatagramTransport> transport,
    PreparedWolfSslServerSession prepared,
    const TrafficKeyRotationPolicy rotation_policy)
    : impl_{std::make_unique<Impl>(
          std::move(transport), std::move(prepared), rotation_policy)} {}

WolfSslDatagramSocket::~WolfSslDatagramSocket() = default;

void WolfSslDatagramSocket::handshake() {
    impl_->handshake();
}

int WolfSslDatagramSocket::send_record(const std::uint8_t type,
                                       const std::uint8_t* const data,
                                       const std::uint16_t length) {
    return impl_->send_record(type, data, length);
}

int WolfSslDatagramSocket::recv_record(std::uint8_t& type,
                                       std::uint8_t* const output,
                                       const std::size_t capacity) {
    return impl_->recv_record(type, output, capacity);
}

void WolfSslDatagramSocket::shutdown() noexcept {
    impl_->shutdown();
}

TrafficKeyRotationStats WolfSslDatagramSocket::rotation_stats() const noexcept {
    return impl_->rotation_stats();
}

} // namespace secure
