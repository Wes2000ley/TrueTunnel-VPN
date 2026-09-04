#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef SCHANNEL_USE_BLACKLISTS
#define SCHANNEL_USE_BLACKLISTS
#endif

#include "SchannelSocket.h"

#include "CngUtils.h"
#include "SharedSecret.h"

#include <windows.h>
#include <winternl.h>
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>
#include <ncrypt.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <limits>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace secure {
namespace {

constexpr std::size_t kSocketReadSize = 16U * 1024U;
constexpr std::size_t kMaximumBufferedTlsBytes = 1024U * 1024U;
constexpr auto kHandshakeTimeout = std::chrono::seconds{15};
constexpr auto kApplicationWriteTimeout = std::chrono::seconds{5};
constexpr long kSocketPollMicroseconds = 200'000L;
constexpr std::uint16_t kTls13ProtocolVersion = 0x0304U;
constexpr std::uint16_t kTlsAes256GcmSha384 = 0x1302U;
constexpr ULONGLONG kPasswordKdfIterations = 100'000ULL;
constexpr std::array<std::uint8_t, 4> kAuthMagic{'T', 'T', 'A', '1'};
constexpr std::string_view kPasswordSaltLabel = "TrueTunnel password KDF v1";
constexpr std::string_view kProofLabel = "TrueTunnel password proof v1";
constexpr std::string_view kContinuityLabel =
    "TrueTunnel session continuity binding v1";
constexpr std::string_view kReplacementProofLabel =
    "TrueTunnel session replacement proof v2";

enum class AuthMessage : std::uint8_t {
    ClientNonce = 1,
    ServerNonce = 2,
    ClientProof = 3,
    ServerProof = 4,
};

[[nodiscard]] std::string hex_status(const unsigned long status) {
    std::ostringstream stream;
    stream << "0x" << std::hex << std::uppercase << std::setw(8)
           << std::setfill('0') << status;
    return stream.str();
}

[[noreturn]] void throw_security_status(const std::string_view operation,
                                        const SECURITY_STATUS status) {
    throw std::runtime_error(std::string(operation) + " failed (" +
                             hex_status(static_cast<unsigned long>(status)) + ")");
}

[[noreturn]] void throw_ncrypt_status(const std::string_view operation,
                                      const SECURITY_STATUS status) {
    throw std::runtime_error(std::string(operation) + " failed (" +
                             hex_status(static_cast<unsigned long>(status)) + ")");
}

[[noreturn]] void throw_last_error(const std::string_view operation) {
    const DWORD error = ::GetLastError();
    throw std::runtime_error(std::string(operation) + " failed (" +
                             hex_status(error) + ")");
}

[[noreturn]] void throw_winsock_error(const std::string_view operation) {
    const int error = ::WSAGetLastError();
    throw std::runtime_error(std::string(operation) + " failed (" +
                             std::to_string(error) + ")");
}

void check_ncrypt(const std::string_view operation,
                  const SECURITY_STATUS status) {
    if (status != ERROR_SUCCESS) {
        throw_ncrypt_status(operation, status);
    }
}

void wipe(std::vector<std::uint8_t>& bytes) noexcept {
    if (!bytes.empty()) {
        ::SecureZeroMemory(bytes.data(), bytes.size());
    }
    bytes.clear();
}

template <std::size_t Size>
void wipe(std::array<std::uint8_t, Size>& bytes) noexcept {
    ::SecureZeroMemory(bytes.data(), bytes.size());
}

class ContextBufferGuard final {
public:
    explicit ContextBufferGuard(SecBuffer& buffer) noexcept : buffer_{buffer} {}
    ~ContextBufferGuard() {
        if (buffer_.pvBuffer != nullptr) {
            ::FreeContextBuffer(buffer_.pvBuffer);
            buffer_.pvBuffer = nullptr;
            buffer_.cbBuffer = 0;
        }
    }

    ContextBufferGuard(const ContextBufferGuard&) = delete;
    ContextBufferGuard& operator=(const ContextBufferGuard&) = delete;

private:
    SecBuffer& buffer_;
};

[[nodiscard]] std::uint16_t decode_u16(const std::uint8_t* bytes) noexcept {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[0]) << 8U) |
                                      static_cast<std::uint16_t>(bytes[1]));
}

void encode_u16(const std::uint16_t value, std::uint8_t* output) noexcept {
    output[0] = static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
    output[1] = static_cast<std::uint8_t>(value & 0xFFU);
}

[[nodiscard]] std::wstring make_transient_key_name() {
    std::array<std::uint8_t, 16> random{};
    random_bytes(random.data(), random.size());

    constexpr std::wstring_view prefix = L"TrueTunnel-TLS-";
    constexpr std::wstring_view hex = L"0123456789abcdef";
    std::wstring name;
    name.reserve(prefix.size() + random.size() * 2U);
    name.append(prefix);
    for (const std::uint8_t byte : random) {
        name.push_back(hex[(byte >> 4U) & 0x0FU]);
        name.push_back(hex[byte & 0x0FU]);
    }
    wipe(random);
    return name;
}

} // namespace

class SchannelSocket::Impl final {
public:
    Impl(const SOCKET socket,
         const std::span<const std::uint8_t> password,
         const bool is_server,
         const CipherSuite suite,
         const TrafficKeyRotationPolicy rotation_policy)
        : socket_{socket},
          is_server_{is_server},
          suite_{suite},
          rotation_policy_{rotation_policy} {
        SecInvalidateHandle(&credential_);
        SecInvalidateHandle(&context_);

        if (socket_ == INVALID_SOCKET) {
            throw std::invalid_argument("Schannel requires a valid TCP socket");
        }
        require_valid_shared_secret(password);
        if (suite_ != CipherSuite::Aes256Gcm) {
            throw std::invalid_argument(
                "Native TCP TLS requires TLS_AES_256_GCM_SHA384; "
                "alternate ciphers remain available for UDP mode");
        }
        u_long nonblocking = 1UL;
        if (::ioctlsocket(socket_, FIONBIO, &nonblocking) == SOCKET_ERROR) {
            throw_winsock_error("ioctlsocket(FIONBIO Schannel)");
        }
        password_.assign(password.begin(), password.end());
    }

    ~Impl() {
        shutdown();
        cleanup();
    }

    void handshake() {
        std::lock_guard lock{handshake_mutex_};
        if (handshake_complete_.load(std::memory_order_acquire)) {
            return;
        }
        if (shutdown_started_.load(std::memory_order_acquire)) {
            throw std::runtime_error("TLS connection is shutting down");
        }
        if (handshake_attempted_) {
            throw std::runtime_error("Schannel handshake cannot be retried");
        }
        handshake_attempted_ = true;
        handshake_in_progress_ = true;
        handshake_deadline_ =
            std::chrono::steady_clock::now() + kHandshakeTimeout;

        try {
            if (is_server_) {
                create_ephemeral_server_certificate();
            }
            acquire_credentials();

            {
                std::lock_guard context_lock{context_mutex_};
                negotiate_initial_context();
                validate_negotiated_context();
            }

            authenticate_password();
            wipe(password_);
            established_ticks_.store(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now().time_since_epoch())
                    .count(),
                std::memory_order_release);
            if (shutdown_started_.load(std::memory_order_acquire)) {
                throw std::runtime_error("TLS connection was closed during authentication");
            }
            handshake_complete_.store(true, std::memory_order_release);
            if (shutdown_started_.load(std::memory_order_acquire)) {
                handshake_complete_.store(false, std::memory_order_release);
                throw std::runtime_error("TLS connection was closed during authentication");
            }
            handshake_in_progress_ = false;
        } catch (...) {
            handshake_in_progress_ = false;
            wipe(password_);
            throw;
        }
    }

    int send_record(const std::uint8_t type,
                    const std::uint8_t* data,
                    const std::uint16_t length) {
        return send_record_until(type, data, length,
                                 std::chrono::steady_clock::now() +
                                     kApplicationWriteTimeout);
    }

    int send_record_until(
        const std::uint8_t type,
        const std::uint8_t* data,
        const std::uint16_t length,
        const std::chrono::steady_clock::time_point deadline) {
        require_ready();
        if (length != 0U && data == nullptr) {
            throw std::invalid_argument("send_record received a null payload");
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            throw std::runtime_error("Schannel TLS application write timed out");
        }

        // Keep the prospective limit check, TLS write, and accounting in one
        // critical section. Direct SchannelSocket callers need this guarantee
        // even when SecureSocket is not providing an outer lock.
        std::unique_lock<std::timed_mutex> accounting_lock{
            send_accounting_mutex_, std::defer_lock};
        if (!accounting_lock.try_lock_until(deadline)) {
            throw std::runtime_error("Schannel TLS application write timed out");
        }
        require_ready();
        enforce_hard_rotation_policy(/*sending=*/true, length);

        std::vector<std::uint8_t> frame(3U + static_cast<std::size_t>(length));
        frame[0] = type;
        encode_u16(length, frame.data() + 1U);
        if (length != 0U) {
            std::memcpy(frame.data() + 3U, data, length);
        }

        try {
            send_plaintext(frame, deadline);
        } catch (...) {
            application_write_poisoned_.store(true, std::memory_order_release);
            wipe(frame);
            throw;
        }
        wipe(frame);
        sent_records_.fetch_add(1U, std::memory_order_relaxed);
        sent_bytes_.fetch_add(length, std::memory_order_relaxed);
        return static_cast<int>(length);
    }

    int recv_record(std::uint8_t& type,
                    std::uint8_t* output,
                    const std::size_t capacity) {
        return recv_record_impl(type, output, capacity, {});
    }

    int recv_record_until(
        std::uint8_t& type,
        std::uint8_t* output,
        const std::size_t capacity,
        const std::chrono::steady_clock::time_point deadline) {
        if (std::chrono::steady_clock::now() >= deadline) {
            throw std::runtime_error("Schannel TLS application read timed out");
        }
        return recv_record_impl(type, output, capacity, deadline);
    }

    int recv_record_impl(
        std::uint8_t& type,
        std::uint8_t* output,
        const std::size_t capacity,
        const std::chrono::steady_clock::time_point deadline) {
        require_ready();

        std::unique_lock<std::timed_mutex> receive_lock{
            receive_mutex_, std::defer_lock};
        if (deadline == std::chrono::steady_clock::time_point{}) {
            receive_lock.lock();
        } else if (!receive_lock.try_lock_until(deadline)) {
            throw std::runtime_error("Schannel TLS application read timed out");
        }
        require_ready();
        enforce_hard_rotation_policy(/*sending=*/false, 0U);
        std::array<std::uint8_t, 3> header{};
        std::size_t header_bytes_read = 0U;
        try {
            if (!read_plaintext_exact(header, deadline, &header_bytes_read)) {
                if (header_bytes_read != 0U) {
                    receive_poisoned_.store(true, std::memory_order_release);
                }
                return -1;
            }
        } catch (...) {
            if (header_bytes_read != 0U) {
                receive_poisoned_.store(true, std::memory_order_release);
            }
            throw;
        }

        type = header[0];
        const std::uint16_t length = decode_u16(header.data() + 1U);
        try {
            // The header is consumed before this check. A crossing record is
            // terminal because accepting a later record would desynchronize
            // the stream's framing and accounting.
            enforce_hard_rotation_policy(/*sending=*/false, length);
        } catch (...) {
            receive_poisoned_.store(true, std::memory_order_release);
            throw;
        }
        std::vector<std::uint8_t> payload(length);
        std::size_t payload_bytes_read = 0U;
        try {
            if (!read_plaintext_exact(payload, deadline, &payload_bytes_read)) {
                wipe(payload);
                if (header_bytes_read != 0U || payload_bytes_read != 0U) {
                    receive_poisoned_.store(true, std::memory_order_release);
                }
                return -1;
            }
        } catch (...) {
            wipe(payload);
            // An idle pre-frame timeout remains recoverable. Once this
            // frame's header or payload has been consumed, retrying could
            // reinterpret the remaining bytes, so fail closed.
            if (header_bytes_read != 0U || payload_bytes_read != 0U) {
                receive_poisoned_.store(true, std::memory_order_release);
            }
            throw;
        }

        // Count the protected application record once its complete plaintext
        // has been accepted, even when the caller supplied an undersized
        // destination. The key-epoch guard must not be bypassable by asking
        // for a rejected buffer size repeatedly.
        received_records_.fetch_add(1U, std::memory_order_relaxed);
        received_bytes_.fetch_add(length, std::memory_order_relaxed);
        if (static_cast<std::size_t>(length) > capacity ||
            (length != 0U && output == nullptr)) {
            wipe(payload);
            return -1;
        }
        if (length != 0U) {
            std::memcpy(output, payload.data(), length);
        }
        wipe(payload);
        return static_cast<int>(length);
    }

#ifdef TRUETUNNEL_SECURE_TRANSPORT_TEST
    void set_test_partial_write_failure_after(
        const std::size_t ciphertext_bytes) {
        if (ciphertext_bytes == 0U) {
            throw std::invalid_argument(
                "Partial-write injection requires at least one ciphertext byte");
        }
        test_partial_write_bytes_remaining_.store(
            ciphertext_bytes, std::memory_order_release);
    }

    void set_test_plaintext_chunk_pause_after(
        const std::size_t completed_chunks,
        const std::chrono::milliseconds pause) {
        if (completed_chunks == 0U || pause <= std::chrono::milliseconds::zero()) {
            throw std::invalid_argument(
                "Plaintext chunk pause requires a positive chunk count and duration");
        }
        test_plaintext_chunk_pause_milliseconds_.store(
            pause.count(),
            std::memory_order_release);
        test_plaintext_chunk_pause_after_.store(
            completed_chunks, std::memory_order_release);
    }
#endif

    void shutdown() noexcept {
        if (shutdown_started_.exchange(true, std::memory_order_acq_rel)) {
            return;
        }
        // A raw socket shutdown must be allowed to interrupt a stalled initial
        // handshake. Only a fully authenticated connection gets close_notify.
        if (!handshake_complete_.load(std::memory_order_acquire)) {
            return;
        }

        try {
            std::unique_lock send_lock{send_mutex_, std::try_to_lock};
            if (!send_lock.owns_lock()) {
                return;
            }
            std::unique_lock context_lock{context_mutex_, std::try_to_lock};
            if (!context_lock.owns_lock()) {
                return;
            }
            if (!tls_negotiated_ || !context_valid_) {
                return;
            }

            DWORD shutdown_token = SCHANNEL_SHUTDOWN;
            SecBuffer control_buffer{};
            control_buffer.BufferType = SECBUFFER_TOKEN;
            control_buffer.cbBuffer = sizeof(shutdown_token);
            control_buffer.pvBuffer = &shutdown_token;
            SecBufferDesc control_desc{};
            control_desc.ulVersion = SECBUFFER_VERSION;
            control_desc.cBuffers = 1;
            control_desc.pBuffers = &control_buffer;

            if (::ApplyControlToken(&context_, &control_desc) != SEC_E_OK) {
                return;
            }

            SecBuffer output{};
            output.BufferType = SECBUFFER_TOKEN;
            SecBufferDesc output_desc{};
            output_desc.ulVersion = SECBUFFER_VERSION;
            output_desc.cBuffers = 1;
            output_desc.pBuffers = &output;
            ContextBufferGuard output_guard{output};

            const SECURITY_STATUS status = context_step(nullptr, output_desc);
            if ((status == SEC_E_OK || status == SEC_I_CONTEXT_EXPIRED ||
                 status == SEC_I_CONTINUE_NEEDED) &&
                output.pvBuffer != nullptr && output.cbBuffer != 0U) {
                (void)write_all_noexcept(
                    {static_cast<const std::uint8_t*>(output.pvBuffer), output.cbBuffer},
                    /*allow_shutdown=*/true);
            }
        } catch (...) {
            // close_notify is best effort; the owner still closes the socket.
        }
    }

private:
    friend class SchannelSocket;

    void enforce_hard_rotation_policy(const bool sending,
                                      const std::size_t payload_length) const {
        const auto records = (sending ? sent_records_ : received_records_)
                                 .load(std::memory_order_acquire);
        const auto bytes = (sending ? sent_bytes_ : received_bytes_)
                               .load(std::memory_order_acquire);
        if (records == (std::numeric_limits<std::uint64_t>::max)() ||
            payload_length >
                (std::numeric_limits<std::uint64_t>::max)() - bytes) {
            throw std::runtime_error(
                "TLS traffic-key accounting limit reached; replacement required");
        }
        if ((rotation_policy_.max_records != 0U &&
             records >= rotation_policy_.max_records) ||
            (rotation_policy_.max_bytes != 0U &&
             (bytes > rotation_policy_.max_bytes ||
              payload_length > rotation_policy_.max_bytes - bytes))) {
            throw std::runtime_error(
                "TLS traffic-key hard record/byte limit reached; replacement required");
        }
        const auto established = established_ticks_.load(std::memory_order_acquire);
        if (rotation_policy_.max_age > std::chrono::seconds::zero() &&
            established > 0) {
            const auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            // Compare in whole seconds instead of converting an arbitrary
            // caller-supplied duration to nanoseconds (which can overflow a
            // signed 64-bit representation for very large policies).
            if (now >= established &&
                static_cast<std::uint64_t>(now - established) /
                        1'000'000'000ULL >=
                    static_cast<std::uint64_t>(rotation_policy_.max_age.count())) {
                throw std::runtime_error(
                    "TLS traffic-key hard age limit reached; replacement required");
            }
        }
    }

    void require_ready() const {
        if (!handshake_complete_.load(std::memory_order_acquire)) {
            throw std::runtime_error("TLS handshake is not complete");
        }
        if (shutdown_started_.load(std::memory_order_acquire)) {
            throw std::runtime_error("TLS connection is shutting down");
        }
        if (receive_poisoned_.load(std::memory_order_acquire)) {
            throw std::runtime_error(
                "TLS application stream is unusable after a partial frame failure");
        }
        if (application_write_poisoned_.load(std::memory_order_acquire)) {
            throw std::runtime_error(
                "TLS application stream is unusable after a failed record write");
        }
    }

    void cleanup() noexcept {
        wipe(password_);
        {
            std::lock_guard continuity_lock{continuity_mutex_};
            wipe(continuity_binding_);
        }
        wipe(encrypted_input_);
        wipe(plaintext_input_);
        wipe(socket_read_buffer_);

        if (context_valid_) {
            ::DeleteSecurityContext(&context_);
            context_valid_ = false;
            SecInvalidateHandle(&context_);
        }
        if (credential_valid_) {
            ::FreeCredentialsHandle(&credential_);
            credential_valid_ = false;
            SecInvalidateHandle(&credential_);
        }
        if (certificate_ != nullptr) {
            ::CertFreeCertificateContext(certificate_);
            certificate_ = nullptr;
        }
        if (certificate_key_ != 0U) {
            if (::NCryptDeleteKey(certificate_key_, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS) {
                ::NCryptFreeObject(certificate_key_);
            }
            certificate_key_ = 0U;
        }
        key_name_.clear();
        if (key_provider_ != 0U) {
            ::NCryptFreeObject(key_provider_);
            key_provider_ = 0U;
        }
    }

    void create_ephemeral_server_certificate() {
        check_ncrypt("NCryptOpenStorageProvider",
                     ::NCryptOpenStorageProvider(&key_provider_,
                                                 MS_KEY_STORAGE_PROVIDER,
                                                 0));
        // NCryptCreatePersistedKey supports a null name for ephemeral keys,
        // but Schannel's certificate credential path requires provider-info
        // that names the key container. Use a random per-connection name and
        // delete it during cleanup; crash leftovers are therefore unguessable.
        key_name_ = make_transient_key_name();
        check_ncrypt("NCryptCreatePersistedKey",
                     ::NCryptCreatePersistedKey(key_provider_,
                                                &certificate_key_,
                                                NCRYPT_ECDSA_P384_ALGORITHM,
                                                key_name_.c_str(),
                                                0,
                                                0));
        DWORD export_policy = 0;
        check_ncrypt("NCryptSetProperty(NCRYPT_EXPORT_POLICY_PROPERTY)",
                     ::NCryptSetProperty(certificate_key_,
                                         NCRYPT_EXPORT_POLICY_PROPERTY,
                                         reinterpret_cast<PBYTE>(&export_policy),
                                         sizeof(export_policy),
                                         0));
        check_ncrypt("NCryptFinalizeKey", ::NCryptFinalizeKey(certificate_key_, 0));

        constexpr wchar_t subject[] = L"CN=TrueTunnel Ephemeral";
        DWORD encoded_size = 0;
        if (!::CertStrToNameW(X509_ASN_ENCODING,
                              subject,
                              CERT_X500_NAME_STR,
                              nullptr,
                              nullptr,
                              &encoded_size,
                              nullptr)) {
            throw_last_error("CertStrToNameW(size)");
        }

        std::vector<std::uint8_t> encoded_subject(encoded_size);
        if (!::CertStrToNameW(X509_ASN_ENCODING,
                              subject,
                              CERT_X500_NAME_STR,
                              nullptr,
                              encoded_subject.data(),
                              &encoded_size,
                              nullptr)) {
            throw_last_error("CertStrToNameW");
        }

        CERT_NAME_BLOB subject_blob{};
        subject_blob.cbData = encoded_size;
        subject_blob.pbData = encoded_subject.data();

        CRYPT_ALGORITHM_IDENTIFIER signature_algorithm{};
        signature_algorithm.pszObjId = const_cast<LPSTR>(szOID_ECDSA_SHA384);

        CRYPT_KEY_PROV_INFO provider_info{};
        provider_info.pwszContainerName = key_name_.data();
        provider_info.pwszProvName = const_cast<LPWSTR>(MS_KEY_STORAGE_PROVIDER);
        provider_info.dwFlags = CERT_SET_KEY_CONTEXT_PROP_ID;

        certificate_ = ::CertCreateSelfSignCertificate(
            certificate_key_,
            &subject_blob,
            0,
            &provider_info,
            &signature_algorithm,
            nullptr,
            nullptr,
            nullptr);
        if (certificate_ == nullptr) {
            throw_last_error("CertCreateSelfSignCertificate");
        }

        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE acquired_key = 0;
        DWORD key_spec = 0;
        BOOL caller_must_free = FALSE;
        constexpr DWORD acquire_flags = CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG |
                                        CRYPT_ACQUIRE_CACHE_FLAG |
                                        CRYPT_ACQUIRE_COMPARE_KEY_FLAG |
                                        CRYPT_ACQUIRE_USE_PROV_INFO_FLAG |
                                        CRYPT_ACQUIRE_SILENT_FLAG;
        if (!::CryptAcquireCertificatePrivateKey(certificate_,
                                                  acquire_flags,
                                                  nullptr,
                                                  &acquired_key,
                                                  &key_spec,
                                                  &caller_must_free)) {
            throw_last_error("CryptAcquireCertificatePrivateKey");
        }
        if (key_spec != CERT_NCRYPT_KEY_SPEC) {
            if (caller_must_free) {
                ::NCryptFreeObject(acquired_key);
            }
            throw std::runtime_error("ephemeral certificate private-key binding is invalid");
        }
        if (caller_must_free) {
            ::NCryptFreeObject(acquired_key);
        }
    }

    void acquire_credentials() {
        TLS_PARAMETERS tls_parameters{};
        tls_parameters.grbitDisabledProtocols = is_server_
            ? (SP_PROT_X_SERVERS & ~SP_PROT_TLS1_3_SERVER)
            : (SP_PROT_X_CLIENTS & ~SP_PROT_TLS1_3_CLIENT);

        SCH_CREDENTIALS credentials{};
        credentials.dwVersion = SCH_CREDENTIALS_VERSION;
        credentials.dwFlags = SCH_USE_STRONG_CRYPTO;
        credentials.cTlsParameters = 1;
        credentials.pTlsParameters = &tls_parameters;

        PCCERT_CONTEXT certificate = certificate_;
        if (is_server_) {
            credentials.cCreds = 1;
            credentials.paCred = &certificate;
            credentials.dwFlags |= SCH_CRED_NO_SYSTEM_MAPPER |
                                   SCH_CRED_DISABLE_RECONNECTS |
                                   SCH_CRED_MEMORY_STORE_CERT;
        } else {
            credentials.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION |
                                   SCH_CRED_NO_DEFAULT_CREDS;
        }

        TimeStamp expiry{};
        const SECURITY_STATUS status = ::AcquireCredentialsHandleW(
            nullptr,
            const_cast<LPWSTR>(UNISP_NAME_W),
            is_server_ ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND,
            nullptr,
            &credentials,
            nullptr,
            nullptr,
            &credential_,
            &expiry);
        if (status != SEC_E_OK) {
            throw_security_status("AcquireCredentialsHandleW", status);
        }
        credential_valid_ = true;
    }

    [[nodiscard]] ULONG requested_context_flags() const noexcept {
        if (is_server_) {
            return ASC_REQ_SEQUENCE_DETECT |
                   ASC_REQ_REPLAY_DETECT |
                   ASC_REQ_CONFIDENTIALITY |
                   ASC_REQ_EXTENDED_ERROR |
                   ASC_REQ_ALLOCATE_MEMORY |
                   ASC_REQ_STREAM;
        }
        return ISC_REQ_SEQUENCE_DETECT |
               ISC_REQ_REPLAY_DETECT |
               ISC_REQ_CONFIDENTIALITY |
               ISC_REQ_EXTENDED_ERROR |
               ISC_REQ_ALLOCATE_MEMORY |
               ISC_REQ_STREAM |
               ISC_REQ_MANUAL_CRED_VALIDATION;
    }

    SECURITY_STATUS context_step(SecBufferDesc* input,
                                 SecBufferDesc& output) noexcept {
        SECURITY_STATUS status = SEC_E_INTERNAL_ERROR;
        if (is_server_) {
            status = ::AcceptSecurityContext(
                &credential_,
                context_valid_ ? &context_ : nullptr,
                input,
                requested_context_flags(),
                SECURITY_NATIVE_DREP,
                &context_,
                &output,
                &context_attributes_,
                nullptr);
        } else {
            status = ::InitializeSecurityContextW(
                &credential_,
                context_valid_ ? &context_ : nullptr,
                const_cast<LPWSTR>(L"TrueTunnel"),
                requested_context_flags(),
                0,
                SECURITY_NATIVE_DREP,
                input,
                0,
                &context_,
                &output,
                &context_attributes_,
                nullptr);
        }

        if (SecIsValidHandle(&context_)) {
            context_valid_ = true;
        }
        return status;
    }

    SECURITY_STATUS complete_auth_token_if_needed(SECURITY_STATUS status,
                                                   SecBufferDesc& output) {
        if (status != SEC_I_COMPLETE_NEEDED &&
            status != SEC_I_COMPLETE_AND_CONTINUE) {
            return status;
        }

        const SECURITY_STATUS completion = ::CompleteAuthToken(&context_, &output);
        if (completion != SEC_E_OK) {
            throw_security_status("CompleteAuthToken", completion);
        }
        return status == SEC_I_COMPLETE_NEEDED ? SEC_E_OK : SEC_I_CONTINUE_NEEDED;
    }

    void send_context_output(
        SecBuffer& output,
        const std::chrono::steady_clock::time_point deadline = {}) {
        if (output.pvBuffer == nullptr || output.cbBuffer == 0U) {
            return;
        }
        write_all({static_cast<const std::uint8_t*>(output.pvBuffer), output.cbBuffer},
                  false, deadline);
    }

    void preserve_extra(const SecBufferDesc& input,
                        std::vector<std::uint8_t>& source) {
        const SecBuffer* extra = nullptr;
        for (ULONG index = 0; index < input.cBuffers; ++index) {
            if (input.pBuffers[index].BufferType == SECBUFFER_EXTRA) {
                extra = &input.pBuffers[index];
                break;
            }
        }

        if (extra == nullptr || extra->cbBuffer == 0U) {
            wipe(source);
            return;
        }
        if (extra->cbBuffer > source.size()) {
            throw std::runtime_error("Schannel returned an invalid SECBUFFER_EXTRA");
        }

        const auto* begin = static_cast<const std::uint8_t*>(extra->pvBuffer);
        const auto source_begin = reinterpret_cast<std::uintptr_t>(source.data());
        const auto source_end = source_begin + source.size();
        const auto extra_begin = reinterpret_cast<std::uintptr_t>(begin);
        const auto extra_end = extra_begin + extra->cbBuffer;
        if (begin == nullptr || extra_begin < source_begin || extra_end > source_end) {
            begin = source.data() + (source.size() - extra->cbBuffer);
        }

        std::vector<std::uint8_t> remaining(begin, begin + extra->cbBuffer);
        wipe(source);
        source.swap(remaining);
    }

    void negotiate_initial_context() {
        bool first_client_call = !is_server_;
        if (is_server_) {
            read_more(encrypted_input_);
        }

        for (;;) {
            SecBuffer input_buffers[2]{};
            SecBufferDesc input_desc{};
            SecBufferDesc* input = nullptr;
            if (!first_client_call) {
                input_buffers[0].BufferType = SECBUFFER_TOKEN;
                input_buffers[0].cbBuffer = static_cast<unsigned long>(encrypted_input_.size());
                input_buffers[0].pvBuffer = encrypted_input_.data();
                input_buffers[1].BufferType = SECBUFFER_EMPTY;
                input_desc.ulVersion = SECBUFFER_VERSION;
                input_desc.cBuffers = 2;
                input_desc.pBuffers = input_buffers;
                input = &input_desc;
            }

            SecBuffer output_buffer{};
            output_buffer.BufferType = SECBUFFER_TOKEN;
            SecBufferDesc output_desc{};
            output_desc.ulVersion = SECBUFFER_VERSION;
            output_desc.cBuffers = 1;
            output_desc.pBuffers = &output_buffer;
            ContextBufferGuard output_guard{output_buffer};

            SECURITY_STATUS status = context_step(input, output_desc);
            status = complete_auth_token_if_needed(status, output_desc);
            send_context_output(output_buffer);

            if (status == SEC_E_INCOMPLETE_MESSAGE) {
                if (first_client_call) {
                    throw std::runtime_error(
                        "Schannel requested input during the initial client call");
                }
                read_more(encrypted_input_);
                continue;
            }

            if (input != nullptr) {
                preserve_extra(*input, encrypted_input_);
            }
            first_client_call = false;

            if (status == SEC_E_OK) {
                tls_negotiated_ = true;
                return;
            }
            if (status == SEC_I_INCOMPLETE_CREDENTIALS) {
                throw std::runtime_error(
                    "The peer requested unsupported TLS certificate authentication");
            }
            if (status != SEC_I_CONTINUE_NEEDED) {
                throw_security_status(is_server_ ? "AcceptSecurityContext"
                                                 : "InitializeSecurityContextW",
                                      status);
            }
            if (encrypted_input_.empty()) {
                read_more(encrypted_input_);
            }
        }
    }

    void validate_negotiated_context() {
        const ULONG confidentiality_flag =
            is_server_ ? ASC_RET_CONFIDENTIALITY : ISC_RET_CONFIDENTIALITY;
        const ULONG sequence_flag =
            is_server_ ? ASC_RET_SEQUENCE_DETECT : ISC_RET_SEQUENCE_DETECT;
        const ULONG replay_flag =
            is_server_ ? ASC_RET_REPLAY_DETECT : ISC_RET_REPLAY_DETECT;
        if ((context_attributes_ & confidentiality_flag) == 0U ||
            (context_attributes_ & sequence_flag) == 0U ||
            (context_attributes_ & replay_flag) == 0U) {
            throw std::runtime_error(
                "Schannel did not grant the required confidentiality and ordering guarantees");
        }

        SecPkgContext_CipherInfo cipher_info{};
        cipher_info.dwVersion = SECPKGCONTEXT_CIPHERINFO_V1;
        SECURITY_STATUS status = ::QueryContextAttributesW(
            &context_, SECPKG_ATTR_CIPHER_INFO, &cipher_info);
        if (status != SEC_E_OK) {
            throw_security_status("QueryContextAttributesW(CIPHER_INFO)", status);
        }

        if (cipher_info.dwProtocol != kTls13ProtocolVersion ||
            cipher_info.dwCipherSuite != kTlsAes256GcmSha384 ||
            cipher_info.dwCipherLen != 256U) {
            throw std::runtime_error(
                "Schannel negotiated outside the required "
                "TLS 1.3 / TLS_AES_256_GCM_SHA384 profile "
                "(protocol=" + hex_status(cipher_info.dwProtocol) +
                ", suite=" + hex_status(cipher_info.dwCipherSuite) +
                ", cipher_bits=" + std::to_string(cipher_info.dwCipherLen) + ")");
        }

        if (!is_server_) {
            PCCERT_CONTEXT remote_certificate = nullptr;
            status = ::QueryContextAttributesW(
                &context_, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &remote_certificate);
            if (status != SEC_E_OK || remote_certificate == nullptr) {
                if (remote_certificate != nullptr) {
                    ::CertFreeCertificateContext(remote_certificate);
                }
                throw std::runtime_error("The TLS server did not present a certificate");
            }
            ::CertFreeCertificateContext(remote_certificate);
        }

        status = ::QueryContextAttributesW(
            &context_, SECPKG_ATTR_STREAM_SIZES, &stream_sizes_);
        if (status != SEC_E_OK) {
            throw_security_status("QueryContextAttributesW(STREAM_SIZES)", status);
        }
        if (stream_sizes_.cbHeader == 0U ||
            stream_sizes_.cbTrailer == 0U ||
            stream_sizes_.cbMaximumMessage < 3U) {
            throw std::runtime_error("Schannel returned invalid TLS stream sizes");
        }
    }

    [[nodiscard]] std::array<std::uint8_t, 32> export_keying_material() {
        char exporter_label[] = "EXPORTER-TrueTunnel-Auth-v1";
        SecPkgContext_KeyingMaterialInfo request{};
        request.cbLabel = static_cast<WORD>(sizeof(exporter_label));
        request.pszLabel = exporter_label;
        request.cbContextValue = 0;
        request.pbContextValue = nullptr;
        request.cbKeyingMaterial = 32;

        SECURITY_STATUS status = ::SetContextAttributesW(
            &context_,
            SECPKG_ATTR_KEYING_MATERIAL_INFO,
            &request,
            sizeof(request));
        if (status != SEC_E_OK) {
            throw_security_status("SetContextAttributesW(KEYING_MATERIAL_INFO)", status);
        }

        SecPkgContext_KeyingMaterial material{};
        status = ::QueryContextAttributesW(
            &context_, SECPKG_ATTR_KEYING_MATERIAL, &material);
        if (status != SEC_E_OK) {
            if (material.pbKeyingMaterial != nullptr) {
                ::SecureZeroMemory(material.pbKeyingMaterial,
                                   material.cbKeyingMaterial);
                ::FreeContextBuffer(material.pbKeyingMaterial);
            }
            throw_security_status("QueryContextAttributesW(KEYING_MATERIAL)", status);
        }

        std::array<std::uint8_t, 32> result{};
        if (material.pbKeyingMaterial == nullptr ||
            material.cbKeyingMaterial != result.size()) {
            if (material.pbKeyingMaterial != nullptr) {
                ::SecureZeroMemory(material.pbKeyingMaterial, material.cbKeyingMaterial);
                ::FreeContextBuffer(material.pbKeyingMaterial);
            }
            throw std::runtime_error("Schannel returned invalid TLS exporter material");
        }

        std::memcpy(result.data(), material.pbKeyingMaterial, result.size());
        ::SecureZeroMemory(material.pbKeyingMaterial, material.cbKeyingMaterial);
        ::FreeContextBuffer(material.pbKeyingMaterial);
        return result;
    }

    [[nodiscard]] std::array<std::uint8_t, 32> derive_password_key(
        const std::array<std::uint8_t, 32>& exporter,
        const std::array<std::uint8_t, 32>& client_nonce,
        const std::array<std::uint8_t, 32>& server_nonce) const {
        std::vector<std::uint8_t> salt;
        salt.reserve(kPasswordSaltLabel.size() + exporter.size() +
                     client_nonce.size() + server_nonce.size() + 2U);
        salt.insert(salt.end(), kPasswordSaltLabel.begin(), kPasswordSaltLabel.end());
        salt.insert(salt.end(), exporter.begin(), exporter.end());
        salt.insert(salt.end(), client_nonce.begin(), client_nonce.end());
        salt.insert(salt.end(), server_nonce.begin(), server_nonce.end());
        salt.push_back(static_cast<std::uint8_t>(kTlsAes256GcmSha384 >> 8U));
        salt.push_back(static_cast<std::uint8_t>(kTlsAes256GcmSha384 & 0xFFU));

        BCRYPT_ALG_HANDLE algorithm = nullptr;
        NTSTATUS ntstatus = ::BCryptOpenAlgorithmProvider(
            &algorithm,
            BCRYPT_SHA256_ALGORITHM,
            nullptr,
            BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (!BCRYPT_SUCCESS(ntstatus)) {
            wipe(salt);
            throw std::runtime_error("BCryptOpenAlgorithmProvider(PBKDF2) failed (" +
                                     hex_status(static_cast<unsigned long>(ntstatus)) + ")");
        }

        std::array<std::uint8_t, 32> key{};
        ntstatus = ::BCryptDeriveKeyPBKDF2(
            algorithm,
            const_cast<PUCHAR>(password_.data()),
            static_cast<ULONG>(password_.size()),
            salt.data(),
            static_cast<ULONG>(salt.size()),
            kPasswordKdfIterations,
            key.data(),
            static_cast<ULONG>(key.size()),
            0);
        ::BCryptCloseAlgorithmProvider(algorithm, 0);
        wipe(salt);
        if (!BCRYPT_SUCCESS(ntstatus)) {
            wipe(key);
            throw std::runtime_error("BCryptDeriveKeyPBKDF2 failed (" +
                                     hex_status(static_cast<unsigned long>(ntstatus)) + ")");
        }
        return key;
    }

    [[nodiscard]] std::array<std::uint8_t, 32> make_proof(
        const std::array<std::uint8_t, 32>& password_key,
        const std::array<std::uint8_t, 32>& exporter,
        const std::array<std::uint8_t, 32>& client_nonce,
        const std::array<std::uint8_t, 32>& server_nonce,
        const AuthMessage role) const {
        HmacSha256 hmac{password_key.data(), password_key.size()};
        hmac.update(kProofLabel.data(), kProofLabel.size());
        const auto role_byte = static_cast<std::uint8_t>(role);
        hmac.update(&role_byte, sizeof(role_byte));
        hmac.update(exporter.data(), exporter.size());
        hmac.update(client_nonce.data(), client_nonce.size());
        hmac.update(server_nonce.data(), server_nonce.size());
        const std::array<std::uint8_t, 2> suite_bytes{
            static_cast<std::uint8_t>(kTlsAes256GcmSha384 >> 8U),
            static_cast<std::uint8_t>(kTlsAes256GcmSha384 & 0xFFU)};
        hmac.update(suite_bytes.data(), suite_bytes.size());
        return hmac.finish();
    }

    void derive_continuity_binding(
        const std::array<std::uint8_t, 32>& exporter,
        const std::array<std::uint8_t, 32>& client_nonce,
        const std::array<std::uint8_t, 32>& server_nonce) {
        HmacSha256 hmac{exporter.data(), exporter.size()};
        hmac.update(kContinuityLabel.data(), kContinuityLabel.size());
        hmac.update(client_nonce.data(), client_nonce.size());
        hmac.update(server_nonce.data(), server_nonce.size());
        const std::array<std::uint8_t, 2> suite_bytes{
            static_cast<std::uint8_t>(kTlsAes256GcmSha384 >> 8U),
            static_cast<std::uint8_t>(kTlsAes256GcmSha384 & 0xFFU)};
        hmac.update(suite_bytes.data(), suite_bytes.size());
        auto binding = hmac.finish();
        {
            std::lock_guard continuity_lock{continuity_mutex_};
            continuity_binding_ = binding;
        }
        wipe(binding);
    }

    void send_auth_message(const AuthMessage message,
                           const std::span<const std::uint8_t> payload) {
        if (payload.size() > (std::numeric_limits<std::uint16_t>::max)()) {
            throw std::length_error("Authentication message is too large");
        }

        std::vector<std::uint8_t> frame(7U + payload.size());
        std::copy(kAuthMagic.begin(), kAuthMagic.end(), frame.begin());
        frame[4] = static_cast<std::uint8_t>(message);
        encode_u16(static_cast<std::uint16_t>(payload.size()), frame.data() + 5U);
        std::copy(payload.begin(), payload.end(), frame.begin() + 7);
        try {
            send_plaintext(frame);
        } catch (...) {
            wipe(frame);
            throw;
        }
        wipe(frame);
    }

    [[nodiscard]] std::vector<std::uint8_t> receive_auth_message(
        const AuthMessage expected,
        const std::size_t expected_size) {
        std::array<std::uint8_t, 7> header{};
        if (!read_plaintext_exact(header)) {
            throw std::runtime_error("Peer closed during password authentication");
        }
        if (!std::equal(kAuthMagic.begin(), kAuthMagic.end(), header.begin()) ||
            header[4] != static_cast<std::uint8_t>(expected) ||
            decode_u16(header.data() + 5U) != expected_size) {
            throw std::runtime_error("Invalid TrueTunnel authentication message");
        }

        std::vector<std::uint8_t> payload(expected_size);
        if (!read_plaintext_exact(payload)) {
            wipe(payload);
            throw std::runtime_error("Peer closed during password authentication");
        }
        return payload;
    }

    void authenticate_password() {
        std::array<std::uint8_t, 32> exporter{};
        {
            std::lock_guard context_lock{context_mutex_};
            exporter = export_keying_material();
        }

        std::array<std::uint8_t, 32> client_nonce{};
        std::array<std::uint8_t, 32> server_nonce{};
        std::array<std::uint8_t, 32> password_key{};
        std::array<std::uint8_t, 32> local_proof{};
        std::array<std::uint8_t, 32> expected_proof{};

        try {
            if (is_server_) {
                auto received_nonce =
                    receive_auth_message(AuthMessage::ClientNonce, client_nonce.size());
                std::copy(received_nonce.begin(), received_nonce.end(), client_nonce.begin());
                wipe(received_nonce);

                random_bytes(server_nonce.data(), server_nonce.size());
                send_auth_message(AuthMessage::ServerNonce, server_nonce);

                password_key = derive_password_key(exporter, client_nonce, server_nonce);
                expected_proof = make_proof(password_key,
                                            exporter,
                                            client_nonce,
                                            server_nonce,
                                            AuthMessage::ClientProof);
                auto peer_proof =
                    receive_auth_message(AuthMessage::ClientProof, expected_proof.size());
                const bool proof_mismatch =
                    ct_memcmp(peer_proof.data(),
                              expected_proof.data(),
                              expected_proof.size()) != 0;
                wipe(peer_proof);
                if (proof_mismatch) {
                    throw std::runtime_error("TrueTunnel password authentication failed");
                }

                derive_continuity_binding(exporter, client_nonce, server_nonce);

                local_proof = make_proof(password_key,
                                         exporter,
                                         client_nonce,
                                         server_nonce,
                                         AuthMessage::ServerProof);
                send_auth_message(AuthMessage::ServerProof, local_proof);
            } else {
                random_bytes(client_nonce.data(), client_nonce.size());
                send_auth_message(AuthMessage::ClientNonce, client_nonce);

                auto received_nonce =
                    receive_auth_message(AuthMessage::ServerNonce, server_nonce.size());
                std::copy(received_nonce.begin(), received_nonce.end(), server_nonce.begin());
                wipe(received_nonce);

                password_key = derive_password_key(exporter, client_nonce, server_nonce);
                local_proof = make_proof(password_key,
                                         exporter,
                                         client_nonce,
                                         server_nonce,
                                         AuthMessage::ClientProof);
                send_auth_message(AuthMessage::ClientProof, local_proof);

                expected_proof = make_proof(password_key,
                                            exporter,
                                            client_nonce,
                                            server_nonce,
                                            AuthMessage::ServerProof);
                auto peer_proof =
                    receive_auth_message(AuthMessage::ServerProof, expected_proof.size());
                const bool proof_mismatch =
                    ct_memcmp(peer_proof.data(),
                              expected_proof.data(),
                              expected_proof.size()) != 0;
                wipe(peer_proof);
                if (proof_mismatch) {
                    throw std::runtime_error("TrueTunnel password authentication failed");
                }

                derive_continuity_binding(exporter, client_nonce, server_nonce);
            }
        } catch (...) {
            wipe(exporter);
            wipe(client_nonce);
            wipe(server_nonce);
            wipe(password_key);
            wipe(local_proof);
            wipe(expected_proof);
            throw;
        }

        wipe(exporter);
        wipe(client_nonce);
        wipe(server_nonce);
        wipe(password_key);
        wipe(local_proof);
        wipe(expected_proof);
    }

    void send_plaintext(
        const std::span<const std::uint8_t> plaintext,
        const std::chrono::steady_clock::time_point deadline = {}) {
        std::unique_lock<std::timed_mutex> send_lock{send_mutex_,
                                                     std::defer_lock};
        if (deadline == std::chrono::steady_clock::time_point{}) {
            send_lock.lock();
        } else if (std::chrono::steady_clock::now() >= deadline ||
                   !send_lock.try_lock_until(deadline)) {
            throw std::runtime_error("Schannel TLS application write timed out");
        }
        const auto write_deadline =
            deadline != std::chrono::steady_clock::time_point{}
                ? deadline
                : (handshake_in_progress_
                       ? handshake_deadline_
                       : std::chrono::steady_clock::now() +
                             kApplicationWriteTimeout);
        std::size_t offset = 0;
#ifdef TRUETUNNEL_SECURE_TRANSPORT_TEST
        std::size_t completed_chunks = 0U;
#endif
        while (offset < plaintext.size()) {
            if (std::chrono::steady_clock::now() >= write_deadline) {
                throw std::runtime_error(
                    handshake_in_progress_
                        ? "Schannel TLS handshake timed out"
                        : "Schannel TLS application write timed out");
            }
            const std::size_t chunk_size = (std::min)(
                plaintext.size() - offset,
                static_cast<std::size_t>(stream_sizes_.cbMaximumMessage));

            std::vector<std::uint8_t> encrypted(
                static_cast<std::size_t>(stream_sizes_.cbHeader) +
                chunk_size +
                static_cast<std::size_t>(stream_sizes_.cbTrailer));
            std::memcpy(encrypted.data() + stream_sizes_.cbHeader,
                        plaintext.data() + offset,
                        chunk_size);

            SecBuffer buffers[4]{};
            buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
            buffers[0].cbBuffer = stream_sizes_.cbHeader;
            buffers[0].pvBuffer = encrypted.data();
            buffers[1].BufferType = SECBUFFER_DATA;
            buffers[1].cbBuffer = static_cast<unsigned long>(chunk_size);
            buffers[1].pvBuffer = encrypted.data() + stream_sizes_.cbHeader;
            buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
            buffers[2].cbBuffer = stream_sizes_.cbTrailer;
            buffers[2].pvBuffer = encrypted.data() + stream_sizes_.cbHeader + chunk_size;
            buffers[3].BufferType = SECBUFFER_EMPTY;

            SecBufferDesc message{};
            message.ulVersion = SECBUFFER_VERSION;
            message.cBuffers = 4;
            message.pBuffers = buffers;

            SECURITY_STATUS status = SEC_E_INTERNAL_ERROR;
            {
                std::lock_guard context_lock{context_mutex_};
                status = ::EncryptMessage(&context_, 0, &message, 0);
            }
            if (status != SEC_E_OK) {
                wipe(encrypted);
                throw_security_status("EncryptMessage", status);
            }

            try {
                write_all({static_cast<const std::uint8_t*>(buffers[0].pvBuffer),
                           buffers[0].cbBuffer},
                          false,
                          write_deadline);
                write_all({static_cast<const std::uint8_t*>(buffers[1].pvBuffer),
                           buffers[1].cbBuffer},
                          false,
                          write_deadline);
                write_all({static_cast<const std::uint8_t*>(buffers[2].pvBuffer),
                           buffers[2].cbBuffer},
                          false,
                          write_deadline);
            } catch (...) {
                wipe(encrypted);
                throw;
            }
            wipe(encrypted);
            offset += chunk_size;
#ifdef TRUETUNNEL_SECURE_TRANSPORT_TEST
            ++completed_chunks;
            auto pause_after = test_plaintext_chunk_pause_after_.load(
                std::memory_order_acquire);
            if (pause_after != 0U && completed_chunks >= pause_after &&
                test_plaintext_chunk_pause_after_.compare_exchange_strong(
                    pause_after, 0U, std::memory_order_acq_rel,
                    std::memory_order_acquire)) {
                const auto pause_ms =
                    test_plaintext_chunk_pause_milliseconds_.exchange(
                        0U, std::memory_order_acq_rel);
                std::this_thread::sleep_for(
                    std::chrono::milliseconds{pause_ms});
            }
#endif
        }
    }

    [[nodiscard]] bool read_plaintext_exact(
        const std::span<std::uint8_t> output,
        const std::chrono::steady_clock::time_point deadline = {},
        std::size_t* copied_out = nullptr) {
        std::size_t copied = 0;
        if (copied_out != nullptr) {
            *copied_out = 0U;
        }
        while (copied < output.size()) {
            if (deadline != std::chrono::steady_clock::time_point{} &&
                std::chrono::steady_clock::now() >= deadline) {
                throw std::runtime_error("Schannel TLS application read timed out");
            }
            if (plaintext_offset_ == plaintext_input_.size()) {
                wipe(plaintext_input_);
                plaintext_offset_ = 0;
                if (!decrypt_next_message(deadline)) {
                    return false;
                }
            }

            const std::size_t available = plaintext_input_.size() - plaintext_offset_;
            const std::size_t amount = (std::min)(available, output.size() - copied);
            std::memcpy(output.data() + copied,
                        plaintext_input_.data() + plaintext_offset_,
                        amount);
            plaintext_offset_ += amount;
            copied += amount;
            if (copied_out != nullptr) {
                *copied_out = copied;
            }
        }
        return true;
    }

    [[nodiscard]] bool decrypt_next_message(
        const std::chrono::steady_clock::time_point deadline = {}) {
        for (;;) {
            if (deadline != std::chrono::steady_clock::time_point{} &&
                std::chrono::steady_clock::now() >= deadline) {
                throw std::runtime_error("Schannel TLS application read timed out");
            }
            if (encrypted_input_.empty()) {
                if (!read_more_allow_eof(encrypted_input_, deadline)) {
                    return false;
                }
            }

            SecBuffer buffers[4]{};
            buffers[0].BufferType = SECBUFFER_DATA;
            buffers[0].cbBuffer = static_cast<unsigned long>(encrypted_input_.size());
            buffers[0].pvBuffer = encrypted_input_.data();
            buffers[1].BufferType = SECBUFFER_EMPTY;
            buffers[2].BufferType = SECBUFFER_EMPTY;
            buffers[3].BufferType = SECBUFFER_EMPTY;

            SecBufferDesc message{};
            message.ulVersion = SECBUFFER_VERSION;
            message.cBuffers = 4;
            message.pBuffers = buffers;

            std::unique_lock context_lock{context_mutex_};
            const SECURITY_STATUS status = ::DecryptMessage(&context_, &message, 0, nullptr);
            if (status == SEC_E_INCOMPLETE_MESSAGE) {
                context_lock.unlock();
                read_more(encrypted_input_, deadline);
                continue;
            }
            if (status == SEC_I_CONTEXT_EXPIRED) {
                wipe(encrypted_input_);
                return false;
            }
            if (status == SEC_I_RENEGOTIATE) {
                SecBuffer* token = nullptr;
                constexpr std::array<ULONG, 3> token_type_preference{
                    SECBUFFER_EXTRA, SECBUFFER_TOKEN, SECBUFFER_DATA};
                for (const ULONG preferred_type : token_type_preference) {
                    for (SecBuffer& buffer : buffers) {
                        if (buffer.BufferType == preferred_type &&
                            buffer.pvBuffer != nullptr && buffer.cbBuffer != 0U) {
                            token = &buffer;
                            break;
                        }
                    }
                    if (token != nullptr) {
                        break;
                    }
                }
                if (token == nullptr) {
                    throw std::runtime_error(
                        "Schannel returned a post-handshake status without a token");
                }

                const auto* token_begin =
                    static_cast<const std::uint8_t*>(token->pvBuffer);
                std::vector<std::uint8_t> post_handshake_input(
                    token_begin, token_begin + token->cbBuffer);
                wipe(encrypted_input_);
                context_lock.unlock();
                continue_post_handshake(std::move(post_handshake_input), deadline);
                continue;
            }
            if (status != SEC_E_OK) {
                wipe(encrypted_input_);
                throw_security_status("DecryptMessage", status);
            }

            std::size_t plaintext_size = 0;
            for (const SecBuffer& buffer : buffers) {
                if (buffer.BufferType == SECBUFFER_DATA) {
                    plaintext_size += buffer.cbBuffer;
                }
            }
            plaintext_input_.reserve(plaintext_input_.size() + plaintext_size);
            for (const SecBuffer& buffer : buffers) {
                if (buffer.BufferType == SECBUFFER_DATA && buffer.cbBuffer != 0U) {
                    const auto* data = static_cast<const std::uint8_t*>(buffer.pvBuffer);
                    plaintext_input_.insert(plaintext_input_.end(),
                                            data,
                                            data + buffer.cbBuffer);
                }
            }
            preserve_extra(message, encrypted_input_);
            context_lock.unlock();

            if (!plaintext_input_.empty()) {
                return true;
            }
        }
    }

    void continue_post_handshake(
        std::vector<std::uint8_t> input_bytes,
        const std::chrono::steady_clock::time_point deadline = {}) {
        // Keep outgoing post-handshake tokens ordered with application TLS
        // records and prevent EncryptMessage from using a half-updated context.
        std::unique_lock<std::timed_mutex> send_lock{send_mutex_,
                                                     std::defer_lock};
        if (deadline == std::chrono::steady_clock::time_point{}) {
            send_lock.lock();
        } else if (std::chrono::steady_clock::now() >= deadline ||
                   !send_lock.try_lock_until(deadline)) {
            throw std::runtime_error("Schannel TLS application read timed out");
        }
        std::lock_guard context_lock{context_mutex_};

        for (;;) {
            if (input_bytes.empty()) {
                read_more(input_bytes, deadline);
            }

            SecBuffer input_buffers[2]{};
            input_buffers[0].BufferType = SECBUFFER_TOKEN;
            input_buffers[0].cbBuffer =
                static_cast<unsigned long>(input_bytes.size());
            input_buffers[0].pvBuffer = input_bytes.data();
            input_buffers[1].BufferType = SECBUFFER_EMPTY;
            SecBufferDesc input{};
            input.ulVersion = SECBUFFER_VERSION;
            input.cBuffers = 2;
            input.pBuffers = input_buffers;

            SecBuffer output_buffer{};
            output_buffer.BufferType = SECBUFFER_TOKEN;
            SecBufferDesc output_desc{};
            output_desc.ulVersion = SECBUFFER_VERSION;
            output_desc.cBuffers = 1;
            output_desc.pBuffers = &output_buffer;
            ContextBufferGuard output_guard{output_buffer};

            SECURITY_STATUS status = context_step(&input, output_desc);
            status = complete_auth_token_if_needed(status, output_desc);
            send_context_output(output_buffer, deadline);

            if (status == SEC_E_INCOMPLETE_MESSAGE) {
                read_more(input_bytes, deadline);
                continue;
            }

            preserve_extra(input, input_bytes);
            if (status == SEC_E_OK) {
                encrypted_input_.swap(input_bytes);
                validate_negotiated_context();
                return;
            }
            if (status == SEC_I_INCOMPLETE_CREDENTIALS) {
                throw std::runtime_error(
                    "The peer requested unsupported TLS certificate authentication");
            }
            if (status != SEC_I_CONTINUE_NEEDED) {
                throw_security_status(is_server_ ? "AcceptSecurityContext(post-handshake)"
                                                 : "InitializeSecurityContextW(post-handshake)",
                                      status);
            }
        }
    }

    void write_all(const std::span<const std::uint8_t> bytes,
                   const bool allow_shutdown = false,
                   std::chrono::steady_clock::time_point deadline = {}) {
        if (!allow_shutdown && deadline == std::chrono::steady_clock::time_point{}) {
            deadline = handshake_in_progress_
                           ? handshake_deadline_
                           : std::chrono::steady_clock::now() +
                                 kApplicationWriteTimeout;
        }
        std::size_t offset = 0;
        while (offset < bytes.size()) {
            if (!allow_shutdown &&
                shutdown_started_.load(std::memory_order_acquire)) {
                throw std::runtime_error("TLS connection is shutting down");
            }
            if (!allow_shutdown &&
                std::chrono::steady_clock::now() >= deadline) {
                throw std::runtime_error(
                    handshake_in_progress_ ? "Schannel TLS handshake timed out"
                                           : "Schannel TLS application write timed out");
            }
            const std::size_t remaining = bytes.size() - offset;
            int request = static_cast<int>((std::min)(
                remaining,
                static_cast<std::size_t>((std::numeric_limits<int>::max)())));
#ifdef TRUETUNNEL_SECURE_TRANSPORT_TEST
            const auto injected_bytes_remaining =
                test_partial_write_bytes_remaining_.load(
                    std::memory_order_acquire);
            const bool inject_partial_failure =
                injected_bytes_remaining !=
                (std::numeric_limits<std::size_t>::max)();
            if (inject_partial_failure) {
                if (injected_bytes_remaining == 0U) {
                    throw std::runtime_error(
                        "Injected Schannel partial ciphertext write failure");
                }
                request = static_cast<int>((std::min)(
                    static_cast<std::size_t>(request),
                    injected_bytes_remaining));
            }
#endif
            const int sent = ::send(socket_,
                                    reinterpret_cast<const char*>(bytes.data() + offset),
                                    request,
                                    0);
            if (sent == SOCKET_ERROR) {
                const int error = ::WSAGetLastError();
                if (error == WSAEINTR) {
                    continue;
                }
                if (error == WSAEWOULDBLOCK) {
                    if (allow_shutdown) {
                        throw std::runtime_error(
                            "TLS close notification would block");
                    }
                    (void)wait_for_socket(/*writable=*/true, deadline);
                    continue;
                }
                throw_winsock_error("send");
            }
            if (sent == 0) {
                throw std::runtime_error("send returned zero bytes");
            }
#ifdef TRUETUNNEL_SECURE_TRANSPORT_TEST
            if (inject_partial_failure) {
                const auto sent_size = static_cast<std::size_t>(sent);
                if (sent_size >= injected_bytes_remaining) {
                    test_partial_write_bytes_remaining_.store(
                        0U, std::memory_order_release);
                    throw std::runtime_error(
                        "Injected Schannel partial ciphertext write failure");
                }
                test_partial_write_bytes_remaining_.store(
                    injected_bytes_remaining - sent_size,
                    std::memory_order_release);
            }
#endif
            offset += static_cast<std::size_t>(sent);
        }
    }

    [[nodiscard]] bool write_all_noexcept(
        const std::span<const std::uint8_t> bytes,
        const bool allow_shutdown = false) noexcept {
        try {
            write_all(bytes, allow_shutdown);
            return true;
        } catch (...) {
            return false;
        }
    }

    void read_more(
        std::vector<std::uint8_t>& destination,
        const std::chrono::steady_clock::time_point deadline = {}) {
        if (!read_more_allow_eof(destination, deadline)) {
            throw std::runtime_error("Peer closed the TLS connection");
        }
    }

    [[nodiscard]] bool read_more_allow_eof(
        std::vector<std::uint8_t>& destination,
        const std::chrono::steady_clock::time_point deadline = {}) {
        if (destination.size() >= kMaximumBufferedTlsBytes) {
            throw std::runtime_error("TLS input exceeded the buffering limit");
        }

        for (;;) {
            if (shutdown_started_.load(std::memory_order_acquire)) {
                throw std::runtime_error("TLS connection is shutting down");
            }
            if (handshake_in_progress_ &&
                std::chrono::steady_clock::now() >= handshake_deadline_) {
                throw std::runtime_error("Schannel TLS handshake timed out");
            }
            if (deadline != std::chrono::steady_clock::time_point{} &&
                std::chrono::steady_clock::now() >= deadline) {
                throw std::runtime_error("Schannel TLS application read timed out");
            }
            const int received = ::recv(socket_,
                                        reinterpret_cast<char*>(socket_read_buffer_.data()),
                                        static_cast<int>(socket_read_buffer_.size()),
                                        0);
            if (received == SOCKET_ERROR) {
                const int error = ::WSAGetLastError();
                if (error == WSAEINTR) {
                    continue;
                }
                if (error == WSAEWOULDBLOCK || error == WSAETIMEDOUT) {
                    (void)wait_for_socket(/*writable=*/false, deadline);
                    continue;
                }
                throw_winsock_error("recv");
            }
            if (received == 0) {
                return false;
            }
            if (destination.size() + static_cast<std::size_t>(received) >
                kMaximumBufferedTlsBytes) {
                throw std::runtime_error("TLS input exceeded the buffering limit");
            }
            destination.insert(destination.end(),
                               socket_read_buffer_.begin(),
                               socket_read_buffer_.begin() + received);
            return true;
        }
    }

    [[nodiscard]] bool wait_for_socket(
        const bool writable,
        const std::chrono::steady_clock::time_point deadline = {}) const {
        fd_set read_set;
        fd_set write_set;
        FD_ZERO(&read_set);
        FD_ZERO(&write_set);
        if (writable) {
            FD_SET(socket_, &write_set);
        } else {
            FD_SET(socket_, &read_set);
        }
        long long poll_microseconds = kSocketPollMicroseconds;
        if (deadline != std::chrono::steady_clock::time_point{}) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) return false;
            const auto remaining = std::chrono::duration_cast<
                std::chrono::microseconds>(deadline - now).count();
            poll_microseconds = (std::min)(
                poll_microseconds, (std::max)(1LL, remaining));
        }
        timeval timeout{};
        timeout.tv_sec = static_cast<long>(poll_microseconds / 1'000'000LL);
        timeout.tv_usec = static_cast<long>(poll_microseconds % 1'000'000LL);
        const int ready = ::select(0,
                                   writable ? nullptr : &read_set,
                                   writable ? &write_set : nullptr,
                                   nullptr,
                                   &timeout);
        if (ready == SOCKET_ERROR) {
            const int error = ::WSAGetLastError();
            if (error == WSAEINTR) return false;
            throw_winsock_error("select(Schannel socket)");
        }
        return ready > 0;
    }

    [[nodiscard]] TrafficKeyRotationStats rotation_stats() const noexcept {
        TrafficKeyRotationStats stats{};
        stats.sent_records = sent_records_.load(std::memory_order_relaxed);
        stats.sent_bytes = sent_bytes_.load(std::memory_order_relaxed);
        stats.received_records =
            received_records_.load(std::memory_order_relaxed);
        stats.received_bytes = received_bytes_.load(std::memory_order_relaxed);
        const auto established = established_ticks_.load(std::memory_order_acquire);
        if (established > 0) {
            const auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            stats.age_microseconds = static_cast<std::uint64_t>(
                (now > established ? now - established : 0) / 1'000LL);
        }
        stats.application_initiation_supported = false;
        return stats;
    }

    [[nodiscard]] std::array<std::uint8_t, 32> continuity_binding() const {
        if (!handshake_complete_.load(std::memory_order_acquire)) {
            throw std::runtime_error(
                "TLS continuity binding is unavailable before authentication");
        }
        std::lock_guard continuity_lock{continuity_mutex_};
        return continuity_binding_;
    }

    [[nodiscard]] std::array<std::uint8_t, 32> replacement_proof(
        const std::span<const std::uint8_t> request_nonce,
        const std::span<const std::uint8_t> assigned_ipv4,
        const std::span<const std::uint8_t> new_binding) const {
        require_ready();
        std::lock_guard continuity_lock{continuity_mutex_};
        return replacement_proof_impl(continuity_binding_, new_binding,
                                      request_nonce, assigned_ipv4);
    }

    [[nodiscard]] static std::array<std::uint8_t, 32> replacement_proof(
        const std::array<std::uint8_t, 32>& old_binding,
        const std::array<std::uint8_t, 32>& new_binding,
        const std::span<const std::uint8_t> request_nonce,
        const std::span<const std::uint8_t> assigned_ipv4) {
        return replacement_proof_impl(old_binding, new_binding, request_nonce,
                                      assigned_ipv4);
    }

    [[nodiscard]] static std::array<std::uint8_t, 32>
    replacement_proof_impl(
        const std::span<const std::uint8_t> old_binding,
        const std::span<const std::uint8_t> new_binding,
        const std::span<const std::uint8_t> request_nonce,
        const std::span<const std::uint8_t> assigned_ipv4) {
        if (old_binding.size() != 32U || new_binding.size() != 32U ||
            request_nonce.size() != 16U || assigned_ipv4.size() != 4U) {
            throw std::invalid_argument(
                "TLS replacement proof inputs have invalid sizes");
        }
        HmacSha256 hmac{old_binding.data(), old_binding.size()};
        hmac.update(kReplacementProofLabel.data(),
                    kReplacementProofLabel.size());
        hmac.update(request_nonce.data(), request_nonce.size());
        hmac.update(assigned_ipv4.data(), assigned_ipv4.size());
        hmac.update(new_binding.data(), new_binding.size());
        return hmac.finish();
    }

    SOCKET socket_{INVALID_SOCKET};
    bool is_server_{false};
    CipherSuite suite_{CipherSuite::Aes256Gcm};
    TrafficKeyRotationPolicy rotation_policy_{};
    std::vector<std::uint8_t> password_;

    NCRYPT_PROV_HANDLE key_provider_{0};
    NCRYPT_KEY_HANDLE certificate_key_{0};
    std::wstring key_name_;
    PCCERT_CONTEXT certificate_{nullptr};
    CredHandle credential_{};
    CtxtHandle context_{};
    bool credential_valid_{false};
    bool context_valid_{false};
    bool tls_negotiated_{false};
    bool handshake_attempted_{false};
    bool handshake_in_progress_{false};
    std::chrono::steady_clock::time_point handshake_deadline_{};
    DWORD context_attributes_{0};
    SecPkgContext_StreamSizes stream_sizes_{};

    std::vector<std::uint8_t> encrypted_input_;
    std::vector<std::uint8_t> plaintext_input_;
    std::array<std::uint8_t, kSocketReadSize> socket_read_buffer_{};
    std::size_t plaintext_offset_{0};

    std::mutex handshake_mutex_;
    std::timed_mutex send_mutex_;
    // Serializes the prospective check with the corresponding application
    // write. send_mutex_ also protects TLS context/output ordering, but is
    // intentionally not used as the accounting lock by internal handshake
    // traffic.
    mutable std::timed_mutex send_accounting_mutex_;
    std::timed_mutex receive_mutex_;
    std::mutex context_mutex_;
    mutable std::mutex continuity_mutex_;
    std::atomic<bool> handshake_complete_{false};
    std::atomic<bool> shutdown_started_{false};
    std::atomic<std::uint64_t> sent_records_{0};
    std::atomic<std::uint64_t> sent_bytes_{0};
    std::atomic<std::uint64_t> received_records_{0};
    std::atomic<std::uint64_t> received_bytes_{0};
    std::atomic<std::int64_t> established_ticks_{0};
    std::atomic<bool> receive_poisoned_{false};
    std::atomic<bool> application_write_poisoned_{false};
    std::array<std::uint8_t, 32> continuity_binding_{};
#ifdef TRUETUNNEL_SECURE_TRANSPORT_TEST
    std::atomic<std::size_t> test_partial_write_bytes_remaining_{
        (std::numeric_limits<std::size_t>::max)()};
    std::atomic<std::size_t> test_plaintext_chunk_pause_after_{0U};
    std::atomic<std::int64_t> test_plaintext_chunk_pause_milliseconds_{0};
#endif
};

SchannelSocket::SchannelSocket(const SOCKET socket,
                               const std::span<const std::uint8_t> password,
                               const bool is_server,
                               const CipherSuite suite,
                               const TrafficKeyRotationPolicy rotation_policy)
    : impl_{std::make_unique<Impl>(
          socket, password, is_server, suite, rotation_policy)} {}

SchannelSocket::~SchannelSocket() = default;

void SchannelSocket::handshake() {
    impl_->handshake();
}

int SchannelSocket::send_record(const std::uint8_t type,
                                const std::uint8_t* data,
                                const std::uint16_t length) {
    return impl_->send_record(type, data, length);
}

int SchannelSocket::send_record_until(
    const std::uint8_t type,
    const std::uint8_t* data,
    const std::uint16_t length,
    const std::chrono::steady_clock::time_point deadline) {
    return impl_->send_record_until(type, data, length, deadline);
}

int SchannelSocket::recv_record(std::uint8_t& type,
                                std::uint8_t* output,
                                const std::size_t capacity) {
    return impl_->recv_record(type, output, capacity);
}

int SchannelSocket::recv_record_until(
    std::uint8_t& type,
    std::uint8_t* output,
    const std::size_t capacity,
    const std::chrono::steady_clock::time_point deadline) {
    return impl_->recv_record_until(type, output, capacity, deadline);
}

void SchannelSocket::shutdown() noexcept {
    impl_->shutdown();
}

TrafficKeyRotationStats SchannelSocket::rotation_stats() const noexcept {
    return impl_->rotation_stats();
}

std::array<std::uint8_t, 32> SchannelSocket::continuity_binding() const {
    return impl_->continuity_binding();
}

std::array<std::uint8_t, 32> SchannelSocket::replacement_proof(
    const std::span<const std::uint8_t> request_nonce,
    const std::span<const std::uint8_t> assigned_ipv4,
    const std::span<const std::uint8_t> new_binding) const {
    return impl_->replacement_proof(request_nonce, assigned_ipv4, new_binding);
}

std::array<std::uint8_t, 32> SchannelSocket::replacement_proof(
    const std::array<std::uint8_t, 32>& old_binding,
    const std::array<std::uint8_t, 32>& new_binding,
    const std::span<const std::uint8_t> request_nonce,
    const std::span<const std::uint8_t> assigned_ipv4) {
    return Impl::replacement_proof(old_binding, new_binding, request_nonce,
                                   assigned_ipv4);
}

#ifdef TRUETUNNEL_SECURE_TRANSPORT_TEST
void SchannelSocket::set_test_partial_write_failure_after(
    const std::size_t ciphertext_bytes) {
    impl_->set_test_partial_write_failure_after(ciphertext_bytes);
}

void SchannelSocket::set_test_plaintext_chunk_pause_after(
    const std::size_t completed_chunks,
    const std::chrono::milliseconds pause) {
    impl_->set_test_plaintext_chunk_pause_after(completed_chunks, pause);
}
#endif

} // namespace secure
