#include "AeadContext.h"

#include <cstring>
#include <cwchar>
#include <cstddef>
#include <stdexcept>

namespace secure {
namespace {

constexpr std::size_t kSaltLen = 4;
constexpr std::size_t kSeqLen = 8;
constexpr std::size_t kNonceLen = kSaltLen + kSeqLen;
constexpr std::size_t kAadLen = 11;

LPCWSTR alg_name_for(CipherSuite suite) {
    switch (suite) {
        case CipherSuite::Aes256Gcm:
        case CipherSuite::Aes128Gcm:
            return BCRYPT_AES_ALGORITHM;
        case CipherSuite::ChaCha20Poly1305:
            // Prefer CNG if present; else null signals software fallback.
#ifdef BCRYPT_CHACHA20_POLY1305_ALGORITHM
            return BCRYPT_CHACHA20_POLY1305_ALGORITHM;
#else
            return nullptr;
#endif
        default:
            throw std::runtime_error("Unsupported cipher suite");
    }
}

void make_nonce(uint8_t* nonce, const std::array<uint8_t, kSaltLen>& salt, uint64_t seq) {
    std::memcpy(nonce, salt.data(), kSaltLen);
    const uint64_t be = secure::to_be64(seq);
    std::memcpy(nonce + kSaltLen, &be, kSeqLen);
}

void build_aad(uint8_t* aad, uint8_t type, uint64_t seq, uint16_t len) {
    aad[0] = type;
    const uint64_t be_seq = secure::to_be64(seq);
    std::memcpy(aad + 1, &be_seq, sizeof(be_seq));
    const uint16_t be_len = secure::to_be16(len);
    std::memcpy(aad + 9, &be_len, sizeof(be_len));
}

} // namespace

    // Read once: TT_CHACHA_IMPL = auto|cng|soft  (default auto)
AeadContext::ChaChaImplOverride AeadContext::ch_override() {
    static ChaChaImplOverride v = []{
        char buf[16] = {0};
        DWORD n = GetEnvironmentVariableA("TT_CHACHA_IMPL", buf, sizeof(buf));
        if (n == 0 || n >= sizeof(buf)) return ChaChaImplOverride::Auto;
        for (DWORD i = 0; i < n; ++i)
            buf[i] = static_cast<char>(tolower(static_cast<unsigned char>(buf[i])));
        if (strcmp(buf, "cng") == 0)  return ChaChaImplOverride::Cng;
        if (strcmp(buf, "soft") == 0) return ChaChaImplOverride::Soft;
        return ChaChaImplOverride::Auto;
    }();
    return v;
}



void AeadContext::configure(CipherSuite suite) {
    if (suite_ == suite && alg_.h != nullptr) {
        return;
    }

    ready_ = false;
    key_ = Key{};
    use_cng_ = true;

    BCRYPT_ALG_HANDLE handle{};
    const LPCWSTR alg_name = alg_name_for(suite);

    // Override handling for ChaCha20-Poly1305
    const auto ov = (suite == CipherSuite::ChaCha20Poly1305) ? ch_override()
                                                             : ChaChaImplOverride::Auto;

    // Force software?
    if (suite == CipherSuite::ChaCha20Poly1305 && ov == ChaChaImplOverride::Soft) {
        use_cng_ = false;
        suite_ = suite;
        tag_len_ = 16;
        return;
    }

    // If ChaCha and no provider symbol, software unless forced CNG
    if (suite == CipherSuite::ChaCha20Poly1305 && !alg_name) {
        if (ov == ChaChaImplOverride::Cng)
            throw std::runtime_error("ChaCha20-Poly1305 CNG requested but not available on this SDK");
         use_cng_ = false;
        suite_ = suite;
       tag_len_ = 16;
        return;
    }
    NTSTATUS st = (alg_name)
                  ? BCryptOpenAlgorithmProvider(&handle, alg_name, nullptr, 0)
                  : ((NTSTATUS)-1);
    if (suite == CipherSuite::ChaCha20Poly1305 && st < 0) {
        if (ov == ChaChaImplOverride::Cng)
            CHECK_NT("Open AEAD provider (ChaCha20-Poly1305 CNG forced)", st); // hard-fail
        // Auto → fallback to software
        use_cng_ = false;
        suite_ = suite;
        tag_len_ = 16;
        return;
    }
    CHECK_NT("Open AEAD provider", st);

    Alg new_alg{handle};
    if (suite == CipherSuite::Aes256Gcm || suite == CipherSuite::Aes128Gcm) {
        CHECK_NT("Set GCM mode",
                 BCryptSetProperty(new_alg.h,
                                   BCRYPT_CHAINING_MODE,
                                   reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                                   static_cast<ULONG>((std::wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) * sizeof(wchar_t)),
                                   0));
    }

    ULONG cb = 0;
    CHECK_NT("Get tag lengths",
             BCryptGetProperty(new_alg.h,
                               BCRYPT_AUTH_TAG_LENGTH,
                               reinterpret_cast<PUCHAR>(&tagLens_),
                               sizeof(tagLens_),
                               &cb,
                               0));

    alg_ = std::move(new_alg);
    suite_ = suite;
    tag_len_ = tagLens_.dwMinLength != 0 ? tagLens_.dwMinLength : 16;
}

void AeadContext::init(CipherSuite suite,
                       const std::array<uint8_t, 32>& key_material,
                       const std::array<uint8_t, kSaltLen>& iv_salt) {
    configure(suite);

        // Software ChaCha20-Poly1305
    if (suite_ == CipherSuite::ChaCha20Poly1305 && !use_cng_) {
        if (key_length_bytes(suite_) != 32) throw std::runtime_error("ChaCha20 requires 256-bit key");
        chacha_fallback_.init(key_material, iv_salt);
        salt_ = iv_salt;
        tag_len_ = 16;
        ready_ = true;
        return;
    }


    const ULONG key_len = static_cast<ULONG>(key_length_bytes(suite));
    if (key_len > key_material.size()) {
        throw std::runtime_error("Insufficient key material for cipher suite");
    }

    BCRYPT_KEY_HANDLE handle{};
    CHECK_NT("Generate symmetric key",
             BCryptGenerateSymmetricKey(alg_.h,
                                        &handle,
                                        nullptr,
                                        0,
                                        const_cast<PUCHAR>(key_material.data()),
                                        key_len,
                                        0));

    key_ = Key{handle};
    salt_ = iv_salt;
    ready_ = true;
}

void AeadContext::seal(uint8_t type,
                       uint64_t seq,
                       const uint8_t* pt,
                       uint16_t pt_len,
                       std::vector<uint8_t>& ct,
                       std::array<uint8_t, 16>& tag) {
    if (!ready_) {
        throw std::runtime_error("AEAD not initialized");
    }
    if (suite_ == CipherSuite::ChaCha20Poly1305 && !use_cng_) {
        chacha_fallback_.seal(type, seq, pt, pt_len, ct, tag);
        return;
    }
    ct.resize(pt_len);
    tag.fill(0);

    std::array<uint8_t, kNonceLen> nonce{};
    make_nonce(nonce.data(), salt_, seq);

    std::array<uint8_t, kAadLen> aad{};
    build_aad(aad.data(), type, seq, pt_len);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce    = nonce.data();
    info.cbNonce    = static_cast<ULONG>(nonce.size());
    info.pbAuthData = aad.data();
    info.cbAuthData = static_cast<ULONG>(aad.size());
    info.pbTag      = tag.data();
    info.cbTag      = tag_len_;

    ULONG out = 0;
    CHECK_NT("AEAD seal",
             BCryptEncrypt(key_.h,
                           const_cast<PUCHAR>(pt),
                           pt_len,
                           &info,
                           nullptr,
                           0,
                           ct.data(),
                           pt_len,
                           &out,
                           0));
    if (out != pt_len) {
        throw std::runtime_error("Encrypt length mismatch");
    }
}

bool AeadContext::open(uint8_t type,
                       uint64_t seq,
                       const uint8_t* ct,
                       uint16_t ct_len,
                       const std::array<uint8_t, 16>& tag,
                       std::vector<uint8_t>& outp) {
    if (!ready_) {
        return false;
    }
    if (suite_ == CipherSuite::ChaCha20Poly1305 && !use_cng_) {
        return chacha_fallback_.open(type, seq, ct, ct_len, tag, outp);
    }
    outp.resize(ct_len);

    std::array<uint8_t, kNonceLen> nonce{};
    make_nonce(nonce.data(), salt_, seq);

    std::array<uint8_t, kAadLen> aad{};
    build_aad(aad.data(), type, seq, ct_len);

    std::array<uint8_t, 16> tag_copy = tag;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce    = nonce.data();
    info.cbNonce    = static_cast<ULONG>(nonce.size());
    info.pbAuthData = aad.data();
    info.cbAuthData = static_cast<ULONG>(aad.size());
    info.pbTag      = tag_copy.data();
    info.cbTag      = tag_len_;

    ULONG out = 0;
    const NTSTATUS status = BCryptDecrypt(key_.h,
                                          const_cast<PUCHAR>(ct),
                                          ct_len,
                                          &info,
                                          nullptr,
                                          0,
                                          outp.data(),
                                          ct_len,
                                          &out,
                                          0);
    if (status < 0) {
        return false;
    }
    return out == ct_len;
}

} // namespace secure
