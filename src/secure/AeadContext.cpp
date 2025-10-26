#include "AeadContext.h"
#include <cstring>
#include <cwchar>

namespace secure {

AeadContext::AeadContext() {
    CHECK_NT("Open AES", BCryptOpenAlgorithmProvider(&aes_.h, BCRYPT_AES_ALGORITHM, nullptr, 0));
    CHECK_NT("Set GCM",
             BCryptSetProperty(aes_.h,
                               BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                               (ULONG)((std::wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) * sizeof(wchar_t)),
                               0));
    ULONG cb=0;
    CHECK_NT("Tag lens", BCryptGetProperty(aes_.h, BCRYPT_AUTH_TAG_LENGTH, (PUCHAR)&tagLens_,
                                           sizeof(tagLens_), &cb, 0));
}

void AeadContext::init(const std::array<uint8_t,32>& key,
                       const std::array<uint8_t,4>& iv_salt) {
    BCRYPT_KEY_HANDLE k{};
    CHECK_NT("Generate key", BCryptGenerateSymmetricKey(aes_.h, &k, nullptr, 0,
                                                        (PUCHAR)key.data(), (ULONG)key.size(), 0));
    key_ = Key{k};
    salt_ = iv_salt;
    ready_ = true;
}

static void make_nonce(uint8_t* nonce12, const std::array<uint8_t,4>& salt, uint64_t seq) {
    std::memcpy(nonce12, salt.data(), 4);
    uint64_t be = secure::to_be64(seq);
    std::memcpy(nonce12+4, &be, 8);
}

static void build_aad(uint8_t* aad, uint8_t type, uint64_t seq, uint16_t len) {
    aad[0] = type;
    uint64_t be_seq = secure::to_be64(seq);
    std::memcpy(aad+1, &be_seq, 8);
    uint16_t be_len = secure::to_be16(len);
    std::memcpy(aad+9, &be_len, 2);
}

void AeadContext::seal(uint8_t type, uint64_t seq, const uint8_t* pt, uint16_t pt_len,
                       std::vector<uint8_t>& ct, std::array<uint8_t,16>& tag) {
    if (!ready_) throw std::runtime_error("AEAD not initialized");
    ct.resize(pt_len);
    tag.fill(0);

    uint8_t nonce[12]; make_nonce(nonce, salt_, seq);
    uint8_t aad[11];   build_aad(aad, type, seq, pt_len);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce        = nonce;
    info.cbNonce        = sizeof(nonce);
    info.pbAuthData     = aad;
    info.cbAuthData     = sizeof(aad);
    info.pbTag          = tag.data();
    info.cbTag          = 16;

    ULONG out = 0;
    CHECK_NT("GCM seal", BCryptEncrypt(key_.h,
                                       (PUCHAR)pt, pt_len,
                                       &info,
                                       nullptr, 0,
                                       ct.data(), pt_len, &out, 0));
    if (out != pt_len) throw std::runtime_error("Encrypt length mismatch");
}

bool AeadContext::open(uint8_t type, uint64_t seq, const uint8_t* ct, uint16_t ct_len,
                       const std::array<uint8_t,16>& tag, std::vector<uint8_t>& outp) {
    if (!ready_) return false;
    outp.resize(ct_len);

    uint8_t nonce[12]; make_nonce(nonce, salt_, seq);
    uint8_t aad[11];   build_aad(aad, type, seq, ct_len);

    std::array<uint8_t,16> tag_copy = tag;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce        = nonce;
    info.cbNonce        = sizeof(nonce);
    info.pbAuthData     = aad;
    info.cbAuthData     = sizeof(aad);
    info.pbTag          = tag_copy.data();
    info.cbTag          = 16;

    ULONG out = 0;
    NTSTATUS s = BCryptDecrypt(key_.h,
                               (PUCHAR)ct, ct_len,
                               &info,
                               nullptr, 0,
                               outp.data(), ct_len, &out, 0);
    if (s < 0) return false;
    if (out != ct_len) return false;
    return true;
}

} // namespace secure
