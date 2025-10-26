#pragma once
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <vector>
#include <array>
#include <string>
#include <stdexcept>
#include <cstring>
#include <memory>
#include <algorithm>
#include <cstdio>


#pragma comment(lib, "bcrypt.lib")

namespace secure {

[[noreturn]] inline void throw_winerr(const char* where, NTSTATUS s) {
    char buf[128];
    std::snprintf(buf, sizeof(buf), "%s failed (NTSTATUS=0x%08X)", where, (unsigned)s);
    throw std::runtime_error(buf);
}

inline void CHECK_NT(const char* where, NTSTATUS s) {
    if (s < 0) throw_winerr(where, s);
}

inline uint16_t to_be16(uint16_t v) { return _byteswap_ushort(v); }
inline uint32_t to_be32(uint32_t v) { return _byteswap_ulong(v); }
inline uint64_t to_be64(uint64_t v) { return _byteswap_uint64(v); }
inline uint16_t from_be16(uint16_t v){ return _byteswap_ushort(v); }
inline uint32_t from_be32(uint32_t v){ return _byteswap_ulong(v);  }
inline uint64_t from_be64(uint64_t v){ return _byteswap_uint64(v); }

inline int ct_memcmp(const void* a, const void* b, size_t n) {
    const auto* x = static_cast<const unsigned char*>(a);
    const auto* y = static_cast<const unsigned char*>(b);
    unsigned char diff = 0;
    for (size_t i=0; i<n; ++i) diff |= (x[i] ^ y[i]);
    return diff;
}

// RAII wrappers
struct Alg {
    BCRYPT_ALG_HANDLE h{};
    Alg() = default;
    explicit Alg(BCRYPT_ALG_HANDLE x) : h(x) {}
    ~Alg(){ if(h) BCryptCloseAlgorithmProvider(h, 0); }
    Alg(const Alg&) = delete; Alg& operator=(const Alg&) = delete;
    Alg(Alg&& o) noexcept : h(o.h){ o.h=nullptr; }
    Alg& operator=(Alg&& o) noexcept { if(this!=&o){ if(h) BCryptCloseAlgorithmProvider(h,0); h=o.h; o.h=nullptr;} return *this; }
};

struct Key {
    BCRYPT_KEY_HANDLE h{};
    Key() = default;
    explicit Key(BCRYPT_KEY_HANDLE x) : h(x) {}
    ~Key(){ if(h) BCryptDestroyKey(h); }
    Key(const Key&) = delete; Key& operator=(const Key&) = delete;
    Key(Key&& o) noexcept : h(o.h){ o.h=nullptr; }
    Key& operator=(Key&& o) noexcept { if(this!=&o){ if(h) BCryptDestroyKey(h); h=o.h; o.h=nullptr;} return *this; }
};

struct Hash {
    BCRYPT_HASH_HANDLE h{};
    PBYTE obj{}; ULONG obj_len{};
    Hash() = default;
    ~Hash(){ if(h) BCryptDestroyHash(h); if(obj) HeapFree(GetProcessHeap(), 0, obj); }
    Hash(const Hash&) = delete; Hash& operator=(const Hash&) = delete;
    Hash(Hash&& o) noexcept : h(o.h), obj(o.obj), obj_len(o.obj_len){ o.h=nullptr; o.obj=nullptr; o.obj_len=0; }
    Hash& operator=(Hash&& o) noexcept {
        if(this!=&o){ if(h) BCryptDestroyHash(h); if(obj) HeapFree(GetProcessHeap(),0,obj);
            h=o.h; obj=o.obj; obj_len=o.obj_len; o.h=nullptr; o.obj=nullptr; o.obj_len=0; }
        return *this;
    }
};

struct Secret {
    BCRYPT_SECRET_HANDLE h{};
    Secret() = default;
    explicit Secret(BCRYPT_SECRET_HANDLE x) : h(x) {}
    ~Secret(){ if(h) BCryptDestroySecret(h); }
    Secret(const Secret&) = delete; Secret& operator=(const Secret&) = delete;
    Secret(Secret&& o) noexcept : h(o.h){ o.h=nullptr; }
    Secret& operator=(Secret&& o) noexcept { if(this!=&o){ if(h) BCryptDestroySecret(h); h=o.h; o.h=nullptr;} return *this; }
};

// RNG
inline void random_bytes(uint8_t* out, size_t n) {
    CHECK_NT("BCryptGenRandom", BCryptGenRandom(nullptr, out, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

// SHA-256
class Sha256 {
public:
    Sha256() {
        CHECK_NT("Open SHA256", BCryptOpenAlgorithmProvider(&alg_.h, BCRYPT_SHA256_ALGORITHM, nullptr, 0));
        ULONG obj_len=0, cb=0;
        CHECK_NT("Hash prop", BCryptGetProperty(alg_.h, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len, sizeof(obj_len), &cb, 0));
        st_.obj = (PBYTE)HeapAlloc(GetProcessHeap(), 0, obj_len);
        st_.obj_len = obj_len;
        CHECK_NT("CreateHash", BCryptCreateHash(alg_.h, &st_.h, st_.obj, st_.obj_len, nullptr, 0, 0));
    }
    void update(const void* p, size_t n) {
        if(n) CHECK_NT("HashData", BCryptHashData(st_.h, (PUCHAR)p, (ULONG)n, 0));
    }
    std::array<uint8_t, 32> finish() {
        std::array<uint8_t,32> out{};
        CHECK_NT("FinishHash", BCryptFinishHash(st_.h, out.data(), (ULONG)out.size(), 0));
        return out;
    }
private:
    Alg   alg_;
    Hash  st_;
};

// HMAC-SHA256
class HmacSha256 {
public:
    explicit HmacSha256(const uint8_t* key, size_t key_len) {
        CHECK_NT("Open HMAC", BCryptOpenAlgorithmProvider(&alg_.h, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG));
        ULONG obj_len=0, cb=0;
        CHECK_NT("HMAC obj len", BCryptGetProperty(alg_.h, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len, sizeof(obj_len), &cb, 0));
        st_.obj = (PBYTE)HeapAlloc(GetProcessHeap(), 0, obj_len);
        st_.obj_len = obj_len;
        CHECK_NT("Create HMAC", BCryptCreateHash(alg_.h, &st_.h, st_.obj, st_.obj_len, (PUCHAR)key, (ULONG)key_len, 0));
    }
    void update(const void* p, size_t n) {
        if(n) CHECK_NT("HMAC data", BCryptHashData(st_.h, (PUCHAR)p, (ULONG)n, 0));
    }
    std::array<uint8_t,32> finish() {
        std::array<uint8_t,32> out{};
        CHECK_NT("HMAC finish", BCryptFinishHash(st_.h, out.data(), (ULONG)out.size(), 0));
        return out;
    }
    static std::array<uint8_t,32> compute(const uint8_t* key, size_t keylen, const void* data, size_t len) {
        HmacSha256 h(key, keylen);
        h.update(data, len);
        return h.finish();
    }
private:
    Alg  alg_;
    Hash st_;
};

// HKDF-SHA256
struct HKDF {
    static std::array<uint8_t,32> extract(const uint8_t* salt, size_t slen, const uint8_t* ikm, size_t ikmlen) {
        // PRK = HMAC(salt, IKM)
        return HmacSha256::compute(salt, slen, ikm, ikmlen);
    }
    static void expand(const uint8_t* prk, size_t prk_len,
                       const uint8_t* info, size_t info_len,
                       uint8_t* out, size_t out_len) {
        // N = ceil(out_len/HashLen). HashLen=32.
        uint8_t T[32]; size_t T_len = 0;
        uint8_t ctr = 1;
        size_t wrote = 0;
        while (wrote < out_len) {
            HmacSha256 h(prk, prk_len);
            if (T_len) h.update(T, T_len);
            if (info_len) h.update(info, info_len);
            h.update(&ctr, 1);
            auto t = h.finish();
            size_t chunk = (std::min)((size_t)32, out_len - wrote);
            std::memcpy(out + wrote, t.data(), chunk);
            wrote += chunk;
            std::memcpy(T, t.data(), 32);
            T_len = 32;
            ctr++;
        }
        SecureZeroMemory(T, sizeof(T));
    }
};

} // namespace secure
