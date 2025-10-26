#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <string>

namespace secure {

enum class CipherSuite : uint8_t {
    Aes256Gcm = 0,
    Aes128Gcm = 1,
    ChaCha20Poly1305 = 2,
};

constexpr std::string_view to_string_view(CipherSuite suite) noexcept {
    switch (suite) {
        case CipherSuite::Aes256Gcm:        return "AES-256-GCM";
        case CipherSuite::Aes128Gcm:        return "AES-128-GCM";
        case CipherSuite::ChaCha20Poly1305: return "ChaCha20-Poly1305";
        default:                            return "Unknown";
    }
}

inline std::string to_string(CipherSuite suite) {
    return std::string(to_string_view(suite));
}

inline std::size_t key_length_bytes(CipherSuite suite) noexcept {
    switch (suite) {
        case CipherSuite::Aes128Gcm:        return 16;
        case CipherSuite::Aes256Gcm:
        case CipherSuite::ChaCha20Poly1305: return 32;
        default:                            return 32;
    }
}

inline bool try_parse_cipher_suite(std::string_view name, CipherSuite& out) {
    if (name == "AES-256-GCM" || name == "aes-256-gcm") {
        out = CipherSuite::Aes256Gcm;
        return true;
    }
    if (name == "AES-128-GCM" || name == "aes-128-gcm") {
        out = CipherSuite::Aes128Gcm;
        return true;
    }
    if (name == "ChaCha20-Poly1305" || name == "chacha20-poly1305" || name == "ChaChaPoly") {
        out = CipherSuite::ChaCha20Poly1305;
        return true;
    }
    return false;
}

} // namespace secure
