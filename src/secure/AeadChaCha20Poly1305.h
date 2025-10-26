#pragma once
#include <array>
#include <cstdint>
#include <vector>
#include <stdexcept>
#include <cstring>

namespace secure {

// AEAD matching your record format:
// AAD = [type:1][seq:8][len:2] (11 bytes). Tag = 16 bytes.
// Nonce = salt(4) || seq_be(8). Key = 32 bytes.
class AeadChaCha20Poly1305 {
public:
    AeadChaCha20Poly1305() = default;

    // key: 32 bytes; iv_salt: 4 bytes (upper 32 of 96-bit nonce).
    void init(const std::array<uint8_t,32>& key, const std::array<uint8_t,4>& iv_salt) {
        key_  = key;
        salt_ = iv_salt;
        ready_ = true;
    }

    void seal(uint8_t type, uint64_t seq, const uint8_t* pt, uint16_t pt_len,
              std::vector<uint8_t>& ct, std::array<uint8_t,16>& tag);

    bool open(uint8_t type, uint64_t seq, const uint8_t* ct, uint16_t ct_len,
              const std::array<uint8_t,16>& tag, std::vector<uint8_t>& out);

private:
    // ---------- ChaCha20 (RFC 8439) ----------
    static inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
    static inline void qr(uint32_t s[16], int a, int b, int c, int d) {
        s[a] += s[b]; s[d] = rotl32(s[d] ^ s[a], 16);
        s[c] += s[d]; s[b] = rotl32(s[b] ^ s[c], 12);
        s[a] += s[b]; s[d] = rotl32(s[d] ^ s[a],  8);
        s[c] += s[d]; s[b] = rotl32(s[b] ^ s[c],  7);
    }
    static void chacha_block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t out[64]) {
        // 16-byte constant without NUL terminator to satisfy MSVC
        static const uint8_t sigma[16] = {
            'e','x','p','a','n','d',' ','3','2','-','b','y','t','e',' ','k'
        };
        uint32_t s[16];
        auto rd32 = [](const uint8_t* p){ return uint32_t(p[0]) | (uint32_t(p[1])<<8) | (uint32_t(p[2])<<16) | (uint32_t(p[3])<<24); };
        s[0] = rd32(sigma+0);  s[1] = rd32(sigma+4);  s[2] = rd32(sigma+8);  s[3] = rd32(sigma+12);
        for (int i=0;i<8;++i) s[4+i] = rd32(key+4*i);
        s[12] = counter;
        s[13] = rd32(nonce+0);
        s[14] = rd32(nonce+4);
        s[15] = rd32(nonce+8);
        uint32_t w[16];
        for (int i=0;i<16;++i) w[i]=s[i];
        for (int i=0;i<10;++i) {
            qr(w,0,4,8,12); qr(w,1,5,9,13); qr(w,2,6,10,14); qr(w,3,7,11,15);
            qr(w,0,5,10,15);qr(w,1,6,11,12);qr(w,2,7,8,13);  qr(w,3,4,9,14);
        }
        auto wr32 = [](uint8_t* p, uint32_t v){ p[0]=uint8_t(v&0xff); p[1]=uint8_t((v>>8)&0xff); p[2]=uint8_t((v>>16)&0xff); p[3]=uint8_t((v>>24)&0xff); };
        for (int i=0;i<16;++i) wr32(out+4*i, w[i]+s[i]);
    }
    static void chacha_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter,
                           const uint8_t* in, uint8_t* out, size_t len) {
        uint8_t block[64];
        uint32_t ctr = counter;
        size_t off = 0;
        while (off < len) {
            chacha_block(key, nonce, ctr++, block);
            size_t chunk = (len - off > 64) ? 64 : (len - off);
            for (size_t i=0;i<chunk;++i) out[off+i] = in[off+i] ^ block[i];
            off += chunk;
        }
        std::memset(block, 0, sizeof(block));
    }

    // ---------- Poly1305 (RFC 8439) ----------
    struct Poly1305 {
        uint32_t r[5]{}, pad[4]{}, h[5]{};
        bool init_ok{false};
        static uint32_t ld32(const uint8_t* p){ return uint32_t(p[0]) | (uint32_t(p[1])<<8) | (uint32_t(p[2])<<16) | (uint32_t(p[3])<<24); }
        void init(const uint8_t k[32]);
        static void blk_to_limbs(const uint8_t* m, size_t n, uint32_t out[5]);
        void update(const uint8_t* m, size_t bytes);
        void finish(const uint8_t* aad, size_t aad_len, const uint8_t* ct, size_t ct_len, uint8_t tag[16]);
        void process_with_lengths(const uint8_t* data, size_t len);
    };

    static void make_nonce(uint8_t out12[12], const std::array<uint8_t,4>& salt, uint64_t seq) {
        std::memcpy(out12, salt.data(), 4);
        out12[4] = uint8_t(seq >> 56); out12[5]=uint8_t(seq>>48);
        out12[6] = uint8_t(seq >> 40); out12[7]=uint8_t(seq>>32);
        out12[8] = uint8_t(seq >> 24); out12[9]=uint8_t(seq>>16);
        out12[10]= uint8_t(seq >> 8);  out12[11]=uint8_t(seq);
    }
    static void build_aad(uint8_t aad[11], uint8_t type, uint64_t seq, uint16_t len) {
        aad[0]=type;
        aad[1]=uint8_t(seq>>56); aad[2]=uint8_t(seq>>48); aad[3]=uint8_t(seq>>40); aad[4]=uint8_t(seq>>32);
        aad[5]=uint8_t(seq>>24); aad[6]=uint8_t(seq>>16); aad[7]=uint8_t(seq>>8);  aad[8]=uint8_t(seq);
        aad[9]=uint8_t(len>>8);  aad[10]=uint8_t(len);
    }

private:
    std::array<uint8_t,32> key_{};
    std::array<uint8_t,4>  salt_{};
    bool ready_{false};
};

} // namespace secure
