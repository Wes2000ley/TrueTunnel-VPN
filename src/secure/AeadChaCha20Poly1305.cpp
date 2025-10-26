#include "AeadChaCha20Poly1305.h"
#include <cstring>

namespace secure {

// ----- Poly1305 helpers -----
void AeadChaCha20Poly1305::Poly1305::init(const uint8_t k[32]) {
    uint32_t t0 = ld32(k+0),  t1 = ld32(k+4),  t2 = ld32(k+8),  t3 = ld32(k+12);
    uint64_t r0 = (t0      ) & 0x3ffffff;
    uint64_t r1 = ((t0>>26) | (uint64_t(t1)<<6)) & 0x3ffff03;
    uint64_t r2 = ((t1>>20) | (uint64_t(t2)<<12))& 0x3ffc0ff;
    uint64_t r3 = ((t2>>14) | (uint64_t(t3)<<18))& 0x3f03fff;
    uint64_t r4 = ((t3>>8) ) & 0x00fffff;
    r[0]=uint32_t(r0); r[1]=uint32_t(r1); r[2]=uint32_t(r2); r[3]=uint32_t(r3); r[4]=uint32_t(r4);
    pad[0]=ld32(k+16); pad[1]=ld32(k+20); pad[2]=ld32(k+24); pad[3]=ld32(k+28);
    h[0]=h[1]=h[2]=h[3]=h[4]=0;
    init_ok = true;
}

void AeadChaCha20Poly1305::Poly1305::blk_to_limbs(const uint8_t* m, size_t n, uint32_t out[5]) {
    if (n == 16) {
        // Full block: parse directly and set the implicit 1<<128 by OR'ing 1<<24 into limb 4.
        uint64_t t0 = ld32(m+0), t1 = ld32(m+4), t2 = ld32(m+8), t3 = ld32(m+12);
        out[0] = uint32_t( t0                    & 0x3ffffff);
        out[1] = uint32_t(((t0>>26)|(t1<<6))    & 0x3ffffff);
        out[2] = uint32_t(((t1>>20)|(t2<<12))   & 0x3ffffff);
        out[3] = uint32_t(((t2>>14)|(t3<<18))   & 0x3ffffff);
        out[4] = uint32_t( (t3>>8)              & 0x3ffffff);
        out[4] |= (1u << 24); // append the '1' bit for a full 16-byte block
        return;
    }
    // Partial block: copy to a 16-byte buffer and append a single 1 byte.
    uint8_t tmp[16]{};
    if (n) std::memcpy(tmp, m, n);
    tmp[n] = 1;
    uint64_t t0 = ld32(tmp+0), t1 = ld32(tmp+4), t2 = ld32(tmp+8), t3 = ld32(tmp+12);
    out[0] = uint32_t( t0                    & 0x3ffffff);
    out[1] = uint32_t(((t0>>26)|(t1<<6))    & 0x3ffffff);
    out[2] = uint32_t(((t1>>20)|(t2<<12))   & 0x3ffffff);
    out[3] = uint32_t(((t2>>14)|(t3<<18))   & 0x3ffffff);
    out[4] = uint32_t( (t3>>8)              & 0x3ffffff);
}

void AeadChaCha20Poly1305::Poly1305::update(const uint8_t* m, size_t bytes) {
    uint64_t r0=r[0], r1=r[1], r2=r[2], r3=r[3], r4=r[4];
    uint64_t r1_5=r1*5, r2_5=r2*5, r3_5=r3*5, r4_5=r4*5;

    while (bytes > 0) {
        size_t n = bytes >= 16 ? 16 : bytes;
        uint32_t t[5];
        blk_to_limbs(m, n, t);

        uint64_t h0 = h[0] + t[0];
        uint64_t h1 = h[1] + t[1];
        uint64_t h2 = h[2] + t[2];
        uint64_t h3 = h[3] + t[3];
        uint64_t h4 = h[4] + t[4];

        uint64_t d0 = h0*r0 + h1*r4_5 + h2*r3_5 + h3*r2_5 + h4*r1_5;
        uint64_t d1 = h0*r1 + h1*r0    + h2*r4_5 + h3*r3_5 + h4*r2_5;
        uint64_t d2 = h0*r2 + h1*r1    + h2*r0    + h3*r4_5 + h4*r3_5;
        uint64_t d3 = h0*r3 + h1*r2    + h2*r1    + h3*r0    + h4*r4_5;
        uint64_t d4 = h0*r4 + h1*r3    + h2*r2    + h3*r1    + h4*r0;

        uint64_t c;
        c = (d0 >> 26); h[0] = uint32_t(d0 & 0x3ffffff); d1 += c;
        c = (d1 >> 26); h[1] = uint32_t(d1 & 0x3ffffff); d2 += c;
        c = (d2 >> 26); h[2] = uint32_t(d2 & 0x3ffffff); d3 += c;
        c = (d3 >> 26); h[3] = uint32_t(d3 & 0x3ffffff); d4 += c;
        c = (d4 >> 26); h[4] = uint32_t(d4 & 0x3ffffff); h[0] += uint32_t(c * 5);
        c =  h[0] >> 26;    h[0] &= 0x3ffffff;           h[1] += uint32_t(c);

        m += n;
        bytes -= n;
    }
}

void AeadChaCha20Poly1305::Poly1305::finish(const uint8_t* aad, size_t aad_len, const uint8_t* ct, size_t ct_len, uint8_t tag[16]) {
    if (!init_ok) return;

    process_with_lengths(aad, aad_len);
    process_with_lengths(ct,  ct_len);

    uint8_t lenblk[16];
    auto wr64 = [](uint8_t* p, uint64_t v){ for(int i=0;i<8;++i) p[i]=uint8_t((v>>(8*i))&0xff); };
    wr64(lenblk+0,  aad_len);
    wr64(lenblk+8,  ct_len);
    update(lenblk, sizeof lenblk);
    std::memset(lenblk,0,sizeof lenblk);

    uint64_t c = uint64_t(h[1]) >> 26; h[1] &= 0x3ffffff; h[2] += uint32_t(c);
    c = uint64_t(h[2]) >> 26; h[2] &= 0x3ffffff; h[3] += uint32_t(c);
    c = uint64_t(h[3]) >> 26; h[3] &= 0x3ffffff; h[4] += uint32_t(c);
    c = uint64_t(h[4]) >> 26; h[4] &= 0x3ffffff; h[0] += uint32_t(c*5);
    c = uint64_t(h[0]) >> 26; h[0] &= 0x3ffffff; h[1] += uint32_t(c);

    uint64_t g0 = uint64_t(h[0]) + 5;
    uint64_t g1 = uint64_t(h[1]) + (g0>>26); g0 &= 0x3ffffff;
    uint64_t g2 = uint64_t(h[2]) + (g1>>26); g1 &= 0x3ffffff;
    uint64_t g3 = uint64_t(h[3]) + (g2>>26); g2 &= 0x3ffffff;
    uint64_t g4 = uint64_t(h[4]) + (g3>>26) - (1ull<<26); g3 &= 0x3ffffff;

    uint32_t mask = uint32_t((g4 >> 31) - 1);
    h[0] = (h[0] & ~mask) | (uint32_t(g0) & mask);
    h[1] = (h[1] & ~mask) | (uint32_t(g1) & mask);
    h[2] = (h[2] & ~mask) | (uint32_t(g2) & mask);
    h[3] = (h[3] & ~mask) | (uint32_t(g3) & mask);
    h[4] = (h[4] & ~mask) | (uint32_t(g4 + (1ull<<26)) & mask);

    uint64_t f0 = ( (uint64_t)h[0]      ) | ((uint64_t)h[1] << 26);
    uint64_t f1 = ( (uint64_t)h[2]      ) | ((uint64_t)h[3] << 26) | ((uint64_t)h[4] << 52);

    f0 += pad[0]; uint64_t c0 = f0 >> 32; uint32_t t0 = uint32_t(f0);
    f1 += pad[1] + c0; uint64_t c1 = f1 >> 32; uint32_t t1 = uint32_t(f1);
    uint64_t f2 = pad[2] + c1; uint32_t t2 = uint32_t(f2);
    uint64_t f3 = pad[3] + (f2 >> 32); uint32_t t3 = uint32_t(f3);

    tag[0]=t0&0xff; tag[1]=(t0>>8)&0xff; tag[2]=(t0>>16)&0xff; tag[3]=(t0>>24)&0xff;
    tag[4]=t1&0xff; tag[5]=(t1>>8)&0xff; tag[6]=(t1>>16)&0xff; tag[7]=(t1>>24)&0xff;
    tag[8]=t2&0xff; tag[9]=(t2>>8)&0xff; tag[10]=(t2>>16)&0xff; tag[11]=(t2>>24)&0xff;
    tag[12]=t3&0xff; tag[13]=(t3>>8)&0xff; tag[14]=(t3>>16)&0xff; tag[15]=(t3>>24)&0xff;

    std::memset(h,0,sizeof h);
    std::memset(r,0,sizeof r);
    std::memset(pad,0,sizeof pad);
    init_ok=false;
}

void AeadChaCha20Poly1305::Poly1305::process_with_lengths(const uint8_t* data, size_t len) {
    const uint8_t* p = data;
    while (len >= 16) { update(p, 16); p += 16; len -= 16; }
    if (len) update(p, len);
}

// ----- AEAD -----
void AeadChaCha20Poly1305::seal(uint8_t type, uint64_t seq, const uint8_t* pt, uint16_t pt_len,
                                std::vector<uint8_t>& ct, std::array<uint8_t,16>& tag)
{
    if (!ready_) throw std::runtime_error("AEAD not initialized");

    ct.resize(pt_len);

    uint8_t nonce[12];
    make_nonce(nonce, salt_, seq);

    uint8_t otk_block[64];
    chacha_block(key_.data(), nonce, /*counter=*/0, otk_block);

    if (pt_len)
        chacha_xor(key_.data(), nonce, /*counter=*/1, pt, ct.data(), pt_len);

    uint8_t aad[11];
    build_aad(aad, type, seq, pt_len);

    Poly1305 p;
    p.init(otk_block);
    p.finish(aad, sizeof(aad), ct.data(), pt_len, tag.data());

    std::memset(otk_block, 0, sizeof(otk_block));
    std::memset(nonce, 0, sizeof(nonce));
}

bool AeadChaCha20Poly1305::open(uint8_t type, uint64_t seq, const uint8_t* ct, uint16_t ct_len,
                                const std::array<uint8_t,16>& tag_in, std::vector<uint8_t>& outp)
{
    if (!ready_) return false;

    outp.resize(ct_len);

    uint8_t nonce[12];
    make_nonce(nonce, salt_, seq);

    uint8_t otk_block[64];
    chacha_block(key_.data(), nonce, /*counter=*/0, otk_block);

    uint8_t aad[11];
    build_aad(aad, type, seq, ct_len);

    std::array<uint8_t,16> tag_calc{};
    {
        Poly1305 p;
        p.init(otk_block);
        p.finish(aad, sizeof(aad), ct, ct_len, tag_calc.data());
    }

    unsigned diff = 0;
    for (size_t i=0;i<16;++i) diff |= uint8_t(tag_calc[i] ^ tag_in[i]);
    bool ok = (diff == 0);

    if (ok && ct_len)
        chacha_xor(key_.data(), nonce, /*counter=*/1, ct, outp.data(), ct_len);

    std::memset(otk_block, 0, sizeof(otk_block));
    std::memset(nonce, 0, sizeof(nonce));
    std::memset(tag_calc.data(), 0, tag_calc.size());
    return ok;
}

} // namespace secure
