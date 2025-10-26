#include "Handshake.h"
#include <stdexcept>
#include <cstring>
#include <cwchar>


namespace secure {

static bool write_all(SOCKET s, const uint8_t* p, size_t n) {
    size_t off=0;
    while (off<n) {
        int sent = ::send(s, (const char*)p+off, (int)(n-off), 0);
        if (sent<=0) return false;
        off += (size_t)sent;
    }
    return true;
}
static bool read_all(SOCKET s, uint8_t* p, size_t n) {
    size_t off=0;
    while (off<n) {
        int got = ::recv(s, (char*)p+off, (int)(n-off), 0);
        if (got<=0) return false;
        off += (size_t)got;
    }
    return true;
}

static void send_vec(SOCKET s, const std::vector<uint8_t>& v) {
    uint32_t be = to_be32((uint32_t)v.size());
    if (!write_all(s, (uint8_t*)&be, 4)) throw std::runtime_error("write len");
    if (!v.empty() && !write_all(s, v.data(), v.size())) throw std::runtime_error("write vec");
}
static std::vector<uint8_t> recv_vec(SOCKET s) {
    uint32_t be=0;
    if (!read_all(s, (uint8_t*)&be, 4)) throw std::runtime_error("read len");
    uint32_t n = from_be32(be);
    std::vector<uint8_t> v(n);
    if (n && !read_all(s, v.data(), n)) throw std::runtime_error("read vec");
    return v;
}

static std::vector<uint8_t> export_ecc_pub(BCRYPT_KEY_HANDLE k) {
    ULONG cb=0;
    NTSTATUS st = BCryptExportKey(k, nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &cb, 0);
    CHECK_NT("Export pub size", st);
    std::vector<uint8_t> buf(cb);
    CHECK_NT("Export pub", BCryptExportKey(k, nullptr, BCRYPT_ECCPUBLIC_BLOB, buf.data(), cb, &cb, 0));
    return buf;
}
static Key import_ecc_pub(const Alg& ecc, const std::vector<uint8_t>& blob) {
    BCRYPT_KEY_HANDLE pk{};
    CHECK_NT("Import pub", BCryptImportKeyPair(ecc.h, nullptr, BCRYPT_ECCPUBLIC_BLOB,
                                               &pk, (PUCHAR)blob.data(), (ULONG)blob.size(), 0));
    return Key{pk};
}

static std::array<uint8_t,32> derive_from_secret(const Secret& sec) {
    // Raw ECDH shared secret (P-256 → 32 bytes). No parameter list needed.
    std::array<uint8_t,32> out{};
    ULONG cb = 0;
    CHECK_NT("DeriveKey",
             BCryptDeriveKey(sec.h,
                             BCRYPT_KDF_RAW_SECRET,
                             nullptr,
                             out.data(),
                             (ULONG)out.size(),
                             &cb,
                             0));
    if (cb != out.size()) {
        // Normalize to 32 bytes if provider returns a different length.
        Sha256 H; H.update(out.data(), cb); out = H.finish();
    }
    return out;
}

HandshakeResult Handshake::run(bool is_server, SOCKET s, const std::vector<uint8_t>& psk) {
    // Algorithms
    Alg ecc; CHECK_NT("Open ECDH", BCryptOpenAlgorithmProvider(&ecc.h, BCRYPT_ECDH_P256_ALGORITHM, nullptr, 0));

    // Ephemeral keypair
    BCRYPT_KEY_HANDLE my_key{};
    CHECK_NT("GenKeyPair", BCryptGenerateKeyPair(ecc.h, &my_key, 256, 0));
    CHECK_NT("Finalize",   BCryptFinalizeKeyPair(my_key, 0));
    Key my{my_key};

    auto my_pub = export_ecc_pub(my.h);

    // Randoms
    std::array<uint8_t,32> my_rand{}; random_bytes(my_rand.data(), my_rand.size());
    std::array<uint8_t,32> peer_rand{};

    // Hello exchange
    if (!is_server) {
        // client: send my_rand, my_pub
        send_vec(s, std::vector<uint8_t>(my_rand.begin(), my_rand.end()));
        send_vec(s, my_pub);
        // recv
        auto v_rand = recv_vec(s);
        auto v_pub  = recv_vec(s);
        if (v_rand.size()!=32) throw std::runtime_error("server rand bad");
        std::memcpy(peer_rand.data(), v_rand.data(), 32);
        Key peer = import_ecc_pub(ecc, v_pub);

        // secret agreement
        BCRYPT_SECRET_HANDLE sh{}; CHECK_NT("SecretAgree", BCryptSecretAgreement(my.h, peer.h, &sh, 0));
        Secret sec{sh};
        auto shared = derive_from_secret(sec);

        // transcript = H(client_rand || server_rand || client_pub || server_pub)
        Sha256 H;
        H.update(my_rand.data(), 32);
        H.update(peer_rand.data(), 32);
        H.update(my_pub.data(),  my_pub.size());
        H.update(v_pub.data(),   v_pub.size());
        auto transcript = H.finish();

        // client verify -> server
        const char c_lbl[] = "client-verify";
        std::vector<uint8_t> vdata( transcript.begin(), transcript.end() );
        vdata.insert(vdata.end(), c_lbl, c_lbl + sizeof(c_lbl)-1);
        auto mac_c = HmacSha256::compute(psk.data(), psk.size(), vdata.data(), vdata.size());
        send_vec(s, std::vector<uint8_t>(mac_c.begin(), mac_c.end()));

        // receive server verify
        auto mac_s_recv = recv_vec(s);
        if (mac_s_recv.size()!=32) throw std::runtime_error("server mac size");
        const char s_lbl[] = "server-verify";
        std::vector<uint8_t> sdata( transcript.begin(), transcript.end() );
        sdata.insert(sdata.end(), s_lbl, s_lbl + sizeof(s_lbl)-1);
        auto mac_s = HmacSha256::compute(psk.data(), psk.size(), sdata.data(), sdata.size());
        if (ct_memcmp(mac_s_recv.data(), mac_s.data(), 32) != 0) throw std::runtime_error("PSK verify failed");

        // key schedule
        Sha256 HS; HS.update(my_rand.data(),32); HS.update(peer_rand.data(),32);
        auto salt = HS.finish(); // 32 bytes

        auto prk = HKDF::extract(salt.data(), salt.size(), shared.data(), shared.size());

        HandshakeResult res{};
        const uint8_t kc2s[] = "key c2s";
        const uint8_t ks2c[] = "key s2c";
        const uint8_t ivc2s[]= "iv c2s";
        const uint8_t ivs2c[]= "iv s2c";

        // client sends c2s, receives s2c
        HKDF::expand(prk.data(), prk.size(), kc2s, sizeof(kc2s)-1, res.keys.k_send.data(), res.keys.k_send.size());
        HKDF::expand(prk.data(), prk.size(), ks2c, sizeof(ks2c)-1, res.keys.k_recv.data(), res.keys.k_recv.size());

        HKDF::expand(prk.data(), prk.size(), ivc2s, sizeof(ivc2s)-1, res.keys.iv_send.data(), res.keys.iv_send.size());
        HKDF::expand(prk.data(), prk.size(), ivs2c, sizeof(ivs2c)-1, res.keys.iv_recv.data(), res.keys.iv_recv.size());


        SecureZeroMemory((void*)shared.data(), shared.size());
        SecureZeroMemory((void*)prk.data(), prk.size());
        return res;
    } else {
        // server: recv client
        auto v_rand = recv_vec(s);
        auto v_pub  = recv_vec(s);
        if (v_rand.size()!=32) throw std::runtime_error("client rand bad");
        std::memcpy(peer_rand.data(), v_rand.data(), 32);
        Key peer = import_ecc_pub(ecc, v_pub);

        // send my
        send_vec(s, std::vector<uint8_t>(my_rand.begin(), my_rand.end()));
        send_vec(s, my_pub);

        // secret
        BCRYPT_SECRET_HANDLE sh{}; CHECK_NT("SecretAgree", BCryptSecretAgreement(my.h, peer.h, &sh, 0));
        Secret sec{sh};
        auto shared = derive_from_secret(sec);

        // transcript = H(client_rand || server_rand || client_pub || server_pub)
        Sha256 H;
        H.update(peer_rand.data(), 32);
        H.update(my_rand.data(),   32);
        H.update(v_pub.data(),     v_pub.size());
        H.update(my_pub.data(),    my_pub.size());
        auto transcript = H.finish();

        // recv client verify
        auto mac_c_recv = recv_vec(s);
        if (mac_c_recv.size()!=32) throw std::runtime_error("client mac size");
        const char c_lbl[] = "client-verify";
        std::vector<uint8_t> cdata( transcript.begin(), transcript.end() );
        cdata.insert(cdata.end(), c_lbl, c_lbl + sizeof(c_lbl)-1);
        auto mac_c = HmacSha256::compute(psk.data(), psk.size(), cdata.data(), cdata.size());
        if (ct_memcmp(mac_c_recv.data(), mac_c.data(), 32) != 0) throw std::runtime_error("PSK verify failed");

        // send server verify
        const char s_lbl[] = "server-verify";
        std::vector<uint8_t> sdata( transcript.begin(), transcript.end() );
        sdata.insert(sdata.end(), s_lbl, s_lbl + sizeof(s_lbl)-1);
        auto mac_s = HmacSha256::compute(psk.data(), psk.size(), sdata.data(), sdata.size());
        send_vec(s, std::vector<uint8_t>(mac_s.begin(), mac_s.end()));

        // key schedule
        Sha256 HS; HS.update(peer_rand.data(),32); HS.update(my_rand.data(),32);
        auto salt = HS.finish(); // 32

        auto prk = HKDF::extract(salt.data(), salt.size(), shared.data(), shared.size());

        HandshakeResult res{};
        const uint8_t kc2s[] = "key c2s";
        const uint8_t ks2c[] = "key s2c";
        const uint8_t ivc2s[]= "iv c2s";
        const uint8_t ivs2c[]= "iv s2c";

        // server receives c2s, sends s2c
        HKDF::expand(prk.data(), prk.size(), kc2s, sizeof(kc2s)-1, res.keys.k_recv.data(), res.keys.k_recv.size());
        HKDF::expand(prk.data(), prk.size(), ks2c, sizeof(ks2c)-1, res.keys.k_send.data(), res.keys.k_send.size());

        HKDF::expand(prk.data(), prk.size(), ivc2s, sizeof(ivc2s)-1, res.keys.iv_recv.data(), res.keys.iv_recv.size());
        HKDF::expand(prk.data(), prk.size(), ivs2c, sizeof(ivs2c)-1, res.keys.iv_send.data(), res.keys.iv_send.size());

        SecureZeroMemory((void*)shared.data(), shared.size());
        SecureZeroMemory((void*)prk.data(), prk.size());
        return res;
    }
}

} // namespace secure
