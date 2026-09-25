// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Deterministic fixture generator for the Family-A full-file import KATs.
// This tool is NOT part of the shipped c2wallet library or its test target: it
// runs once, on a build host that has Berkeley DB and OpenSSL, to emit the
// fixture files and an expected-values header that the KATs are checked against.
//
// Independence: it writes real Berkeley DB btree containers with libdb and does
// all crypto with OpenSSL (AES/SHA/HMAC/EC) + zlib — implementations wholly
// separate from the parser under test (which uses c2pool's btclibs + a hand
// AES-CBC + a hand BDB page reader). The "expected" secrets are the literal
// inputs (chosen scalars) and a published canonical BIP32 vector xprv, so no
// value is transcribed from the parser it validates.
//
// Build (host tooling only):
//   g++ -std=c++20 -Wno-deprecated-declarations gen_fixtures.cpp -o gen_fixtures \
//       -ldb -lcrypto -lz
//   ./gen_fixtures <out_fixtures_dir>

#include <db.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <zlib.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using Bytes = std::vector<uint8_t>;

// ── crypto helpers (OpenSSL) ────────────────────────────────────────────────
static Bytes sha256(const uint8_t* p, size_t n) { Bytes o(32); SHA256(p, n, o.data()); return o; }
static Bytes sha256d(const uint8_t* p, size_t n) { auto a = sha256(p, n); return sha256(a.data(), a.size()); }
static Bytes sha512b(const uint8_t* p, size_t n) { Bytes o(64); SHA512(p, n, o.data()); return o; }
static Bytes hmac_sha256(const Bytes& key, const uint8_t* msg, size_t n) {
    Bytes o(32); unsigned int l = 32; HMAC(EVP_sha256(), key.data(), (int)key.size(), msg, n, o.data(), &l); o.resize(l); return o;
}
static Bytes aes_cbc_enc(const Bytes& key, const uint8_t iv[16], const Bytes& pt) {
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    const EVP_CIPHER* cip = key.size() == 16 ? EVP_aes_128_cbc() : EVP_aes_256_cbc();
    EVP_EncryptInit_ex(c, cip, nullptr, key.data(), iv);
    Bytes out(pt.size() + 16); int l1 = 0, l2 = 0;
    EVP_EncryptUpdate(c, out.data(), &l1, pt.data(), (int)pt.size());
    EVP_EncryptFinal_ex(c, out.data() + l1, &l2);
    out.resize(l1 + l2); EVP_CIPHER_CTX_free(c); return out;
}
static std::string b64(const Bytes& in) {
    std::string out; out.resize(4 * ((in.size() + 2) / 3) + 1);
    int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), in.data(), (int)in.size());
    out.resize(n); return out;
}
static Bytes zlib_compress(const std::string& s) {
    uLongf bound = compressBound((uLong)s.size());
    Bytes out(bound);
    compress2(out.data(), &bound, reinterpret_cast<const Bytef*>(s.data()), (uLong)s.size(), 1);
    out.resize(bound); return out;
}

// ── secp256k1 via OpenSSL EC ────────────────────────────────────────────────
struct Ec {
    EC_GROUP* g; BN_CTX* ctx;
    Ec() { g = EC_GROUP_new_by_curve_name(NID_secp256k1); ctx = BN_CTX_new(); }
    ~Ec() { EC_GROUP_free(g); BN_CTX_free(ctx); }
    Bytes pub_compressed(const uint8_t sec[32]) {
        BIGNUM* d = BN_bin2bn(sec, 32, nullptr);
        EC_POINT* P = EC_POINT_new(g); EC_POINT_mul(g, P, d, nullptr, nullptr, ctx);
        Bytes out(33); EC_POINT_point2oct(g, P, POINT_CONVERSION_COMPRESSED, out.data(), 33, ctx);
        EC_POINT_free(P); BN_free(d); return out;
    }
    // ecdh = compress( scalar * pub_point ), pub given compressed.
    Bytes ecdh_compressed(const Bytes& pub, const uint8_t scalar[32]) {
        EC_POINT* P = EC_POINT_new(g); EC_POINT_oct2point(g, P, pub.data(), pub.size(), ctx);
        BIGNUM* s = BN_bin2bn(scalar, 32, nullptr);
        EC_POINT* R = EC_POINT_new(g); EC_POINT_mul(g, R, nullptr, P, s, ctx);
        Bytes out(33); EC_POINT_point2oct(g, R, POINT_CONVERSION_COMPRESSED, out.data(), 33, ctx);
        EC_POINT_free(P); EC_POINT_free(R); BN_free(s); return out;
    }
    Bytes der_privkey(const uint8_t sec[32]) {
        EC_KEY* k = EC_KEY_new_by_curve_name(NID_secp256k1);
        BIGNUM* d = BN_bin2bn(sec, 32, nullptr);
        EC_KEY_set_private_key(k, d);
        EC_POINT* P = EC_POINT_new(g); EC_POINT_mul(g, P, d, nullptr, nullptr, ctx);
        EC_KEY_set_public_key(k, P);
        EC_KEY_set_conv_form(k, POINT_CONVERSION_COMPRESSED);
        EC_KEY_set_asn1_flag(k, OPENSSL_EC_NAMED_CURVE);   // keep the classic explicit-params CPrivKey shape off
        int len = i2d_ECPrivateKey(k, nullptr);
        Bytes der(len); unsigned char* p = der.data(); i2d_ECPrivateKey(k, &p);
        EC_POINT_free(P); BN_free(d); EC_KEY_free(k); return der;
    }
    // reduce a big-endian buffer mod group order -> 32 bytes.
    Bytes reduce_mod_n(const Bytes& in) {
        const BIGNUM* n = EC_GROUP_get0_order(g);
        BIGNUM* v = BN_bin2bn(in.data(), (int)in.size(), nullptr);
        BIGNUM* r = BN_new(); BN_mod(r, v, n, ctx);
        Bytes out(32); BN_bn2binpad(r, out.data(), 32);
        BN_free(v); BN_free(r); return out;
    }
};

// ── Bitcoin serialization helpers ───────────────────────────────────────────
static void put_compact(Bytes& b, uint64_t v) {
    if (v < 253) b.push_back((uint8_t)v);
    else if (v <= 0xffff) { b.push_back(253); b.push_back(v & 0xff); b.push_back((v >> 8) & 0xff); }
    else if (v <= 0xffffffff) { b.push_back(254); for (int i = 0; i < 4; ++i) b.push_back((v >> (8 * i)) & 0xff); }
    else { b.push_back(255); for (int i = 0; i < 8; ++i) b.push_back((v >> (8 * i)) & 0xff); }
}
static void put_varbytes(Bytes& b, const Bytes& v) { put_compact(b, v.size()); b.insert(b.end(), v.begin(), v.end()); }
static void put_string(Bytes& b, const char* s) { size_t n = std::strlen(s); put_compact(b, n); b.insert(b.end(), s, s + n); }
static void put_u32(Bytes& b, uint32_t v) { for (int i = 0; i < 4; ++i) b.push_back((v >> (8 * i)) & 0xff); }

// ── BDB writer ───────────────────────────────────────────────────────────────
struct Rec { Bytes key, value; };
static bool write_bdb(const std::string& path, const std::vector<Rec>& recs) {
    std::remove(path.c_str());
    DB* db = nullptr;
    if (db_create(&db, nullptr, 0) != 0) return false;
    db->set_pagesize(db, 4096);
    if (db->open(db, nullptr, path.c_str(), "main", DB_BTREE, DB_CREATE, 0600) != 0) { db->close(db, 0); return false; }
    for (const auto& r : recs) {
        DBT k, v; std::memset(&k, 0, sizeof(k)); std::memset(&v, 0, sizeof(v));
        k.data = const_cast<uint8_t*>(r.key.data()); k.size = (uint32_t)r.key.size();
        v.data = const_cast<uint8_t*>(r.value.data()); v.size = (uint32_t)r.value.size();
        if (db->put(db, nullptr, &k, &v, 0) != 0) { db->close(db, 0); return false; }
    }
    db->close(db, 0);
    return true;
}

static void write_file(const std::string& path, const std::string& data) {
    FILE* f = std::fopen(path.c_str(), "wb"); std::fwrite(data.data(), 1, data.size(), f); std::fclose(f);
}
static std::string hex(const Bytes& b) { static const char* H = "0123456789abcdef"; std::string s; for (uint8_t x : b) { s += H[x >> 4]; s += H[x & 15]; } return s; }

int main(int argc, char** argv) {
    std::string dir = argc > 1 ? argv[1] : ".";
    if (!dir.empty() && dir.back() != '/') dir += '/';
    Ec ec;

    // Canonical BIP32 test-vector-1 master xprv (seed 000102..0f). Published.
    const char* MASTER_XPRV =
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    const char* PASSWORD = "c2pool-test-pass";

    // ── Electrum fixtures ───────────────────────────────────────────────────
    // (1) plaintext standard bip32 wallet.
    std::string plain_json =
        std::string("{\"seed_version\": 18, \"wallet_type\": \"standard\", ") +
        "\"keystore\": {\"type\": \"bip32\", \"pw_hash_version\": 1, " +
        "\"xpub\": \"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet\", " +
        "\"xprv\": \"" + MASTER_XPRV + "\"}}";
    write_file(dir + "electrum_plain.json", plain_json);

    // (2) plaintext storage, but the xprv field is pw_encode'd (version 1).
    {
        Bytes secret = sha256d(reinterpret_cast<const uint8_t*>(PASSWORD), std::strlen(PASSWORD));
        uint8_t iv[16]; for (int i = 0; i < 16; ++i) iv[i] = (uint8_t)(0x30 + i);   // deterministic IV
        Bytes pt(MASTER_XPRV, MASTER_XPRV + std::strlen(MASTER_XPRV));
        Bytes ct = aes_cbc_enc(secret, iv, pt);
        Bytes blob; blob.insert(blob.end(), iv, iv + 16); blob.insert(blob.end(), ct.begin(), ct.end());
        std::string enc_field = b64(blob);
        std::string field_json =
            std::string("{\"seed_version\": 18, \"wallet_type\": \"standard\", ") +
            "\"keystore\": {\"type\": \"bip32\", \"pw_hash_version\": 1, \"xprv\": \"" + enc_field + "\"}}";
        write_file(dir + "electrum_field_enc.json", field_json);

        // (3) BIE1 storage encryption wrapping (2).
        Bytes secret64 = [&] {
            Bytes o(64); PKCS5_PBKDF2_HMAC(PASSWORD, (int)std::strlen(PASSWORD), (const unsigned char*)"", 0, 1024, EVP_sha512(), 64, o.data()); return o;
        }();
        Bytes scalar = ec.reduce_mod_n(secret64);
        Bytes pub = ec.pub_compressed(scalar.data());               // encryption pubkey
        uint8_t eph[32]; for (int i = 0; i < 32; ++i) eph[i] = (uint8_t)(0x40 + i);   // deterministic ephemeral
        Bytes eph_pub = ec.pub_compressed(eph);
        Bytes ecdh = ec.ecdh_compressed(eph_pub, scalar.data());     // scalar * ephemeral_pub == eph * pub
        Bytes key = sha512b(ecdh.data(), 33);
        uint8_t iv2[16]; std::memcpy(iv2, key.data(), 16);
        Bytes key_e(key.begin() + 16, key.begin() + 32);             // AES-128
        Bytes key_m(key.begin() + 32, key.begin() + 64);
        Bytes body = zlib_compress(field_json);
        Bytes ct2 = aes_cbc_enc(key_e, iv2, body);
        Bytes encrypted; const char* magic = "BIE1";
        encrypted.insert(encrypted.end(), magic, magic + 4);
        encrypted.insert(encrypted.end(), eph_pub.begin(), eph_pub.end());
        encrypted.insert(encrypted.end(), ct2.begin(), ct2.end());
        Bytes mac = hmac_sha256(key_m, encrypted.data(), encrypted.size());
        encrypted.insert(encrypted.end(), mac.begin(), mac.end());
        write_file(dir + "electrum_bie1.wallet", b64(encrypted));
    }

    // ── wallet.dat fixtures ─────────────────────────────────────────────────
    uint8_t s1[32], s2[32];
    for (int i = 0; i < 32; ++i) { s1[i] = 0x11; s2[i] = 0x22; }
    Bytes pub1 = ec.pub_compressed(s1), pub2 = ec.pub_compressed(s2);

    // Unencrypted wallet.dat: "key" records with DER CPrivKey values.
    {
        std::vector<Rec> recs;
        for (auto pr : std::vector<std::pair<uint8_t*, Bytes*>>{{s1, &pub1}, {s2, &pub2}}) {
            Rec r;
            put_string(r.key, "key"); put_varbytes(r.key, *pr.second);
            Bytes der = ec.der_privkey(pr.first);
            put_varbytes(r.value, der);
            Bytes hin(pr.second->begin(), pr.second->end()); hin.insert(hin.end(), der.begin(), der.end());
            Bytes h = sha256d(hin.data(), hin.size());
            r.value.insert(r.value.end(), h.begin(), h.end());       // trailing checksum (ignored by parser)
            recs.push_back(std::move(r));
        }
        write_bdb(dir + "wallet_unenc.dat", recs);
    }

    // Encrypted wallet.dat: an mkey + two ckey records.
    {
        std::vector<Rec> recs;
        Bytes vmaster(32); for (int i = 0; i < 32; ++i) vmaster[i] = 0xAB;
        uint8_t salt[8]; for (int i = 0; i < 8; ++i) salt[i] = (uint8_t)(i + 1);
        uint32_t iters = 1024;
        uint8_t kkey[32], kiv[16];
        EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha512(), salt,
                       (const unsigned char*)PASSWORD, (int)std::strlen(PASSWORD), iters, kkey, kiv);
        Bytes kkeyv(kkey, kkey + 32);
        Bytes mkey_ct = aes_cbc_enc(kkeyv, kiv, vmaster);            // 48 bytes

        Rec mk;
        put_string(mk.key, "mkey"); put_u32(mk.key, 1);
        put_varbytes(mk.value, mkey_ct);
        put_varbytes(mk.value, Bytes(salt, salt + 8));
        put_u32(mk.value, 0);            // nDerivationMethod
        put_u32(mk.value, iters);        // nDeriveIterations
        put_compact(mk.value, 0);        // vchOtherDerivationParameters
        recs.push_back(std::move(mk));

        for (auto pr : std::vector<std::pair<uint8_t*, Bytes*>>{{s1, &pub1}, {s2, &pub2}}) {
            Bytes h = sha256d(pr.second->data(), pr.second->size());
            uint8_t iv[16]; std::memcpy(iv, h.data(), 16);
            Bytes sec(pr.first, pr.first + 32);
            Bytes ct = aes_cbc_enc(vmaster, iv, sec);                // 48 bytes
            Rec r;
            put_string(r.key, "ckey"); put_varbytes(r.key, *pr.second);
            put_varbytes(r.value, ct);
            recs.push_back(std::move(r));
        }
        write_bdb(dir + "wallet_enc.dat", recs);
    }

    // ── expected-values header (literal inputs + published xprv) ─────────────
    {
        std::string h;
        h += "// SPDX-License-Identifier: AGPL-3.0-or-later\n";
        h += "// GENERATED by gen_fixtures.cpp — do not edit. Expected values are the\n";
        h += "// literal fixture inputs (chosen scalars) and a published BIP32 vector.\n";
        h += "#pragma once\n#include <string>\nnamespace fx {\n";
        h += std::string("inline const std::string electrum_master_xprv = \"") + MASTER_XPRV + "\";\n";
        h += std::string("inline const std::string password = \"") + PASSWORD + "\";\n";
        h += std::string("inline const std::string walletdat_scalar1_hex = \"") + hex(Bytes(s1, s1 + 32)) + "\";\n";
        h += std::string("inline const std::string walletdat_scalar2_hex = \"") + hex(Bytes(s2, s2 + 32)) + "\";\n";
        h += std::string("inline const std::string walletdat_pub1_hex = \"") + hex(pub1) + "\";\n";
        h += std::string("inline const std::string walletdat_pub2_hex = \"") + hex(pub2) + "\";\n";
        h += "}\n";
        write_file(dir + "fixture_expected.hpp", h);
    }

    std::printf("fixtures written to %s\n", dir.c_str());
    return 0;
}
