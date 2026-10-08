// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Electrum.hpp"

#include "AesCbc.hpp"
#include "Bip32.hpp"
#include "Bip39.hpp"
#include "KeyImport.hpp"
#include "MiniJson.hpp"
#include "Secp.hpp"

#include <btclibs/crypto/hmac_sha256.h>
#include <btclibs/crypto/sha256.h>
#include <btclibs/crypto/sha512.h>

#include <zlib.h>

#include <array>
#include <cctype>
#include <cstring>

namespace c2w::hdkeys {

namespace {

// ── base64 decode (standard alphabet, tolerant of embedded whitespace) ──────
int b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
bool b64_decode(const std::string& in, std::vector<uint8_t>& out) {
    out.clear();
    int bits = 0, acc = 0, pad = 0;
    for (char c : in) {
        if (std::isspace((unsigned char)c)) continue;
        if (c == '=') { ++pad; continue; }
        if (pad) return false;               // data after padding
        int v = b64val(c);
        if (v < 0) return false;
        acc = (acc << 6) | v; bits += 6;
        if (bits >= 8) { bits -= 8; out.push_back((uint8_t)((acc >> bits) & 0xff)); }
    }
    return true;
}

// ── zlib inflate (Electrum storage body is zlib.compress'd) ─────────────────
bool zlib_inflate(const uint8_t* in, size_t in_len, std::string& out) {
    z_stream zs; std::memset(&zs, 0, sizeof(zs));
    if (inflateInit(&zs) != Z_OK) return false;
    zs.next_in = const_cast<Bytef*>(in);
    zs.avail_in = (uInt)in_len;
    char buf[16384];
    int ret;
    do {
        zs.next_out = reinterpret_cast<Bytef*>(buf);
        zs.avail_out = sizeof(buf);
        ret = inflate(&zs, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END) { inflateEnd(&zs); return false; }
        out.append(buf, sizeof(buf) - zs.avail_out);
    } while (ret != Z_STREAM_END);
    inflateEnd(&zs);
    return true;
}

void sha256d(const uint8_t* in, size_t n, uint8_t out[32]) {
    uint8_t t[32];
    CSHA256().Write(in, n).Finalize(t);
    CSHA256().Write(t, 32).Finalize(out);
}

// secp256k1 group order N, big-endian, padded to 33 bytes (leading 0x00) so a
// left-shift during long division cannot overflow the buffer.
const uint8_t kN33[33] = {
    0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41};

bool ge33(const uint8_t a[33], const uint8_t b[33]) {
    for (int i = 0; i < 33; ++i) { if (a[i] != b[i]) return a[i] > b[i]; }
    return true;   // equal
}
void sub33(uint8_t a[33], const uint8_t b[33]) {
    int borrow = 0;
    for (int i = 32; i >= 0; --i) { int d = a[i] - b[i] - borrow; borrow = d < 0; a[i] = (uint8_t)(d & 0xff); }
}

// Reduce an arbitrary-length big-endian integer mod N -> 32-byte big-endian.
// (Electrum: ec_key = ECPrivkey.from_arbitrary_size_secret(pbkdf2_sha512(pw))).
std::array<uint8_t, 32> reduce_mod_n(const uint8_t* in, size_t n) {
    uint8_t rem[33] = {0};
    for (size_t b = 0; b < n; ++b) {
        for (int bit = 7; bit >= 0; --bit) {
            int carry = (in[b] >> bit) & 1;
            for (int i = 32; i >= 0; --i) { int nc = (rem[i] >> 7) & 1; rem[i] = (uint8_t)((rem[i] << 1) | carry); carry = nc; }
            if (ge33(rem, kN33)) sub33(rem, kN33);
        }
    }
    std::array<uint8_t, 32> out{};
    std::memcpy(out.data(), rem + 1, 32);
    return out;
}

// The Electrum storage decryption scalar: pbkdf2-HMAC-SHA512(password, "", 1024)
// (64 bytes) reduced mod N. Returns 32-byte big-endian scalar.
std::array<uint8_t, 32> electrum_password_scalar(const std::string& password) {
    uint8_t secret[64];
    pbkdf2_hmac_sha512(reinterpret_cast<const uint8_t*>(password.data()), password.size(),
                       reinterpret_cast<const uint8_t*>(""), 0, 1024, secret, 64);
    auto s = reduce_mod_n(secret, 64);
    secure::secure_wipe(secret, 64);
    return s;
}

std::string lower(std::string s) { for (char& c : s) c = (char)std::tolower((unsigned char)c); return s; }

bool looks_base64ish(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) { if (!(b64val(c) >= 0 || c == '=' || std::isspace((unsigned char)c))) return false; }
    return true;
}

// Recover an xprv field that may be raw or Electrum-pw_encoded. Returns the
// recovered xprv string, or "" (and sets need_pw if a password would be needed).
std::string recover_xprv(const std::string& field, const std::string& password,
                         int pw_hash_version, bool& need_pw) {
    if (field.empty()) return "";
    if (HDKey::parse(field)) return field;                 // raw xprv/yprv/zprv
    if (!password.empty()) {
        std::string plain;
        if (electrum_pw_decode(field, password, pw_hash_version, plain) && HDKey::parse(plain))
            return plain;
        need_pw = true;                                    // present but undecryptable
    } else if (looks_base64ish(field)) {
        need_pw = true;                                    // looks encrypted, no password given
    }
    return "";
}

// Recover a seed / passphrase text field (may be pw_encoded).
std::string recover_text(const std::string& field, const std::string& password,
                         int pw_hash_version, bool& need_pw) {
    if (field.empty()) return "";
    // A plaintext Electrum seed is printable and typically space-separated.
    bool has_space = field.find(' ') != std::string::npos;
    if (has_space) return field;
    if (!password.empty() && looks_base64ish(field)) {
        std::string plain;
        if (electrum_pw_decode(field, password, pw_hash_version, plain)) return plain;
        need_pw = true;
        return "";
    }
    if (password.empty() && looks_base64ish(field) && field.size() >= 24) { need_pw = true; return ""; }
    return field;   // treat as plaintext (e.g. old-electrum hex seed)
}

void harvest_block(const mjson::JVal& block, const std::string& source,
                   const std::string& password, ElectrumImport& r) {
    std::string type = block.str_of("type");
    int pwv = 1;
    if (const mjson::JVal* v = block.find("pw_hash_version"); v && v->t == mjson::JVal::T::Num)
        pwv = (int)v->num;

    // bip32 xprv
    if (const mjson::JVal* xf = block.find("xprv"); xf && xf->t == mjson::JVal::T::Str && !xf->str.empty()) {
        bool need = false;
        std::string xprv = recover_xprv(xf->str, password, pwv, need);
        if (!xprv.empty()) {
            ElectrumKeyItem it; it.kind = ElectrumKeyItem::Kind::Xprv;
            it.keystore_type = type.empty() ? "bip32" : type; it.source = source; it.text = xprv;
            r.items.push_back(std::move(it));
        } else if (need) r.needs_password = true;
    }
    // electrum seed (+ optional extension passphrase)
    if (const mjson::JVal* sf = block.find("seed"); sf && sf->t == mjson::JVal::T::Str && !sf->str.empty()) {
        bool need = false;
        std::string seed = recover_text(sf->str, password, pwv, need);
        if (!seed.empty()) {
            ElectrumKeyItem it; it.kind = ElectrumKeyItem::Kind::Seed;
            it.keystore_type = type.empty() ? "old" : type; it.source = source; it.text = seed;
            if (const mjson::JVal* pf = block.find("passphrase"); pf && pf->t == mjson::JVal::T::Str && !pf->str.empty()) {
                bool n2 = false; it.passphrase = recover_text(pf->str, password, pwv, n2);
            }
            r.items.push_back(std::move(it));
        } else if (need) r.needs_password = true;
    }
    // old-keystore master private key (rare; usually watching-only mpk)
    if (const mjson::JVal* mf = block.find("master_private_key"); mf && mf->t == mjson::JVal::T::Str && !mf->str.empty()) {
        ElectrumKeyItem it; it.kind = ElectrumKeyItem::Kind::MasterPrivateKey;
        it.keystore_type = type.empty() ? "old" : type; it.source = source; it.text = mf->str;
        r.items.push_back(std::move(it));
    }
    // imported keystore: keypairs = { pubkey_hex : wif(maybe pw_encoded) }
    if (const mjson::JVal* kp = block.find("keypairs"); kp && kp->t == mjson::JVal::T::Obj) {
        for (const auto& kv : kp->obj) {
            if (kv.second.t != mjson::JVal::T::Str) continue;
            const std::string& wif = kv.second.str;
            WifDecode d = decode_wif(wif);
            std::string plain;
            if (!d.ok && !password.empty() && looks_base64ish(wif) &&
                electrum_pw_decode(wif, password, pwv, plain))
                d = decode_wif(plain);
            if (d.ok) {
                ElectrumKeyItem it; it.kind = ElectrumKeyItem::Kind::Wif;
                it.keystore_type = "imported"; it.source = source;
                it.scalar = d.scalar.copy(); it.compressed = d.compressed;
                r.items.push_back(std::move(it));
            } else if (!password.empty() || looks_base64ish(wif)) r.needs_password = true;
        }
    }
}

bool is_cosigner_key(const std::string& k) {
    // x1/, x2/, ... (multisig / 2fa cosigner blocks)
    if (k.size() < 3 || k[0] != 'x' || k.back() != '/') return false;
    for (size_t i = 1; i + 1 < k.size(); ++i) if (!std::isdigit((unsigned char)k[i])) return false;
    return true;
}

} // namespace

// ── Electrum field pw_decode (version 1) ────────────────────────────────────
bool electrum_pw_decode(const std::string& b64, const std::string& password,
                        int pw_hash_version, std::string& out_plaintext) {
    if (pw_hash_version != 1) return false;   // v2+ unsupported (Electrum dropped it too)
    std::vector<uint8_t> blob;
    if (!b64_decode(b64, blob) || blob.size() < 32 || (blob.size() % 16) != 0) return false;
    uint8_t key[32];
    sha256d(reinterpret_cast<const uint8_t*>(password.data()), password.size(), key);   // secret = SHA256d(pw)
    const uint8_t* iv = blob.data();
    auto pt = aes_cbc_decrypt_pkcs7(key, 32, iv, blob.data() + 16, blob.size() - 16);
    secure::secure_wipe(key, 32);
    if (!pt) return false;
    out_plaintext.assign(reinterpret_cast<const char*>(pt->data()), pt->size());
    return true;
}

// ── Electrum BIE1 storage decrypt ───────────────────────────────────────────
bool electrum_decrypt_storage(const std::string& b64_blob, const std::string& password,
                              std::string& out_json, std::string& out_error) {
    std::vector<uint8_t> enc;
    if (!b64_decode(b64_blob, enc)) { out_error = "storage blob is not valid base64"; return false; }
    if (enc.size() < 85) { out_error = "storage blob too short"; return false; }
    if (std::memcmp(enc.data(), "BIE1", 4) != 0) { out_error = "unexpected storage magic (expected BIE1)"; return false; }

    const uint8_t* ephem_pub = enc.data() + 4;           // 33 bytes compressed
    const uint8_t* ciphertext = enc.data() + 37;
    size_t ct_len = enc.size() - 37 - 32;
    const uint8_t* mac = enc.data() + enc.size() - 32;

    auto scalar = electrum_password_scalar(password);
    std::vector<uint8_t> ephem(ephem_pub, ephem_pub + 33);
    auto ecdh = Secp::instance().ecdh_compressed(ephem, scalar.data());
    secure::secure_wipe(scalar.data(), scalar.size());
    if (ecdh.size() != 33) { out_error = "invalid ephemeral pubkey in storage blob"; return false; }

    uint8_t key[64];
    CSHA512().Write(ecdh.data(), 33).Finalize(key);
    const uint8_t* iv = key;             // key[0:16]
    const uint8_t* key_e = key + 16;     // key[16:32]  -> AES-128
    const uint8_t* key_m = key + 32;     // key[32:64]

    uint8_t want_mac[32];
    CHMAC_SHA256(key_m, 32).Write(enc.data(), enc.size() - 32).Finalize(want_mac);
    bool mac_ok = std::memcmp(want_mac, mac, 32) == 0;
    if (!mac_ok) {
        secure::secure_wipe(key, 64);
        out_error = "wrong password (HMAC mismatch)";
        return false;
    }
    auto body = aes_cbc_decrypt_pkcs7(key_e, 16, iv, ciphertext, ct_len);
    secure::secure_wipe(key, 64);
    if (!body) { out_error = "storage body decrypt failed"; return false; }
    bool ok = zlib_inflate(body->data(), body->size(), out_json);
    if (!ok) { out_error = "storage body inflate failed"; return false; }
    return true;
}

ElectrumImport import_electrum_wallet(const std::string& data, const std::string& password) {
    ElectrumImport r;

    // Trim leading whitespace to sniff the format.
    size_t start = 0;
    while (start < data.size() && std::isspace((unsigned char)data[start])) ++start;
    std::string json;
    if (start < data.size() && data[start] == '{') {
        json = data;                                        // plaintext JSON
    } else {
        // Storage-encrypted blob. Peek the magic.
        std::vector<uint8_t> enc;
        if (b64_decode(data, enc) && enc.size() >= 4 && std::memcmp(enc.data(), "BIE2", 4) == 0) {
            r.was_encrypted = true; r.needs_password = true;
            r.error = "Electrum BIE2 (xpub-password) storage is not supported without the wallet xpub";
            return r;
        }
        r.was_encrypted = true;
        if (password.empty()) { r.needs_password = true; r.error = "encrypted Electrum wallet: password required"; return r; }
        std::string err;
        if (!electrum_decrypt_storage(data, password, json, err)) {
            r.needs_password = true; r.error = err; return r;
        }
    }

    auto pr = mjson::parse(json);
    if (!pr.ok) { r.error = "Electrum wallet JSON parse error: " + pr.error; return r; }
    const mjson::JVal& root = pr.root;
    if (!root.is_obj()) { r.error = "Electrum wallet is not a JSON object"; return r; }

    if (const mjson::JVal* sv = root.find("seed_version"); sv && sv->t == mjson::JVal::T::Num) {
        r.seed_version = (int)sv->num;
        if (r.seed_version < 4 || r.seed_version > 72) {
            r.error = "unsupported Electrum seed_version " + std::to_string(r.seed_version);
            return r;
        }
    }
    r.wallet_type = root.str_of("wallet_type");
    {
        std::string wt = lower(r.wallet_type);
        r.two_factor = (wt == "2fa");
        // "<m>of<n>" multisig marker.
        size_t of = wt.find("of");
        if (of != std::string::npos && of > 0 && of + 2 < wt.size() &&
            std::isdigit((unsigned char)wt[of - 1]) && std::isdigit((unsigned char)wt[of + 2]))
            r.multisig = true;
    }

    // Harvest the single keystore and any cosigner blocks.
    if (const mjson::JVal* ks = root.find("keystore"); ks && ks->is_obj())
        harvest_block(*ks, "keystore", password, r);
    for (const auto& kv : root.obj) {
        if (is_cosigner_key(kv.first) && kv.second.is_obj()) {
            r.multisig = r.multisig || !r.two_factor;   // x2/ etc. imply multi-cosigner
            harvest_block(kv.second, kv.first, password, r);
        }
    }

    if (r.needs_password && r.items.empty()) {
        if (r.error.empty()) r.error = "password required to decrypt keystore fields";
        return r;
    }
    r.ok = true;
    if (r.items.empty())
        r.error = "no recoverable private-key material (watching-only wallet?)";
    return r;
}

} // namespace c2w::hdkeys
