// SPDX-License-Identifier: AGPL-3.0-or-later
#include "WalletDat.hpp"

#include "AesCbc.hpp"
#include "Secp.hpp"

#include <btclibs/crypto/sha256.h>
#include <btclibs/crypto/sha512.h>

#include <cstring>

namespace c2w::hdkeys {

namespace {

// ── little-endian readers ───────────────────────────────────────────────────
uint16_t rd16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }
uint32_t rd32(const uint8_t* p) { return (uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24)); }

// BDB page types / item types we care about.
constexpr uint8_t P_LBTREE  = 5;
constexpr uint8_t P_OVERFLOW = 7;
constexpr uint8_t B_KEYDATA = 1;
constexpr uint8_t B_OVERFLOW = 3;
constexpr size_t  PAGE_HDR = 26;              // PAGE header size

constexpr uint32_t BTREE_MAGIC = 0x00053162;
constexpr uint32_t HASH_MAGIC  = 0x00061561;

void sha256d(const uint8_t* in, size_t n, uint8_t out[32]) {
    uint8_t t[32];
    CSHA256().Write(in, n).Finalize(t);
    CSHA256().Write(t, 32).Finalize(out);
}

// Core crypter passphrase KDF: EVP_BytesToKey(aes-256-cbc, sha512, salt, pw,
// iterations) producing 32-byte key + 16-byte iv (nDerivationMethod 0).
void bytes_to_key_sha512(const uint8_t salt[8], const std::string& pw, uint32_t iterations,
                         uint8_t out_key[32], uint8_t out_iv[16]) {
    uint8_t d[64];
    CSHA512().Write(reinterpret_cast<const uint8_t*>(pw.data()), pw.size()).Write(salt, 8).Finalize(d);
    for (uint32_t i = 1; i < iterations; ++i) CSHA512().Write(d, 64).Finalize(d);
    std::memcpy(out_key, d, 32);
    std::memcpy(out_iv, d + 32, 16);
    secure::secure_wipe(d, 64);
}

// ── a growable byte cursor over a serialized value blob ─────────────────────
struct Cursor {
    const uint8_t* p; size_t n; size_t i = 0;
    Cursor(const uint8_t* d, size_t len) : p(d), n(len) {}
    bool ok() const { return i <= n; }
    bool remaining(size_t k) const { return i + k <= n; }
    uint8_t u8() { return i < n ? p[i++] : 0; }
    uint32_t u32() { if (!remaining(4)) { i = n + 1; return 0; } uint32_t v = rd32(p + i); i += 4; return v; }
    // Bitcoin CompactSize.
    uint64_t compact() {
        uint8_t c = u8();
        if (c < 253) return c;
        if (c == 253) { if (!remaining(2)) { i = n + 1; return 0; } uint16_t v = rd16(p + i); i += 2; return v; }
        if (c == 254) { return u32(); }
        if (!remaining(8)) { i = n + 1; return 0; }
        uint64_t v = 0; for (int k = 0; k < 8; ++k) v |= (uint64_t)p[i + k] << (8 * k); i += 8; return v;
    }
    // A CompactSize-length-prefixed byte vector.
    std::vector<uint8_t> varbytes() {
        uint64_t len = compact();
        if (!remaining(len) || len > (1u << 24)) { i = n + 1; return {}; }
        std::vector<uint8_t> v(p + i, p + i + len); i += (size_t)len; return v;
    }
    std::string varstr() {
        auto b = varbytes();
        return std::string(b.begin(), b.end());
    }
};

// Extract the 32-byte secret from an OpenSSL DER-encoded EC private key
// (SEC1 ECPrivateKey). Core exports these as CPrivKey. The secret is the
// 32-byte OCTET STRING right after the "02 01 01 04 20" prefix.
bool der_secret(const std::vector<uint8_t>& der, uint8_t out[32]) {
    static const uint8_t pat[5] = {0x02, 0x01, 0x01, 0x04, 0x20};
    if (der.size() < 5 + 32) return false;
    for (size_t i = 0; i + 5 + 32 <= der.size(); ++i) {
        if (std::memcmp(der.data() + i, pat, 5) == 0) {
            std::memcpy(out, der.data() + i + 5, 32);
            return true;
        }
    }
    return false;
}

// A parsed (key,value) record with its type string stripped from the key.
struct Record {
    std::string type;
    std::vector<uint8_t> key_rest;   // key bytes after the type string
    std::vector<uint8_t> value;
};

struct MasterKey {
    std::vector<uint8_t> crypted;    // 48-byte encrypted master key
    uint8_t salt[8] = {0};
    uint32_t method = 0;
    uint32_t iterations = 0;
    bool present = false;
};

// ── BDB page walk ────────────────────────────────────────────────────────────
class BdbReader {
public:
    BdbReader(const uint8_t* data, size_t len) : d_(data), n_(len) {}

    bool parse(std::vector<Record>& out, std::string& error) {
        if (n_ < 512) { error = "file too small to be a BDB wallet"; return false; }
        uint32_t magic = rd32(d_ + 12);
        if (magic != BTREE_MAGIC && magic != HASH_MAGIC) { error = "not a Berkeley DB file (bad magic)"; return false; }
        if (magic == HASH_MAGIC) { error = "BDB hash-format wallet.dat is not supported (expected btree)"; return false; }
        pagesize_ = rd32(d_ + 20);
        if (pagesize_ < 512 || pagesize_ > (1u << 20) || (pagesize_ & (pagesize_ - 1)) != 0) {
            error = "invalid BDB page size"; return false;
        }
        size_t npages = n_ / pagesize_;
        for (size_t pg = 0; pg < npages; ++pg) {
            const uint8_t* page = d_ + pg * pagesize_;
            if (page[25] != P_LBTREE) continue;
            uint16_t entries = rd16(page + 20);
            // Leaf entries alternate key,data; collect item payloads in order.
            std::vector<std::vector<uint8_t>> items;
            items.reserve(entries);
            bool page_ok = true;
            for (uint16_t e = 0; e < entries; ++e) {
                size_t idx_off = PAGE_HDR + (size_t)e * 2;
                if (idx_off + 2 > pagesize_) { page_ok = false; break; }
                uint16_t off = rd16(page + idx_off);
                if ((size_t)off + 3 > pagesize_) { page_ok = false; break; }
                uint8_t itype = page[off + 2];
                if (itype == B_KEYDATA) {
                    uint16_t len = rd16(page + off);
                    if ((size_t)off + 3 + len > pagesize_) { page_ok = false; break; }
                    items.emplace_back(page + off + 3, page + off + 3 + len);
                } else if (itype == B_OVERFLOW) {
                    if ((size_t)off + 12 > pagesize_) { page_ok = false; break; }
                    uint32_t opg = rd32(page + off + 4);
                    uint32_t tlen = rd32(page + off + 8);
                    std::vector<uint8_t> buf;
                    if (!read_overflow(opg, tlen, buf)) { page_ok = false; break; }
                    items.emplace_back(std::move(buf));
                } else {
                    // B_DUPLICATE or unknown: not used by Core wallets.
                    items.emplace_back();
                }
            }
            if (!page_ok) continue;               // skip a malformed page, keep going
            for (size_t k = 0; k + 1 < items.size(); k += 2) {
                Record rec;
                Cursor kc(items[k].data(), items[k].size());
                rec.type = kc.varstr();
                if (!kc.ok()) continue;
                rec.key_rest.assign(items[k].begin() + kc.i, items[k].end());
                rec.value = std::move(items[k + 1]);
                out.push_back(std::move(rec));
            }
        }
        return true;
    }

private:
    bool read_overflow(uint32_t pgno, uint32_t tlen, std::vector<uint8_t>& out) {
        out.clear();
        out.reserve(tlen);
        size_t guard = 0;
        while (pgno != 0 && out.size() < tlen) {
            if (++guard > n_ / pagesize_ + 2) return false;
            if ((size_t)pgno * pagesize_ + pagesize_ > n_) return false;
            const uint8_t* page = d_ + (size_t)pgno * pagesize_;
            if (page[25] != P_OVERFLOW) return false;
            uint16_t on_page = rd16(page + 22);     // OV_LEN = hf_offset
            if (PAGE_HDR + on_page > pagesize_) return false;
            size_t take = out.size() + on_page > tlen ? tlen - out.size() : on_page;
            out.insert(out.end(), page + PAGE_HDR, page + PAGE_HDR + take);
            pgno = rd32(page + 16);                 // next_pgno
        }
        return out.size() == tlen;
    }

    const uint8_t* d_;
    size_t n_;
    uint32_t pagesize_ = 0;
};

} // namespace

WalletDatImport import_wallet_dat(const uint8_t* data, size_t len, const std::string& password)
{
    WalletDatImport r;
    std::vector<Record> records;
    BdbReader reader(data, len);
    if (!reader.parse(records, r.error)) return r;

    MasterKey mk;
    struct PendingCkey { std::vector<uint8_t> pubkey, crypted; };
    std::vector<PendingCkey> ckeys;

    for (auto& rec : records) {
        if (rec.type == "key" || rec.type == "wkey") {
            // key_rest = CPubKey (varbytes); value begins with CPrivKey (varbytes, DER).
            Cursor kc(rec.key_rest.data(), rec.key_rest.size());
            std::vector<uint8_t> pub = kc.varbytes();
            Cursor vc(rec.value.data(), rec.value.size());
            std::vector<uint8_t> der = vc.varbytes();
            if (pub.empty() || der.empty()) continue;
            ++r.key_records;
            uint8_t sk[32];
            if (der_secret(der, sk) && Secp::instance().seckey_verify(sk)) {
                WalletDatKey k;
                k.pubkey = pub; k.encrypted = false; k.decrypted = true;
                k.scalar.assign(sk, 32);
                r.keys.push_back(std::move(k));
            }
            secure::secure_wipe(sk, 32);
        } else if (rec.type == "ckey") {
            Cursor kc(rec.key_rest.data(), rec.key_rest.size());
            std::vector<uint8_t> pub = kc.varbytes();
            Cursor vc(rec.value.data(), rec.value.size());
            std::vector<uint8_t> ct = vc.varbytes();
            if (pub.empty() || ct.empty()) continue;
            ++r.key_records;
            r.is_encrypted = true;
            ckeys.push_back({pub, ct});
        } else if (rec.type == "mkey") {
            Cursor vc(rec.value.data(), rec.value.size());
            std::vector<uint8_t> crypted = vc.varbytes();
            std::vector<uint8_t> salt = vc.varbytes();
            uint32_t method = vc.u32();
            uint32_t iters = vc.u32();
            if (!vc.ok() || salt.size() != 8 || crypted.empty()) continue;
            ++r.master_keys;
            r.is_encrypted = true;
            mk.crypted = crypted;
            std::memcpy(mk.salt, salt.data(), 8);
            mk.method = method; mk.iterations = iters; mk.present = true;
        }
    }

    // Encrypted path: unlock the master key, then each ckey.
    if (r.is_encrypted && !ckeys.empty()) {
        if (!mk.present) { r.error = "encrypted wallet has crypted keys but no master key record"; r.ok = false; return r; }
        secure::SecureBytes vmaster;
        bool unlocked = false;
        if (!password.empty() && mk.method == 0) {
            uint8_t kkey[32], kiv[16];
            bytes_to_key_sha512(mk.salt, password, mk.iterations, kkey, kiv);
            auto dec = aes_cbc_decrypt_pkcs7(kkey, 32, kiv, mk.crypted.data(), mk.crypted.size());
            secure::secure_wipe(kkey, 32); secure::secure_wipe(kiv, 16);
            if (dec && dec->size() == 32) { vmaster = std::move(*dec); unlocked = true; }
        }
        if (mk.method != 0 && !password.empty()) {
            r.error = "unsupported wallet key-derivation method (only sha512/EVP_BytesToKey is handled)";
        }
        if (!unlocked) {
            r.needs_password = true;
            for (auto& c : ckeys) { WalletDatKey k; k.pubkey = c.pubkey; k.encrypted = true; k.decrypted = false; k.crypted = c.crypted; r.keys.push_back(std::move(k)); }
            if (r.error.empty()) r.error = password.empty() ? "encrypted wallet.dat: passphrase required"
                                                            : "wrong wallet.dat passphrase";
            r.ok = true;   // parsed fine; caller sees needs_password
            return r;
        }
        for (auto& c : ckeys) {
            WalletDatKey k; k.pubkey = c.pubkey; k.encrypted = true;
            uint8_t iv[32];
            sha256d(c.pubkey.data(), c.pubkey.size(), iv);   // IV = SHA256d(pubkey)[0:16]
            auto dec = aes_cbc_decrypt_pkcs7(vmaster.data(), 32, iv, c.crypted.data(), c.crypted.size());
            if (dec && dec->size() == 32 && Secp::instance().seckey_verify(dec->data())) {
                k.decrypted = true; k.scalar = dec->copy();
            } else {
                k.decrypted = false; k.crypted = c.crypted;
            }
            r.keys.push_back(std::move(k));
        }
    }

    r.ok = true;
    if (r.keys.empty() && r.error.empty()) r.error = "no key records found in wallet.dat";
    return r;
}

} // namespace c2w::hdkeys
