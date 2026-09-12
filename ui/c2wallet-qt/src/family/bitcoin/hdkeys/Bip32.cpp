// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Bip32.hpp"

#include "Secp.hpp"
#include "CoinParams.hpp"

#include "../../../secure/SecureString.hpp"

#include <btclibs/crypto/sha256.h>
#include <btclibs/crypto/ripemd160.h>
#include <btclibs/crypto/hmac_sha512.h>
#include <btclibs/base58.h>
#include <btclibs/span.h>

#include <cstring>

namespace c2w::hdkeys {

namespace {
// RAII scrub for stack scratch that holds secret material (the HMAC-SHA512
// output I, and the hardened-CKD data block that embeds ser256(k)). Fires on
// every return path, success or error.
struct ScopeWipe {
    void* p;
    std::size_t n;
    ~ScopeWipe() { c2w::secure::secure_wipe(p, n); }
};
} // namespace

HDKey::~HDKey()
{
    c2w::secure::secure_wipe(privkey_.data(), privkey_.size());
    c2w::secure::secure_wipe(chaincode_.data(), chaincode_.size());
}

std::array<uint8_t, 20> hash160(const uint8_t* data, size_t n)
{
    uint8_t sha[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(data, n).Finalize(sha);
    std::array<uint8_t, 20> out;
    CRIPEMD160().Write(sha, 32).Finalize(out.data());
    return out;
}

static void be32(uint32_t v, uint8_t out[4])
{
    out[0] = uint8_t(v >> 24); out[1] = uint8_t(v >> 16);
    out[2] = uint8_t(v >> 8);  out[3] = uint8_t(v);
}
static uint32_t rd_be32(const uint8_t* p)
{
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}

std::optional<HDKey> HDKey::from_seed(const uint8_t* seed, size_t seed_len, Bip32Versions versions)
{
    static const char* kKey = "Bitcoin seed";
    uint8_t I[64];
    CHMAC_SHA512 h(reinterpret_cast<const uint8_t*>(kKey), std::strlen(kKey));
    h.Write(seed, seed_len);
    h.Finalize(I);
    ScopeWipe wipe_I{I, sizeof(I)};  // scrub the 64-byte HMAC scratch on exit

    HDKey k;
    std::memcpy(k.privkey_.data(), I, 32);
    std::memcpy(k.chaincode_.data(), I + 32, 32);
    if (!Secp::instance().seckey_verify(k.privkey_.data())) return std::nullopt;
    k.has_private_ = true;
    k.pubkey_ = Secp::instance().pubkey_create(k.privkey_.data(), /*compressed=*/true);
    if (k.pubkey_.size() != 33) return std::nullopt;
    k.depth_ = 0;
    k.child_number_ = 0;
    k.parent_fp_ = {0, 0, 0, 0};
    k.versions_ = versions;
    return k;
}

std::array<uint8_t, 4> HDKey::fingerprint() const
{
    auto h = hash160(pubkey_.data(), pubkey_.size());
    return {h[0], h[1], h[2], h[3]};
}

std::optional<HDKey> HDKey::derive_child(uint32_t index) const
{
    const bool hardened = (index & kHardened) != 0;
    if (hardened && !has_private_) return std::nullopt;  // cannot harden from xpub

    // data = (hardened ? 0x00 ‖ ser256(k) : serP(K)) ‖ ser32(index)
    uint8_t data[37];
    if (hardened) {
        data[0] = 0x00;
        std::memcpy(data + 1, privkey_.data(), 32);
    } else {
        std::memcpy(data, pubkey_.data(), 33);
    }
    be32(index, data + 33);
    ScopeWipe wipe_data{data, sizeof(data)};  // hardened path embeds ser256(k)

    uint8_t I[64];
    CHMAC_SHA512 h(chaincode_.data(), chaincode_.size());
    h.Write(data, 37);
    h.Finalize(I);
    ScopeWipe wipe_I{I, sizeof(I)};  // scrub the 64-byte HMAC scratch on exit

    HDKey child;
    std::memcpy(child.chaincode_.data(), I + 32, 32);
    child.versions_ = versions_;
    child.depth_ = uint8_t(depth_ + 1);
    child.child_number_ = index;
    child.parent_fp_ = fingerprint();

    if (has_private_) {
        std::memcpy(child.privkey_.data(), privkey_.data(), 32);
        if (!Secp::instance().seckey_tweak_add(child.privkey_.data(), I)) return std::nullopt;
        child.has_private_ = true;
        child.pubkey_ = Secp::instance().pubkey_create(child.privkey_.data(), true);
        if (child.pubkey_.size() != 33) return std::nullopt;
    } else {
        child.has_private_ = false;
        child.pubkey_ = pubkey_;  // 33-byte compressed
        if (!Secp::instance().pubkey_tweak_add(child.pubkey_, I)) return std::nullopt;
    }
    return child;
}

std::optional<HDKey> HDKey::derive_path(const std::vector<uint32_t>& path) const
{
    HDKey cur = *this;
    for (uint32_t idx : path) {
        auto next = cur.derive_child(idx);
        if (!next) return std::nullopt;
        cur = std::move(*next);
    }
    return cur;
}

HDKey HDKey::neuter() const
{
    HDKey k = *this;
    k.has_private_ = false;
    k.privkey_.fill(0);
    return k;
}

std::string HDKey::serialize() const
{
    std::vector<uint8_t> raw;
    raw.reserve(78);
    uint8_t v[4];
    be32(has_private_ ? versions_.priv : versions_.pub, v);
    raw.insert(raw.end(), v, v + 4);
    raw.push_back(depth_);
    raw.insert(raw.end(), parent_fp_.begin(), parent_fp_.end());
    uint8_t cn[4];
    be32(child_number_, cn);
    raw.insert(raw.end(), cn, cn + 4);
    raw.insert(raw.end(), chaincode_.begin(), chaincode_.end());
    if (has_private_) {
        raw.push_back(0x00);
        raw.insert(raw.end(), privkey_.begin(), privkey_.end());
    } else {
        raw.insert(raw.end(), pubkey_.begin(), pubkey_.end());  // 33 bytes
    }
    return EncodeBase58Check(Span<const unsigned char>(raw.data(), raw.size()));
}

std::optional<HDKey> HDKey::parse(const std::string& ext_key)
{
    std::vector<unsigned char> raw;
    if (!DecodeBase58Check(ext_key, raw, 78)) return std::nullopt;
    if (raw.size() != 78) return std::nullopt;

    uint32_t version = rd_be32(raw.data());
    const Slip132Entry* e = lookup_bip32_version(version);
    if (!e) return std::nullopt;   // unrecognised version bytes

    HDKey k;
    k.versions_ = e->versions;
    k.depth_ = raw[4];
    std::memcpy(k.parent_fp_.data(), raw.data() + 5, 4);
    k.child_number_ = rd_be32(raw.data() + 9);
    std::memcpy(k.chaincode_.data(), raw.data() + 13, 32);

    const uint8_t* keydata = raw.data() + 45;   // 33 bytes
    if (e->is_private) {
        if (keydata[0] != 0x00) return std::nullopt;
        std::memcpy(k.privkey_.data(), keydata + 1, 32);
        if (!Secp::instance().seckey_verify(k.privkey_.data())) return std::nullopt;
        k.has_private_ = true;
        k.pubkey_ = Secp::instance().pubkey_create(k.privkey_.data(), true);
        if (k.pubkey_.size() != 33) return std::nullopt;
    } else {
        if (keydata[0] != 0x02 && keydata[0] != 0x03) return std::nullopt;
        k.has_private_ = false;
        k.pubkey_.assign(keydata, keydata + 33);
        // Validate the point by reserializing through secp256k1.
        auto rt = Secp::instance().pubkey_reserialize(k.pubkey_, true);
        if (rt.size() != 33) return std::nullopt;
        k.pubkey_ = rt;
    }
    return k;
}

} // namespace c2w::hdkeys
