// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Secp.hpp"

#include "Csprng.hpp"

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#include <btclibs/crypto/sha256.h>

#include <cstring>

namespace c2w::hdkeys {

// BIP340 tagged hash: SHA256( SHA256(tag) ‖ SHA256(tag) ‖ msg ).
static void tagged_hash(const char* tag, const uint8_t* msg, size_t msg_len, uint8_t out[32])
{
    uint8_t th[32];
    CSHA256().Write(reinterpret_cast<const uint8_t*>(tag), std::strlen(tag)).Finalize(th);
    CSHA256 h;
    h.Write(th, 32).Write(th, 32).Write(msg, msg_len).Finalize(out);
}

struct Secp::Impl {
    secp256k1_context* ctx;
};

Secp::Secp() : p_(new Impl)
{
    p_->ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    // Side-channel hardening: randomize the context.
    uint8_t seed[32];
    csprng_bytes(seed, 32);
    secp256k1_context_randomize(p_->ctx, seed);
    volatile uint8_t* v = seed;
    for (int i = 0; i < 32; ++i) v[i] = 0;
}

Secp::~Secp()
{
    if (p_) {
        if (p_->ctx) secp256k1_context_destroy(p_->ctx);
        delete p_;
        p_ = nullptr;
    }
}

Secp& Secp::instance()
{
    static Secp s;
    return s;
}

bool Secp::seckey_verify(const uint8_t sk[32]) const
{
    return secp256k1_ec_seckey_verify(p_->ctx, sk) == 1;
}

std::vector<uint8_t> Secp::pubkey_create(const uint8_t sk[32], bool compressed) const
{
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(p_->ctx, &pub, sk)) return {};
    std::vector<uint8_t> out(compressed ? 33 : 65);
    size_t len = out.size();
    secp256k1_ec_pubkey_serialize(p_->ctx, out.data(), &len, &pub,
                                  compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    out.resize(len);
    return out;
}

std::vector<uint8_t> Secp::pubkey_reserialize(const std::vector<uint8_t>& pub, bool compressed) const
{
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(p_->ctx, &pk, pub.data(), pub.size())) return {};
    std::vector<uint8_t> out(compressed ? 33 : 65);
    size_t len = out.size();
    secp256k1_ec_pubkey_serialize(p_->ctx, out.data(), &len, &pk,
                                  compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    out.resize(len);
    return out;
}

bool Secp::seckey_tweak_add(uint8_t sk[32], const uint8_t tweak[32]) const
{
    return secp256k1_ec_seckey_tweak_add(p_->ctx, sk, tweak) == 1;
}

bool Secp::seckey_tweak_mul(uint8_t sk[32], const uint8_t factor[32]) const
{
    return secp256k1_ec_seckey_tweak_mul(p_->ctx, sk, factor) == 1;
}

bool Secp::pubkey_tweak_add(std::vector<uint8_t>& pub33, const uint8_t tweak[32]) const
{
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(p_->ctx, &pk, pub33.data(), pub33.size())) return false;
    if (!secp256k1_ec_pubkey_tweak_add(p_->ctx, &pk, tweak)) return false;
    pub33.assign(33, 0);
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(p_->ctx, pub33.data(), &len, &pk, SECP256K1_EC_COMPRESSED);
    pub33.resize(len);
    return true;
}

std::vector<uint8_t> Secp::xonly_serialize(const std::vector<uint8_t>& pub) const
{
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(p_->ctx, &pk, pub.data(), pub.size())) return {};
    secp256k1_xonly_pubkey xo;
    int parity = 0;
    if (!secp256k1_xonly_pubkey_from_pubkey(p_->ctx, &xo, &parity, &pk)) return {};
    std::vector<uint8_t> out(32);
    secp256k1_xonly_pubkey_serialize(p_->ctx, out.data(), &xo);
    return out;
}

// Shared core: given a parsed x-only internal key, apply the key-path taptweak
// and return the tweaked output key serialized to 32 bytes.
static std::vector<uint8_t> taptweak_xonly(secp256k1_context* ctx,
                                           const secp256k1_xonly_pubkey& internal)
{
    uint8_t px[32];
    secp256k1_xonly_pubkey_serialize(ctx, px, &internal);
    uint8_t tweak[32];
    tagged_hash("TapTweak", px, 32, tweak);   // key-path only: no script commitment
    secp256k1_pubkey out_full;
    if (!secp256k1_xonly_pubkey_tweak_add(ctx, &out_full, &internal, tweak)) return {};
    secp256k1_xonly_pubkey out_xo;
    int out_parity = 0;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &out_xo, &out_parity, &out_full)) return {};
    std::vector<uint8_t> q(32);
    secp256k1_xonly_pubkey_serialize(ctx, q.data(), &out_xo);
    return q;
}

std::vector<uint8_t> Secp::taproot_output_key_from_seckey(const uint8_t sk[32]) const
{
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(p_->ctx, &pub, sk)) return {};
    secp256k1_xonly_pubkey internal;
    int parity = 0;
    if (!secp256k1_xonly_pubkey_from_pubkey(p_->ctx, &internal, &parity, &pub)) return {};
    return taptweak_xonly(p_->ctx, internal);
}

std::vector<uint8_t> Secp::taproot_output_key_from_xonly(const uint8_t px[32]) const
{
    secp256k1_xonly_pubkey internal;
    if (!secp256k1_xonly_pubkey_parse(p_->ctx, &internal, px)) return {};
    return taptweak_xonly(p_->ctx, internal);
}

} // namespace c2w::hdkeys
