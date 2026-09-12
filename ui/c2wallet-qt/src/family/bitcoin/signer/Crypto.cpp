// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Crypto.hpp"

#include <secp256k1.h>

#include <cstring>

namespace c2w::signer {

struct Secp::Impl {
    secp256k1_context* ctx;
};

Secp::Secp() : p_(new Impl)
{
    // Modern libsecp256k1 (>=0.2) signs and verifies under the single default
    // context; no separate SIGN/VERIFY flags are required.
    p_->ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
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

std::vector<uint8_t> Secp::sign_ecdsa_der(const uint8_t sk[32], const uint8_t hash32[32]) const
{
    secp256k1_ecdsa_signature sig;
    // nullptr noncefp => RFC6979 deterministic nonce (nonce-reuse key-leak class
    // removed, §5.3). libsecp produces canonical low-S here; normalize anyway so
    // the invariant is explicit and survives a library change.
    if (!secp256k1_ecdsa_sign(p_->ctx, &sig, hash32, sk, nullptr, nullptr)) return {};
    secp256k1_ecdsa_signature_normalize(p_->ctx, &sig, &sig);
    std::vector<uint8_t> der(72);
    size_t derlen = der.size();
    if (!secp256k1_ecdsa_signature_serialize_der(p_->ctx, der.data(), &derlen, &sig)) return {};
    der.resize(derlen);
    return der;
}

bool Secp::verify_ecdsa_der(const std::vector<uint8_t>& pub,
                            const uint8_t hash32[32],
                            const std::vector<uint8_t>& der) const
{
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(p_->ctx, &pk, pub.data(), pub.size())) return false;
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_signature_parse_der(p_->ctx, &sig, der.data(), der.size())) return false;
    secp256k1_ecdsa_signature_normalize(p_->ctx, &sig, &sig);
    return secp256k1_ecdsa_verify(p_->ctx, &sig, hash32, &pk) == 1;
}

} // namespace c2w::signer
