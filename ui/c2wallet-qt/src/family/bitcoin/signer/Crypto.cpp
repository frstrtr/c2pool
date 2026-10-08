// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Crypto.hpp"

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

#include <cstring>

namespace c2w::signer {

namespace {
// Wipe a libsecp keypair's on-stack secret scratch — the keypair carries the
// (possibly negated/tweaked) private scalar. Compiler-barrier'd (§5.3 memory
// hygiene). Kept file-local; the public secret containers are SecureBytes.
inline void secure_scratch_wipe(secp256k1_keypair* kp)
{
    volatile unsigned char* p = reinterpret_cast<volatile unsigned char*>(kp);
    for (size_t i = 0; i < sizeof(*kp); ++i) p[i] = 0;
}
} // namespace

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

// ── BIP340/341/342 Schnorr surface ──────────────────────────────────────────

bool Secp::xonly_pubkey(const uint8_t sk[32], uint8_t out_xonly[32], int* parity) const
{
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(p_->ctx, &kp, sk)) return false;
    secp256k1_xonly_pubkey xo;
    int pk_parity = 0;
    if (!secp256k1_keypair_xonly_pub(p_->ctx, &xo, &pk_parity, &kp)) {
        secure_scratch_wipe(&kp);
        return false;
    }
    secp256k1_xonly_pubkey_serialize(p_->ctx, out_xonly, &xo);
    if (parity) *parity = pk_parity;
    secure_scratch_wipe(&kp);
    return true;
}

bool Secp::xonly_tweak_add(const uint8_t xonly_in[32], const uint8_t tweak32[32],
                           uint8_t out_q[32], int* q_parity) const
{
    secp256k1_xonly_pubkey P;
    if (!secp256k1_xonly_pubkey_parse(p_->ctx, &P, xonly_in)) return false;
    secp256k1_pubkey Q;
    if (!secp256k1_xonly_pubkey_tweak_add(p_->ctx, &Q, &P, tweak32)) return false;
    secp256k1_xonly_pubkey Qxo;
    int parity = 0;
    if (!secp256k1_xonly_pubkey_from_pubkey(p_->ctx, &Qxo, &parity, &Q)) return false;
    secp256k1_xonly_pubkey_serialize(p_->ctx, out_q, &Qxo);
    if (q_parity) *q_parity = parity;
    return true;
}

std::vector<uint8_t> Secp::schnorr_sign_tweaked(const uint8_t d[32], const uint8_t tweak32[32],
                                                const uint8_t msg32[32], const uint8_t aux32[32],
                                                uint8_t out_tweaked_sk[32]) const
{
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(p_->ctx, &kp, d)) return {};
    // keypair_xonly_tweak_add negates the secret as needed so BOTH the internal
    // key P and the output key Q are even-Y (BIP341 §4.1), then applies +tweak.
    if (!secp256k1_keypair_xonly_tweak_add(p_->ctx, &kp, tweak32)) {
        secure_scratch_wipe(&kp);
        return {};
    }
    if (out_tweaked_sk) secp256k1_keypair_sec(p_->ctx, out_tweaked_sk, &kp);
    std::vector<uint8_t> sig(64);
    if (!secp256k1_schnorrsig_sign32(p_->ctx, sig.data(), msg32, &kp, aux32)) {
        secure_scratch_wipe(&kp);
        return {};
    }
    secure_scratch_wipe(&kp);
    return sig;
}

std::vector<uint8_t> Secp::schnorr_sign(const uint8_t d[32], const uint8_t msg32[32],
                                        const uint8_t aux32[32]) const
{
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(p_->ctx, &kp, d)) return {};
    std::vector<uint8_t> sig(64);
    if (!secp256k1_schnorrsig_sign32(p_->ctx, sig.data(), msg32, &kp, aux32)) {
        secure_scratch_wipe(&kp);
        return {};
    }
    secure_scratch_wipe(&kp);
    return sig;
}

bool Secp::schnorr_verify(const uint8_t xonly[32], const uint8_t msg32[32],
                          const std::vector<uint8_t>& sig64) const
{
    if (sig64.size() != 64) return false;
    secp256k1_xonly_pubkey pk;
    if (!secp256k1_xonly_pubkey_parse(p_->ctx, &pk, xonly)) return false;
    return secp256k1_schnorrsig_verify(p_->ctx, sig64.data(), msg32, 32, &pk) == 1;
}

} // namespace c2w::signer
