// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Thin, Qt-free wrapper over the system libsecp256k1 for the SIGNING core
// (design §2.4: secp256k1 is system-linked; we do NOT reimplement EC math).
// Deterministic RFC6979 nonce + canonical low-S + strict-DER serialization —
// the inherited non-negotiables of §1 / §5.3. Secrets arrive in a zeroizing
// buffer; this layer copies the 32-byte scalar only into libsecp's own stack
// and wipes its scratch on every path.
//
// M4-A adds the BIP340/341/342 Schnorr surface (design §4.1 P2TR rows): x-only
// pubkeys + keypair tweak-add (secp256k1 `extrakeys`) and Schnorr sign/verify
// (secp256k1 `schnorrsig`) — no hand-rolled Schnorr, no custom nonce RNG. The
// BIP340 nonce is the library's deterministic derivation; a fixed aux value is
// passed so signatures are reproducible (never an RNG in the signing path).

#include <array>
#include <cstdint>
#include <vector>

namespace c2w::signer {

class Secp {
public:
    static Secp& instance();

    // seckey -> serialized pubkey (33 compressed / 65 uncompressed). Empty on
    // an invalid scalar.
    std::vector<uint8_t> pubkey_create(const uint8_t sk[32], bool compressed) const;

    // 1 <= k < N.
    bool seckey_verify(const uint8_t sk[32]) const;

    // ECDSA sign the 32-byte message hash under sk. RFC6979 deterministic nonce
    // (libsecp default), normalized to low-S, serialized strict-DER (NO trailing
    // sighash byte — the caller appends it). Empty on failure.
    std::vector<uint8_t> sign_ecdsa_der(const uint8_t sk[32], const uint8_t hash32[32]) const;

    // Verify a strict-DER ECDSA sig (no sighash byte) over hash32 under pub.
    bool verify_ecdsa_der(const std::vector<uint8_t>& pub,
                          const uint8_t hash32[32],
                          const std::vector<uint8_t>& der) const;

    // ── BIP340/341/342 Schnorr surface (M4-A) ─────────────────────────────────

    // x-only pubkey (32 bytes) of sk. `parity` (0 even / 1 odd) is the Y-sign of
    // the FULL pubkey before x-only normalisation. false on an invalid scalar.
    bool xonly_pubkey(const uint8_t sk[32], uint8_t out_xonly[32], int* parity) const;

    // Tweak a 32-byte x-only internal key P by scalar `tweak32`, returning the
    // tweaked x-only key Q and its Y-parity (the control-block parity bit).
    // Pure public-key math (no secret). false if P or the result is invalid.
    bool xonly_tweak_add(const uint8_t xonly_in[32], const uint8_t tweak32[32],
                         uint8_t out_q[32], int* q_parity) const;

    // BIP341 key-path signature: keypair(d) -> keypair_xonly_tweak_add(tweak)
    // (this negates d as needed so both P and Q are even-Y, §4.1), then a BIP340
    // Schnorr sign of msg32 with a fixed 32-byte aux. Returns the 64-byte sig
    // (empty on failure). If `out_tweaked_sk` is non-null it receives the
    // normalised tweaked scalar d' (for KAT cross-check only).
    std::vector<uint8_t> schnorr_sign_tweaked(const uint8_t d[32], const uint8_t tweak32[32],
                                              const uint8_t msg32[32], const uint8_t aux32[32],
                                              uint8_t out_tweaked_sk[32] = nullptr) const;

    // BIP342 tapleaf signature: BIP340 Schnorr sign of msg32 under the UNTWEAKED
    // leaf key d (even-Y normalised by keypair). 64-byte sig, empty on failure.
    std::vector<uint8_t> schnorr_sign(const uint8_t d[32], const uint8_t msg32[32],
                                      const uint8_t aux32[32]) const;

    // Verify a 64-byte BIP340 Schnorr sig over msg32 under the 32-byte x-only pk.
    bool schnorr_verify(const uint8_t xonly[32], const uint8_t msg32[32],
                        const std::vector<uint8_t>& sig64) const;

    Secp(const Secp&) = delete;
    Secp& operator=(const Secp&) = delete;

private:
    Secp();
    ~Secp();
    struct Impl;
    Impl* p_;
};

} // namespace c2w::signer
