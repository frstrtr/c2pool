// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Thin, Qt-free wrapper over the system libsecp256k1 for the SIGNING core
// (design §2.4: secp256k1 is system-linked; we do NOT reimplement EC math).
// Deterministic RFC6979 nonce + canonical low-S + strict-DER serialization —
// the inherited non-negotiables of §1 / §5.3. Secrets arrive in a zeroizing
// buffer; this layer copies the 32-byte scalar only into libsecp's own stack
// and wipes its scratch on every path.

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

    Secp(const Secp&) = delete;
    Secp& operator=(const Secp&) = delete;

private:
    Secp();
    ~Secp();
    struct Impl;
    Impl* p_;
};

} // namespace c2w::signer
