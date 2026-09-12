// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Thin, Qt-free wrapper over the system libsecp256k1 (design §2.4: secp256k1 is
// system-linked; headers incl. extrakeys). We do NOT reimplement EC math — this
// only owns a context and exposes the exact operations the key layer needs:
// pubkey derivation, scalar validation, BIP32 tweak-add (parent->child), and
// the BIP341 key-path taptweak via secp256k1_extrakeys.

#include <array>
#include <cstdint>
#include <vector>

namespace c2w::hdkeys {

class Secp {
public:
    static Secp& instance();

    // 1 <= k < N  (rejects 0 and >= group order). Design §3.1 raw-hex range-check.
    bool seckey_verify(const uint8_t sk[32]) const;

    // seckey -> serialized pubkey (33 bytes compressed / 65 uncompressed).
    // Returns empty on failure (invalid scalar).
    std::vector<uint8_t> pubkey_create(const uint8_t sk[32], bool compressed) const;

    // Re-serialize a pubkey in the other encoding. Accepts 33 or 65 in; returns
    // 33 (compressed=true) or 65 (compressed=false). Empty on parse failure.
    std::vector<uint8_t> pubkey_reserialize(const std::vector<uint8_t>& pub, bool compressed) const;

    // BIP32 CKD tweak: child_sk = (parent_sk + tweak) mod N. In place on sk32.
    // false if the result is invalid (tweak >= N or sum == 0) => caller skips index.
    bool seckey_tweak_add(uint8_t sk[32], const uint8_t tweak[32]) const;

    // BIP32 public CKD: child_pub = parent_pub + tweak*G. In/out serialized pub
    // (33 compressed). false if invalid.
    bool pubkey_tweak_add(std::vector<uint8_t>& pub33, const uint8_t tweak[32]) const;

    // BIP341 key-path output key: given an internal seckey, compute the tweaked
    // output x-only key Q.x (32 bytes) where Q = P + H_TapTweak(P.x)*G.
    // Returns empty on failure.
    std::vector<uint8_t> taproot_output_key_from_seckey(const uint8_t sk[32]) const;

    // BIP341 key-path output key from an x-only INTERNAL key (no secret needed):
    // Q.x where Q = P + H_TapTweak(P.x)*G. Returns empty on failure.
    std::vector<uint8_t> taproot_output_key_from_xonly(const uint8_t px[32]) const;

    // x-only serialization of a pubkey (32 bytes). Empty on failure.
    std::vector<uint8_t> xonly_serialize(const std::vector<uint8_t>& pub) const;

    Secp(const Secp&) = delete;
    Secp& operator=(const Secp&) = delete;

private:
    Secp();
    ~Secp();
    struct Impl;
    Impl* p_;
};

} // namespace c2w::hdkeys
