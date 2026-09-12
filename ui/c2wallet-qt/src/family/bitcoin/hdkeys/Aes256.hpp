// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Minimal, self-contained AES-256 single-block ECB primitive (FIPS-197).
//
// This is the ONE new symmetric-crypto dependency BIP38 needs (design §3.1:
// "Only new dep is AES"). c2pool ships no general AES-256 block cipher — the
// in-tree AES material is either x11-hashing round macros (dash) or RandomX's
// soft_aes, neither of which exposes a clean 256-bit block encrypt/decrypt — so
// a compact FIPS-197 implementation is added here and KAT-gated against the
// FIPS-197 Appendix C.3 vector.
//
// Scope is deliberately tiny: 16-byte block, 32-byte key, no mode/padding. BIP38
// XORs the derived-half plaintext itself, so ECB single-block is exactly right
// and no IV/mode is involved.

#include <cstdint>

namespace c2w::hdkeys {

class Aes256 {
public:
    // key MUST be 32 bytes. Expands the round keys on construction.
    explicit Aes256(const uint8_t key[32]);
    ~Aes256();

    // Encrypt / decrypt exactly one 16-byte block. in and out may alias.
    void encrypt_block(const uint8_t in[16], uint8_t out[16]) const;
    void decrypt_block(const uint8_t in[16], uint8_t out[16]) const;

    Aes256(const Aes256&) = delete;
    Aes256& operator=(const Aes256&) = delete;

private:
    // 15 round keys * 16 bytes = 240 bytes of expanded key material (Nr=14).
    uint8_t rk_[240];
};

} // namespace c2w::hdkeys
