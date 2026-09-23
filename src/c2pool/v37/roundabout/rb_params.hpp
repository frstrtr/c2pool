#pragma once
// V37 roundabout split — shared primitives (S1-S5). CONSUMER-tree, header-only,
// stdlib-only. NEW module: no existing translation unit includes it, so every
// pre-existing golden (lane digest, owed_digest, wire freeze, coinbase shape)
// is unchanged by construction.
//
// Terminology (project law): "roundabouts" only. A roundabout here is one
// partition of share gossip/verification for ONE coin; the OwedLedger stays
// REPLICATED on every node (D1) — no owed row ever moves between roundabouts.
//
// Name-collision guard: ::v37::Roundabout (src/sharechain/v37/v37_roundabout.hpp)
// is the canon multichain Lane container. This module lives in
// c2pool::v37n::rb and never redefines or extends that class.

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

#include <sharechain/v37/v37_fixed.hpp>  // u64, u128, U256
#include <sharechain/v37/v37_hash.hpp>   // bytes32, sha256d

namespace c2pool::v37n::rb {

using ::v37::bytes32;
using ::v37::u128;
using ::v37::u64;
using ::v37::U256;

using ChainId  = std::uint32_t;   // == ::v37::ChainId
using MapEpoch = std::uint64_t;   // map period index e (Map_e)
using RbIndex  = std::uint32_t;   // roundabout index in [0, k)
using Stripe   = std::uint16_t;   // stripe index s in [0, n(id))

// ── canonical little-endian append helpers (consensus byte order) ──────────
inline void put_u8(std::vector<std::uint8_t>& b, std::uint8_t x) { b.push_back(x); }
inline void put_u16(std::vector<std::uint8_t>& b, std::uint16_t x) {
    for (int i = 0; i < 2; ++i) b.push_back(static_cast<std::uint8_t>(x >> (8 * i)));
}
inline void put_u32(std::vector<std::uint8_t>& b, std::uint32_t x) {
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<std::uint8_t>(x >> (8 * i)));
}
inline void put_u64(std::vector<std::uint8_t>& b, u64 x) {
    for (int i = 0; i < 8; ++i) b.push_back(static_cast<std::uint8_t>(x >> (8 * i)));
}
inline void put_u128(std::vector<std::uint8_t>& b, u128 x) {
    put_u64(b, static_cast<u64>(x));
    put_u64(b, static_cast<u64>(x >> 64));
}
inline void put_u256(std::vector<std::uint8_t>& b, const U256& x) {
    for (int i = 0; i < 4; ++i) put_u64(b, x.v[i]);
}
inline void put_b32(std::vector<std::uint8_t>& b, const bytes32& h) {
    b.insert(b.end(), h.begin(), h.end());
}
inline void put_tag(std::vector<std::uint8_t>& b, const char* tag) {
    b.insert(b.end(), tag, tag + std::strlen(tag));
}

// Domain tags (ASCII, no NUL). Every consensus hash in this module is
// domain-separated so no preimage can collide with an existing v37 digest
// ("V37H" lane header, "V37Q" owed digest, "V37C" XMR tail, ...).
inline constexpr const char* TAG_STRIPE     = "V37RB";   // stripe_key (D2, fixed by design)
inline constexpr const char* TAG_LANE_TAG   = "V37RBT";  // S1 lane_tag
inline constexpr const char* TAG_GEOMETRY   = "V37RBG";  // S1 geometry digest wrapper
inline constexpr const char* TAG_MAP        = "V37RBM";  // S3 map digest
inline constexpr const char* TAG_SUMMARY    = "V37RBS";  // S4 summary hash
inline constexpr const char* TAG_MERKLE_LF  = "V37RBL";  // S4 merkle leaf
inline constexpr const char* TAG_MERKLE_ND  = "V37RBN";  // S4 merkle node

// ── integer helpers (no floats anywhere in this module) ────────────────────
inline constexpr bool is_pow2_u64(u64 x) { return x != 0 && (x & (x - 1)) == 0; }

// floor(log2(x)) for a power of two x (x >= 1).
inline constexpr unsigned log2_pow2(u64 x) {
    unsigned r = 0;
    while (x > 1) { x >>= 1; ++r; }
    return r;
}

// Top `m` bits of a 32-byte big-endian key (m <= 32). m == 0 -> 0.
inline std::uint32_t top_bits(const bytes32& key, unsigned m) {
    if (m == 0) return 0;
    std::uint64_t hi = 0;
    for (int i = 0; i < 8; ++i) hi = (hi << 8) | key[i];
    return static_cast<std::uint32_t>(hi >> (64 - m));
}

inline bytes32 hash_bytes(const std::vector<std::uint8_t>& b) { return ::v37::sha256d(b); }

}  // namespace c2pool::v37n::rb
