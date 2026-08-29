// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// dgb::coin::grind_won_nonce -- the embedded real work-gen nonce grinder
// (#82 Stage 4b/4c). Given a reconstructed 80-byte DigiByte block header and
// the parent target, it increments the header nonce until the DGB-Scrypt PoW
// digest satisfies the target, returning the winning nonce. This is the
// missing primitive between the faithful won-block RECONSTRUCTION (#82 leg-2,
// reconstruct_won_block.hpp) and a node-B ProcessNewBlock ACCEPT: the A/B
// delivery proof reached node B but was consensus-rejected "high-hash, proof
// of work failed" precisely because the forced-won seam carried no real PoW.
// The grinder closes that gap.
//
// SSOT call-through: the hash is computed ONLY via scrypt_pow_hash (the #286
// digest CALL SSOT), never a private/bypass routine -- so a nonce this grinder
// accepts is, by construction, a nonce node B's own Scrypt validation accepts.
// The comparison is the EXACT satisfaction gate coin/header_chain.hpp runs:
// pow_hash <= target (inclusive), MSB-first via u256::operator>.
//
// Nonce placement: the canonical bitcoin/DigiByte 80-byte header is
// version(4)|prev(32)|merkle(32)|time(4)|bits(4)|nonce(4) -- the nonce is the
// LAST field, bytes [76..79], little-endian. This is the identical layout
// pack(BlockHeaderType) emits (header_sample_build.hpp serializes the header
// once and feeds the SAME bytes to sha256d AND scrypt), so a header serialized
// at the ingest/reconstruct boundary and ground here agree byte-for-byte.
//
// Standalone-guard discipline: header-only, depends ONLY on scrypt_pow.hpp
// (which pulls real btclibs scrypt + the header-only u256). No core, no dgb
// OBJECT lib -- the same no-link constraint dgb_arith256.hpp / scrypt_pow.hpp
// keep, so its guard TU links the _dgb_scrypt_tus real-scrypt set, not a
// synthetic hash. Wiring grind -> reconstruct -> submit onto the live
// forced-won path (serialize BlockHeaderType, grind, write the winning nonce
// back) is the explicitly-next integration slice; this is the pure primitive.
//
// Per-coin isolation: src/impl/dgb/ only. p2pool-merged-v36 surface: NONE --
// DGB-Scrypt is a STANDALONE parent; no share format, coinbase commitment, or
// PPLNS math is touched.
// ---------------------------------------------------------------------------

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

#include <impl/dgb/coin/scrypt_pow.hpp>     // scrypt_pow_hash (PoW digest SSOT, #286)
#include <impl/dgb/coin/dgb_arith256.hpp>   // dgb::coin::u256 (also via scrypt_pow.hpp)

namespace dgb::coin {

// Byte offset of the 4-byte little-endian nonce in the canonical 80-byte header.
inline constexpr std::size_t kHeaderNonceOffset = 76;

// Write a 32-bit nonce little-endian into header[76..79] (consensus byte order).
inline void put_header_nonce_le(std::array<unsigned char, 80>& header, uint32_t nonce) {
    header[kHeaderNonceOffset + 0] = static_cast<unsigned char>(nonce & 0xffu);
    header[kHeaderNonceOffset + 1] = static_cast<unsigned char>((nonce >> 8) & 0xffu);
    header[kHeaderNonceOffset + 2] = static_cast<unsigned char>((nonce >> 16) & 0xffu);
    header[kHeaderNonceOffset + 3] = static_cast<unsigned char>((nonce >> 24) & 0xffu);
}

struct GrindOutcome {
    uint32_t nonce;     // winning nonce -- also left written into header[76..79]
    u256     pow_hash;  // scrypt_pow_hash of the winning header (<= target)
    uint64_t iters;     // nonces tried, 1-based -- the search budget consumed
};

// Grind header[76..79] from start_nonce until scrypt_pow_hash(header) <= target.
//
//   header      : the reconstructed 80-byte header; on success its nonce field
//                 is left set to the winning value (caller broadcasts THIS blob)
//   target      : compact_to_target(nBits) for the parent -- the SAME u256 the
//                 satisfaction gate compares pow_hash against
//   start_nonce : where to begin the search (default 0)
//   max_iters   : search budget. Regtest powLimit is trivially easy, so the live
//                 forced-won path satisfies in very few iters; this is the guard
//                 that the grinder TERMINATES (no infinite loop), not an expected
//                 ceiling. Defaults to the full 2^32 nonce space.
//
// Returns the winning {nonce, pow_hash, iters} on success, or std::nullopt if
// the budget (or the full 2^32 space) is exhausted with no satisfying nonce.
// "No nonce found in budget" is a hard failure the caller MUST NOT broadcast a
// header for -- failing closed mirrors the reconstructor's loud-throw posture:
// a header that does not satisfy its target is rejected by the daemon anyway.
inline std::optional<GrindOutcome>
grind_won_nonce(std::array<unsigned char, 80>& header, const u256& target,
                uint32_t start_nonce = 0,
                uint64_t max_iters = (uint64_t{1} << 32)) {
    uint32_t nonce = start_nonce;
    for (uint64_t tried = 1; tried <= max_iters; ++tried) {
        put_header_nonce_le(header, nonce);
        u256 pow = scrypt_pow_hash(header);
        if (!(pow > target))                 // pow <= target -> valid PoW (inclusive)
            return GrindOutcome{nonce, pow, tried};
        ++nonce;
        if (nonce == start_nonce) break;     // wrapped full 2^32 space, none satisfied
    }
    return std::nullopt;
}

}  // namespace dgb::coin