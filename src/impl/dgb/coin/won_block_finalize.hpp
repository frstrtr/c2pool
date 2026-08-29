// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// dgb::coin::finalize_won_block_pow -- the grind->reconstruct->submit JOINT
// (#82 gate). It is the missing composition between the faithful won-block
// RECONSTRUCTION (reconstruct_won_block*.hpp, leg-2) and a node-B
// ProcessNewBlock ACCEPT: the A/B delivery proof reached node B but was
// consensus-rejected "high-hash, proof of work failed" because the forced-won
// seam carried no real PoW. This seam grinds the reconstructed block's header
// nonce until the DGB-Scrypt digest satisfies the parent target, then hands the
// finalized {bytes, hex} to the existing dual-path broadcaster (P2P relay arm +
// submitblock RPC fallback) unchanged.
//
// ORDERING (integrator-pinned, 2026-06-21): merkle_root is set FIRST (it is
// already baked into bytes[36..67] by the reconstructor / assemble_won_block),
// THEN the nonce at bytes[76..79] is ground -- scrypt hashes the full 80 bytes,
// so grinding before the merkle was fixed would invalidate the found nonce.
// This seam runs strictly AFTER reconstruction, so that invariant holds by
// construction.
//
// Byte layout: the reconstructor frames the canonical block as
//   header(80) | tx_count(CompactSize) | [gentx] ++ other_txs
// where header = version(4)|prev(32)|merkle(32)|time(4)|bits(4)|nonce(4).
// bytes[0..79] is therefore the exact 80-byte header node B re-hashes, and the
// nonce is bytes[76..79] little-endian (== nonce_grinder.hpp kHeaderNonceOffset).
//
// SSOT call-through: the PoW is computed ONLY via grind_won_nonce ->
// scrypt_pow_hash (the #286 digest CALL SSOT), the EXACT pow<=target gate
// header_chain.hpp runs -- so a finalized block this seam emits is, by
// construction, one node B's own Scrypt validation accepts.
//
// FAIL-CLOSED (mirrors make_reconstruct_closure): returns std::nullopt -- never
// a partial/wrong block -- when the input is too short to frame a header or no
// satisfying nonce is found inside max_iters. A header that does not satisfy its
// target is daemon-rejected anyway, so emitting nothing is strictly safer.
//
// Standalone-guard discipline: depends ONLY on nonce_grinder.hpp (real btclibs
// scrypt + header-only u256). NO core, NO dgb OBJECT lib, NO util/HexStr -- the
// RPC-fallback hex is regenerated with a local lowercase encoder byte-identical
// to HexStr, so the seam (and its KAT) link exactly like the grinder. Operates
// on raw {bytes} so it pulls none of the block_assembly/reconstruct include set.
//
// Per-coin isolation: src/impl/dgb/ only. p2pool-merged-v36 surface: NONE.
// DGB-Scrypt is a STANDALONE parent in the V36 default build.
// ---------------------------------------------------------------------------

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <impl/dgb/coin/nonce_grinder.hpp>   // grind_won_nonce, GrindOutcome, u256, kHeaderNonceOffset

namespace dgb::coin {

// A reconstructed parent block whose header nonce now satisfies the parent
// target -- ready for the dual-path broadcaster:
//   bytes : the blob the embedded P2P relay sends
//   hex   : the same block for the external submitblock (RPC) fallback
//   grind : the winning nonce + its pow_hash + iteration count (audit trail)
struct FinalizedWonBlock {
    std::vector<unsigned char> bytes;
    std::string                hex;
    GrindOutcome               grind;
};

// Lowercase hex, byte-identical to bitcoin util HexStr -- kept local so this
// seam stays in the grinder's no-core / no-util standalone lineage.
inline std::string finalize_block_to_hex(const std::vector<unsigned char>& v) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s;
    s.reserve(v.size() * 2);
    for (unsigned char b : v) {
        s.push_back(kHex[(b >> 4) & 0xf]);
        s.push_back(kHex[b & 0xf]);
    }
    return s;
}

// Grind the reconstructed block to a node-acceptable PoW.
//
//   block_bytes : a fully reconstructed block (header at [0..79], merkle_root
//                 ALREADY set); the seam owns header[76..79] only.
//   target      : compact_to_target(nBits) for the parent -- the SAME u256
//                 header_chain.hpp / the grinder KAT compare against.
//   start_nonce / max_iters : forwarded to grind_won_nonce.
//
// Returns {bytes, hex, grind} with hex == finalize_block_to_hex(bytes) and the
// winning nonce spliced into bytes[76..79] LE. Returns std::nullopt (fail-
// closed) if block_bytes is too short to frame an 80-byte header or no nonce
// satisfies the target within max_iters.
inline std::optional<FinalizedWonBlock>
finalize_won_block_pow(std::vector<unsigned char> block_bytes, const u256& target,
                       uint32_t start_nonce = 0,
                       uint64_t max_iters = (uint64_t{1} << 32))
{
    if (block_bytes.size() < 80)
        return std::nullopt;   // too short to frame a header -> fail closed

    std::array<unsigned char, 80> header{};
    // The size>=80 guard above proves this 80-byte read is in-bounds. GCC 13's
    // -Wstringop-overread mis-tracks the vector extent through inlining when a
    // caller passes a compile-time-known short (<80) vector by value (e.g. the
    // FailsClosedOnShortInput KAT's 79-byte buffer): it false-positives here
    // ("reading 80 bytes from a region of size 79") even though that path early-
    // returns std::nullopt above. Suppress narrowly; the runtime guard is the
    // real (and only) safety net. No behavior change.
#if defined(__GNUC__) && !defined(__clang__)
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wstringop-overread"
#endif
    std::copy(block_bytes.begin(), block_bytes.begin() + 80, header.begin());
#if defined(__GNUC__) && !defined(__clang__)
#  pragma GCC diagnostic pop
#endif

    auto out = grind_won_nonce(header, target, start_nonce, max_iters);
    if (!out.has_value())
        return std::nullopt;   // no satisfying nonce in budget -> fail closed

    // Splice the winning nonce (grinder wrote it LE into header[76..79]) back
    // into the block; only the 4 nonce bytes change, every tx byte is untouched.
    std::copy(header.begin() + kHeaderNonceOffset, header.begin() + 80,
              block_bytes.begin() + kHeaderNonceOffset);

    std::string hex = finalize_block_to_hex(block_bytes);
    return FinalizedWonBlock{std::move(block_bytes), std::move(hex), *out};
}

}  // namespace dgb::coin