// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// dgb::coin::regrind_block_nonce -- the grind -> reconstruct -> submit
// INTEGRATION seam (#82 Stage 4b/4c). The missing wiring between the faithful
// won-block RECONSTRUCTION (reconstruct_closure.hpp -> {bytes, hex}) and a
// node-B ProcessNewBlock ACCEPT.
//
// reconstruct_won_block_from_template frames a byte-faithful parent block, but
// the header it carries is the SHARE's small_header verbatim -- whose nonce, on
// the forced-won soak path, was never ground to satisfy the PARENT target. So
// the A/B delivery proof reached node B and was consensus-rejected "high-hash,
// proof of work failed". This seam closes that: given the already-framed block
// blob it grinds the header nonce through the #286 scrypt_pow_hash SSOT until
// the DGB-Scrypt PoW digest satisfies the parent target, writing the winning
// nonce back into the serialized header IN PLACE.
//
// Ordering invariant (integrator 2026-06-21): the merkle_root is fixed FIRST
// (reconstruct recomputes it from gentx_hash up the share merkle_link), THEN
// the nonce is ground -- scrypt hashes the full 80 bytes, so grinding before
// the merkle is fixed would invalidate the found nonce. This seam ENFORCES that
// order structurally: it only ever runs on an already-framed block, and it
// mutates ONLY header bytes [76..79] (kHeaderNonceOffset), never the merkle
// region [36..67] or the tx tail -- so a nonce it finds is valid for the block
// exactly as reconstructed.
//
// SSOT call-through: the hash is computed ONLY via grind_won_nonce ->
// scrypt_pow_hash (the #286 digest CALL SSOT), and the satisfaction comparison
// is the EXACT gate coin/header_chain.hpp runs (pow_hash <= target, inclusive).
// A nonce this seam accepts is, by construction, one node B accepts.
//
// FAIL-CLOSED: returns std::nullopt (block_bytes left UNCHANGED) on a runt blob
// (< 80 bytes, not even a header) or budget exhaustion -- mirroring the
// reconstructor's posture. A header that does not satisfy its target is
// daemon-rejected anyway, so the caller MUST NOT broadcast on a nullopt.
//
// Standalone-guard discipline: header-only, depends ONLY on nonce_grinder.hpp
// (-> scrypt_pow.hpp -> real btclibs scrypt + header-only u256). No core, no
// dgb OBJECT lib -- the same no-link constraint scrypt_pow/nonce_grinder keep,
// so its guard TU links the _dgb_scrypt_tus real-scrypt set.
//
// Per-coin isolation: src/impl/dgb/ only. DGB-Scrypt is a STANDALONE parent in
// the V36 default build. p2pool-merged-v36 surface: NONE -- no share format,
// coinbase commitment, or PPLNS math is touched; only the parent block header
// nonce, exactly as a real miner would have ground it.
// ---------------------------------------------------------------------------

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include <impl/dgb/coin/nonce_grinder.hpp>   // grind_won_nonce, GrindOutcome, kHeaderNonceOffset, u256

namespace dgb::coin {

// Grind the nonce of an already-framed reconstructed block (block_bytes) until
// its DGB-Scrypt PoW digest satisfies the parent target, writing the winning
// nonce back into the serialized 80-byte header [76..79] IN PLACE.
//
//   block_bytes : the reconstruct_won_block_from_template {bytes} blob --
//                 header(80) | varint(txcount) | txs. On success bytes [76..79]
//                 are overwritten with the winning nonce; ALL other bytes
//                 (merkle root, tx tail) are untouched. On failure UNCHANGED.
//   target      : compact_to_target(nBits) for the parent -- the SAME u256 the
//                 satisfaction gate compares pow_hash against.
//   start_nonce : where to begin the search (default 0).
//   max_iters   : search budget (default the full 2^32 nonce space). Regtest
//                 powLimit is trivially easy; this is the TERMINATION guard.
//
// Returns the winning {nonce, pow_hash, iters} on success (block_bytes mutated
// in place), or std::nullopt on a runt blob or exhausted budget (UNCHANGED).
inline std::optional<GrindOutcome>
regrind_block_nonce(std::vector<unsigned char>& block_bytes, const u256& target,
                    uint32_t start_nonce = 0,
                    uint64_t max_iters = (uint64_t{1} << 32))
{
    if (block_bytes.size() < 80) return std::nullopt;   // not even a header -- fail closed

    std::array<unsigned char, 80> header{};
    for (std::size_t i = 0; i < 80; ++i) header[i] = block_bytes[i];

    auto out = grind_won_nonce(header, target, start_nonce, max_iters);
    if (!out) return std::nullopt;                       // budget exhausted -- bytes UNCHANGED

    // Winning nonce -> back into the block blob, header [76..79] ONLY. The
    // merkle root [36..67] and the tx tail are never touched, so the block is
    // valid exactly as reconstructed.
    for (std::size_t i = kHeaderNonceOffset; i < 80; ++i) block_bytes[i] = header[i];
    return out;
}

}  // namespace dgb::coin