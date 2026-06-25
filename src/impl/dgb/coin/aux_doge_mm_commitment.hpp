#pragma once
// ---------------------------------------------------------------------------
// DGB+DOGE merged-mining (phase DB) -- DGB-side AuxPoW coinbase-commitment
// entry point.  THIN DELEGATION to the canonical cross-coin SSOT producer
// c2pool::merged::build_auxpow_commitment.  This header carries NO duplicate
// build logic of its own.
//
// RATIONALE (integrator adjudication 2026-06-25, thread "core builder = MM
// SSOT").  The AuxPoW merged-mining commitment build is a v36-NATIVE SHARED
// structure, not a per-coin transition-compat one.  The single producer lives
// in shared A-level scaffolding (src/c2pool/merged/merged_mining.cpp +
// src/core/coinbase_builder.hpp); it is chain_id-parameterized, and DGB/DOGE
// plug in as CHAINS, not as a per-coin build path.  A fenced DGB builder that
// "mirrors" the core one is exactly the cross-coin divergence the v36->v37
// standardization goal forbids.  DGBs real per-coin value is therefore its
// chain_id slot + fabe6d6d GOLDENS pinned to the canonical builder (see the
// KAT aux_doge_mm_commitment_test.cpp), NOT a second copy of the machinery.
//
// This header exposes only a DGB-namespaced symbol that forwards verbatim to
// the SSOT, so DGB-as-parent call sites read naturally while the bytes are
// produced in exactly one place.
//
// CANONICAL LAYOUT (owned by the SSOT; reproduced here for readers only):
//     [4]   fa be 6d 6d        MM magic
//     [32]  aux_merkle_root     big-endian (byte 31 first)
//     [4]   merkle_size         little-endian
//     [4]   merkle_nonce        little-endian
//     Total: 44 bytes.
//
// FENCED -- NOT REWIRED.  No live caller invokes this yet; the mint/work-source
// path is untouched.  Live wiring (DB embed-at-mint / DC dual-target) routes
// THROUGH the core builder and is gated on ltc-doge concurrence + operator tap.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <vector>

#include <core/uint256.hpp>
#include <c2pool/merged/merged_mining.hpp>  // SSOT: c2pool::merged::build_auxpow_commitment

namespace dgb {
namespace coin {

// MM merged-mining magic marker: 0xfa 0xbe 0x6d 0x6d ("\xfa\xbe" + "mm").
// Pinned by the KAT and available to readers/asserts; the bytes themselves are
// emitted by the SSOT, never reconstructed here.
inline constexpr unsigned char AUX_MM_MAGIC[4] = {0xfa, 0xbe, 0x6d, 0x6d};

// Size in bytes of the canonical AuxPoW merged-mining commitment blob
// (magic(4) + aux_merkle_root(32) + merkle_size(4) + merkle_nonce(4)).
inline constexpr std::size_t AUX_MM_COMMITMENT_SIZE = 44;

// Build the canonical merged-mining coinbase commitment for a DGB-as-parent
// coinbase.  THIN DELEGATION -- forwards verbatim to the cross-coin SSOT
// c2pool::merged::build_auxpow_commitment; there is NO DGB-local layout logic.
//
//   aux_merkle_root -- auxiliary (DOGE) blockchain merkle root.
//   merkle_size     -- aux merkle-tree size.
//   merkle_nonce    -- aux merkle nonce.
//
// Returns exactly AUX_MM_COMMITMENT_SIZE (44) bytes.
inline std::vector<unsigned char> build_aux_mm_commitment(
    const uint256& aux_merkle_root,
    uint32_t merkle_size,
    uint32_t merkle_nonce)
{
    return c2pool::merged::build_auxpow_commitment(
        aux_merkle_root, merkle_size, merkle_nonce);
}

} // namespace coin
} // namespace dgb
