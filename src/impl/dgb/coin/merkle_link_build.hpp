// ---------------------------------------------------------------------------
// merkle_link_build.hpp -- calculate_merkle_link(): the FORWARD merkle-branch
// builder, the exact inverse of share_check.hpp check_merkle_link().
//
// WHY this exists (the won-block multi-tx gap):
//   A reconstructed won block's merkle ROOT is recomputed from the gentx hash
//   up the share's m_merkle_link (reconstruct_won_block.hpp:20-21,
//   block_assembly.hpp check_merkle_link(gentx_hash, link)); the other_txs only
//   populate the block BODY. So the merkle_link MUST encode the branch for the
//   exact non-coinbase set the block carries -- a coinbase-only link over a
//   multi-tx body hashes to the WRONG root and node B rejects bad-txnmrklroot.
//   The live stratum path will carry a real link from its job; the regtest
//   forced-won seed synthesizes one coinbase-only, so to drive a tx-bearing
//   won-block re-soak its m_merkle_link must be REBUILT over [gentx]++captured
//   template txids. check_merkle_link only VERIFIES a branch; this builds one.
//
// CONTRACT (round-trips through the production verifier byte-for-byte):
//   check_merkle_link(tx_hashes[index],
//                     calculate_merkle_link(tx_hashes, index))
//     == BlockMerkleRoot(tx_hashes)      // the root node B validates
//   For the won-block coinbase, index == 0 (the leftmost leaf).
//
//   merkle_combine() below mirrors check_merkle_link's combine EXACTLY
//   (share_check.hpp:198-218): PackStream(left||right) -> double-SHA256. The
//   tree uses Bitcoin's duplicate-last-on-odd rule, matching the daemon's
//   ComputeMerkleRoot, so the rebuilt root agrees with node B's.
//
// Per-coin isolation: src/impl/dgb/ only. p2pool-merged-v36 surface: NONE
// (a build-side helper; the wire merkle_link semantics are unchanged).
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <impl/dgb/share_types.hpp>   // MerkleLink

namespace dgb
{
namespace coin
{

// double-SHA256 of (left || right) -- byte-identical to check_merkle_link's
// per-level combine (share_check.hpp:198-218). Kept here so this builder and
// the verifier share ONE concatenation/hash convention.
inline uint256 merkle_combine(const uint256& left, const uint256& right)
{
    PackStream ps;
    ps << left;
    ps << right;
    auto sp = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(ps.data()), ps.size());
    return Hash(sp);
}

// Build the merkle branch from leaf `index` up to the root over `tx_hashes`,
// using Bitcoin's duplicate-last-on-odd rule. Replays through
// check_merkle_link(tx_hashes[index], result) == BlockMerkleRoot(tx_hashes).
// A single-element list yields an empty branch (root == that element).
inline MerkleLink calculate_merkle_link(std::vector<uint256> level,
                                        uint32_t index = 0)
{
    if (level.empty())
        throw std::invalid_argument("calculate_merkle_link: empty tx list");
    if (index >= level.size())
        throw std::invalid_argument("calculate_merkle_link: index out of range");

    MerkleLink link;
    link.m_index = index;

    uint32_t pos = index;
    while (level.size() > 1)
    {
        // Bitcoin merkle: duplicate the last node when the level is odd, so the
        // computed intermediate (and any self-pair on the index path) matches
        // the daemon's ComputeMerkleRoot.
        if (level.size() & 1u)
            level.push_back(level.back());

        // The sibling combined with the current node at this level.
        link.m_branch.push_back(level[pos ^ 1u]);

        std::vector<uint256> next;
        next.reserve(level.size() / 2);
        for (std::size_t k = 0; k + 1 < level.size(); k += 2)
            next.push_back(merkle_combine(level[k], level[k + 1]));

        level = std::move(next);
        pos >>= 1;
    }

    return link;
}

} // namespace coin
} // namespace dgb
