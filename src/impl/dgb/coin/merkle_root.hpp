#pragma once
// ---------------------------------------------------------------------------
// dgb::coin::build_block_merkle_root -- the block-body merkle-root SSOT.
//
// Factored out of block_assembly.hpp so BOTH the block framer (block_assembly)
// AND the BIP141 witness-commitment injector (witness_commitment.hpp) can build
// a duplicate-last Bitcoin merkle root over an ordered hash list without a
// circular include.  The symbol stays dgb::coin::build_block_merkle_root and is
// still visible through block_assembly.hpp (which includes this), so existing
// callers/tests are unchanged.
//
// Build the canonical Bitcoin block merkle root over an ordered hash list
// (txids for the block body root; wtxids for the BIP141 witness root): duplicate
// the last leaf on an odd count, then sha256d each adjacent pair up to the
// single root.
//
// Per-coin isolation: src/impl/dgb/ only.  p2pool-merged-v36 surface: NONE.
// ---------------------------------------------------------------------------

#include <utility>
#include <vector>

#include <core/hash.hpp>
#include <core/uint256.hpp>

namespace dgb
{
namespace coin
{

inline uint256 build_block_merkle_root(std::vector<uint256> txids)
{
    if (txids.empty()) return uint256();
    while (txids.size() > 1) {
        if (txids.size() % 2 == 1)
            txids.push_back(txids.back());
        std::vector<uint256> next;
        next.reserve(txids.size() / 2);
        for (size_t i = 0; i + 1 < txids.size(); i += 2)
            next.push_back(Hash(txids[i], txids[i + 1]));
        txids = std::move(next);
    }
    return txids[0];
}

} // namespace coin
} // namespace dgb
