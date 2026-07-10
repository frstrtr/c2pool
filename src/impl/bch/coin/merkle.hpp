// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// bch::coin merkle helpers -- single source of truth for the SHA256d
// transaction merkle root. BCH did NOT change the merkle rule from Bitcoin:
// pairwise SHA256d, odd row duplicates its last element. CTOR (Nov 2018)
// changes only the *order* transactions appear in the block (coinbase first,
// then ascending txid); the merkle is still computed over that block order
// as-is, so nothing CTOR-specific lives here.
//
// Extracted from template_builder.hpp so both the producer side (GBT template
// builder, M4) and the consumer side (p2p_node full-block accept, M5) compute
// the root through one implementation rather than two divergent copies.
//
// p2pool-merged-v36 SURFACE: NONE. This is the consensus merkle of the parent
// BCH block -- it never touches share hashing, the share merkle_link, the
// coinbase commitment, or PPLNS. Source-only / build-inert.
// ---------------------------------------------------------------------------

#include <core/hash.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <span>
#include <vector>

namespace bch
{
namespace coin
{

/// SHA256d of two concatenated 32-byte hashes (an internal merkle node).
inline uint256 merkle_hash_pair(const uint256& left, const uint256& right) {
    auto sl = std::span<const uint8_t>(left.data(),  32);
    auto sr = std::span<const uint8_t>(right.data(), 32);
    return Hash(sl, sr);
}

/// Merkle root over txids (SHA256d pairwise, last element duplicated for odd
/// counts). Identical algorithm to BTC -- BCH did not change the merkle rule.
inline uint256 compute_merkle_root(std::vector<uint256> hashes) {
    if (hashes.empty()) return uint256::ZERO;
    while (hashes.size() > 1) {
        if (hashes.size() & 1u)
            hashes.push_back(hashes.back());
        std::vector<uint256> next;
        next.reserve(hashes.size() / 2);
        for (size_t i = 0; i < hashes.size(); i += 2)
            next.push_back(merkle_hash_pair(hashes[i], hashes[i + 1]));
        hashes = std::move(next);
    }
    return hashes[0];
}

} // namespace coin
} // namespace bch