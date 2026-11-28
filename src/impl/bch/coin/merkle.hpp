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
// p2pool-merged-v36 SURFACE: compute_merkle_root/merkle_hash_pair are the
// consensus merkle of the parent BCH block. stratum_merkle_siblings is the
// coinbase-left branch list the stratum job hands the miner; the same list
// becomes the share's merkle_link (index 0).
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

/// Coinbase-left merkle branch siblings for a stratum job.
///
/// `tx_hashes` is WorkData::m_hashes: the body txids [tx1..txN] in block
/// (CTOR) order, with NO coinbase slot. The block's merkle tree has the
/// coinbase as leaf 0, so a placeholder leaf is prepended before folding. At
/// each level the sibling of the left-most (coinbase-descended) node is
/// emitted. Contract:
///     acc = coinbase_txid
///     for b in siblings: acc = merkle_hash_pair(acc, b)
///     acc == compute_merkle_root([coinbase_txid, tx1..txN])
/// Returns {} for a coinbase-only template (the coinbase txid is the root).
inline std::vector<uint256> stratum_merkle_siblings(const std::vector<uint256>& tx_hashes) {
    if (tx_hashes.empty()) return {};

    std::vector<uint256> level;
    level.reserve(tx_hashes.size() + 1);
    level.push_back(uint256::ZERO);  // coinbase placeholder (leaf 0)
    level.insert(level.end(), tx_hashes.begin(), tx_hashes.end());

    std::vector<uint256> siblings;
    while (level.size() > 1) {
        siblings.push_back(level[1]);  // right sibling of the coinbase node

        std::vector<uint256> next;
        next.reserve((level.size() + 2) / 2);
        next.push_back(uint256::ZERO);  // placeholder for (coinbase, level[1])
        for (size_t i = 2; i < level.size(); i += 2) {
            const uint256& l = level[i];
            const uint256& r = (i + 1 < level.size()) ? level[i + 1] : level[i];
            next.push_back(merkle_hash_pair(l, r));
        }
        level = std::move(next);
    }
    return siblings;
}

} // namespace coin
} // namespace bch