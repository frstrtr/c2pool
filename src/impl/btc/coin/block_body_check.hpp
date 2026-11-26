// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// btc::coin::block_body_matches_header -- a block body received from a coin
// peer belongs to its header (which the header chain holds, PoW-checked); the
// checks of Bitcoin Core's IsBlockMutated:
//   - at least one transaction; the first is a coinbase and no other is
//     (Core tests for 64-byte transactions, CVE-2017-12842, only when the
//     first one is not a coinbase, which this already rejects; a 64-byte
//     transaction is valid by consensus and is accepted);
//   - no two with the same txid (a duplicated subtree leaves the merkle root
//     unchanged);
//   - the txid merkle root equals the header's merkle root;
//   - BIP 141: if the coinbase has a witness commitment output (the last
//     output whose script starts 6a24aa21a9ed and is at least 38 bytes), the
//     coinbase input's witness is one 32-byte item and
//     SHA256d(witness merkle root || that item) equals the committed hash;
//     with no commitment, no transaction carries witness data.
// The standalone coin peer pool passes a body to the coin node only when this
// holds. The witness rules are applied whatever the block's height: the pool
// fetches bodies only near the header tip (pool_body_wanted), and a block
// before segwit activation carries no witness data and no commitment, which
// passes. The checks themselves are basic_block_body_check.hpp (shared with
// c2pool-bip110); this header binds them to the BTC hashes.

#include "basic_block_body_check.hpp"
#include "block.hpp"
#include "mempool.hpp"           // compute_txid
#include "template_builder.hpp"  // compute_merkle_root, witness_merkle_root

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <vector>

namespace btc::coin {

/// Index of the BIP 141 witness commitment output in `coinbase`, or -1.
inline int witness_commitment_index(const MutableTransaction& coinbase)
{
    return basic_witness_commitment_index(coinbase);
}

/// A coinbase transaction: one input, spending the null outpoint.
inline bool is_coinbase_tx(const MutableTransaction& tx)
{
    return basic_is_coinbase_tx(tx);
}

inline uint256 compute_wtxid(const MutableTransaction& tx)
{
    auto packed = pack(TX_WITH_WITNESS(tx));
    return Hash(packed.get_span());
}

/// The BTC hashes of basic_block_body_matches_header.
struct BtcBodyHashes {
    static uint256 txid(const MutableTransaction& tx) { return compute_txid(tx); }
    static uint256 wtxid(const MutableTransaction& tx) { return compute_wtxid(tx); }
    static uint256 merkle_root(const std::vector<uint256>& txids)
    {
        return compute_merkle_root(txids);
    }
    static uint256 witness_merkle_root(const std::vector<uint256>& other_wtxids)
    {
        return btc::coin::witness_merkle_root(other_wtxids);
    }
};

inline bool block_body_matches_header(const BlockType& block)
{
    return basic_block_body_matches_header<BtcBodyHashes>(block);
}

} // namespace btc::coin
