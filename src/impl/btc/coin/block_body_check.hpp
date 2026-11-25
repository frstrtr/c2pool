// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// btc::coin::block_body_matches_header -- a block body received from a coin
// peer belongs to its header (which the header chain holds, PoW-checked):
//   - at least one transaction, no two with the same txid (a duplicated
//     subtree leaves the merkle root unchanged);
//   - the txid merkle root equals the header's merkle root;
//   - BIP 141: if the coinbase has a witness commitment output (the last
//     output whose script starts 6a24aa21a9ed and is at least 38 bytes), the
//     coinbase input's witness is one 32-byte item and
//     SHA256d(witness merkle root || that item) equals the committed hash;
//     with no commitment, no transaction carries witness data.
// The standalone coin peer pool passes a body to the coin node only when this
// holds.

#include "block.hpp"
#include "mempool.hpp"           // compute_txid
#include "template_builder.hpp"  // compute_merkle_root, witness_merkle_root

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <cstring>
#include <set>
#include <span>
#include <vector>

namespace btc::coin {

inline constexpr size_t kWitnessCommitmentMinSize = 38;

/// Index of the BIP 141 witness commitment output in `coinbase`, or -1.
inline int witness_commitment_index(const MutableTransaction& coinbase)
{
    int idx = -1;
    for (size_t i = 0; i < coinbase.vout.size(); ++i) {
        const auto& spk = coinbase.vout[i].scriptPubKey.m_data;
        if (spk.size() >= kWitnessCommitmentMinSize && spk[0] == 0x6a && spk[1] == 0x24
            && spk[2] == 0xaa && spk[3] == 0x21 && spk[4] == 0xa9 && spk[5] == 0xed)
            idx = static_cast<int>(i);
    }
    return idx;
}

inline uint256 compute_wtxid(const MutableTransaction& tx)
{
    auto packed = pack(TX_WITH_WITNESS(tx));
    return Hash(packed.get_span());
}

inline bool block_body_matches_header(const BlockType& block)
{
    if (block.m_txs.empty())
        return false;
    std::vector<uint256> txids;
    txids.reserve(block.m_txs.size());
    std::set<uint256> unique;
    for (const auto& tx : block.m_txs) {
        txids.push_back(compute_txid(tx));
        if (!unique.insert(txids.back()).second)
            return false;
    }
    if (compute_merkle_root(txids) != block.m_merkle_root)
        return false;

    const auto& coinbase = block.m_txs.front();
    const int ci = witness_commitment_index(coinbase);
    if (ci < 0) {
        for (const auto& tx : block.m_txs)
            for (const auto& in : tx.vin)
                if (!in.scriptWitness.IsNull())
                    return false;
        return true;
    }
    if (coinbase.vin.empty())
        return false;
    const auto& stack = coinbase.vin.front().scriptWitness.stack;
    if (stack.size() != 1 || stack.front().size() != 32)
        return false;
    std::vector<uint256> others;
    others.reserve(block.m_txs.size() - 1);
    for (size_t i = 1; i < block.m_txs.size(); ++i)
        others.push_back(compute_wtxid(block.m_txs[i]));
    const uint256 root = witness_merkle_root(others);
    const uint256 commitment = Hash(std::span<const uint8_t>(root.data(), 32),
                                    std::span<const uint8_t>(stack.front().data(), 32));
    const auto& spk = coinbase.vout[static_cast<size_t>(ci)].scriptPubKey.m_data;
    return std::memcmp(spk.data() + 6, commitment.data(), 32) == 0;
}

} // namespace btc::coin
