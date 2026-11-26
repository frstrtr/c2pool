// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// bip110::coin::block_body_matches_header -- a block body received from a fork
// peer belongs to its header (which the header chain holds: BLAKE2b PoW at and
// after the fork, the v2 version / committed-height gate) and keeps the block
// rules of BIP-110. The coin peer pool connects a body, or passes it to the
// mempool, only when this holds:
//   - the checks c2pool-btc makes (btc::coin::basic_block_body_matches_header,
//     impl/btc/coin/basic_block_body_check.hpp): a coinbase first and only
//     there, no repeated txid, the txid merkle root, the BIP 141 witness
//     commitment or no witness data;
//   - a v2 header's committed transaction count (m_txcount, folded into the
//     header's PoW hash) equals the body's (the lane's own block template
//     commits 1 + N and refuses to serve a body / header skew,
//     stratum/work_source.cpp);
//   - RDTS: the block weight is at most RDTS_MAX_BLOCK_WEIGHT (800000 WU)
//     while the cap is active: for a v2 block whose parent's median time
//     past is before RDTS_EXPIRY_TIME (params.hpp; an unknown median time
//     counts as before, so the cap stays on).
// A body that is valid for Bitcoin but breaks one of these is never
// connected to the UTXO view and never reaches the mempool.

#include "block.hpp"
#include "mempool.hpp"           // compute_txid, compute_tx_weight
#include "template_builder.hpp"  // compute_merkle_root, witness_merkle_root
#include "transaction.hpp"
#include "../params.hpp"         // RDTS_MAX_BLOCK_WEIGHT, RDTS_EXPIRY_TIME

#include <impl/btc/coin/basic_block_body_check.hpp>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <vector>

namespace bip110::coin {

/// The BIP-110 hashes of btc::coin::basic_block_body_matches_header (txid and
/// wtxid as Bitcoin's).
struct Bip110BodyHashes {
    static uint256 txid(const MutableTransaction& tx) { return compute_txid(tx); }
    static uint256 wtxid(const MutableTransaction& tx)
    {
        auto packed = pack(TX_WITH_WITNESS(tx));
        return Hash(packed.get_span());
    }
    static uint256 merkle_root(const std::vector<uint256>& txids)
    {
        return compute_merkle_root(txids);
    }
    static uint256 witness_merkle_root(const std::vector<uint256>& other_wtxids)
    {
        return bip110::coin::witness_merkle_root(other_wtxids);
    }
};

/// BIP 141 weight of the whole block: 4 x (header + transaction count) plus
/// each transaction's weight (a v2 header is 164 bytes).
inline uint64_t block_weight(const BlockType& block)
{
    auto header = pack(static_cast<const BlockHeaderType&>(block));
    const uint64_t n = block.m_txs.size();
    const uint64_t count_size = n < 253 ? 1 : (n <= 0xffff ? 3 : (n <= 0xffffffffull ? 5 : 9));
    uint64_t weight = (static_cast<uint64_t>(header.size()) + count_size) * 4;
    for (const auto& tx : block.m_txs) {
        uint32_t base = 0, witness = 0, tx_weight = 0;
        compute_tx_weight(tx, base, witness, tx_weight);
        weight += tx_weight;
    }
    return weight;
}

/// A v2 header's committed transaction count matches the body (a v1 header
/// commits none).
inline bool txcount_matches(const BlockType& block)
{
    if (!block.is_v2())
        return true;
    return block.m_txs.size() <= 0xffff && block.m_txcount == block.m_txs.size();
}

/// Median time past for a block whose parent is `prev`: the median timestamp
/// of `prev` and up to 10 of its ancestors (Core GetMedianTimePast over 11
/// blocks), as far as `lookup` (std::optional<BlockHeaderType>(const uint256&))
/// holds them; nullopt if it does not hold `prev`.
template <typename Lookup>
inline std::optional<uint32_t> parent_median_time_past(const uint256& prev, const Lookup& lookup)
{
    std::vector<uint32_t> times;
    uint256 h = prev;
    for (int i = 0; i < 11; ++i) {
        const auto header = lookup(h);
        if (!header)
            break;
        times.push_back(header->m_timestamp);
        if (header->m_previous_block.IsNull())
            break;
        h = header->m_previous_block;
    }
    if (times.empty())
        return std::nullopt;
    std::sort(times.begin(), times.end());
    return times[times.size() / 2];
}

/// The RDTS weight cap applies to `header`'s block: a v2 block whose parent's
/// median time past is before RDTS_EXPIRY_TIME (unknown counts as before).
inline bool rdts_weight_cap_applies(const BlockHeaderType& header,
                                    std::optional<uint32_t> parent_mtp)
{
    return header.is_v2() && (!parent_mtp || *parent_mtp < bip110::RDTS_EXPIRY_TIME);
}

/// The body matches its header and keeps the BIP-110 block rules;
/// rdts_weight_cap: rdts_weight_cap_applies() for this block.
inline bool block_body_matches_header(const BlockType& block, bool rdts_weight_cap)
{
    if (!btc::coin::basic_block_body_matches_header<Bip110BodyHashes>(block))
        return false;
    if (!txcount_matches(block))
        return false;
    if (rdts_weight_cap && block_weight(block) > bip110::RDTS_MAX_BLOCK_WEIGHT)
        return false;
    return true;
}

} // namespace bip110::coin
