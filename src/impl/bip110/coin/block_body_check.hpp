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
// connected to the UTXO view and never reaches the mempool. block_body_rule
// names the rule a body breaks; BodyRuleAlarm decides when bodies from two or
// more peers that break only a BIP-110 rule (they pass every c2pool-btc check)
// are worth an ERROR: a rule of ours that the fork network may not share.

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
#include <chrono>
#include <cstdint>
#include <deque>
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
///
/// The time of a block is its m_timestamp (nTime), not m_timestamp +
/// m_time_offset: nTime is the field committed in the header's h1 hash the
/// way Bitcoin's is, and the one the header chain's retarget reads
/// (header_chain.hpp); m_time_offset is miner work space folded only into the
/// last BLAKE2b stage (pow.hpp; the stratum work shape rolls it, R3), and no
/// source the lane holds adds it to the block time. The two differ only for a
/// block whose miner rolled m_time_offset, and the RDTS expiry this feeds is
/// 2027-09-01: confirm against the Knots source before then.
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

/// The rule a body breaks, the c2pool-btc checks first.
enum class BodyRule {
    Ok,         // matches its header, keeps the BIP-110 rules
    Header,     // a c2pool-btc check (merkle root, coinbase, txids, BIP 141)
    TxCount,    // the v2 header's committed transaction count
    Weight,     // the RDTS weight cap
};

inline const char* body_rule_name(BodyRule r)
{
    switch (r) {
    case BodyRule::Ok:      return "ok";
    case BodyRule::Header:  return "body / header match";
    case BodyRule::TxCount: return "committed transaction count";
    case BodyRule::Weight:  return "RDTS weight cap";
    }
    return "?";
}

/// rdts_weight_cap: rdts_weight_cap_applies() for this block.
inline BodyRule block_body_rule(const BlockType& block, bool rdts_weight_cap)
{
    if (!btc::coin::basic_block_body_matches_header<Bip110BodyHashes>(block))
        return BodyRule::Header;
    if (!txcount_matches(block))
        return BodyRule::TxCount;
    if (rdts_weight_cap && block_weight(block) > bip110::RDTS_MAX_BLOCK_WEIGHT)
        return BodyRule::Weight;
    return BodyRule::Ok;
}

/// The body matches its header and keeps the BIP-110 block rules;
/// rdts_weight_cap: rdts_weight_cap_applies() for this block.
inline bool block_body_matches_header(const BlockType& block, bool rdts_weight_cap)
{
    return block_body_rule(block, rdts_weight_cap) == BodyRule::Ok;
}

/// When to log an ERROR for a block whose bodies fail only a BIP-110 rule
/// (TxCount or Weight): bad_peers (distinct peers that sent a failing body,
/// the coin peer pool's on_bad_body count) is 2 or more, the block was not
/// logged yet (the last kRemembered blocks), and kEverySec passed since the
/// last such ERROR. IO thread only.
class BodyRuleAlarm {
public:
    using Clock = std::chrono::steady_clock;
    static constexpr int64_t kEverySec    = 600;
    static constexpr size_t  kRemembered  = 64;

    bool should_log(const uint256& block, BodyRule rule, size_t bad_peers, Clock::time_point now)
    {
        if (bad_peers < 2 || (rule != BodyRule::TxCount && rule != BodyRule::Weight))
            return false;
        if (std::find(m_logged.begin(), m_logged.end(), block) != m_logged.end())
            return false;
        if (m_last != Clock::time_point{}
            && std::chrono::duration_cast<std::chrono::seconds>(now - m_last).count() < kEverySec)
            return false;
        m_last = now;
        m_logged.push_back(block);
        if (m_logged.size() > kRemembered)
            m_logged.pop_front();
        return true;
    }

private:
    Clock::time_point   m_last{};
    std::deque<uint256> m_logged;
};

} // namespace bip110::coin
