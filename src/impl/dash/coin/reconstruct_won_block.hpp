// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// dash::coin::reconstruct_won_block -- turn a VERIFIED won share into the full
// serialized DASH parent block, ready for broadcast_won_block's dual path.
//
// This is the DASH analogue of dgb::coin::reconstruct_won_block
// (src/impl/dgb/coin/reconstruct_won_block.hpp) and the C++ of p2pool-dash
// data.py Share.as_block(tracker, known_txs):
//
//     gentx     = self.check(tracker, known_txs)                 # coinbase tx
//     other_txs = [known_txs[h]
//                  for h in self.get_other_tx_hashes(tracker)]   # ref-walk
//     return dict(header=self.header, txs=[gentx]+other_txs)
//
// THE DASH-SPECIFIC BIT -- the coinbase is a DIP3/DIP4 special CbTx (version|type
// = 3|(5<<16), extra_payload appended). We do NOT re-implement that assembly:
// generate_share_transaction (share_check.hpp) ALREADY regenerates the exact
// coinbase the share committed to (it is the accept-path payout-commitment
// keystone, KAT-proven by test_dash_payout_commitment / test_dash_share_producer),
// and now exposes the coinbase BYTES + txid via its out_gentx param. We reuse
// that ONE byte path. So the reconstructed coinbase is, by construction, the
// very coinbase whose txid equals the gentx_hash the share's hash_link committed
// to -- the same value share_init_verify folded into the block's merkle_root.
//
// FAIL-LOUD (reward-safety, mirrors p2pool "GOT INCOMPLETE BLOCK" + dgb "NOT
// broadcast"): every unrecoverable condition returns std::nullopt so the caller
// broadcasts NOTHING -- never a partial/malformed block:
//   * the winning share's parent is not yet in-chain (no PPLNS window to rebuild
//     the coinbase from) -> nullopt;
//   * generate_share_transaction throws / yields empty coinbase bytes -> nullopt;
//   * the share references other (non-coinbase) txs whose bodies are not in the
//     known-tx set -> nullopt (an incomplete block would hash to the committed
//     merkle_root's tree but omit a body -> daemon-rejected; never emit it).
// A partial/wrong reconstruction hashes to the wrong merkle_root and is rejected
// by every peer/daemon, so failing loudly here is strictly safer than emitting.
//
// COINBASE-ONLY is the DAEMONLESS NORM (transactions==[]): the share carries no
// transaction_hash_refs, other_tx_hashes is empty, the block is [gentx] alone,
// and merkle_root == gentx_txid (an empty merkle_link is identity). That is the
// path this reconstructor takes today; the ref-walk + known-tx bodies fill in
// automatically as embedded mempool tx-selection lands, with no change here.
//
// Reward/consensus-NEUTRAL: it READS already-validated share_info + the on-chain
// PPLNS window (the SAME reads the accept path already did under the same tracker
// lock) and already-relayed tx bodies; it WRITES no consensus, PPLNS, payout, or
// target state. Per-coin isolation: src/impl/dash/ only.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <core/hash.hpp>
#include <core/log.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>   // HexStr

#include "gentx_coinbase.hpp"
#include "won_block_dispatch.hpp"       // dash::coin::ReconstructedWonBlock
#include "../share.hpp"
#include "../share_check.hpp"            // generate_share_transaction, check_merkle_link

namespace dash
{
namespace coin
{

// Look up a known non-coinbase tx BODY (non-witness bytes) by txid, or nullptr
// if absent. The run-loop binds this to the node's remember_tx / m_known_txs
// cache; an empty function means "no known-tx source" -> any share that
// references other txs fails loud (coinbase-only still reconstructs).
using KnownTxLookup =
    std::function<const std::vector<unsigned char>*(const uint256&)>;

// ── resolve_other_tx_hashes (DASH) ──────────────────────────────────────────
// Resolve a share's transaction_hash_refs to the ordered other_tx hash list,
// the DASH port of dgb::coin::resolve_other_tx_hashes. DASH stores refs FLAT as
// [share_count, tx_count] pairs (share.hpp: std::vector<uint64_t>), so we walk
// them two-at-a-time. Throws std::out_of_range on a ref that walks off the known
// sharechain or indexes past an ancestor's new_transaction_hashes -- both are
// malformed-share conditions the caller turns into a fail-loud nullopt.
//
//   nth_parent_fn    : (start, n) -> hash of the n-th parent (n==0 -> start),
//                      IsNull() when the walk runs off the known sharechain
//   new_tx_hashes_fn : share_hash -> that share's new_transaction_hashes (copy)
inline std::vector<uint256>
resolve_other_tx_hashes(
    const uint256& won_share_hash,
    const std::vector<uint64_t>& refs,
    const std::function<uint256(const uint256&, uint64_t)>& nth_parent_fn,
    const std::function<std::vector<uint256>(const uint256&)>& new_tx_hashes_fn)
{
    std::vector<uint256> out;
    out.reserve(refs.size() / 2);

    for (std::size_t i = 0; i + 1 < refs.size(); i += 2)
    {
        const uint64_t share_count = refs[i];
        const uint64_t tx_count    = refs[i + 1];

        const uint256 ancestor = nth_parent_fn(won_share_hash, share_count);
        if (ancestor.IsNull())
            throw std::out_of_range(
                "dash resolve_other_tx_hashes: transaction_hash_ref share_count "
                "walks past the known sharechain");

        const std::vector<uint256> nths = new_tx_hashes_fn(ancestor);
        if (tx_count >= nths.size())
            throw std::out_of_range(
                "dash resolve_other_tx_hashes: transaction_hash_ref tx_count "
                "out of range for ancestor new_transaction_hashes");

        out.push_back(nths[tx_count]);
    }

    return out;
}

// ── frame_won_block (pure) ──────────────────────────────────────────────────
// Frame the final block bytes from its parts. Pure + injectable (no tracker):
//   header = version|prev|merkle_root|time|bits|nonce   (80 bytes, DASH block)
//   merkle_root = check_merkle_link(gentx.txid, merkle_link)   (== gentx.txid
//                 for an empty coinbase-only link)
//   body   = varint(1 + other.size()) ++ gentx.bytes ++ other_tx_bodies...
// The header build MIRRORS share_check.hpp share_init_verify byte-for-byte, so
// X11(header) of the reconstructed block equals the share hash the tracker fired
// on -- i.e. the reconstructed block IS the block the winning share solved.
inline ReconstructedWonBlock
frame_won_block(const bitcoin_family::coin::SmallBlockHeaderType& min_header,
                const MerkleLink& merkle_link,
                const GentxCoinbase& gentx,
                const std::vector<std::vector<unsigned char>>& other_tx_bodies)
{
    const uint256 merkle_root = check_merkle_link(gentx.txid, merkle_link);

    // 80-byte block header (identical field order to share_init_verify).
    PackStream header;
    {
        uint32_t hdr_version = static_cast<uint32_t>(min_header.m_version);
        header << hdr_version;
    }
    header << min_header.m_previous_block;
    header << merkle_root;
    header << min_header.m_timestamp;
    header << min_header.m_bits;
    header << min_header.m_nonce;

    std::vector<unsigned char> block(
        reinterpret_cast<const unsigned char*>(header.data()),
        reinterpret_cast<const unsigned char*>(header.data()) + header.size());

    // tx count (CompactSize) then [gentx] ++ other bodies.
    const std::size_t n_txs = 1 + other_tx_bodies.size();
    if (n_txs < 253) {
        block.push_back(static_cast<unsigned char>(n_txs));
    } else {
        block.push_back(0xfd);
        block.push_back(static_cast<unsigned char>(n_txs & 0xff));
        block.push_back(static_cast<unsigned char>((n_txs >> 8) & 0xff));
    }

    block.insert(block.end(), gentx.bytes.begin(), gentx.bytes.end());
    for (const auto& body : other_tx_bodies)
        block.insert(block.end(), body.begin(), body.end());

    ReconstructedWonBlock out;
    out.hex = HexStr(block);
    out.bytes = std::move(block);
    return out;
}

// ── reconstruct_won_block (tracker-bound) ───────────────────────────────────
// Full reconstruction for the run-loop. MUST be called on the compute thread
// with the tracker lock held (the m_on_block_found contract): it reads the
// on-chain PPLNS window via generate_share_transaction and walks the sharechain
// via tracker.chain -- exactly the reads the accept path already performed under
// this same lock. Returns std::nullopt (never throws) on any unrecoverable
// condition so the caller broadcasts NOTHING.
template <typename TrackerT>
inline std::optional<ReconstructedWonBlock>
reconstruct_won_block(const uint256& share_hash,
                      const DashShare& share,
                      TrackerT& tracker,
                      const core::CoinParams& params,
                      const KnownTxLookup& known_txs = {})
{
    // Guard: the coinbase recompute needs the parent's PPLNS window in-chain.
    if (share.m_prev_hash.IsNull() || !tracker.chain.contains(share.m_prev_hash)) {
        LOG_WARNING << "[EMB-DASH] won-block " << share_hash.GetHex().substr(0, 16)
                    << " parent not in-chain -- cannot rebuild coinbase; NOT broadcast.";
        return std::nullopt;
    }

    // 1. Regenerate the DIP3/DIP4 coinbase (bytes + txid) via the SSOT accept
    //    path. Any throw -> fail loud.
    GentxCoinbase gentx;
    try {
        (void)generate_share_transaction(share, tracker, params, &gentx);
    } catch (const std::exception& e) {
        LOG_WARNING << "[EMB-DASH] won-block " << share_hash.GetHex().substr(0, 16)
                    << " coinbase regen threw (" << e.what() << ") -- NOT broadcast.";
        return std::nullopt;
    }
    if (gentx.bytes.empty()) {
        LOG_WARNING << "[EMB-DASH] won-block " << share_hash.GetHex().substr(0, 16)
                    << " coinbase regen empty -- NOT broadcast.";
        return std::nullopt;
    }

    // 2. Resolve any other (non-coinbase) tx bodies. Empty for the coinbase-only
    //    daemonless norm. Missing body / malformed ref -> fail loud.
    std::vector<std::vector<unsigned char>> other_bodies;
    try {
        const std::vector<uint256> other_hashes = resolve_other_tx_hashes(
            share_hash, share.m_transaction_hash_refs,
            [&tracker](const uint256& h, uint64_t n) {
                return tracker.chain.get_nth_parent_via_skip(h, n);
            },
            [&tracker](const uint256& h) {
                std::vector<uint256> nths;
                tracker.chain.get_share(h).invoke([&](auto* obj) {
                    if (obj) nths = obj->m_new_transaction_hashes;
                });
                return nths;
            });

        other_bodies.reserve(other_hashes.size());
        for (const auto& h : other_hashes) {
            const std::vector<unsigned char>* body = known_txs ? known_txs(h) : nullptr;
            if (!body) {
                LOG_WARNING << "[EMB-DASH] won-block " << share_hash.GetHex().substr(0, 16)
                            << " references unknown tx " << h.GetHex().substr(0, 16)
                            << " -- INCOMPLETE, NOT broadcast.";
                return std::nullopt;
            }
            other_bodies.push_back(*body);
        }
    } catch (const std::exception& e) {
        LOG_WARNING << "[EMB-DASH] won-block " << share_hash.GetHex().substr(0, 16)
                    << " other-tx resolve threw (" << e.what() << ") -- NOT broadcast.";
        return std::nullopt;
    }

    // 3. Frame [gentx] ++ other bodies under the share's committed header.
    return frame_won_block(share.m_min_header, share.m_merkle_link, gentx, other_bodies);
}

} // namespace coin
} // namespace dash
