// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Embedded LTC: feed blocks to the UTXO set strictly in height order.
///
/// The UTXO cache has no continuity check (connect_block takes whatever it is
/// given) and a warm restart resumes at best_height + 1, so a block connected
/// over a missing parent leaves a permanent gap. With compact blocks that is
/// an everyday race: block N needs a getblocktxn round trip, N+1 reconstructs
/// from the mempool at once and would be connected over N-1, and N's late
/// completion would then be "old".
///
/// The rule: a block is connected only when it is best_height + 1. A block
/// further ahead arms the ordered pipeline (core::coin::BlockBootstrapState,
/// the same buffer the cold-start bootstrap uses) for best_height + 1 .. its
/// height: it is buffered, the missing heights are requested, and blocks are
/// drained in order as they arrive. The full-block handler in main_ltc.cpp
/// calls these helpers; the KAT drives the same helpers in the same order.

#include <core/coin/block_bootstrapper.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <utility>

namespace ltc {
namespace coin {

/// What the full-block handler does with a block at `height` when the UTXO
/// set is at `utxo_best` and no ordered fill is running.
enum class UtxoConnect {
    Connect,  // height == utxo_best + 1: connect now
    Gap,      // height >  utxo_best + 1: buffer it, fetch the missing heights
    Skip,     // height <= utxo_best (or unknown): already connected / old
};

inline UtxoConnect utxo_connect_action(uint32_t utxo_best, uint32_t height)
{
    if (height == 0 || height <= utxo_best)
        return UtxoConnect::Skip;
    if (height == utxo_best + 1)
        return UtxoConnect::Connect;
    return UtxoConnect::Gap;
}

/// Arm the ordered pipeline for heights [from, to] (from = utxo_best + 1).
/// Nothing is buffered yet; the caller buffers the block it holds and
/// requests the window (ordered_refill).
template <typename BlockT>
void ordered_arm(core::coin::BlockBootstrapState<BlockT>& bs, uint32_t from, uint32_t to)
{
    bs.active = true;
    bs.next_height = from;
    bs.end_height = to;
    bs.next_request = from;
    bs.processed = 0;
    bs.total = to >= from ? to - from + 1 : 0;
    bs.buffer.clear();
    bs.last_drain_time = std::chrono::steady_clock::now();
}

/// Buffer a block for the running pipeline. A block past end_height extends
/// the range (a new block mined meanwhile). Blocks below next_height are
/// ignored (already drained). The first copy for a height wins.
template <typename BlockT>
void ordered_buffer(core::coin::BlockBootstrapState<BlockT>& bs, uint32_t height,
                    const BlockT& block, const uint256& hash)
{
    if (height < bs.next_height)
        return;
    if (height > bs.end_height) {
        bs.end_height = height;
        bs.total = bs.processed + (bs.end_height - bs.next_height + 1);
    }
    bs.buffer.try_emplace(height, std::make_pair(block, hash));
}

/// Why a block may (not) be connected to the UTXO set now.
enum class ConnectCheck {
    Ok,
    NotNext,         // not utxo_best + 1: connecting it would leave a gap
    NotBestChain,    // not the best chain's block at its height
    ParentMismatch,  // its parent is not the UTXO set's best block
};

inline const char* connect_check_name(ConnectCheck c)
{
    switch (c) {
    case ConnectCheck::Ok:             return "ok";
    case ConnectCheck::NotNext:        return "not-next-height";
    case ConnectCheck::NotBestChain:   return "not-best-chain";
    case ConnectCheck::ParentMismatch: return "parent-is-not-utxo-best";
    }
    return "unknown";
}

/// The check at every UTXO connect point: block `hash` (parent `prev`) at
/// `height` is the UTXO set's next height, the best chain's block there
/// (`best_chain_hash`: the header chain's hash at `height`), and builds on
/// the UTXO set's best block. An empty UTXO set (null best block) starts at
/// any height of the best chain (the cold-start bootstrap).
inline ConnectCheck utxo_connect_check(uint32_t utxo_best, const uint256& utxo_best_block,
                                       uint32_t height, const uint256& hash,
                                       const uint256& prev, const uint256& best_chain_hash)
{
    if (best_chain_hash.IsNull() || best_chain_hash != hash)
        return ConnectCheck::NotBestChain;
    if (utxo_best_block.IsNull())
        return ConnectCheck::Ok;
    if (height != utxo_best + 1)
        return ConnectCheck::NotNext;
    if (prev != utxo_best_block)
        return ConnectCheck::ParentMismatch;
    return ConnectCheck::Ok;
}

struct DrainResult {
    uint32_t     connected{0};
    ConnectCheck refused{ConnectCheck::Ok};  // Ok = nothing refused
    uint32_t     refused_height{0};
};

/// Drain consecutive buffered blocks from next_height in order. Each block
/// goes through check(block, hash, height) -> ConnectCheck first; Ok ->
/// connect(block, hash, height). The first refused block is dropped and the
/// drain stops (the caller recovers, see ordered_recover).
template <typename BlockT, typename CheckFn, typename ConnectFn>
DrainResult ordered_drain(core::coin::BlockBootstrapState<BlockT>& bs, CheckFn&& check,
                          ConnectFn&& connect)
{
    DrainResult r;
    while (bs.buffer.count(bs.next_height)) {
        auto node = bs.buffer.extract(bs.next_height);
        auto& [b, bh] = node.mapped();
        const uint32_t h = bs.next_height;
        const ConnectCheck c = check(b, bh, h);
        if (c != ConnectCheck::Ok) {
            r.refused = c;
            r.refused_height = h;
            return r;
        }
        connect(b, bh, h);
        ++bs.next_height;
        ++bs.processed;
        bs.last_drain_time = std::chrono::steady_clock::now();
        ++r.connected;
    }
    return r;
}

/// After a refused block: restart the pipeline at the UTXO set's real next
/// height (stale buffer dropped) up to at least `to`. A parent mismatch
/// means the UTXO set itself is on another branch, which refetching cannot
/// fix (the reorg handler has to disconnect it): the pipeline stops.
/// Returns true when the pipeline was re-armed (the caller refills).
template <typename BlockT>
bool ordered_recover(core::coin::BlockBootstrapState<BlockT>& bs, ConnectCheck why,
                     uint32_t utxo_best, uint32_t to)
{
    if (why == ConnectCheck::ParentMismatch || to <= utxo_best) {
        bs.active = false;
        bs.buffer.clear();
        return false;
    }
    const std::string phase = bs.phase;
    ordered_arm(bs, utxo_best + 1, std::max(to, bs.end_height));
    bs.phase = phase;
    return true;
}

/// Reorg: whatever the pipeline was doing, restart it from the UTXO set's
/// real best (after the disconnect) to the new tip. Its buffer may hold
/// blocks of the old branch and its next height may be above the fork.
/// Returns true when armed (the caller refills).
template <typename BlockT>
bool ordered_rearm_after_reorg(core::coin::BlockBootstrapState<BlockT>& bs, uint32_t utxo_best,
                               uint32_t new_height)
{
    if (new_height <= utxo_best)
        return false;
    ordered_arm(bs, utxo_best + 1, new_height);
    return true;
}

/// Keep up to WINDOW_SIZE requests in flight: request(height) for every
/// height not yet requested and not buffered. Returns how many were asked.
template <typename BlockT, typename RequestFn>
uint32_t ordered_refill(core::coin::BlockBootstrapState<BlockT>& bs, RequestFn&& request)
{
    uint32_t n = 0;
    while (bs.next_request <= bs.end_height
           && (bs.next_request - bs.next_height) < bs.WINDOW_SIZE) {
        if (!bs.buffer.count(bs.next_request)) {
            request(bs.next_request);
            ++n;
        }
        ++bs.next_request;
    }
    return n;
}

/// The pipeline has drained its whole range.
template <typename BlockT>
bool ordered_done(const core::coin::BlockBootstrapState<BlockT>& bs)
{
    return bs.next_height > bs.end_height;
}

/// A tip change is a reorg when the new tip does not descend from the old
/// one. `new_ancestor_at(h)` returns the hash of the new chain's block at
/// height h (null if unknown).
template <typename AncestorFn>
bool tip_change_is_reorg(const uint256& old_tip, uint32_t old_height, uint32_t new_height,
                         AncestorFn&& new_ancestor_at)
{
    if (old_tip.IsNull())
        return false;
    if (new_height <= old_height)
        return true;
    return new_ancestor_at(old_height) != old_tip;
}

} // namespace coin
} // namespace ltc
