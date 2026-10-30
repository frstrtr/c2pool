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
#include <core/coin/utxo.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
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

/// Keep up to bs.window requests in flight: request(height) for every
/// height not yet requested and not buffered. Returns how many were asked.
template <typename BlockT, typename RequestFn>
uint32_t ordered_refill(core::coin::BlockBootstrapState<BlockT>& bs, RequestFn&& request)
{
    uint32_t n = 0;
    while (bs.next_request <= bs.end_height
           && (bs.next_request - bs.next_height) < bs.window) {
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

/// Extend the running pipeline's range to `height` without buffering a block
/// (a new tip, or a block ahead of the window: asked in order later).
template <typename BlockT>
void ordered_extend(core::coin::BlockBootstrapState<BlockT>& bs, uint32_t height)
{
    if (height > bs.end_height) {
        bs.end_height = height;
        bs.total = bs.processed + (bs.end_height - bs.next_height + 1);
    }
}

/// Buffer a best-chain body for a fill whose download bounds what it keeps
/// (core::coin::BlockDownload::keep: its window, its byte bound): kept and
/// counted, or only the range extended (the height is asked in order when
/// the window gets there). Returns true when kept. Before, the accrual
/// set's fill buffered every body at or above its next height (FRESH-NODE
/// 3: the accrual buffer had no bound).
template <typename BlockT, typename Download>
bool ordered_buffer_bounded(core::coin::BlockBootstrapState<BlockT>& bs, Download& dl, uint32_t height,
                            const BlockT& block, const uint256& hash, size_t bytes)
{
    if (!dl.keep(bs, height, bytes)) {
        ordered_extend(bs, height);
        return false;
    }
    const bool fresh = height >= bs.next_height && !bs.buffer.count(height);
    ordered_buffer(bs, height, block, hash);
    if (fresh && bs.buffer.count(height))
        dl.buffered(height, bytes);
    return true;
}

/// How a fill's heights are asked for.
enum class FillAsk {
    Download,  // the cold start ("Bootstrap"): one peer per height, core::coin::BlockDownload
    Targeted,  // gap / reorg / rebuild fills: one peer round robin
};

inline FillAsk fill_ask(const std::string& phase)
{
    return phase == "Bootstrap" ? FillAsk::Download : FillAsk::Targeted;
}

/// The cold-start Bootstrap of a partial UTXO view (the embedded LTC set,
/// the DOGE accrual set): when it starts and over which heights.
///   - only once the header chain is synced (tip age < 24 h). Before, the
///     first block above `keep` armed it at whatever tip the header chain
///     had then, on a fresh node the checkpoint-era one, and every
///     best-chain block extended it to the real tip (FRESH-NODE 2.2: LTC
///     289 -> 114,549 blocks; 2.3: DOGE 1,441 -> 276,000) while templates
///     waited for it to reach the tip;
///   - over the synced tip's last `blocks` heights, or from the set's best
///     + 1 when that is within them (a warm restart catches up); a set at
///     most one block behind needs none (the normal path takes the tip);
///   - a fill that falls more than `blocks` + its window behind the tip is
///     armed again at the tip (cold_start_rearm).
struct ColdStart {
    enum class Action {
        Wait,  // not yet (header chain not synced): no fill, the set takes no block
        Warm,  // the set is at most one block behind the tip: no fill
        Arm,   // fetch [from, to] in order
    };
    Action   action{Action::Wait};
    uint32_t from{0};
    uint32_t to{0};
    uint32_t jump_from{0};  // the deliberate jump over a non-empty set too far behind (0 = none)
};

inline ColdStart cold_start_plan(uint32_t blocks, bool synced, uint32_t tip, uint32_t utxo_best)
{
    ColdStart p;
    if (!synced || blocks == 0 || tip == 0)
        return p;
    if (utxo_best + 1 >= tip) {
        p.action = ColdStart::Action::Warm;
        return p;
    }
    const uint32_t lo = tip >= blocks ? tip - blocks + 1 : 1;
    p.action = ColdStart::Action::Arm;
    p.from = (utxo_best > 0 && utxo_best + 1 >= lo) ? utxo_best + 1 : lo;
    p.to = tip;
    p.jump_from = (utxo_best > 0 && p.from > utxo_best + 1) ? p.from : 0;
    return p;
}

/// A running Bootstrap whose next height is more than `blocks` + its window
/// below the tip (it downloads slower than blocks are found, or the node
/// was away): the range to arm it again, the tip's last `blocks` heights.
/// The caller wipes the partial set first (the new range does not continue
/// it). nullopt: keep going.
template <typename BlockT>
std::optional<std::pair<uint32_t, uint32_t>> cold_start_rearm(
    const core::coin::BlockBootstrapState<BlockT>& bs, uint32_t tip, uint32_t blocks)
{
    if (!bs.active || blocks == 0 || tip < bs.next_height)
        return std::nullopt;
    if (uint64_t(tip) - bs.next_height <= uint64_t(blocks) + bs.window)
        return std::nullopt;
    return std::make_pair(tip >= blocks ? tip - blocks + 1 : 1u, tip);
}

/// Who is asked for a new tip's body (the DOGE tip-change handler).
enum class TipBodyAsk {
    None,       // the initial header sync, or the cold start runs: nobody
    Announcer,  // the peer whose headers brought the tip
    OnePeer,    // the announcer is gone: one peer, round robin
    EveryPeer,  // no peer could be asked one at a time
};

/// Nothing during the initial header sync (no body is of use before the
/// cold start, which waits for the synced chain) nor while the cold start
/// runs (its download takes the tip in order); else the announcer, else one
/// peer, else every peer. from(peer) / one() return whether the request was
/// sent. Before, every peer was asked for every new tip, sync or not
/// (FRESH-NODE 2.3: 2-5 copies of each tip body).
template <typename FromFn, typename OneFn, typename AllFn>
TipBodyAsk ask_tip_body(bool chain_synced, bool cold_start_runs, const std::string& announcer,
                        FromFn&& from, OneFn&& one, AllFn&& all)
{
    if (!chain_synced || cold_start_runs)
        return TipBodyAsk::None;
    if (!announcer.empty() && from(announcer))
        return TipBodyAsk::Announcer;
    if (one())
        return TipBodyAsk::OnePeer;
    all();
    return TipBodyAsk::EveryPeer;
}

/// Result of walking the UTXO set back to the best chain.
struct RewindResult {
    /// Why the walk stopped short of the best chain.
    enum class Why {
        None,           // it did not: the set's best is on the best chain
        NoUndo,         // no undo record at a height the walk has to disconnect
        Legacy,         // a legacy (pre-#2059) record: its spent coins cannot be put back
        TooDeep,        // more than max_depth blocks to disconnect
        CannotJudge,    // the header chain has no block at a height (a hole in
                        // its index), or above its tip no parent for the set's block
        BlockMismatch,  // the record at a height belongs to another block
        BlockUnknown,   // the header chain has another block at a height and no
                        // longer knows the set's block there (no parent to step to)
    };
    bool     ok{true};          // false: see why
    Why      why{Why::None};
    uint32_t disconnected{0};
    uint32_t height{0};         // the UTXO set's best after the walk
    uint256  hash;              // ... and its block hash (flush to this)

    /// No amount of waiting brings the set back (the record is gone, cannot
    /// restore, belongs to another block, or the fork is too deep): only a
    /// rebuild does. CannotJudge is transient: the header index is being
    /// rebuilt.
    bool permanent() const { return !ok && why != Why::CannotJudge; }
};

inline const char* rewind_why_name(RewindResult::Why w)
{
    using Why = RewindResult::Why;
    switch (w) {
    case Why::None:          return "none";
    case Why::NoUndo:        return "undo record missing";
    case Why::Legacy:        return "legacy undo record";
    case Why::TooDeep:       return "deeper than the undo window";
    case Why::CannotJudge:   return "a height the header chain cannot judge";
    case Why::BlockMismatch: return "undo record of another block";
    case Why::BlockUnknown:  return "the header chain no longer knows the UTXO set's block";
    }
    return "unknown";
}

/// Walk the UTXO set's best back, one height at a time, until its block is
/// the best chain's block at that height (`chain_hash_at(h)`). Above
/// `chain_height` (the header chain's tip) no block is on the best chain, so
/// those are disconnected without asking (a reorg onto a shorter, heavier
/// chain). At or below it a null answer means the header chain cannot judge
/// that height: the walk fails instead of calling the UTXO set good.
/// `prev_of(hash)` gives a block's parent (std::optional; nullopt = unknown):
/// unknown at a height the chain judged (it has another block there) means
/// the header DB has lost the set's block, which no wait brings back
/// (BlockUnknown); above the tip it stays CannotJudge.
/// `disconnect(h, hash)` undoes the UTXO set's block `hash` at height h and
/// returns Why::None, or why the record at h cannot bring the set back
/// (disconnect_with_undo below). At most `max_depth` blocks are disconnected.
/// The caller flushes to (height, hash) when anything was disconnected, then
/// re-arms the fill. An empty UTXO set (null best block) is left alone.
template <typename ChainHashAtFn, typename PrevOfFn, typename DisconnectFn>
RewindResult rewind_to_best_chain(uint32_t max_depth, uint32_t chain_height, uint32_t utxo_best,
                                  const uint256& utxo_best_block,
                                  ChainHashAtFn&& chain_hash_at, PrevOfFn&& prev_of,
                                  DisconnectFn&& disconnect)
{
    using Why = RewindResult::Why;
    RewindResult r;
    r.height = utxo_best;
    r.hash = utxo_best_block;
    if (utxo_best_block.IsNull())
        return r;
    auto fail = [&r](Why why) {
        r.ok = false;
        r.why = why;
        return r;
    };
    while (r.height > 0) {
        const bool judged = r.height <= chain_height;
        if (judged) {
            const uint256 at = chain_hash_at(r.height);
            if (at == r.hash)
                break;
            if (at.IsNull())
                return fail(Why::CannotJudge);
        }
        if (r.disconnected >= max_depth)
            return fail(Why::TooDeep);
        const auto prev = prev_of(r.hash);
        if (!prev)
            return fail(judged ? Why::BlockUnknown : Why::CannotJudge);
        const Why w = disconnect(r.height, r.hash);
        if (w != Why::None)
            return fail(w);
        r.hash = *prev;
        --r.height;
        ++r.disconnected;
    }
    return r;
}

/// The walk's disconnect step over a UTXO DB's undo records (main_ltc's heal):
/// the record at h must exist, belong to the block being undone (`hash`; Core
/// binds a record to its block with a checksum over pprev's hash,
/// validation.cpp:1676-1678, 1872 — a record without a hash is unbound) and be
/// able to put its spent coins back; then the block is disconnected. A record
/// that cannot bring the set back touches nothing (the caller logs the reason
/// with the height, once).
template <typename UndoDbT, typename UtxoT>
RewindResult::Why disconnect_with_undo(UndoDbT& db, UtxoT& utxo, uint32_t h, const uint256& hash)
{
    using Why = RewindResult::Why;
    core::coin::BlockUndo undo;
    if (!db.get_block_undo(h, undo))
        return Why::NoUndo;
    if (!undo.block_hash.IsNull() && undo.block_hash != hash)
        return Why::BlockMismatch;
    if (!undo.restorable())
        return Why::Legacy;
    if (!utxo.disconnect_from_undo(undo))
        return Why::Legacy;
    return Why::None;
}

/// First height of a rebuild from an empty UTXO set: the last `keep` blocks
/// below the tip, as the cold-start bootstrap takes them.
inline uint32_t utxo_rebuild_from(uint32_t tip, uint32_t keep)
{
    return tip > keep ? tip - keep : 1;
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
