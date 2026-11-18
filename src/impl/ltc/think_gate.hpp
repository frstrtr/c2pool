// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ============================================================================
// think_gate.hpp — the LTC think-slot protocol (port of DASH #854,
// src/impl/dash/think_gate.hpp).
//
// The LTC node runs one think()/clean cycle at a time: the compute pool has a
// single thread, the cycle holds m_tracker_mutex exclusively, and a `running`
// flag (m_think_running) is set when a cycle is dispatched and cleared by its
// IO-phase epilogue.
//
// A run_think() that finds the flag set used to be DROPPED. The flag is still
// set after the compute thread has released the tracker lock, until the
// epilogue runs on the io thread, so a local mint (notify_local_share ->
// run_think) or a peer batch landing in that window was in the chain but
// never elected: no best-share change, no work refresh, miners kept the old
// prev_share_hash until some later trigger. Now a request that loses the race
// is remembered (`rethink_pending`) and the cycle that owns the slot posts one
// run_think() when it releases.
//
// THREADING. Unlike DASH, LTC run_think() is not io-thread-confined: the
// stratum submit path reaches notify_local_share() from the HTTP JSON-RPC
// thread too. acquire_think_slot() is therefore written for any thread (see
// its note); release happens on the io thread (the epilogues).
//
// Consensus-neutral: this decides only WHEN an election re-runs and when
// miners are told. No share bytes, PPLNS weight or block-submit path.
// ============================================================================

#include <core/uint256.hpp>

#include <atomic>

namespace ltc::think {

/// Take the think slot for a run_think() cycle. True: the caller owns the
/// cycle and must release it. False: a cycle is in flight and the request is
/// recorded; the owner posts one run_think() when it releases.
///
/// Any thread. The owner releases with running=false THEN pending.exchange.
/// A requester that set `pending` after that exchange, and then sees the
/// slot free, takes its request back and retries the slot; if the request
/// is already gone, whoever consumed it serves it (an owner posts a think, a
/// requester retries the slot itself). So a request is never left with no
/// cycle to serve it. All operations are sequentially consistent.
inline bool acquire_think_slot(std::atomic<bool>& running,
                               std::atomic<bool>& rethink_pending)
{
    while (running.exchange(true)) {
        rethink_pending.store(true);
        if (running.load())
            return false;                       // the owner will see it on release
        if (!rethink_pending.exchange(false))
            return false;                       // consumed: served by the consumer
    }
    return true;
}

/// Take the slot for the periodic CLEAN cycle. A failure records nothing:
/// the cycle that holds the slot runs the same election clean's Step 1
/// would, and the clean timer retries. compare_exchange, not load-then-store,
/// so a run_think() on another thread cannot take the slot in between.
inline bool acquire_clean_slot(std::atomic<bool>& running)
{
    bool expected = false;
    return running.compare_exchange_strong(expected, true);
}

/// Release the slot at the end of a cycle's IO phase. True: at least one
/// run_think() was skipped while the slot was held, so the caller must post
/// one. Any number of skipped requests collapse into one (think() is a full
/// re-election). `running` is cleared first: a request that interleaves sees
/// the slot free and takes it itself.
inline bool release_think_slot(std::atomic<bool>& running,
                               std::atomic<bool>& rethink_pending)
{
    running.store(false);
    return rethink_pending.exchange(false);
}

/// Did the CLEAN cycle move the sharechain tip? clean_tracker() runs think()
/// twice (Step 1 and, after the prune, Step 4) and both assign the best share.
/// The tip at cycle entry against the tip at exit catches a change made in
/// either; comparing Step 4 with Step 1 missed every change Step 1 made. A
/// null exit is a node that never elected anything, not a change.
inline bool clean_cycle_best_changed(const uint256& best_at_entry,
                                     const uint256& best_at_exit)
{
    return !best_at_exit.IsNull() && best_at_exit != best_at_entry;
}

} // namespace ltc::think
