// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ============================================================================
// think_gate.hpp — the DASH async-think serialization protocol, in ONE place.
//
// The DASH node runs at most one tracker.think() at a time: the compute pool
// has a single thread and think() holds m_tracker_mutex exclusively. That is
// enforced by a `running` flag which run_think() exchanges on entry and the
// IO-phase clears on exit.
//
// The bug that flag alone creates (#854): a run_think() request that arrives
// while a cycle is in flight is DROPPED, not queued. It is reachable on the
// hot path — add_local_share() (node.cpp, mint) and drain_peer_best_adverts()
// both call run_think() from the IO thread, and a think cycle's IO-phase runs
// on that same thread with `running` still true (the tracker lock is already
// released, so the mint that triggered the request has really landed in the
// chain). The election that would have promoted the freshly minted share to
// the tip never runs, so the sharechain best-share-changed callback never
// fires, so no mining.notify is pushed and rigs keep hashing the previous
// prev_share_hash until the 25 s keepalive — which is itself non-clean
// (clean_jobs is keyed on the COIN prevhash, core/stratum_server.cpp), i.e. a
// bounded sibling burst. That is the residual of the #853 storm.
//
// The fix is a second flag: a request that loses the race is REMEMBERED, and
// the owner of the cycle services it when it releases. These two free
// functions are the whole protocol, so node.cpp and the KATs
// (test_dash_stratum_notify_roundtrip) exercise literally the same code.
//
// ── THREADING ───────────────────────────────────────────────────────────────
// Both flags are touched ONLY on the IO thread in main_dash (one ioc.run()
// thread): run_think()'s prologue, clean_tracker()'s prologue (the periodic
// timer callback), and both cycles' IO-phase epilogues, which are
// boost::asio::post(*m_context, ...) handlers. The compute thread NEVER reads
// or writes either flag. They are std::atomic anyway so the release/acquire
// pairing across the compute-thread hop is well defined, and so the pattern
// stays correct if the DASH lane ever grows a second IO thread.
//
// Release ordering is deliberate: `running` is cleared BEFORE the pending flag
// is consumed. A request that interleaves at that point sees running == false,
// wins the slot outright and runs the think itself — so the re-think is served
// exactly once and never lost. The reverse order could drop it.
//
// Consensus-neutral: this file decides only WHEN an election re-runs and when
// miners are told about it. It touches no share bytes, no timestamp, no
// gentx/ref_hash, no PPLNS weight, and no part of the won-block submit path.
// ============================================================================

#include <core/uint256.hpp>

#include <atomic>

namespace dash::think {

/// Try to take the single think slot for a run_think() cycle.
///
/// Returns true if the caller now owns the cycle and must eventually call
/// release_think_slot(). Returns false if a cycle is already in flight — in
/// which case the request is recorded, and the owner of the running cycle will
/// re-post run_think() when it releases.
inline bool acquire_think_slot(std::atomic<bool>& running,
                               std::atomic<bool>& rethink_pending)
{
    if (running.exchange(true)) {
        rethink_pending.store(true);   // #854: remember the dropped request
        return false;
    }
    return true;
}

/// Try to take the single think slot for the CLEAN maintenance cycle.
///
/// Unlike acquire_think_slot() a failure here records NOTHING: clean_tracker()
/// is periodic maintenance driven by its own timer, and the think cycle that
/// beat it to the slot already performs the election clean's Step 1 would have
/// performed. Queuing a re-think for a skipped CLEAN would just add a
/// redundant think.
///
/// compare_exchange (not load-then-store) closes the check-then-act window the
/// pre-#854 clean_tracker() prologue carried as a TODO: the guard is now
/// symmetric with the m_clean_running exchange() above it.
inline bool acquire_clean_slot(std::atomic<bool>& running)
{
    bool expected = false;
    return running.compare_exchange_strong(expected, true);
}

/// Release the think slot at the end of a cycle's IO-phase.
///
/// Returns true if at least one run_think() request was dropped while the
/// cycle held the slot, i.e. the caller MUST re-post run_think(). Multiple
/// dropped requests collapse into one re-think — think() is a full re-election
/// over the current chain, so one pass subsumes any number of requests.
inline bool release_think_slot(std::atomic<bool>& running,
                               std::atomic<bool>& rethink_pending)
{
    running.store(false);              // clear FIRST — see the ordering note
    return rethink_pending.exchange(false);
}

/// Did the CLEAN cycle move the sharechain tip?
///
/// #854: clean_tracker() runs think() TWICE — Step 1 (score the chain as
/// found) and Step 4 (re-score after stale-head eating / tail dropping) — and
/// BOTH assign m_best_share_hash. The pre-#854 code computed the "did the tip
/// move" flag inside Step 4 only, against the value Step 1 had ALREADY
/// updated:
///
///     Step 1: m_best_share_hash = result.best;                  // A -> B
///     Step 4: changed = (m_best_share_hash != result.best);     // B != B -> false
///
/// so an election absorbed by Step 1 — exactly the case a mint landing during
/// a think IO-phase produces — evaluated false and pushed no work to the rigs.
///
/// Comparing the tip at cycle ENTRY against the tip at cycle EXIT detects the
/// change wherever inside the cycle it materialised. `best_at_exit` is
/// m_best_share_hash after both thinks; it is null only on a node that has
/// never elected anything, which is not a tip change.
inline bool clean_cycle_best_changed(const uint256& best_at_entry,
                                     const uint256& best_at_exit)
{
    return !best_at_exit.IsNull() && best_at_exit != best_at_entry;
}

} // namespace dash::think
