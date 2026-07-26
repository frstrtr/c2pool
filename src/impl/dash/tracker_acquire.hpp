// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ═══════════════════════════════════════════════════════════════════════════
//  Bounded tracker acquisition for the BLOCK-WINNING mint path (#889)
// ═══════════════════════════════════════════════════════════════════════════
//
// THE PROBLEM
// -----------
// Every IO-thread tracker acquisition in this node is `try_to_lock` and
// DECLINES when the compute thread is mid-think() (node.hpp's synchronisation
// contract: "IO thread reads: shared_lock(try_to_lock) — non-blocking, skip if
// busy"). For an ordinary share that trade is sound — the decline costs one
// share and the NEXT solve mints instead.
//
// A block-winning share has no next solve. The block is found once, so a
// momentarily busy tracker permanently forfeits the highest-work share the node
// will ever produce. And because p2pool nodes detect pool blocks THROUGH the
// sharechain (p2pool/node.py:145-147 fires only for a share with
// `pow_hash <= header['bits'].target`), a share that is never minted is a block
// that no peer — including our own oracle — can ever see. The decline is
// therefore not merely share-weight loss: it reproduces the FULL #887 symptom,
// just intermittently.
//
// THE SHAPE OF THE FIX
// --------------------
// Make the acquisition BOUNDED-BLOCKING on the block-winning path ONLY. The
// ordinary share path keeps `Urgency::Opportunistic`, i.e. exactly today's
// single `try_lock` with no behavioural change whatsoever.
//
// WHY POLLED try_lock AND NOT A BLOCKING lock()
// ---------------------------------------------
//  * It must be BOUNDED. An unbounded `lock()` on the stratum IO thread would
//    stall every other miner's submissions for as long as the compute thread
//    wanted, with no ceiling and no diagnostic.
//  * `std::shared_mutex` has NO timed acquire — that is `std::shared_timed_mutex`.
//    Switching the type would rewrite ~30 explicit `std::shared_lock<std::shared_mutex>`
//    reader-discipline call sites across node.hpp/node.cpp, i.e. a far larger and
//    riskier diff than the defect warrants on a live reward path.
//  * A poll loop keeps the mutex type, the reader discipline and every existing
//    call site byte-identical, and gives an exact, testable deadline.
//
// COST OF THE POLL: at BLOCK_SHARE_LOCK_POLL = 200 us the worst case is 10 000
// wakeups over the full 2 s budget; the EXPECTED case is one think() tail
// (measured p50 125 ms => ~625 wakeups). Both are noise against a solved block.
//
// FAIRNESS, HONESTLY STATED: polled try_lock is not fair. A writer poll can in
// principle be starved by an unbroken stream of shared readers. Every shared
// reader on this mutex is itself an IO-thread `try_to_lock` that holds for
// microseconds (an advert walk, a stats read), so unbroken coverage for 2 s is
// not a realistic state — and if it ever happened the bound converts it into a
// LOGGED, COUNTED forfeit rather than a wedged IO thread. That is strictly
// better than today, where the same situation is a silent drop.
//
// ⚠️ #878/#881 DEFECT CLASS — READ BEFORE ADDING A CALLER
// -------------------------------------------------------
// A caller that already holds the tracker lock and then calls into a
// self-locking callee makes the callee dead code; making that callee BLOCKING
// turns dead code into a DEADLOCK. Every `Urgency::BlockWinning` call site must
// therefore hold ZERO locks on entry. The two live ones (main_dash.cpp's mint
// lambda and NodeImpl::add_local_share) are reached from the stratum handler
// at lock depth zero — see the trace in the PR. `on_compute_thread` below is
// the belt-and-braces guard: the compute thread already owns the exclusive
// lock, so it NEVER waits here.

#include <atomic>
#include <chrono>
#include <mutex>
#include <shared_mutex>
#include <thread>

namespace dash {
namespace tracker_acquire {

/// How badly the caller needs the lock.
enum class Urgency {
    /// Today's behaviour, unchanged: one `try_lock`, decline if busy.
    /// Correct for ordinary shares — the next solve mints.
    Opportunistic,
    /// Bounded wait. ONLY for a solve that already cleared the BLOCK target:
    /// there is no next solve, so a decline is permanent and also hides the
    /// block from every p2pool peer.
    BlockWinning,
};

/// Wait budget for a block-winning acquisition.
///
/// RATIONALE — measured, not guessed. From a 42 h DASH sharechain soak
/// (`[ASYNC-THINK] compute done in Nms`, n = 6721 think cycles, post-join
/// steady state):
///
///     p50 = 125 ms   p90 = 193 ms   p99 = 300 ms   p99.9 = 512 ms   max = 1074 ms
///     > 500 ms: 8 cycles (0.119%)   > 750 ms: 3 (0.045%)   > 1000 ms: 1 (0.015%)
///
/// 2000 ms covers 100% of the observed steady-state distribution with ~1.9x
/// headroom over the single worst cycle. It is deliberately NOT tighter: the
/// exclusive hold also covers publish_snapshot() + flush_verified_to_leveldb()
/// (a little beyond the logged think_ms), and clean_tracker() takes the same
/// exclusive lock for a think + stale-head eat + tail drop + LevelDB prune that
/// this build does not time at all. Against an unmeasured second holder, the
/// safe direction is more headroom, because the failure mode of a too-tight
/// budget is exactly the loss we are fixing.
///
/// It is also deliberately NOT looser. During the first ~5 minutes after a
/// cold join the same log shows think cycles of 6–15 s (the bootstrap
/// full-verify pass over an empty verified set). A budget that covered THOSE
/// would stall the stratum IO thread for 15 s. A node in bootstrap has no
/// sharechain to mint onto and is not winning blocks, so covering that state is
/// worthless — capping below it is the point of having a bound at all.
inline constexpr std::chrono::milliseconds BLOCK_SHARE_LOCK_BUDGET{2000};

/// Re-poll interval while waiting. 200 us is ~0.16% of the p50 think tail, so
/// the added latency over a true blocking acquire is immaterial, and 10 000
/// wakeups is the worst-case ceiling.
inline constexpr std::chrono::microseconds BLOCK_SHARE_LOCK_POLL{200};

/// Bounded EXCLUSIVE acquisition.
///
/// Returns an owning `unique_lock` on success, or a NON-owning one on expiry —
/// callers MUST check `owns_lock()` exactly as they check it today, so an
/// expired budget degrades to precisely the pre-#889 decline (never a silent
/// or unchecked proceed).
///
/// `on_compute_thread` is the #878/#881 guard: the compute thread already holds
/// this mutex exclusively, so it degrades to a single try and never waits.
template <class Mutex>
std::unique_lock<Mutex> exclusive(
    Mutex& m,
    Urgency urgency,
    bool on_compute_thread = false,
    std::chrono::milliseconds budget = BLOCK_SHARE_LOCK_BUDGET,
    std::chrono::microseconds poll   = BLOCK_SHARE_LOCK_POLL)
{
    std::unique_lock<Mutex> lock(m, std::try_to_lock);
    if (lock.owns_lock() || urgency == Urgency::Opportunistic || on_compute_thread
        || budget <= std::chrono::milliseconds::zero())
        return lock;

    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(poll);
        if (lock.try_lock())
            return lock;
    }
    return lock;   // non-owning — budget expired, caller declines + counts it
}

/// Bounded SHARED acquisition. Same contract as `exclusive` above.
template <class Mutex>
std::shared_lock<Mutex> shared(
    Mutex& m,
    Urgency urgency,
    bool on_compute_thread = false,
    std::chrono::milliseconds budget = BLOCK_SHARE_LOCK_BUDGET,
    std::chrono::microseconds poll   = BLOCK_SHARE_LOCK_POLL)
{
    std::shared_lock<Mutex> lock(m, std::try_to_lock);
    if (lock.owns_lock() || urgency == Urgency::Opportunistic || on_compute_thread
        || budget <= std::chrono::milliseconds::zero())
        return lock;

    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(poll);
        if (lock.try_lock())
            return lock;
    }
    return lock;
}

} // namespace tracker_acquire
} // namespace dash
