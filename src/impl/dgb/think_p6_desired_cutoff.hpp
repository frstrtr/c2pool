// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// SSOT for the think() Phase-6 desired-shares TIMESTAMP CUTOFF — the two pure
// decisions that govern which outstanding (desired) share requests survive the
// final filter at the end of think():
//   (a) the cutoff timestamp itself, derived from the best share (or a 24h
//       fallback when there is no valid best), and
//   (b) the per-request keep/drop predicate against that cutoff.
//
// These are currently OPEN-CODED inline in share_tracker.hpp think() Phase 6
// (the best-valid vs no-best branch computing timestamp_cutoff, plus the
// `d.max_timestamp >= timestamp_cutoff` keep test in the desired loop). A silent
// drift — wrong fallback window, wrong 3600s back-off, or a flipped comparison —
// would change which shares a c2pool-dgb node keeps requesting during sync, with
// NO compile error: too-loose hammers peers with unanswerable requests until they
// drop us; too-tight starves the chain of legitimately-missing parents. Lifting
// the arithmetic to a single header-only SSOT lets a KAT pin it exactly.
//
// Oracle: p2pool data.py:2360-2374  OkayTracker.think() tail:
//     if best is not None:
//         timestamp_cutoff = min(int(time.time()), best_share.timestamp) - 3600
//     else:
//         timestamp_cutoff = int(time.time()) - 24*60*60
//     return best, [(peer_addr, hash) for peer_addr, hash, ts, targ in desired
//                   if ts >= timestamp_cutoff]
//
// Per-coin isolation: dgb/ only. Header-only, additive; this slice does NOT yet
// rewire share_tracker.hpp (that is the byte-identity-fenced delegation
// follow-on) — it pins the cutoff math as free functions so the KAT exercises
// them with no ShareTracker/NodeImpl standup. Consensus-neutral: pure arithmetic,
// no value semantics changed.

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace dgb {

// The Phase-6 desired-shares timestamp cutoff.
//   best_valid == true : min(now, best_ts) - 3600   (1h grace below the best
//       share timestamp; min() guards a best share whose timestamp is ahead of
//       local clock from pushing the cutoff into the future).
//   best_valid == false: now - 24*60*60             (24h fallback window when no
//       best share is resolved yet).
// uint32_t arithmetic, byte-identical to the inline share_tracker.hpp formula.
inline uint32_t think_p6_timestamp_cutoff(bool best_valid, uint32_t best_ts,
                                          uint32_t now)
{
    if (best_valid)
        return std::min(now, best_ts) - 3600u;
    return now - 24u * 60u * 60u;
}

// Per-desired-request keep predicate: a request whose max-available timestamp is
// at or after the cutoff is retained (inclusive lower bound), matching the
// p2pool list-comprehension guard `ts >= timestamp_cutoff`.
inline bool think_p6_passes_cutoff(uint32_t max_timestamp, uint32_t cutoff)
{
    return max_timestamp >= cutoff;
}

// ── Dormant-chain revive (operator decision 2026-11-27) ─────────────────────
// The one difference from p2pool's think() tail (data.py:2360-2374). While no
// head has ever verified on this node (no valid best, verified chain empty), a
// desired parent the cutoff would drop is still requested: at most
// kRevivePerThink per think and kReviveMaxRequests in all (each request asks a
// peer for up to 500 parents; think-P1 already stops asking once a head is in
// the pruning zone, 2*CHAIN_LENGTH+10). Without it a node whose stored chain is
// older than 24 h, with every head shallower than CHAIN_LENGTH, never fetches
// the parents it needs, never verifies a head and never serves work. Once a
// best share exists the revive ends for good and the cutoff applies exactly as
// before. Only WHICH parents are requested changes; share validity and
// verification are untouched.
inline constexpr int kRevivePerThink = 1;
inline constexpr int kReviveMaxRequests = 64;

struct ReviveState {
    int requests_left = kReviveMaxRequests;
    bool done = false;
};

/// Once per think, before the filter: whether this think may revive. A valid
/// best ends the revive for good.
inline bool think_p6_revive_armed(ReviveState& st, bool best_valid, size_t verified_count)
{
    if (best_valid)
        st.done = true;
    return !st.done && verified_count == 0 && st.requests_left > 0;
}

/// Per desired entry the cutoff drops: whether the revive requests it anyway.
inline bool think_p6_revive_take(ReviveState& st, bool armed, int& taken_this_think)
{
    if (!armed || taken_this_think >= kRevivePerThink || st.requests_left <= 0)
        return false;
    ++taken_this_think;
    --st.requests_left;
    return true;
}

} // namespace dgb