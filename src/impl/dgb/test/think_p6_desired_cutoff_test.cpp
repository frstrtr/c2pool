// SPDX-License-Identifier: AGPL-3.0-or-later
// dgb think() Phase-6 desired-shares TIMESTAMP CUTOFF conformance KAT.
//
// FENCED, additive (no production code touched this slice). Pins
// src/impl/dgb/think_p6_desired_cutoff.hpp against the p2pool data.py think()
// Phase-6 tail oracle for the two pure decisions:
//   timestamp_cutoff = min(now, best_ts) - 3600   if best valid
//                    = now - 24*60*60              otherwise
//   keep(req)        = req.max_timestamp >= timestamp_cutoff   (inclusive)
//
// Expectations are HAND-DERIVED from the oracle formula, NOT read back from the
// code under test — a conformance KAT that asks its subject for the answer
// passes vacuously. Pure arithmetic: links only core (no chain standup). MUST
// appear in BOTH this dir's CMakeLists.txt AND the build.yml --target allowlist,
// or it becomes a #143 NOT_BUILT sentinel (compiled-out, silently "passing").

#include <impl/dgb/think_p6_desired_cutoff.hpp>

#include <gtest/gtest.h>

#include <cstdint>

namespace {

// A fixed "now" well above the 24h/1h offsets so no uint32 underflow occurs in
// the hand-derived arithmetic below. (1700000000 ~= 2023-11-14 UTC.)
constexpr uint32_t NOW = 1700000000u;

// ---- timestamp_cutoff: no valid best -> 24h fallback window
TEST(ThinkP6DesiredCutoff, NoBestUses24hFallback)
{
    // best_ts is ignored on the no-best branch.
    EXPECT_EQ(dgb::think_p6_timestamp_cutoff(false, 0,            NOW),
              NOW - 86400u);
    EXPECT_EQ(dgb::think_p6_timestamp_cutoff(false, NOW + 50000u, NOW),
              NOW - 86400u);
    EXPECT_EQ(dgb::think_p6_timestamp_cutoff(false, 12345u,       NOW),
              NOW - 86400u);
}

// ---- timestamp_cutoff: valid best, best_ts BEHIND now -> best_ts - 3600
TEST(ThinkP6DesiredCutoff, BestBehindNowUsesBestMinus3600)
{
    const uint32_t best_ts = NOW - 7200u;          // 2h behind local clock
    EXPECT_EQ(dgb::think_p6_timestamp_cutoff(true, best_ts, NOW),
              best_ts - 3600u);                     // min(now,best)=best
}

// ---- timestamp_cutoff: valid best, best_ts AHEAD of now -> now - 3600
// min() clamps a best share whose timestamp leads local clock so the cutoff
// can never be pushed into the future.
TEST(ThinkP6DesiredCutoff, BestAheadOfNowClampsToNowMinus3600)
{
    const uint32_t best_ts = NOW + 10000u;         // best leads local clock
    EXPECT_EQ(dgb::think_p6_timestamp_cutoff(true, best_ts, NOW),
              NOW - 3600u);                          // min(now,best)=now
}

// ---- timestamp_cutoff: valid best, best_ts == now -> now - 3600 (boundary)
TEST(ThinkP6DesiredCutoff, BestEqualsNowBoundary)
{
    EXPECT_EQ(dgb::think_p6_timestamp_cutoff(true, NOW, NOW), NOW - 3600u);
}

// ---- keep predicate: inclusive lower bound at the cutoff
TEST(ThinkP6DesiredCutoff, KeepPredicateInclusive)
{
    const uint32_t cutoff = NOW - 3600u;
    EXPECT_FALSE(dgb::think_p6_passes_cutoff(cutoff - 1u, cutoff)); // stale -> drop
    EXPECT_TRUE (dgb::think_p6_passes_cutoff(cutoff,      cutoff)); // == cutoff -> keep
    EXPECT_TRUE (dgb::think_p6_passes_cutoff(cutoff + 1u, cutoff)); // fresh -> keep
    EXPECT_TRUE (dgb::think_p6_passes_cutoff(NOW,         cutoff));
    EXPECT_FALSE(dgb::think_p6_passes_cutoff(0u,          cutoff));
}

// ---- Non-circular delegation proof ---------------------------------------
// When share_tracker.hpp think() Phase 6 is rewired to CALL the SSOT functions
// above, this anchors against drift. It does NOT stand up a ShareTracker;
// instead it re-implements the EXACT pre-delegation inline expressions verbatim
// (copied from the share_tracker.hpp think() body as it stood before this slice)
// and asserts byte-identity to the SSOT across a dense input grid. Independent
// code path => non-circular.

// Verbatim copy of the pre-delegation inline cutoff computation.
// Original (best valid): std::min(static_cast<uint32_t>(now), best_ts) - 3600
//          (no best)   : now - 24*60*60
inline uint32_t inline_cutoff_verbatim(bool best_valid, uint32_t best_ts,
                                       uint32_t now)
{
    uint32_t timestamp_cutoff;
    if (best_valid)
        timestamp_cutoff = std::min(static_cast<uint32_t>(now), best_ts) - 3600;
    else
        timestamp_cutoff = static_cast<uint32_t>(now) - 24 * 60 * 60;
    return timestamp_cutoff;
}

// Verbatim copy of the pre-delegation inline keep test.
// Original: if (d.max_timestamp >= timestamp_cutoff) keep;
inline bool inline_keep_verbatim(uint32_t max_timestamp, uint32_t cutoff)
{
    return max_timestamp >= cutoff;
}

TEST(ThinkP6DesiredCutoff, DelegationMatchesPreDelegationInlineCutoff)
{
    for (uint32_t now : {1700000000u, 1234567890u, 90000u}) {
        // no-best branch
        EXPECT_EQ(dgb::think_p6_timestamp_cutoff(false, 0u, now),
                  inline_cutoff_verbatim(false, 0u, now))
            << "no-best cutoff drift @ now=" << now;
        // best-valid branch across a window straddling `now`
        for (uint32_t off = 0; off <= 20000u; off += 250u) {
            const uint32_t behind = now - off;
            const uint32_t ahead  = now + off;
            EXPECT_EQ(dgb::think_p6_timestamp_cutoff(true, behind, now),
                      inline_cutoff_verbatim(true, behind, now))
                << "best-behind cutoff drift @ now=" << now << " off=" << off;
            EXPECT_EQ(dgb::think_p6_timestamp_cutoff(true, ahead, now),
                      inline_cutoff_verbatim(true, ahead, now))
                << "best-ahead cutoff drift @ now=" << now << " off=" << off;
        }
    }
}

TEST(ThinkP6DesiredCutoff, DelegationMatchesPreDelegationInlineKeep)
{
    const uint32_t cutoff = 1700000000u - 3600u;
    for (int32_t delta = -5000; delta <= 5000; delta += 25) {
        const uint32_t ts = static_cast<uint32_t>(static_cast<int64_t>(cutoff) + delta);
        EXPECT_EQ(dgb::think_p6_passes_cutoff(ts, cutoff),
                  inline_keep_verbatim(ts, cutoff))
            << "keep drift @ delta=" << delta;
    }
}

} // namespace