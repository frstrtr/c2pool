// SPDX-License-Identifier: AGPL-3.0-or-later
// sharechain::select_pool_rate_head + average_stale_prop -- dashboard pool-rate
// head-selection KAT (issue #1482).
//
// Pins the pure decision of WHICH sharechain head the dashboard pool-hashrate
// estimator (and the pool_stale_prop series) anchors on. This is the load-
// bearing new logic behind un-flapping the ltc.voidbind graph: the estimator
// (get_pool_attempts_per_second) is unchanged; the fix is that the head is now
// the pool's best-known LIVE head -- verified best when live, else the fastest
// LIVE raw head -- instead of the tallest RAW head (which flipped between two
// near-equal-height forks sample-to-sample).
//
// Oracle (mirrors p2pool web.py feeding the graph off the node's best-known
// live head, and data.py get_average_stale_prop):
//   1. verified best present AND live (newest share within the horizon) -> it,
//      unconditionally (even if a raw head has a larger APS).
//   2. verified best absent OR stale -> the LIVE raw head with the greatest
//      get_pool_attempts_per_second; ties -> greater height -> first-seen.
//   3. a raw head older than the horizon is DEAD and ignored even if its APS
//      is larger (never anchor the live graph on a dead foreign fork).
//   4. nothing live -> null (the caller holds its last-good value).
//   5. average_stale_prop(stales, lookbehind) == stales / (lookbehind + stales).
//
// All expectations are hand-derived from that oracle, not produced by calling
// the helper under test, so the KAT is non-circular. The pre-#1482 behaviour
// (verified-best-unconditional / tallest-raw, whole-window stale count) would
// FAIL cases (2) and (5) -- that divergence is the fix.
//
// FOLDED into the already-allowlisted `share_test` target (a fresh
// add_executable would trip CI's NOT_BUILT sentinel, #143/#883/#893). Pure
// header-only logic; no NodeImpl / ShareTracker / socket standup.

#include <sharechain/pool_rate_head_select.hpp>

#include <cstdio>

#include <gtest/gtest.h>

namespace {

using sharechain::PoolRateHead;
using sharechain::select_pool_rate_head;
using sharechain::average_stale_prop;

// Distinct non-null test hashes: n encoded as a hex uint256.
uint256 H(uint32_t n) {
    char buf[9];
    std::snprintf(buf, sizeof(buf), "%08x", n);
    uint256 x;
    x.SetHex(buf);
    return x;
}

PoolRateHead mk(uint32_t n, int32_t height, int64_t age_s, double aps) {
    PoolRateHead h;
    h.hash = H(n);
    h.height = height;
    h.newest_share_age_s = age_s;
    h.aps = aps;
    return h;
}

// ---- (1) verified best present + LIVE wins outright ----------------------

TEST(PoolRateHeadSelect, VerifiedBestLiveWins) {
    // Verified best is live (age 10 s). A raw head has a LARGER APS, but the
    // live verified head still wins -- p2pool anchors on best_share_hash when it
    // is current.
    PoolRateHead verified = mk(7, 900, /*age*/ 10, /*aps*/ 100.0);
    std::vector<PoolRateHead> raw = {mk(11, 901, 5, 999.0)};
    EXPECT_EQ(select_pool_rate_head(verified, /*present=*/true, raw), H(7));
}

// ---- (1b) FUTURE-DATED head is LIVE, not dead (blocker A) ----------------

TEST(PoolRateHeadSelect, FutureDatedHeadIsLive) {
    // A newest share dated a few seconds AHEAD of the sampling clock (clock skew
    // or a legitimately future-dated share) makes now-ts NEGATIVE. That head is
    // maximally live -- it MUST stay anchorable. The pre-fix code overloaded the
    // -1 "undatable" sentinel with any negative age, so a share 1 s in the future
    // read as DEAD, the verified head lost liveness, and the anchor flipped off
    // it (the #1482 symptom). With kUnknownAge = INT64_MIN the two are distinct.
    using sharechain::pool_rate_head_is_live;
    using sharechain::kUnknownAge;

    // A future-dated head is live at any negative age; the undatable sentinel is
    // NOT live even though it too is "negative".
    EXPECT_TRUE(pool_rate_head_is_live(mk(1, 100, /*age*/ -5, 10.0), 600));
    EXPECT_TRUE(pool_rate_head_is_live(mk(2, 100, /*age*/ -1, 10.0), 600));
    PoolRateHead undatable = mk(3, 100, /*age*/ 0, 10.0);
    undatable.newest_share_age_s = kUnknownAge;
    EXPECT_FALSE(pool_rate_head_is_live(undatable, 600));

    // A verified best whose newest share is 5 s in the FUTURE still wins outright
    // -- it does not fall through to the raw-head branch.
    PoolRateHead verified = mk(7, 900, /*age*/ -5, /*aps*/ 100.0);
    std::vector<PoolRateHead> raw = {mk(11, 901, 5, 999.0)};
    EXPECT_EQ(select_pool_rate_head(verified, /*present=*/true, raw), H(7));

    // And a future-dated RAW head is a valid live anchor when no verified head is
    // present (beats an undatable head that must be skipped).
    PoolRateHead undatable_raw = mk(12, 950, /*age*/ 0, 1e9);
    undatable_raw.newest_share_age_s = kUnknownAge;
    std::vector<PoolRateHead> raw2 = {undatable_raw,
                                      mk(13, 400, /*age*/ -3, 42.0)};
    EXPECT_EQ(select_pool_rate_head(PoolRateHead{}, /*present=*/false, raw2),
              H(13));
}

// ---- (2) STALE verified best -> fastest LIVE raw head --------------------

TEST(PoolRateHeadSelect, StaleVerifiedBestYieldsFastestLiveRawHead) {
    // THE #1482 CASE: the verified best-share election froze (its newest share
    // is 700 s old, past the 600 s horizon), so it is stale. Among the LIVE raw
    // heads pick the one with the greatest APS -- h(12) at aps 500 beats h(11)
    // at aps 120, regardless of height. Pre-#1482 (verified-best-unconditional,
    // or tallest-raw = h(11) at height 950) picks a different head: RED there.
    PoolRateHead verified = mk(7, 900, /*age*/ 700, /*aps*/ 80.0);
    std::vector<PoolRateHead> raw = {
        mk(11, 950, /*age*/ 30, /*aps*/ 120.0),   // tallest, but slower
        mk(12, 900, /*age*/ 30, /*aps*/ 500.0),   // fastest LIVE -> chosen
    };
    EXPECT_EQ(select_pool_rate_head(verified, /*present=*/true, raw), H(12));
}

// ---- (3) a DEAD (stale) foreign head is ignored even if fast -------------

TEST(PoolRateHeadSelect, DeadForeignHeadIgnored) {
    // No verified head. Two raw heads: h(20) has a HUGE APS but its newest share
    // is 700 s old (dead foreign fork nobody extends); h(21) is slower but LIVE
    // (age 90 s). The live-but-slower head must win; the dead fast head is never
    // anchored on.
    std::vector<PoolRateHead> raw = {
        mk(20, 1000, /*age*/ 700, /*aps*/ 1e9),   // dead: ignored
        mk(21,  400, /*age*/  90, /*aps*/ 42.0),  // live: chosen
    };
    EXPECT_EQ(select_pool_rate_head(PoolRateHead{}, /*present=*/false, raw),
              H(21));
}

// ---- (4) nothing live -> null (caller holds last-good) -------------------

TEST(PoolRateHeadSelect, EmptyTrackerReturnsNull) {
    std::vector<PoolRateHead> none;
    EXPECT_TRUE(
        select_pool_rate_head(PoolRateHead{}, /*present=*/false, none).IsNull());
}

TEST(PoolRateHeadSelect, AllRawHeadsDeadReturnsNull) {
    // Every raw head is past the horizon, and there is no verified head: null.
    std::vector<PoolRateHead> raw = {
        mk(30, 500, /*age*/ 601, 10.0),
        mk(31, 900, /*age*/ 5000, 99.0),
    };
    EXPECT_TRUE(
        select_pool_rate_head(PoolRateHead{}, /*present=*/false, raw).IsNull());
}

TEST(PoolRateHeadSelect, StaleVerifiedAndNoLiveRawReturnsNull) {
    // Verified present but stale, and no raw head is live -> null (hold).
    PoolRateHead verified = mk(7, 900, /*age*/ 700, 80.0);
    std::vector<PoolRateHead> raw = {mk(11, 950, /*age*/ 900, 120.0)};
    EXPECT_TRUE(select_pool_rate_head(verified, /*present=*/true, raw).IsNull());
}

// ---- selection determinism (tie-break + null-hash skip) ------------------

TEST(PoolRateHeadSelect, EqualApsBreaksToGreaterHeightThenFirstSeen) {
    // Two live raw heads with EQUAL aps: the greater height wins.
    std::vector<PoolRateHead> raw = {
        mk(40, 800, 10, 50.0),
        mk(41, 900, 10, 50.0),   // taller at equal aps -> chosen
    };
    EXPECT_EQ(select_pool_rate_head(PoolRateHead{}, false, raw), H(41));
}

TEST(PoolRateHeadSelect, NullHashRawHeadsAreSkipped) {
    PoolRateHead nullhead;            // null hash, but "fast" and "live"
    nullhead.height = 999;
    nullhead.newest_share_age_s = 1;
    nullhead.aps = 1e9;
    std::vector<PoolRateHead> raw = {nullhead, mk(50, 300, 30, 12.0)};
    EXPECT_EQ(select_pool_rate_head(PoolRateHead{}, false, raw), H(50));
}

TEST(PoolRateHeadSelect, VerifiedPresentButNullHashFallsToLiveRaw) {
    // "present" true but the hash is null (defensive): treated as absent.
    PoolRateHead verified;           // null hash
    verified.newest_share_age_s = 5; // "live" but null -> not usable
    std::vector<PoolRateHead> raw = {mk(60, 300, 30, 7.0)};
    EXPECT_EQ(select_pool_rate_head(verified, /*present=*/true, raw), H(60));
}

// ---- (5) p2pool get_average_stale_prop formula ---------------------------

TEST(PoolRateHeadSelect, StalePropFormulaMatchesP2pool) {
    // p2pool data.py get_average_stale_prop == stales / (lookbehind + stales).
    // Hand-derived oracle values (NOT the count-over-whole-window formula that
    // flapped 0.05<->0.40 pre-#1482).
    EXPECT_DOUBLE_EQ(average_stale_prop(0, 360), 0.0);
    EXPECT_DOUBLE_EQ(average_stale_prop(3, 360), 3.0 / 363.0);
    EXPECT_DOUBLE_EQ(average_stale_prop(40, 360), 40.0 / 400.0);   // 0.10
    // Degenerate: no window and no stales -> 0, never a divide-by-zero.
    EXPECT_DOUBLE_EQ(average_stale_prop(0, 0), 0.0);
    // All stale (lookbehind 0, stales 5) -> 5/(0+5) = 1.0.
    EXPECT_DOUBLE_EQ(average_stale_prop(5, 0), 1.0);
    // Negative inputs are clamped to 0 (defensive), never negative prop.
    EXPECT_DOUBLE_EQ(average_stale_prop(-3, 360), 0.0);
}

}  // namespace
