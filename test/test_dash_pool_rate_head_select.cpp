// SPDX-License-Identifier: AGPL-3.0-or-later
// dash::select_pool_rate_head -- dashboard pool-rate head-selection KAT.
//
// Pins coin/pool_rate_head_select.hpp: the pure decision of WHICH sharechain
// head the dashboard pool-hashrate estimator anchors on. This is the load-
// bearing new logic behind "populate the pool-rate graph with 0 local miners":
// the estimator (get_pool_attempts_per_second) is unchanged; the fix is that
// when the VERIFIED best-share head is absent (zero-local-miner bootstrap, the
// contabo / dash.voidbind.com relay case) the estimator falls back to the
// tallest RAW chain head instead of short-circuiting to 0.
//
// Oracle (mirrors node.hpp advertised_best_share()'s raw-head walk + p2pool
// web.py add_point() feeding the graph off the shared chain regardless of any
// local miner):
//   1. verified head present (non-null AND in chain) -> use it verbatim
//   2. else -> tallest raw head, ties keep first-seen at max (h > best_height)
//   3. no raw heads -> null (caller holds last-good, never a spurious 0)
//
// All expectations are hand-derived from that oracle, not produced by calling
// the helper under test, so the KAT is non-circular.
//
// FOLDED into the already-allowlisted test_dash_share_tracker target (a fresh
// executable would need a build.yml --target edit and would otherwise trip CI's
// NOT_BUILT sentinel, #143/#883/#893). The estimator arithmetic proper lives in
// share_tracker.hpp; this header captures ONLY the head choice.

#include <impl/dash/coin/pool_rate_head_select.hpp>

#include <cstdio>

#include <gtest/gtest.h>

namespace {

using dash::RawChainHead;
using dash::select_pool_rate_head;

// Distinct non-null test hashes: n encoded as a hex uint256.
uint256 h(uint32_t n) {
    char buf[9];
    std::snprintf(buf, sizeof(buf), "%08x", n);
    uint256 x;
    x.SetHex(buf);
    return x;
}

// ---- (1) verified head present -> used verbatim -------------------------

TEST(DashPoolRateHead, VerifiedHeadUsedWhenPresent) {
    // Verified head is non-null and in chain: returned as-is, raw heads ignored
    // even if a raw head is taller.
    std::vector<RawChainHead> raw = {{h(10), 500}, {h(11), 900}};
    EXPECT_EQ(select_pool_rate_head(h(7), /*in_chain=*/true, raw), h(7));
}

TEST(DashPoolRateHead, VerifiedHeadNotInChainTriggersFallback) {
    // Non-null verified head but NOT in the chain (stale/pruned): fall back to
    // the tallest raw head.
    std::vector<RawChainHead> raw = {{h(10), 500}, {h(11), 900}};
    EXPECT_EQ(select_pool_rate_head(h(7), /*in_chain=*/false, raw), h(11));
}

// ---- (2) zero-local-miner fallback: tallest raw head --------------------

TEST(DashPoolRateHead, NullVerifiedPicksTallestRawHead) {
    // The bootstrap case: no verified head, peers filled the raw chain. Pick the
    // tallest raw head (900 > 500 > 100).
    std::vector<RawChainHead> raw = {{h(1), 100}, {h(2), 900}, {h(3), 500}};
    EXPECT_EQ(select_pool_rate_head(uint256::ZERO, false, raw), h(2));
}

TEST(DashPoolRateHead, TieKeepsFirstSeenAtMaxHeight) {
    // Equal heights -> strictly-greater comparison keeps the FIRST at that max
    // (h(5), not h(9)), matching advertised_best_share()'s walk.
    std::vector<RawChainHead> raw = {{h(5), 800}, {h(9), 800}};
    EXPECT_EQ(select_pool_rate_head(uint256::ZERO, false, raw), h(5));
}

TEST(DashPoolRateHead, NullHashRawHeadsAreSkipped) {
    // A null-hash raw head is not selectable even if it sorts "first".
    std::vector<RawChainHead> raw = {{uint256::ZERO, 999}, {h(4), 300}};
    EXPECT_EQ(select_pool_rate_head(uint256::ZERO, false, raw), h(4));
}

// ---- (3) empty tracker -> null (caller holds last-good) -----------------

TEST(DashPoolRateHead, NoHeadsReturnsNull) {
    std::vector<RawChainHead> raw;
    EXPECT_TRUE(select_pool_rate_head(uint256::ZERO, false, raw).IsNull());
}

TEST(DashPoolRateHead, NullVerifiedAndOnlyNullRawHeadsReturnsNull) {
    std::vector<RawChainHead> raw = {{uint256::ZERO, 5}, {uint256::ZERO, 9}};
    EXPECT_TRUE(select_pool_rate_head(uint256::ZERO, false, raw).IsNull());
}

}  // namespace
