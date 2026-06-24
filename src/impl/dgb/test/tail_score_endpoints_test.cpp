// dgb tail-hashrate-score endpoints — chain-walk endpoint arithmetic KAT.
//
// FENCED, additive (no production code touched this slice). Pins
// src/impl/dgb/coin/tail_score_endpoints.hpp against the p2pool-dgb-scrypt
// data.py:843-855 ShareTracker.score() oracle:
//     head_height = self.verified.get_height(share_hash)
//     if head_height < self.net.CHAIN_LENGTH: return head_height, None
//     end_point = self.verified.get_nth_parent_hash(share_hash, CHAIN_LENGTH*15//16)
//     block_height = max(block_rel_height_func(...) for share in
//         self.verified.get_chain(end_point, CHAIN_LENGTH//16))
//     return CHAIN_LENGTH, get_delta(share_hash, end_point).work
//         / ((0 - block_height + 1) * PARENT.BLOCK_PERIOD)
//
// Every expectation is hand-derived from the oracle formula and the DGB net
// constants (CHAIN_LENGTH = 2880 mainnet / 400 testnet, PARENT.BLOCK_PERIOD =
// 75s), NOT read from the code under test. The chain-walk halves (get_nth_parent_hash,
// get_chain, get_delta) stay in ShareTracker; this header lifts only the integer
// endpoint offsets, the short-chain guard, the unresolvable-block fallback, and
// the span-clamp+divide. share_tracker.hpp is NOT rewired (delegation is the
// byte-identity follow-on). Pure header (uint288) -> links core only.
// MUST appear in BOTH this dir CMakeLists.txt AND the build.yml --target
// allowlist, or it becomes a #143 NOT_BUILT sentinel.

#include <impl/dgb/coin/tail_score_endpoints.hpp>

#include <core/uint256.hpp>  // uint288

#include <gtest/gtest.h>

// --- end-point offset = CHAIN_LENGTH*15//16 (Python floor div) --------------
TEST(DgbTailScoreEndpoints, EndpointOffsetMatchesOracle) {
    EXPECT_EQ(dgb::score_endpoint_offset(2880), 2700);  // 2880*15/16 = 43200/16
    EXPECT_EQ(dgb::score_endpoint_offset(400),  375);   // testnet: 400*15/16 = 6000/16
    EXPECT_EQ(dgb::score_endpoint_offset(16),   15);    // 16*15/16 = 15
    EXPECT_EQ(dgb::score_endpoint_offset(32),   30);    // 480/16
    EXPECT_EQ(dgb::score_endpoint_offset(0),    0);
}

// --- trailing-walk length = min(CHAIN_LENGTH//16, end_point_acc_height) -----
TEST(DgbTailScoreEndpoints, TailWalkCountMatchesOracleAndClamps) {
    EXPECT_EQ(dgb::score_tail_walk_count(2880, 5000), 180);  // min(180, 5000)
    EXPECT_EQ(dgb::score_tail_walk_count(2880, 100),  100);  // clamp to acc-height
    EXPECT_EQ(dgb::score_tail_walk_count(2880, 180),  180);  // exact boundary
    EXPECT_EQ(dgb::score_tail_walk_count(400,  5000), 25);   // testnet 400/16
    EXPECT_EQ(dgb::score_tail_walk_count(2880, 0),    0);    // <=0 -> caller early-returns
}

// --- short-chain guard: head_height < CHAIN_LENGTH -> score undefined -------
TEST(DgbTailScoreEndpoints, ShortChainGuardMatchesOracle) {
    EXPECT_TRUE (dgb::score_head_too_short(2879, 2880));  // one short of a full chain
    EXPECT_FALSE(dgb::score_head_too_short(2880, 2880));  // exactly full -> scored
    EXPECT_FALSE(dgb::score_head_too_short(5000, 2880));  // long -> scored
    EXPECT_TRUE (dgb::score_head_too_short(399,  400));   // testnet short
    EXPECT_FALSE(dgb::score_head_too_short(400,  400));   // testnet full
}

// --- unresolvable-block fallback: 1e6 confirmations (tiny but non-zero) -----
TEST(DgbTailScoreEndpoints, UnresolvableBlockFallbackMatchesOracle) {
    EXPECT_EQ(dgb::score_resolved_block_span(true,  4), 4);        // resolved, 3-deep
    EXPECT_EQ(dgb::score_resolved_block_span(true,  1), 1);        // resolved, tip
    EXPECT_EQ(dgb::score_resolved_block_span(false, 4), 1000000);  // window had none
    EXPECT_EQ(dgb::score_resolved_block_span(true,  0), 1000000);  // resolved <= 0
    EXPECT_EQ(dgb::score_resolved_block_span(true, -3), 1000000);  // negative -> fallback
}

// --- time span = block_span * BLOCK_PERIOD, clamped strictly positive -------
TEST(DgbTailScoreEndpoints, TimeSpanMatchesOracleAndClamps) {
    EXPECT_EQ(dgb::score_time_span(1, 75),       75);        // tip: 1*75
    EXPECT_EQ(dgb::score_time_span(4, 75),       300);       // 4-deep: 4*75
    EXPECT_EQ(dgb::score_time_span(1000000, 75), 75000000);  // fallback span
    EXPECT_EQ(dgb::score_time_span(0, 75),       1);         // clamp <=0
    EXPECT_EQ(dgb::score_time_span(1, 0),        1);         // zero period -> clamp
}

// --- final score = work / time_span (integer divide) -----------------------
TEST(DgbTailScoreEndpoints, ScoreValueMatchesOracle) {
    EXPECT_EQ(dgb::score_value(uint288(300),  75),  uint288(4));   // 300/75
    EXPECT_EQ(dgb::score_value(uint288(900),  300), uint288(3));   // 900/300
    EXPECT_EQ(dgb::score_value(uint288(0),    75),  uint288(0));   // no work
    EXPECT_EQ(dgb::score_value(uint288(1000000000ULL), 75000000), uint288(13));  // 1e9/75e6
}

// --- non-circular composite: full oracle scoring, hand-derived literals -----
// Case A (resolved, 4-deep tip block): CHAIN_LENGTH=2880, BLOCK_PERIOD=75,
//   work=900000, block_height=4 (resolved).
//   not short (2880>=2880); span=4; time_span=4*75=300; score=900000/300=3000.
TEST(DgbTailScoreEndpoints, CompositeResolvedScoreHandDerived) {
    ASSERT_FALSE(dgb::score_head_too_short(2880, 2880));
    int32_t span      = dgb::score_resolved_block_span(true, 4);   // 4
    int32_t time_span = dgb::score_time_span(span, 75);            // 300
    uint288 score     = dgb::score_value(uint288(900000), time_span);
    EXPECT_EQ(span, 4);
    EXPECT_EQ(time_span, 300);
    EXPECT_EQ(score, uint288(3000));  // 900000 / 300, hand-computed
}

// Case B (unresolvable window): work=750000000, no block resolves.
//   span=1000000; time_span=1000000*75=75000000; score=750000000/75000000=10.
TEST(DgbTailScoreEndpoints, CompositeUnresolvableScoreHandDerived) {
    int32_t span      = dgb::score_resolved_block_span(false, 0);  // 1000000
    int32_t time_span = dgb::score_time_span(span, 75);            // 75000000
    uint288 score     = dgb::score_value(uint288(750000000ULL), time_span);
    EXPECT_EQ(span, 1000000);
    EXPECT_EQ(time_span, 75000000);
    EXPECT_EQ(score, uint288(10));  // tiny but non-zero, hand-computed
}
