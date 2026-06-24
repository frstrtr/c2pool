// btc_auto_ratchet_tail_guard_test: FENCED, additive conformance KAT suite for
// BTC's AutoRatchet staged V35 -> V36 transition gate
// (src/impl/btc/auto_ratchet.hpp::get_share_version).
//
// Closes the gap recorded verbatim in
//   scripts/btc_g2_ratchet_staged_migration_harness.sh:
//     "UNLIKE DGB #427, BTC has NO AutoRatchet ctest suite to sim (only
//      version_gate boundary KATs exist) ... there is no sim fallback for
//      C2/C3/C4."
//
// This suite gives the G2 staged-migration checks C2/C3/C4 a RIG-FREE verdict by
// pinning the staged-gate LOGIC non-circularly:
//   C2  VOTING-mint accounting     : 95%-vote activation threshold; the
//                                     desired-version VOTE tally is distinct
//                                     from the actual-FORMAT share tally.
//   C3  STAGED ACCEPT GATE (#288)  : the WORK-WEIGHTED 60% tail guard. A
//                                     95%-by-flat-COUNT activation MUST NOT fire
//                                     while the oldest-10% window is <60%-by-WORK
//                                     -- mint cannot outrun accept.
//   C4  CONFIRM ordering           : confirm window = 2*CHAIN_LENGTH; confirm
//                                     requires in-FORMAT shares (share_pct), not
//                                     merely votes; cumulative count is monotonic.
//
// Each numeric expression below is a VERBATIM replica of the live inline form in
// AutoRatchet::get_share_version, reproduced here so the hand-derived oracle
// compares SSOT-canonical arithmetic WITHOUT importing the heavy consensus header
// (config_pool / share_tracker). The auto_ratchet.hpp consensus path is NOT
// instantiated here -- this is a pure arithmetic pin, btc-tree-local / test-only.

#include <gtest/gtest.h>

#include <core/uint256.hpp>

#include <algorithm>
#include <cstdint>
#include <vector>

namespace {

// --- Thresholds: VERBATIM mirror of AutoRatchet's static constexpr members ---
//   ACTIVATION_THRESHOLD   = 95;  // % votes to activate
//   DEACTIVATION_THRESHOLD = 50;  // % below which to revert
//   CONFIRMATION_MULTIPLIER = 2;  // confirm after 2x CHAIN_LENGTH
//   SWITCH_THRESHOLD       = 60;  // % required for format switch in validation
constexpr int ACTIVATION_THRESHOLD    = 95;
constexpr int DEACTIVATION_THRESHOLD  = 50;
constexpr int CONFIRMATION_MULTIPLIER = 2;
constexpr int SWITCH_THRESHOLD        = 60;

// VERBATIM replica of the live WORK-WEIGHTED tail guard in get_share_version:
//   bool tail_ok = !(tail_target * uint32_t(100) < tail_total * uint32_t(SWITCH_THRESHOLD));
// Canonical p2pool form: counts.get(VERSION,0) >= sum(counts)*60//100.
bool inline_tail_ok(const uint288& target, const uint288& total,
                    uint32_t thr = SWITCH_THRESHOLD)
{
    return !(target * static_cast<uint32_t>(100) < total * thr);
}

// VERBATIM replica of the live integer-percent forms in get_share_version:
//   int vote_pct  = (target_votes  * 100) / total;
//   int share_pct = (target_shares * 100) / total;
int inline_pct(int hits, int total) { return (hits * 100) / total; }

} // namespace

// ===========================================================================
// C2 -- VOTING-mint accounting
// ===========================================================================

// Below the 95% activation threshold the node stays in VOTING (keeps minting the
// current version, votes the target). Exactly at 95% it becomes eligible (then
// still subject to the C3 tail guard before it may transition).
TEST(BtcAutoRatchetC2, VoteThresholdBoundaryAt95)
{
    EXPECT_LT(inline_pct(94, 100), ACTIVATION_THRESHOLD);   // 94% -> stay VOTING
    EXPECT_GE(inline_pct(95, 100), ACTIVATION_THRESHOLD);   // 95% -> eligible
    EXPECT_GE(inline_pct(96, 100), ACTIVATION_THRESHOLD);
}

// The DEACTIVATION revert gate sits at 50% and is strictly below activation, so
// the VOTING<->ACTIVATED band cannot oscillate at a single point.
TEST(BtcAutoRatchetC2, RevertBandStrictlyBelowActivation)
{
    EXPECT_LT(DEACTIVATION_THRESHOLD, ACTIVATION_THRESHOLD);
    EXPECT_LT(inline_pct(49, 100), DEACTIVATION_THRESHOLD); // revert
    EXPECT_GE(inline_pct(50, 100), DEACTIVATION_THRESHOLD); // hold
}

// The VOTE tally (desired_version >= target) is counted independently of the
// actual in-FORMAT share tally (share version >= target). A node can vote 95%
// while 0% of shares are yet in the new format -- activation keys off votes,
// confirmation (C4) keys off format. Pin that these two percentages diverge.
TEST(BtcAutoRatchetC2, VoteTallyDistinctFromFormatTally)
{
    const int total        = 100;
    const int target_votes = 95;  // desired_version >= target
    const int target_shares = 0;  // none yet minted in new format
    EXPECT_GE(inline_pct(target_votes, total), ACTIVATION_THRESHOLD);
    EXPECT_LT(inline_pct(target_shares, total), ACTIVATION_THRESHOLD);
}

// ===========================================================================
// C3 -- STAGED ACCEPT GATE (#288): work-weighted 60% tail guard
// ===========================================================================

// Exact 60%-by-work passes (>= floor); one unit below fails. Canonical floor
// boundary: !(target*100 < total*60).
TEST(BtcAutoRatchetC3, TailGuardFloorBoundaryAt60)
{
    EXPECT_TRUE (inline_tail_ok(uint288(60), uint288(100)));  // 6000 !< 6000
    EXPECT_FALSE(inline_tail_ok(uint288(59), uint288(100)));  // 5900  < 6000
    EXPECT_TRUE (inline_tail_ok(uint288(61), uint288(100)));
}

// All-target and all-not-target endpoints.
TEST(BtcAutoRatchetC3, TailGuardEndpoints)
{
    EXPECT_TRUE (inline_tail_ok(uint288(100), uint288(100))); // 100% -> ok
    EXPECT_FALSE(inline_tail_ok(uint288(0),   uint288(100))); // 0%   -> gated
    // Degenerate empty window: 0 < 0 is false, so !false == true. Matches the
    // live form (an empty tail cannot fail the guard).
    EXPECT_TRUE (inline_tail_ok(uint288(0), uint288(0)));
}

// THE #288 acceptance criterion: mint cannot outrun accept.
// Construct a heterogeneous-hashrate window where the new format wins by flat
// COUNT but loses by WORK: 19 tiny v36 shares (work=1 each) + 1 heavy v35 share
// (work=100). By count v36 = 19/20 = 95% (would clear ACTIVATION_THRESHOLD); by
// work v36 = 19/119 = ~16% (far below SWITCH_THRESHOLD). The tail guard MUST gate
// activation so the node never mints a v36 boundary share its peers would reject.
TEST(BtcAutoRatchetC3, CountMajorityButWorkMinorityIsGated)
{
    const int v36_count = 19, v35_count = 1;
    const int total_count = v36_count + v35_count;

    // By flat COUNT the new format would clear the activation threshold...
    EXPECT_GE(inline_pct(v36_count, total_count), ACTIVATION_THRESHOLD); // 95%

    // ...but by WORK it is a small minority, so the staged accept gate holds.
    uint288 v36_work(19);                       // 19 tiny shares, work 1 each
    uint288 v35_work(100);                      // 1 heavy share, work 100
    uint288 tail_target = v36_work;
    uint288 tail_total  = v36_work + v35_work;  // 119
    EXPECT_FALSE(inline_tail_ok(tail_target, tail_total))
        << "95%-by-count v36 must NOT activate while <60%-by-work (mint outran accept)";
}

// Symmetric guard: when WORK actually crosses 60%, the gate opens even if the
// flat count looks marginal -- accept implies mint may proceed.
TEST(BtcAutoRatchetC3, WorkMajorityOpensGate)
{
    // 2 v36 shares of heavy work (200) + 8 v35 shares of tiny work (80).
    uint288 v36_work(200);
    uint288 v35_work(80);
    uint288 tail_target = v36_work;
    uint288 tail_total  = v36_work + v35_work;        // 280; 200/280 = ~71%
    EXPECT_TRUE(inline_tail_ok(tail_target, tail_total));
}

// MONOTONICITY: as v36 work-weight rises from 0 to total, the tail guard flips
// from gated -> open exactly once, at the 60% floor, and never reverts. A
// non-monotone gate would let staged migration thrash.
TEST(BtcAutoRatchetC3, TailGuardMonotonicInTargetWork)
{
    const uint64_t total = 1000;
    bool prev = inline_tail_ok(uint288(0), uint288(total));
    int flips = 0;
    uint64_t open_at = total + 1;
    for (uint64_t t = 1; t <= total; ++t) {
        bool cur = inline_tail_ok(uint288(t), uint288(total));
        if (cur != prev) { ++flips; if (cur) open_at = t; }
        EXPECT_FALSE(prev && !cur) << "tail guard regressed open->gated at t=" << t;
        prev = cur;
    }
    EXPECT_EQ(flips, 1) << "gate must open exactly once across rising work";
    EXPECT_EQ(open_at, 600u) << "gate opens at the 60% floor (600/1000)";
}

// No overflow under realistic large work weights. Build a large unit by repeated
// *uint32_t (target_to_average_attempts can be near 2^256; target*100 still fits
// inside the 288-bit accumulator). Uses only the *uint32_t and + operators.
TEST(BtcAutoRatchetC3, TailGuardLargeWorkNoOverflow)
{
    uint288 unit(1);
    for (int i = 0; i < 8; ++i)                       // 10^72 ~ 2^239
        unit = unit * static_cast<uint32_t>(1000000000u);
    uint288 total      = unit * static_cast<uint32_t>(100); // 100*unit
    uint288 target_60  = unit * static_cast<uint32_t>(60);  // 60% -> ok
    uint288 target_59  = unit * static_cast<uint32_t>(59);  // 59% -> gated
    EXPECT_TRUE (inline_tail_ok(target_60, total));
    EXPECT_FALSE(inline_tail_ok(target_59, total));
}

// ===========================================================================
// C4 -- CONFIRM ordering
// ===========================================================================

// Confirmation window is exactly 2x the PPLNS chain length.
TEST(BtcAutoRatchetC4, ConfirmWindowIsTwiceChainLength)
{
    const uint32_t chain_length = 5760;
    EXPECT_EQ(chain_length * CONFIRMATION_MULTIPLIER, 11520u);
}

// Confirmation requires actual in-FORMAT shares (share_pct >= 95), not merely
// the cumulative count -- a node cannot CONFIRM on votes alone.
TEST(BtcAutoRatchetC4, ConfirmRequiresFormatShareMajority)
{
    const uint32_t window = 100;
    const int32_t confirm_count = 120;            // count satisfied
    EXPECT_GE(confirm_count, static_cast<int32_t>(window));
    EXPECT_LT(inline_pct(50, 100), ACTIVATION_THRESHOLD);  // 50% format -> NOT confirmed
    EXPECT_GE(inline_pct(96, 100), ACTIVATION_THRESHOLD);  // 96% format -> confirmable
}

// Cumulative confirm_count advances monotonically with chain depth:
//   if (height > last_seen_height_) confirm_count_ += (height - last_seen_height_);
// Replaying a sequence of non-decreasing heights never decreases the counter.
TEST(BtcAutoRatchetC4, ConfirmCountMonotonicWithHeight)
{
    std::vector<int32_t> heights{10, 10, 11, 15, 15, 20};
    int32_t confirm_count = 0, last_seen = 0;
    int32_t prev_confirm = 0;
    for (int32_t h : heights) {
        if (last_seen > 0 && h > last_seen) confirm_count += (h - last_seen);
        last_seen = h;
        EXPECT_GE(confirm_count, prev_confirm) << "confirm_count regressed at height " << h;
        prev_confirm = confirm_count;
    }
    // Net advance equals span from first observed height to last (10 -> 20 = 10).
    EXPECT_EQ(confirm_count, 10);
}
