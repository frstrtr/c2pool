// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH v36-native MINT-side accept-floor auto-ratchet KAT.
//
// FENCED, additive (no production call site touched -- pins the pure free functions
// in src/impl/dash/auto_ratchet.hpp). Mirrors the dgb-scrypt oracle
// update_min_protocol_version (data.py:715-719):
//     minpver    = getattr(share.net, 'MINIMUM_PROTOCOL_VERSION', 1700)
//     newminpver = getattr(share.net, 'NEW_MINIMUM_PROTOCOL_VERSION', minpver)
//     if (counts is not None) and (minpver < newminpver):
//         if counts.get(share.VERSION, 0) >= sum(counts.itervalues())*95//100:
//             share.net.MINIMUM_PROTOCOL_VERSION = newminpver
//
// counts is the WORK-WEIGHTED get_desired_version_weights map -- each share weighted
// by target_to_average_attempts(target), keyed by desired_version, looked up by the
// best share VERSION. The cold floor 1700 is the DASH oracle net constant
// (frstrtr/p2pool-dash networks/dash.py:23, == config_pool.hpp MINIMUM_PROTOCOL_VERSION).
//
// TARGET below is a v36-successor floor STAND-IN: the DASH oracle has no
// NEW_MINIMUM_PROTOCOL_VERSION, so the concrete ratchet target is a c2pool v36-native
// choice made at the S8 wire-up (see auto_ratchet.hpp ORACLE NOTE). The KAT exercises
// the decision MATH, which is oracle-faithful independent of the target's value.
//
// The window the runtime samples is anchor = nth_parent(prev, CHAIN_LENGTH*9/10),
// size = CHAIN_LENGTH/10 -- the SAME window the 60% version-switch accept gate reads
// (version_negotiation.hpp). CL below is a stand-in CHAIN_LENGTH.
//
// Every expectation is hand-derived from the oracle formula. MUST appear in BOTH this
// dir CMakeLists.txt AND the build.yml --target allowlists (there are TWO), or it
// becomes a NOT_BUILT sentinel that silently passes.

#include <impl/dash/auto_ratchet.hpp>
#include <impl/dash/config_pool.hpp>            // COLD 1700 / NEW_MINIMUM 3600 crossing constants
#include <impl/dash/min_protocol_gate.hpp>      // MinProtocolGate — LIVE handshake accept gate
#include <impl/dash/version_activation_latch.hpp> // VOTING->ACTIVATED->CONFIRMED state machine
#include <impl/dash/version_negotiation.hpp>    // 60% weighted successor gate

#include <core/uint256.hpp>  // uint288

#include <algorithm>
#include <gtest/gtest.h>

namespace {

uint288 u(uint64_t n) { return uint288(n); }

// 2^k as a uint288 -- the scale of a real target_to_average_attempts (ttaa(2^k-1)
// = 2^(256-k)), so the boundary/overflow cases run at consensus magnitudes.
uint288 pow2(unsigned k) {
    uint288 v = u(1);
    for (unsigned i = 0; i < k; ++i) v = v * uint32_t(2);
    return v;
}

constexpr uint32_t COLD   = 1700;  // DASH oracle dash.py:23 MINIMUM_PROTOCOL_VERSION
constexpr uint32_t TARGET = 3600;  // v36-successor floor STAND-IN (set at S8 wire-up)

}  // namespace

// ============================================================================
// Pure ratchet -- dash::ratchet_min_protocol_version (oracle dict-branch)
// ============================================================================

// --- guard: floor already at/above target -> no-op (minpver < newminpver false)
TEST(DashAutoRatchet, AlreadyAtTargetIsNoOp) {
    EXPECT_EQ(dash::ratchet_min_protocol_version({{36, u(100)}}, 36, TARGET, TARGET), TARGET);
    EXPECT_EQ(dash::ratchet_min_protocol_version({{36, u(100)}}, 36, TARGET + 1, TARGET), TARGET + 1);
}

// --- unanimous support -> ratchet cold floor up to target -------------------
TEST(DashAutoRatchet, UnanimousRatchets) {
    EXPECT_EQ(dash::ratchet_min_protocol_version({{36, u(100)}}, 36, COLD, TARGET), TARGET);
}

// --- exactly 95% (sum=100, best=95) -> 95 >= 100*95//100=95 -> ratchet -------
TEST(DashAutoRatchet, Exactly95PercentRatchets) {
    auto w = std::map<uint64_t, uint288>{{36, u(95)}, {35, u(5)}};
    EXPECT_EQ(dash::ratchet_min_protocol_version(w, 36, COLD, TARGET), TARGET);
}

// --- just below 95% (sum=100, best=94) -> 94 >= 95 false -> stays cold -------
TEST(DashAutoRatchet, JustBelow95PercentStaysCold) {
    auto w = std::map<uint64_t, uint288>{{36, u(94)}, {35, u(6)}};
    EXPECT_EQ(dash::ratchet_min_protocol_version(w, 36, COLD, TARGET), COLD);
}

// --- floor-div vs cross-multiply BOUNDARY: sum=101, best=95.
//     oracle floor: 95 >= floor(101*95/100)=floor(95.95)=95 -> RATCHET.
//     cross-mult (best*100 >= sum*95): 9500 >= 9595 false -> would NOT ratchet.
//     Proves the function floor-divides like the oracle, not cross-mults.
TEST(DashAutoRatchet, FloorDivBoundaryRatchets) {
    auto w = std::map<uint64_t, uint288>{{36, u(95)}, {35, u(6)}};  // sum=101
    EXPECT_EQ(dash::ratchet_min_protocol_version(w, 36, COLD, TARGET), TARGET);
}

// --- best version absent from the map -> best_weight 0 -> stays cold ---------
TEST(DashAutoRatchet, BestVersionAbsentStaysCold) {
    EXPECT_EQ(dash::ratchet_min_protocol_version({{35, u(100)}}, 36, COLD, TARGET), COLD);
}

// --- empty window: 0 >= 0*95//100=0 -> oracle ratchets (counts={} != None).
//     The None-guard is the CALL-SITE job; the pure fn mirrors the dict-branch.
TEST(DashAutoRatchet, EmptyWindowMirrorsOracleDictBranch) {
    EXPECT_EQ(dash::ratchet_min_protocol_version({}, 36, COLD, TARGET), TARGET);
}

// --- consensus-magnitude weights (2^256-scale), no overflow in total*95 ------
TEST(DashAutoRatchet, ConsensusMagnitudeNoOverflow) {
    uint288 unit = pow2(256);
    uint288 best = unit; for (int i = 1; i < 96; ++i) best = best + unit;   // 96 * 2^256
    uint288 rest = unit; for (int i = 1; i < 4;  ++i) rest = rest + unit;   //  4 * 2^256
    auto w = std::map<uint64_t, uint288>{{36, best}, {35, rest}};
    EXPECT_EQ(dash::ratchet_min_protocol_version(w, 36, COLD, TARGET), TARGET);
}

// ============================================================================
// THE GAP-CLOSING ASSERT (integrator #357 follow-up #2): the WEIGHTED decision
// must DIVERGE from the PLAIN-COUNT decision on a crafted window. If the ratchet
// ever regressed to consuming a flat count, this test flips red.
// ============================================================================

// Crafted window: v36 is a single HEAVY share (dominant WORK); v35 is ten TINY
// shares (dominant COUNT). Best share VERSION = 36.
//   WEIGHTED: v36=1000, v35=10, total=1010 -> 1000 >= 1010*95//100=959 -> RATCHET.
//   FLAT:     v36=1,    v35=10, total=11   -> 1    >= 11*95//100=10     -> stays COLD.
// Same window, same best_version, full window present -> opposite decisions.
TEST(DashAutoRatchet, WeightedDivergesFromPlainCount) {
    std::vector<dash::VersionWork> window;
    for (int i = 0; i < 10; ++i) window.push_back({35, u(1)});  // 10 tiny v35 shares
    window.push_back({36, u(1000)});                            // 1 heavy v36 share

    auto weighted = dash::accumulate_version_weights(window);
    auto flat     = dash::accumulate_version_counts(window);

    const int32_t CL = 100;  // full window present (parent_height >= CL) for both arms

    const uint32_t weighted_decision =
        dash::apply_min_protocol_ratchet_decision(CL, CL, weighted, 36, COLD, TARGET);
    const uint32_t flat_decision =
        dash::apply_min_protocol_ratchet_decision(CL, CL, flat, 36, COLD, TARGET);

    EXPECT_EQ(weighted_decision, TARGET);  // work-weighted -> ratchets
    EXPECT_EQ(flat_decision,     COLD);    // plain-count   -> does NOT ratchet
    EXPECT_NE(weighted_decision, flat_decision);  // the divergence is the whole point
}

// ============================================================================
// apply_min_protocol_ratchet_decision -- RUNTIME WIRING full-window guard
// ============================================================================

constexpr int32_t CL = 100;  // stand-in CHAIN_LENGTH for the window guard

// --- FULL-WINDOW GUARD: parent_height < CHAIN_LENGTH -> NEVER lift, even when the
//     partial window is unanimous. Fresh-node bug the wiring exists to prevent.
TEST(DashAutoRatchetWiring, ShortChainNeverLifts) {
    auto w = std::map<uint64_t, uint288>{{36, u(100)}};  // unanimous
    EXPECT_EQ(dash::ratchet_min_protocol_version(w, 36, COLD, TARGET), TARGET);  // pure fn would
    EXPECT_EQ(dash::apply_min_protocol_ratchet_decision(CL - 1, CL, w, 36, COLD, TARGET), COLD);
    EXPECT_EQ(dash::apply_min_protocol_ratchet_decision(0,      CL, w, 36, COLD, TARGET), COLD);
}

// --- empty window + short chain -> no lift.
TEST(DashAutoRatchetWiring, ShortChainEmptyWindowNoLift) {
    EXPECT_EQ(dash::apply_min_protocol_ratchet_decision(CL - 1, CL, {}, 36, COLD, TARGET), COLD);
}

// --- FULL WINDOW present (parent_height >= CHAIN_LENGTH) + unanimous -> lift.
TEST(DashAutoRatchetWiring, FullWindowUnanimousLifts) {
    auto w = std::map<uint64_t, uint288>{{36, u(100)}};
    EXPECT_EQ(dash::apply_min_protocol_ratchet_decision(CL,     CL, w, 36, COLD, TARGET), TARGET);
    EXPECT_EQ(dash::apply_min_protocol_ratchet_decision(CL * 5, CL, w, 36, COLD, TARGET), TARGET);
}

// --- FULL WINDOW present but best < 95% -> stays cold (delegates to pure fn).
TEST(DashAutoRatchetWiring, FullWindowBelow95StaysCold) {
    auto w = std::map<uint64_t, uint288>{{36, u(94)}, {35, u(6)}};  // sum=100, 94<95
    EXPECT_EQ(dash::apply_min_protocol_ratchet_decision(CL, CL, w, 36, COLD, TARGET), COLD);
}

// --- already at/above target short-circuits regardless of window/height (latch).
TEST(DashAutoRatchetWiring, AlreadyAtTargetShortCircuits) {
    auto w = std::map<uint64_t, uint288>{{36, u(100)}};
    EXPECT_EQ(dash::apply_min_protocol_ratchet_decision(CL, CL, w, 36, TARGET, TARGET), TARGET);
    EXPECT_EQ(dash::apply_min_protocol_ratchet_decision(0,  CL, w, 36, TARGET, TARGET), TARGET);
}

// ============================================================================
// RUNTIME WIRE-UP KATs (branch dash/v36-ratchet-wireup). The pure decision above
// is proven; these pin the node.cpp consumer's COMPOSED behavior:
//   * the crossing constants are the DASH-native 1700 -> 3600 pair,
//   * the LIVE handshake gate (MinProtocolGate + the atomic-runtime max() the node
//     composes in handle_version) enforces the crossing floor AND stays backward-
//     compatible pre-crossing,
//   * the node's DASH-specific best_desired>=36 SAFETY GUARD is necessary (the raw
//     decision would false-lift on a fully-agreed pre-crossing chain),
//   * the VOTING->ACTIVATED->CONFIRMED latch is driven by the SAME 95% verdict,
//   * the 60% weighted successor gate (the mint<->accept coupling the crossing rides).
// ============================================================================

// The wire-up constants ARE the DASH-native crossing pair (config_pool.hpp SSOT).
TEST(DashRatchetCrossing, ConstantsAreDashNativeCrossingPair) {
    EXPECT_EQ(dash::SharechainConfig::MINIMUM_PROTOCOL_VERSION,     COLD);    // 1700 cold
    EXPECT_EQ(dash::SharechainConfig::NEW_MINIMUM_PROTOCOL_VERSION, TARGET);  // 3600 ratchet target
    EXPECT_EQ(dash::SharechainConfig::ADVERTISED_PROTOCOL_VERSION,  TARGET);  // 3600 v36 advert >= target
}

// The effective floor the node's handle_version composes: max(operator knob,
// atomic auto-ratchet floor). Mirrors src/impl/dash/node.hpp handle_version.
static uint32_t effective_floor(uint32_t operator_knob, uint32_t runtime_ratchet) {
    return std::max(operator_knob, runtime_ratchet);
}

// BACKWARD-COMPAT (item 6d): PRE-crossing, both the operator knob and the runtime
// ratchet sit at the cold 1700 floor, so a legacy DASH peer advertising 1700 — and a
// v36-capable peer advertising 3600 — are BOTH admitted. The node must still JOIN at
// the current protocol; the crossing is opt-in via the ratchet, never a hard cut.
TEST(DashRatchetCrossing, PreCrossingAdmitsLegacyAndV36Peers) {
    dash::MinProtocolGate gate;  // default operator knob = 1700
    const uint32_t runtime = COLD;  // m_runtime_min_protocol_version seed (pre-ratchet)
    const uint32_t floor = effective_floor(gate.min_version, runtime);
    EXPECT_EQ(floor, COLD);
    EXPECT_GE(1700u, floor);            // legacy peer advertising 1700 admitted
    EXPECT_TRUE(1700u >= floor);
    EXPECT_TRUE(3600u >= floor);        // v36-advertising peer admitted too
    EXPECT_FALSE(1699u >= floor);       // genuinely below-floor peer still rejected
}

// CROSSING-FLOOR ENFORCEMENT (item 6c): once apply_min_protocol_ratchet lifts the
// atomic runtime floor to 3600, the composed effective floor rejects legacy 1700
// peers and admits only >= 3600 (v36) peers — the crossing has partitioned legacy off.
TEST(DashRatchetCrossing, PostCrossingRejectsLegacyAdmitsV36) {
    dash::MinProtocolGate gate;  // operator knob still cold 1700 (auto-ratchet drives it)
    const uint32_t runtime = TARGET;  // ratchet has lifted the atomic to 3600
    const uint32_t floor = effective_floor(gate.min_version, runtime);
    EXPECT_EQ(floor, TARGET);
    EXPECT_FALSE(1700u >= floor);       // legacy 1700 peer now REJECTED
    EXPECT_FALSE(3599u >= floor);       // just-below-target rejected
    EXPECT_TRUE(3600u >= floor);        // v36 peer admitted
}

// SAFETY GUARD RATIONALE (DASH divergence from dgb): DASH has no v36 share TYPE, so
// the node keys the ratchet on the best share's m_desired_version VOTE and guards
// best_desired >= 36. This test proves the guard is NECESSARY: on a fully-agreed
// PRE-crossing chain everybody desires v16, and the raw decision keyed on 16 WOULD
// lift the floor to 3600 (partitioning the pool). The node's >=36 guard is what
// prevents that; keyed on 36 (the crossing vote) with a 100%-v16 window stays COLD.
TEST(DashRatchetCrossing, GuardPreventsPreCrossingFalseLift) {
    auto all_v16 = std::map<uint64_t, uint288>{{16, u(100)}};  // unanimous pre-crossing
    // Raw decision keyed on the CURRENT vote (16): weights[16]=100% -> WOULD lift.
    EXPECT_EQ(dash::apply_min_protocol_ratchet_decision(CL, CL, all_v16, 16, COLD, TARGET),
              TARGET);  // <-- the danger the node's best_desired>=36 guard blocks
    // Keyed on the crossing vote (36): weights[36]=0 -> stays COLD (correct).
    EXPECT_EQ(dash::apply_min_protocol_ratchet_decision(CL, CL, all_v16, 36, COLD, TARGET),
              COLD);
}

// STATE MACHINE (item 6a): the VOTING->ACTIVATED->CONFIRMED latch is driven by the
// SAME 95% work-weighted verdict the accept-floor ratchet uses. We synthesize a
// window that has crossed (v36 holds >=95% by work), feed the ratchet's own verdict
// into the latch, and assert the progression + the pre-confirmation revert.
TEST(DashRatchetCrossing, LatchDrivenByRatchetVerdict) {
    namespace val = dash::version_activation_latch;
    // Crossed window: v36 heavy (work 96), v16 light (work 4) -> 96 >= 100*95//100=95.
    auto crossed = std::map<uint64_t, uint288>{{36, u(96)}, {16, u(4)}};
    const bool crossed_active =
        dash::apply_min_protocol_ratchet_decision(CL, CL, crossed, 36, COLD, TARGET) == TARGET;
    EXPECT_TRUE(crossed_active);  // the ratchet fires -> the latch's "active" input

    val::ActivationLatch latch;
    latch.confirm_span = 10;  // short span so the KAT need not walk 2*CHAIN_LENGTH
    EXPECT_EQ(latch.state, val::LatchState::Voting);

    latch.observe(crossed_active, /*height=*/100);
    EXPECT_EQ(latch.state, val::LatchState::Activated);
    EXPECT_EQ(latch.activated_height, 100u);

    // Sustained past the span -> CONFIRMED (irreversible).
    latch.observe(crossed_active, /*height=*/111);  // 111-100=11 >= span 10
    EXPECT_EQ(latch.state, val::LatchState::Confirmed);
    latch.observe(false, /*height=*/200);  // a later dip cannot un-confirm
    EXPECT_EQ(latch.state, val::LatchState::Confirmed);

    // A pre-confirmation dip reverts ACTIVATED -> VOTING (crossing was not real).
    val::ActivationLatch latch2;
    latch2.confirm_span = 10;
    latch2.observe(true, 100);
    EXPECT_EQ(latch2.state, val::LatchState::Activated);
    latch2.observe(false, 105);  // dip before the span elapsed
    EXPECT_EQ(latch2.state, val::LatchState::Voting);
}

// 60% WEIGHTED SUCCESSOR GATE (item 6b): the mint<->accept coupling the crossing
// rides. successor_switch_allowed consumes the WORK-WEIGHTED tally (not a flat count)
// and clears at exactly 60% by work. This is the gate a 36-desiring share must pass.
TEST(DashRatchetCrossing, SuccessorGateIsSixtyPercentByWork) {
    namespace vn = dash::version_negotiation;
    // Exactly 60% by work -> allowed (have*100 >= total*60, 60*100 >= 100*60).
    EXPECT_TRUE(vn::successor_switch_allowed({{16, u(40)}, {36, u(60)}}, 36));
    // Just below 60% -> rejected.
    EXPECT_FALSE(vn::successor_switch_allowed({{16, u(41)}, {36, u(59)}}, 36));
    // Empty tally -> rejected (no support window).
    EXPECT_FALSE(vn::successor_switch_allowed({}, 36));
}

// The successor gate is WORK-weighted, not flat-count: one heavy v36 share outvotes
// many tiny v16 shares. Guards the same F10 divergence the accept-floor ratchet does.
TEST(DashRatchetCrossing, SuccessorGateIsWeightedNotFlatCount) {
    namespace vn = dash::version_negotiation;
    // 1 heavy v36 (work 70) vs 9 tiny v16 (work 1 each = 9). By WORK: 70/79 = 88% -> pass.
    // By flat COUNT it would be 1/10 = 10% -> fail. Proves the weighting.
    auto weights = std::map<uint64_t, uint288>{{36, u(70)}, {16, u(9)}};
    EXPECT_TRUE(vn::successor_switch_allowed(weights, 36));
}