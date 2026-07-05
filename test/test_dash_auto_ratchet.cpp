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

#include <core/uint256.hpp>  // uint288

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
