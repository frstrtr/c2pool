// SPDX-License-Identifier: AGPL-3.0-or-later
// dgb runtime P2P accept-floor RATCHET KAT.
//
// FENCED, additive (no production code touched -- pins the pure free function
// dgb::ratchet_min_protocol_version in coin/desired_version_tally.hpp). Mirrors
// the p2pool-dgb-scrypt update_min_protocol_version oracle (data.py:857-863):
//     def update_min_protocol_version(counts, share):
//         minpver    = getattr(share.net, "MINIMUM_PROTOCOL_VERSION", 1400)
//         newminpver = share.MINIMUM_PROTOCOL_VERSION
//         if (counts is not None) and (minpver < newminpver):
//             if counts.get(share.VERSION, 0) >= sum(counts.itervalues())*95//100:
//                 share.net.MINIMUM_PROTOCOL_VERSION = newminpver
//
// counts is the WORK-WEIGHTED get_desired_version_counts map (each share weighted
// by target_to_average_attempts, keyed by desired_version, looked up by the best
// share VERSION) -- c2pool exposes it as get_desired_version_weights. The cold
// floor 1400 / ratchet target 3500 are the oracle p2p.py:153 getattr fallback and
// data.py:81 BaseShare.MINIMUM_PROTOCOL_VERSION (== config_pool.hpp
// MINIMUM_PROTOCOL_VERSION / SHARE_MINIMUM_PROTOCOL_VERSION, step-1 #599).
//
// Every expectation is hand-derived from the oracle formula. MUST appear in BOTH
// this dir CMakeLists.txt AND the build.yml --target allowlist, or it becomes a
// #143 NOT_BUILT sentinel.

#include <impl/dgb/coin/desired_version_tally.hpp>

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

constexpr uint32_t COLD   = 1400;  // oracle p2p.py:153 getattr fallback
constexpr uint32_t TARGET = 3500;  // oracle data.py:81 BaseShare.MINIMUM_PROTOCOL_VERSION

}  // namespace

// --- guard: floor already at/above target -> no-op (minpver < newminpver false)
TEST(DgbMinProtocolRatchet, AlreadyAtTargetIsNoOp) {
    EXPECT_EQ(dgb::ratchet_min_protocol_version({{36, u(100)}}, 36, TARGET, TARGET), TARGET);
    EXPECT_EQ(dgb::ratchet_min_protocol_version({{36, u(100)}}, 36, TARGET + 1, TARGET), TARGET + 1);
}

// --- unanimous support -> ratchet cold floor up to target -------------------
TEST(DgbMinProtocolRatchet, UnanimousRatchets) {
    EXPECT_EQ(dgb::ratchet_min_protocol_version({{36, u(100)}}, 36, COLD, TARGET), TARGET);
}

// --- exactly 95% (sum=100, best=95) -> 95 >= 100*95//100=95 -> ratchet -------
TEST(DgbMinProtocolRatchet, Exactly95PercentRatchets) {
    auto w = std::map<uint64_t, uint288>{{36, u(95)}, {35, u(5)}};
    EXPECT_EQ(dgb::ratchet_min_protocol_version(w, 36, COLD, TARGET), TARGET);
}

// --- just below 95% (sum=100, best=94) -> 94 >= 95 false -> stays cold -------
TEST(DgbMinProtocolRatchet, JustBelow95PercentStaysCold) {
    auto w = std::map<uint64_t, uint288>{{36, u(94)}, {35, u(6)}};
    EXPECT_EQ(dgb::ratchet_min_protocol_version(w, 36, COLD, TARGET), COLD);
}

// --- floor-div vs cross-multiply BOUNDARY: sum=101, best=95.
//     oracle floor: 95 >= floor(101*95/100)=floor(95.95)=95 -> RATCHET.
//     cross-mult (best*100 >= sum*95): 9500 >= 9595 false -> would NOT ratchet.
//     This case proves the function floor-divides like the oracle, not cross-mults.
TEST(DgbMinProtocolRatchet, FloorDivBoundaryRatchets) {
    auto w = std::map<uint64_t, uint288>{{36, u(95)}, {35, u(6)}};  // sum=101
    EXPECT_EQ(dgb::ratchet_min_protocol_version(w, 36, COLD, TARGET), TARGET);
}

// --- best version absent from the map -> best_weight 0 -> stays cold ---------
TEST(DgbMinProtocolRatchet, BestVersionAbsentStaysCold) {
    EXPECT_EQ(dgb::ratchet_min_protocol_version({{35, u(100)}}, 36, COLD, TARGET), COLD);
}

// --- empty window: 0 >= 0*95//100=0 -> oracle ratchets (counts={} != None).
//     The None-guard is the CALL-SITE job (oracle main.py:216 only calls when
//     len(shares) > CHAIN_LENGTH); the pure function mirrors the dict-branch.
TEST(DgbMinProtocolRatchet, EmptyWindowMirrorsOracleDictBranch) {
    EXPECT_EQ(dgb::ratchet_min_protocol_version({}, 36, COLD, TARGET), TARGET);
}

// --- work-weighted, NOT flat count: version 35 has the most SHARES but version
//     36 holds the dominant WORK. ratchet keys on work (get_desired_version_weights).
//     Build the map through accumulate_version_weights to exercise the real pipe.
TEST(DgbMinProtocolRatchet, WorkWeightedNotFlatCount) {
    // ten tiny v35 shares (work 1 each = 10) + one heavy v36 share (work 1000).
    std::vector<dgb::VersionWork> window;
    for (int i = 0; i < 10; ++i) window.push_back({35, u(1)});
    window.push_back({36, u(1000)});  // total=1010, best(36)=1000 >= 1010*95//100=959
    auto w = dgb::accumulate_version_weights(window);
    EXPECT_EQ(dgb::ratchet_min_protocol_version(w, 36, COLD, TARGET), TARGET);
    // flat count would give v35 ten shares vs v36 one -> would NOT ratchet on 36.
}

// --- consensus-magnitude weights (2^256-scale), no overflow in total*95 ------
TEST(DgbMinProtocolRatchet, ConsensusMagnitudeNoOverflow) {
    // 96 * 2^256 at v36, 4 * 2^256 at v35: total=100*2^256, best=96*2^256 >= 95% -> ratchet.
    uint288 unit = pow2(256);
    uint288 best = unit; for (int i = 1; i < 96; ++i) best = best + unit;   // 96 * 2^256
    uint288 rest = unit; for (int i = 1; i < 4;  ++i) rest = rest + unit;   //  4 * 2^256
    auto w = std::map<uint64_t, uint288>{{36, best}, {35, rest}};
    EXPECT_EQ(dgb::ratchet_min_protocol_version(w, 36, COLD, TARGET), TARGET);
}

// ============================================================================
// apply_min_protocol_ratchet_decision -- the RUNTIME WIRING guard (follow-on to
// the pure ratchet above). Adds the oracle main.py:212 full-window guard
// (len(shares) > CHAIN_LENGTH) the pure function deliberately omits. CL below is
// a stand-in CHAIN_LENGTH; parent_height is the height of the best share's parent.
// ============================================================================

constexpr int32_t CL = 100;  // stand-in CHAIN_LENGTH for the window guard

// --- FULL-WINDOW GUARD: parent_height < CHAIN_LENGTH -> NEVER lift, even when the
//     (partial) window is unanimous. This is the fresh-node bug the wiring exists to
//     prevent: without it a young chain would lock the floor to 3500 and reject every
//     legitimate peer. Contrast EmptyWindowMirrorsOracleDictBranch: the PURE fn
//     ratchets on the same weights; the DECISION fn must NOT (no full window yet).
TEST(DgbMinProtocolRatchetWiring, ShortChainNeverLifts) {
    auto w = std::map<uint64_t, uint288>{{36, u(100)}};  // unanimous
    // pure fn would ratchet...
    EXPECT_EQ(dgb::ratchet_min_protocol_version(w, 36, COLD, TARGET), TARGET);
    // ...but the decision guard holds it cold while parent_height < CL.
    EXPECT_EQ(dgb::apply_min_protocol_ratchet_decision(CL - 1, CL, w, 36, COLD, TARGET), COLD);
    // exactly one short of a full window still holds.
    EXPECT_EQ(dgb::apply_min_protocol_ratchet_decision(0, CL, w, 36, COLD, TARGET), COLD);
}

// --- empty window + short chain -> no lift (guards the EmptyWindowMirrorsOracle
//     dict-branch behaviour behind the full-window precondition).
TEST(DgbMinProtocolRatchetWiring, ShortChainEmptyWindowNoLift) {
    EXPECT_EQ(dgb::apply_min_protocol_ratchet_decision(CL - 1, CL, {}, 36, COLD, TARGET), COLD);
}

// --- FULL WINDOW present (parent_height >= CHAIN_LENGTH) + unanimous -> lift.
TEST(DgbMinProtocolRatchetWiring, FullWindowUnanimousLifts) {
    auto w = std::map<uint64_t, uint288>{{36, u(100)}};
    EXPECT_EQ(dgb::apply_min_protocol_ratchet_decision(CL, CL, w, 36, COLD, TARGET), TARGET);
    EXPECT_EQ(dgb::apply_min_protocol_ratchet_decision(CL * 5, CL, w, 36, COLD, TARGET), TARGET);
}

// --- FULL WINDOW present but best < 95% -> stays cold (delegates to pure fn).
TEST(DgbMinProtocolRatchetWiring, FullWindowBelow95StaysCold) {
    auto w = std::map<uint64_t, uint288>{{36, u(94)}, {35, u(6)}};  // sum=100, 94<95
    EXPECT_EQ(dgb::apply_min_protocol_ratchet_decision(CL, CL, w, 36, COLD, TARGET), COLD);
}

// --- already at/above target short-circuits regardless of window/height.
TEST(DgbMinProtocolRatchetWiring, AlreadyAtTargetShortCircuits) {
    auto w = std::map<uint64_t, uint288>{{36, u(100)}};
    EXPECT_EQ(dgb::apply_min_protocol_ratchet_decision(CL, CL, w, 36, TARGET, TARGET), TARGET);
    // even with a short chain the latch holds at target (never lowers).
    EXPECT_EQ(dgb::apply_min_protocol_ratchet_decision(0, CL, w, 36, TARGET, TARGET), TARGET);
}