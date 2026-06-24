// dgb desired-version tally -- version->work / version->count accumulation KAT.
//
// FENCED, additive (no production code touched this slice). Pins
// src/impl/dgb/coin/desired_version_tally.hpp against the p2pool-dgb-scrypt
// data.py:918-922 get_desired_version_counts oracle:
//     res = {}
//     for share in tracker.get_chain(best_share_hash, dist):
//         res[share.desired_version] = res.get(share.desired_version, 0) \
//             + bitcoin_data.target_to_average_attempts(share.target)
//     return res
//
// The oracle weights each share by target_to_average_attempts(share.target);
// c2pool exposes that as get_desired_version_weights (CONSENSUS gate input) with
// per-share weight = ShareIndex::work = chain::target_to_average_attempts(
// chain::bits_to_target(m_bits)). The flat-count accumulator is diagnostics-only
// and has NO oracle equivalent (the oracle has no flat count) -- it is pinned
// here only to lock the documented divergence (each share == 1, work ignored).
//
// Every expectation is hand-derived from the oracle formula. The work-equivalence
// anchor uses targets whose target_to_average_attempts is exactly computable by
// hand: ttaa(t) = 2^256 / (t + 1), so for t = 2^k - 1, t + 1 = 2^k and
// ttaa = 2^(256-k). The chain-walk + lookbehind clamp stay in ShareTracker; this
// header lifts ONLY the per-version map accumulation. share_tracker.hpp is NOT
// rewired (delegation is the byte-identity follow-on). Pure header (uint288) ->
// links core only. MUST appear in BOTH this dir CMakeLists.txt AND the build.yml
// --target allowlist, or it becomes a #143 NOT_BUILT sentinel.

#include <impl/dgb/coin/desired_version_tally.hpp>

#include <core/uint256.hpp>      // uint288
#include <core/target_utils.hpp> // chain::target_to_average_attempts

#include <gtest/gtest.h>

namespace {

uint288 u(uint64_t n) { return uint288(n); }

}  // namespace

// --- empty window -> empty maps (the actual<=0 early-return shape) ----------
TEST(DgbDesiredVersionTally, EmptyWindowYieldsEmptyMaps) {
    EXPECT_TRUE(dgb::accumulate_version_weights({}).empty());
    EXPECT_TRUE(dgb::accumulate_version_counts({}).empty());
}

// --- single share: one bucket, weight == its work, count == 1 ---------------
TEST(DgbDesiredVersionTally, SingleShareSingleBucket) {
    auto w = dgb::accumulate_version_weights({{36, u(42)}});
    ASSERT_EQ(w.size(), 1u);
    EXPECT_EQ(w[36], u(42));

    auto c = dgb::accumulate_version_counts({36});
    ASSERT_EQ(c.size(), 1u);
    EXPECT_EQ(c[36], 1);
}

// --- same version, many shares: weights sum, count increments ---------------
TEST(DgbDesiredVersionTally, SameVersionAccumulates) {
    auto w = dgb::accumulate_version_weights({{36, u(10)}, {36, u(20)}, {36, u(30)}});
    ASSERT_EQ(w.size(), 1u);
    EXPECT_EQ(w[36], u(60));  // 10 + 20 + 30

    auto c = dgb::accumulate_version_counts({36, 36, 36});
    EXPECT_EQ(c[36], 3);
}

// --- multiple versions are bucketed independently ---------------------------
TEST(DgbDesiredVersionTally, MultipleVersionsBucketed) {
    auto w = dgb::accumulate_version_weights(
        {{35, u(5)}, {36, u(11)}, {35, u(7)}});
    ASSERT_EQ(w.size(), 2u);
    EXPECT_EQ(w[35], u(12));  // 5 + 7
    EXPECT_EQ(w[36], u(11));

    auto c = dgb::accumulate_version_counts({35, 36, 35});
    EXPECT_EQ(c[35], 2);
    EXPECT_EQ(c[36], 1);
}

// --- NON-CIRCULAR oracle anchor: per-share weight == target_to_average_attempts,
//     summed per version, matches data.py:918 res[dv] += ttaa(target). ---------
//     t = 2^255-1 -> ttaa = 2 ; t = 2^254-1 -> ttaa = 4 ; t = 2^253-1 -> ttaa = 8
TEST(DgbDesiredVersionTally, WorkWeightedMatchesOracleAttempts) {
    uint256 t255, t254, t253;
    t255.SetHex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // 2^255-1
    t254.SetHex("3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // 2^254-1
    t253.SetHex("1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // 2^253-1

    const uint288 a255 = chain::target_to_average_attempts(t255);
    const uint288 a254 = chain::target_to_average_attempts(t254);
    const uint288 a253 = chain::target_to_average_attempts(t253);

    // Hand-derived ttaa = 2^(256-k). These also non-circularly pin the work def.
    ASSERT_EQ(a255, u(2));
    ASSERT_EQ(a254, u(4));
    ASSERT_EQ(a253, u(8));

    // v36 has two shares (work 2 and 4), v35 has one share (work 8).
    auto w = dgb::accumulate_version_weights(
        {{36, a255}, {35, a253}, {36, a254}});
    ASSERT_EQ(w.size(), 2u);
    EXPECT_EQ(w[36], u(6));  // 2 + 4
    EXPECT_EQ(w[35], u(8));  // 8
}

// --- flat count is NOT work-weighted: pins the documented divergence ---------
TEST(DgbDesiredVersionTally, FlatCountIgnoresWork) {
    // Three v36 shares with wildly different work: weights sum the work,
    // counts treat each as exactly 1 (diagnostics-only, never the gate).
    auto w = dgb::accumulate_version_weights({{36, u(1)}, {36, u(1000)}, {36, u(7)}});
    EXPECT_EQ(w[36], u(1008));

    auto c = dgb::accumulate_version_counts({36, 36, 36});
    EXPECT_EQ(c[36], 3);  // not 1008 -- work is ignored
}
