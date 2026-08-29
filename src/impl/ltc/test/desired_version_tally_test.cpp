// SPDX-License-Identifier: AGPL-3.0-or-later
// LTC desired-version tally -- version->work (consensus) / version->count
// (diagnostic) accumulation KAT, exercised through LTC's REAL ShareTracker API.
//
// FENCED, additive (no production code touched this slice). LTC is the V36
// reference impl but -- unlike dgb -- does NOT modularize this tally into
// src/impl/ltc/coin/; the accumulation lives inline in
// ShareTracker::get_desired_version_weights() (the CONSENSUS 60%-by-work switch
// gate input, share_check step 2 / #288 AutoRatchet tail guard) and its
// flat-count diagnostic sibling ShareTracker::get_desired_version_counts()
// (share_tracker.hpp:2151 / :2181). This KAT therefore drives the tally through
// the real chain-walk API rather than a lifted header -- it builds a resolved
// ltc::ShareTracker of ltc::MergedMiningShare (V36) and asserts the two
// per-version maps against the p2pool oracle.
//
// Oracle: p2pool data.py:2651 get_desired_version_counts is ALREADY
// work-weighted -- each share contributes target_to_average_attempts(share.target),
// NOT 1:
//     res = {}
//     for share in tracker.get_chain(best_share_hash, dist):
//         res[share.desired_version] = res.get(share.desired_version, 0) \
//             + bitcoin_data.target_to_average_attempts(share.target)
//     return res
// c2pool splits this into two accessors: get_desired_version_weights (the true
// oracle match -- per-share weight = ShareIndex::work = chain::
// target_to_average_attempts(chain::bits_to_target(m_bits)), share.hpp:304, the
// CONSENSUS gate input) and get_desired_version_counts (a flat occurrence count,
// diagnostics-only, NEVER the gate -- see the share_tracker.hpp comment / #288).
//
// NON-CIRCULAR: the work-definition anchor pins chain::target_to_average_attempts
// to hand-derived constants over 2^k-1 targets (ttaa(2^k-1) = 2^256/2^k =
// 2^(256-k)); the tracker-tally expectations are then re-derived from first
// principles by an INDEPENDENT accumulation loop applying that same production
// primitive to the input bits -- NOT read from the maps under test. share_tracker.hpp
// is NOT rewired. This target joins the existing `share_test` executable (already
// on the build.yml --target allowlist), so it cannot become a #143 NOT_BUILT sentinel.

#include <cstdint>
#include <cstdio>
#include <map>
#include <vector>

#include <gtest/gtest.h>

#include <core/uint256.hpp>       // uint288
#include <core/target_utils.hpp>  // chain::bits_to_target, chain::target_to_average_attempts
#include <impl/ltc/share.hpp>
#include <impl/ltc/share_tracker.hpp>

namespace {

uint288 u(uint64_t n) { return uint288(n); }

// A short hex tail -> uint256 (zero-padded to 64 nibbles), matching the dgb
// share_test hx() convention so share identities are compact and readable.
uint256 hx(const std::string& tail) {
    uint256 v;
    v.SetHex(std::string(64 - tail.size(), '0') + tail);
    return v;
}

// One synthetic V36 share's tally-relevant inputs: its desired_version and the
// compact bits that (via ShareIndex::work) fix its work weight.
struct In { uint64_t dv; uint32_t bits; };

// Build a resolved ltc::ShareTracker from `shares` (share i's parent is i-1;
// share 0 has a null parent = resolved chain genesis) and return the tip hash.
uint256 seed_tracker(ltc::ShareTracker& tracker, const std::vector<In>& shares) {
    uint256 prev;
    prev.SetNull();
    uint256 tip;
    for (size_t i = 0; i < shares.size(); ++i) {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%zx", static_cast<size_t>(0x1c70 + i));
        uint256 h = hx(buf);
        auto* sh = new ltc::MergedMiningShare();
        sh->m_hash = h;
        if (i == 0) sh->m_prev_hash.SetNull(); else sh->m_prev_hash = prev;
        sh->m_desired_version = shares[i].dv;
        sh->m_bits = shares[i].bits;
        sh->m_max_bits = shares[i].bits;
        ltc::ShareType st;
        st = sh;
        tracker.add(st);
        prev = h;
        tip = h;
    }
    return tip;
}

// Independent (first-principles) oracle: the flat count and the work-weighted
// sum per desired_version, computed WITHOUT touching the maps under test.
void expected_maps(const std::vector<In>& shares,
                   std::map<uint64_t, int32_t>& counts,
                   std::map<uint64_t, uint288>& weights) {
    for (const auto& in : shares) {
        counts[in.dv] += 1;
        const uint288 w = chain::target_to_average_attempts(chain::bits_to_target(in.bits));
        weights[in.dv] = weights[in.dv] + w;
    }
}

}  // namespace

// --- work-definition anchor: ttaa(2^k-1) = 2^(256-k), hand-derived ----------
//     t = 2^255-1 -> ttaa = 2 ; t = 2^254-1 -> ttaa = 4 ; t = 2^253-1 -> ttaa = 8
// Pins the production work primitive NON-CIRCULARLY, so the tracker-tally
// expectations below (which re-apply this primitive to the input bits) rest on
// a hand-verified base rather than the code under test.
TEST(LtcDesiredVersionTally, WorkPrimitiveMatchesOracleAttempts) {
    uint256 t255, t254, t253;
    t255.SetHex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // 2^255-1
    t254.SetHex("3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // 2^254-1
    t253.SetHex("1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // 2^253-1
    EXPECT_EQ(chain::target_to_average_attempts(t255), u(2));
    EXPECT_EQ(chain::target_to_average_attempts(t254), u(4));
    EXPECT_EQ(chain::target_to_average_attempts(t253), u(8));
}

// --- empty / absent tip -> empty maps (the actual<=0 / !contains early-return) --
TEST(LtcDesiredVersionTally, EmptyOrAbsentTipYieldsEmptyMaps) {
    ltc::ShareTracker tracker;
    // Absent tip: chain.contains(hash) == false -> empty.
    EXPECT_TRUE(tracker.get_desired_version_counts(hx("deadbeef"), 1000).empty());
    EXPECT_TRUE(tracker.get_desired_version_weights(hx("deadbeef"), 1000).empty());

    // Present tip but lookbehind<=0 -> min(lookbehind,height)<=0 -> empty.
    std::vector<In> shares = {{36, 0x1e0fffff}, {36, 0x1e0fffff}};
    const uint256 tip = seed_tracker(tracker, shares);
    EXPECT_TRUE(tracker.get_desired_version_counts(tip, 0).empty());
    EXPECT_TRUE(tracker.get_desired_version_weights(tip, 0).empty());
}

// --- single share: one bucket, weight == its work, count == 1 ---------------
TEST(LtcDesiredVersionTally, SingleShareSingleBucket) {
    ltc::ShareTracker tracker;
    std::vector<In> shares = {{36, 0x1e0fffff}};
    const uint256 tip = seed_tracker(tracker, shares);

    const uint288 w36 = chain::target_to_average_attempts(chain::bits_to_target(0x1e0fffff));

    auto c = tracker.get_desired_version_counts(tip, 1000);
    ASSERT_EQ(c.size(), 1u);
    EXPECT_EQ(c.at(36u), 1);

    auto w = tracker.get_desired_version_weights(tip, 1000);
    ASSERT_EQ(w.size(), 1u);
    EXPECT_EQ(w.at(36u), w36);
}

// --- same version, many shares: weights sum, count increments ---------------
TEST(LtcDesiredVersionTally, SameVersionAccumulates) {
    ltc::ShareTracker tracker;
    std::vector<In> shares = {{36, 0x1e0fffff}, {36, 0x1e07ffff}, {36, 0x1d00ffff}};
    const uint256 tip = seed_tracker(tracker, shares);

    std::map<uint64_t, int32_t> want_counts;
    std::map<uint64_t, uint288> want_weights;
    expected_maps(shares, want_counts, want_weights);

    EXPECT_EQ(tracker.get_desired_version_counts(tip, 1000), want_counts);
    EXPECT_EQ(tracker.get_desired_version_weights(tip, 1000), want_weights);
    // The three works genuinely differ (non-trivial sum), not a degenerate 3x same.
    EXPECT_EQ(want_counts.at(36u), 3);
}

// --- multiple versions bucketed independently; work-weight can INVERT count --
// The exact case where a flat count (36 leads 3:1) inverts under work-weighting
// (the single hard dv=35 share outweighs the three easy dv=36 shares).
TEST(LtcDesiredVersionTally, MultipleVersionsBucketedAndWorkInverts) {
    ltc::ShareTracker tracker;
    std::vector<In> shares = {{36, 0x1e0fffff}, {36, 0x1e0fffff},
                              {35, 0x1d00ffff}, {36, 0x1e0fffff}};
    const uint256 tip = seed_tracker(tracker, shares);

    std::map<uint64_t, int32_t> want_counts;
    std::map<uint64_t, uint288> want_weights;
    expected_maps(shares, want_counts, want_weights);

    auto c = tracker.get_desired_version_counts(tip, 1000);
    auto w = tracker.get_desired_version_weights(tip, 1000);
    EXPECT_EQ(c, want_counts);
    EXPECT_EQ(w, want_weights);

    // Flat count: 36 leads 3:1 ...
    ASSERT_EQ(c.at(36u), 3);
    ASSERT_EQ(c.at(35u), 1);
    // ... but work-weighting inverts it: the lone hard dv=35 share outweighs the
    // three easy dv=36 shares (0x1d00ffff is far more work than 0x1e0fffff).
    EXPECT_GT(w.at(35u), w.at(36u));
}

// --- lookbehind clamp stays inline & correct: a window shorter than the chain
//     tallies ONLY the clamped tail ---------------------------------------
TEST(LtcDesiredVersionTally, LookbehindClampsToTail) {
    ltc::ShareTracker tracker;
    // g(dv35) <- a(dv36) <- b(dv36): a lookbehind of 2 sees only {a,b} = 2x dv36.
    std::vector<In> shares = {{35, 0x1e0fffff}, {36, 0x1e0fffff}, {36, 0x1e0fffff}};
    const uint256 tip = seed_tracker(tracker, shares);

    auto c2 = tracker.get_desired_version_counts(tip, 2);
    ASSERT_EQ(c2.size(), 1u);
    EXPECT_EQ(c2.at(36u), 2);   // dv35 genesis is outside the 2-deep tail

    auto w2 = tracker.get_desired_version_weights(tip, 2);
    ASSERT_EQ(w2.size(), 1u);
    const uint288 w36 = chain::target_to_average_attempts(chain::bits_to_target(0x1e0fffff));
    EXPECT_EQ(w2.at(36u), w36 + w36);
}
