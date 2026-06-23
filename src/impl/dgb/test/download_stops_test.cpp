// dgb download stops-list — requester-side SHAREREQ bound conformance KAT.
//
// FENCED, additive (no production code touched this slice). Pins
// src/impl/dgb/download_stops.hpp against the p2pool node.py download_shares
// oracle:
//     stops=list(set(tracker.heads) | set(
//         tracker.get_nth_parent_hash(head, min(max(0, height-1), 10))
//         for head in tracker.heads))[:100]
//
// Expectations are hand-derived from the oracle formula, NOT read from the code
// under test. The per-head depth min(max(0,height-1),10) and the head-inclusion
// / null-parent-skip / dedup behaviour are oracle-faithful. The 100-cap survivor
// SELECTION is a c2pool determinism choice (Python set() iteration order is
// arbitrary; c2pool pins std::set<uint256> ascending order) — the cap test below
// constructs numerically-ordered hashes so the expected survivors (the 100
// smallest) are hand-computable, pinning that documented contract non-vacuously.
//
// No NodeImpl / ShareTracker standup: heads + acc-height + nth-parent are fakes.
// MUST appear in BOTH this dir CMakeLists.txt AND the build.yml --target
// allowlist, or it becomes a #143 NOT_BUILT sentinel.

#include <impl/dgb/download_stops.hpp>

#include <core/uint256.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace {

uint256 u256(const char* hex) {
    uint256 t;
    t.SetHex(hex);
    return t;
}

// 64-hex-char zero-padded id so numeric uint256 ordering == ascending id:
// id 1 -> 0x..0001 < id 2 -> 0x..0002 < ...  Lets the 100-cap survivors be hand-named.
uint256 id256(int id) {
    char buf[65];
    std::snprintf(buf, sizeof(buf),
        "%064x", id);
    return u256(buf);
}

const uint256 NULLH; // default uint256 == null

} // namespace

// --- depth formula: min(max(0, height-1), 10), hand-tabulated --------------
TEST(DgbDownloadStops, NthDepthFormulaMatchesOracle) {
    EXPECT_EQ(dgb::download_stops_nth(0), 0);   // max(0,-1)=0
    EXPECT_EQ(dgb::download_stops_nth(1), 0);   // max(0,0)=0
    EXPECT_EQ(dgb::download_stops_nth(2), 1);
    EXPECT_EQ(dgb::download_stops_nth(5), 4);
    EXPECT_EQ(dgb::download_stops_nth(11), 10);
    EXPECT_EQ(dgb::download_stops_nth(12), 10); // capped at 10
    EXPECT_EQ(dgb::download_stops_nth(1000), 10);
}

// --- two deep heads -> head + 10th-parent each = 4 distinct stops ----------
TEST(DgbDownloadStops, TwoDeepHeadsIncludeHeadAndNthParent) {
    uint256 h1 = id256(0x11), h2 = id256(0x22);
    uint256 p1 = id256(0x01), p2 = id256(0x02);
    std::vector<uint256> heads{h1, h2};

    auto height = [](const uint256&) { return 20; };           // nth = 10
    auto nthp = [&](const uint256& h, int nth) -> uint256 {
        EXPECT_EQ(nth, 10);
        return h == h1 ? p1 : p2;
    };

    auto stops = dgb::compute_download_stops(heads, height, nthp);
    std::set<uint256> got(stops.begin(), stops.end());
    EXPECT_EQ(stops.size(), 4u);
    EXPECT_EQ(got, (std::set<uint256>{h1, h2, p1, p2}));
}

// --- head at height 1 contributes only itself, nth-parent NEVER queried ----
TEST(DgbDownloadStops, HeightOneHeadHasNoParentAndSkipsLookup) {
    uint256 h = id256(0x33);
    bool nth_called = false;
    auto height = [](const uint256&) { return 1; };            // nth = 0
    auto nthp = [&](const uint256&, int) -> uint256 { nth_called = true; return NULLH; };

    auto stops = dgb::compute_download_stops({h}, height, nthp);
    EXPECT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0], h);
    EXPECT_FALSE(nth_called); // nth==0 -> no get_nth_parent call (inline guard)
}

// --- null nth-parent is skipped (head still included) ----------------------
TEST(DgbDownloadStops, NullNthParentSkipped) {
    uint256 h = id256(0x44);
    auto height = [](const uint256&) { return 5; };            // nth = 4
    auto nthp = [&](const uint256&, int nth) -> uint256 {
        EXPECT_EQ(nth, 4);
        return NULLH; // unresolved
    };
    auto stops = dgb::compute_download_stops({h}, height, nthp);
    EXPECT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0], h);
}

// --- two heads sharing one nth-parent dedups via the set -------------------
TEST(DgbDownloadStops, SharedNthParentDeduped) {
    uint256 h1 = id256(0x55), h2 = id256(0x66), shared = id256(0x07);
    auto height = [](const uint256&) { return 20; };
    auto nthp = [&](const uint256&, int) -> uint256 { return shared; };
    auto stops = dgb::compute_download_stops({h1, h2}, height, nthp);
    EXPECT_EQ(stops.size(), 3u); // {h1, h2, shared}, NOT 4
    std::set<uint256> got(stops.begin(), stops.end());
    EXPECT_EQ(got, (std::set<uint256>{h1, h2, shared}));
}

// --- 100-cap: 150 height-1 heads -> 100 smallest in ascending order --------
TEST(DgbDownloadStops, CapAt100KeepsSmallestAscending) {
    std::vector<uint256> heads;
    for (int i = 1; i <= 150; ++i) heads.push_back(id256(i)); // distinct, only-self
    auto height = [](const uint256&) { return 1; };           // nth = 0, no parents
    auto nthp = [&](const uint256&, int) -> uint256 { return NULLH; };

    auto stops = dgb::compute_download_stops(heads, height, nthp);
    ASSERT_EQ(stops.size(), 100u);                            // [:100]
    for (int i = 0; i < 100; ++i)
        EXPECT_EQ(stops[i], id256(i + 1)) << "survivor " << i; // ids 1..100, ascending
    EXPECT_TRUE(std::is_sorted(stops.begin(), stops.end()));
}

// --- custom cap argument honoured ------------------------------------------
TEST(DgbDownloadStops, CustomCapHonoured) {
    std::vector<uint256> heads;
    for (int i = 1; i <= 10; ++i) heads.push_back(id256(i));
    auto height = [](const uint256&) { return 1; };
    auto nthp = [&](const uint256&, int) -> uint256 { return NULLH; };
    auto stops = dgb::compute_download_stops(heads, height, nthp, 3);
    ASSERT_EQ(stops.size(), 3u);
    EXPECT_EQ(stops[0], id256(1));
    EXPECT_EQ(stops[1], id256(2));
    EXPECT_EQ(stops[2], id256(3));
}
