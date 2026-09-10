// SPDX-License-Identifier: AGPL-3.0-or-later
// KAT for the shared stops builder that LTC's download_shares now calls
// (pool::download::build_stops) instead of open-coding the same walk inline.
//
// WHY THIS EXISTS. The inline version read the tracker with NO lock held, and
// chain.get_heads() hands back a REFERENCE to the live heads container
// (sharechain.hpp:322). On the IO thread, with clean_tracker concurrently
// erasing heads on the compute thread, that is a use-after-free — the prod
// SIGSEGV of 2026-09-10 faulted inside base_uint<256>::CompareTo while inserting
// a freed head hash into the stop set. The fix takes the tracker lock
// (try_to_lock, never blocking) around the build and delegates to this helper.
//
// The lock itself cannot be unit-tested here — what CAN be pinned, and what this
// KAT pins, is that the shared helper is behaviour-identical to the LTC code it
// replaced, so the race fix carries no silent behaviour change with it. The
// helper is a template, so a minimal fake chain exercises it without standing up
// a real ShareTracker.

#include <gtest/gtest.h>

#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include <core/uint256.hpp>
#include <pool/share_download.hpp>

namespace {

// Short hex tail -> uint256, matching the idiom used by the other LTC KATs.
uint256 hx(const std::string& tail)
{
    uint256 v;
    v.SetHex(std::string(64 - tail.size(), '0') + tail);
    return v;
}

// Minimal stand-in for the sharechain: just the three accessors build_stops
// touches. Heads map head -> tail, exactly like the real container.
struct FakeChain {
    std::map<uint256, uint256> heads;
    std::map<uint256, int> acc_height;
    std::map<std::pair<uint256, int>, uint256> nth_parent;

    const std::map<uint256, uint256>& get_heads() const { return heads; }
    int get_acc_height(const uint256& h) const
    {
        auto it = acc_height.find(h);
        return it == acc_height.end() ? 0 : it->second;
    }
    uint256 get_nth_parent_via_skip(const uint256& h, int nth) const
    {
        auto it = nth_parent.find({h, nth});
        return it == nth_parent.end() ? uint256::ZERO : it->second;
    }
};

}  // namespace

// A head taller than 10 contributes itself AND its 10th parent — the p2pool
// rule the LTC inline code implemented.
TEST(BuildStops, head_and_tenth_parent)
{
    FakeChain c;
    const auto head = hx("aa");
    const auto p10 = hx("bb");
    c.heads[head] = hx("01");
    c.acc_height[head] = 500;
    c.nth_parent[{head, 10}] = p10;

    auto stops = pool::download::build_stops(c);
    ASSERT_EQ(stops.size(), 2u);
    EXPECT_NE(std::find(stops.begin(), stops.end(), head), stops.end());
    EXPECT_NE(std::find(stops.begin(), stops.end(), p10), stops.end());
}

// height-1 head: nth clamps to 0, so no parent lookup happens and only the head
// itself is a stop. This is the orphan case the prod node had ~5000 of.
TEST(BuildStops, height_one_head_contributes_only_itself)
{
    FakeChain c;
    const auto head = hx("cc");
    c.heads[head] = head;      // head == tail: an isolated single-share orphan
    c.acc_height[head] = 1;
    c.nth_parent[{head, 10}] = hx("dd");   // must NOT be consulted

    auto stops = pool::download::build_stops(c);
    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0], head);
}

// A shallow head clamps nth to height-1 rather than 10.
TEST(BuildStops, shallow_head_clamps_to_height_minus_one)
{
    FakeChain c;
    const auto head = hx("ee");
    const auto p3 = hx("ff");
    c.heads[head] = hx("02");
    c.acc_height[head] = 4;          // min(max(0, 4-1), 10) == 3
    c.nth_parent[{head, 3}] = p3;
    c.nth_parent[{head, 10}] = hx("99");   // wrong depth, must not appear

    auto stops = pool::download::build_stops(c);
    ASSERT_EQ(stops.size(), 2u);
    EXPECT_NE(std::find(stops.begin(), stops.end(), p3), stops.end());
    EXPECT_EQ(std::find(stops.begin(), stops.end(), hx("99")), stops.end());
}

// A null parent is skipped, not inserted as ZERO — inserting a null stop would
// silently widen every reply.
TEST(BuildStops, null_parent_is_not_a_stop)
{
    FakeChain c;
    const auto head = hx("1a");
    c.heads[head] = hx("03");
    c.acc_height[head] = 200;
    // no nth_parent entry -> get_nth_parent_via_skip returns ZERO

    auto stops = pool::download::build_stops(c);
    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0], head);
    EXPECT_EQ(std::find(stops.begin(), stops.end(), uint256::ZERO), stops.end());
}

// THE CAP. The replaced LTC code stopped at 100 stops; the helper must too,
// otherwise a fragmented chain (the prod node peaked at 5140 heads) would build
// a request that dwarfs the reply it is meant to bound.
TEST(BuildStops, caps_at_one_hundred)
{
    FakeChain c;
    for (int i = 0; i < 500; ++i) {
        char buf[8];
        std::snprintf(buf, sizeof(buf), "%03x", i + 1);
        const auto head = hx(buf);
        c.heads[head] = head;
        c.acc_height[head] = 1;      // orphan heads, no parent lookups
    }
    ASSERT_EQ(c.heads.size(), 500u);

    auto stops = pool::download::build_stops(c);
    EXPECT_EQ(stops.size(), pool::download::STOPS_CAP);
    EXPECT_EQ(stops.size(), 100u);
}

// An empty chain yields no stops rather than something malformed.
TEST(BuildStops, empty_chain_yields_no_stops)
{
    FakeChain c;
    EXPECT_TRUE(pool::download::build_stops(c).empty());
}

// Stops are de-duplicated: two heads sharing a 10th parent contribute it once.
TEST(BuildStops, shared_parent_deduplicated)
{
    FakeChain c;
    const auto h1 = hx("2a"), h2 = hx("2b"), shared = hx("2c");
    c.heads[h1] = hx("04");
    c.heads[h2] = hx("05");
    c.acc_height[h1] = 300;
    c.acc_height[h2] = 300;
    c.nth_parent[{h1, 10}] = shared;
    c.nth_parent[{h2, 10}] = shared;

    auto stops = pool::download::build_stops(c);
    EXPECT_EQ(stops.size(), 3u);
    EXPECT_EQ(std::count(stops.begin(), stops.end(), shared), 1);
}
