// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// test_dash_dashboard_views — BINDING KATs for the DASH sharechain WINDOW /
// DELTA / SHARE-DETAIL read-models.
//
// THE DEFECT. MiningInterface::set_sharechain_window_fn / _delta_fn /
// set_share_lookup_fn had exactly ONE caller each in the whole repository —
// main_ltc.cpp:3730 / :3946 / :4077. Nothing on the DASH lane bound them, so
// core answered from its FALLBACK STUBS (web_server.cpp:2907 / :3313 / :6768).
// A stub is not a 404: it is HTTP 200 carrying a well-formed EMPTY document
// ({"shares":[],"total":0,...}), which is why three dashboard widgets went dark
// with no error anywhere and the front-end guard `if (!data.shares) return`
// (dashboard.html:5011) sailed straight through a truthy `[]`.
//
// WHY THESE KATs ARE NOT VACUOUS. Each positive KAT is paired with the
// NEGATIVE CONTROL that reproduces the shipped defect: the same assertion run
// against core's stub shape, which passes the front-end's null check and fails
// its content check. A KAT that only asserted "the builder returns an object"
// would have been green on the broken build too.
//
// Display-only surface: nothing here reaches mint, payout, target or block
// submission. The builders take an ALREADY-READ-LOCKED tracker and only read.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <impl/dash/dashboard_views.hpp>
#include <impl/dash/node.hpp>
#include <impl/dash/share.hpp>
#include <impl/dash/share_check.hpp>

#include <core/address_utils.hpp>
#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace {

constexpr uint32_t V_BLOCK_BITS = 0x1d00ffff;
constexpr uint32_t V_SHARE_BITS = 0x1e0ffff0;
constexpr uint32_t V_BASE_TIME  = 1753000000;
constexpr uint64_t V_SUBSIDY    = 155000000;   // duffs

uint256 view_hash(unsigned int n)
{
    static const char* digits = "0123456789abcdef";
    std::string s = "7d";
    s += digits[(n >> 12) & 0xf];
    s += digits[(n >>  8) & 0xf];
    s += digits[(n >>  4) & 0xf];
    s += digits[ n        & 0xf];
    s += std::string(64 - s.size(), '0');
    uint256 h;
    h.SetHex(s);
    return h;
}

uint160 view_pkh(unsigned char b)
{
    static const char* digits = "0123456789abcdef";
    std::string s;
    s += digits[b >> 4];
    s += digits[b & 0x0f];
    s += std::string(40 - s.size(), '3');
    uint160 h;
    h.SetHex(s);
    return h;
}

// A share carrying every field the grid cell reads, so a builder that silently
// dropped one would show up as a missing key rather than as a plausible zero.
dash::DashShare* make_view_share(unsigned int n, const uint256& prev, unsigned char pkh_byte)
{
    auto* s = new dash::DashShare();
    s->m_hash      = view_hash(n);
    s->m_prev_hash = prev;
    s->m_min_header.m_bits      = V_BLOCK_BITS;
    s->m_min_header.m_timestamp = V_BASE_TIME + n;
    s->m_bits            = V_SHARE_BITS;
    s->m_max_bits        = V_SHARE_BITS;
    s->m_timestamp       = V_BASE_TIME + n;
    s->m_absheight       = 2500000 + n;
    s->m_desired_version = 36;
    s->m_pubkey_hash     = view_pkh(pkh_byte);
    s->m_subsidy         = V_SUBSIDY;
    const std::string tag = "/P2Pool-DASH/c2pool/";
    s->m_coinbase.m_data.assign(tag.begin(), tag.end());
    return s;
}

// Real tracker (dash::NodeImpl's ctor is what wires verified.set_parent_chain),
// loaded with a linear chain of `count` shares. Returned tip is the head.
struct ChainHarness
{
    dash::NodeImpl node;
    uint256        tip;
    unsigned int   count{0};

    explicit ChainHarness(unsigned int n)
    {
        uint256 prev = uint256::ZERO;
        for (unsigned int i = 0; i < n; ++i) {
            // Two distinct miners so the address column is demonstrably
            // per-share and not a single constant.
            auto* s = make_view_share(i, prev, static_cast<unsigned char>(0xa0 + (i % 2)));
            node.tracker().chain.add(s);
            prev = s->m_hash;
            tip  = s->m_hash;
        }
        count = n;
    }

    dash::dashboard::ViewContext ctx() const
    {
        dash::dashboard::ViewContext c;
        c.testnet     = false;
        c.window_size = 4320;
        return c;
    }
};

// The exact shape core serves when the seam is UNBOUND (web_server.cpp:2907).
nlohmann::json core_window_stub()
{
    nlohmann::json r;
    r["shares"]       = nlohmann::json::array();
    r["total"]        = 0;
    r["best_hash"]    = "";
    r["chain_length"] = 0;
    return r;
}

// The front-end's own admission test, transcribed from dashboard.html:5011
// (`if (!data || !data.shares) return;`) plus the render precondition that
// actually puts cells on screen.
bool front_end_would_render(const nlohmann::json& w)
{
    if (w.is_null() || !w.contains("shares")) return false;   // the null guard
    if (!w["shares"].is_array())              return false;
    return !w["shares"].empty();                              // the render precondition
}

} // namespace

// ── KAT 1: the window carries the chain ─────────────────────────────────────
TEST(DashDashboardViews, WindowCarriesEveryShareAndTheGridContract)
{
    ChainHarness h(12);
    auto w = dash::dashboard::build_window(h.node.tracker(), h.ctx());

    ASSERT_TRUE(w.contains("shares"));
    ASSERT_EQ(w["shares"].size(), 12u);
    EXPECT_EQ(w["total"].get<int>(), 12);
    EXPECT_EQ(w["chain_length"].get<int>(), 12);
    EXPECT_EQ(w["window_size"].get<int>(), 4320);
    EXPECT_EQ(w["best_hash"].get<std::string>(), h.tip.GetHex());

    // Walk order is tip-first (position 0 == tallest head), matching the LTC
    // grid the front-end already renders.
    const auto& first = w["shares"][0];
    EXPECT_EQ(first["H"].get<std::string>(), h.tip.GetHex());
    EXPECT_EQ(first["h"].get<std::string>(), h.tip.GetHex().substr(0, 16));
    EXPECT_EQ(first["p"].get<int>(), 0);

    // Every key the front-end reads must be present — a missing one renders as
    // a blank/NaN cell rather than an error.
    for (const char* k : {"h", "H", "p", "v", "t", "V", "s", "b", "a", "dv", "m"})
        EXPECT_TRUE(first.contains(k)) << "missing grid key: " << k;

    EXPECT_EQ(first["V"].get<int>(), 16);            // live DASH wire version
    EXPECT_EQ(first["dv"].get<int>(), 36);           // the v16->v36 vote
    EXPECT_EQ(first["b"].get<uint32_t>(), V_SHARE_BITS);
    EXPECT_EQ(first["v"].get<int>(), 0);             // nothing verified in this fixture

    // Miner column is a real DASH mainnet address ('X'), not a Bitcoin '1'.
    const std::string addr = first["m"].get<std::string>();
    ASSERT_FALSE(addr.empty());
    EXPECT_EQ(addr[0], 'X');
    EXPECT_EQ(addr, core::script_to_address(
                        dash::pubkey_hash_to_script2(view_pkh(0xa1)), "", 76, 16));

    // Coinbase tag survives the printable-run extraction.
    ASSERT_TRUE(first.contains("cb"));
    EXPECT_EQ(first["cb"].get<std::string>(), "/P2Pool-DASH/c2pool/");

    // The two miners are actually distinguished.
    EXPECT_NE(w["shares"][0]["m"].get<std::string>(),
              w["shares"][1]["m"].get<std::string>());

    // Heads are reported for fork marking.
    ASSERT_TRUE(w.contains("heads"));
    EXPECT_EQ(w["heads"].size(), 1u);

    // POSITIVE: this payload renders. NEGATIVE CONTROL: the stub the DASH lane
    // shipped passes the front-end null guard and still draws nothing — the
    // exact silent failure being fixed.
    EXPECT_TRUE(front_end_would_render(w));
    EXPECT_FALSE(front_end_would_render(core_window_stub()));
    EXPECT_TRUE(core_window_stub().contains("shares"));   // why it was silent
}

// ── KAT 2: the window is bounded by window_size ──────────────────────────────
TEST(DashDashboardViews, WindowIsClampedToTheConfiguredWindowSize)
{
    ChainHarness h(30);
    auto ctx = h.ctx();
    ctx.window_size = 10;
    auto w = dash::dashboard::build_window(h.node.tracker(), ctx);

    EXPECT_EQ(w["shares"].size(), 10u);
    EXPECT_EQ(w["total"].get<int>(), 30);          // total is the whole store
    EXPECT_EQ(w["window_size"].get<int>(), 10);
}

// ── KAT 3: the empty chain degrades honestly ────────────────────────────────
TEST(DashDashboardViews, EmptyChainYieldsAnHonestEmptyWindow)
{
    ChainHarness h(0);
    auto w = dash::dashboard::build_window(h.node.tracker(), h.ctx());

    EXPECT_TRUE(w["shares"].is_array());
    EXPECT_TRUE(w["shares"].empty());
    EXPECT_EQ(w["best_hash"].get<std::string>(), "");
    EXPECT_FALSE(front_end_would_render(w));   // nothing to draw, and it says so
}

// ── KAT 4: the delta returns only what the client is missing ────────────────
TEST(DashDashboardViews, DeltaStopsAtTheHashTheClientAlreadyHas)
{
    ChainHarness h(12);
    auto ctx = h.ctx();

    // Client already at the tip -> nothing new.
    auto d0 = dash::dashboard::build_delta(h.node.tracker(),
                                           h.tip.GetHex().substr(0, 16), ctx);
    EXPECT_EQ(d0["count"].get<int>(), 0);
    EXPECT_TRUE(d0["shares"].empty());
    EXPECT_EQ(d0["tip"].get<std::string>(), h.tip.GetHex().substr(0, 16));

    // Client three shares behind -> exactly three.
    const std::string behind = view_hash(8).GetHex().substr(0, 16);   // 11,10,9 are newer
    auto d3 = dash::dashboard::build_delta(h.node.tracker(), behind, ctx);
    EXPECT_EQ(d3["count"].get<int>(), 3);
    ASSERT_EQ(d3["shares"].size(), 3u);
    EXPECT_EQ(d3["shares"][0]["H"].get<std::string>(), view_hash(11).GetHex());
    EXPECT_EQ(d3["shares"][2]["H"].get<std::string>(), view_hash(9).GetHex());

    // Cold client (no `since`) -> the full walk, capped.
    auto dall = dash::dashboard::build_delta(h.node.tracker(), "", ctx);
    EXPECT_EQ(dall["count"].get<int>(), 12);
}

TEST(DashDashboardViews, DeltaHonoursItsSafetyCap)
{
    ChainHarness h(40);
    auto ctx = h.ctx();
    ctx.delta_max_shares = 5;
    auto d = dash::dashboard::build_delta(h.node.tracker(), "", ctx);
    EXPECT_EQ(d["count"].get<int>(), 5);
    EXPECT_EQ(d["shares"].size(), 5u);
}

// ── KAT 4b: a `since` the walk can't re-derive resyncs, not silently drifts ──
// Explorer SSE fade-by-age (task #112). When the client's held tip is orphaned
// by a reorg (or the client is more than a window behind), walking back from the
// current best never reaches `since_hash`. Emitting fork_switch tells the client
// to rebuild from the authoritative set; without it the client spliced a
// disconnected delta, kept the orphaned shares, and evicted good ones by cap.
TEST(DashDashboardViews, DeltaSignalsForkSwitchWhenSinceIsNotOnTheBestChain)
{
    ChainHarness h(12);
    auto ctx = h.ctx();

    // Normal cases carry the flag explicitly false — never a spurious resync.
    auto at_tip = dash::dashboard::build_delta(h.node.tracker(),
                                               h.tip.GetHex().substr(0, 16), ctx);
    ASSERT_TRUE(at_tip.contains("fork_switch"));
    EXPECT_FALSE(at_tip["fork_switch"].get<bool>());

    const std::string behind = view_hash(8).GetHex().substr(0, 16);
    auto d_behind = dash::dashboard::build_delta(h.node.tracker(), behind, ctx);
    EXPECT_FALSE(d_behind["fork_switch"].get<bool>());

    // Cold client (empty since) is a legitimate full walk, not a fork.
    auto cold = dash::dashboard::build_delta(h.node.tracker(), "", ctx);
    EXPECT_FALSE(cold["fork_switch"].get<bool>());

    // An orphaned / unknown tip the chain has never held -> resync. The walk
    // still returns the current window so the client can rebuild from it.
    const std::string orphan = view_hash(0x777).GetHex().substr(0, 16);
    auto d_fork = dash::dashboard::build_delta(h.node.tracker(), orphan, ctx);
    EXPECT_TRUE(d_fork["fork_switch"].get<bool>());
    EXPECT_EQ(d_fork["count"].get<int>(), 12);
    EXPECT_EQ(d_fork["shares"].size(), 12u);
}

// ── KAT 5: the individual share page ────────────────────────────────────────
TEST(DashDashboardViews, ShareDetailAnswersForAShareInTheTracker)
{
    ChainHarness h(6);
    auto s = dash::dashboard::build_share_detail(h.node.tracker(), h.tip.GetHex(), h.ctx());

    // NEGATIVE CONTROL first: this is the document the unwired lane served for
    // a hash that IS in the tracker (web_server.cpp:6773).
    ASSERT_FALSE(s.contains("error"))
        << "share lookup still falling through to the not-found stub";

    EXPECT_EQ(s["version"].get<int>(), 16);
    EXPECT_EQ(s["type_name"].get<std::string>(), "V16");
    EXPECT_EQ(s["parent"].get<std::string>(), view_hash(4).GetHex());
    EXPECT_FALSE(s["is_block_solution"].get<bool>());

    ASSERT_TRUE(s.contains("share_data"));
    const auto& sd = s["share_data"];
    // share.html reads exactly these (share.html:545 payout_address, and the
    // kv() rows below it) — a missing key renders as a blank field.
    for (const char* k : {"timestamp", "target", "max_target", "payout_address",
                          "stale_info", "nonce", "desired_version", "absheight",
                          "difficulty"})
        EXPECT_TRUE(sd.contains(k)) << "missing share_data key: " << k;

    EXPECT_EQ(sd["payout_address"].get<std::string>()[0], 'X');
    EXPECT_EQ(sd["absheight"].get<uint32_t>(), 2500005u);
    EXPECT_GT(sd["difficulty"].get<double>(), 0.0);

    ASSERT_TRUE(s.contains("block"));
    EXPECT_EQ(s["block"]["hash"].get<std::string>(), h.tip.GetHex());
    EXPECT_TRUE(s["block"].contains("header"));
    EXPECT_TRUE(s["block"].contains("gentx"));

    ASSERT_TRUE(s.contains("local"));
    EXPECT_FALSE(s["local"]["verified"].get<bool>());

    // DASH-specific block, present even when the fixture carries no payments —
    // absent would be indistinguishable from "builder forgot it".
    ASSERT_TRUE(s.contains("dash_metadata"));
    EXPECT_TRUE(s["dash_metadata"]["packed_payments"].is_array());
}

TEST(DashDashboardViews, ShareDetailReportsAnHonestMiss)
{
    ChainHarness h(6);
    auto s = dash::dashboard::build_share_detail(
        h.node.tracker(), view_hash(999).GetHex(), h.ctx());
    ASSERT_TRUE(s.contains("error"));
    EXPECT_EQ(s["error"].get<std::string>(), "share not found");
}

// ── KAT 6: the node-fee marking ─────────────────────────────────────────────
TEST(DashDashboardViews, FeeSharesAreMarkedByHash160)
{
    ChainHarness h(4);
    auto ctx = h.ctx();
    ctx.fee_hash160 = view_pkh(0xa1).GetHex();   // the odd-index miner

    auto w = dash::dashboard::build_window(h.node.tracker(), ctx);
    ASSERT_EQ(w["shares"].size(), 4u);
    // Shares 3 and 1 carry pkh 0xa1; 2 and 0 carry 0xa0.
    EXPECT_TRUE(w["shares"][0].contains("fee"));    // share 3
    EXPECT_FALSE(w["shares"][1].contains("fee"));   // share 2
    EXPECT_EQ(w["fee_hash160"].get<std::string>(), ctx.fee_hash160);
}
