// SPDX-License-Identifier: AGPL-3.0-or-later
// BTC sharechain dashboard views, over a real btc::ShareTracker and the
// btc::dashboard functions main_btc.cpp serves:
//   /web/share/<hash>   share_detail: the share.html document for a known
//                       share, {"error":"share not found"} for an unknown one
//   /sharechain/window  window_json(window_snapshot): rows carry V (share
//                       version), s, dv and the payout address
//   /sharechain/delta   delta_json(delta_snapshot): the shares after a cursor
//   /sharechain/tip     tip_of

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <core/uint256.hpp>
#include <impl/btc/share.hpp>
#include <impl/btc/share_tracker.hpp>
#include <impl/btc/dashboard_sharechain.hpp>

namespace {

namespace views = core::sharechain_views;

// A hash whose display hex starts with `head` (zero-padded on the right), so
// test shares have distinct 16-hex short hashes, the delta cursor's key.
uint256 hx(const std::string& head) {
    uint256 v;
    v.SetHex(head + std::string(64 - head.size(), '0'));
    return v;
}

constexpr uint32_t kBits    = 0x1d00ffffu;
constexpr uint32_t kMaxBits = 0x1d00ffffu;
constexpr uint64_t kSubsidy = 312500000ull;

// `count` v36 shares, share i's parent i-1 (share 0: null parent). Share i pays
// a distinct P2PKH key, desires version 36 and has a printable coinbase tag.
std::vector<uint256> build_v36_chain(btc::ShareTracker& tracker, int count) {
    std::vector<uint256> hashes;
    uint256 prev;
    for (int i = 0; i < count; ++i) {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "b7c%x", 0x100 + i);
        const uint256 h = hx(buf);
        auto* s = new btc::MergedMiningShare(h, i == 0 ? uint256::ZERO : prev);
        s->m_bits            = kBits;
        s->m_max_bits        = kMaxBits;
        s->m_donation        = 655;
        s->m_desired_version = 36;
        s->m_stale_info      = btc::StaleInfo::none;
        s->m_pubkey_type     = 0;
        s->m_pubkey_hash.SetNull();
        s->m_pubkey_hash.begin()[0] = static_cast<unsigned char>(0x20 + i);
        s->m_min_header.m_version   = 0x20000000;
        s->m_min_header.m_bits      = 0x17034219u;
        s->m_min_header.m_timestamp = 1790000000u + i;
        s->m_min_header.m_nonce     = 77u + i;
        s->m_timestamp  = 1790000000u + i;
        s->m_absheight  = 500 + i;
        s->m_nonce      = 9000u + i;
        s->m_subsidy    = kSubsidy;
        s->m_last_txout_nonce = 0x1122334455667788ull;
        const std::string tag = "/c2pool-btc-test/";
        s->m_coinbase.m_data = {0x03, 0x01, 0x02, 0x03};
        s->m_coinbase.m_data.insert(s->m_coinbase.m_data.end(), tag.begin(), tag.end());
        s->m_far_share_hash = (i >= 2) ? hashes[i - 2] : uint256::ZERO;
        tracker.add(s);
        hashes.push_back(h);
        prev = h;
    }
    return hashes;
}

// A v35 share on top of `prev` (the public BTC chain's version today).
uint256 add_v35_share(btc::ShareTracker& tracker, const uint256& prev, const std::string& tail) {
    const uint256 h = hx(tail);
    auto* s = new btc::PaddingBugfixShare(h, prev);
    s->m_bits            = kBits;
    s->m_max_bits        = kMaxBits;
    s->m_desired_version = 36;
    s->m_stale_info      = btc::StaleInfo::orphan;
    s->m_donation        = 0;
    s->m_nonce           = 1;
    s->m_last_txout_nonce = 0;
    s->m_min_header.m_version   = 0x20000000;
    s->m_min_header.m_bits      = kBits;
    s->m_min_header.m_timestamp = 1790001000u;
    s->m_min_header.m_nonce     = 2;
    const std::string addr = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT";
    s->m_address.m_data.assign(addr.begin(), addr.end());
    s->m_timestamp = 1790001000u;
    s->m_absheight = 900;
    s->m_subsidy   = kSubsidy;
    tracker.add(s);
    return h;
}

} // namespace

TEST(BtcDashboardSharechain, ShareDetailCarriesTheShareHtmlFields)
{
    btc::ShareTracker tracker;
    const auto hashes = build_v36_chain(tracker, 4);
    const uint256 mid = hashes[2];

    const nlohmann::json d = btc::dashboard::share_detail(tracker, mid.GetHex(), /*testnet=*/false);
    ASSERT_FALSE(d.contains("error")) << d.dump();

    EXPECT_EQ(d["hash"], mid.GetHex());
    EXPECT_EQ(d["parent"], hashes[1].GetHex());
    EXPECT_EQ(d["far_parent"], hashes[0].GetHex());
    EXPECT_EQ(d["type_name"], "V36");
    EXPECT_EQ(d["version"], 36);
    EXPECT_EQ(d["is_block_solution"], false);
    ASSERT_TRUE(d["children"].is_array());
    ASSERT_EQ(d["children"].size(), 1u);
    EXPECT_EQ(d["children"][0], hashes[3].GetHex());

    ASSERT_TRUE(d["local"].is_object());
    EXPECT_TRUE(d["local"].contains("verified"));
    EXPECT_TRUE(d["local"].contains("time_first_seen"));
    EXPECT_TRUE(d["local"].contains("peer_first_received_from"));

    const auto& sd = d["share_data"];
    ASSERT_TRUE(sd.is_object());
    EXPECT_EQ(sd["timestamp"], 1790000002u);
    EXPECT_EQ(sd["target"], kBits);
    EXPECT_EQ(sd["max_target"], kMaxBits);
    EXPECT_EQ(sd["nonce"], 9002u);
    EXPECT_EQ(sd["desired_version"], 36);
    EXPECT_EQ(sd["absheight"], 502);
    EXPECT_EQ(sd["stale_info"], 0);
    EXPECT_NEAR(sd["donation"].get<double>(), 655.0 / 65535.0, 1e-12);
    EXPECT_NEAR(sd["difficulty"].get<double>(), 1.0, 1e-9);
    EXPECT_NEAR(sd["min_difficulty"].get<double>(), 1.0, 1e-9);
    EXPECT_TRUE(sd["abswork"].is_string());
    const std::string payout = sd["payout_address"].get<std::string>();
    ASSERT_FALSE(payout.empty());
    EXPECT_EQ(payout[0], '1') << payout;   // mainnet P2PKH, as /current_payouts keys it

    const auto& block = d["block"];
    EXPECT_EQ(block["hash"], mid.GetHex());
    EXPECT_EQ(block["header"]["version"], 0x20000000);
    EXPECT_EQ(block["header"]["target"], 0x17034219u);
    EXPECT_EQ(block["header"]["timestamp"], 1790000002u);
    EXPECT_EQ(block["header"]["nonce"], 79u);
    EXPECT_TRUE(block["header"]["previous_block"].is_string());
    EXPECT_TRUE(block["header"]["merkle_root"].is_null());
    EXPECT_TRUE(block["gentx"]["hash"].is_null());
    EXPECT_NEAR(block["gentx"]["value"].get<double>(), 3.125, 1e-12);
    EXPECT_EQ(block["gentx"]["last_txout_nonce"], 0x1122334455667788ull);
    EXPECT_NE(block["gentx"]["coinbase"].get<std::string>().find("2f6332706f6f6c"), std::string::npos);

    ASSERT_TRUE(d.contains("v36_metadata"));
    EXPECT_TRUE(d["v36_metadata"]["merged_addresses"].is_array());
    EXPECT_EQ(d["v36_metadata"]["message_data_size"], 0u);
}

TEST(BtcDashboardSharechain, ShareDetailUnknownHashIsNotFound)
{
    btc::ShareTracker tracker;
    build_v36_chain(tracker, 3);
    const nlohmann::json miss = btc::dashboard::share_detail(tracker, hx("dead").GetHex(), false);
    EXPECT_EQ(miss, (nlohmann::json{{"error", "share not found"}}));
    const nlohmann::json zero = btc::dashboard::share_detail(tracker, std::string(64, '0'), false);
    EXPECT_EQ(zero, (nlohmann::json{{"error", "share not found"}}));
    const nlohmann::json junk = btc::dashboard::share_detail(tracker, "not-a-hash", false);
    EXPECT_TRUE(junk.contains("error"));
}

TEST(BtcDashboardSharechain, ShareDetailFoundBlockFields)
{
    btc::ShareTracker tracker;
    const auto hashes = build_v36_chain(tracker, 3);
    tracker.chain.get_index(hashes[1])->is_block_solution = true;
    nlohmann::json d = btc::dashboard::share_detail(tracker, hashes[1].GetHex(), false);
    ASSERT_EQ(d["is_block_solution"], true);

    struct Row {
        std::string hash, share_hash;
        uint64_t height;
        uint32_t confirmations;
        int status;
    };
    const std::vector<Row> found = {
        {"aa", "", 1, 1, 0},                          // another block
        {hashes[1].GetHex(), hashes[1].GetHex(), 925000, 6, 1},
    };
    views::add_found_block_fields(d, found, [](const Row&) { return true; });
    EXPECT_EQ(d["block_height"], 925000u);
    EXPECT_EQ(d["block_confirmations"], 6u);
    EXPECT_EQ(d["block_status"], 1);
}

TEST(BtcDashboardSharechain, WindowRowsCarryShareVersion)
{
    btc::ShareTracker tracker;
    const auto hashes = build_v36_chain(tracker, 5);
    const uint256 v35 = add_v35_share(tracker, hashes.back(), "b7cfff");

    const auto snap = btc::dashboard::window_snapshot(tracker);
    const std::vector<std::string> found = {hashes[1].GetHex(), hx("abc").GetHex()};
    const nlohmann::json w = views::window_json(snap, btc::PoolConfig::chain_length(),
                                                "", "", found, false);

    EXPECT_EQ(w["best_hash"], v35.GetHex());
    EXPECT_EQ(w["chain_length"], 6);
    EXPECT_EQ(w["window_size"], static_cast<int>(btc::PoolConfig::chain_length()));
    ASSERT_TRUE(w["shares"].is_array());
    ASSERT_EQ(w["shares"].size(), 6u);
    for (const auto& s : w["shares"]) {
        ASSERT_TRUE(s.contains("V")) << s.dump();
        for (const char* k : {"h", "H", "p", "v", "t", "s", "b", "a", "dv", "m"})
            EXPECT_TRUE(s.contains(k)) << k << " missing in " << s.dump();
        EXPECT_EQ(s["dv"], 36);
        const std::string m = s["m"].get<std::string>();
        ASSERT_FALSE(m.empty());
        EXPECT_EQ(m[0], '1') << m;
    }
    const auto& top = w["shares"][0];
    EXPECT_EQ(top["H"], v35.GetHex());
    EXPECT_EQ(top["V"], 35);
    EXPECT_EQ(top["s"], 253);
    EXPECT_EQ(top["m"], "1BoatSLRHtKNngkdXEeobR76b53LETtpyT");
    EXPECT_EQ(top["p"], 0);
    EXPECT_EQ(w["shares"][1]["V"], 36);
    EXPECT_EQ(w["shares"][1]["cb"], "/c2pool-btc-test/");

    ASSERT_EQ(w["heads"].size(), 1u);
    EXPECT_EQ(w["heads"][0], v35.GetHex().substr(0, 16));
    // block_hashes: only the found blocks whose shares are in the window.
    ASSERT_EQ(w["block_hashes"].size(), 1u);
    EXPECT_EQ(w["block_hashes"][0], hashes[1].GetHex());
    EXPECT_EQ(w["blocks"].size(), 2u);
}

TEST(BtcDashboardSharechain, WindowMarksTheNodeFeeShares)
{
    btc::ShareTracker tracker;
    const auto hashes = build_v36_chain(tracker, 3);
    // Share 1 pays pubkey hash 0x21 00..00: the node fee hash160.
    std::vector<unsigned char> h160(20, 0);
    h160[0] = 0x21;
    const auto snap = btc::dashboard::window_snapshot(tracker);
    const nlohmann::json w = views::window_json(snap, 8640, "", HexStr(h160), {}, false);
    int fee = 0;
    for (const auto& s : w["shares"]) if (s.value("fee", 0) == 1) ++fee;
    EXPECT_EQ(fee, 1);
}

TEST(BtcDashboardSharechain, DeltaStopsAtTheCursor)
{
    btc::ShareTracker tracker;
    const auto hashes = build_v36_chain(tracker, 6);

    const auto snap = btc::dashboard::delta_snapshot(tracker, hashes[3].GetHex().substr(0, 16));
    const nlohmann::json d = views::delta_json(snap, "", {}, false);
    EXPECT_EQ(d["count"], 2);
    ASSERT_EQ(d["shares"].size(), 2u);
    EXPECT_EQ(d["shares"][0]["H"], hashes[5].GetHex());
    EXPECT_EQ(d["shares"][1]["H"], hashes[4].GetHex());
    EXPECT_EQ(d["shares"][0]["V"], 36);
    EXPECT_EQ(d["tip"], hashes[5].GetHex().substr(0, 16));
    EXPECT_FALSE(d.contains("block_hashes"));

    // The full hash is a cursor too.
    const auto snap2 = btc::dashboard::delta_snapshot(tracker, hashes[4].GetHex());
    EXPECT_EQ(views::delta_json(snap2, "", {}, false)["count"], 1);
}

TEST(BtcDashboardSharechain, TipIsTheTallestHead)
{
    btc::ShareTracker empty;
    EXPECT_FALSE(views::tip_of(empty).has_value());

    btc::ShareTracker tracker;
    const auto hashes = build_v36_chain(tracker, 4);
    const auto tip = views::tip_of(tracker);
    ASSERT_TRUE(tip.has_value());
    EXPECT_EQ(tip->hash, hashes.back().GetHex().substr(0, 16));
    EXPECT_EQ(tip->total, 4);
    EXPECT_EQ(tip->height, tracker.chain.get_height(hashes.back()));
}

// main_btc.cpp rebuilds the window when the best share changes (and on the
// 30 s fallback), not on every cache pump tick, and unbinds that refresh
// before the node and the dashboard are torn down.
TEST(BtcDashboardSharechain, WindowRefreshesOnBestShareChange)
{
#ifndef BTC_MAIN_SRC
    GTEST_SKIP() << "BTC_MAIN_SRC not defined";
#else
    std::ifstream f(BTC_MAIN_SRC, std::ios::binary);
    const std::string src((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    ASSERT_FALSE(src.empty());
    const auto window = src.find("mi->set_sharechain_window_fn(");
    const auto tip    = src.find("mi->set_sharechain_tip_fn(", window);
    ASSERT_NE(window, std::string::npos);
    ASSERT_NE(tip, std::string::npos);
    const std::string between = src.substr(window, tip - window);
    EXPECT_NE(between.find("mi->mark_last_cache_tip_driven();"), std::string::npos)
        << "the window cache is tip-driven";
    EXPECT_NE(between.find("set_on_best_share_changed([mi]() { mi->refresh_tip_sensitive_caches(); });"),
              std::string::npos)
        << "a best-share change refreshes the tip-driven caches";
    const auto unbind = src.find("p2p_node->set_on_best_share_changed(nullptr);");
    const auto reset  = src.find("p2p_node.reset();");
    ASSERT_NE(unbind, std::string::npos);
    ASSERT_NE(reset, std::string::npos);
    EXPECT_LT(unbind, reset) << "the refresh is unbound before the node goes";
#endif
}
