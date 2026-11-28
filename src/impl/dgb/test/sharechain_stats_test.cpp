// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The DGB dashboard sharechain stats (rides dgb_work_source_test):
// DASHBOARD-GAPS-DGB.md item 2. The fn reads the tracker under its guard and
// emits LTC's field shape (chain_height, verified_count, the version counts),
// so /global_stats current_height and the sync chain_size are not 0.
// ---------------------------------------------------------------------------

#include <impl/dgb/coin/header_chain.hpp>
#include <impl/dgb/coin/mempool.hpp>
#include <impl/dgb/config_coin.hpp>
#include <impl/dgb/config_pool.hpp>
#include <impl/dgb/share.hpp>
#include <impl/dgb/stratum/work_source.hpp>
#include <impl/dgb/share_tracker.hpp>
#include <impl/dgb/sharechain_stats.hpp>

#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <gtest/gtest.h>

#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#ifndef DGB_MAIN_SRC
#error "DGB_MAIN_SRC must name src/c2pool/main_dgb.cpp"
#endif

namespace {

uint256 add_share(dgb::ShareTracker& t, int n, const uint256& prev, const std::string& addr,
                  uint64_t desired = 35, int stale = 0)
{
    auto* s = new dgb::PaddingBugfixShare();
    uint256 h;
    h.SetHex(std::to_string(8100000 + n));
    s->m_hash = h;
    s->m_prev_hash = prev;
    s->m_bits = 0x1e0fffff;
    s->m_max_bits = 0x1e0fffff;
    s->m_timestamp = 1790000000u + 15u * static_cast<uint32_t>(n);
    s->m_absheight = static_cast<uint32_t>(n);
    s->m_desired_version = desired;
    s->m_stale_info = static_cast<dgb::StaleInfo>(stale);
    s->m_address.m_data.assign(addr.begin(), addr.end());
    dgb::ShareType st;
    st = s;
    t.add(st);
    return h;
}

const std::string kA = "DQ8AwqR2XJE9G5dSEfspJYH7Spre85dj6L";
const std::string kB = "dgb1qzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw";

} // namespace

TEST(DgbSharechainStats, FieldsFromTheTallestHeadOrTheVerifiedBest)
{
    dgb::ShareTracker t;
    std::vector<uint256> hs;
    uint256 prev;
    for (int i = 0; i < 5; ++i) {
        prev = add_share(t, i, prev, i % 2 ? kB : kA, i == 4 ? 36 : 35, i == 2 ? 253 : 0);
        hs.push_back(prev);
    }
    const int tip_height = static_cast<int>(t.chain.get_height(hs.back()));
    ASSERT_EQ(tip_height, 5);

    const auto r = dgb::sharechain_stats_json(t, uint256());   // no verified best: the tallest head
    EXPECT_EQ(r["chain_tip_hash"], hs.back().GetHex());
    EXPECT_EQ(r["chain_height"], 5);
    EXPECT_EQ(r["chain_length"], static_cast<int>(dgb::PoolConfig::chain_length()));
    EXPECT_EQ(r["fork_count"], 1);
    EXPECT_EQ(r["verified_count"], 0);
    EXPECT_EQ(r["total_shares"], 5);
    EXPECT_EQ(r["orphan_shares"], 1);
    EXPECT_EQ(r["dead_shares"], 0);
    EXPECT_EQ(r["shares_by_version"]["35"], 5);
    EXPECT_EQ(r["shares_by_desired_version"]["35"], 4);
    EXPECT_EQ(r["shares_by_desired_version"]["36"], 1);
    EXPECT_EQ(r["shares_by_miner"].size(), 2u);
    const double d = chain::target_to_difficulty(chain::bits_to_target(0x1e0fffff));
    EXPECT_DOUBLE_EQ(r["min_difficulty"].get<double>(), d);
    EXPECT_DOUBLE_EQ(r["average_difficulty"].get<double>(), d);
    EXPECT_DOUBLE_EQ(r["pool_stale_prop"].get<double>(), 1.0 / (5 + 1));   // lookbehind min(5, 240)

    // A verified best in the chain anchors the walk.
    const auto v = dgb::sharechain_stats_json(t, hs[3]);
    EXPECT_EQ(v["chain_tip_hash"], hs[3].GetHex());
    EXPECT_EQ(v["chain_height"], 4);
    EXPECT_EQ(v["total_shares"], 4);
    EXPECT_EQ(v["shares_by_desired_version"].count("36"), 0u);

    // A best not in the chain falls back to the tallest head.
    uint256 stranger;
    stranger.SetHex("abcdef");
    EXPECT_EQ(dgb::sharechain_stats_json(t, stranger)["chain_tip_hash"], hs.back().GetHex());
}

TEST(DgbSharechainStats, EmptyChainIsZeroNotAnError)
{
    dgb::ShareTracker t;
    const auto r = dgb::sharechain_stats_json(t, uint256());
    EXPECT_EQ(r["chain_tip_hash"], "");
    EXPECT_EQ(r["chain_height"], 0);
    EXPECT_EQ(r["total_shares"], 0);
    EXPECT_EQ(r["fork_count"], 0);
    EXPECT_FALSE(r.contains("min_difficulty"));
    EXPECT_DOUBLE_EQ(r["pool_stale_prop"].get<double>(), 0.0);
}

TEST(DgbSharechainStats, MainDgbReadsUnderTheGuard)
{
    std::ifstream f(DGB_MAIN_SRC);
    ASSERT_TRUE(f.good()) << DGB_MAIN_SRC;
    std::stringstream ss;
    ss << f.rdbuf();
    const std::string s = ss.str();
    const auto fn = s.find("mi->set_sharechain_stats_fn(");
    ASSERT_NE(fn, std::string::npos);
    const auto end = s.find("mi->set_sharechain_window_fn(", fn);
    ASSERT_NE(end, std::string::npos);
    const std::string body = s.substr(fn, end - fn);
    EXPECT_NE(body.find("auto guard = p2p_node.read_tracker();"), std::string::npos);
    EXPECT_NE(body.find("dgb::sharechain_stats_json(*guard, best);"), std::string::npos);
    EXPECT_NE(body.find("const uint256 best = cell->get();"), std::string::npos)
        << "the best share is not the stratum cell's";
    EXPECT_EQ(body.find("best_share_hash()"), std::string::npos) << "IO-thread state read on the HTTP thread";
    EXPECT_EQ(body.find("out[\"chain_height\"] = snap.chain_count"), std::string::npos) << "a count as a height";
    EXPECT_NE(body.find("p2p_node.get_tracker_snapshot()"), std::string::npos) << "no busy-path fallback";
    EXPECT_EQ(body.find("p2p_node.tracker()"), std::string::npos) << "an unguarded tracker read";
}

// The dashboard's block value / network difficulty / height come from the
// last template served; reading them builds nothing.
TEST(DgbDashboardHooks, LastTemplateSummaryIsAPlainRead)
{
    c2pool::dgb::HeaderChain hc;
    dgb::coin::Mempool mempool;
    hc.set_base_height(20000000);
    dgb::stratum::DGBWorkSource ws(hc, mempool, false, [](const std::vector<unsigned char>&, uint32_t) { return false; },
                                   [](uint32_t h) -> uint64_t { return dgb::CoinParams::subsidy(h); });
    int gbt_calls = 0;
    ws.set_gbt_tip_fn([&gbt_calls]() -> std::optional<dgb::stratum::DGBWorkSource::GbtTip> {
        ++gbt_calls;
        return dgb::stratum::DGBWorkSource::GbtTip{std::string(64, '1'), "1a00ffff", 20000000};
    });
    EXPECT_FALSE(ws.last_template_summary().has_value());
    EXPECT_EQ(gbt_calls, 0) << "the summary read reached digibyted";
    const auto t = ws.get_current_work_template();
    ASSERT_FALSE(t.empty());
    const auto sum = ws.last_template_summary();
    ASSERT_TRUE(sum.has_value());
    EXPECT_EQ(sum->height, 20000000u);
    EXPECT_EQ(sum->bits, 0x1a00ffffu);
    EXPECT_EQ(sum->coinbase_value, t["coinbasevalue"].get<uint64_t>());
    EXPECT_GT(sum->coinbase_value, 0u);
}

TEST(DgbDashboardHooks, MainDgbBindsBestShareCoinWorkAndAGuardedHashrate)
{
    std::ifstream f(DGB_MAIN_SRC);
    ASSERT_TRUE(f.good()) << DGB_MAIN_SRC;
    std::stringstream ss;
    ss << f.rdbuf();
    const std::string s = ss.str();
    EXPECT_NE(s.find("mi->set_best_share_hash_fn([cell = stratum_best_share]() { return cell->get(); });"),
              std::string::npos);
    const auto cw = s.find("mi->set_coin_work_fn(");
    ASSERT_NE(cw, std::string::npos);
    EXPECT_NE(s.find("ws->last_template_summary()", cw), std::string::npos);
    const auto hr = s.find("mi->set_pool_hashrate_fn(");
    ASSERT_NE(hr, std::string::npos);
    const std::string body = s.substr(hr, s.find("});", hr) - hr);
    EXPECT_NE(body.find("auto guard = p2p_node.read_tracker();"), std::string::npos);
    EXPECT_EQ(body.find("p2p_node.tracker()"), std::string::npos) << "an unguarded tracker read";
}
