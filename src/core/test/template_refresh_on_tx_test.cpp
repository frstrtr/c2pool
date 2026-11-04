// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// Transaction-triggered template refresh (#2137 S1; rides core_test).
//
// The embedded LTC node rebuilt its template on blocks, MWEB state and
// sharechain best-share changes only; the debounced share refresh drops its
// trailing call when the sharechain tip did not move, so between shares the
// template aged by tens of seconds while transactions arrived. Pinned here:
//   - core::TxRefreshPacer: changes inside the interval coalesce into one
//     rebuild at its end, counted from the last rebuild of any cause; a
//     change after a quiet interval rebuilds at once; a change another
//     rebuild covered costs nothing; a rebuild that ran meanwhile re-arms the
//     timer instead of a second rebuild inside the interval; a rebuild over
//     500 ms backs the interval off to 2 s;
//   - a REAL WebServer + MiningInterface over a mock coin node: after a
//     sharechain-unchanged debounce window (its trailing refresh dropped) two
//     priced txs within a second still give exactly one rebuild, and
//     /local_stats template_refresh counts it under "tx" next to "share".
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <chrono>
#include <string>

#include <nlohmann/json.hpp>

#include <core/template_refresh.hpp>
#include <core/web_server.hpp>
#include <core/coin/node_iface.hpp>
#include <core/coin/work_view.hpp>

namespace {

using core::TxRefreshPacer;
using clk = TxRefreshPacer::clock;
using std::chrono::milliseconds;

// A coin node that counts template builds.
struct CountingCoinNode : public core::coin::ICoinNode {
    int builds = 0;
    core::coin::WorkView get_work_view() override
    {
        ++builds;
        core::coin::WorkView v;
        v.m_data = {
            {"previousblockhash", std::string(62, '0') + "ab"},
            {"version", 0x20000000},
            {"height", 100},
            {"bits", "207fffff"},
            {"curtime", 1600000000},
            {"coinbasevalue", 5000000000LL},
            {"transactions", nlohmann::json::array()},
            {"rules", nlohmann::json::array({"segwit"})},
            {"mweb", ""},
        };
        return v;
    }
    bool submit_block_hex(const std::string&, bool) override { return true; }
    bool is_embedded() const override { return true; }
    bool has_rpc() const override { return false; }
};

} // namespace

// Two txs priced within the interval after a rebuild: one rebuild, at the
// end of the interval.
TEST(TemplateRefreshOnTx, TwoChangesWithinTheIntervalRebuildOnce)
{
    TxRefreshPacer p;
    const auto t0 = clk::now();
    p.on_rebuild(t0, milliseconds(100), p.changes());  // a block's rebuild

    auto a = p.on_change(t0 + milliseconds(100));
    EXPECT_FALSE(a.rebuild);
    ASSERT_TRUE(a.schedule);
    EXPECT_EQ(a.at, t0 + TxRefreshPacer::INTERVAL);
    auto b = p.on_change(t0 + milliseconds(300));
    EXPECT_FALSE(b.rebuild);
    EXPECT_FALSE(b.schedule) << "the armed timer covers the second change";

    auto t = p.on_timer(t0 + TxRefreshPacer::INTERVAL);
    EXPECT_TRUE(t.rebuild);
    p.on_rebuild(t0 + TxRefreshPacer::INTERVAL, milliseconds(100), p.changes());
    EXPECT_EQ(p.covered(), 2u);
    EXPECT_FALSE(p.timer_armed());
}

// After a quiet interval a change rebuilds at once (no rebuild yet counts as
// quiet).
TEST(TemplateRefreshOnTx, ChangeAfterAQuietIntervalRebuildsAtOnce)
{
    TxRefreshPacer p;
    const auto t0 = clk::now();
    EXPECT_TRUE(p.on_change(t0).rebuild) << "no rebuild yet";
    p.on_rebuild(t0, milliseconds(50), p.changes());
    auto c = p.on_change(t0 + milliseconds(1500));
    EXPECT_TRUE(c.rebuild);
    EXPECT_FALSE(c.schedule);
}

// A change that another rebuild (a share's, a block's) covered before the
// timer fired costs nothing.
TEST(TemplateRefreshOnTx, ChangeCoveredByAnotherRebuildSkips)
{
    TxRefreshPacer p;
    const auto t0 = clk::now();
    p.on_rebuild(t0, milliseconds(50), p.changes());
    ASSERT_TRUE(p.on_change(t0 + milliseconds(100)).schedule);
    p.on_rebuild(t0 + milliseconds(500), milliseconds(50), p.changes());  // covers it
    auto t = p.on_timer(t0 + TxRefreshPacer::INTERVAL);
    EXPECT_FALSE(t.rebuild);
    EXPECT_FALSE(t.schedule);
}

// A rebuild that ran while the timer was armed, followed by another change:
// the timer re-arms for one interval after that rebuild, never a second
// rebuild inside it.
TEST(TemplateRefreshOnTx, RebuildMeanwhileReArmsTheTimer)
{
    TxRefreshPacer p;
    const auto t0 = clk::now();
    p.on_rebuild(t0, milliseconds(50), p.changes());
    ASSERT_TRUE(p.on_change(t0 + milliseconds(100)).schedule);
    p.on_rebuild(t0 + milliseconds(800), milliseconds(50), p.changes());  // covers change 1
    EXPECT_FALSE(p.on_change(t0 + milliseconds(900)).schedule);           // timer still armed
    auto t = p.on_timer(t0 + TxRefreshPacer::INTERVAL);
    EXPECT_FALSE(t.rebuild);
    ASSERT_TRUE(t.schedule);
    EXPECT_EQ(t.at, t0 + milliseconds(800) + TxRefreshPacer::INTERVAL);
    EXPECT_TRUE(p.on_timer(t.at).rebuild);
}

// A rebuild over 500 ms backs the interval off to 2 s; a fast one restores 1 s.
TEST(TemplateRefreshOnTx, SlowRebuildBacksOffToTwoSeconds)
{
    TxRefreshPacer p;
    const auto t0 = clk::now();
    p.on_rebuild(t0, milliseconds(600), p.changes());
    EXPECT_EQ(p.interval(), TxRefreshPacer::SLOW_INTERVAL);
    auto c = p.on_change(t0 + milliseconds(1200));
    EXPECT_FALSE(c.rebuild) << "1.2 s after a slow rebuild is inside the 2 s interval";
    ASSERT_TRUE(c.schedule);
    EXPECT_EQ(c.at, t0 + TxRefreshPacer::SLOW_INTERVAL);
    EXPECT_TRUE(p.on_timer(c.at).rebuild);
    p.on_rebuild(c.at, milliseconds(500), p.changes());
    EXPECT_EQ(p.interval(), TxRefreshPacer::INTERVAL) << "500 ms is not over the bound";
    EXPECT_EQ(std::string(core::refresh_cause_name(core::RefreshCause::tx)), "tx");
    EXPECT_EQ(std::string(core::refresh_cause_name(core::RefreshCause::mweb)), "mweb");
}

// The production path: a share refresh, its trailing refresh dropped on the
// unchanged sharechain tip, then two priced txs within a second -> exactly
// one more rebuild, counted under "tx".
TEST(TemplateRefreshOnTx, WebServerRebuildsOnTxAfterAnUnchangedSharechainWindow)
{
    boost::asio::io_context ioc;
    core::WebServer ws(ioc, "127.0.0.1", 0, /*testnet=*/true);
    ws.set_stratum_port(0);
    CountingCoinNode node;
    core::MiningInterface* mi = ws.get_mining_interface();
    ASSERT_NE(mi, nullptr);
    mi->set_coin_node(&node);
    ASSERT_TRUE(ws.start());

    auto run = [&ioc](milliseconds d) {
        ioc.restart();
        ioc.run_for(d);
    };

    // Share refresh: leading edge, at once.
    ws.trigger_work_refresh_debounced();
    EXPECT_EQ(node.builds, 1);
    // A second one inside the 300 ms window: its trailing refresh is gated on
    // a sharechain change and dropped.
    ws.trigger_work_refresh_debounced();
    run(milliseconds(450));
    EXPECT_EQ(node.builds, 1) << "the debounced trailing refresh was dropped";

    // Two txs priced within a second, less than the interval after the share
    // rebuild: one rebuild at the end of the interval.
    ws.trigger_work_refresh_mempool();
    ws.trigger_work_refresh_mempool();
    EXPECT_EQ(node.builds, 1) << "paced: the share rebuild was under 1 s ago";
    run(milliseconds(1200));
    EXPECT_EQ(node.builds, 2) << "the tx-triggered rebuild fired on an unchanged sharechain";
    run(milliseconds(1200));
    EXPECT_EQ(node.builds, 2) << "nothing new to cover";

    const auto stats = mi->rest_local_stats();
    ASSERT_TRUE(stats.contains("template_refresh"));
    const auto& tr = stats["template_refresh"];
    EXPECT_EQ(tr["by_cause"]["share"].get<uint64_t>(), 1u);
    EXPECT_EQ(tr["by_cause"]["tx"].get<uint64_t>(), 1u);
    EXPECT_EQ(tr["by_cause"]["block"].get<uint64_t>(), 0u);
    EXPECT_EQ(tr["by_cause"]["mweb"].get<uint64_t>(), 0u);
    EXPECT_TRUE(tr["ms_last"].is_number_unsigned());
    EXPECT_EQ(tr["last_cause"], "tx");
    EXPECT_EQ(tr["tx_changes"].get<uint64_t>(), 2u);

    // After a quiet interval a priced tx rebuilds at once; the immediate
    // refresh counts under its own cause.
    ws.trigger_work_refresh_mempool();
    EXPECT_EQ(node.builds, 3);
    ws.trigger_work_refresh(core::RefreshCause::mweb);
    EXPECT_EQ(node.builds, 4);
    EXPECT_EQ(mi->rest_local_stats()["template_refresh"]["by_cause"]["mweb"].get<uint64_t>(), 1u);
    ws.stop();
}
