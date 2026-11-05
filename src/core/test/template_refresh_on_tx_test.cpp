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
//     timer instead of a second rebuild inside the interval;
//   - the interval scales with the rebuild cost (>= 4x: tx rebuilds take at
//     most about 25 % of the io thread);
//   - a REAL WebServer + MiningInterface over a mock coin node: after a
//     sharechain-unchanged debounce window (its trailing refresh dropped) two
//     priced txs within a second still give exactly one rebuild, and
//     /local_stats template_refresh counts it under "tx" next to "share"; a
//     tx rebuild that installed the same template notifies nobody;
//   - every session's job of one template generation shares one tx-hex
//     vector: 256 generations x 8 sessions retain 256 vectors (measured).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <chrono>
#include <cstdio>
#include <iostream>
#include <memory>
#include <set>
#include <span>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <core/hash.hpp>
#include <core/template_refresh.hpp>
#include <core/uint256.hpp>
#include <core/web_server.hpp>
#include <core/coin/node_iface.hpp>
#include <core/coin/work_view.hpp>

#include <btclibs/util/strencodings.h>

namespace {

using core::TxRefreshPacer;
using clk = TxRefreshPacer::clock;
using std::chrono::milliseconds;

// A coin node that counts template builds.
struct CountingCoinNode : public core::coin::ICoinNode {
    int builds = 0;
    int64_t coinbasevalue = 5000000000LL;
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
            {"coinbasevalue", coinbasevalue},
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

// The interval is at least 1 s and at least 4 rebuild costs, so tx rebuilds
// take at most about 25 % of the io thread: a 600 ms rebuild widens it to
// 2.4 s at once, a 1.5 s one to 6 s; cheap rebuilds narrow it by a quarter
// each, back to the 1 s floor.
TEST(TemplateRefreshOnTx, BackOffScalesWithTheRebuildCost)
{
    TxRefreshPacer p;
    const auto t0 = clk::now();
    p.on_rebuild(t0, milliseconds(100), p.changes());
    EXPECT_EQ(p.interval(), TxRefreshPacer::INTERVAL) << "400 ms of cost: the 1 s floor";
    p.on_rebuild(t0, milliseconds(600), p.changes());
    EXPECT_EQ(p.interval(), milliseconds(2400));
    auto c = p.on_change(t0 + milliseconds(1200));
    EXPECT_FALSE(c.rebuild) << "1.2 s after a 600 ms rebuild is inside its 2.4 s interval";
    ASSERT_TRUE(c.schedule);
    EXPECT_EQ(c.at, t0 + milliseconds(2400));
    EXPECT_TRUE(p.on_timer(c.at).rebuild);
    p.on_rebuild(c.at, milliseconds(1500), p.changes());
    EXPECT_EQ(p.interval(), milliseconds(6000)) << "duty 1.5 s / 6 s = 25 %";
    // Cheap rebuilds (a HOLD returning early) decay the estimate, never at once.
    p.on_rebuild(c.at, milliseconds(0), p.changes());
    EXPECT_EQ(p.cost(), milliseconds(1125));
    for (int i = 0; i < 12; ++i)
        p.on_rebuild(c.at, milliseconds(0), p.changes());
    EXPECT_EQ(p.interval(), TxRefreshPacer::INTERVAL);
    // Duty bound over a run of equal rebuilds: cost / interval <= 1/4.
    for (int took : {50, 250, 400, 700, 2000}) {
        TxRefreshPacer q;
        q.on_rebuild(t0, milliseconds(took), q.changes());
        EXPECT_LE(4 * took, q.interval().count()) << took << " ms";
    }
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
    EXPECT_EQ(tr["tx_unchanged"].get<uint64_t>(), 1u)
        << "the tx rebuild installed the same template: nobody notified";

    // After a quiet interval a priced tx rebuilds at once; this time the
    // template changed (a fee came in), so it is pushed. The immediate
    // refresh counts under its own cause.
    node.coinbasevalue += 1'000;
    ws.trigger_work_refresh_mempool();
    EXPECT_EQ(node.builds, 3);
    EXPECT_EQ(mi->rest_local_stats()["template_refresh"]["tx_unchanged"].get<uint64_t>(), 1u)
        << "a changed template is not counted as unchanged";
    ws.trigger_work_refresh(core::RefreshCause::mweb);
    EXPECT_EQ(node.builds, 4);
    EXPECT_EQ(mi->rest_local_stats()["template_refresh"]["by_cause"]["mweb"].get<uint64_t>(), 1u);
    ws.stop();
}

namespace {

// A legacy 1-in/1-out tx whose prevout encodes `n`, and its txid.
std::string legacy_tx_hex(uint32_t n)
{
    char prev[65];
    std::snprintf(prev, sizeof(prev), "%08x%056x", n, 0u);
    return std::string("01000000") + "01" + prev + "00000000" + "00" + "ffffffff"
         + "01" + "00e1f50500000000" + "00" + "00000000";
}

std::string txid_of(const std::string& hex)
{
    const auto bytes = ParseHex(hex);
    return Hash(std::span<const unsigned char>(bytes.data(), bytes.size())).GetHex();
}

// A coin node serving a template of `n_txs` txs; each generation shifts the
// tx set by one (a tx confirmed, a new one priced), as a tx refresh does.
struct TxTemplateNode : public core::coin::ICoinNode {
    uint32_t n_txs = 0;
    uint32_t generation = 0;
    std::string degraded;  // kTemplateDegradedKey, when set
    core::coin::WorkView get_work_view() override
    {
        nlohmann::json txs = nlohmann::json::array();
        for (uint32_t i = 0; i < n_txs; ++i) {
            const std::string hex = legacy_tx_hex(generation + i);
            const std::string id = txid_of(hex);
            txs.push_back({{"data", hex}, {"txid", id}, {"hash", id}});
        }
        core::coin::WorkView v;
        v.m_data = {
            {"previousblockhash", std::string(62, '0') + "ab"},
            {"version", 0x20000000},
            {"height", 100},
            {"bits", "207fffff"},
            {"curtime", 1600000000},
            {"coinbasevalue", 5000000000LL},
            {"transactions", txs},
            {"rules", nlohmann::json::array({"segwit"})},
            {"mweb", ""},
        };
        if (!degraded.empty())
            v.m_data["degraded"] = degraded;
        for (const auto& t : txs) {
            uint256 h;
            h.SetHex(t["txid"].get<std::string>());
            v.m_hashes.push_back(h);
        }
        return v;
    }
    bool submit_block_hex(const std::string&, bool) override { return true; }
    bool is_embedded() const override { return true; }
    bool has_rpc() const override { return false; }
};

} // namespace

// Every connection's job of one template generation points at ONE tx-hex
// vector (#2137): a notify used to deep-copy the template and rebuild the
// tx hex per session, so 256 jobs x N sessions each held a copy (the
// verifier measured 512 MB per session for a full block at 1 notify/s).
// Pinned as a measurement: 256 generations (256 s at one notify a second)
// x 8 sessions retain 256 vectors, not 2,048, and their bytes do not grow
// with the session count.
TEST(TemplateRefreshOnTx, SessionsShareOneTxDataPerGeneration)
{
    core::MiningInterface mi{/*testnet=*/true};
    TxTemplateNode node;
    node.n_txs = 200;
    mi.set_coin_node(&node);
    mi.set_ref_hash_fn([](const uint256&, const std::vector<unsigned char>&,
                          const std::vector<unsigned char>&, uint64_t, uint32_t, uint32_t,
                          bool, const std::string&, const uint256&,
                          const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>&,
                          const std::vector<uint256>&) {
        core::MiningInterface::RefHashResult r;
        r.ref_hash.SetHex(std::string(64, '5'));
        r.bits = 0x207fffff;
        return r;
    });
    const std::vector<unsigned char> payout{0x76, 0xa9, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                                            11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0x88, 0xac};
    constexpr int kGenerations = 256;
    constexpr int kSessions = 8;
    std::vector<std::shared_ptr<const std::vector<std::string>>> jobs;  // every session's job store
    jobs.reserve(kGenerations * kSessions);
    for (int g = 0; g < kGenerations; ++g) {
        node.generation = static_cast<uint32_t>(g);
        mi.refresh_work();
        const auto cached = mi.get_cached_tx_data();
        ASSERT_TRUE(cached) << g;
        ASSERT_EQ(cached->size(), node.n_txs) << g;
        for (int s = 0; s < kSessions; ++s) {
            char en1[9];
            std::snprintf(en1, sizeof(en1), "%08x", s);
            auto cbr = mi.build_connection_coinbase(uint256(), en1, payout, {});
            ASSERT_FALSE(cbr.coinb1.empty()) << g << "/" << s;
            ASSERT_EQ(cbr.snapshot.tx_data.get(), cached.get()) << "session " << s << " copied the tx hex";
            jobs.push_back(cbr.snapshot.tx_data);
        }
    }
    std::set<const std::vector<std::string>*> distinct;
    size_t retained = 0;
    size_t one_generation = 0;
    for (const auto& j : jobs) {
        if (distinct.insert(j.get()).second) {
            size_t bytes = 0;
            for (const auto& h : *j)
                bytes += h.size();
            retained += bytes;
            one_generation = bytes;
        }
    }
    EXPECT_EQ(distinct.size(), static_cast<size_t>(kGenerations))
        << "one tx-hex vector per generation, whatever the session count";
    const size_t per_session_copies = one_generation * kGenerations * kSessions;
    std::cout << "[MEASURE] tx hex retained by " << kSessions << " sessions x " << kGenerations
              << " jobs (one notify a second): " << retained << " bytes shared ("
              << one_generation << " per generation) vs " << per_session_copies
              << " bytes with a copy per session job" << std::endl;
    EXPECT_EQ(retained * kSessions, per_session_copies);
}

// The embedded LTC builder's empty template on the tip (#2136) is valid work:
// ingress serves it -- no HOLD, not the MWEB-degraded state that refuses LTC
// blocks at assembly -- and /local_stats template_degraded counts it by code.
TEST(TemplateRefreshOnTx, EmptyTemplateOnTheTipIsServedAndCounted)
{
    core::MiningInterface mi{/*testnet=*/true};
    TxTemplateNode node;
    node.degraded = "utxo-view-not-at-tip";
    mi.set_coin_node(&node);
    mi.refresh_work();
    EXPECT_EQ(mi.get_current_gbt_prevhash(), std::string(62, '0') + "ab") << "served";
    EXPECT_FALSE(mi.is_work_degraded()) << "valid work: LTC blocks from it are submitted";
    EXPECT_FALSE(mi.is_mweb_holding());
    mi.refresh_work();
    const auto stats = mi.rest_local_stats();
    ASSERT_TRUE(stats.contains("template_degraded"));
    EXPECT_EQ(stats["template_degraded"]["utxo-view-not-at-tip"].get<uint64_t>(), 2u);
}
