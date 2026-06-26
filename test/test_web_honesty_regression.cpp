// Web honesty-regression KAT (SAFE-ADDITIVE characterization test).
//
// Charter: "A dashboard must never lie about prod health." (founding bug
// 2026-06-22 -- the getinfo / local_stats surface reported connections=0 and
// poolhashps=0 while the node was fully peered + mining, because the embedded
// prod build runs MiningInterface with an UNPOPULATED m_node (the enhanced_node
// stub whose peer/hashrate/share accessors all return 0). It lied to the
// operator TWICE in one night about contabo LTC+DOGE prod health.)
//
// This test pins the un-stub fix in place: it constructs MiningInterface with
// node == nullptr -- the exact embedded-prod topology that produced the false
// zeros -- and verifies getinfo() sources connections / poolhashps / poolshares
// / difficulty from the live MiningInterface hooks instead of collapsing to the
// historical 0-stubs. If anyone re-introduces the m_node-only path, these
// expectations fail loudly.
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <core/web_server.hpp>

using namespace core;
using nlohmann::json;

// With an empty m_node but live hooks wired, getinfo must report TRUTH, not the
// historical zeros.
TEST(WebHonestyRegression, GetInfoSourcesLiveHooksNotZeroStubs) {
    // node == nullptr: the embedded-prod topology where every m_node accessor
    // returns 0 -- the founding-bug scenario.
    MiningInterface mi(/*testnet=*/true, /*node=*/nullptr);

    // 7 real c2pool share-peers (the prod node ran 6-7 V36 share peers on the
    // night of the founding bug while the dashboard said "0").
    mi.set_peer_info_fn([] {
        json peers = json::array();
        for (int i = 0; i < 7; ++i)
            peers.push_back(json{{"addr", "10.0.0." + std::to_string(i)}});
        return peers;
    });
    // Real pool hashrate -- 62.2 GH/s was the verified contabo prod truth once
    // the stub was fixed (see founding-charter-verified-prod).
    mi.set_pool_hashrate_fn([] { return 62.2e9; });
    // Live sharechain stats (same truthful source #462 used for stale/DOA).
    mi.set_sharechain_stats_fn([] {
        return json{{"total_shares", 12345}, {"average_difficulty", 1024.0}};
    });

    json r = mi.getinfo("kat");

    // The four metrics that the founding bug zeroed out:
    EXPECT_EQ(r["connections"].get<int>(), 7)
        << "share-peer count must come from m_peer_info_fn, not the 0-stub";
    EXPECT_GT(r["poolhashps"].get<double>(), 0.0)
        << "pool hashrate must come from m_pool_hashrate_fn, not the 0-stub";
    EXPECT_DOUBLE_EQ(r["poolhashps"].get<double>(), 62.2e9);
    EXPECT_EQ(r["poolshares"].get<uint64_t>(), 12345u)
        << "poolshares must come from the live sharechain stats hook";
    EXPECT_GT(r["difficulty"].get<double>(), 0.0)
        << "difficulty must come from the live sharechain stats hook";
}

// Belt-and-braces: a nodeless interface with NO hooks still returns a
// well-formed object whose un-stub keys are STRUCTURALLY present (value 0).
// Absent telemetry reporting a structural 0 ("not instrumented") is honest --
// distinct from the founding lie of reporting 0 while live data exists.
TEST(WebHonestyRegression, GetInfoWellFormedWithoutHooks) {
    MiningInterface mi(/*testnet=*/true, /*node=*/nullptr);

    json r = mi.getinfo("kat");
    ASSERT_TRUE(r.is_object());
    EXPECT_TRUE(r.contains("connections"));
    EXPECT_TRUE(r.contains("poolhashps"));
    EXPECT_TRUE(r.contains("poolshares"));
    EXPECT_TRUE(r.contains("difficulty"));
}

// --- getstats: same founding-bug surface as getinfo --------------------------
// getstats() reported connected_peers=0 / pool_hashrate=0 and zeroed orphan/DOA/
// stale share counts whenever m_node was the empty embedded-prod stub, while
// /stale_rates (the same m_sharechain_stats_fn hook) showed the truth. Pin the
// un-stub: with node==nullptr and live hooks wired, pool_statistics must report
// real peers / hashrate / orphan / DOA / stale.
TEST(WebHonestyRegression, GetStatsSourcesLiveHooksNotZeroStubs) {
    MiningInterface mi(/*testnet=*/true, /*node=*/nullptr);

    mi.set_peer_info_fn([] {
        json peers = json::array();
        for (int i = 0; i < 7; ++i)
            peers.push_back(json{{"addr", "10.0.0." + std::to_string(i)}});
        return peers;
    });
    mi.set_pool_hashrate_fn([] { return 62.2e9; });
    // 1000 total shares, 30 orphan + 10 dead -> 40 stale, 4% stale_prop.
    mi.set_sharechain_stats_fn([] {
        return json{{"total_shares", 1000}, {"orphan_shares", 30}, {"dead_shares", 10}};
    });

    json r = mi.getstats("kat");
    ASSERT_TRUE(r.contains("pool_statistics"));
    const json& ps = r["pool_statistics"];

    EXPECT_EQ(ps["connected_peers"].get<int>(), 7)
        << "connected_peers must come from m_peer_info_fn, not the 0-stub";
    EXPECT_DOUBLE_EQ(ps["pool_hashrate"].get<double>(), 62.2e9)
        << "pool_hashrate must come from m_pool_hashrate_fn, not the 0-stub";
    EXPECT_EQ(ps["orphan_shares"].get<uint64_t>(), 30u)
        << "orphan_shares must come from the live sharechain stats hook";
    EXPECT_EQ(ps["doa_shares"].get<uint64_t>(), 10u)
        << "doa_shares must come from the live sharechain stats hook";
    EXPECT_EQ(ps["stale_shares"].get<uint64_t>(), 40u)
        << "stale_shares = orphan + dead from the live hook";
    EXPECT_DOUBLE_EQ(ps["stale_prop"].get<double>(), 0.04)
        << "stale_prop = (orphan+dead)/total from the live hook";
}

// Belt-and-braces: nodeless interface with NO hooks still returns a well-formed
// getstats whose un-stub keys are structurally present (honest 0 = "not
// instrumented", distinct from the founding lie of 0-while-live-data-exists).
TEST(WebHonestyRegression, GetStatsWellFormedWithoutHooks) {
    MiningInterface mi(/*testnet=*/true, /*node=*/nullptr);

    json r = mi.getstats("kat");
    ASSERT_TRUE(r.contains("pool_statistics"));
    const json& ps = r["pool_statistics"];
    EXPECT_TRUE(ps.contains("connected_peers"));
    EXPECT_TRUE(ps.contains("pool_hashrate"));
    EXPECT_TRUE(ps.contains("orphan_shares"));
    EXPECT_TRUE(ps.contains("doa_shares"));
    EXPECT_TRUE(ps.contains("stale_shares"));
}

// --- getpeerinfo: the real per-peer list, not the 0-count fallback -----------
// On the embedded-prod build m_node->get_connected_peers_count() returns 0 while
// the node is fully peered. getpeerinfo() must return the real per-peer list
// from m_peer_info_fn -- not the single {connected_peers:0} aggregate fallback.
TEST(WebHonestyRegression, GetPeerInfoReturnsLivePeerListNotZeroStub) {
    MiningInterface mi(/*testnet=*/true, /*node=*/nullptr);

    mi.set_peer_info_fn([] {
        json peers = json::array();
        for (int i = 0; i < 7; ++i)
            peers.push_back(json{{"addr", "10.0.0." + std::to_string(i)}});
        return peers;
    });

    json r = mi.getpeerinfo("kat");
    ASSERT_TRUE(r.is_array());
    EXPECT_EQ(r.size(), 7u)
        << "getpeerinfo must return the real per-peer list from m_peer_info_fn";
    EXPECT_EQ(r[0]["addr"].get<std::string>(), "10.0.0.0");
}

// Without a live hook and without a node, getpeerinfo returns an empty array --
// honest absence (no peers reported because none are observable), never a
// fabricated count.
TEST(WebHonestyRegression, GetPeerInfoEmptyWithoutHooksIsHonest) {
    MiningInterface mi(/*testnet=*/true, /*node=*/nullptr);

    json r = mi.getpeerinfo("kat");
    ASSERT_TRUE(r.is_array());
    EXPECT_TRUE(r.empty())
        << "no node + no hook -> empty list (honest absence), not a fake count";
}
