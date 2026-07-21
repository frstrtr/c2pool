// SPDX-License-Identifier: AGPL-3.0-or-later
/// DASH-isolated CoinPeerManager (network-standalone arm) — scoring/selection KATs
///
/// Exercises src/impl/dash/coin/coin_peer_manager.hpp — the DASH-local peer
/// manager that lets the embedded coin-network arm reach the Dash network on
/// its OWN scored, group-diverse peer set (independent of the local dashd),
/// the precondition for a daemonless c2pool-dash. This is a self-contained
/// copy of the merged manager (isolation fence — see the header preamble);
/// these KATs pin the ported behaviour on the DASH side:
///
///   (a) source scoring — daemon-learned (coind) peers penalised (-20),
///       addr-crawl peers preferred (+50): the 70-point swing that pulls the
///       embedded arm OFF the dashd peer view onto an independent one.
///   (b) selection ordering — get_peers_to_connect() returns addr-crawl peers
///       ahead of daemon-learned peers.
///   (c) network-group (Sybil) cap — no more than max_new_peers_per_group
///       untried peers admitted from a single /16.
///   (d) anchor persistence — a successfully-connected peer is remembered as
///       an anchor across a save/reload (partition resistance across restart).
///   (e) protected local node — the pinned dashd is admitted (local/private
///       allowed), scored 999999, and never pruned.
///
/// Pure manager-level tests (no sockets) — compiled as a second TU into the
/// EXISTING allowlisted test_dash_p2p_node target (no new test target, no
/// workflow edit).

#include <gtest/gtest.h>

#include <impl/dash/coin/coin_peer_manager.hpp>
#include <impl/dash/coin/chain_seeds.hpp>

#include <core/netaddress.hpp>

#include <boost/asio.hpp>

#include <filesystem>
#include <string>
#include <vector>

using dash::coin::DashCoinPeerManager;
using dash::coin::DashPeerInfo;
using dash::coin::DashPeerManagerConfig;
using dash::coin::peer_network_group;

namespace {

DashPeerManagerConfig make_cfg()
{
    DashPeerManagerConfig cfg;
    cfg.valid_ports = {9999};      // DASH mainnet coin-P2P port
    return cfg;
}

std::string unique_tmp_dir(const std::string& tag)
{
    auto dir = std::filesystem::temp_directory_path()
        / ("c2pool_dash_pm_" + tag + "_" + std::to_string(::getpid()) + "_"
           + std::to_string(reinterpret_cast<uintptr_t>(&tag)));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir.string();
}

// ── (a) source scoring: daemon-peer penalty vs addr-crawl bonus ──────────────

TEST(DashCoinPeerManager, source_scoring_daemon_penalty_vs_addr_bonus)
{
    auto now = std::chrono::steady_clock::now();

    DashPeerInfo coind;
    coind.source = DashPeerInfo::Source::coind;
    coind.first_seen = now;
    coind.last_seen = now;

    DashPeerInfo crawl;
    crawl.source = DashPeerInfo::Source::addr_crawl;
    crawl.first_seen = now;
    crawl.last_seen = now;

    // Both freshly seen (<1h => +50 age bonus each). Only the source term
    // differs: coind -20, addr_crawl +50 => a 70-point swing favouring the
    // independent (crawl) peer.
    EXPECT_GT(crawl.compute_score(), coind.compute_score());
    EXPECT_EQ(crawl.compute_score() - coind.compute_score(), 70);
}

// ── (b) selection ordering: addr-crawl ahead of daemon-learned ───────────────

TEST(DashCoinPeerManager, selection_prefers_independent_over_daemon_peer)
{
    boost::asio::io_context ioc;
    DashCoinPeerManager pm(ioc, "DASH", unique_tmp_dir("order"), make_cfg());

    // A daemon-learned peer (coind source) via getpeerinfo bootstrap...
    pm.set_getpeerinfo_fn([]() -> std::vector<NetService> {
        return { NetService{"1.2.3.4", 9999} };
    });
    pm.start();  // bootstraps the coind peer (no DNS seeds set => no network I/O)

    // ...and an independent addr-crawl peer in a DIFFERENT /16 group.
    pm.add_discovered_peer(NetService{"5.6.7.8", 9999});

    auto picks = pm.get_peers_to_connect({});
    ASSERT_GE(picks.size(), 2u);
    // Highest score first: the addr-crawl peer beats the daemon-learned one.
    EXPECT_EQ(picks.front().host(), "5.6.7.8");
    // The daemon peer is present but ranked below.
    bool daemon_seen = false;
    for (auto& p : picks) if (p.host() == "1.2.3.4") daemon_seen = true;
    EXPECT_TRUE(daemon_seen);

    pm.stop();
}

// ── (c) network-group (Sybil) cap on untried peers per /16 ───────────────────

TEST(DashCoinPeerManager, sybil_group_cap_limits_new_peers_per_16)
{
    boost::asio::io_context ioc;
    auto cfg = make_cfg();
    cfg.max_new_peers_per_group = 3;   // stricter untried cap
    DashCoinPeerManager pm(ioc, "DASH", unique_tmp_dir("sybil"), cfg);
    pm.start();

    // Five routable peers all in the SAME /16 group "9.9".
    pm.add_discovered_peer(NetService{"9.9.1.1", 9999});
    pm.add_discovered_peer(NetService{"9.9.2.2", 9999});
    pm.add_discovered_peer(NetService{"9.9.3.3", 9999});
    pm.add_discovered_peer(NetService{"9.9.4.4", 9999});   // over cap
    pm.add_discovered_peer(NetService{"9.9.5.5", 9999});   // over cap

    EXPECT_EQ(peer_network_group("9.9.4.4"), "9.9");
    // Only max_new_peers_per_group untried peers admitted from the group.
    EXPECT_EQ(pm.peer_count(), 3u);

    pm.stop();
}

// ── (d) anchor persistence across save/reload ────────────────────────────────

TEST(DashCoinPeerManager, anchor_persists_across_reload)
{
    boost::asio::io_context ioc;
    const auto data_dir = unique_tmp_dir("anchor");
    const std::string key = "5.6.7.8:9999";

    {
        DashCoinPeerManager pm(ioc, "DASH", data_dir, make_cfg());
        pm.start();
        pm.add_discovered_peer(NetService{"5.6.7.8", 9999});
        pm.notify_connected(key);   // in_tried + anchor
        auto st = pm.peer_stats();
        EXPECT_EQ(st.anchor_count, 1);
        EXPECT_EQ(st.tried, 1);
        pm.stop();                  // saves peers + anchors to disk
    }

    // Fresh manager, SAME data_dir: load restores the anchor.
    {
        DashCoinPeerManager pm2(ioc, "DASH", data_dir, make_cfg());
        pm2.start();
        EXPECT_EQ(pm2.peer_stats().anchor_count, 1);
        pm2.stop();
    }

    std::filesystem::remove_all(data_dir);
}

// ── (e) protected local node: admitted, top-scored, never pruned ─────────────

TEST(DashCoinPeerManager, protected_local_node_is_pinned_and_survives_prune)
{
    boost::asio::io_context ioc;
    DashCoinPeerManager pm(ioc, "DASH", unique_tmp_dir("pinned"), make_cfg());

    // A private/LAN dashd address — rejected as a discovered peer, but ACCEPTED
    // as the protected local node (the daemon IS local).
    ASSERT_TRUE(pm.set_local_node(NetService{"192.168.1.50", 9999}));
    EXPECT_EQ(pm.peer_count(), 1u);

    // Pinned node is offered for connection even against an empty routable set.
    auto picks = pm.get_peers_to_connect({});
    ASSERT_GE(picks.size(), 1u);
    EXPECT_EQ(picks.front().host(), "192.168.1.50");

    // Pruning dead peers never removes the protected node.
    pm.prune_dead_peers();
    EXPECT_EQ(pm.peer_count(), 1u);

    pm.stop();
}

// ── DASH seed sanity: the real canonical mainnet seed is present ─────────────

TEST(DashCoinPeerManager, dash_mainnet_seeds_are_canonical)
{
    auto dns = dash::coin::dash_dns_seeds(/*testnet=*/false);
    ASSERT_FALSE(dns.empty());
    EXPECT_EQ(dns.front().hostname, "dnsseed.dash.org");
    EXPECT_EQ(dns.front().default_port, 9999);

    auto fixed = dash::coin::dash_fixed_seeds(/*testnet=*/false);
    EXPECT_FALSE(fixed.empty());
    for (auto& s : fixed) EXPECT_EQ(s.port(), 9999);
}

} // namespace
