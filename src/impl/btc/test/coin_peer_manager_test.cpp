// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// btc::coin::BtcCoinPeerManager — socket-free admission/isolation KATs.
//
// Pins the BTC-ISOLATED coin-network peer manager wired behind
// --coin-p2p-discover (main_btc.cpp). These KATs exercise the deterministic,
// zero-socket surface: address validation, the require-routable gate, the
// valid_ports filter, the /16 network-group Sybil cap, and that the seed-tier
// setters (DNS/fixed/HTTP incl. set_http_peer_seeds) never fetch or throw on
// their own. Live DNS/HTTP bootstrap is scheduled async and is out of scope.
//
// Rides the already-allowlisted btc_share_test executable (see
// src/impl/btc/test/CMakeLists.txt) and gtest_add_tests(... AUTO), so it both
// builds AND runs in CI -- no build.yml --target change is required. A new
// standalone add_executable would build green yet never run.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>
#include <memory>

#include "../coin/coin_peer_manager.hpp"

using btc::coin::BtcCoinPeerManager;
using btc::coin::BtcPeerManagerConfig;

namespace {

std::unique_ptr<BtcCoinPeerManager> make_mgr(boost::asio::io_context& ioc,
                                             const BtcPeerManagerConfig& cfg)
{
    // data_dir "." -> resolves under config_path()/btc_embedded_peers; the KATs
    // never call start()/save_peers(), so no files are written.
    return std::make_unique<BtcCoinPeerManager>(ioc, "BTC", ".", cfg);
}

} // namespace

TEST(BtcCoinPeerManager, SymbolAndEmptyOnConstruct)
{
    boost::asio::io_context ioc;
    auto m = make_mgr(ioc, BtcPeerManagerConfig{});
    EXPECT_EQ(m->symbol(), "BTC");
    EXPECT_EQ(m->peer_stats().total, 0);
}

TEST(BtcCoinPeerManager, LocalNodeAcceptsValidRejectsEmpty)
{
    boost::asio::io_context ioc;
    auto m = make_mgr(ioc, BtcPeerManagerConfig{});
    // Local node may be private (the daemon IS local) -- accepted + pinned.
    EXPECT_TRUE(m->set_local_node(NetService("192.168.1.10", 8333)));
    EXPECT_EQ(m->peer_stats().total, 1);
    // Empty/unparseable host is rejected; peer table is unchanged.
    EXPECT_FALSE(m->set_local_node(NetService("", 0)));
    EXPECT_EQ(m->peer_stats().total, 1);
}

TEST(BtcCoinPeerManager, DiscoveredPeerMustBeRoutable)
{
    boost::asio::io_context ioc;
    auto m = make_mgr(ioc, BtcPeerManagerConfig{});
    // addr-crawl discovery requires routable: a private RFC1918 addr is dropped.
    m->add_discovered_peer(NetService("10.0.0.5", 8333));
    EXPECT_EQ(m->peer_stats().total, 0);
    // A globally-routable addr is admitted.
    m->add_discovered_peer(NetService("8.8.8.8", 8333));
    EXPECT_EQ(m->peer_stats().total, 1);
}

TEST(BtcCoinPeerManager, ValidPortsFilterGatesAdmission)
{
    boost::asio::io_context ioc;
    BtcPeerManagerConfig cfg;
    cfg.valid_ports = { 8333 };   // BTC mainnet only
    auto m = make_mgr(ioc, cfg);
    m->add_discovered_peer(NetService("8.8.8.8", 9999));  // wrong port -> rejected
    EXPECT_EQ(m->peer_stats().total, 0);
    m->add_discovered_peer(NetService("8.8.8.8", 8333));  // valid port -> admitted
    EXPECT_EQ(m->peer_stats().total, 1);
}

TEST(BtcCoinPeerManager, NetworkGroupCapLimitsSameSlash16)
{
    boost::asio::io_context ioc;
    BtcPeerManagerConfig cfg;              // defaults: max_new_peers_per_group = 3
    auto m = make_mgr(ioc, cfg);
    // Five routable peers all in the 8.8/16 group; the untried-source cap admits
    // at most max_new_peers_per_group of them (Sybil resistance).
    for (int i = 1; i <= 5; ++i)
        m->add_discovered_peer(NetService("8.8.0." + std::to_string(i), 8333));
    EXPECT_EQ(m->peer_stats().total, cfg.max_new_peers_per_group);
    EXPECT_EQ(m->peer_stats().unique_groups, 1);
}

TEST(BtcCoinPeerManager, SeedSettersDoNotFetchOrThrow)
{
    boost::asio::io_context ioc;
    auto m = make_mgr(ioc, BtcPeerManagerConfig{});
    // Setters only stash config; nothing is fetched until start() schedules the
    // async fallbacks. None of these may throw or mutate the peer table.
    EXPECT_NO_THROW(m->set_dns_seeds({}));
    EXPECT_NO_THROW(m->set_fixed_seeds({}));
    EXPECT_NO_THROW(m->set_http_peer_seeds({{"voidbind.com", 8080}}));
    EXPECT_EQ(m->peer_stats().total, 0);
}
