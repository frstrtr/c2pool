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


// ---------------------------------------------------------------------------
// Emergency seed re-arm KATs (fail to COMPILE on master -- the entry points
// below do not exist there; the maintenance handler is a no-op).
//
// The four-lane re-arm spec (docs/coin-peer-manager-rearm sections 2.1-2.4)
// pins three MANDATORY properties. These assert each one DIRECTLY and
// deterministically -- no wall clock, no sockets: the emergency timer is never
// run, so the latch state and attempt counter are observed exactly as the
// maintenance handler leaves them.
// ---------------------------------------------------------------------------

// 2.1 BACKOFF: saturating binary exponential, base floored at 60, clamped at
// max_backoff_sec, overflow-safe for large n.
TEST(BtcCoinPeerManager, EmergencyBackoffScheduleSaturatesWithoutOverflow)
{
    boost::asio::io_context ioc;
    BtcPeerManagerConfig cfg;                 // base_backoff_sec=30, max=3600 (defaults)
    auto m = make_mgr(ioc, cfg);

    // base is FLOORED at 60 so a re-arm never beats the original 60s one-shot,
    // even though PeerManagerConfig::base_backoff_sec defaults to 30.
    EXPECT_EQ(m->emergency_base_sec(), 60);

    // base, 2*base, 4*base, ... : 60, 120, 240, 480, 960, 1920, then clamp.
    EXPECT_EQ(m->emergency_backoff_delay(0), 60);
    EXPECT_EQ(m->emergency_backoff_delay(1), 120);
    EXPECT_EQ(m->emergency_backoff_delay(2), 240);
    EXPECT_EQ(m->emergency_backoff_delay(3), 480);
    EXPECT_EQ(m->emergency_backoff_delay(4), 960);
    EXPECT_EQ(m->emergency_backoff_delay(5), 1920);
    // 60<<6 = 3840 -> clamped to the 3600 ceiling, and stays there.
    EXPECT_EQ(m->emergency_backoff_delay(6), cfg.max_backoff_sec);
    EXPECT_EQ(m->emergency_backoff_delay(7), cfg.max_backoff_sec);

    // Overflow safety: large n must saturate at the cap -- never UB, never a
    // negative/zero delay from a wrapped base<<n.
    for (int n : {30, 31, 62, 63, 64, 100, 1000, 1 << 20}) {
        const int d = m->emergency_backoff_delay(n);
        EXPECT_EQ(d, cfg.max_backoff_sec) << "n=" << n << " must saturate at cap";
        EXPECT_GT(d, 0) << "n=" << n << " backoff must stay positive (no overflow)";
    }
}

// 2.2 RE-ENTRY GUARD: N consecutive starved maintenance ticks between two timer
// firings schedule EXACTLY ONE re-arm (counter advances by 1, not N).
TEST(BtcCoinPeerManager, EmergencyReentryGuardArmsOncePerCycle)
{
    boost::asio::io_context ioc;
    BtcPeerManagerConfig cfg;
    cfg.min_peers = 5;
    // Own data_dir under /tmp so start()/stop() never write into config_path().
    BtcCoinPeerManager mgr(ioc, "BTC", "/tmp/btc_rearm_kat_guard", cfg);
    mgr.start();   // sets m_running so arm_emergency_fallbacks() is live

    EXPECT_EQ(mgr.emergency_attempts(), 0);
    EXPECT_FALSE(mgr.emergency_active());

    // 25 starved ticks (connected=0 < min_peers=5). The dedicated emergency
    // timer is never run, so the latch stays set and every tick after the first
    // must no-op -- no timer storm.
    for (int i = 0; i < 25; ++i)
        mgr.on_maintenance_tick(/*connected=*/0);

    EXPECT_TRUE(mgr.emergency_active())
        << "latch must remain set between arm and fire";
    EXPECT_EQ(mgr.emergency_attempts(), 1)
        << "N starved ticks must schedule EXACTLY ONE re-arm (counter +1, not +N)";

    mgr.stop();
}

// 2.3 STOP CONDITION / RECOVERY: a tick with connected >= min_peers zeroes the
// attempt counter and clears the latch; the subsequent starvation re-arms from
// BASE, not from the prior (higher) step.
TEST(BtcCoinPeerManager, EmergencyRecoveryResetsBackoffToBase)
{
    boost::asio::io_context ioc;
    BtcPeerManagerConfig cfg;
    cfg.min_peers = 5;
    BtcCoinPeerManager mgr(ioc, "BTC", "/tmp/btc_rearm_kat_reset", cfg);
    mgr.start();

    // Arm once under starvation -> counter advances, next arm would step up.
    mgr.on_maintenance_tick(/*connected=*/0);
    EXPECT_EQ(mgr.emergency_attempts(), 1);
    EXPECT_TRUE(mgr.emergency_active());
    // Pending: the NEXT arm (after this one fires) would use n=1 -> 120s, i.e.
    // strictly above base -- backoff is genuinely escalating.
    EXPECT_EQ(mgr.next_emergency_delay(), mgr.emergency_backoff_delay(1));
    EXPECT_GT(mgr.next_emergency_delay(), mgr.emergency_base_sec());

    // RECOVERY edge: a maintenance tick observing connected >= min_peers.
    mgr.on_maintenance_tick(/*connected=*/cfg.min_peers);   // 5 >= 5
    EXPECT_EQ(mgr.emergency_attempts(), 0)
        << "recovery must zero the attempt counter";
    EXPECT_FALSE(mgr.emergency_active())
        << "recovery must clear the re-entry latch";

    // The subsequent starvation re-arms from BASE, not from the ceiling: the
    // very next arm uses n=0 -> base (60s), demonstrably below the ceiling.
    EXPECT_EQ(mgr.next_emergency_delay(), mgr.emergency_base_sec());
    EXPECT_LT(mgr.emergency_base_sec(), cfg.max_backoff_sec);
    mgr.on_maintenance_tick(/*connected=*/0);
    EXPECT_EQ(mgr.emergency_attempts(), 1)
        << "a fresh drop after recovery re-arms exactly once from base";

    mgr.stop();
}
