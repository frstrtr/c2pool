// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch::coin::BchCoinPeerManager -- socket-free admission / isolation / scoring /
// re-arm / persistence KATs for the --coin-p2p-discover network-standalone arm
// (BCH FIX-2). Pins the deterministic, zero-socket surface the CoinAddrMan-backed
// peer manager exposes to EmbeddedDaemon::maybe_start_p2p:
//
//   1) LAN-default regression WITNESS: a private RFC1918 addr (the old
//      192.168.86.110 hardcoded default) is REJECTED as non-routable and banks
//      nothing; a routable addr is admitted 1/1. This is the test that would go
//      red if a LAN default ever came back.
//   2) valid_ports admission filter (mainnet 8333 vs a wrong port; testnet 18333).
//   3) /16 Sybil cap: N addrs in one /16 -> working set <= max_new_peers_per_group
//      but the bucketed addrman banks ALL of them (bank-before-gate).
//   4) get_peers_to_connect: bounded by budget, <= 2 per /16, excludes the
//      already-connected keys handed in.
//   5) #940 dial-failure vs post-handshake-drop scoring: notify_dial_failed backs
//      a peer OFF the next dial plan; notify_connected promotes it to tried;
//      notify_disconnected keeps it.
//   6) Emergency re-arm (the/docs/coin-peer-manager-rearm.md 2.1-2.4): the
//      saturating-exponential backoff schedule + overflow guard, the re-entry
//      latch (N starved arms -> ONE), the timer-fire latch release, and the
//      recovery reset.
//   7) JSON persistence round-trip: stop() -> a fresh manager on the same dir
//      restores peer_count / addrman size / tried_count (addrman_BCH.json).
//   8) discovery_enabled() gate: true when armed + bank under soft-capacity,
//      false under disable_discovery.
//
// Harness: plain int main() + assert-style CHECK (CTest treats exit 0 as PASS),
// matching the sibling bch KATs (seed_tier_kat_test.cpp). Header-only over
// coin/coin_peer_manager.hpp + <core/*>; links the same set as the ABLA tests
// (core provides CoinAddrMan) -> per-coin isolation stays clean. NO start()-side
// DNS/HTTP fetch is exercised with real seeds -> strictly network-free. Every
// data_dir is a UNIQUE temp path (never "." -> never ~/.c2pool).
// ---------------------------------------------------------------------------

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <set>
#include <string>
#include <unistd.h>   // getpid (unique temp-dir suffix)

#include <boost/asio/io_context.hpp>

#include <core/netaddress.hpp>
#include "../coin/coin_peer_manager.hpp"

namespace {
int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

using bch::coin::BchCoinPeerManager;
using bch::coin::BchPeerManagerConfig;

NetService ns(const std::string& ip, uint16_t port) { return NetService(ip, port); }

// Unique temp dir per manager -- never "." (that would write under ~/.c2pool).
std::string unique_dir(const std::string& tag)
{
    static int counter = 0;
    auto p = std::filesystem::temp_directory_path()
             / ("bch_pm_kat_" + tag + "_" + std::to_string(::getpid())
                + "_" + std::to_string(counter++));
    std::filesystem::create_directories(p);
    return p.string();
}

std::unique_ptr<BchCoinPeerManager> make_mgr(boost::asio::io_context& ioc,
                                             const BchPeerManagerConfig& cfg,
                                             const std::string& tag)
{
    return std::make_unique<BchCoinPeerManager>(ioc, "BCH", unique_dir(tag), cfg);
}

bool plan_contains(const std::vector<PeerEndpoint>& plan, const std::string& key)
{
    for (const auto& pe : plan)
        if (pe.to_string() == key) return true;
    return false;
}
} // namespace

int main()
{
    boost::asio::io_context ioc;

    // ---- 1) LAN-default regression witness -------------------------------
    // The old hardcoded 192.168.86.110 LAN default is non-routable: adding it as
    // a discovered peer is REJECTED and banks nothing. A routable addr is 1/1.
    {
        auto m = make_mgr(ioc, BchPeerManagerConfig{}, "lan");
        m->add_discovered_peer(ns("192.168.86.110", 8333));   // the old LAN default
        CHECK(m->peer_count() == 0);
        CHECK(m->addrman().size() == 0);
        m->add_discovered_peer(ns("8.8.8.8", 8333));          // globally-routable
        CHECK(m->peer_count() == 1);
        CHECK(m->addrman().size() == 1);
        // Empty/unparseable local node rejected; valid private local node pinned.
        CHECK(!m->set_local_node(ns("", 0)));
        CHECK(m->set_local_node(ns("192.168.1.10", 8333)));   // daemon IS local
    }

    // ---- 2) valid_ports admission filter ---------------------------------
    {
        BchPeerManagerConfig cfg;
        cfg.valid_ports = { 8333 };                            // BCH mainnet only
        auto m = make_mgr(ioc, cfg, "port_main");
        m->add_discovered_peer(ns("8.8.8.8", 8334));           // wrong port -> reject
        CHECK(m->peer_count() == 0);
        CHECK(m->addrman().size() == 0);                       // port gate precedes the bank
        m->add_discovered_peer(ns("8.8.8.8", 8333));           // valid port -> admit
        CHECK(m->peer_count() == 1);

        BchPeerManagerConfig tcfg;
        tcfg.valid_ports = { 18333 };                          // BCH testnet3
        auto t = make_mgr(ioc, tcfg, "port_test");
        t->add_discovered_peer(ns("8.8.8.8", 8333));           // mainnet port -> reject
        CHECK(t->peer_count() == 0);
        t->add_discovered_peer(ns("8.8.8.8", 18333));          // testnet port -> admit
        CHECK(t->peer_count() == 1);
    }

    // ---- 3) /16 Sybil cap: bank-before-gate ------------------------------
    // 5 routable addrs in one /16 (8.8.0.0/16): the working set is capped at
    // max_new_peers_per_group (3) but the bucketed addrman banks ALL 5.
    {
        auto m = make_mgr(ioc, BchPeerManagerConfig{}, "sybil");  // default cap = 3 new/group
        for (int i = 1; i <= 5; ++i)
            // Peers all share one /16 (group "8.8") so the working-set group
            // cap binds, but each is gossiped by a DISTINCT source /16 so the
            // addrman banks every one in its own new-table bucket — no same-
            // bucket slot collision, size() is deterministically 5.
            m->add_discovered_peer(ns("8.8.100." + std::to_string(i), 8333),
                                   "51." + std::to_string(i) + ".0.1"); // peer /16 "8.8", source /16 distinct
        CHECK(m->peer_count() <= 3);                            // working-set group cap
        CHECK(m->addrman().size() == 5);                        // bank keeps them all
    }

    // ---- 4) get_peers_to_connect: budget + /16 diversity + exclusion ------
    {
        BchPeerManagerConfig cfg;
        cfg.max_connections_per_cycle = 4;
        auto m = make_mgr(ioc, cfg, "plan");
        // Group A (8.8.x): admit up to the new-per-group cap; groups B/C distinct /16s.
        for (int i = 1; i <= 3; ++i)
            m->add_discovered_peer(ns("8.8.100." + std::to_string(i), 8333));
        m->add_discovered_peer(ns("1.1.1.1", 8333));
        m->add_discovered_peer(ns("9.9.9.9", 8333));

        std::set<std::string> none;
        auto plan = m->get_peers_to_connect(none);
        CHECK(!plan.empty());
        CHECK(static_cast<int>(plan.size()) <= cfg.max_connections_per_cycle);
        // <= 2 outbound per /16 in the plan.
        int grpA = 0;
        for (const auto& pe : plan)
            if (pe.host().rfind("8.8.", 0) == 0) ++grpA;
        CHECK(grpA <= 2);
        // Excludes an already-connected key.
        const std::string excl = plan.front().to_string();
        std::set<std::string> connected{ excl };
        auto plan2 = m->get_peers_to_connect(connected);
        CHECK(!plan_contains(plan2, excl));
    }

    // ---- 5) #940 dial-failure vs post-handshake-drop scoring --------------
    {
        auto m = make_mgr(ioc, BchPeerManagerConfig{}, "score");
        m->add_discovered_peer(ns("8.8.8.8", 8333));
        const std::string key = ns("8.8.8.8", 8333).to_string();

        // A failed dial backs the peer OFF the very next plan (backoff gate).
        m->notify_dial_failed(key);
        auto after_fail = m->get_peers_to_connect(std::set<std::string>{});
        CHECK(!plan_contains(after_fail, key));

        // A successful connect promotes it to tried and lists it in get_tried_peers.
        m->notify_connected(key);
        CHECK(m->peer_stats().tried == 1);
        bool in_tried = false;
        for (const auto& pe : m->get_tried_peers(25))
            if (pe.to_string() == key) { in_tried = true; break; }
        CHECK(in_tried);

        // A post-handshake disconnect KEEPS the entry (does not delete it).
        m->notify_disconnected(key);
        CHECK(m->peer_count() >= 1);
    }

    // ---- 6) Emergency re-arm (spec 2.1-2.4) ------------------------------
    {
        // 6.1 saturating exponential backoff + overflow guard (pure static).
        using PM = BchCoinPeerManager;
        const long long expect[] = {60, 120, 240, 480, 960, 1920, 3600};
        for (int n = 0; n <= 6; ++n)
            CHECK(PM::emergency_backoff_delay_sec(30, 3600, n) == expect[n]);
        // base floored at 60s; cap saturates; n=100 never overflows.
        CHECK(PM::emergency_backoff_delay_sec(10, 3600, 0) == 60);
        CHECK(PM::emergency_backoff_delay_sec(30, 3600, 100) == 3600);

        // 6.2 re-entry latch: N starved arms -> exactly ONE (attempt advances 1).
        auto m = make_mgr(ioc, BchPeerManagerConfig{}, "rearm");
        m->start();                                   // no seeds -> network-free; m_running=true
        CHECK(m->emergency_attempt() == 0);
        m->arm_emergency_fallbacks();
        m->arm_emergency_fallbacks();                 // latched -> no second schedule
        CHECK(m->emergency_active());
        CHECK(m->emergency_attempt() == 1);
        // 6.3 timer fire releases the latch (no seeds -> the re-run tiers are no-ops).
        m->on_emergency_timer_fired(boost::system::error_code{});
        CHECK(!m->emergency_active());
        // 6.4 recovery reset zeroes the attempt counter + clears the latch.
        m->clear_emergency_state();
        CHECK(m->emergency_attempt() == 0);
        CHECK(!m->emergency_active());
        m->stop();
    }

    // ---- 7) JSON persistence round-trip ----------------------------------
    {
        const std::string dir = unique_dir("persist");
        const std::string key = ns("8.8.8.8", 8333).to_string();
        {
            BchCoinPeerManager m(ioc, "BCH", dir, BchPeerManagerConfig{});
            m.add_discovered_peer(ns("8.8.8.8", 8333));
            m.notify_connected(key);                  // promote to tried in both books
            CHECK(m.peer_count() == 1);
            CHECK(m.addrman().tried_count() >= 1);
            m.stop();                                 // save_peers() -> peers_BCH.json + addrman_BCH.json
        }
        CHECK(std::filesystem::exists(
            std::filesystem::path(dir) / "addrman_BCH.json"));
        {
            BchCoinPeerManager m2(ioc, "BCH", dir, BchPeerManagerConfig{});
            m2.start();                               // load_peers() restores both books (no seeds)
            CHECK(m2.peer_count() == 1);
            CHECK(m2.addrman().size() >= 1);
            CHECK(m2.addrman().tried_count() >= 1);
            CHECK(m2.peer_stats().tried == 1);        // in_tried survived the round-trip
            m2.stop();
        }
    }

    // ---- 8) discovery_enabled() gate -------------------------------------
    {
        auto on = make_mgr(ioc, BchPeerManagerConfig{}, "disc_on");
        on->add_discovered_peer(ns("8.8.8.8", 8333));
        CHECK(on->discovery_enabled());               // armed + bank << soft-capacity

        BchPeerManagerConfig off_cfg;
        off_cfg.disable_discovery = true;             // isolated network -> no discovery
        auto off = make_mgr(ioc, off_cfg, "disc_off");
        CHECK(!off->discovery_enabled());
    }

    if (failures == 0) {
        std::cout << "coin_peer_manager_kat_test: ALL CHECKS PASSED\n";
        return 0;
    }
    std::cerr << "coin_peer_manager_kat_test: " << failures << " FAILURE(S)\n";
    return 1;
}
