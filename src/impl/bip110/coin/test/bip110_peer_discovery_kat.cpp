// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bip110 coin-P2P PEER DISCOVERY KAT — the Knots getaddr/addr crawl port.
//
// Pins the peer-discovery mechanisms wired behind --coin-p2p-discover /
// --bip110-sharechain (main_bip110.cpp): getaddr-on-connect, the NODE_BLAKE2B
// addr-ingest fork filter + future-poison drop, addr -> bucketed addrman ->
// tried promotion, the multi-peer dial plan, and the fan-out target (> 1).
//
// The live symptom this closes: the embedded node latched at ONE oracle peer and
// never grew (dashboard "CONNECTIONS 1 Active/Target", zero getaddr/addr traffic)
// because getaddr was never sent, the addr handler discarded gossip, and the
// scorer never learned of connects. Every assert below is zero-socket and
// deterministic — nothing dials, resolves, or fetches.
//
// RED-before / GREEN-after:
//   * filter_fork_addr_records did NOT EXIST on the branch tip (the old addr
//     handler forwarded rec.m_endpoint for EVERY record, keeping non-fork +
//     future-dated poison) — T1/T5 fail to compile / assert there.
//   * NodeP2P had no getaddr flag / lifecycle seams and Bip110Broadcaster had no
//     slot configurator — T2 references entry points that did not exist.
// ---------------------------------------------------------------------------

#include <cassert>
#include <cstdint>
#include <iostream>
#include <set>
#include <string>
#include <vector>

#include <boost/asio/io_context.hpp>

#include <core/core_util.hpp>          // core::timestamp()
#include "../p2p_messages.hpp"         // btc_addr_record_t (the wire record)
#include "../p2p_node.hpp"             // filter_fork_addr_records, NodeP2P, COIN_NODE_BLAKE2B
#include "../broadcaster.hpp"          // Bip110Broadcaster (fan-out pool)
#include "../coin_peer_manager.hpp"    // BtcCoinPeerManager + core::CoinAddrMan

using bip110::coin::p2p::COIN_NODE_BLAKE2B;
using bip110::coin::p2p::filter_fork_addr_records;
using bip110::coin::p2p::btc_addr_record_t;
using bip110::coin::BtcCoinPeerManager;
using bip110::coin::BtcPeerManagerConfig;

// Minimal duck-typed config mirroring main_bip110's MiniConfig — enough to
// instantiate NodeP2P<Cfg> / Bip110Broadcaster<Cfg> (they only ever read
// config->coin()->m_p2p.prefix, which these KATs never exercise).
namespace {
struct KatCoinCfg {
    struct P2P { std::vector<std::byte> prefix; NetService address; } m_p2p;
    bool m_testnet{false};
    bool m_regtest{false};
    std::string m_symbol{"BIP110"};
};
struct KatConfig {
    KatCoinCfg m_coin;
    bool m_testnet{false};
    KatCoinCfg* coin() { return &m_coin; }
};

// Service-flag helpers (match p2p_node.hpp's version handshake).
constexpr uint64_t NODE_NETWORK = 1;
constexpr uint64_t NODE_WITNESS = (1u << 3);

btc_addr_record_t make_rec(uint64_t services, uint32_t ts, const NetService& ep)
{
    btc_addr_record_t r;
    r.m_services  = services;
    r.m_timestamp = ts;
    r.m_endpoint  = ep;
    return r;
}

int g_failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " (line " << __LINE__ << ")\n"; ++g_failures; } } while (0)

// ── T1: addr fork filter + future-poison drop (the LOAD-BEARING logic) ───────
void t1_fork_filter()
{
    const int64_t now = static_cast<int64_t>(core::timestamp());
    std::vector<btc_addr_record_t> recs = {
        // fork-capable, fresh, routable -> KEEP
        make_rec(NODE_NETWORK | NODE_WITNESS | COIN_NODE_BLAKE2B,
                 static_cast<uint32_t>(now), NetService("8.8.8.8", 8333)),
        // main-chain-only (no NODE_BLAKE2B) -> DROP (would poison the fork addrman)
        make_rec(NODE_NETWORK | NODE_WITNESS,
                 static_cast<uint32_t>(now), NetService("1.1.1.1", 8333)),
        // fork-capable but grossly future-dated (now + 1h) -> DROP as poison
        make_rec(NODE_NETWORK | COIN_NODE_BLAKE2B,
                 static_cast<uint32_t>(now + 3600), NetService("9.9.9.9", 9333)),
        // second good fork peer -> KEEP
        make_rec(NODE_NETWORK | COIN_NODE_BLAKE2B,
                 static_cast<uint32_t>(now), NetService("51.51.51.51", 9333)),
    };

    size_t dn = 0, df = 0;
    auto ok = filter_fork_addr_records(recs, now, &dn, &df);
    CHECK(ok.size() == 2);            // only the two NODE_BLAKE2B + fresh survive
    CHECK(dn == 1);                   // one non-fork dropped
    CHECK(df == 1);                   // one future-dated dropped
    // the survivors are exactly the two good endpoints
    bool has88 = false, has51 = false;
    for (auto& e : ok) {
        if (e.to_string() == "8.8.8.8:8333")     has88 = true;
        if (e.to_string() == "51.51.51.51:9333") has51 = true;
    }
    CHECK(has88 && has51);

    // an all-non-fork batch yields nothing (the fork mesh stays uncontaminated)
    std::vector<btc_addr_record_t> nonfork = {
        make_rec(NODE_NETWORK | NODE_WITNESS, static_cast<uint32_t>(now),
                 NetService("2.2.2.2", 8333)),
    };
    CHECK(filter_fork_addr_records(nonfork, now).empty());
    std::cout << "T1 fork-filter: kept=" << ok.size()
              << " dropped_nonfork=" << dn << " dropped_future=" << df << "\n";
}

// ── T2: NodeP2P + Bip110Broadcaster discovery seams (getaddr flag, setters,
//        fan-out target > 1, primary exclusion, dedup) ──────────────────────
void t2_seams_and_fanout_target()
{
    boost::asio::io_context ioc;

    // getaddr-on-connect flag: default OFF, enable flips it (the crawl trigger).
    KatConfig cfg;
    bip110::coin::p2p::NodeP2P<KatConfig> node(&ioc, nullptr, &cfg, "kat");
    CHECK(!node.getaddr_discovery_enabled());
    node.enable_getaddr_discovery();
    CHECK(node.getaddr_discovery_enabled());
    // lifecycle + addr setters accept callbacks without touching the socket.
    node.set_addr_callback([](const std::vector<NetService>&, const NetService&) {});
    node.set_on_peer_connected([](const NetService&) {});
    node.set_on_peer_disconnected([](const NetService&) {});
    node.set_on_dial_failed([](const NetService&) {});

    // Fan-out target: select_targets is pure (creates no slots). With max_peers=8
    // and 12 fork candidates it selects 8 — proving the fan-out target is raised
    // off 1. The primary is excluded, and duplicates are collapsed.
    bip110::coin::Bip110Broadcaster<KatConfig> bc(&ioc, nullptr, nullptr, /*max_peers=*/8);
    std::vector<NetService> cands;
    for (int i = 0; i < 12; ++i)
        cands.emplace_back("45." + std::to_string(i) + ".0.1", 9333);
    auto chosen = bc.select_targets(cands);
    CHECK(chosen.size() == 8);                    // target > 1, capped at max_peers

    // exclude the primary: it must never be a fan-out slot target.
    bc.set_primary_addr(cands[0]);
    auto chosen2 = bc.select_targets(cands);
    for (auto& e : chosen2)
        CHECK(e.to_string() != cands[0].to_string());

    // dedup within the batch: 4 copies of one addr collapse to a single target.
    std::vector<NetService> dups(4, NetService("46.1.0.1", 9333));
    CHECK(bc.select_targets(dups).size() == 1);

    // the slot configurator seam exists and is accepted (wired in main to push
    // getaddr + addr-ingest + scorer feedback onto every fan-out slot).
    bc.set_slot_configurator([](bip110::coin::p2p::NodeP2P<KatConfig>& s) {
        s.enable_getaddr_discovery();
    });
    std::cout << "T2 seams: getaddr flag OK, fanout target=" << chosen.size()
              << "/8 (was pinned at 1)\n";
}

// ── T3: addr ingest -> bucketed addrman -> tried promotion + multi-peer plan ─
void t3_ingest_bucket_tried_plan()
{
    boost::asio::io_context ioc;
    BtcPeerManagerConfig cfg;
    cfg.valid_ports = { 8333, 9333 };
    BtcCoinPeerManager mgr(ioc, "BIP110", "/tmp/bip110_peerdisc_kat", cfg);

    // A single fork peer gossiped by the oracle enters the bucketed addrman.
    const NetService peer("8.8.8.8", 8333);
    mgr.add_discovered_peer(peer, /*source=*/"52.52.52.52");
    CHECK(mgr.addrman().size() == 1u);
    CHECK(mgr.peer_stats().total == 1);

    // A completed handshake promotes it into the addrman TRIED table (scorer
    // feedback: notify_connected -> addrman.good) and it becomes serveable.
    mgr.notify_connected(peer.to_string());
    CHECK(mgr.addrman().is_tried(peer));
    CHECK(mgr.addrman().tried_count() == 1u);
    CHECK(!mgr.get_tried_peers(16).empty());

    // Bank a group-diverse set: the dial plan must then produce MORE THAN ONE
    // candidate (the fan-out draws its target-off-1 set from exactly this).
    mgr.add_discovered_peer(NetService("51.51.1.1", 9333), "52.52.52.52");
    mgr.add_discovered_peer(NetService("1.1.1.1", 8333),  "52.52.52.52");
    mgr.add_discovered_peer(NetService("45.45.1.1", 9333), "52.52.52.52");
    auto plan = mgr.get_peers_to_connect({});
    CHECK(plan.size() >= 2);

    // dial-failure feedback lands (the #940 leg): a drawn candidate that fails to
    // connect is scored down so the plan rotates off it.
    mgr.notify_dial_failed(NetService("45.45.1.1", 9333).to_string());
    std::cout << "T3 ingest/tried/plan: addrman=" << mgr.addrman().size()
              << " tried=" << mgr.addrman().tried_count()
              << " plan=" << plan.size() << "\n";
}

// ── T4: END-TO-END — one oracle gossip bootstraps MANY fork dial targets ─────
void t4_oracle_bootstraps_many()
{
    boost::asio::io_context ioc;
    BtcPeerManagerConfig cfg;
    cfg.valid_ports = { 8333, 9333 };
    cfg.max_peers = 64;
    BtcCoinPeerManager mgr(ioc, "BIP110", "/tmp/bip110_peerdisc_kat_e2e", cfg);

    const int64_t now = static_cast<int64_t>(core::timestamp());

    // The oracle answers our getaddr with a MIXED gossip: 10 fork peers (distinct
    // /16 groups), 3 main-chain-only peers, 1 future-dated poison. This is what
    // the addr handler receives on the wire.
    std::vector<btc_addr_record_t> gossip;
    for (int i = 0; i < 10; ++i)
        gossip.push_back(make_rec(NODE_NETWORK | COIN_NODE_BLAKE2B,
                                  static_cast<uint32_t>(now),
                                  NetService("77." + std::to_string(i) + ".3.3", 9333)));
    for (int i = 0; i < 3; ++i)
        gossip.push_back(make_rec(NODE_NETWORK | NODE_WITNESS,
                                  static_cast<uint32_t>(now),
                                  NetService("88." + std::to_string(i) + ".4.4", 8333)));
    gossip.push_back(make_rec(NODE_NETWORK | COIN_NODE_BLAKE2B,
                              static_cast<uint32_t>(now + 7200),
                              NetService("99.9.9.9", 9333)));

    // Filter (as the addr handler does) then bank each survivor (as the
    // set_addr_callback -> add_discovered_peer wiring does).
    auto survivors = filter_fork_addr_records(gossip, now);
    CHECK(survivors.size() == 10u);   // only the 10 fork peers, no poison
    for (auto& s : survivors)
        mgr.add_discovered_peer(s, /*oracle source*/"70.0.0.1");

    // The addrman now holds the whole fork mesh (was 0 -> 10 from ONE gossip).
    CHECK(mgr.addrman().size() == 10u);

    // And the fan-out pool can dial MANY of them: feed the scored dial plan into
    // the broadcaster's pure selector; it returns a multi-peer target (> 1).
    bip110::coin::Bip110Broadcaster<KatConfig> bc(&ioc, nullptr, nullptr, /*max_peers=*/8);
    std::vector<NetService> targets;
    for (const auto& ep : mgr.get_peers_to_connect({}))
        targets.push_back(ep.to_net_service());
    auto chosen = bc.select_targets(targets);
    CHECK(chosen.size() > 1);         // ONE oracle link -> MANY fork dial targets

    std::cout << "T4 oracle bootstrap: gossip=" << gossip.size()
              << " survivors=" << survivors.size()
              << " addrman=" << mgr.addrman().size()
              << " fanout_targets=" << chosen.size() << " (was 1)\n";
}

} // namespace

int main()
{
    std::cout << "=== bip110 coin-P2P peer-discovery KAT ===\n";
    t1_fork_filter();
    t2_seams_and_fanout_target();
    t3_ingest_bucket_tried_plan();
    t4_oracle_bootstraps_many();

    if (g_failures) {
        std::cerr << "\nbip110_peer_discovery_kat: " << g_failures << " CHECK(s) FAILED\n";
        return 1;
    }
    std::cout << "\nbip110_peer_discovery_kat: ALL PASS\n";
    return 0;
}
