// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_broadcaster_kat — M3 PR-C2 addrman-backed FOUND-BLOCK fan-out.
//
// Network-free red/green over src/impl/bip110/coin/broadcaster.hpp +
// broadcaster_full.hpp. The money property under test: a won block must fan out
// to EVERY reachable NODE_BLAKE2B peer, not a single submit — and the fan-out
// pool is addrman-backed (grown from a candidate set), deduped, capped, and
// primary-excluded. The DASH #152 shape, adapted to the bip110 NodeP2P whose
// submit_block_raw is REAL.
//
// The transport is not exercised: the slot factory, liveness predicate and
// fan-out hook are injected (exactly the leaf's designed seams), so every KAT
// pins the SELECTION / FAN-OUT logic deterministically without a socket. What is
// real code here: select_targets (dedupe/backoff/primary-exclude/cap),
// discover, prune_dead, submit_block_raw_all's per-slot fan-out and reached
// count, and the dual-arm on_block_found verdict.

#include <cstdio>
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <boost/asio.hpp>

#include <core/netaddress.hpp>

#include <impl/bip110/coin/broadcaster.hpp>
#include <impl/bip110/coin/broadcaster_full.hpp>

namespace {

int g_fail = 0;
void expect(const std::string& what, bool ok) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what.c_str());
    if (!ok) ++g_fail;
}

// Minimal duck-typed config the coin NodeP2P template reads (only
// coin()->m_p2p.prefix is touched, and only when a message is framed — never in
// this network-free KAT).
struct TestCoinCfg {
    struct P2P { std::vector<std::byte> prefix; NetService address; } m_p2p;
    bool m_testnet{false};
    bool m_regtest{false};
    std::string m_symbol{"BIP110"};
};
struct TestConfig {
    TestCoinCfg m_coin;
    bool m_testnet{false};
    TestCoinCfg* coin() { return &m_coin; }
};

using Broadcaster     = bip110::coin::Bip110Broadcaster<TestConfig>;
using BroadcasterFull = bip110::coin::Bip110BroadcasterFull<TestConfig>;
using Node            = bip110::coin::p2p::NodeP2P<TestConfig>;

} // namespace

int main() {
    std::printf("bip110_broadcaster_kat — M3 PR-C2 found-block fan-out\n");

    boost::asio::io_context ioc;
    TestConfig config;
    bip110::interfaces::Node coin_iface;   // simple struct target for slot callbacks

    // A candidate set of NODE_BLAKE2B fork peers (as the addrman would feed).
    std::vector<NetService> cands = {
        NetService("10.0.0.1", 8333),
        NetService("10.0.0.2", 8333),
        NetService("10.0.0.3", 8333),
        NetService("10.0.0.1", 8333),   // duplicate of #1 — must be deduped
    };

    // ── KAT 1: discover creates one slot per DISTINCT candidate (deduped) ──────
    {
        Broadcaster bc(&ioc, &coin_iface, &config, /*max_peers=*/8);
        // Inject a factory that constructs a real (unconnected) NodeP2P slot, and
        // a liveness predicate that reports every slot live (transport-free).
        bc.set_slot_factory([&](const NetService&) {
            return std::make_shared<Node>(&ioc, &coin_iface, &config, "kat");
        });
        bc.set_live_predicate([](const Node&) { return true; });

        size_t dialed = bc.discover(cands);
        expect("discover dialed 3 distinct peers (dup collapsed)", dialed == 3);
        expect("slot_count == 3", bc.slot_count() == 3);
        expect("live_count == 3", bc.live_count() == 3);
        // A second discover with the same set adds nothing (all already held).
        expect("re-discover adds 0 (dedupe vs existing slots)", bc.discover(cands) == 0);
    }

    // ── KAT 2: submit_block_raw_all fans to EVERY live slot ────────────────────
    {
        Broadcaster bc(&ioc, &coin_iface, &config, /*max_peers=*/8);
        int fanned = 0;
        bc.set_slot_factory([&](const NetService&) {
            return std::make_shared<Node>(&ioc, &coin_iface, &config, "kat");
        });
        bc.set_live_predicate([](const Node&) { return true; });
        bc.set_fan_out_hook([&](Node&, const std::vector<unsigned char>&) {
            ++fanned; return true;   // accepted
        });
        bc.discover(cands);         // 3 live slots
        std::vector<unsigned char> block = { 0xde, 0xad, 0xbe, 0xef };
        size_t reached = bc.submit_block_raw_all(block);
        expect("fan-out invoked on all 3 live slots", fanned == 3);
        expect("submit_block_raw_all reached == 3", reached == 3);
    }

    // ── KAT 3: max_peers cap + primary exclusion ───────────────────────────────
    {
        Broadcaster bc(&ioc, &coin_iface, &config, /*max_peers=*/2);
        bc.set_slot_factory([&](const NetService&) {
            return std::make_shared<Node>(&ioc, &coin_iface, &config, "kat");
        });
        bc.set_live_predicate([](const Node&) { return true; });
        bc.set_primary_addr(NetService("10.0.0.2", 8333));  // primary excluded
        size_t dialed = bc.discover(cands);
        expect("cap honoured: dialed == max_peers (2)", dialed == 2);
        expect("primary 10.0.0.2:8333 excluded from pool",
               !bc.has_slot("10.0.0.2:8333"));
    }

    // ── KAT 4: prune_dead drops non-live slots and arms backoff ────────────────
    {
        Broadcaster bc(&ioc, &coin_iface, &config, /*max_peers=*/8);
        bool alive = true;
        bc.set_slot_factory([&](const NetService&) {
            return std::make_shared<Node>(&ioc, &coin_iface, &config, "kat");
        });
        bc.set_live_predicate([&](const Node&) { return alive; });
        bc.discover({ NetService("10.0.0.9", 8333) });
        expect("slot present while live", bc.slot_count() == 1);
        alive = false;
        size_t pruned = bc.prune_dead();
        expect("prune_dead removed the dead slot", pruned == 1 && bc.slot_count() == 0);
        expect("dead address is now backed off", bc.is_backed_off("10.0.0.9:8333"));
    }

    // ── KAT 5: dual-arm on_block_found verdict ─────────────────────────────────
    {
        // (a) ARM A reaches peers, no ARM B wired -> reached_network via peers.
        Broadcaster bc(&ioc, &coin_iface, &config, /*max_peers=*/8);
        bc.set_slot_factory([&](const NetService&) {
            return std::make_shared<Node>(&ioc, &coin_iface, &config, "kat");
        });
        bc.set_live_predicate([](const Node&) { return true; });
        bc.set_fan_out_hook([](Node&, const std::vector<unsigned char>&) { return true; });
        bc.discover(cands);
        BroadcasterFull full(&bc);
        auto out = full.on_block_found({ 0x01, 0x02 });
        expect("ARM A only: peers_reached == 3", out.peers_reached == 3);
        expect("ARM A only: reached_network true", out.reached_network());
        expect("ARM A only: primary not attempted", !out.primary_attempted);

        // (b) EMPTY pool + ARM B success -> reached_network via primary.
        Broadcaster empty(&ioc, &coin_iface, &config, /*max_peers=*/8);
        BroadcasterFull full2(&empty);
        bool arm_b_called = false;
        full2.set_primary_submit([&](const std::vector<unsigned char>&) {
            arm_b_called = true; return true;
        });
        auto out2 = full2.on_block_found({ 0x03 });
        expect("empty pool: 0 peers reached", out2.peers_reached == 0);
        expect("ARM B attempted + ok", out2.primary_attempted && out2.primary_ok);
        expect("ARM B win => reached_network true", out2.reached_network());
        expect("ARM B actually invoked", arm_b_called);

        // (c) EMPTY pool + ARM B failure -> NOT relayed (loud, never silent).
        Broadcaster empty2(&ioc, &coin_iface, &config, /*max_peers=*/8);
        BroadcasterFull full3(&empty2);
        full3.set_primary_submit([](const std::vector<unsigned char>&) { return false; });
        auto out3 = full3.on_block_found({ 0x04 });
        expect("no peers + ARM B fail => reached_network FALSE", !out3.reached_network());
    }

    // ── KAT 6: FLAG-OFF analog — an empty (never-discovered) pool fans to 0 ─────
    // Proves the OFF-path property at the unit level: with no slots the fan-out
    // is a no-op (main gates the whole broadcaster behind --bip110-sharechain, so
    // OFF => the object is never even constructed).
    {
        Broadcaster bc(&ioc, &coin_iface, &config, /*max_peers=*/8);
        expect("no slots => submit_block_raw_all reaches 0",
               bc.submit_block_raw_all({ 0x00 }) == 0);
        expect("no slots => live_count 0", bc.live_count() == 0);
    }

    // ── KAT 7: for_each_live_slot surfaces per-peer version/height/uptime ───────
    // The dashboard peer-detail gap: live fan-out rows must carry each fork
    // peer's subver/startingheight/conntime, not blanks. The factory stamps a
    // distinct metadata tuple per slot (the version handler's job on a live
    // handshake); for_each_live_slot must yield one entry per live slot, every
    // one with a non-empty subver, its stamped start_height, and conntime >= 0.
    {
        Broadcaster bc(&ioc, &coin_iface, &config, /*max_peers=*/8);
        int seq = 0;
        bc.set_slot_factory([&](const NetService&) {
            auto n = std::make_shared<Node>(&ioc, &coin_iface, &config, "kat");
            // Stamp a distinct handshake-advertised tuple per slot (what the
            // version handler would set on a real connection).
            n->set_peer_metadata_for_test(
                70016,
                "/Satoshi:29.4.1/Knots:2026050" + std::to_string(seq) + "/",
                966370u + static_cast<uint32_t>(seq));
            ++seq;
            return n;
        });
        bc.set_live_predicate([](const Node&) { return true; });
        bc.discover(cands);   // 3 distinct live slots

        int rows = 0, with_subver = 0, height_ok = 0, conntime_ok = 0;
        std::set<std::string> keys_seen;
        bc.for_each_live_slot([&](const std::string& key, const Node& n) {
            ++rows;
            keys_seen.insert(key);
            if (!n.peer_subver().empty()) ++with_subver;
            if (n.peer_start_height() >= 966370u) ++height_ok;
            if (n.peer_uptime_sec() >= 0) ++conntime_ok;
        });
        expect("for_each_live_slot yields one row per live slot (3)", rows == 3);
        expect("all 3 rows carry a non-empty subver", with_subver == 3);
        expect("all 3 rows carry the stamped startingheight", height_ok == 3);
        expect("all 3 rows carry a non-negative conntime", conntime_ok == 3);
        expect("rows are distinct keys (deduped by slot map)", keys_seen.size() == 3);
    }

    std::printf("%s\n", g_fail == 0 ? "bip110_broadcaster_kat PASS"
                                    : "bip110_broadcaster_kat FAIL");
    return g_fail == 0 ? 0 : 1;
}
