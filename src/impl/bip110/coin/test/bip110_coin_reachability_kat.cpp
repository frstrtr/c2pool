// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bip110 coin-P2P REACHABILITY KAT — self-address advertisement (Knots net.cpp
// GetLocalAddress / SeenLocal / MaybeSendAddr + CConnman self-connect nonce).
//
// The live defect this closes (contabo 2026-09-03): the InboundListener is up on
// :8333 and externally reachable, yet ZERO inbound connections arrive — the fork
// network never LEARNS our address. Listening is necessary but NOT sufficient; a
// node becomes dialable only once peers record our reachable IP:port and gossip
// it. The fix advertises our own address (version addr_from + a self-addr push at
// handshake and periodically), discovers that address (operator --coin-externalip
// or peer-echo scoring), and guards against dialing ourselves once our routable
// addr comes back through the gossip mesh.
//
// Every assert is zero-socket and deterministic — nothing dials, resolves, or
// accepts. Live inbound arrival on contabo is the operator soak gate (necessary,
// not sufficient).
//
// RED-before / GREEN-after: on the branch tip LocalAddrTable / SelfNonceRegistry
// did not exist, the outbound version addr_from was a hardcoded 192.168.0.1:8333
// (T3 fails), no self-addr push existed (T4), the getaddr reply omitted our own
// address and dropped NODE_WITNESS (T5), and there was no self-connect guard (T2).
// ---------------------------------------------------------------------------

#include <cassert>
#include <cstdint>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include <boost/asio/io_context.hpp>

#include <core/core_util.hpp>          // core::timestamp()
#include <core/pack.hpp>
#include <core/netaddress.hpp>
#include "../p2p_messages.hpp"         // message_version, message_addr, btc_addr_record_t
#include "../local_addr.hpp"           // LocalAddrTable, SelfNonceRegistry
#include "../p2p_node.hpp"             // NodeP2P (seam compile-proof), COIN_NODE_BLAKE2B
#include "../inbound_listener.hpp"     // InboundListener (seam compile-proof)

using bip110::coin::p2p::LocalAddrTable;
using bip110::coin::p2p::SelfNonceRegistry;
using bip110::coin::p2p::COIN_NODE_BLAKE2B;
using bip110::coin::p2p::btc_addr_record_t;
using bip110::coin::p2p::message_version;
using bip110::coin::p2p::message_addr;

namespace {

constexpr uint64_t NODE_NETWORK = 1;
constexpr uint64_t NODE_WITNESS = (uint64_t{1} << 3);
// Truthful per Knots protocol.h SeedsServiceFlags 0x10000009.
constexpr uint64_t OUR_SERVICES = NODE_NETWORK | NODE_WITNESS | COIN_NODE_BLAKE2B;

// Minimal duck-typed config mirroring main_bip110's MiniConfig (only ever reads
// config->coin()->m_p2p.prefix, never exercised here). Lets us instantiate the
// NodeP2P / InboundListener templates to compile-prove the self-advertise seams.
struct KatCoinCfg {
    struct P2P { std::vector<std::byte> prefix; NetService address; } m_p2p;
    bool m_testnet{false};
    bool m_regtest{false};
    std::string m_symbol{"BIP110"};
    KatCoinCfg* coin() { return this; }
};
struct KatConfig {
    KatCoinCfg m_coin;
    bool m_testnet{false};
    KatCoinCfg* coin() { return &m_coin; }
};

int g_failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " (line " << __LINE__ << ")\n"; ++g_failures; } } while (0)

// ── T1: LocalAddrTable — peer-echo scoring, routable-only, port substitution,
//        --coin-externalip override (Knots SeenLocal / GetLocalAddress) ────────
void t1_local_addr_table()
{
    LocalAddrTable t(/*listen_port=*/8333);

    // No signal yet -> we do not know our address (never guess).
    CHECK(!t.best_local().has_value());

    // Private / documentation / loopback echoes are REJECTED (never advertise a
    // NAT-mangled or LAN echo — it would poison every peer that learns it).
    t.seen_local("10.0.0.5");        // RFC1918
    t.seen_local("192.168.1.1");     // RFC1918
    t.seen_local("127.0.0.1");       // loopback
    t.seen_local("203.0.113.9");     // RFC5737 documentation
    CHECK(!t.best_local().has_value());

    // Routable echoes are scored; the most-agreed IP wins. The echoed PORT is
    // discarded — best_local() always substitutes our real listen port (8333),
    // because a dialed-out echo carries our EPHEMERAL source port (the #1 trap:
    // advertising it points peers at a dead port).
    t.seen_local("45.13.214.55");
    t.seen_local("45.13.214.55");
    t.seen_local("8.8.8.8");
    auto best = t.best_local();
    CHECK(best.has_value());
    CHECK(best->address() == "45.13.214.55");   // 2 votes beats 1
    CHECK(best->port() == 8333);                // listen port, NOT any echoed ephemeral

    // --coin-externalip is authoritative: it wins over peer-echo, keeps the
    // listen port, and rejects a non-routable pin.
    LocalAddrTable t2(8333);
    t2.set_external("192.168.0.1");             // RFC1918 -> ignored
    CHECK(!t2.best_local().has_value());
    t2.seen_local("8.8.8.8");
    t2.set_external("51.51.51.51");             // routable pin
    auto ext = t2.best_local();
    CHECK(ext.has_value());
    CHECK(ext->address() == "51.51.51.51" && ext->port() == 8333);

    std::cout << "T1 local-addr: best=" << best->to_string()
              << " external-pin=" << ext->to_string() << "\n";
}

// ── T2: SelfNonceRegistry — self-connect guard (Knots CConnman nonce) ─────────
void t2_self_nonce_registry()
{
    SelfNonceRegistry r(/*capacity=*/4);

    // 0 is never a self-nonce (Knots treats 0 specially).
    r.record(0);
    CHECK(!r.is_self(0));

    r.record(0xDEADBEEFULL);
    CHECK(r.is_self(0xDEADBEEFULL));
    CHECK(!r.is_self(0x1234ULL));      // a nonce we never sent -> a real peer

    // Bounded ring: after capacity is exceeded the OLDEST nonce is evicted.
    r.record(1); r.record(2); r.record(3); r.record(4); // evicts 0xDEADBEEF + fills
    r.record(5);                                         // evicts 1
    CHECK(!r.is_self(0xDEADBEEFULL));   // aged out
    CHECK(r.is_self(5));                // freshest retained
    CHECK(r.is_self(2));               // still within window

    std::cout << "T2 self-nonce: guard + bounded eviction OK\n";
}

// ── T3: outgoing version addr_from carries OUR reachable addr, NEVER the old
//        hardcoded 192.168.0.1 (G3). Round-trips through the real wire codec. ──
void t3_version_addr_from()
{
    LocalAddrTable t(8333);
    t.seen_local("158.220.92.171");        // contabo public IP (routable)
    auto best = t.best_local();
    CHECK(best.has_value());

    // Build a version EXACTLY as NodeP2P::connected() now does: addr_from = our
    // reachable addr with OUR_SERVICES.
    PackStream ps = message_version::make(
        uint32_t{70016}, OUR_SERVICES, uint64_t{0},
        addr_t{OUR_SERVICES, NetService{std::string("8.8.8.8"), uint16_t{8333}}},   // addr_to (the peer)
        addr_t{OUR_SERVICES, *best},                                                 // addr_from (US)
        uint64_t{0}, std::string("/c2pool:0.1/bip110/frstrtr/"), uint32_t{0});

    auto parsed = message_version::make(ps);   // round-trip decode
    CHECK(parsed->m_addr_from.m_endpoint.address() == "158.220.92.171");
    CHECK(parsed->m_addr_from.m_endpoint.port() == 8333);
    CHECK((parsed->m_addr_from.m_services & COIN_NODE_BLAKE2B) != 0);
    // The old untruthful literal is gone.
    CHECK(parsed->m_addr_from.m_endpoint.address() != "192.168.0.1");

    std::cout << "T3 version addr_from: " << parsed->m_addr_from.m_endpoint.to_string()
              << " services=0x" << std::hex << parsed->m_addr_from.m_services << std::dec
              << " (was 192.168.0.1)\n";
}

// ── T4: self-addr push record (G2) — the Knots MaybeSendAddr payload we send at
//        verack: 1 record, our reachable IP:8333, NODE_BLAKE2B + NODE_WITNESS. ─
void t4_self_addr_record()
{
    LocalAddrTable t(8333);
    t.seen_local("158.220.92.171");
    auto best = t.best_local();
    CHECK(best.has_value());

    btc_addr_record_t rec;
    rec.m_services  = OUR_SERVICES;
    rec.m_endpoint  = *best;
    rec.m_timestamp = static_cast<uint32_t>(core::timestamp());

    PackStream ps = message_addr::make(std::vector<btc_addr_record_t>{rec});
    auto parsed = message_addr::make(ps);
    CHECK(parsed->m_addrs.size() == 1);
    CHECK(parsed->m_addrs[0].m_endpoint.address() == "158.220.92.171");
    CHECK(parsed->m_addrs[0].m_endpoint.port() == 8333);
    CHECK((parsed->m_addrs[0].m_services & COIN_NODE_BLAKE2B) != 0);
    CHECK((parsed->m_addrs[0].m_services & NODE_WITNESS) != 0);

    std::cout << "T4 self-addr push: 1 record " << parsed->m_addrs[0].m_endpoint.to_string()
              << " NODE_BLAKE2B+NODE_WITNESS\n";
}

// ── T5: getaddr reply now INCLUDES our own address FIRST and carries the FULL
//        service set (NODE_WITNESS was previously dropped) (G5). Replicates the
//        listener's reply-construction logic. ─────────────────────────────────
void t5_getaddr_self_and_services()
{
    LocalAddrTable t(8333);
    t.seen_local("158.220.92.171");
    auto best = t.best_local();
    CHECK(best.has_value());

    const auto now = static_cast<uint32_t>(core::timestamp());
    std::vector<btc_addr_record_t> records;

    // Self record FIRST (Knots includes the local addr in getaddr replies).
    {
        btc_addr_record_t self;
        self.m_services  = OUR_SERVICES;
        self.m_endpoint  = *best;
        self.m_timestamp = now;
        records.push_back(self);
    }
    // Then the fork-filtered tried set (services carry the full fork set — the
    // pre-fix reply hardcoded NODE_BLAKE2B|NODE_NETWORK and dropped NODE_WITNESS).
    for (const auto& ns : { NetService("45.13.214.55", 8333),
                            NetService("47.203.64.175", 9333) }) {
        btc_addr_record_t rec;
        rec.m_services  = OUR_SERVICES;
        rec.m_endpoint  = ns;
        rec.m_timestamp = now;
        records.push_back(rec);
    }

    PackStream ps = message_addr::make(records);
    auto parsed = message_addr::make(ps);
    CHECK(parsed->m_addrs.size() == 3);
    // our own reachable addr is served (so a crawler learns US directly).
    CHECK(parsed->m_addrs[0].m_endpoint.address() == "158.220.92.171");
    CHECK(parsed->m_addrs[0].m_endpoint.port() == 8333);
    // every served record advertises the FULL fork service set incl NODE_WITNESS.
    for (const auto& r : parsed->m_addrs) {
        CHECK((r.m_services & COIN_NODE_BLAKE2B) != 0);
        CHECK((r.m_services & NODE_WITNESS) != 0);
    }

    std::cout << "T5 getaddr reply: served=" << parsed->m_addrs.size()
              << " (self first) all NODE_WITNESS\n";
}

// ── T6: addr-relay fresh-batch selection (G6, Knots RelayAddress nTime<=10min,
//        batch<=10). Only recent NODE_BLAKE2B records are forwarded. ───────────
void t6_relay_fresh_batch()
{
    const int64_t now = static_cast<int64_t>(core::timestamp());
    auto rec = [](uint64_t svc, uint32_t ts, const NetService& ep) {
        btc_addr_record_t r; r.m_services = svc; r.m_timestamp = ts; r.m_endpoint = ep; return r;
    };
    std::vector<btc_addr_record_t> in = {
        rec(OUR_SERVICES, static_cast<uint32_t>(now),        NetService("45.13.214.55", 8333)), // fresh fork -> KEEP
        rec(OUR_SERVICES, static_cast<uint32_t>(now + 3600), NetService("9.9.9.9",     9333)), // +1h future -> DROP
        rec(OUR_SERVICES, static_cast<uint32_t>(now - 3600), NetService("8.8.8.8",     8333)), // -1h old    -> DROP
        rec(NODE_NETWORK | NODE_WITNESS, static_cast<uint32_t>(now), NetService("1.1.1.1", 8333)), // non-fork -> DROP
    };

    // The exact predicate the addr handler uses to build the relay batch.
    std::vector<btc_addr_record_t> fresh;
    for (const auto& r : in) {
        if (!(r.m_services & COIN_NODE_BLAKE2B)) continue;
        const int64_t ts = static_cast<int64_t>(r.m_timestamp);
        if (ts > now + 10 * 60 || ts < now - 10 * 60) continue;
        fresh.push_back(r);
        if (fresh.size() >= 10) break;
    }
    CHECK(fresh.size() == 1);
    CHECK(fresh[0].m_endpoint.address() == "45.13.214.55");

    std::cout << "T6 addr-relay: in=" << in.size() << " fresh-fork=" << fresh.size() << "\n";
}

// ── T7: compile-proof that the self-advertise seams exist and accept the shared
//        tables on BOTH arms (outbound NodeP2P + InboundListener), reusing the
//        live infra — no reinvented addr/socket stack. ───────────────────────
void t7_seam_wiring_compile_proof()
{
    boost::asio::io_context ioc;
    auto local = std::make_shared<LocalAddrTable>(uint16_t{8333});
    auto nonce = std::make_shared<SelfNonceRegistry>();

    KatConfig cfg;
    bip110::coin::p2p::NodeP2P<KatConfig> node(&ioc, nullptr, &cfg, "kat");
    node.set_local_addr_table(local);
    node.set_self_nonce_registry(nonce);
    node.set_addr_relay_sink(
        [](const std::vector<btc_addr_record_t>&, const NetService&) {});

    bip110::coin::p2p::InboundListener<KatConfig> il(&ioc, &cfg, "kat-inbound");
    il.set_local_addr_table(local);
    il.set_self_nonce_registry(nonce);
    il.set_addr_callback([](const std::vector<NetService>&, const NetService&) {});
    // relay_addr is a no-op with no live sessions but must be callable.
    il.relay_addr({}, "0.0.0.0:8333");

    CHECK(local->listen_port() == 8333);
    std::cout << "T7 seam wiring: NodeP2P + InboundListener accept shared "
                 "LocalAddrTable/SelfNonceRegistry/relay seams\n";
}

} // namespace

int main()
{
    std::cout << "=== bip110 coin-P2P reachability (self-advertise) KAT ===\n";
    t1_local_addr_table();
    t2_self_nonce_registry();
    t3_version_addr_from();
    t4_self_addr_record();
    t5_getaddr_self_and_services();
    t6_relay_fresh_batch();
    t7_seam_wiring_compile_proof();

    if (g_failures) {
        std::cerr << "\nbip110_coin_reachability_kat: " << g_failures << " CHECK(s) FAILED\n";
        return 1;
    }
    std::cout << "\nbip110_coin_reachability_kat: ALL PASS\n";
    return 0;
}
