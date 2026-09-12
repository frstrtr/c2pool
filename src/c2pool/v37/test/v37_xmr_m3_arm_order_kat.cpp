// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_m3_arm_order_kat.cpp   --  M3
//
// R-ARMORDER, pinned on BOTH settings.
//
// M3 makes the FIND path switchable: daemon-first (the default, and what M0
// through M2h ran) keeps monerod as the tip, the canonical test and the block
// publisher; p2p-first moves all three onto the embedded native node. A switch
// is only worth having if both of its positions are held to their claim, so
// this file asserts the two of them side by side, against the same daemon
// transport, and counts what that transport was asked to do.
//
// THE COUNT IS THE POINT. CountingTransport wraps the monerod stub and counts
// every rpc_post and every zmq_subscribe. Under daemon-first that count must be
// NON-ZERO -- the adapter really is talking to a daemon, and a "zero" there
// would mean the default path had quietly stopped working rather than that M3
// succeeded. Under p2p-first it must be EXACTLY ZERO, through bring-up and
// through a complete FOUND -> SETTLED, because that is the milestone's whole
// claim and an off-by-one is a failed claim.
//
// Suites:
//   A  the switch's declared rules (arm_order_refusal), pure and exhaustive
//   B  daemon-first is UNCHANGED: adapter live, tip drives finalize, RPC > 0
//   C  p2p-first is DAEMONLESS: no adapter, a pumped native chain drives the
//      same finalize contract, and the daemon transport is never touched
//   D  p2p-first is FAIL-CLOSED: no canonical test installed -> bring_up
//      refuses, rather than starting into a window where every settled block
//      would be orphaned by a predicate that cannot answer
//   E  the publisher: a found block goes out as a levin 2008 through C5, and a
//      relay that reached NOBODY pushes NO FOUND event
//
// No sockets, no RandomX, no live daemon: builds and runs on BOTH build.yml
// legs (the Linux x86_64 leg and the ASan+UBSan one), which is also why it is
// listed in both --target lists -- a registered-but-unbuilt target reads as
// "***Not Run" and fails ctest with exit 8 (the #1539 lesson).
// ===========================================================================
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <map>
#include <unistd.h>
#include <string>
#include <vector>

#include "c2pool/v37/xmr/xmr_node.hpp"
#include "c2pool/v37/xmr/xmr_node_config.hpp"
#include "c2pool/v37/xmr/xmr_p2p_block_publisher.hpp"
#include "impl/xmr/native/contracts/fakes/fakes.hpp"
#include "impl/xmr/native/relay/xmr_block_relay.hpp"
#include "impl/xmr/node/monerod_transport.hpp"

#include "xmr_c2a_golden.hpp"

using namespace c2pool::v37n::xmr;
namespace node   = ::c2pool::xmr::node;
namespace native = ::c2pool::xmr::native;

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------
static int g_pass = 0, g_fail = 0;

static void check(bool ok, const std::string& what, const std::string& detail = {}) {
    if (ok) {
        ++g_pass;
    } else {
        ++g_fail;
        std::printf("  [FAIL] %s%s%s\n", what.c_str(), detail.empty() ? "" : " -- ",
                    detail.c_str());
        return;
    }
    std::printf("  [ok]   %s\n", what.c_str());
}

// A point-check backend for the light build: not a torsion check, just enough
// for the P-1 XMR descriptor validator to be LIVE so XmrNode will start (the
// real ref10 check is pinned by xmr_torsion_kat).
static bool test_point_check(const std::uint8_t* pt) {
    for (int i = 0; i < 32; ++i)
        if (pt[i] != 0) return true;
    return false;
}

// ---------------------------------------------------------------------------
// CountingTransport -- the monerod stub, with a turnstile on it.
// ---------------------------------------------------------------------------
class CountingTransport final : public node::IMonerodTransport {
public:
    void rpc_post(const std::string& body,
                  std::function<void(const node::RpcResponse&)> on_done) override {
        ++rpc_calls;
        last_method = node::MockMonerodTransport::extract_method(body);
        node::RpcResponse r;
        r.error = "counting-transport: no responder installed";
        on_done(r);
    }
    void zmq_subscribe(const std::string& topic,
                       std::function<void(const node::ZmqFrame&)>) override {
        ++zmq_subs;
        last_topic = topic;
    }

    std::uint64_t rpc_calls = 0;
    std::uint64_t zmq_subs  = 0;
    std::string   last_method;
    std::string   last_topic;

    std::uint64_t touches() const { return rpc_calls + zmq_subs; }
};

static node::Hash blk_id(std::uint8_t b) {
    node::Hash h{};
    for (int i = 0; i < 32; ++i) h[i] = static_cast<std::uint8_t>(b + i);
    return h;
}

static node::MainchainEvent extend_at(std::uint64_t h, std::uint8_t seed, std::uint8_t prev_seed) {
    node::MainchainEvent ev;
    ev.kind          = node::MainchainEventKind::Extend;
    ev.block.height  = h;
    ev.block.id      = blk_id(seed);
    ev.block.prev_id = blk_id(prev_seed);
    return ev;
}

static XmrNodeConfig base_cfg(const std::filesystem::path& dir, ::v37::ChainId chain,
                              std::uint64_t d_conf) {
    XmrNodeConfig c;
    c.network        = MoneroNetwork::Stagenet;
    c.lane_chain     = chain;
    c.d_conf         = d_conf;
    c.settle_db_path = dir.string();
    return c;
}

// ===========================================================================
// A -- the switch's declared rules
// ===========================================================================
static void suite_a() {
    std::printf("A: the arm-order preconditions\n");

    check(std::string(to_string(ArmOrderMode::DaemonFirst)) == "daemon-first",
          "A1 daemon-first renders as its flag spelling");
    check(std::string(to_string(ArmOrderMode::P2PFirst)) == "p2p-first",
          "A2 p2p-first renders as its flag spelling");

    XmrNodeConfig c;
    check(c.arm_order == ArmOrderMode::DaemonFirst,
          "A3 DaemonFirst is the DEFAULT (bring-up posture, ruling R-ARMORDER)");

    // daemon-first accepts every coinbase / template combination, exactly as
    // M0..M2h did: the switch adds a mode, it does not narrow the old one.
    check(arm_order_refusal(c).empty(), "A4 daemon-first + option A is accepted");
    c.coinbase = CoinbaseMode::V37Settlement;
    check(arm_order_refusal(c).empty(), "A5 daemon-first + option B is accepted");
    c.template_source = TemplateSourceMode::Native;
    check(arm_order_refusal(c).empty(), "A6 daemon-first + native template is accepted");

    // p2p-first refuses anything that would leave a daemon on the find path.
    XmrNodeConfig p;
    p.arm_order = ArmOrderMode::P2PFirst;
    check(!arm_order_refusal(p).empty(),
          "A7 p2p-first REFUSES option A (its block IS get_block_template)");
    p.coinbase = CoinbaseMode::V37Settlement;
    check(!arm_order_refusal(p).empty(),
          "A8 p2p-first REFUSES the monerod template source (get_miner_data per refresh)");
    p.template_source = TemplateSourceMode::Native;
    check(!arm_order_refusal(p).empty(),
          "A9 p2p-first REFUSES an empty --native-connect (no chain, nowhere to relay)");
    p.native_connect.push_back("127.0.0.1:18080");
    check(arm_order_refusal(p).empty(),
          "A10 p2p-first + option B + native template + a peer is accepted");
}

// ===========================================================================
// B -- daemon-first is unchanged
// ===========================================================================
static void suite_b(const std::filesystem::path& root) {
    std::printf("B: daemon-first (default) still drives the tip from monerod\n");

    CountingTransport tx;
    XmrNode node(base_cfg(root / "daemon_first", 7, 3), tx, &test_point_check);
    bool up = true;
    try {
        node.bring_up();
    } catch (const std::exception& e) {
        up = false;
        check(false, "B1 bring_up succeeds under daemon-first", e.what());
    }
    if (!up) return;
    check(true, "B1 bring_up succeeds under daemon-first");

    check(node.daemon_tip_active(),
          "B2 the X2 adapter IS the tip driver under daemon-first");
    check(tx.touches() > 0,
          "B3 the daemon transport WAS used (adapter start + initial_sync)",
          "rpc=" + std::to_string(tx.rpc_calls) + " zmq=" + std::to_string(tx.zmq_subs));
    check(tx.zmq_subs > 0, "B4 the ZMQ topics were subscribed");

    // The adapter's own index drives settlement, as it always did.
    node::ChainMainBlock r;
    r.height  = 11;
    r.id      = blk_id(11);
    r.prev_id = blk_id(10);
    node.adapter().index().apply(r);
    check(node.best_height() == 11,
          "B5 best_height reads the adapter's index under daemon-first",
          "best=" + std::to_string(node.best_height()));
}

// ===========================================================================
// C -- p2p-first is daemonless, end to end
// ===========================================================================
static void suite_c(const std::filesystem::path& root) {
    std::printf("C: p2p-first drives the find path from the native chain, at zero RPC\n");

    const ::v37::ChainId CHAIN  = 7;
    const std::uint64_t  D_CONF = 3;

    // The native chain, as a main-thread model of what NativeNode's tip feed
    // hands over: a height -> id map the canonical test reads, and a queue of
    // events the loop pumps. Same two shapes native_chain_source() binds.
    std::map<std::uint64_t, std::string> chain;

    XmrNodeConfig cfg = base_cfg(root / "p2p_first", CHAIN, D_CONF);
    cfg.arm_order       = ArmOrderMode::P2PFirst;
    cfg.coinbase        = CoinbaseMode::V37Settlement;
    cfg.template_source = TemplateSourceMode::Native;
    cfg.native_connect.push_back("127.0.0.1:18080");

    CountingTransport tx;
    XmrNode node(cfg, tx, &test_point_check);
    node.set_native_chain_presence([&chain](std::uint64_t h, const std::string& bid) {
        auto it = chain.find(h);
        return it != chain.end() && it->second == bid;
    });

    bool up = true;
    try {
        node.bring_up();
    } catch (const std::exception& e) {
        up = false;
        check(false, "C1 bring_up succeeds under p2p-first", e.what());
    }
    if (!up) return;
    check(true, "C1 bring_up succeeds under p2p-first");

    check(!node.daemon_tip_active(),
          "C2 NO X2 adapter is built under p2p-first");
    check(tx.touches() == 0,
          "C3 bring_up made ZERO daemon touches (rpc + zmq)",
          "rpc=" + std::to_string(tx.rpc_calls) + " zmq=" + std::to_string(tx.zmq_subs));

    // The block we found, at height 20, on the chain we verified ourselves.
    const std::uint64_t FOUND_H = 20;
    const node::Hash    FOUND_ID = blk_id(20);
    chain[FOUND_H] = hex_of(FOUND_ID);

    // A valueless {}/{} record, exactly as the daemon writes one without payee
    // keys: the ledger still registers the block, which is what matures.
    const bool won = node.on_network_block_won(FOUND_H, FOUND_ID, Amounts{}, Amounts{});
    check(won, "C4 a found block registers through the SAME wire-4 entry point");

    // Walk the native chain past D_CONF burial, one pumped event at a time --
    // the substitution for pump_poll(), and nothing else.
    for (std::uint64_t h = FOUND_H; h <= FOUND_H + D_CONF + 1; ++h) {
        chain[h] = hex_of(blk_id(static_cast<std::uint8_t>(h)));
        node.pump_mainchain_event(extend_at(h, static_cast<std::uint8_t>(h),
                                            static_cast<std::uint8_t>(h - 1)));
    }

    check(node.best_height() == FOUND_H + D_CONF + 1,
          "C5 best_height follows the PUMPED native tip",
          "best=" + std::to_string(node.best_height()));
    check(node.hw().hw_height == FOUND_H + D_CONF + 1,
          "C6 the settlement high-water advanced off the native tip",
          "hw=" + std::to_string(node.hw().hw_height));
    check(node.finalize_driver().cursor_height() >= FOUND_H,
          "C7 the F1 finalize cursor stepped PAST the found height (SETTLED)",
          "cursor=" + std::to_string(node.finalize_driver().cursor_height()));

    check(tx.touches() == 0,
          "C8 FOUND -> SETTLED made ZERO daemon touches: rpc_on_find_path == 0",
          "rpc=" + std::to_string(tx.rpc_calls) + " zmq=" + std::to_string(tx.zmq_subs));

    // An orphan disposes through the same seam, still without a daemon.
    node::MainchainEvent orph;
    orph.kind        = node::MainchainEventKind::Orphan;
    orph.orphaned_id = blk_id(20);
    node.pump_mainchain_event(orph);
    check(tx.touches() == 0, "C9 an orphan disposition made ZERO daemon touches");
}

// ===========================================================================
// D -- p2p-first is fail-closed on its canonical test
// ===========================================================================
static void suite_d(const std::filesystem::path& root) {
    std::printf("D: p2p-first refuses to start without a canonical test\n");

    XmrNodeConfig cfg = base_cfg(root / "failclosed", 7, 3);
    cfg.arm_order       = ArmOrderMode::P2PFirst;
    cfg.coinbase        = CoinbaseMode::V37Settlement;
    cfg.template_source = TemplateSourceMode::Native;
    cfg.native_connect.push_back("127.0.0.1:18080");

    CountingTransport tx;
    XmrNode node(cfg, tx, &test_point_check);
    bool threw = false;
    std::string why;
    try {
        node.bring_up();
    } catch (const std::exception& e) {
        threw = true;
        why   = e.what();
    }
    check(threw, "D1 bring_up REFUSES p2p-first with no presence test installed");
    check(threw && why.find("p2p-first") != std::string::npos,
          "D2 the refusal names the mode it refused", why);
    check(tx.touches() == 0, "D3 the refusal itself touched no daemon");
}

// ===========================================================================
// E -- the publisher: a levin 2008 instead of submit_block
// ===========================================================================
namespace {

// A block the relay will accept: a real captured stagenet block, re-identified
// by this repository's own code rather than trusted from the fixture.
struct BlockFixture {
    std::vector<std::uint8_t> blob;
    native::Hash              id{};
    std::vector<std::uint8_t> hashing_blob;
    std::uint64_t             height       = 0;
    std::uint32_t             nonce        = 0;
    std::size_t               nonce_offset = 0;
};

std::vector<std::uint8_t> bytes_from_hex(const std::string& hex) {
    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
        out.push_back(static_cast<std::uint8_t>(nib(hex[i]) * 16 + nib(hex[i + 1])));
    return out;
}

bool load_fixture(BlockFixture& f) {
    f.blob   = bytes_from_hex(native::golden_c2a::BLOCKS[0].blob_hex);
    f.height = native::golden_c2a::BLOCKS[0].height;
    native::ParsedBlock   pb;
    native::BlockIdentity ident;
    if (native::parse_and_identify(f.blob, pb, ident) != native::BlockParseStatus::Ok)
        return false;
    if (pb.header_size < 4) return false;
    f.id           = ident.id;
    f.hashing_blob = ident.hashing_blob;
    f.nonce        = pb.header.nonce;
    f.nonce_offset = pb.header_size - 4;   // the u32 nonce ends the header
    // The fixture is only usable if OUR identity matches the one monerod
    // reported for these bytes; otherwise every assertion below would be
    // checking this file against itself.
    const std::vector<std::uint8_t> want = bytes_from_hex(native::golden_c2a::BLOCKS[0].id_hex);
    return want.size() == f.id.size() &&
           std::equal(want.begin(), want.end(), f.id.begin());
}

} // namespace

static void suite_e() {
    std::printf("E: the p2p publisher relays a found block and never invents one\n");

    BlockFixture f;
    if (!load_fixture(f)) {
        check(false, "E0 the captured block fixture parses and re-identifies");
        return;
    }
    check(true, "E0 the captured block fixture parses and re-identifies");

    native::fakes::FakeBroadcastPort port;
    native::fakes::FakeMinerDataSource bodies;
    native::fakes::FakeChain           chain;

    native::relay::RelayConfig rcfg;
    rcfg.policy.order                 = native::ArmOrder::P2pOnly;
    rcfg.policy.include_all_tx_bodies = true;
    native::relay::LevinBlockRelay relay(port, native::relay::DaemonSubmitSink{}, &bodies,
                                         &chain, rcfg);

    submit::FoundBlockQueue found;
    auto lookup = [&f](std::uint32_t, std::uint32_t, submit::BlockCandidate& out) {
        out.template_id     = 1;
        out.height          = f.height;
        out.full_blob       = f.blob;
        out.hashing_blob    = f.hashing_blob;
        out.nonce_offset    = f.nonce_offset;
        out.expected_reward = 600000000000ull;
        return true;
    };

    o2::P2pBlockPublisher pub(relay, found, lookup);

    // (1) fail-closed before the RandomX verifier says so.
    pub.submit_network_block(1, f.nonce, 0);
    check(pub.refused() == 1 && found.pushed() == 0,
          "E1 a disabled relay REFUSES and pushes no FOUND event",
          pub.last_error());

    // (2) armed, with peers: the block goes out and a FOUND event follows.
    pub.enable_network_relay(true);
    port.state_normal_peers = 3;
    pub.submit_network_block(1, f.nonce, 0);
    check(pub.relayed() == 1, "E2 the block was relayed over levin", pub.last_error());
    check(found.pushed() == 1, "E3 exactly one FOUND event was pushed");
    submit::FoundBlockEvent ev;
    const bool got = found.pop(ev);
    check(got && ev.block_id == f.id,
          "E4 the FOUND event carries OUR block id, off the bytes we relayed");
    check(got && ev.id_source == submit::IdSource::Local,
          "E5 the id source is Local -- no daemon named this block");
    check(got && ev.header_check == submit::HeaderCheck::NotRun,
          "E6 header_check stays NotRun: nothing confirmed the height for us");
    check(got && ev.rpc_ms == 0.0, "E7 the publish cost zero RPC milliseconds");
    check(port.broadcasts.size() == 1 && port.broadcasts[0].cmd == 2008u,
          "E8 exactly one 2008 NOTIFY_NEW_FLUFFY_BLOCK went to the port");
    // THE BODY, NOT A FRAME. IBroadcastPort takes the epee message body and the
    // transport writes the levin bucket header around it. C5 handed it a
    // complete frame until M3's live run, and every Monero peer answered
    // "portable_storage: wrong binary format - signature mismatch" while the
    // peers-written count read perfectly -- the bytes reached the socket and
    // the block reached no chain. The epee storage signature is the pin:
    // 01 11 01 01 | 01 01 02 01 | version, never a levin header (01 21 01 01).
    {
        const std::vector<std::uint8_t>& b = port.broadcasts[0].bytes;
        const std::uint8_t want[9] = {0x01, 0x11, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01};
        bool bare = b.size() >= 9;
        for (int i = 0; bare && i < 9; ++i)
            bare = (b[static_cast<std::size_t>(i)] == want[i]);
        check(bare, "E8b the port got a BARE epee body, not a doubly-framed notify");
    }

    // (3) THE FAIL-CLOSED ONE: a relay that reached nobody must not push a
    //     FOUND event. A block in the settlement ledger that no peer ever
    //     received would mature, be refused by the canonical test and be
    //     disposed as an orphan -- after the share that paid for it was spent.
    port.state_normal_peers = 0;
    port.broadcasts.clear();
    pub.submit_network_block(1, f.nonce, 0);
    check(pub.failed() == 1, "E9 zero peers is a LOUD failure, not a shrug",
          pub.last_error());
    check(found.pushed() == 1,
          "E10 a block that reached NOBODY pushes NO FOUND event (fail-closed)",
          "pushed=" + std::to_string(found.pushed()));

    // (4) a candidate with no served hashing blob has no verified id to attest.
    port.state_normal_peers = 3;
    auto blind = [&f](std::uint32_t, std::uint32_t, submit::BlockCandidate& out) {
        out.template_id  = 1;
        out.height       = f.height;
        out.full_blob    = f.blob;
        out.nonce_offset = f.nonce_offset;
        return true;                       // note: no hashing_blob
    };
    o2::P2pBlockPublisher blind_pub(relay, found, blind);
    blind_pub.enable_network_relay(true);
    blind_pub.submit_network_block(1, f.nonce, 0);
    check(blind_pub.refused() == 1 && blind_pub.relayed() == 0,
          "E11 no hashing blob -> no attestable id -> REFUSED, never relayed",
          blind_pub.last_error());
}

// ===========================================================================
int main() {
    std::printf("== v37_xmr_m3_arm_order_kat: R-ARMORDER pinned on both settings ==\n");

    const std::filesystem::path root =
        std::filesystem::temp_directory_path() /
        ("v37-xmr-m3-armorder-" + std::to_string(static_cast<long>(::getpid())));
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    suite_a();
    suite_b(root);
    suite_c(root);
    suite_d(root);
    suite_e();

    std::filesystem::remove_all(root);

    std::printf("== %s: %d passed, %d failed ==\n", g_fail ? "FAIL" : "OK", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
