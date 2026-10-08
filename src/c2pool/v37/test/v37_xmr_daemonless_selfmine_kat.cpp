// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_daemonless_selfmine_kat.cpp
//
// THE SOLO CONFIGURATION, PINNED: what it lets through, and what it does NOT.
//
// The in-process CPU miner already hashed the node's own template and submitted
// its own wins. What it could not do was run with nothing else alive: the find
// path still needed a levin PEER, because the genesis blob was asked for over
// the wire and because a found block was only booked once a peer had received
// it. --native-solo removes both needs. This file pins the three pieces of that
// and, more importantly, the four places it must still refuse.
//
//   A  THE TRUST ROOT, ASSEMBLED LOCALLY. rt::local_genesis_blob(net) must
//      derive, through the SAME genesis_row_from_blob() gate the levin path
//      feeds, a row whose id IS the pinned per-network genesis id -- and a
//      blob with one byte moved must be refused by that same gate. This is the
//      whole reason the local blob is not a trust addition: it is an input to a
//      check, not a substitute for one. A2 also pins the locally assembled
//      mainnet blob against the M0 capture from monerod 0.18.5.1, so the
//      construction is checked against a daemon's bytes and not only against
//      its own hash.
//
//   B  THE SOLO BOOT. ChainBoot::boot_from_local_genesis() seeds row 0 with no
//      peer in sight, is idempotent, and refuses an empty or foreign blob.
//
//   C  THE VERDICT. A relay that reached nobody but that our own index took now
//      SAYS so (own_index_attempted / own_index_accepted / landed_own_chain())
//      -- and reached_network() is UNCHANGED by all of it, because the wire
//      claim and the own-chain claim must never become the same sentence.
//
//   D  THE PUBLISHER, BOTH WAYS. Default (solo OFF) is #1662's behaviour to the
//      letter: zero peers -> no FOUND event, failed()+1, whatever our own index
//      did. Solo ON: the same relay books exactly one FOUND event, counts it in
//      solo_landed() and NOT in relayed(), and still refuses when the index
//      itself said no. The negative case is the one that matters: without D1,
//      turning solo on would be indistinguishable from removing the gate.
//
//   E  THE REFUSALS, as pure functions. solo_refusal() is regtest-only,
//      p2p-first-only, takes no peers and no anchor; arm_order_refusal() drops
//      its one-peer requirement for solo and keeps it for everybody else. And
//      --mine stays OFF and --native-solo stays OFF in a default config, which
//      is the one property a reader of this branch will want checked first.
//
// No sockets, no daemon, no RandomX, no threads: this links xmr_node for the
// boot/index/relay and xmr_coin for keccak and block parsing.
//
// HOLLOW-GREEN GUARD: this target is ALSO listed in BOTH build.yml `--target`
// lists (the Linux x86_64 leg and the ASan+UBSan leg). A registered-but-unbuilt
// target reports "***Not Run" and fails ctest with exit 8 -- a red that is not
// a test failure (the #1539 lesson).
// ===========================================================================
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "c2pool/v37/xmr/xmr_node_config.hpp"
#include "c2pool/v37/xmr/xmr_p2p_block_publisher.hpp"
#include "impl/xmr/native/chain/xmr_chain_index.hpp"
#include "impl/xmr/native/contracts/fakes/fakes.hpp"
#include "impl/xmr/native/node/xmr_chain_boot.hpp"
#include "impl/xmr/native/node/xmr_genesis_blob.hpp"
#include "impl/xmr/native/p2p/chain_seeds.hpp"
#include "impl/xmr/native/relay/xmr_block_relay.hpp"

#include "xmr_c2a_golden.hpp"

using namespace c2pool::v37n::xmr;
namespace native = ::c2pool::xmr::native;
namespace rt     = ::c2pool::xmr::native::rt;
namespace submit = ::c2pool::v37n::xmr::submit;

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------
static int g_pass = 0, g_fail = 0;

static void check(bool ok, const std::string& what, const std::string& detail = {}) {
    if (ok) {
        ++g_pass;
        std::printf("  [ok]   %s\n", what.c_str());
        return;
    }
    ++g_fail;
    std::printf("  [FAIL] %s%s%s\n", what.c_str(), detail.empty() ? "" : " -- ", detail.c_str());
}

static std::vector<std::uint8_t> bytes_from_hex(const std::string& h) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<std::uint8_t> out;
    for (std::size_t i = 0; i + 1 < h.size(); i += 2) {
        const int hi = nib(h[i]), lo = nib(h[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

// The genesis block of the Monero MAINNET chain exactly as monerod 0.18.5.1
// returned it from get_block(height=0) -- the same capture the M0 node KAT
// carries. A fakechain (--regtest) daemon serves these same bytes at height 0,
// which is why regtest boots on the mainnet genesis.
static constexpr const char* MONEROD_MAINNET_GENESIS_BLOB_HEX =
    "010000000000000000000000000000000000000000000000000000000000000000000010"
    "270000013c01ff0001ffffffffffff03029b2e4c0281c0b02e7c53291a94d1d0cbff8883"
    "f8024f5142ee494ffbbd08807121017767aafcde9be00dcfd098715ebcf7f410daebc582"
    "fda69d24a28e9d0bc890d100";

// ===========================================================================
// A -- the locally assembled trust root, through the same gate
// ===========================================================================
static void suite_a() {
    std::printf("A: the local genesis blob derives the PINNED row, and only it\n");

    struct Case {
        native::levin::XmrNet net;
        native::Hash          pinned;
        const char*           name;
    };
    const Case cases[] = {
        {native::levin::XmrNet::Mainnet,  native::p2p::MAINNET_GENESIS,  "mainnet/regtest"},
        {native::levin::XmrNet::Testnet,  native::p2p::TESTNET_GENESIS,  "testnet"},
    };

    for (const Case& c : cases) {
        const std::vector<std::uint8_t> blob = rt::local_genesis_blob(c.net);
        check(!blob.empty(), std::string("A1 ") + c.name + ": a blob is assembled at all");

        native::ChainRow row;
        std::string      why;
        const bool ok = rt::genesis_row_from_blob(blob, c.pinned, row, why);
        check(ok, std::string("A2 ") + c.name +
                      ": the assembled blob re-derives the PINNED genesis id "
                      "(the id is recomputed here, never taken)",
              why);
        if (!ok) continue;
        check(row.height == 0 && row.difficulty.lo == 1 && row.cumulative_difficulty.lo == 1,
              std::string("A3 ") + c.name + ": row 0, difficulty 1, cumulative 1");
        check(row.already_generated_coins != 0 && row.block_weight != 0,
              std::string("A4 ") + c.name +
                  ": coins and weight are carried forward (the readiness gate needs both)");
        check(row.timestamp == 0 && row.major_version == 1,
              std::string("A5 ") + c.name + ": timestamp 0, major 1");
    }

    // Against a DAEMON's bytes, not only against our own hash: the assembled
    // mainnet blob must be byte-identical to what monerod returned for height 0.
    const std::vector<std::uint8_t> ours = rt::local_genesis_blob(native::levin::XmrNet::Mainnet);
    const std::vector<std::uint8_t> theirs = bytes_from_hex(MONEROD_MAINNET_GENESIS_BLOB_HEX);
    check(!theirs.empty() && ours == theirs,
          "A6 the assembled mainnet blob is byte-identical to monerod 0.18.5.1's get_block(0)");

    // One byte moved anywhere in the blob must fail the id check. Walk the
    // NONCE, because that is the only field that differs between networks and
    // therefore the only one a copy-paste error would plausibly land in.
    {
        std::vector<std::uint8_t> bad = ours;
        check(bad.size() > 38, "A7 the blob is long enough to carry a nonce at offset 35");
        if (bad.size() > 38) {
            bad[35] ^= 0x01;
            native::ChainRow row;
            std::string      why;
            check(!rt::genesis_row_from_blob(bad, native::p2p::MAINNET_GENESIS, row, why),
                  "A8 one flipped nonce byte is REFUSED by the same gate (not warned about)");
        }
    }

    // And the right blob against the WRONG network's pin is refused too: this
    // is what stops a solo node being pointed at a chain it did not mean.
    {
        native::ChainRow row;
        std::string      why;
        check(!rt::genesis_row_from_blob(ours, native::p2p::STAGENET_GENESIS, row, why),
              "A9 the mainnet blob under the stagenet pin is REFUSED");
    }

    // --- THE STAGENET FINDING, pinned so it cannot quietly go away ---------
    //
    // The construction above reproduces the mainnet and testnet pins exactly.
    // The SAME construction under stagenet's documented GENESIS_NONCE (10002)
    // does NOT reproduce STAGENET_GENESIS -- so either that nonce or that
    // pinned id is wrong. This branch does not decide which: the pinned id is a
    // live wire constant (it terminates every locator sent to a stagenet peer,
    // and the node runs against stagenet today), so changing it on the strength
    // of a local derivation would trade a checkable mismatch for an unnoticed
    // one. Solo is regtest-only and needs no stagenet blob, so the honest move
    // is to ship none and assert the gap, out loud, here.
    check(rt::genesis_nonce(native::levin::XmrNet::Stagenet) == 0,
          "A10 stagenet has NO verified local construction and is declared so (nonce 0)");
    check(rt::local_genesis_blob(native::levin::XmrNet::Stagenet).empty(),
          "A11 so it yields no blob at all -- a boot refusal, never an unverified guess");
    {
        // The evidence for A10, re-derived here rather than asserted in prose:
        // the 10002 construction really does miss the pin.
        std::vector<std::uint8_t> as_documented = ours;   // mainnet layout
        as_documented[35] = 0x12;                         // 10002 = 0x2712, LE low byte
        native::ChainRow row;
        std::string      why;
        check(!rt::genesis_row_from_blob(as_documented, native::p2p::STAGENET_GENESIS, row, why),
              "A12 (evidence) GENESIS_TX under nonce 10002 does not hash to STAGENET_GENESIS");
    }
}

// ===========================================================================
// B -- the solo boot
// ===========================================================================
static native::ChainIndexOptions regtest_options() {
    native::ChainIndexOptions o;
    o.net         = native::XmrNet::Regtest;
    o.require_pow = false;   // this suite is about the boot seam, not hashes
    return o;
}

static void suite_b() {
    std::printf("B: ChainBoot seeds row 0 with no peer, and refuses anything else\n");

    {
        native::NoPowSource pow;
        native::ChainIndex  index(regtest_options(), pow);
        rt::ChainBoot       boot(index, rt::BootMode::LocalGenesis, native::p2p::MAINNET_GENESIS,
                                 native::XmrNet::Regtest);
        check(!boot.booted(), "B1 a solo boot starts un-booted, like every other boot");

        std::string why;
        const bool  ok =
            boot.boot_from_local_genesis(rt::local_genesis_blob(native::levin::XmrNet::Mainnet),
                                         why);
        check(ok, "B2 the locally assembled blob seeds the index with NO peer contacted", why);
        check(boot.booted(), "B3 and the boot reports itself booted");
        const auto tip = index.tip();
        check(tip.has_value() && tip->height == 0, "B4 the index now has row zero");
        check(boot.stats().blobs_inspected == 1 && boot.stats().refusals == 0,
              "B5 exactly one blob was inspected and none refused");
        // Idempotent: a second call is a no-op success, not a second seed.
        std::string why2;
        check(boot.boot_from_local_genesis(
                  rt::local_genesis_blob(native::levin::XmrNet::Mainnet), why2),
              "B6 booting twice is a no-op success", why2);
        check(boot.stats().blobs_inspected == 1,
              "B7 and it inspects nothing a second time");
    }

    {
        native::NoPowSource pow;
        native::ChainIndex  index(regtest_options(), pow);
        rt::ChainBoot       boot(index, rt::BootMode::LocalGenesis, native::p2p::MAINNET_GENESIS,
                                 native::XmrNet::Regtest);
        std::string why;
        check(!boot.boot_from_local_genesis({}, why) && !why.empty(),
              "B8 an empty blob is a named refusal, never a silent un-booted node");
        check(!boot.booted(), "B9 and the node stays un-booted");
    }

    {
        // The STAGENET blob offered to a node pinned on mainnet: the gate is
        // the same one the levin path uses, so this must fail there too.
        native::NoPowSource pow;
        native::ChainIndex  index(regtest_options(), pow);
        rt::ChainBoot       boot(index, rt::BootMode::LocalGenesis, native::p2p::MAINNET_GENESIS,
                                 native::XmrNet::Regtest);
        std::string why;
        check(!boot.boot_from_local_genesis(
                  rt::local_genesis_blob(native::levin::XmrNet::Testnet), why),
              "B10 a foreign network's genesis is REFUSED by the solo path as well");
        check(boot.stats().refusals == 1, "B11 and the refusal is counted");
    }
}

// ===========================================================================
// C + D -- the verdict and the publisher, both ways round
// ===========================================================================
namespace {

struct BlockFixture {
    std::vector<std::uint8_t> blob;
    std::vector<std::uint8_t> hashing_blob;
    native::Hash              id{};
    std::uint64_t             height = 0;
    std::uint32_t             nonce  = 0;
    std::size_t               nonce_offset = 0;
};

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
    f.nonce_offset = pb.header_size - 4;
    const std::vector<std::uint8_t> want = bytes_from_hex(native::golden_c2a::BLOCKS[0].id_hex);
    return want.size() == f.id.size() &&
           std::equal(want.begin(), want.end(), f.id.begin());
}

} // namespace

static void suite_cd() {
    std::printf("C/D: reached_network() is untouched; solo books on our own index, opt-in only\n");

    // --- C: the verdict shape, independent of any relay -------------------
    {
        native::BlockRelayVerdict v;
        check(!v.reached_network() && !v.landed_own_chain(),
              "C1 a default verdict claims neither the wire nor our own chain");
        v.own_index_attempted = true;
        v.own_index_accepted  = true;
        check(!v.reached_network(),
              "C2 our own index accepting a block does NOT make reached_network() true");
        check(v.landed_own_chain(), "C3 but landed_own_chain() says what did happen");
        v.p2p_peers_sent = 1;
        check(v.reached_network() && v.landed_own_chain(),
              "C4 the two facts coexist without either standing in for the other");
    }

    BlockFixture f;
    if (!load_fixture(f)) {
        check(false, "D0 the captured block fixture parses and re-identifies");
        return;
    }
    check(true, "D0 the captured block fixture parses and re-identifies");

    auto lookup = [&f](std::uint32_t, std::uint32_t, submit::BlockCandidate& out) {
        out.template_id     = 1;
        out.height          = f.height;
        out.full_blob       = f.blob;
        out.hashing_blob    = f.hashing_blob;
        out.nonce_offset    = f.nonce_offset;
        out.expected_reward = 600000000000ull;
        return true;
    };

    // --- D1: DEFAULT (solo OFF) is #1662 to the letter ---------------------
    {
        native::fakes::FakeBroadcastPort port;    // zero state_normal peers
        native::fakes::FakeMinerDataSource bodies;
        native::fakes::FakeChain           chain; // accept_own_block = true
        native::relay::RelayConfig rcfg;
        rcfg.policy.order                 = native::ArmOrder::P2pOnly;
        rcfg.policy.include_all_tx_bodies = true;
        native::relay::LevinBlockRelay relay(port, native::relay::DaemonSubmitSink{}, &bodies,
                                             &chain, rcfg);
        submit::FoundBlockQueue found;
        o2::P2pBlockPublisher   pub(relay, found, lookup);
        pub.enable_network_relay(true);
        check(!pub.solo_own_index_enabled(), "D1 solo is OFF in a freshly built publisher");

        pub.submit_network_block(1, f.nonce, 0);
        check(found.pushed() == 0,
              "D2 zero peers -> NO FOUND event, even though our own index took the block",
              pub.last_error());
        check(pub.failed() == 1 && pub.relayed() == 0 && pub.solo_landed() == 0,
              "D3 it is counted as reached-nobody, exactly as before this branch");
        check(!chain.own_blocks.empty(),
              "D4 (and the own-index push DID happen -- D2 is a booking decision, not a "
              "missing write)");
    }

    // --- D2: SOLO ON, own index accepts -----------------------------------
    {
        native::fakes::FakeBroadcastPort port;
        native::fakes::FakeMinerDataSource bodies;
        native::fakes::FakeChain           chain;
        native::relay::RelayConfig rcfg;
        rcfg.policy.order                 = native::ArmOrder::P2pOnly;
        rcfg.policy.include_all_tx_bodies = true;
        native::relay::LevinBlockRelay relay(port, native::relay::DaemonSubmitSink{}, &bodies,
                                             &chain, rcfg);
        submit::FoundBlockQueue found;
        o2::P2pBlockPublisher   pub(relay, found, lookup);
        pub.enable_network_relay(true);
        pub.enable_solo_own_index(true);

        pub.submit_network_block(1, f.nonce, 0);
        check(found.pushed() == 1,
              "D5 SOLO: one FOUND event for a block only our own chain index received",
              pub.last_error());
        check(pub.solo_landed() == 1 && pub.relayed() == 0,
              "D6 counted in solo_landed(), NOT in relayed() -- the two never add up");
        check(pub.failed() == 0, "D7 and it is not also counted as a failure");
        check(pub.last_error().find("SOLO") != std::string::npos,
              "D8 the status line still says the block reached no peer", pub.last_error());
        submit::FoundBlockEvent ev;
        const bool got = found.pop(ev);
        check(got && ev.block_id == f.id,
              "D9 the FOUND event carries OUR id, off the bytes the gate verified");
        check(got && ev.header_check == submit::HeaderCheck::NotRun && ev.rpc_ms == 0.0,
              "D10 with header_check NotRun and no RPC: nothing confirmed the height for us");
    }

    // --- D3: SOLO ON, own index REFUSES -> still nothing is booked ---------
    {
        native::fakes::FakeBroadcastPort port;
        native::fakes::FakeMinerDataSource bodies;
        native::fakes::FakeChain           chain;
        chain.accept_own_block = false;
        chain.reject_reason    = "fake index refuses";
        native::relay::RelayConfig rcfg;
        rcfg.policy.order                 = native::ArmOrder::P2pOnly;
        rcfg.policy.include_all_tx_bodies = true;
        native::relay::LevinBlockRelay relay(port, native::relay::DaemonSubmitSink{}, &bodies,
                                             &chain, rcfg);
        submit::FoundBlockQueue found;
        o2::P2pBlockPublisher   pub(relay, found, lookup);
        pub.enable_network_relay(true);
        pub.enable_solo_own_index(true);

        pub.submit_network_block(1, f.nonce, 0);
        check(found.pushed() == 0 && pub.solo_landed() == 0 && pub.failed() == 1,
              "D11 SOLO with an index that said NO books nothing -- solo relaxes WHO must "
              "accept, never WHETHER anybody did",
              pub.last_error());
    }

    // --- D4: solo does not weaken the RandomX gate -------------------------
    {
        native::fakes::FakeBroadcastPort port;
        native::fakes::FakeMinerDataSource bodies;
        native::fakes::FakeChain           chain;
        native::relay::RelayConfig rcfg;
        rcfg.policy.order                 = native::ArmOrder::P2pOnly;
        rcfg.policy.include_all_tx_bodies = true;
        native::relay::LevinBlockRelay relay(port, native::relay::DaemonSubmitSink{}, &bodies,
                                             &chain, rcfg);
        submit::FoundBlockQueue found;
        o2::P2pBlockPublisher   pub(relay, found, lookup);
        pub.enable_solo_own_index(true);   // solo on, network relay still OFF
        pub.submit_network_block(1, f.nonce, 0);
        check(pub.refused() == 1 && found.pushed() == 0 && pub.solo_landed() == 0,
              "D12 solo does not open the fail-closed RandomX gate: a disabled relay still "
              "REFUSES and books nothing",
              pub.last_error());
        check(chain.own_blocks.empty(),
              "D13 and a refusal never reaches our own index either");
    }
}

// ===========================================================================
// E -- the refusals, as pure functions
// ===========================================================================
static XmrNodeConfig solo_config() {
    XmrNodeConfig c;
    c.network         = MoneroNetwork::Regtest;
    c.coinbase        = CoinbaseMode::V37Settlement;
    c.template_source = TemplateSourceMode::Native;
    c.arm_order       = ArmOrderMode::P2PFirst;
    c.native_solo     = true;
    return c;
}

static void suite_e() {
    std::printf("E: the defaults, and what --native-solo refuses\n");

    {
        const XmrNodeConfig def;
        check(!def.native_solo, "E1 --native-solo is OFF in a default config");
        check(!def.mine_enabled, "E2 --mine is OFF in a default config");
        check(def.arm_order == ArmOrderMode::DaemonFirst,
              "E3 and the arm order still defaults to daemon-first");
        check(solo_refusal(def).empty(),
              "E4 solo_refusal() has nothing to say about a config that did not ask for solo");
    }

    {
        const XmrNodeConfig c = solo_config();
        check(solo_refusal(c).empty(), "E5 regtest + p2p-first + no peers + no anchor is allowed",
              solo_refusal(c));
        check(arm_order_refusal(c).empty(),
              "E6 arm_order_refusal() drops its one-peer requirement for a solo run",
              arm_order_refusal(c));
    }

    {
        XmrNodeConfig c = solo_config();
        c.native_solo = false;
        check(!arm_order_refusal(c).empty(),
              "E7 and KEEPS it for everybody else: p2p-first with no peer is still refused");
    }

    {
        XmrNodeConfig c = solo_config();
        c.network = MoneroNetwork::Mainnet;
        check(!solo_refusal(c).empty(), "E8 solo on MAINNET is refused");
        c.network = MoneroNetwork::Stagenet;
        check(!solo_refusal(c).empty(), "E9 solo on stagenet is refused (a silent private fork)");
        c.network = MoneroNetwork::Testnet;
        check(!solo_refusal(c).empty(), "E10 solo on testnet is refused for the same reason");
    }

    {
        XmrNodeConfig c = solo_config();
        c.arm_order = ArmOrderMode::DaemonFirst;
        check(!solo_refusal(c).empty(), "E11 solo under daemon-first is refused");
    }

    {
        XmrNodeConfig c = solo_config();
        c.native_connect.push_back("127.0.0.1:18080");
        check(!solo_refusal(c).empty(),
              "E12 solo WITH a pinned peer is refused rather than silently ignoring one of them");
    }

    {
        XmrNodeConfig c = solo_config();
        c.native_anchor_path = "/tmp/anchor.bin";
        check(!solo_refusal(c).empty(), "E13 solo WITH an anchor is refused: pick one trust root");
    }
}

// ===========================================================================
int main() {
    std::printf("== v37_xmr_daemonless_selfmine_kat: the peerless, daemonless find path ==\n");
    suite_a();
    suite_b();
    suite_cd();
    suite_e();
    std::printf("== %s: %d passed, %d failed ==\n", g_fail ? "FAIL" : "OK", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
