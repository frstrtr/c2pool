// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_mainnet_readiness_kat.cpp
//
// THE POOL BINARY'S OWN NATIVE-NODE PLUMBING, pinned where it was missing.
//
// c2pool-v37-xmr runs the embedded daemonless Monero node through
// NativeTemplateBackend. Three things the node itself has always been able to
// do were unreachable from the pool binary, and every one of them was
// unreachable in the same way: the knob existed on the node, the standalone
// xmr_native_node tool exposed it, and the pool binary's argv loop simply had
// no arm for it. Nothing failed; the flag was not a flag, and the default
// happened instead.
//
//   1. GATE 4's window (--anchor-confirm-peers / -peer-ms / -timeout-ms). The
//      gate is not optional and these only WIDEN it, which is exactly why an
//      operator on a slow or filtered mainnet link needs them: without them a
//      peer that answers in fifteen seconds is indistinguishable from a
//      fabricated anchor, and the refusal reads as a broken build.
//   2. --native-seeds / --seeds. p2p::dns_seeds() has existed and been pinned
//      by the locator KAT since C1c and was CALLED BY NOBODY: a mainnet node
//      with no --native-connect had six compiled-in IP addresses and no way to
//      reach the live seed A-records monerod itself bootstraps from.
//   3. --native-snapshot-path. chain/xmr_chain_index.hpp has carried
//      save_snapshot()/load_snapshot() since C2 and nothing ever wrote one to
//      disk, so every restart re-walked the chain from the anchor.
//
// WHAT IS PINNED HERE is the plumbing and its fail-closed edges, never the
// components: the chain index's own snapshot codec is xmr_native_chain_index_kat's,
// and gate 4's judgement is xmr_native_anchor_gate4_kat's. This file asserts
// that the pool binary's PARSE and its FORWARD are the same code the node runs
// on -- which is the property whose absence created all three gaps.
//
//   A  the flags parse, in the one function that owns them, and a malformed
//      one REFUSES rather than defaulting
//   B  the forward: every parsed knob arrives in NativeTemplateConfig, the
//      defaults are byte-equal to the node's own, and NO configuration --
//      including a hand-zeroed one -- can disarm gate 4
//   C  seeds: --seeds sets use_seeds, mainnet has the four DNS seed hosts and
//      the two test networks correctly have none, and seeds alone satisfy the
//      p2p-first address-source precondition
//   D  the snapshot's DISK half: save -> envelope -> file -> read -> decode ->
//      load round-trips an index to the same state, and every corruption
//      (short, tampered, foreign network, foreign anchor, wrong magic, wrong
//      version, lying length) is REFUSED so the node stays on its anchor boot
//   E  gate 4 is STILL fail-closed through the pool binary's config: a
//      tampered anchor id cannot be confirmed by the genuine block, the
//      forwarded peer bound is the bound that is enforced, and the deadline
//      refuses rather than trusting
//
// No sockets, no daemon, no RandomX: the ordinary ctest lane on BOTH CI legs,
// which is also why it is listed in both build.yml `--target` lists -- a
// registered-but-unbuilt target reads as "***Not Run" and fails ctest with
// exit 8 (the #1539 lesson).
// ===========================================================================
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <optional>
#include <fstream>
#include <string>
#include <vector>

#include "c2pool/v37/xmr/xmr_native_template_backend.hpp"
#include "c2pool/v37/xmr/xmr_node_config.hpp"
#include "impl/xmr/native/anchor/xmr_anchor_load.hpp"
#include "impl/xmr/native/chain/xmr_chain_index.hpp"
#include "impl/xmr/native/contracts/fakes/fake_fetcher.hpp"
#include "impl/xmr/native/node/xmr_anchor_confirm.hpp"
#include "impl/xmr/native/node/xmr_chain_snapshot_store.hpp"
#include "impl/xmr/native/p2p/chain_seeds.hpp"

namespace cfgns  = c2pool::v37n::xmr;
namespace o2     = c2pool::v37n::xmr::o2;
namespace native = c2pool::xmr::native;
namespace rt     = c2pool::xmr::native::rt;
namespace p2p    = c2pool::xmr::native::p2p;

using cfgns::ArmOrderMode;
using cfgns::MoneroNetwork;
using cfgns::TemplateSourceMode;
using cfgns::XmrNodeConfig;
using native::ChainIndex;
using native::ChainIndexOptions;
using native::ChainRow;
using native::DifficultyRow;
using native::Hash;
using native::PeerRef;
using native::PeerSyncData;
using native::U128;
using rt::AnchorConfirmConfig;
using rt::AnchorConfirmDriver;
using rt::AnchorConfirmState;
using rt::AnchorNetworkConfirm;

namespace {

int g_pass = 0;
int g_fail = 0;

void check(bool ok, const std::string& what) {
    if (ok) { ++g_pass; return; }
    ++g_fail;
    std::printf("  FAIL: %s\n", what.c_str());
}

// ---------------------------------------------------------------------------
// argv helper: run the pool binary's OWN flag function over a whole command
// line, the way main's loop does. Returns the refusal, or "" when every token
// was consumed by a native-node flag.
//
// It deliberately calls apply_native_node_flag rather than re-implementing the
// dispatch: a test that re-spelled the parse would go on passing after the
// parse changed, which is the failure mode this whole file exists to close.
// ---------------------------------------------------------------------------
std::string parse_all(XmrNodeConfig& c, const std::vector<std::string>& args,
                      int* consumed_out = nullptr) {
    std::vector<const char*> argv;
    argv.reserve(args.size());
    for (const std::string& a : args) argv.push_back(a.c_str());
    const int argc = static_cast<int>(argv.size());

    int consumed = 0;
    for (int i = 0; i < argc; ++i) {
        std::string err;
        const int used = cfgns::apply_native_node_flag(c, argc, argv.data(), i, err);
        if (used < 0) { if (consumed_out) *consumed_out = consumed; return err; }
        if (used == 0) continue;            // not one of ours; main handles it
        consumed += used;
        i += used - 1;
    }
    if (consumed_out) *consumed_out = consumed;
    return {};
}

// A config that is otherwise a legitimate p2p-first native run, so that a
// suite can change one thing and attribute the result to it.
XmrNodeConfig base_config() {
    XmrNodeConfig c;
    c.network         = MoneroNetwork::Mainnet;
    c.template_source = TemplateSourceMode::Native;
    c.arm_order       = ArmOrderMode::P2PFirst;
    // p2p-first is only coherent with option B: option As block IS monerods
    // get_block_template, so a daemonless find of it is a contradiction and
    // arm_order_refusal() says so. Set here so suite C attributes its verdict
    // to the ADDRESS SOURCE and to nothing else.
    c.coinbase        = cfgns::CoinbaseMode::V37Settlement;
    return c;
}

// =============================================================================
// A. the flags parse, and a malformed one refuses
// =============================================================================
void suite_a_parse() {
    std::printf("A. flag parsing\n");

    // A1 -- absent flags change nothing. The defaults are the node's, and this
    // is the check that keeps "defaults unchanged when the flags are absent"
    // from being a claim in a commit message.
    {
        XmrNodeConfig c = base_config();
        const std::string err = parse_all(c, {"--network", "mainnet", "--rpc-port", "18081"});
        check(err.empty(), "A1: an argv with no native-node flag produced a refusal: " + err);
        const AnchorConfirmConfig d;
        check(c.anchor_confirm_peers == d.peers,
              "A1: default anchor_confirm_peers drifted from the node's");
        check(c.anchor_confirm_timeout_ms == d.timeout_ms,
              "A1: default anchor_confirm_timeout_ms drifted from the node's");
        check(c.anchor_confirm_peer_ms == d.per_peer_ms,
              "A1: default anchor_confirm_peer_ms drifted from the node's");
        check(!c.native_use_seeds, "A1: seeds default to ON");
        check(c.native_snapshot_path.empty(), "A1: a snapshot path appeared from nowhere");
    }

    // A2 -- the three gate 4 knobs land, and the consumed count proves each one
    // ate its value rather than leaving it for main to misread as a flag.
    {
        XmrNodeConfig c = base_config();
        int consumed = 0;
        const std::string err = parse_all(c, {"--anchor-confirm-peers", "9",
                                              "--anchor-confirm-peer-ms", "20000",
                                              "--anchor-confirm-timeout-ms", "150000"},
                                          &consumed);
        check(err.empty(), "A2: refused a well-formed gate 4 window: " + err);
        check(consumed == 6, "A2: the three knobs consumed " + std::to_string(consumed)
                                 + " tokens, expected 6");
        check(c.anchor_confirm_peers == 9, "A2: --anchor-confirm-peers did not land");
        check(c.anchor_confirm_peer_ms == 20000, "A2: --anchor-confirm-peer-ms did not land");
        check(c.anchor_confirm_timeout_ms == 150000,
              "A2: --anchor-confirm-timeout-ms did not land");
    }

    // A3 -- seeds, under both spellings, plus the snapshot pair.
    {
        XmrNodeConfig c = base_config();
        const std::string err = parse_all(c, {"--seeds", "--native-snapshot-path",
                                              "/var/lib/c2pool/xmr.snap",
                                              "--native-snapshot-every", "60"});
        check(err.empty(), "A3: refused a well-formed seeds/snapshot line: " + err);
        check(c.native_use_seeds, "A3: --seeds did not set use_seeds");
        check(c.native_snapshot_path == "/var/lib/c2pool/xmr.snap",
              "A3: --native-snapshot-path did not land");
        check(c.native_snapshot_every_s == 60, "A3: --native-snapshot-every did not land");

        XmrNodeConfig c2 = base_config();
        check(parse_all(c2, {"--native-seeds"}).empty(), "A3: --native-seeds refused");
        check(c2.native_use_seeds, "A3: --native-seeds did not set use_seeds");
    }

    // A4 -- --native-connect still works, and works ALONGSIDE seeds. The whole
    // point of the change is that the two are alternatives, not a replacement.
    {
        XmrNodeConfig c = base_config();
        const std::string err = parse_all(c, {"--native-connect", "203.0.113.7:18080",
                                              "--native-connect", "198.51.100.9:18080",
                                              "--seeds"});
        check(err.empty(), "A4: refused connect+seeds together: " + err);
        check(c.native_connect.size() == 2, "A4: --native-connect stopped accumulating");
        check(c.native_connect[0] == "203.0.113.7:18080" &&
              c.native_connect[1] == "198.51.100.9:18080",
              "A4: --native-connect values are wrong or reordered");
        check(c.native_use_seeds, "A4: --seeds was lost next to --native-connect");
    }

    // A5 -- malformed. Each of these is a REFUSAL, never a silent default: a
    // value flag typed last on the line, a number that is not one, and the
    // three zeros that would be the switch that turns gate 4 off.
    {
        struct Case { std::vector<std::string> argv; const char* what; };
        const Case cases[] = {
            {{"--anchor-confirm-peers"},                "a value flag with no value"},
            {{"--anchor-confirm-peers", "banana"},      "a non-numeric peer count"},
            {{"--anchor-confirm-peers", "0"},           "zero peers (gate 4 asking nobody)"},
            {{"--anchor-confirm-peer-ms", "0"},         "a zero per-peer turn"},
            {{"--anchor-confirm-timeout-ms", "0"},      "a zero gate deadline"},
            {{"--anchor-confirm-timeout-ms", "x9"},     "a non-numeric deadline"},
            {{"--native-snapshot-path"},                "a snapshot path with no path"},
            {{"--native-snapshot-path", ""},            "an empty snapshot path"},
            {{"--native-connect"},                      "a connect with no address"},
            {{"--native-snapshot-every", "soon"},       "a non-numeric cadence"},
        };
        for (const Case& k : cases) {
            XmrNodeConfig c = base_config();
            const std::string err = parse_all(c, k.argv);
            check(!err.empty(), std::string("A5: ") + k.what + " was ACCEPTED");
        }
    }

    // A6 -- a refused zero leaves the config untouched, so a partially parsed
    // line cannot hand main a half-configured gate.
    {
        XmrNodeConfig c = base_config();
        const std::string err = parse_all(c, {"--anchor-confirm-peers", "0"});
        check(!err.empty(), "A6: zero peers accepted");
        check(c.anchor_confirm_peers == AnchorConfirmConfig{}.peers,
              "A6: a refused --anchor-confirm-peers still mutated the config");
    }
}

// =============================================================================
// B. the forward -- every knob arrives at the node
// =============================================================================
void suite_b_forward() {
    std::printf("B. forward into NativeTemplateConfig\n");

    // B1 -- an untouched config forwards the NODE's defaults, field for field.
    // This is the check that keeps the two default sets from drifting apart
    // silently, which is how a "default" becomes two different numbers.
    {
        const o2::NativeTemplateConfig n = o2::native_template_config_of(base_config());
        const AnchorConfirmConfig d;
        check(n.anchor_confirm.peers == d.peers,
              "B1: forwarded peers default differs from AnchorConfirmConfig's");
        check(n.anchor_confirm.timeout_ms == d.timeout_ms,
              "B1: forwarded timeout default differs from AnchorConfirmConfig's");
        check(n.anchor_confirm.per_peer_ms == d.per_peer_ms,
              "B1: forwarded per-peer default differs from AnchorConfirmConfig's");
        check(!n.use_seeds, "B1: use_seeds defaults ON");
        check(n.snapshot_path.empty(), "B1: a snapshot path defaults to non-empty");
    }

    // B2 -- parsed knobs arrive. Parse and forward are run back to back here
    // exactly as main runs them.
    {
        XmrNodeConfig c = base_config();
        const std::string err = parse_all(c, {"--anchor-confirm-peers", "7",
                                              "--anchor-confirm-peer-ms", "25000",
                                              "--anchor-confirm-timeout-ms", "180000",
                                              "--seeds",
                                              "--native-snapshot-path", "/tmp/x.snap",
                                              "--native-snapshot-every", "45",
                                              "--native-connect", "203.0.113.7:18080"});
        check(err.empty(), "B2: the mainnet-shaped command line was refused: " + err);
        const o2::NativeTemplateConfig n = o2::native_template_config_of(c);
        check(n.anchor_confirm.peers == 7,       "B2: peers did not reach the node config");
        check(n.anchor_confirm.per_peer_ms == 25000, "B2: per-peer ms did not reach it");
        check(n.anchor_confirm.timeout_ms == 180000, "B2: timeout ms did not reach it");
        check(n.use_seeds,                       "B2: use_seeds did not reach it");
        check(n.snapshot_path == "/tmp/x.snap",  "B2: snapshot path did not reach it");
        check(n.snapshot_every_s == 45,          "B2: snapshot cadence did not reach it");
        check(n.connect.size() == 1 && n.connect[0] == "203.0.113.7:18080",
              "B2: --native-connect stopped reaching the node config");
        check(n.net == rt::NativeNet::Mainnet, "B2: the mainnet mapping is wrong");
    }

    // B3 -- THE GATE CANNOT BE DISARMED. The flag parser refuses a zero, but a
    // programmatic caller can build any struct it likes, so the forward is the
    // second guard and this is the assertion that it holds. Every one of these
    // must come out sane(), which is what AnchorConfirmDriver requires to run
    // the gate at all.
    {
        struct Case { std::uint32_t peers; std::uint64_t timeout; std::uint64_t per_peer;
                      const char* what; };
        const Case cases[] = {
            {0, 60000, 12000, "zero peers"},
            {4, 0,     12000, "zero deadline"},
            {4, 60000, 0,     "zero per-peer turn"},
            {0, 0,     0,     "everything zeroed"},
        };
        for (const Case& k : cases) {
            XmrNodeConfig c = base_config();
            c.anchor_confirm_peers      = k.peers;
            c.anchor_confirm_timeout_ms = k.timeout;
            c.anchor_confirm_peer_ms    = k.per_peer;
            const o2::NativeTemplateConfig n = o2::native_template_config_of(c);
            check(n.anchor_confirm.sane(),
                  std::string("B3: ") + k.what + " forwarded an INSANE confirm config "
                  "(gate 4 would fall back to defaults or not run)");
            check(n.anchor_confirm.peers >= 1,
                  std::string("B3: ") + k.what + " forwarded a zero peer bound");
        }
    }

    // B4 -- the anchor boot mode still follows the bundle path, and the
    // snapshot is NOT a boot mode of its own. A snapshot path with no anchor
    // must not turn a genesis boot into an anchored one.
    {
        XmrNodeConfig c = base_config();
        check(parse_all(c, {"--native-snapshot-path", "/tmp/y.snap"}).empty(),
              "B4: snapshot path refused");
        const o2::NativeTemplateConfig n = o2::native_template_config_of(c);
        check(n.boot == rt::BootMode::Genesis,
              "B4: a snapshot path silently promoted the boot to Anchor");

        XmrNodeConfig c2 = base_config();
        check(parse_all(c2, {"--native-anchor", "/tmp/a.inc",
                             "--native-snapshot-path", "/tmp/y.snap"}).empty(),
              "B4: anchor+snapshot refused");
        const o2::NativeTemplateConfig n2 = o2::native_template_config_of(c2);
        check(n2.boot == rt::BootMode::Anchor, "B4: --native-anchor no longer selects Anchor");
        check(n2.anchor_path == "/tmp/a.inc",  "B4: the anchor path did not reach the node");
    }

    // B5 -- p2p-first still pins the daemon fallback OFF whatever else was
    // asked for. The new flags must not have weakened the daemonless claim.
    {
        XmrNodeConfig c = base_config();
        check(parse_all(c, {"--native-template-fallback", "on", "--seeds"}).empty(),
              "B5: fallback+seeds refused");
        const o2::NativeTemplateConfig n = o2::native_template_config_of(c);
        check(!n.fallback, "B5: p2p-first forwarded fallback ON");

        XmrNodeConfig d = base_config();
        d.arm_order = ArmOrderMode::DaemonFirst;
        check(parse_all(d, {"--native-template-fallback", "off"}).empty(),
              "B5: daemon-first fallback off refused");
        check(!o2::native_template_config_of(d).fallback,
              "B5: daemon-first ignored an explicit fallback off");
    }
}

// =============================================================================
// C. seeds
// =============================================================================
void suite_c_seeds() {
    std::printf("C. mainnet seed discovery\n");

    // C1 -- the mainnet DNS seed set is monerod's, and the two test networks
    // correctly have none (net_node.h guards the list with `if MAINNET`).
    {
        const std::vector<p2p::DnsSeed> m = p2p::dns_seeds(p2p::XmrNet::Mainnet);
        check(m.size() == 4, "C1: mainnet has " + std::to_string(m.size())
                                 + " DNS seed hosts, expected 4");
        const char* want[] = {"seeds.moneroseeds.se", "seeds.moneroseeds.ae.org",
                              "seeds.moneroseeds.ch", "seeds.moneroseeds.li"};
        for (const char* w : want) {
            bool found = false;
            for (const p2p::DnsSeed& s : m) if (s.host == w) found = true;
            check(found, std::string("C1: mainnet DNS seed ") + w + " is missing");
        }
        for (const p2p::DnsSeed& s : m)
            check(s.port == 18080, "C1: a mainnet DNS seed is not on 18080");
        check(p2p::dns_seeds(p2p::XmrNet::Testnet).empty(),  "C1: testnet grew DNS seeds");
        check(p2p::dns_seeds(p2p::XmrNet::Stagenet).empty(), "C1: stagenet grew DNS seeds");
    }

    // C2 -- the IP seeds are the fallback when DNS answers nothing, so they
    // have to exist on every network. Mainnet carries one host the test
    // networks do not.
    {
        check(p2p::ip_seeds(p2p::XmrNet::Mainnet).size() == 6,  "C2: mainnet IP seed count changed");
        check(p2p::ip_seeds(p2p::XmrNet::Testnet).size() == 5,  "C2: testnet IP seed count changed");
        check(p2p::ip_seeds(p2p::XmrNet::Stagenet).size() == 5, "C2: stagenet IP seed count changed");
        for (const p2p::IpSeed& s : p2p::ip_seeds(p2p::XmrNet::Mainnet))
            check(s.port == 18080, "C2: a mainnet IP seed is not on 18080");
    }

    // C3 -- seeds are an ADDRESS SOURCE for the p2p-first precondition. Before
    // the forward, --native-connect was the only one and an operator who asked
    // for seeds got a refusal naming a flag they had deliberately not used.
    {
        XmrNodeConfig none = base_config();
        check(!cfgns::arm_order_refusal(none).empty(),
              "C3: p2p-first with NO address source was allowed");

        XmrNodeConfig seeds = base_config();
        check(parse_all(seeds, {"--seeds"}).empty(), "C3: --seeds refused");
        check(cfgns::arm_order_refusal(seeds).empty(),
              "C3: p2p-first with --seeds was refused: " + cfgns::arm_order_refusal(seeds));

        XmrNodeConfig pinned = base_config();
        check(parse_all(pinned, {"--native-connect", "203.0.113.7:18080"}).empty(),
              "C3: --native-connect refused");
        check(cfgns::arm_order_refusal(pinned).empty(),
              "C3: p2p-first with a pinned peer was refused");
    }

    // C4 -- the peer key a resolved seed becomes is the key the ban list and
    // the dial plan use. A shape change here would make seeded addresses
    // unbannable and undiallable at once.
    {
        check(p2p::make_peer_key("203.0.113.7", 18080) == "203.0.113.7:18080",
              "C4: the peer key format changed");
        std::string ip; std::uint16_t port = 0;
        check(p2p::split_peer_key("203.0.113.7:18080", ip, port) && ip == "203.0.113.7"
                  && port == 18080,
              "C4: a made peer key does not split back");
    }

    // C5 -- the table the seed round SELECTS. C1/C2 pin what each network
    // ships and B2 pins that --network mainnet reaches the node as
    // NativeNet::Mainnet; neither says which table a NativeNet::Mainnet node
    // actually reads. resolve_nets() is that link, and the half that matters is
    // `wire` (the levin net), NOT `consensus`: NativeNode passes nets_.wire to
    // dns_seeds(), and the peer pool it builds seeds its store from
    // ip_seeds(cfg_.net), which is the same wire net. Without this check a
    // mainnet pool could have been seeded off a test network table with every
    // other check in this file still green.
    //
    // The comparisons are whole-vector and length-guarded on purpose: a check
    // that reads .front() of a table this very check suspects of being empty
    // would crash instead of failing, and a KAT that segfaults on a red says
    // nothing about what broke.
    {
        const auto mainnet_sel = rt::resolve_nets(rt::NativeNet::Mainnet).wire;
        check(mainnet_sel == p2p::XmrNet::Mainnet,
              "C5: --net mainnet does not select the mainnet seed table");

        const std::vector<p2p::DnsSeed> sel_dns  = p2p::dns_seeds(mainnet_sel);
        const std::vector<p2p::DnsSeed> main_dns = p2p::dns_seeds(p2p::XmrNet::Mainnet);
        check(sel_dns.size() == 4,
              "C5: the table --net mainnet selects has " + std::to_string(sel_dns.size())
                  + " DNS seeds, expected the mainnet 4");
        bool dns_same = (sel_dns.size() == main_dns.size());
        for (std::size_t i = 0; dns_same && i < sel_dns.size(); ++i)
            dns_same = (sel_dns[i].host == main_dns[i].host && sel_dns[i].port == main_dns[i].port);
        check(dns_same, "C5: the selected DNS seed table is not the mainnet one");

        const std::vector<p2p::IpSeed> sel_ip  = p2p::ip_seeds(mainnet_sel);
        const std::vector<p2p::IpSeed> main_ip = p2p::ip_seeds(p2p::XmrNet::Mainnet);
        bool ip_same = (sel_ip.size() == main_ip.size());
        for (std::size_t i = 0; ip_same && i < sel_ip.size(); ++i)
            ip_same = (sel_ip[i].ip == main_ip[i].ip && sel_ip[i].port == main_ip[i].port);
        check(ip_same, "C5: the selected IP seed table is not the mainnet one");

        // The two public test networks select their own (DNS-seedless) tables.
        check(p2p::dns_seeds(rt::resolve_nets(rt::NativeNet::Stagenet).wire).empty(),
              "C5: stagenet selects a DNS seed table");
        check(p2p::dns_seeds(rt::resolve_nets(rt::NativeNet::Testnet).wire).empty(),
              "C5: testnet selects a DNS seed table");

        // REGTEST shares the MAINNET wire net (same genesis id), so a regtest
        // rig that asked for seeds would dial the PUBLIC mainnet seed hosts.
        // That is the standing reason --seeds is opt-in and OFF by default
        // (A1), and it is pinned here so the default cannot be flipped without
        // this check failing.
        check(rt::resolve_nets(rt::NativeNet::Regtest).wire == p2p::XmrNet::Mainnet,
              "C5: the regtest wire net changed -- re-check the seed default");
        check(!base_config().native_use_seeds,
              "C5: seeds are no longer opt-in, and regtest would dial mainnet seeds");
    }
}

// =============================================================================
// D. the snapshot's disk half
// =============================================================================

// A PoW source that answers Accept without hashing: this suite is about bytes
// on disk, and a real verifier here would only make the test slow.
class AcceptPow final : public native::IPowSource {
public:
    bool prefetch(const Hash&, const std::optional<Hash>&) override { return true; }
    bool seed_resident(const Hash&) const override { return true; }
    native::PowVerdict verify(const std::uint8_t*, std::size_t, const Hash&, const U128&,
                              Hash&) override {
        return native::PowVerdict::Accept;
    }
    native::RandomXMode mode() const override { return native::RandomXMode::LightInterpreter; }
};

Hash fake_hash(std::uint8_t seed) {
    Hash h{};
    for (std::size_t i = 0; i < h.size(); ++i)
        h[i] = static_cast<std::uint8_t>(seed + i * 7u);
    return h;
}

// The shape a node has moments after an anchor boot: one row and the live
// windows. That is precisely the restart this feature is for -- and, per
// save_snapshot()'s own comment, the depth-0 case, so it is also the one whose
// disk round-trip has to be exact.
ChainRow anchor_shaped_row() {
    ChainRow row;
    row.height                  = 2204000;
    row.id                      = fake_hash(0x11);
    row.prev_id                 = fake_hash(0x22);
    row.timestamp               = 1788965550;
    row.major_version           = 16;
    row.minor_version           = 16;
    row.block_weight            = 3000;
    row.long_term_weight        = 3000;
    row.difficulty              = U128{500000u};
    row.cumulative_difficulty   = U128{123456789u};
    row.already_generated_coins = 18000000000000000000ull;
    row.pow_verified            = true;
    return row;
}

void seed_like_boot(ChainIndex& idx, const ChainRow& row) {
    idx.seed_direct(row,
                    {DifficultyRow{row.timestamp, row.cumulative_difficulty}},
                    {row.block_weight},
                    {row.long_term_weight},
                    {row.timestamp},
                    {{2202000, fake_hash(0x33)}});
}

rt::SnapshotKey key_for(native::XmrNet net, const ChainRow& row) {
    rt::SnapshotKey k;
    k.net           = static_cast<std::uint64_t>(net);
    k.anchor_height = row.height;
    k.anchor_id     = row.id;
    return k;
}

void suite_d_snapshot() {
    std::printf("D. snapshot persistence (disk half)\n");

    const ChainRow row = anchor_shaped_row();
    const rt::SnapshotKey key = key_for(native::XmrNet::Mainnet, row);

    std::error_code ec;
    const std::filesystem::path dir =
        std::filesystem::temp_directory_path(ec) / "c2pool_xmr_mainnet_readiness_kat";
    std::filesystem::remove_all(dir, ec);
    const std::string path = (dir / "nested" / "xmr.snap").string();

    // D1 -- an ABSENT file is not an error, it is the first run. The node's
    // only correct response is to carry on from the anchor, so the reader has
    // to say "no" without saying "stop".
    {
        std::vector<std::uint8_t> got;
        std::string why;
        check(!rt::read_snapshot_file(path, got, why),
              "D1: reading a non-existent snapshot succeeded");
        check(!why.empty(), "D1: the absent-file refusal carried no reason");
    }

    // D2 -- the full round trip, through every layer the node uses:
    // save_snapshot -> encode -> write (via a temp + rename) -> read -> decode
    // -> load_snapshot, into a SEPARATE index with its own verifier.
    std::vector<std::uint8_t> file;
    {
        AcceptPow pow;
        ChainIndexOptions o;
        o.net = native::XmrNet::Mainnet;
        ChainIndex idx(o, pow);
        seed_like_boot(idx, row);

        std::vector<std::uint8_t> image;
        std::string why;
        check(idx.save_snapshot(image, why), "D2: save_snapshot refused: " + why);
        check(!image.empty(), "D2: save_snapshot produced no bytes");

        file = rt::encode_snapshot_envelope(key, image);
        check(file.size() == image.size() + 8 + 8 + 8 + 8 + 32 + 8 + 32,
              "D2: the envelope is not the documented fixed size plus the image");
        check(rt::write_snapshot_file(path, file, why), "D2: write refused: " + why);
        check(std::filesystem::exists(path), "D2: nothing landed at the snapshot path");
        check(!std::filesystem::exists(path + ".tmp"),
              "D2: the write left its temporary file behind");

        std::vector<std::uint8_t> back;
        check(rt::read_snapshot_file(path, back, why), "D2: read refused: " + why);
        check(back == file, "D2: the file did not read back byte-for-byte");

        std::vector<std::uint8_t> image2;
        check(rt::decode_snapshot_envelope(back, key, image2, why),
              "D2: decode refused its own envelope: " + why);
        check(image2 == image, "D2: the decoded image is not the saved one");

        AcceptPow pow2;
        ChainIndex restored(o, pow2);
        check(restored.load_snapshot(image2, why), "D2: load_snapshot refused: " + why);

        const auto tip_before = idx.tip();
        const auto tip_after  = restored.tip();
        check(tip_before.has_value() && tip_after.has_value(), "D2: a tip went missing");
        if (tip_before && tip_after) {
            check(tip_after->id == tip_before->id, "D2: the restored tip id differs");
            check(tip_after->height == tip_before->height,
                  "D2: the restored tip height differs");
            check(tip_after->difficulty == tip_before->difficulty,
                  "D2: the restored tip difficulty differs");
            check(tip_after->prev_id == tip_before->prev_id,
                  "D2: the restored tip prev_id differs");
        }
        check(restored.verified_frontier() == idx.verified_frontier(),
              "D2: the restored verified frontier differs");
        const auto t0 = idx.view().state().template_inputs_partial();
        const auto t1 = restored.view().state().template_inputs_partial();
        check(t1.difficulty == t0.difficulty && t1.median_weight == t0.median_weight
                  && t1.median_timestamp == t0.median_timestamp
                  && t1.already_generated_coins == t0.already_generated_coins
                  && t1.block_weight_limit == t0.block_weight_limit,
              "D2: the restored template inputs differ -- the resume is not the same node");

        // And a re-save of the restored index reproduces the same image, which
        // is what makes a restart chain (save, restart, save, restart) rather
        // than decay a little each time.
        std::vector<std::uint8_t> again;
        check(restored.save_snapshot(again, why), "D2: the restored index cannot save: " + why);
        check(again == image, "D2: a save->load->save round trip is not a fixed point");
    }

    // D3 -- every corruption is REFUSED. Each case is the same refusal to the
    // node (carry on from the anchor), and each is a different way a file on
    // disk goes wrong: a backup script, a shared volume, a half-written file,
    // a copy from the wrong host.
    {
        std::string why;
        std::vector<std::uint8_t> image;

        std::vector<std::uint8_t> shortf(40, 0);
        check(!rt::decode_snapshot_envelope(shortf, key, image, why),
              "D3: a file too short to be an envelope was accepted");

        std::vector<std::uint8_t> flipped = file;
        flipped[flipped.size() / 2] ^= 0x40;
        check(!rt::decode_snapshot_envelope(flipped, key, image, why),
              "D3: a tampered byte in the image was accepted");
        check(why.find("digest") != std::string::npos,
              "D3: the tamper refusal did not name the digest (" + why + ")");

        std::vector<std::uint8_t> chopped = file;
        chopped.resize(chopped.size() - 16);
        check(!rt::decode_snapshot_envelope(chopped, key, image, why),
              "D3: a truncated file was accepted");

        // A foreign NETWORK and a foreign ANCHOR are the two substitutions the
        // envelope exists for: the index's own image is checked only loosely
        // against these, and a file is exactly the thing that gets swapped.
        rt::SnapshotKey other_net = key;
        other_net.net = static_cast<std::uint64_t>(native::XmrNet::Stagenet);
        check(!rt::decode_snapshot_envelope(file, other_net, image, why),
              "D3: a snapshot from another network was accepted");

        rt::SnapshotKey other_anchor = key;
        other_anchor.anchor_id = fake_hash(0x99);
        check(!rt::decode_snapshot_envelope(file, other_anchor, image, why),
              "D3: a snapshot bound to another anchor id was accepted");

        rt::SnapshotKey other_height = key;
        other_height.anchor_height = key.anchor_height + 1;
        check(!rt::decode_snapshot_envelope(file, other_height, image, why),
              "D3: a snapshot bound to another anchor height was accepted");

        std::vector<std::uint8_t> bad_magic = file;
        bad_magic[0] ^= 0xff;
        check(!rt::decode_snapshot_envelope(bad_magic, key, image, why),
              "D3: a file with the wrong magic was accepted");

        std::vector<std::uint8_t> bad_version = file;
        bad_version[8] = 0x7f;
        check(!rt::decode_snapshot_envelope(bad_version, key, image, why),
              "D3: a file with an unknown version was accepted");

        // A LYING LENGTH is the one that matters most: the digest is checked
        // before any length inside the file is trusted, so a corrupt header
        // cannot steer the reader into a huge allocation or a bad read.
        std::vector<std::uint8_t> lying = file;
        for (int i = 0; i < 8; ++i) lying[64 + static_cast<std::size_t>(i)] = 0xff;
        check(!rt::decode_snapshot_envelope(lying, key, image, why),
              "D3: a file claiming an implausible image length was accepted");
    }

    // D4 -- a rewrite replaces the file atomically and the new one still
    // round-trips, so a periodic save cannot leave a half file behind.
    {
        std::string why;
        std::vector<std::uint8_t> second = file;
        second = rt::encode_snapshot_envelope(key, std::vector<std::uint8_t>(file.begin() + 72,
                                                                             file.end() - 32));
        check(rt::write_snapshot_file(path, second, why), "D4: rewrite refused: " + why);
        std::vector<std::uint8_t> back;
        check(rt::read_snapshot_file(path, back, why), "D4: re-read refused: " + why);
        check(back == second, "D4: the rewritten file is not what was written");
        check(!std::filesystem::exists(path + ".tmp"),
              "D4: the rewrite left its temporary file behind");
    }

    // D5 -- an unwritable path is a refusal with a reason, not a crash and not
    // a silent success. A pool whose snapshot directory is read-only must
    // still run; it just does not resume.
    {
        std::string why;
        check(!rt::write_snapshot_file("/proc/definitely/not/writable/xmr.snap", file, why),
              "D5: writing into an unwritable path reported success");
        check(!why.empty(), "D5: the write refusal carried no reason");
    }

    std::filesystem::remove_all(dir, ec);
}

// =============================================================================
// E. gate 4 is still fail-closed, through the pool binary's own config
// =============================================================================
void suite_e_gate4() {
    std::printf("E. gate 4 remains fail-closed\n");

    // The embedded stagenet bundle is the only anchor in the tree, and it is
    // the right fixture: what is under test is the JUDGEMENT on a bundle, and
    // a genuine one is what a tamper has to be made from.
    native::AnchorBundle real;
    std::string why;
    const bool loaded = native::load_anchor("", native::XmrNet::Stagenet, real, why);
    check(loaded, "E0: the embedded stagenet anchor did not load: " + why);
    if (!loaded) return;

    // E1 -- the comparison itself. A genuine block confirms the genuine bundle
    // and CANNOT confirm a bundle whose id was altered: this is the one `!=`
    // that stands between a fabricated trust root and a running pool.
    {
        check(native::anchor_confirmed_by_network(real, real.id, why),
              "E1: the genuine anchor id did not confirm its own bundle");

        native::AnchorBundle tampered = real;
        tampered.id[0] ^= 0x01;
        check(!native::anchor_confirmed_by_network(tampered, real.id, why),
              "E1: a TAMPERED anchor id was confirmed by the genuine block");
        check(!why.empty(), "E1: the tamper refusal carried no reason");
    }

    // E2 -- the FORWARDED peer bound is the bound that is enforced. The config
    // comes out of the pool binary's flag parser and its forward, so this is
    // the pool binary's gate, not a hand-built one.
    {
        XmrNodeConfig c = base_config();
        check(parse_all(c, {"--native-anchor", "/tmp/anchor.inc",
                            "--anchor-confirm-peers", "2",
                            "--anchor-confirm-peer-ms", "1000",
                            "--anchor-confirm-timeout-ms", "100000"}).empty(),
              "E2: the gate 4 window was refused");
        const o2::NativeTemplateConfig n = o2::native_template_config_of(c);

        native::AnchorBundle tampered = real;
        tampered.id[0] ^= 0x01;

        AnchorNetworkConfirm confirm;
        confirm.arm(tampered);
        check(!confirm.ready(), "E2: a PENDING gate reported ready to serve");

        native::fakes::FakeFetcher fetcher;
        for (int i = 1; i <= 5; ++i) {
            PeerRef p;
            p.peer_id = static_cast<std::uint64_t>(i);
            p.addr    = "198.51.100." + std::to_string(i) + ":18080";
            fetcher.peer_table.push_back({p, PeerSyncData{}});
        }

        std::uint64_t clock = 1000;
        AnchorConfirmDriver drv(fetcher, confirm, n.anchor_confirm, [&clock] { return clock; });

        // Nobody answers. Each peer's turn expires, and when the forwarded
        // bound is spent the gate REFUSES rather than asking the rest of the
        // network until the deadline.
        AnchorConfirmState st = AnchorConfirmState::Pending;
        for (int step = 0; step < 40 && st != AnchorConfirmState::Refused; ++step) {
            st = drv.poll();
            clock += n.anchor_confirm.per_peer_ms + 1;
        }
        check(st == AnchorConfirmState::Refused,
              "E2: the gate did not refuse once its peer bound was spent");
        check(drv.asked() == 2,
              "E2: the gate asked " + std::to_string(drv.asked())
                  + " peers, not the 2 that were forwarded -- the knob is not in force");
        check(!confirm.ready(), "E2: a REFUSED gate reported ready to serve");
        check(confirm.refused(), "E2: the gate settled on something other than Refused");
    }

    // E3 -- the DEADLINE refuses too, independently of the peer bound: a gate
    // that can be kept pending forever by peers that never answer is not a
    // gate. Here the peer set is large enough that exhaustion cannot fire.
    {
        XmrNodeConfig c = base_config();
        check(parse_all(c, {"--anchor-confirm-peers", "50",
                            "--anchor-confirm-peer-ms", "1000",
                            "--anchor-confirm-timeout-ms", "5000"}).empty(),
              "E3: the gate 4 window was refused");
        const o2::NativeTemplateConfig n = o2::native_template_config_of(c);

        AnchorNetworkConfirm confirm;
        confirm.arm(real);
        native::fakes::FakeFetcher fetcher;   // no peers at all

        std::uint64_t clock = 500;
        AnchorConfirmDriver drv(fetcher, confirm, n.anchor_confirm, [&clock] { return clock; });
        check(drv.poll() == AnchorConfirmState::Pending,
              "E3: an armed gate with no peers settled immediately");
        clock += n.anchor_confirm.timeout_ms + 1;
        check(drv.poll() == AnchorConfirmState::Refused,
              "E3: the gate outlived its forwarded deadline");
        check(!confirm.ready(), "E3: a deadline-refused gate reported ready to serve");
    }

    // E4 -- the gate is a GATE, not a wall. A node that booted from genesis
    // arms nothing, and an unarmed confirm is ready by construction: gate 4
    // withholds serving only where there is an anchor to vouch for. (The
    // CONFIRMED path is driven end to end, from real block bytes, by
    // xmr_native_anchor_gate4_kat; what matters here is that adding the
    // window flags did not turn the gate into an unconditional refusal.)
    {
        AnchorNetworkConfirm fresh;
        check(!fresh.armed(), "E4: an untouched confirm reported itself armed");
        check(fresh.state() == AnchorConfirmState::Disarmed,
              "E4: an untouched confirm is not Disarmed");
        check(fresh.ready(), "E4: a genesis boot (no anchor) was withheld from serving");
        check(!fresh.confirmed(), "E4: a Disarmed confirm claims to be Confirmed");

        AnchorNetworkConfirm armed;
        armed.arm(real);
        check(armed.armed(), "E4: arming did not arm");
        check(!armed.ready(), "E4: an armed-but-pending gate is ready to serve");
        check(armed.wanted() == real.id, "E4: the gate is waiting for the wrong id");
        check(armed.wanted_height() == real.height,
              "E4: the gate is waiting at the wrong height");
    }
}

} // namespace

int main() {
    std::printf("v37_xmr_mainnet_readiness_kat -- c2pool-v37-xmr native-node plumbing\n");
    suite_a_parse();
    suite_b_forward();
    suite_c_seeds();
    suite_d_snapshot();
    suite_e_gate4();
    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
