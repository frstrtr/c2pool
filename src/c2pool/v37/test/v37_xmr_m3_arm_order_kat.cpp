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
// The find path's switch (daemon-first keeps monerod as the tip and
// the block publisher; p2p-first moves both onto the embedded native node).
//
// Suites:
//   A  the switch's declared rules (arm_order_refusal), pure and exhaustive
//   E  the publisher: a found block goes out as a levin 2008 through C5, and a
//      relay that reached NOBODY delivers NO found event
//
// No sockets, no RandomX, no live daemon; on both build.yml --target lists.
// ===========================================================================
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <map>
#include <unistd.h>
#include <string>
#include <vector>

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

    // daemon-first accepts every template source.
    check(arm_order_refusal(c).empty(), "A4 daemon-first (the default config) is accepted");
    c.template_source = TemplateSourceMode::Native;
    check(arm_order_refusal(c).empty(), "A6 daemon-first + native template is accepted");

    // p2p-first refuses anything that would leave a daemon on the find path.
    XmrNodeConfig p;
    p.arm_order = ArmOrderMode::P2PFirst;
    p.native_connect.push_back("127.0.0.1:18080");
    check(!arm_order_refusal(p).empty(),
          "A8 p2p-first REFUSES the monerod template source (get_miner_data per refresh), a peer given");
    p.template_source = TemplateSourceMode::Native;
    p.native_connect.clear();
    check(!arm_order_refusal(p).empty(),
          "A9 p2p-first REFUSES an empty --native-connect (no chain, nowhere to relay)");
    p.native_connect.push_back("127.0.0.1:18080");
    check(arm_order_refusal(p).empty(),
          "A10 p2p-first + native template + a peer is accepted");
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

    auto lookup = [&f](std::uint32_t, std::uint32_t, submit::BlockCandidate& out) {
        out.template_id     = 1;
        out.height          = f.height;
        out.full_blob       = f.blob;
        out.hashing_blob    = f.hashing_blob;
        out.nonce_offset    = f.nonce_offset;
        out.expected_reward = 600000000000ull;
        return true;
    };

    o2::P2pBlockPublisher pub(relay, lookup);
    std::vector<submit::FoundBlockEvent> found;
    pub.set_found_hook([&found](const submit::FoundBlockEvent& e) { found.push_back(e); });

    // (1) fail-closed before the RandomX verifier says so.
    pub.submit_network_block(1, f.nonce, 0);
    check(pub.refused() == 1 && pub.delivered() == 0 && found.empty(),
          "E1 a disabled relay REFUSES and delivers no found event",
          pub.last_error());

    // (2) armed, with peers: the block goes out and a FOUND event follows.
    pub.enable_network_relay(true);
    port.state_normal_peers = 3;
    pub.submit_network_block(1, f.nonce, 0);
    check(pub.relayed() == 1, "E2 the block was relayed over levin", pub.last_error());
    check(pub.delivered() == 1 && found.size() == 1, "E3 exactly one found event was delivered");
    const bool got = found.size() == 1;
    const submit::FoundBlockEvent ev = got ? found[0] : submit::FoundBlockEvent{};
    check(got && ev.block_id == f.id,
          "E4 the found event carries OUR block id, off the bytes we relayed");
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

    // (3) THE FAIL-CLOSED ONE: a relay that reached nobody delivers no found
    //     event.
    port.state_normal_peers = 0;
    port.broadcasts.clear();
    pub.submit_network_block(1, f.nonce, 0);
    check(pub.failed() == 1, "E9 zero peers is a LOUD failure, not a shrug",
          pub.last_error());
    check(pub.delivered() == 1 && found.size() == 1,
          "E10 a block that reached NOBODY delivers NO found event (fail-closed)",
          "delivered=" + std::to_string(pub.delivered()));

    // (4) a candidate with no served hashing blob has no verified id to attest.
    port.state_normal_peers = 3;
    auto blind = [&f](std::uint32_t, std::uint32_t, submit::BlockCandidate& out) {
        out.template_id  = 1;
        out.height       = f.height;
        out.full_blob    = f.blob;
        out.nonce_offset = f.nonce_offset;
        return true;                       // note: no hashing_blob
    };
    o2::P2pBlockPublisher blind_pub(relay, blind);
    blind_pub.enable_network_relay(true);
    blind_pub.submit_network_block(1, f.nonce, 0);
    check(blind_pub.refused() == 1 && blind_pub.relayed() == 0,
          "E11 no hashing blob -> no attestable id -> REFUSED, never relayed",
          blind_pub.last_error());
}


// ===========================================================================
int main() {
    std::printf("== v37_xmr_m3_arm_order_kat: R-ARMORDER pinned on both settings ==\n");

    suite_a();
    suite_e();

    std::printf("== %s: %d passed, %d failed ==\n", g_fail ? "FAIL" : "OK", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
