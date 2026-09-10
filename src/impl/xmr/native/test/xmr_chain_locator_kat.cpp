// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_chain_locator_kat.cpp
//
// Wave 1, C1c: the NOTIFY_REQUEST_CHAIN locator and the network seed tables.
//
// The load-bearing assertion in this file is the GENESIS TERMINUS. monerod's
// Blockchain::find_blockchain_supplement rejects a locator whose last id is not
// the genesis id, and handle_request_chain turns that rejection into
// drop_connection() -- with no error frame, so the symptom is "peers keep
// disconnecting" rather than anything that names the locator. Every path that
// can produce a locator is therefore checked to end in genesis, including the
// paths where the index has NO rows and where the caller passes an id list that
// already ends in genesis.
//
// The stagenet genesis id pinned in chain_seeds.hpp was verified live on
// 2026-09-11 against a stagenet monerod (read-only, one connection): a
// single-id locator equal to STAGENET_GENESIS was answered
// NOTIFY_RESPONSE_CHAIN_ENTRY start_height=0 with ids[0] == STAGENET_GENESIS.
// The hex in HEX_STAGENET_GENESIS below is that captured id.
// ---------------------------------------------------------------------------
#include <cstdio>
#include <string>
#include <vector>

#include "impl/xmr/native/contracts/fakes/fake_chain.hpp"
#include "impl/xmr/native/p2p/chain_locator.hpp"
#include "impl/xmr/native/p2p/chain_seeds.hpp"
#include "xmr_p2p_kat_util.hpp"

namespace native = c2pool::xmr::native;
namespace p2p    = c2pool::xmr::native::p2p;
namespace kat    = c2pool::xmr::native::kat;
using native::Hash;
using p2p::XmrNet;

namespace {

// The three ids, as hex, independently of the constants under test: a typo in
// chain_seeds.hpp and a matching typo here would have to be the same typo made
// twice, in two different notations.
constexpr const char* HEX_MAINNET_GENESIS =
    "418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3";
constexpr const char* HEX_TESTNET_GENESIS =
    "48ca7cd3c8de5b6a4d53d2861fbdaedca141553559f9be9520068053cd8e6734";
constexpr const char* HEX_STAGENET_GENESIS =
    "76ee3cc98646292206cd3e86f74d88b4dcc1d937088645e9b0cbca84b7ce74eb";

Hash hash_of_hex(const char* hex) {
    const std::vector<std::uint8_t> b = kat::from_hex(hex);
    Hash h{};
    for (std::size_t i = 0; i < h.size() && i < b.size(); ++i) h[i] = b[i];
    return h;
}

Hash hash_of_byte(std::uint8_t v) {
    Hash h{};
    h.fill(v);
    return h;
}

std::string hex_of(const Hash& h) {
    return kat::to_hex(std::vector<std::uint8_t>(h.begin(), h.end()));
}

// -----------------------------------------------------------------------
void test_genesis_constants() {
    kat::check(p2p::genesis_id(XmrNet::Mainnet)  == hash_of_hex(HEX_MAINNET_GENESIS),
               "mainnet genesis id matches the pinned hex");
    kat::check(p2p::genesis_id(XmrNet::Testnet)  == hash_of_hex(HEX_TESTNET_GENESIS),
               "testnet genesis id matches the pinned hex");
    kat::check(p2p::genesis_id(XmrNet::Stagenet) == hash_of_hex(HEX_STAGENET_GENESIS),
               "stagenet genesis id matches the live-verified hex");

    // The constexpr reader is the thing that turns the hex literal into the
    // constant; prove it is not silently yielding zero on any of them.
    kat::check(!p2p::detail::is_zero(p2p::STAGENET_GENESIS),
               "the constexpr hex reader produced a non-zero stagenet id");
    kat::checkf(hex_of(p2p::STAGENET_GENESIS) == std::string(HEX_STAGENET_GENESIS),
                "stagenet genesis re-hexes to itself: got %s",
                hex_of(p2p::STAGENET_GENESIS).c_str());
}

// -----------------------------------------------------------------------
void test_seed_tables() {
    // DNS seeds exist for MAINNET ONLY (net_node.h guards the list on nettype).
    // An empty list for the test networks is the correct answer: querying the
    // mainnet hosts on stagenet would dial mainnet daemons that can never pass
    // our network-id admission.
    kat::check(p2p::dns_seeds(XmrNet::Mainnet).size() == 4, "mainnet has four DNS seeds");
    kat::check(p2p::dns_seeds(XmrNet::Testnet).empty(),  "testnet has no DNS seeds");
    kat::check(p2p::dns_seeds(XmrNet::Stagenet).empty(), "stagenet has no DNS seeds");

    const auto main_dns = p2p::dns_seeds(XmrNet::Mainnet);
    kat::check(main_dns[0].host == "seeds.moneroseeds.se", "first DNS seed host");
    kat::check(main_dns[1].host == "seeds.moneroseeds.ae.org", "second DNS seed host");
    kat::check(main_dns[2].host == "seeds.moneroseeds.ch", "third DNS seed host");
    kat::check(main_dns[3].host == "seeds.moneroseeds.li", "fourth DNS seed host");
    for (const auto& s : main_dns) kat::check(s.port == 18080, "DNS seed port is 18080");

    kat::check(p2p::ip_seeds(XmrNet::Mainnet).size() == 6,  "mainnet has six IP seeds");
    kat::check(p2p::ip_seeds(XmrNet::Testnet).size() == 5,  "testnet has five IP seeds");
    kat::check(p2p::ip_seeds(XmrNet::Stagenet).size() == 5, "stagenet has five IP seeds");

    for (const auto& s : p2p::ip_seeds(XmrNet::Stagenet))
        kat::check(s.port == 38080, "stagenet IP seeds are on :38080");
    for (const auto& s : p2p::ip_seeds(XmrNet::Testnet))
        kat::check(s.port == 28080, "testnet IP seeds are on :28080");
    for (const auto& s : p2p::ip_seeds(XmrNet::Mainnet))
        kat::check(s.port == 18080, "mainnet IP seeds are on :18080");

    // 88.198.163.90 is the one mainnet-only host.
    bool testnet_has_88198 = false;
    for (const auto& s : p2p::ip_seeds(XmrNet::Testnet))
        if (s.ip == "88.198.163.90") testnet_has_88198 = true;
    kat::check(!testnet_has_88198, "the mainnet-only IP seed is absent from testnet");
}

// -----------------------------------------------------------------------
void test_netgroups() {
    std::uint32_t v = 0;
    kat::check(p2p::parse_ipv4("192.168.86.44", v) && v == 0xC0A8562Cu, "IPv4 parse");
    kat::check(!p2p::parse_ipv4("192.168.86", v),      "a three-octet address is refused");
    kat::check(!p2p::parse_ipv4("192.168.86.444", v),  "an out-of-range octet is refused");
    kat::check(!p2p::parse_ipv4("192.168.86.44.1", v), "a five-octet address is refused");
    kat::check(!p2p::parse_ipv4("", v),                "an empty address is refused");

    kat::check(p2p::netgroup16("10.1.2.3") == p2p::netgroup16("10.1.99.99"),
               "the same /16 groups together");
    kat::check(p2p::netgroup16("10.1.2.3") != p2p::netgroup16("10.2.2.3"),
               "a different /16 is a different group");
    // A non-IPv4 string must not alias a real /16: the cap would then be
    // bypassable by handing us a hostname.
    kat::check(p2p::netgroup16("not-an-ip") > 0xffffu,
               "an unparseable address lands outside the IPv4 group space");

    std::string ip;
    std::uint16_t port = 0;
    kat::check(p2p::split_peer_key("192.168.86.44:38080", ip, port)
                   && ip == "192.168.86.44" && port == 38080, "peer key splits");
    kat::check(!p2p::split_peer_key("192.168.86.44", ip, port), "a key with no port is refused");
    kat::check(!p2p::split_peer_key("192.168.86.44:0", ip, port), "port 0 is refused");
    kat::check(!p2p::split_peer_key("192.168.86.44:99999", ip, port), "port > 65535 is refused");
    kat::check(p2p::make_peer_key("1.2.3.4", 18080) == "1.2.3.4:18080", "peer key formats");
}

// -----------------------------------------------------------------------
void test_locator_heights() {
    // monerod's get_short_chain_history: ten consecutive from the tip, then a
    // doubling step, ending at the floor.
    const auto h = p2p::locator_heights(1000, 0);
    kat::check(h.front() == 1000, "the locator starts at the tip");
    kat::check(h.back()  == 0,    "the locator ends at the floor");
    for (std::size_t i = 0; i + 1 < h.size(); ++i)
        kat::check(h[i] > h[i + 1], "locator heights descend strictly");
    for (std::size_t i = 0; i < 10 && i + 1 < h.size(); ++i)
        kat::checkf(h[i] == 1000 - i, "the first ten ids are consecutive (i=%zu)", i);
    // After the dense prefix the gaps double.
    kat::check(h.size() < 40, "a 1000-deep walk stays short");

    const auto one = p2p::locator_heights(7, 7);
    kat::check(one.size() == 1 && one[0] == 7, "tip == floor yields a single height");

    kat::check(p2p::locator_heights(5, 9).empty(), "a floor above the tip yields nothing");

    // The cap keeps the floor: a truncated walk that stops mid-chain is a
    // locator with no bottom, which is exactly what the terminus rule forbids.
    const auto capped = p2p::locator_heights(1'000'000, 0, 12);
    kat::checkf(capped.size() <= 12, "the cap is honoured (%zu)", capped.size());
    kat::check(capped.back() == 0, "the capped walk still reaches the floor");
}

// -----------------------------------------------------------------------
void test_finalize_terminus() {
    const Hash g = p2p::genesis_id(XmrNet::Stagenet);

    // 1. The ordinary case: an anchored index's retained ids, none of which is
    //    genesis. The genesis id is appended.
    std::vector<Hash> ids{hash_of_byte(0x11), hash_of_byte(0x22), hash_of_byte(0x33)};
    auto out = p2p::finalize_locator(ids, g);
    kat::check(out.size() == 4, "the genesis id is appended to a retained-window locator");
    kat::check(p2p::locator_ends_with_genesis(out, g), "... and it is the terminus");
    kat::check(out[0] == ids[0], "the tip-most id stays first (it is what splices)");

    // 2. A full node whose walk already reached genesis: no duplicate.
    std::vector<Hash> with_g{hash_of_byte(0x11), g};
    out = p2p::finalize_locator(with_g, g);
    kat::check(out.size() == 2, "an id list already ending in genesis is not extended");
    kat::check(p2p::locator_ends_with_genesis(out, g), "... and still ends in genesis");

    // 3. THE EMPTY-INDEX CASE. A node that has not yet loaded its anchor has no
    //    ids at all, and the wire still requires a terminus.
    out = p2p::finalize_locator({}, g);
    kat::check(out.size() == 1 && out[0] == g,
               "an empty index still produces a genesis-only locator");

    // 4. Zero ids are never asked about, and consecutive repeats collapse.
    std::vector<Hash> noisy{hash_of_byte(0x11), hash_of_byte(0x11), Hash{}, hash_of_byte(0x22)};
    out = p2p::finalize_locator(noisy, g);
    kat::check(out.size() == 3, "repeats collapse and zero ids are dropped");
    kat::check(out[0] == hash_of_byte(0x11) && out[1] == hash_of_byte(0x22),
               "... leaving the real ids in order");

    // 5. The cap never costs the terminus: truncation happens BEFORE the append.
    std::vector<Hash> many;
    for (int i = 1; i <= 200; ++i) many.push_back(hash_of_byte(static_cast<std::uint8_t>(i)));
    out = p2p::finalize_locator(many, g, 16);
    kat::checkf(out.size() == 16, "the locator honours its cap (%zu)", out.size());
    kat::check(p2p::locator_ends_with_genesis(out, g),
               "a capped locator still ends in genesis");
    kat::check(out[0] == many[0], "the capped locator keeps the TIP-most ids");

    // 6. A zero genesis is refused outright rather than sent. Sending a zero
    //    terminus is the dropped-connection case this whole file exists for, so
    //    failing loudly at the call site beats failing silently on the wire.
    kat::check(p2p::finalize_locator(ids, Hash{}).empty(),
               "an all-zero genesis produces no locator at all");

    // 7. Cross-network: a mainnet terminus on a stagenet locator is not
    //    "ends_with_genesis" for stagenet. This is the shape of the bug where a
    //    node is configured for one network and pinned to another's constants.
    out = p2p::finalize_locator(ids, p2p::genesis_id(XmrNet::Mainnet));
    kat::check(!p2p::locator_ends_with_genesis(out, g),
               "a mainnet terminus does not satisfy the stagenet rule");
}

// -----------------------------------------------------------------------
void test_build_from_serving() {
    // build_locator() reads IChainServing::locator() -- the C2c index's own
    // walk, which terminates at the OLDEST RETAINED ROW and deliberately does
    // not invent a genesis it never saw. This is the seam: C1c is what turns
    // that honest-but-unsendable list into a wire-legal locator.
    native::fakes::FakeChain chain;
    const Hash g = p2p::genesis_id(XmrNet::Stagenet);

    // FakeChain::locator() derives its ids from `rows`.
    for (std::uint64_t h = 2'204'000; h <= 2'204'020; ++h) {
        native::node::ChainMainBlock b{};
        b.height = h;
        b.id     = hash_of_byte(static_cast<std::uint8_t>(h & 0xff));
        chain.rows.push_back(b);
    }

    const std::vector<Hash> raw = chain.locator();
    kat::check(!raw.empty(), "the fake index offers a locator");
    kat::check(!p2p::locator_ends_with_genesis(raw, g),
               "the INDEX locator does not end in genesis (it never saw height 0)");

    const std::vector<Hash> wire = p2p::build_locator(chain, XmrNet::Stagenet);
    kat::check(p2p::locator_ends_with_genesis(wire, g),
               "the WIRE locator does end in genesis");
    kat::check(wire.size() == raw.size() + 1, "exactly one id was added");
    kat::check(wire[0] == raw[0], "the splice candidate is still first");

    // An index with no rows at all: still one id, still genesis.
    native::fakes::FakeChain empty;
    const std::vector<Hash> cold = p2p::build_locator(empty, XmrNet::Stagenet);
    kat::check(cold.size() == 1 && cold[0] == g,
               "a cold index produces a genesis-only locator, not an empty one");
}

} // namespace

int main() {
    test_genesis_constants();
    test_seed_tables();
    test_netgroups();
    test_locator_heights();
    test_finalize_terminus();
    test_build_from_serving();
    return kat::report("xmr_native_chain_locator_kat");
}
