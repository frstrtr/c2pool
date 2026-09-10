// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/p2p/chain_seeds.hpp
//
// Wave 1, component C1c: WHERE A COLD NODE STARTS, and the one identity it can
// never guess.
//
// Three tables live here, and they are together because they are the same fact
// -- "which network am I on" -- read three ways:
//
//   1. DNS seeds. monerod's net_node.h carries four A-record hosts for MAINNET
//      only: seeds.moneroseeds.se, .ae.org, .ch and .li. Every A record they
//      return is an 18080 peer. TESTNET AND STAGENET HAVE NO DNS SEEDS -- the
//      list in net_node.h is guarded by `if (m_nettype == MAINNET)` and the
//      other two nettypes fall straight through to the hardcoded IP seeds. A
//      client that "helpfully" queried the mainnet hosts on stagenet would dial
//      mainnet daemons, fail admission on the network id, and burn its dial
//      budget on peers that can never answer.
//
//   2. IP seeds (net_node.inl::get_ip_seed_nodes). Mainnet has six, testnet and
//      stagenet share five of them on their own ports (28080 / 38080): the same
//      operators run all three nettypes on one host.
//
//   3. THE GENESIS ID. This is the one that is not a convenience. monerod's
//      Blockchain::find_blockchain_supplement -- the handler behind
//      NOTIFY_REQUEST_CHAIN (2006) -- opens with
//
//          if (qblock_ids.back() != m_db->get_block_hash_from_height(0)) {
//              MCERROR(... "genesis block mismatch" ...);  return false;
//          }
//
//      and a false return there makes handle_request_chain call
//      drop_connection(). So a locator whose LAST id is not the genesis id is
//      not "slightly less efficient": it is a dropped connection, every time,
//      from every peer, with no error frame to explain it. That is why the
//      genesis id is pinned here as network data rather than derived from the
//      index -- an anchored node (C2b starts at height 2204000, not 0) has no
//      genesis block to read and would otherwise have nothing to terminate its
//      locator with. See chain_locator.hpp for the rule that consumes it.
//
//      LIVE VERIFICATION (2026-09-11, read-only, one connection): a levin
//      handshake against the stagenet daemon on 192.168.86.44:38080 followed by
//      NOTIFY_REQUEST_CHAIN with a single-id locator equal to STAGENET_GENESIS
//      answered NOTIFY_RESPONSE_CHAIN_ENTRY start_height=0, 10000 ids, ids[0]
//      == STAGENET_GENESIS. The daemon accepting the terminus and echoing it as
//      the height-0 id is the id's own proof.
//
// SCOPE FENCE (standing XMR-lane rule): everything under src/impl/xmr/. This
// tree is a WORK SOURCE for the pool, not part of the v37 share-chain record;
// nothing here activates v37 consensus and src/sharechain/v37 is not touched.
//
// Header-only, STL only.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "impl/xmr/native/contracts/types.hpp"
#include "impl/xmr/native/p2p/levin_messages.hpp"

namespace c2pool::xmr::native::p2p {

using levin::XmrNet;
using levin::p2p_default_port;

// ---------------------------------------------------------------------------
// Seed descriptors. Deliberately plain: the DNS resolution itself belongs to
// core::DnsSeeder, and the peer pool only needs the host/port pair to hand it.
// ---------------------------------------------------------------------------
struct DnsSeed {
    std::string   host;
    std::uint16_t port = 0;
};

struct IpSeed {
    std::string   ip;      // dotted-quad IPv4 literal
    std::uint16_t port = 0;
};

// ---------------------------------------------------------------------------
// DNS seeds -- MAINNET ONLY (net_node.h). Returning an empty vector for the two
// test networks is the correct answer, not a gap.
// ---------------------------------------------------------------------------
inline std::vector<DnsSeed> dns_seeds(XmrNet net) {
    if (net != XmrNet::Mainnet) return {};
    const std::uint16_t port = p2p_default_port(XmrNet::Mainnet);
    return {
        {"seeds.moneroseeds.se",     port},
        {"seeds.moneroseeds.ae.org", port},
        {"seeds.moneroseeds.ch",     port},
        {"seeds.moneroseeds.li",     port},
    };
}

// ---------------------------------------------------------------------------
// Hardcoded IP seeds (net_node.inl::get_ip_seed_nodes). Mainnet carries one
// extra host (88.198.163.90) that the two test networks do not.
// ---------------------------------------------------------------------------
inline std::vector<IpSeed> ip_seeds(XmrNet net) {
    const std::uint16_t port = p2p_default_port(net);
    std::vector<IpSeed> out{
        {"176.9.0.187",   port},
        {"192.99.8.110",  port},
        {"37.187.74.171", port},
        {"88.99.195.15",  port},
        {"5.104.84.64",   port},
    };
    if (net == XmrNet::Mainnet) out.insert(out.begin() + 1, IpSeed{"88.198.163.90", port});
    return out;
}

// ---------------------------------------------------------------------------
// Genesis ids, per network. These are the ids of the block at height 0 --
// monerod's GENESIS_TX under the per-network GENESIS_NONCE (10000 / 10001 /
// 10002) -- and they are the mandatory terminus of every NOTIFY_REQUEST_CHAIN
// locator we send. See the header comment for what a wrong one costs.
// ---------------------------------------------------------------------------
inline constexpr const char* MAINNET_GENESIS_HEX =
    "418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3";
inline constexpr const char* TESTNET_GENESIS_HEX =
    "48ca7cd3c8de5b6a4d53d2861fbdaedca141553559f9be9520068053cd8e6734";
inline constexpr const char* STAGENET_GENESIS_HEX =
    "76ee3cc98646292206cd3e86f74d88b4dcc1d937088645e9b0cbca84b7ce74eb";

namespace detail {

// A tiny constexpr hex reader so the ids above stay readable as hex and still
// become a Hash at compile time. Returns an all-zero hash on malformed input,
// which the static_asserts below turn into a build failure rather than a
// silently wrong constant.
constexpr int hex_nibble(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

constexpr Hash hash_from_hex(const char* hex) noexcept {
    Hash h{};
    for (std::size_t i = 0; i < h.size(); ++i) {
        const int hi = hex_nibble(hex[2 * i]);
        const int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return Hash{};
        h[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    // A 65th character means the literal is longer than 32 bytes: refuse it.
    if (hex[2 * 32] != '\0') return Hash{};
    return h;
}

constexpr bool is_zero(const Hash& h) noexcept {
    for (std::uint8_t b : h) if (b != 0) return false;
    return true;
}

} // namespace detail

inline constexpr Hash MAINNET_GENESIS  = detail::hash_from_hex(MAINNET_GENESIS_HEX);
inline constexpr Hash TESTNET_GENESIS  = detail::hash_from_hex(TESTNET_GENESIS_HEX);
inline constexpr Hash STAGENET_GENESIS = detail::hash_from_hex(STAGENET_GENESIS_HEX);

static_assert(!detail::is_zero(MAINNET_GENESIS),  "mainnet genesis literal is malformed");
static_assert(!detail::is_zero(TESTNET_GENESIS),  "testnet genesis literal is malformed");
static_assert(!detail::is_zero(STAGENET_GENESIS), "stagenet genesis literal is malformed");
static_assert(MAINNET_GENESIS != TESTNET_GENESIS && TESTNET_GENESIS != STAGENET_GENESIS
                  && MAINNET_GENESIS != STAGENET_GENESIS,
              "the three networks must not share a genesis id");

inline constexpr Hash genesis_id(XmrNet net) noexcept {
    switch (net) {
        case XmrNet::Testnet:  return TESTNET_GENESIS;
        case XmrNet::Stagenet: return STAGENET_GENESIS;
        case XmrNet::Mainnet:  break;
    }
    return MAINNET_GENESIS;
}

// ---------------------------------------------------------------------------
// "ip:port" is the peer key everywhere in C1c (ban lists, peer store, PeerRef).
// One formatter, so the key a dial produces and the key a ban checks are
// byte-identical.
// ---------------------------------------------------------------------------
inline std::string make_peer_key(const std::string& ip, std::uint16_t port) {
    return ip + ":" + std::to_string(port);
}

inline bool split_peer_key(const std::string& key, std::string& ip, std::uint16_t& port) {
    const std::size_t colon = key.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 >= key.size()) return false;
    ip = key.substr(0, colon);
    unsigned long v = 0;
    for (std::size_t i = colon + 1; i < key.size(); ++i) {
        const char c = key[i];
        if (c < '0' || c > '9') return false;
        v = v * 10 + static_cast<unsigned long>(c - '0');
        if (v > 65535) return false;
    }
    if (v == 0) return false;
    port = static_cast<std::uint16_t>(v);
    return true;
}

// ---------------------------------------------------------------------------
// IPv4 helpers. The /16 netgroup is the eclipse guard's unit (section "refill
// and rotation" in xmr_dial_plan.hpp) and monerod uses the same width for its
// own address-class diversity, so the two agree by construction.
// ---------------------------------------------------------------------------
inline bool parse_ipv4(const std::string& s, std::uint32_t& out) {
    std::uint32_t acc = 0;
    int octets = 0;
    std::size_t i = 0;
    while (octets < 4) {
        if (i >= s.size() || s[i] < '0' || s[i] > '9') return false;
        unsigned v = 0;
        std::size_t digits = 0;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
            v = v * 10 + static_cast<unsigned>(s[i] - '0');
            ++i; ++digits;
            if (v > 255 || digits > 3) return false;
        }
        acc = (acc << 8) | v;
        ++octets;
        if (octets < 4) {
            if (i >= s.size() || s[i] != '.') return false;
            ++i;
        }
    }
    if (i != s.size()) return false;
    out = acc;
    return true;
}

// The /16 group of a dotted-quad. An unparseable address (a hostname, an IPv6
// literal) hashes to its own group so it neither collides with a real /16 nor
// escapes the cap.
inline std::uint32_t netgroup16(const std::string& ip) {
    std::uint32_t v = 0;
    if (parse_ipv4(ip, v)) return v >> 16;
    // FNV-1a over the string, forced above the 16-bit IPv4 group space so a
    // hostname can never alias a real /16.
    std::uint32_t h = 2166136261u;
    for (char c : ip) { h ^= static_cast<std::uint8_t>(c); h *= 16777619u; }
    return 0x10000u | (h & 0xffffu);
}

inline std::uint32_t netgroup16_of_key(const std::string& peer_key) {
    std::string ip;
    std::uint16_t port = 0;
    if (!split_peer_key(peer_key, ip, port)) return netgroup16(peer_key);
    return netgroup16(ip);
}

} // namespace c2pool::xmr::native::p2p
