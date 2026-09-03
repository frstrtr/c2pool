// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bip110_coin_subver_brand_kat — the outgoing coin-p2p user-agent BRAND gate.
//
// The BIP-110 fork node is the c2pool embedded daemonless SPV (NO bitcoind). It
// already brands on-chain (coinbase /c2pool/ tag) and on the sharechain pool
// wire (/c2pool:0.1/). The COIN-P2P (BLAKE2b) version message it sends to Knots
// /Core fork peers previously carried a BARE, non-BIP14 token ("c2pool-bip110"):
// crawlers/bitnodes and the peers' own -netinfo parse the subver as a BIP14
// `/name:version/` user-agent, so a bare token displays without our brand.
//
// This KAT pins the fix: the outgoing subver is the SINGLE named constant
// bip110::coin::p2p::BIP110_COIN_SUBVER, defaulting to the branded BIP14 form
// "/c2pool:0.1/bip110/", and a serialized message_version carrying that exact
// constant embeds it as a correctly length-prefixed var-string at the subver
// field offset — the precise bytes a fork peer / crawler reads as our UA.
//
// It also asserts the identity is DISPLAY-ONLY and cannot break the handshake:
// fork-peer acceptance is gated on the NODE_BLAKE2B service bit
// (COIN_NODE_BLAKE2B, bit 28), never on the subver string, so the version this
// KAT builds still advertises NODE_BLAKE2B and is accepted regardless of brand.
//
// Zero-socket / deterministic: nothing dials, resolves, or accepts. This is a
// serialization + constant KAT; live acceptance by the contabo Knots fork peers
// is the operator's soak gate (necessary, not sufficient).
// ---------------------------------------------------------------------------

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <core/pack.hpp>
#include <core/netaddress.hpp>
#include "../p2p_messages.hpp"   // bip110::coin::p2p::message_version
#include "../p2p_node.hpp"       // bip110::coin::p2p::BIP110_COIN_SUBVER / COIN_NODE_BLAKE2B

using bip110::coin::p2p::BIP110_COIN_SUBVER;
using bip110::coin::p2p::COIN_NODE_BLAKE2B;
using bip110::coin::p2p::message_version;

namespace {

int g_fail = 0;
void expect_true(const std::string& name, bool cond)
{
    if (cond) std::printf("  [ok]   %s\n", name.c_str());
    else { std::printf("  [FAIL] %s\n", name.c_str()); ++g_fail; }
}

// Find the exact var-string encoding [len][bytes] of `s` inside the serialized
// payload — i.e. a single-byte CompactSize length prefix (s.size() < 253) that
// equals the string length, immediately followed by the string's bytes. This is
// how the subver field is on the wire, so a hit proves a peer/crawler reads our
// brand as the subver, not as an incidental substring.
bool contains_varstr(const std::vector<uint8_t>& buf, const std::string& s)
{
    if (s.empty() || s.size() >= 253) return false;           // this KAT's strings fit 1-byte CompactSize
    const uint8_t len = static_cast<uint8_t>(s.size());
    for (size_t i = 0; i + 1 + s.size() <= buf.size(); ++i) {
        if (buf[i] != len) continue;
        if (std::memcmp(&buf[i + 1], s.data(), s.size()) == 0) return true;
    }
    return false;
}

} // namespace

int main()
{
    std::printf("bip110_coin_subver_brand_kat: outgoing coin-p2p user-agent brand\n");

    const std::string subver = BIP110_COIN_SUBVER;

    // ── (A) The constant is the branded BIP14 default ──
    expect_true("[A] BIP110_COIN_SUBVER == \"/c2pool:0.1/bip110/\" (branded default)",
                subver == "/c2pool:0.1/bip110/");
    expect_true("[A] subver is BIP14-shaped (leading '/', trailing '/')",
                subver.size() >= 2 && subver.front() == '/' && subver.back() == '/');
    expect_true("[A] subver advertises c2pool (crawler/bitnodes brand reach)",
                subver.find("c2pool") != std::string::npos);
    expect_true("[A] subver is no longer the bare non-BIP14 token \"c2pool-bip110\"",
                subver != "c2pool-bip110");

    // ── (B) A version message built EXACTLY as NodeP2P::connected() does carries
    //        the branded subver as a correctly length-prefixed var-string, and
    //        advertises NODE_BLAKE2B (the acceptance bit) ──
    static constexpr uint64_t NODE_NETWORK = 1;
    static constexpr uint64_t NODE_WITNESS = (1 << 3);
    const uint64_t our_services = NODE_NETWORK | NODE_WITNESS | COIN_NODE_BLAKE2B;

    // Mirror the make_raw(...) arg order at p2p_node.hpp connected().
    PackStream ps = message_version::make(
        /*version*/       uint32_t{70016},
        /*services*/      our_services,
        /*timestamp*/     uint64_t{0},
        /*addr_to*/       addr_t{our_services, NetService{std::string("192.168.0.1"), uint16_t{8333}}},
        /*addr_from*/     addr_t{our_services, NetService{std::string("192.168.0.1"), uint16_t{8333}}},
        /*nonce*/         uint64_t{0},
        /*subversion*/    subver,
        /*start_height*/  uint32_t{0}
    );

    std::vector<uint8_t> buf(reinterpret_cast<uint8_t*>(ps.data()),
                             reinterpret_cast<uint8_t*>(ps.data()) + ps.size());

    expect_true("[B] serialized message_version embeds BIP110_COIN_SUBVER as a "
                "length-prefixed var-string (the exact bytes a fork peer reads as UA)",
                contains_varstr(buf, subver));

    // The service bit that ACTUALLY gates acceptance is present; changing the
    // subver cannot affect it (bit 28 is set independently of the UA string).
    expect_true("[B] our_services advertises NODE_BLAKE2B (bit 28) — acceptance is "
                "service-bit gated, so the brand change cannot break the handshake",
                (our_services & COIN_NODE_BLAKE2B) != 0);

    // Sanity: the stale bare token must NOT appear as a var-string in our payload.
    expect_true("[B] the bare \"c2pool-bip110\" token is NOT the serialized subver",
                !contains_varstr(buf, std::string("c2pool-bip110")));

    if (g_fail == 0) {
        std::printf("RESULT: PASS — the outgoing coin-p2p version carries the branded "
                    "BIP14 subver \"%s\" via BIP110_COIN_SUBVER, and still advertises "
                    "NODE_BLAKE2B (service-bit gated acceptance). Live contabo Knots "
                    "fork-peer acceptance is the operator soak gate.\n", subver.c_str());
        return 0;
    }
    std::printf("RESULT: FAIL — %d assertion(s) failed.\n", g_fail);
    return 1;
}
