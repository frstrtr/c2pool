// DASH V36 conformance — merkle-root-equality precondition (S6 slice).
//
// Before any share/block can be conformance-checked against DASH's own
// older-than-v35 oracle (frstrtr/p2pool-dash), one structural invariant must
// hold: the gentx hash plus the share's merkle_link must reconstruct the
// SAME block merkle root that a full-tree reduction of the transaction set
// produces. If that precondition fails, every downstream equality comparison
// is meaningless (you'd be comparing roots derived two different ways).
//
// This test pins that precondition WITHOUT a node dependency. It cross-checks
// the production path —
//     dash::coinbase::merkle_branches_raw()  (build the index-0 branch)
//     dash::check_merkle_link()              (walk gentx + branch -> root)
// — against an INDEPENDENT in-test reference reduction (canonical Bitcoin/
// p2pool merkle: pairwise SHA256d, duplicate-last on odd). Two implementations
// agreeing is the invariant.
//
// The expected-root hex strings are KAT vectors computed OUT-OF-BAND with
// CPython hashlib (double-SHA256), so the pins are not circular with the C++
// code under test. Leaves are sha256d(single byte i) so the fixtures are
// reproducible with a three-line script and carry no byte-order ambiguity
// (raw digest bytes == uint256 internal order == HexStr(GetChars())).
//
// NOTE: real captured-corpus KAT vectors from a live Dash node (VM200/201)
// are the S6 follow-on and gate on node-state-green; this slice locks the
// structural precondition those vectors will later exercise.

#include <gtest/gtest.h>

#include <impl/dash/coinbase_builder.hpp>   // dash::coinbase::merkle_branches_raw, HexStr
#include <impl/dash/share_check.hpp>        // dash::check_merkle_link
#include <impl/dash/share_types.hpp>        // dash::MerkleLink

#include <core/hash.hpp>                     // Hash (sha256d)
#include <core/uint256.hpp>

#include <cstdint>
#include <span>
#include <vector>

namespace {

// Leaf fixture: sha256d of a single byte. Matches CPython
//   hashlib.sha256(hashlib.sha256(bytes([i])).digest()).digest()
uint256 leaf(uint8_t b) {
    unsigned char x = b;
    return Hash(std::span<const unsigned char>(&x, 1));
}

// Independent canonical merkle-root reduction (NOT the production walk):
// pairwise SHA256d over the whole layer, duplicate the last on odd width.
uint256 reference_root(std::vector<uint256> layer) {
    while (layer.size() > 1) {
        if (layer.size() % 2 == 1) layer.push_back(layer.back());
        std::vector<uint256> next;
        next.reserve(layer.size() / 2);
        for (size_t i = 0; i + 1 < layer.size(); i += 2) {
            unsigned char buf[64];
            std::memcpy(buf,      layer[i].data(),     32);
            std::memcpy(buf + 32, layer[i + 1].data(), 32);
            next.push_back(Hash(std::span<const unsigned char>(buf, 64)));
        }
        layer.swap(next);
    }
    return layer.empty() ? uint256() : layer[0];
}

std::string hex_internal(const uint256& h) {
    auto c = h.GetChars();
    return HexStr(std::span<const unsigned char>(c.data(), c.size()));
}

// Production path: build the index-0 branch and walk gentx (=leaf[0]) back.
uint256 production_root(const std::vector<uint256>& txs) {
    dash::MerkleLink link;
    link.m_branch = dash::coinbase::merkle_branches_raw(txs);
    link.m_index  = 0;  // coinbase / gentx is always at position 0
    return dash::check_merkle_link(txs[0], link);
}

struct Kat { int n; const char* root_hex; };

// KAT vectors — CPython hashlib double-SHA256, internal (raw-digest) byte order.
const Kat KATS[] = {
    {1, "1406e05881e299367766d313e26c05564ec91bf721d31726bd6e46e60689539a"},
    {2, "4bbe83bc38ebe2bcc7520d234139df1c0eb9ffa51f83eab1c5129b5b906b7655"},
    {3, "e129dfe02f567fc612d126596d43406144f40a771810ac7143421d2df3e5c1d0"},
    {5, "f4113849d628f7c3bc91cc0ff785a6aee3ee236c1c912b28cc09c44f9f97b748"},
    {7, "7de65c7d57cdc72971c9beab94af6ad4e99f233fb6ccebd2b4b19f13697ca54d"},
};

}  // namespace

// Production walk == independent reference reduction, across tree shapes
// (1 leaf, even, odd/duplicate-last). This is the merkle-root-equality
// precondition itself.
TEST(DashConformanceMerkle, ProductionWalkMatchesReferenceReduction) {
    for (const auto& k : KATS) {
        std::vector<uint256> txs;
        for (int i = 0; i < k.n; ++i) txs.push_back(leaf(static_cast<uint8_t>(i)));
        EXPECT_EQ(production_root(txs), reference_root(txs))
            << "n=" << k.n << ": gentx+merkle_link did not reconstruct the full-tree root";
    }
}

// Both paths must equal the out-of-band CPython KAT — locks byte order and
// guards against a coordinated regression in BOTH C++ implementations.
TEST(DashConformanceMerkle, MatchesOutOfBandKat) {
    for (const auto& k : KATS) {
        std::vector<uint256> txs;
        for (int i = 0; i < k.n; ++i) txs.push_back(leaf(static_cast<uint8_t>(i)));
        EXPECT_EQ(hex_internal(production_root(txs)), std::string(k.root_hex))
            << "n=" << k.n << ": production root != CPython KAT";
        EXPECT_EQ(hex_internal(reference_root(txs)), std::string(k.root_hex))
            << "n=" << k.n << ": reference root != CPython KAT";
    }
}

// A single transaction (coinbase only): the gentx IS the merkle root, branch
// is empty, and the walk must be the identity.
TEST(DashConformanceMerkle, SingleTxRootIsGentx) {
    std::vector<uint256> txs{leaf(0)};
    EXPECT_TRUE(dash::coinbase::merkle_branches_raw(txs).empty());
    EXPECT_EQ(production_root(txs), txs[0]);
}

// ── Payout-script-encoding conformance (S6 slice 2) ──────────────────────────
// Before any PPLNS payout SET can be conformance-checked against DASH's own
// older oracle (frstrtr/p2pool-dash data.py), each recipient's scriptPubKey
// must encode byte-identically. Dash payouts are ALWAYS P2PKH (no segwit):
//     OP_DUP OP_HASH160 <0x14> <20-byte hash160> OP_EQUALVERIFY OP_CHECKSIG
// i.e. 76 a9 14 <hash> 88 ac, total 25 bytes, with the hash emitted in uint160
// internal (GetChars) order and NO reversal. These KATs pin that encoding with
// no node dependency; the donation cross-check proves two independent
// representations of the same recipient agree.
namespace {

uint160 h160(const std::vector<unsigned char>& v) { return uint160(v); }

std::string hex_bytes(const std::vector<unsigned char>& v) {
    return HexStr(std::span<const unsigned char>(v.data(), v.size()));
}

// p2pool-dash DONATION_SCRIPT hash160 (data.py) — the 20 bytes between the
// 76 a9 14 prefix and the 88 ac suffix of dash::DONATION_SCRIPT.
const std::vector<unsigned char> DONATION_H160 = {
    0x20, 0xcb, 0x5c, 0x22, 0xb1, 0xe4, 0xd5, 0x94,
    0x7e, 0x5c, 0x11, 0x2c, 0x76, 0x96, 0xb5, 0x1a,
    0xd9, 0xaf, 0x3c, 0x61
};

struct ScriptKat { std::vector<unsigned char> h160; const char* script_hex; };

}  // namespace

// Canonical P2PKH shape for arbitrary hash160s, hash bytes in GetChars order.
TEST(DashConformancePayoutScript, CanonicalP2PKHStructure) {
    const std::vector<std::vector<unsigned char>> hashes = {
        std::vector<unsigned char>(20, 0x00),
        std::vector<unsigned char>(20, 0xff),
        DONATION_H160,
    };
    for (const auto& hv : hashes) {
        auto s = dash::pubkey_hash_to_script2(h160(hv));
        ASSERT_EQ(s.size(), 25u);
        EXPECT_EQ(s[0], 0x76); EXPECT_EQ(s[1], 0xa9); EXPECT_EQ(s[2], 0x14);
        EXPECT_EQ(s[23], 0x88); EXPECT_EQ(s[24], 0xac);
        for (size_t i = 0; i < 20; ++i)
            EXPECT_EQ(s[3 + i], hv[i]) << "hash byte " << i << " not in GetChars order";
    }
}

// Out-of-band KAT: full 25-byte P2PKH script hex for fixed hash160s.
TEST(DashConformancePayoutScript, MatchesOutOfBandKat) {
    const ScriptKat kats[] = {
        { std::vector<unsigned char>(20, 0x00),
          "76a914000000000000000000000000000000000000000088ac" },
        { DONATION_H160,
          "76a91420cb5c22b1e4d5947e5c112c7696b51ad9af3c6188ac" },
    };
    for (const auto& k : kats)
        EXPECT_EQ(hex_bytes(dash::pubkey_hash_to_script2(h160(k.h160))),
                  std::string(k.script_hex));
}

// Two independent representations of the donation recipient agree: the literal
// DONATION_SCRIPT array (data.py copy) equals the script-builder over the
// donation hash160. Catches an accidental edit to either path.
TEST(DashConformancePayoutScript, DonationScriptIsP2PKHOverDonationHash) {
    EXPECT_EQ(dash::pubkey_hash_to_script2(h160(DONATION_H160)),
              dash::DONATION_SCRIPT);
}
