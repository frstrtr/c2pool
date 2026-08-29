// SPDX-License-Identifier: AGPL-3.0-or-later
// BTC won-block reconstructor -- gentx-bytes -> MutableTransaction unpack KAT.
//
// Locks btc::coin::unpack_gentx_coinbase() (coin/gentx_unpack.hpp), the codec
// step the run-loop uses to turn a share's SSOT non-witness gentx bytes back
// into the MutableTransaction reconstruct_won_block injects at block tx index 0.
//
// The BTC non-witness coinbase serialization is byte-identical to the generic
// Bitcoin tx codec (version|vin|vout|locktime), so the ground-truth vectors are
// coin-agnostic: each (bytes, txid) pair is a pure double-SHA256 relation over
// the exact bytes, shared verbatim with the DGB sibling KAT
// (src/impl/dgb/test/gentx_unpack_test.cpp) whose CI already pins the pairing.
// This test proves BTC's identical codec recovers the SAME bytes + txid.
//
// Proof legs (all ORACLE-PINNED against fixed vectors -- no self-generation):
//   1. unpack(oracle_bytes) -> re-serialize TX_NO_WITNESS == oracle_bytes
//      EXACTLY, and txid == oracle_txid (the byte-exact, txid-stable round-trip
//      the merkle_root walk depends on; any drift corrupts the assembled block).
//   2. HasWitness()==false on both layouts (no witness drift; the segwit
//      commitment is a vout, not a witness).
//   3. Structural sanity: the recovered coinbase carries the p2pool gentx shape.
//   4. A trailing byte past a complete tx is a malformed gentx -> throw.
//
// The inverse-pairing-vs-SSOT leg (assemble -> unpack) lands with the BTC
// gentx_coinbase.hpp SSOT-exposure slice, which does not yet exist on BTC.
//
// Per-coin isolation: src/impl/btc/ only. p2pool-merged-v36 surface: NONE.

#include <gtest/gtest.h>
#include <impl/btc/coin/gentx_unpack.hpp>

#include <core/pack.hpp>

#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::vector<unsigned char> unhex(const std::string& h) {
    std::vector<unsigned char> v; v.reserve(h.size() / 2);
    auto nyb = [](char c) -> int { return (c <= '9') ? c - '0' : (c | 0x20) - 'a' + 10; };
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        v.push_back(static_cast<unsigned char>((nyb(h[i]) << 4) | nyb(h[i + 1])));
    return v;
}
std::string tohex(const std::vector<unsigned char>& v) {
    static const char* H = "0123456789abcdef";
    std::string s; s.reserve(v.size() * 2);
    for (unsigned char b : v) { s.push_back(H[b >> 4]); s.push_back(H[b & 0xf]); }
    return s;
}

// Re-serialize a MutableTransaction in non-witness form and hex it (the exact
// bytes the txid + merkle_root walk are taken over).
std::string noseg_hex(const btc::coin::MutableTransaction& tx) {
    auto packed = pack(btc::coin::TX_NO_WITNESS(tx));
    auto sp = packed.get_span();
    std::vector<unsigned char> v(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    return tohex(v);
}

// Ground truth: coin-agnostic non-witness coinbase serializations + their
// SHA256d txids, shared verbatim with the DGB sibling KAT.
const std::string NOSEG_BYTES =
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0d03a1b2c3041122334455667788ffffffff0400f2052a010000001976a914111111111111111111111111111111111111111188ac00f90295000000001976a914222222222222222222222222222222222222222288ac0100000000000000434104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac00000000000000002a6a28abababababababababababababababababababababababababababababababab080706050403020100000000";
const std::string NOSEG_TXID =
    "c5734775c1521b216e0e1bca506e4d15755cf55125caf56b7e0728a6d54a9b59";
const std::string SEG_BYTES =
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0d03a1b2c3041122334455667788ffffffff050000000000000000266a24aa21a9edcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd00f2052a010000001976a914111111111111111111111111111111111111111188ac00f90295000000001976a914222222222222222222222222222222222222222288ac0100000000000000434104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac00000000000000002a6a28abababababababababababababababababababababababababababababababab080706050403020100000000";
const std::string SEG_TXID =
    "4b66aabff52ca1336b52688815cece123075856880aaf6e77cb44f0d477b6162";

} // namespace

// (1a) ORACLE round-trip, no-segwit layout: bytes exact + txid stable.
TEST(BTC_gentx_unpack, NoSegwitOracleRoundTrip) {
    auto u = btc::coin::unpack_gentx_coinbase(unhex(NOSEG_BYTES));
    EXPECT_EQ(noseg_hex(u.tx), NOSEG_BYTES);   // byte-exact non-witness re-serialize
    EXPECT_EQ(u.txid.GetHex(), NOSEG_TXID);    // gentx_hash stable
    EXPECT_FALSE(u.tx.HasWitness());           // no witness drift
}

// (1b) ORACLE round-trip, witness-commitment-first layout: still non-witness.
TEST(BTC_gentx_unpack, SegwitCommitmentFirstOracleRoundTrip) {
    auto u = btc::coin::unpack_gentx_coinbase(unhex(SEG_BYTES));
    EXPECT_EQ(noseg_hex(u.tx), SEG_BYTES);
    EXPECT_EQ(u.txid.GetHex(), SEG_TXID);
    EXPECT_FALSE(u.tx.HasWitness());           // commitment is a vout, not a witness
}

// (3) Structural sanity: the recovered coinbase has the p2pool gentx shape.
TEST(BTC_gentx_unpack, RecoversCoinbaseShape) {
    auto u = btc::coin::unpack_gentx_coinbase(unhex(NOSEG_BYTES));
    EXPECT_EQ(u.tx.version, 1);
    EXPECT_EQ(u.tx.locktime, 0u);
    ASSERT_EQ(u.tx.vin.size(), 1u);
    EXPECT_TRUE(u.tx.vin[0].prevout.hash.IsNull());        // coinbase: null prev
    EXPECT_EQ(u.tx.vin[0].prevout.index, 0xffffffffu);
    EXPECT_EQ(u.tx.vin[0].sequence, 0xffffffffu);
    EXPECT_EQ(u.tx.vout.size(), 4u);                       // P1,P2,donation,op_return
}

// (4) Robustness: a trailing byte past a complete tx is a malformed gentx -> throw.
TEST(BTC_gentx_unpack, TrailingBytesThrow) {
    auto bytes = unhex(NOSEG_BYTES);
    bytes.push_back(0x00);   // one extra byte after a complete tx
    EXPECT_THROW(btc::coin::unpack_gentx_coinbase(bytes), std::out_of_range);
}
