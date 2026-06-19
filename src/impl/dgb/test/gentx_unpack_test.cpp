// DGB #82 — gentx-bytes -> MutableTransaction unpack round-trip KAT.
//
// Locks dgb::coin::unpack_gentx_coinbase() (coin/gentx_unpack.hpp) — the
// INVERSE of #173's GentxCoinbase exposure — as the codec step that the
// run-loop uses to turn the share's SSOT non-witness gentx bytes back into the
// MutableTransaction that reconstruct_won_block injects at block tx index 0.
//
// The proof is two-pronged and uses the SAME ground-truth vectors as
// gentx_coinbase_test.cpp (derived from the canonical oracle
// frstrtr/p2pool-dgb-scrypt, NOT self-generated):
//   1. ORACLE-PINNED: unpack(oracle_bytes) -> re-serialize TX_NO_WITNESS ==
//      oracle_bytes EXACTLY, and txid == oracle_txid. This is the byte-exact,
//      txid-stable round-trip the merkle_root walk depends on (integrator
//      2026-06-19: any drift here corrupts the assembled block).
//   2. INVERSE PAIRING: assemble_gentx_coinbase(...) -> unpack(...) recovers a
//      tx whose non-witness bytes and txid equal the assembler's GentxCoinbase
//      {bytes, txid} — proving unpack is the exact inverse of the #173 path
//      for both the no-segwit and witness-commitment-first layouts.
//
// Per-coin isolation: src/impl/dgb/ only; the only DGB<->BCH divergence is the
// segwit predicate at assemble time (vout count), exercised by both layouts;
// the unpacked gentx carries no witness either way (HasWitness()==false).

#include <gtest/gtest.h>
#include <impl/dgb/coin/gentx_unpack.hpp>
#include <impl/dgb/coin/gentx_coinbase.hpp>

#include <core/pack.hpp>

#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
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
std::string noseg_hex(const dgb::coin::MutableTransaction& tx) {
    auto packed = pack(dgb::coin::TX_NO_WITNESS(tx));
    auto sp = packed.get_span();
    std::vector<unsigned char> v(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    return tohex(v);
}

// --- fixed inputs shared verbatim with gentx_coinbase_test / the oracle ----
const std::vector<unsigned char> CB  = unhex("03a1b2c3041122334455667788");
const std::vector<unsigned char> P1  = unhex(std::string("76a914") + std::string(40, '1') + "88ac");
const std::vector<unsigned char> P2  = unhex(std::string("76a914") + std::string(40, '2') + "88ac");
const std::vector<unsigned char> DON = unhex("4104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac");

const std::vector<std::pair<std::vector<unsigned char>, uint64_t>> PAYOUTS = {
    {P1, 5000000000ull},
    {P2, 2500000000ull},
};

// Ground truth from the oracle serializer (identical to gentx_coinbase_test).
const std::string NOSEG_BYTES =
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0d03a1b2c3041122334455667788ffffffff0400f2052a010000001976a914111111111111111111111111111111111111111188ac00f90295000000001976a914222222222222222222222222222222222222222288ac0100000000000000434104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac00000000000000002a6a28abababababababababababababababababababababababababababababababab080706050403020100000000";
const std::string NOSEG_TXID =
    "c5734775c1521b216e0e1bca506e4d15755cf55125caf56b7e0728a6d54a9b59";
const std::string SEG_BYTES =
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0d03a1b2c3041122334455667788ffffffff050000000000000000266a24aa21a9edcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd00f2052a010000001976a914111111111111111111111111111111111111111188ac00f90295000000001976a914222222222222222222222222222222222222222288ac0100000000000000434104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac00000000000000002a6a28abababababababababababababababababababababababababababababababab080706050403020100000000";
const std::string SEG_TXID =
    "4b66aabff52ca1336b52688815cece123075856880aaf6e77cb44f0d477b6162";

std::vector<unsigned char> make_opret() {
    auto v = unhex("6a28");
    for (int i = 0; i < 32; ++i) v.push_back(0xab);
    const unsigned char nonce[8] = {0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
    for (unsigned char b : nonce) v.push_back(b);
    return v;
}
std::vector<unsigned char> make_wc() {
    auto v = unhex("6a24aa21a9ed");
    for (int i = 0; i < 32; ++i) v.push_back(0xcd);
    return v;
}

} // namespace

// (1a) ORACLE round-trip, no-segwit layout: bytes exact + txid stable.
TEST(DGB_gentx_unpack, NoSegwitOracleRoundTrip) {
    auto u = dgb::coin::unpack_gentx_coinbase(unhex(NOSEG_BYTES));
    EXPECT_EQ(noseg_hex(u.tx), NOSEG_BYTES);   // byte-exact non-witness re-serialize
    EXPECT_EQ(u.txid.GetHex(), NOSEG_TXID);    // gentx_hash stable
    EXPECT_FALSE(u.tx.HasWitness());           // no witness drift
}

// (1b) ORACLE round-trip, witness-commitment-first layout: still non-witness.
TEST(DGB_gentx_unpack, SegwitCommitmentFirstOracleRoundTrip) {
    auto u = dgb::coin::unpack_gentx_coinbase(unhex(SEG_BYTES));
    EXPECT_EQ(noseg_hex(u.tx), SEG_BYTES);
    EXPECT_EQ(u.txid.GetHex(), SEG_TXID);
    EXPECT_FALSE(u.tx.HasWitness());           // commitment is a vout, not a witness
}

// Structural sanity: the recovered coinbase has the p2pool gentx shape.
TEST(DGB_gentx_unpack, RecoversCoinbaseShape) {
    auto u = dgb::coin::unpack_gentx_coinbase(unhex(NOSEG_BYTES));
    EXPECT_EQ(u.tx.version, 1);
    EXPECT_EQ(u.tx.locktime, 0u);
    ASSERT_EQ(u.tx.vin.size(), 1u);
    EXPECT_TRUE(u.tx.vin[0].prevout.hash.IsNull());        // coinbase: null prev
    EXPECT_EQ(u.tx.vin[0].prevout.index, 0xffffffffu);
    EXPECT_EQ(u.tx.vin[0].sequence, 0xffffffffu);
    EXPECT_EQ(u.tx.vout.size(), 4u);                       // P1,P2,donation,op_return
}

// (2) INVERSE PAIRING: assemble (#173 path) -> unpack recovers bytes + txid.
TEST(DGB_gentx_unpack, IsInverseOfAssembleNoSegwit) {
    auto opret = make_opret();
    auto g = dgb::coin::assemble_gentx_coinbase(
        CB, std::nullopt, PAYOUTS, /*donation_amount=*/1, DON, opret);
    auto u = dgb::coin::unpack_gentx_coinbase(g.bytes);
    EXPECT_EQ(noseg_hex(u.tx), tohex(g.bytes));   // exact inverse
    EXPECT_EQ(u.txid.GetHex(), g.txid.GetHex());  // txid == GentxCoinbase.txid
}

TEST(DGB_gentx_unpack, IsInverseOfAssembleSegwitCommitment) {
    auto opret = make_opret();
    auto wc = make_wc();
    auto g = dgb::coin::assemble_gentx_coinbase(
        CB, std::optional<std::vector<unsigned char>>(wc), PAYOUTS,
        /*donation_amount=*/1, DON, opret);
    auto u = dgb::coin::unpack_gentx_coinbase(g.bytes);
    EXPECT_EQ(noseg_hex(u.tx), tohex(g.bytes));
    EXPECT_EQ(u.txid.GetHex(), g.txid.GetHex());
}

// Robustness: a trailing byte past a complete tx is a malformed gentx -> throw.
TEST(DGB_gentx_unpack, TrailingBytesThrow) {
    auto bytes = unhex(NOSEG_BYTES);
    bytes.push_back(0x00);   // one extra byte after a complete tx
    EXPECT_THROW(dgb::coin::unpack_gentx_coinbase(bytes), std::out_of_range);
}
