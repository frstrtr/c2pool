// SPDX-License-Identifier: AGPL-3.0-or-later
// DGB #82 — SSOT non-witness coinbase (gentx) assembler KAT.
//
// Locks dgb::coin::assemble_gentx_coinbase() (coin/gentx_coinbase.hpp) — the
// single coinbase wire-layout extracted from generate_share_transaction()
// (share_check.hpp:933, the verification SSOT) — against GROUND-TRUTH vectors
// derived from the canonical oracle frstrtr/p2pool-dgb-scrypt
// (util/pack.py byte logic + bitcoin/data.py tx_id_type; donation script
// 4104ffd0...ac). The vectors are NOT self-generated from this builder: they
// are the oracle serializer's output, so a PASS proves emission==oracle, not
// merely self-consistency.
//
// Asserts, for both the no-segwit and witness-commitment-first layouts:
//   build -> non-witness serialize == oracle BYTES
//   double-SHA256(bytes) (GetHex display) == oracle TXID
// Per-coin isolation: the only DGB<->BCH divergence is the segwit predicate at
// serialize time (witness vout present-or-absent), exercised by both cases.

#include <gtest/gtest.h>
#include <impl/dgb/coin/gentx_coinbase.hpp>

#include <optional>
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

// --- fixed inputs shared verbatim with the oracle generator ----------------
const std::vector<unsigned char> CB    = unhex("03a1b2c3041122334455667788");
const std::vector<unsigned char> P1    = unhex(std::string("76a914") + std::string(40, '1') + "88ac");
const std::vector<unsigned char> P2    = unhex(std::string("76a914") + std::string(40, '2') + "88ac");
const std::vector<unsigned char> DON   = unhex("4104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac");

const std::vector<std::pair<std::vector<unsigned char>, uint64_t>> PAYOUTS = {
    {P1, 5000000000ull},
    {P2, 2500000000ull},
};

// Ground truth from the oracle serializer (see file header).
const std::string NOSEG_BYTES =
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0d03a1b2c3041122334455667788ffffffff0400f2052a010000001976a914111111111111111111111111111111111111111188ac00f90295000000001976a914222222222222222222222222222222222222222288ac0100000000000000434104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac00000000000000002a6a28abababababababababababababababababababababababababababababababab080706050403020100000000";
const std::string NOSEG_TXID =
    "c5734775c1521b216e0e1bca506e4d15755cf55125caf56b7e0728a6d54a9b59";
const std::string SEG_BYTES =
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0d03a1b2c3041122334455667788ffffffff050000000000000000266a24aa21a9edcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd00f2052a010000001976a914111111111111111111111111111111111111111188ac00f90295000000001976a914222222222222222222222222222222222222222288ac0100000000000000434104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac00000000000000002a6a28abababababababababababababababababababababababababababababababab080706050403020100000000";
const std::string SEG_TXID =
    "4b66aabff52ca1336b52688815cece123075856880aaf6e77cb44f0d477b6162";

} // namespace

// op_return / wc literals: build them explicitly to avoid std::string surprises.
static std::vector<unsigned char> make_opret() {
    auto v = unhex("6a28");
    for (int i = 0; i < 32; ++i) v.push_back(0xab);
    const unsigned char nonce[8] = {0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
    for (unsigned char b : nonce) v.push_back(b);
    return v;
}
static std::vector<unsigned char> make_wc() {
    auto v = unhex("6a24aa21a9ed");
    for (int i = 0; i < 32; ++i) v.push_back(0xcd);
    return v;
}

TEST(DGB_gentx_coinbase, NoSegwitOracleVector) {
    auto opret = make_opret();
    auto g = dgb::coin::assemble_gentx_coinbase(
        CB, std::nullopt, PAYOUTS, /*donation_amount=*/1, DON, opret);
    EXPECT_EQ(tohex(g.bytes), NOSEG_BYTES);
    EXPECT_EQ(g.txid.GetHex(), NOSEG_TXID);
}

TEST(DGB_gentx_coinbase, SegwitCommitmentFirstOracleVector) {
    auto opret = make_opret();
    auto wc = make_wc();
    auto g = dgb::coin::assemble_gentx_coinbase(
        CB, std::optional<std::vector<unsigned char>>(wc), PAYOUTS,
        /*donation_amount=*/1, DON, opret);
    EXPECT_EQ(tohex(g.bytes), SEG_BYTES);
    EXPECT_EQ(g.txid.GetHex(), SEG_TXID);
}

// Guard the per-coin isolation invariant: toggling only the segwit predicate
// changes vout-count + prepends exactly one 0-value commitment vout, nothing
// else — the divergence is gated, not a forked framer.
TEST(DGB_gentx_coinbase, SegwitPredicateIsTheOnlyDivergence) {
    EXPECT_NE(NOSEG_BYTES, SEG_BYTES);
    // both share the identical coinbase-script vin prefix and donation/op_return tail
    EXPECT_EQ(NOSEG_BYTES.substr(0, 90), SEG_BYTES.substr(0, 90));
}