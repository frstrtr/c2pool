// SPDX-License-Identifier: MIT
//
// DASH S8 stratum extranonce coinb1/coinb2 split contract KAT.
//
// Pins the mining.subscribe + mining.notify wire *split* that the get_work()
// slot KAT (test_dash_stratum_binding) and the notify merkle KAT
// (test_dash_stratum_notify_roundtrip) do not: the server ships the coinbase to
// the miner as two hex halves -- coinb1 || <extranonce2> || coinb2 -- and
// advertises an extranonce2_size the miner must fill EXACTLY. This leaf binds
// the REAL landed producer dash::coinbase::split_coinb()
// (src/impl/dash/coinbase_builder.hpp) and proves:
//   * the split leaves a gap of exactly EXTRANONCE2_SIZE (==8) bytes between
//     coinb1 and coinb2 -- i.e. the advertised extranonce2_size the server
//     returns in mining.subscribe equals the reserved nonce64 slot width;
//   * coinb1 == bytes[0 : nonce64_offset], coinb2 == bytes[nonce64_offset+8 :]
//     (no overlap with the slot, no gap, no truncation);
//   * reassembling coinb1 || extranonce2 || coinb2 reproduces the EXACT coinbase
//     whose sha256d the slot-substitution KATs golden-anchor -- so the split
//     producer and the slot-substitution producer agree byte-for-byte;
//   * distinct extranonce2 values propagate injectively through the reassembly;
//   * a wrong-width extranonce2 (7 or 9 bytes) reassembles to a coinbase of the
//     wrong length -- the advertised size is load-bearing, not decorative.
//
// Oracle (frstrtr/p2pool-dash @9a0a609):
//   p2pool/dash/stratum.py  rpc_subscribe returns
//        [subscription_details, extranonce1, extranonce2_size(=COINBASE_NONCE_LENGTH)]
//        -- the size the miner must fill; here COINBASE_NONCE_LENGTH == 8.
//   p2pool/work.py get_work -> coinb1/coinb2 hex around the extranonce slot.
//
// Non-circular: the coinbase-hash golden anchors are computed by independent
// Python hashlib sha256d (NOT the oracle code and NOT split_coinb) -- identical
// to the anchors the notify-roundtrip leaf pins, cross-binding the two
// producers. The coinb1/coinb2 hex anchors are the raw fixture bytes
// (independently enumerable).
//
// Fenced: test/ + build.yml allowlist only. Non-consensus, socket-free,
// node-free -- pure synthetic CoinbaseLayout, no live node / RPC / P2P.

#include <gtest/gtest.h>

#include <cstddef>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include <impl/dash/coinbase_builder.hpp>  // CoinbaseLayout, CoinbSplit, split_coinb, sha256d, EXTRANONCE2_SIZE
#include <btclibs/util/strencodings.h>     // HexStr, ParseHex
#include <core/uint256.hpp>

using dash::coinbase::CoinbaseLayout;
using dash::coinbase::CoinbSplit;
using dash::coinbase::split_coinb;
using dash::coinbase::sha256d;
using dash::coinbase::EXTRANONCE2_SIZE;

namespace {

// Same 40-byte synthetic coinbase as the slot/notify KATs: bytes[i] = i, with
// the 8-byte nonce64 (extranonce2) slot at [28,36). nonce64_offset =
// 40 - locktime(4) - nonce64(8) = 28.
constexpr size_t kTotal       = 40;
constexpr size_t kNonceOffset = 28;

CoinbaseLayout make_layout() {
    CoinbaseLayout lay;
    lay.bytes.resize(kTotal);
    for (size_t i = 0; i < kTotal; ++i) lay.bytes[i] = static_cast<unsigned char>(i);
    for (size_t i = kNonceOffset; i < kNonceOffset + EXTRANONCE2_SIZE; ++i) lay.bytes[i] = 0;
    lay.ref_hash_offset = kNonceOffset - 32;   // 32B ref_hash region precedes the slot
    lay.nonce64_offset  = kNonceOffset;
    return lay;
}

// Reassemble coinb1 || extranonce2 || coinb2 exactly as a miner does, returning
// the raw bytes. e2 may be any width (used by the wrong-width guard).
std::vector<unsigned char> reassemble(const CoinbSplit& s, std::span<const unsigned char> e2) {
    std::vector<unsigned char> b1 = ParseHex(s.coinb1_hex);
    std::vector<unsigned char> b2 = ParseHex(s.coinb2_hex);
    std::vector<unsigned char> out;
    out.reserve(b1.size() + e2.size() + b2.size());
    out.insert(out.end(), b1.begin(), b1.end());
    out.insert(out.end(), e2.begin(), e2.end());
    out.insert(out.end(), b2.begin(), b2.end());
    return out;
}

uint256 reassembled_hash(const CoinbSplit& s, std::span<const unsigned char> e2) {
    auto cb = reassemble(s, e2);
    return sha256d(std::span<const unsigned char>(cb.data(), cb.size()));
}

const std::vector<unsigned char> E2_ZERO(8, 0x00);
const std::vector<unsigned char> E2_A{0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8};
const std::vector<unsigned char> E2_B{0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8};

// Independent fixture-byte anchors (coinb1 = bytes 0x00..0x1b, coinb2 = 0x24..0x27).
const char* GOLD_COINB1 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b";
const char* GOLD_COINB2 = "24252627";

// Independent Python hashlib sha256d anchors (display/GetHex form) -- identical
// to the coinbase-hash goldens the notify-roundtrip leaf pins, cross-binding
// split_coinb to the slot-substitution producer.
const char* GOLD_CBHASH_Z = "b0d22de8e7f6765f9d8c289ecd77ad8e0ab6a88c2a4ccf594c509d7775bb54ab";
const char* GOLD_CBHASH_A = "22a146527ac0731341d026480042a55cee0bdb804043b570af24feb9e76f2c8b";
const char* GOLD_CBHASH_B = "04c8f4793537be307eaa2166642accc8265add0a59ccf4d01525f0ec54c6237a";

} // namespace

// (1) Split geometry: coinb1 ends at the slot, coinb2 begins after it, and the
//     gap between them is EXACTLY EXTRANONCE2_SIZE bytes -- the advertised
//     extranonce2_size the server returns in mining.subscribe.
TEST(DashStratumExtranonceSplit, SplitLeavesExactSlotGap) {
    auto lay = make_layout();
    CoinbSplit s = split_coinb(lay);
    const size_t b1 = s.coinb1_hex.size() / 2;
    const size_t b2 = s.coinb2_hex.size() / 2;
    EXPECT_EQ(b1, kNonceOffset);                          // coinb1 == bytes[0:offset]
    EXPECT_EQ(b2, kTotal - kNonceOffset - EXTRANONCE2_SIZE);
    // The gap the miner must fill == the advertised extranonce2_size == slot width.
    EXPECT_EQ(kTotal - b1 - b2, EXTRANONCE2_SIZE);
    EXPECT_EQ(EXTRANONCE2_SIZE, 8u);                      // == oracle COINBASE_NONCE_LENGTH
}

// (2) coinb1 / coinb2 are the exact fixture halves around the slot (byte-parity).
TEST(DashStratumExtranonceSplit, HalvesAreExactBytesAroundSlot) {
    CoinbSplit s = split_coinb(make_layout());
    EXPECT_EQ(s.coinb1_hex, GOLD_COINB1);
    EXPECT_EQ(s.coinb2_hex, GOLD_COINB2);
}

// (3) Reassembly contract: coinb1 || extranonce2 || coinb2 reproduces the EXACT
//     coinbase whose sha256d the slot/notify KATs golden-anchor -- the split
//     producer and the slot-substitution producer agree byte-for-byte.
TEST(DashStratumExtranonceSplit, ReassemblyReproducesGoldenCoinbase) {
    CoinbSplit s = split_coinb(make_layout());
    EXPECT_EQ(reassembled_hash(s, E2_ZERO).GetHex(), GOLD_CBHASH_Z);
    EXPECT_EQ(reassembled_hash(s, E2_A).GetHex(),    GOLD_CBHASH_A);
    EXPECT_EQ(reassembled_hash(s, E2_B).GetHex(),    GOLD_CBHASH_B);
}

// (4) Injectivity: distinct extranonce2 -> distinct reassembled coinbase hash,
//     so the slot the split reserves demonstrably carries the miner's nonce.
TEST(DashStratumExtranonceSplit, DistinctExtranonce2AreInjective) {
    CoinbSplit s = split_coinb(make_layout());
    uint256 z = reassembled_hash(s, E2_ZERO);
    uint256 a = reassembled_hash(s, E2_A);
    uint256 b = reassembled_hash(s, E2_B);
    EXPECT_NE(z, a);
    EXPECT_NE(z, b);
    EXPECT_NE(a, b);
}

// (5) Size is load-bearing: a wrong-width extranonce2 reassembles to a coinbase
//     of the wrong length. Only the advertised EXTRANONCE2_SIZE reproduces 40B.
TEST(DashStratumExtranonceSplit, WrongWidthExtranonce2BreaksLength) {
    CoinbSplit s = split_coinb(make_layout());
    const std::vector<unsigned char> e2_short(EXTRANONCE2_SIZE - 1, 0xEE);
    const std::vector<unsigned char> e2_long(EXTRANONCE2_SIZE + 1, 0xEE);
    EXPECT_EQ(reassemble(s, E2_A).size(),     kTotal);
    EXPECT_NE(reassemble(s, e2_short).size(), kTotal);
    EXPECT_NE(reassemble(s, e2_long).size(),  kTotal);
}

// (6) Bad offset guard: split_coinb throws when the nonce64 slot runs past the
//     coinbase end (mirrors the in-source runtime_error precondition).
TEST(DashStratumExtranonceSplit, BadOffsetThrows) {
    CoinbaseLayout lay = make_layout();
    lay.nonce64_offset = lay.bytes.size();   // slot would start at EOF -> +8 overruns
    EXPECT_THROW(split_coinb(lay), std::runtime_error);
}
