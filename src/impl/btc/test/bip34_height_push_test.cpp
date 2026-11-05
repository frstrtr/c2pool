// SPDX-License-Identifier: AGPL-3.0-or-later
// BIP34 coinbase height-push KAT (BTC port of DGB #1810).
//
// Pins btc::stratum::bip34_height_push to Bitcoin Core's `CScript() << nHeight`
// encoding. Heights 0..16 are small-int opcodes (OP_0, OP_1..OP_16); the
// pre-fix data-push form ("0101" for height 1) made any block won at height
// 0..16 on a fresh regtest/testnet chain a bad-cb-height reject. Heights >= 17
// are minimal little-endian data pushes with a sign-bit pad, unchanged.

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include <impl/btc/stratum/bip34_height.hpp>

using btc::stratum::bip34_height_push;

namespace {

std::string tohex(const std::vector<uint8_t>& v)
{
    static const char* kHex = "0123456789abcdef";
    std::string s;
    for (uint8_t b : v) {
        s.push_back(kHex[b >> 4]);
        s.push_back(kHex[b & 0x0f]);
    }
    return s;
}

} // namespace

// 0 -> OP_0, 1..16 -> OP_1..OP_16 (0x51..0x60), never a 1-byte data push.
TEST(BtcBip34HeightPush, SmallHeightsAreOpcodes) {
    EXPECT_EQ(tohex(bip34_height_push(0)), "00");
    EXPECT_EQ(tohex(bip34_height_push(1)), "51");
    EXPECT_EQ(tohex(bip34_height_push(16)), "60");
    for (uint32_t h = 1; h <= 16; ++h) {
        const auto p = bip34_height_push(h);
        ASSERT_EQ(p.size(), 1u) << "height " << h;
        EXPECT_EQ(p[0], 0x50 + h) << "height " << h;
    }
}

// 17 is the first data push; 0x7f is the largest 1-byte push without a pad.
TEST(BtcBip34HeightPush, FirstDataPushes) {
    EXPECT_EQ(tohex(bip34_height_push(17)), "0111");
    EXPECT_EQ(tohex(bip34_height_push(0x7f)), "017f");
}

// 0x80 has the high bit set -> zero pad, push 2 bytes (not a bare 0x80,
// which a script integer would parse as negative zero).
TEST(BtcBip34HeightPush, SignBitPad) {
    EXPECT_EQ(tohex(bip34_height_push(0x80)), "028000");
}

// 21,000,000 = 0x01406f40 -> push 4 bytes LE, no pad (top byte 0x01).
TEST(BtcBip34HeightPush, MainnetScaleHeight) {
    EXPECT_EQ(tohex(bip34_height_push(21000000)), "04406f4001");
}
