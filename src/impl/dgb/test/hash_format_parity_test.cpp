// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// dgb_hash_format_parity_test -- FENCED, additive KAT pinning the pure GBT
// block-hash display formatter dgb::coin::u256_be_display_hex lifted into
// coin/hash_format.hpp.
//
// u256_be_display_hex renders a 256-bit value (coin/dgb_arith256.hpp u256, a
// little-endian limb array with limb[0] least-significant) as the
// GBT-conventional big-endian display hex: most-significant limb first, 64
// lowercase hex digits, no 0x prefix -- the encoding the stratum work source
// and the embedded work path both emit for "previousblockhash". A 1-nibble
// divergence in limb/byte ordering there means the two callers of
// build_work_template could emit a prevhash the parent daemon never accepts.
//
// The anchor is NON-CIRCULAR: the DigiByte mainnet genesis block hash
// 7497ea1b465eb39f1c8f507bc877078fe016d6fcb6dfad3a64c98dcc6e1e8496 is the
// external constant the DGB oracle pins at frstrtr/p2pool-dgb-scrypt
// bitcoin/networks/digibyte.py:55 (helper.check_block_header(..., 'genesis')).
// The test parses that literal display hex into 32 MSB-first bytes with an
// independent hex reader, reverses to the on-the-wire little-endian byte order,
// feeds u256::from_le_bytes (the exact storage path a real tip hash takes), and
// asserts u256_be_display_hex reproduces the original oracle string byte for
// byte. The formatter under test is the only code computing the output.
//
// DIAGNOSTICS / WIRE-DISPLAY ONLY: no consensus surface, no payout/subsidy/
// version-gate value. Pure header (<cstdint>/<string>) -> links only GTest. No
// call site rewired. MUST also be in BOTH build.yml --target allowlists
// (#143 NOT_BUILT trap).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <string>

#include "../coin/hash_format.hpp"

using dgb::coin::u256;
using dgb::coin::u256_be_display_hex;

namespace {

// Independent hex reader (does NOT share the formatter's nibble/limb logic):
// parse a 64-char big-endian display hex string into 32 MSB-first bytes.
std::array<unsigned char, 32> be_hex_to_msb_bytes(const std::string& hex)
{
    EXPECT_EQ(hex.size(), 64u);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::array<unsigned char, 32> out{};
    for (int i = 0; i < 32; ++i)
        out[i] = (unsigned char)((nib(hex[2 * i]) << 4) | nib(hex[2 * i + 1]));
    return out;
}

// Build a u256 from a big-endian display hex string via the production
// from_le_bytes path: reverse MSB-first display bytes into little-endian
// storage order (the byte order a parsed tip hash actually arrives in).
u256 u256_from_display_hex(const std::string& hex)
{
    auto msb = be_hex_to_msb_bytes(hex);
    unsigned char le[32];
    for (int i = 0; i < 32; ++i) le[i] = msb[31 - i];
    return u256::from_le_bytes(le);
}

} // namespace

// Oracle anchor: the DGB mainnet genesis hash (digibyte.py:55) must round-trip
// through the LE storage path back to its canonical display hex.
TEST(DgbHashFormatParity, GenesisHashRendersOracleDisplayHex)
{
    const std::string genesis =
        "7497ea1b465eb39f1c8f507bc877078fe016d6fcb6dfad3a64c98dcc6e1e8496";
    EXPECT_EQ(u256_be_display_hex(u256_from_display_hex(genesis)), genesis);
}

// Zero renders 64 zero nibbles -- no truncation, full left-padding.
TEST(DgbHashFormatParity, ZeroRendersSixtyFourZeros)
{
    EXPECT_EQ(u256_be_display_hex(u256{}), std::string(64, '0'));
}

// A tiny value pins the left zero-padding and that limb[0] is the LOW nibble.
TEST(DgbHashFormatParity, OneRendersPaddedToSixtyFourDigits)
{
    u256 v;
    v.limb[0] = 1;
    EXPECT_EQ(u256_be_display_hex(v), std::string(63, '0') + "1");
}

// Distinct per-limb values pin most-significant-limb-FIRST ordering (limb[3]
// is the leading 16 hex digits, limb[0] the trailing 16).
TEST(DgbHashFormatParity, LimbOrderingMostSignificantFirst)
{
    u256 v;
    v.limb[3] = 0x0123456789abcdefULL;
    v.limb[2] = 0xfedcba9876543210ULL;
    v.limb[1] = 0x00000000ffffffffULL;
    v.limb[0] = 0xdeadbeefcafef00dULL;
    EXPECT_EQ(u256_be_display_hex(v),
              "0123456789abcdef"
              "fedcba9876543210"
              "00000000ffffffff"
              "deadbeefcafef00d");
}

// All-ones renders 64 'f' nibbles (every limb fully populated).
TEST(DgbHashFormatParity, AllOnesRendersSixtyFourEffs)
{
    u256 v;
    for (int i = 0; i < 4; ++i) v.limb[i] = 0xffffffffffffffffULL;
    EXPECT_EQ(u256_be_display_hex(v), std::string(64, 'f'));
}

// from_le_bytes with a fully-distinct 0x00..0x1f pattern pins the byte
// reversal: LE byte 0 (0x00) is the LOW byte -> trailing "00", LE byte 31
// (0x1f) is the HIGH byte -> leading "1f".
TEST(DgbHashFormatParity, FromLeBytesByteReversalIsBigEndianDisplay)
{
    unsigned char le[32];
    for (int i = 0; i < 32; ++i) le[i] = (unsigned char)i;
    EXPECT_EQ(u256_be_display_hex(u256::from_le_bytes(le)),
              "1f1e1d1c1b1a1918"
              "1716151413121110"
              "0f0e0d0c0b0a0908"
              "0706050403020100");
}