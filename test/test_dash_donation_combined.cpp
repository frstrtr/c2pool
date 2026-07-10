// SPDX-License-Identifier: AGPL-3.0-or-later
/// Phase v36-migration-std — DASH unified v36 donation-P2SH standardization KATs.
///
/// Closes the Bucket-2 gap (operator FLAG6, 2026-06-17 3-bucket rule): DASH was
/// the ONLY coin missing the unified cross-coin v36 COMBINED_DONATION_SCRIPT that
/// btc/bch/dgb/ltc all carry. params.donation_script_func was hardwired to the
/// DASH-specific P2PKH for every version. This slice defines the unified P2SH and
/// makes the selector version-keyed (pre-v36 -> P2PKH Bucket-3 keep-for-soak;
/// v36+ -> unified P2SH Bucket-2). These KATs prove:
///
///   (1) CombinedIsCanonicalUnifiedP2SH — dash::COMBINED_DONATION_SCRIPT is the
///       exact 23-byte a914<8c627262..85>87 P2SH, byte-identical to the other coins.
///   (2) PreV36SelectsP2PKH             — donation_script_func(16) == DONATION_SCRIPT.
///   (3) V36SelectsCombinedP2SH         — donation_script_func(36) == COMBINED_DONATION_SCRIPT.
///   (4) ScriptsDiffer                  — the two arms are not accidentally equal.

#include <gtest/gtest.h>

#include <impl/dash/params.hpp>
#include <impl/dash/share_check.hpp>
#include <core/version_gate.hpp>

namespace {

// Canonical unified cross-coin v36 donation P2SH (FLAG6: P2SH of the 1-of-2
// forrestv + c2pool dev-key redeem script). Literal mirror of the btc/bch/dgb/ltc
// COMBINED_DONATION_SCRIPT — DASH must match this byte-for-byte.
const std::vector<unsigned char> kCanonicalCombined = {
    0xa9, 0x14,
    0x8c, 0x62, 0x72, 0x62, 0x1d, 0x89, 0xe8, 0xfa,
    0x52, 0x6d, 0xd8, 0x6a, 0xcf, 0xf6, 0x0c, 0x71,
    0x36, 0xbe, 0x8e, 0x85,
    0x87
};

} // namespace

TEST(DashDonationCombined, CombinedIsCanonicalUnifiedP2SH)
{
    EXPECT_EQ(dash::COMBINED_DONATION_SCRIPT, kCanonicalCombined);
    ASSERT_EQ(dash::COMBINED_DONATION_SCRIPT.size(), 23u);
    EXPECT_EQ(dash::COMBINED_DONATION_SCRIPT.front(), 0xa9); // OP_HASH160
    EXPECT_EQ(dash::COMBINED_DONATION_SCRIPT[1], 0x14);      // PUSH20
    EXPECT_EQ(dash::COMBINED_DONATION_SCRIPT.back(), 0x87);  // OP_EQUAL
}

TEST(DashDonationCombined, PreV36SelectsP2PKH)
{
    auto p = dash::make_coin_params(false);
    ASSERT_FALSE(core::version_gate::is_v36_active(16u));
    EXPECT_EQ(p.donation_script_func(16), dash::DONATION_SCRIPT);
}

TEST(DashDonationCombined, V36SelectsCombinedP2SH)
{
    auto p = dash::make_coin_params(false);
    ASSERT_TRUE(core::version_gate::is_v36_active(36u));
    EXPECT_EQ(p.donation_script_func(36), dash::COMBINED_DONATION_SCRIPT);
}

TEST(DashDonationCombined, ScriptsDiffer)
{
    EXPECT_NE(dash::DONATION_SCRIPT, dash::COMBINED_DONATION_SCRIPT);
}