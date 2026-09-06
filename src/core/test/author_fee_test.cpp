// SPDX-License-Identifier: AGPL-3.0-or-later
// author_fee_test.cpp — SSOT KAT for the built-in author/dev donation policy
// (core/author_fee.hpp), the single source of truth every coin lane
// (DASH/LTC/BTC/DGB/BCH/BIP110) now shares for the committed p2pool donation
// field.
//
// W-MONEY change under test: the in-code author default is HARD-PINNED at 0.1%
// (was 0.5% on BTC, and hardcoded 50 on DGB/BCH). 0.1% converts to the u16 field
// as round(65535 * 0.1 / 100) = 66 — the same value the DASH/LTC lanes already
// commit (test_dash_mint_runloop.cpp). Pinning the constant AND the conversion
// here guards against a silent drift back to 0.5% (u16 328) or the old
// hardcoded 50.
//
// Red on master: core/author_fee.hpp does not exist there, so this TU fails to
// compile — the whole-binary compile-red is the intended red state. Green after
// the W-MONEY change lands the header + the SSOT default.
//
// Folded into the EXISTING allowlisted core_test target (never a new
// add_executable — the #769 "Not Run" trap). Header-only over core, one KAT
// covers every coin lane because all five consume this one conversion.

#include <gtest/gtest.h>

#include <core/author_fee.hpp>

namespace {

// The built-in default is EXACTLY 0.1% — not 0.5%, not 0. This is the operator
// money rule (author-fee default = 0.1%, NEVER 0) encoded as a compile-time SSOT.
TEST(AuthorFee, DefaultIsPointOnePercent)
{
    EXPECT_DOUBLE_EQ(core::kAuthorFeeDefaultPct, 0.1);
}

// The default percent converts to the committed u16 donation field as 66 — the
// value the ref preimage and the created share BOTH stamp on every lane. A
// mismatch between the two sites is a 100% self-decline, so this is the anchor
// the DGB/BCH single-donation_u16-local refactor pins to.
TEST(AuthorFee, DefaultConvertsToU16_66)
{
    EXPECT_EQ(core::donation_percent_to_u16(core::kAuthorFeeDefaultPct), 66);
}

// The perfect_round conversion (p2pool work.py math) across the reference points
// the DASH KAT (test_dash_mint_runloop.cpp) already pins — now the shared SSOT.
TEST(AuthorFee, ConversionReferencePoints)
{
    EXPECT_EQ(core::donation_percent_to_u16(0.0), 0);
    EXPECT_EQ(core::donation_percent_to_u16(0.1), 66);      // W-MONEY default
    EXPECT_EQ(core::donation_percent_to_u16(0.5), 328);     // the OLD p2pool default
    EXPECT_EQ(core::donation_percent_to_u16(2.5), 1638);
    EXPECT_EQ(core::donation_percent_to_u16(100.0), 65535);
}

// Clamps: out-of-range percentages saturate rather than wrap the u16 field.
TEST(AuthorFee, ConversionClamps)
{
    EXPECT_EQ(core::donation_percent_to_u16(250.0), 65535);  // over 100% clamps high
    EXPECT_EQ(core::donation_percent_to_u16(-3.0), 0);       // negative clamps low
}

} // namespace
