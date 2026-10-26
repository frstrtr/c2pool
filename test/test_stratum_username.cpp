// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * KATs for the stratum login-field parsers in core/stratum_username.hpp —
 * the SAME functions StratumSession::handle_authorize / parse_address_separators
 * call (no re-implemented copy), so reverting the parser turns these red.
 *
 *   1. "/<diff>" colon-less token -> share difficulty (#865 slice 2)
 *   2. 09-23 rule: /0, negatives, inf, nan (and hex) set NO target
 *   3. "+inf" / "+nan" fixed pseudoshare difficulty rejected (std::isfinite)
 *   4. Preservation: LTC/DOGE "ADDR/CHAIN_ID:ADDR" merged tokens unchanged
 *   5. Worker dot-strip skipped when the last "/" token is a valid diff
 */

#include <gtest/gtest.h>
#include <core/stratum_username.hpp>

#include <string>

using namespace core::stratum_username;

namespace {

const std::string LTC_ADDR  = "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9";
const std::string DOGE_ADDR = "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L";
const std::string DASH_ADDR = "XpESxaUmonkq8RaLLp46Brx2K39ggQe226";

} // namespace

// --- 1. "/<diff>" share difficulty ---------------------------------------

TEST(StratumUsername, SlashNumericTokenSetsShareDiff)
{
    std::string u = DASH_ADDR + "/1024";
    auto r = parse_slash_tokens(u);
    EXPECT_TRUE(r.had_slash);
    EXPECT_EQ(u, DASH_ADDR);
    ASSERT_TRUE(r.share_diff.has_value());
    EXPECT_DOUBLE_EQ(*r.share_diff, 1024.0);
    EXPECT_TRUE(r.merged_addresses.empty());
}

TEST(StratumUsername, SlashFractionalAndExponentDiff)
{
    std::string a = DASH_ADDR + "/0.5";
    auto ra = parse_slash_tokens(a);
    ASSERT_TRUE(ra.share_diff.has_value());
    EXPECT_DOUBLE_EQ(*ra.share_diff, 0.5);

    std::string b = DASH_ADDR + "/1e3";
    auto rb = parse_slash_tokens(b);
    ASSERT_TRUE(rb.share_diff.has_value());
    EXPECT_DOUBLE_EQ(*rb.share_diff, 1000.0);
}

TEST(StratumUsername, SlashDiffMixedWithMergedTokens)
{
    std::string a = LTC_ADDR + "/98:" + DOGE_ADDR + "/2048";
    auto ra = parse_slash_tokens(a);
    EXPECT_EQ(a, LTC_ADDR);
    ASSERT_EQ(ra.merged_addresses.size(), 1u);
    EXPECT_EQ(ra.merged_addresses.at(98), DOGE_ADDR);
    ASSERT_TRUE(ra.share_diff.has_value());
    EXPECT_DOUBLE_EQ(*ra.share_diff, 2048.0);

    std::string b = LTC_ADDR + "/2048/98:" + DOGE_ADDR;
    auto rb = parse_slash_tokens(b);
    EXPECT_EQ(b, LTC_ADDR);
    ASSERT_EQ(rb.merged_addresses.size(), 1u);
    EXPECT_EQ(rb.merged_addresses.at(98), DOGE_ADDR);
    ASSERT_TRUE(rb.share_diff.has_value());
    EXPECT_DOUBLE_EQ(*rb.share_diff, 2048.0);
}

// --- 2. 09-23 rule: invalid diffs set NO target --------------------------

TEST(StratumUsername, SlashInvalidDiffSetsNoTarget)
{
    for (const char* bad : {"0", "0.0", "-5", "-0", "inf", "+inf", "-inf",
                            "INF", "infinity", "nan", "NaN", "1e999",
                            "0x10", "1024abc", "", "abc", " 1024"}) {
        std::string u = DASH_ADDR + "/" + bad;
        auto r = parse_slash_tokens(u);
        EXPECT_TRUE(r.had_slash) << bad;
        EXPECT_EQ(u, DASH_ADDR) << bad;
        EXPECT_FALSE(r.share_diff.has_value()) << "token '" << bad << "'";
        EXPECT_TRUE(r.merged_addresses.empty()) << bad;
    }
}

TEST(StratumUsername, ParsePositiveFiniteDiff)
{
    EXPECT_EQ(parse_positive_finite_diff("1024"), 1024.0);
    EXPECT_EQ(parse_positive_finite_diff("0.001"), 0.001);
    EXPECT_FALSE(parse_positive_finite_diff("0").has_value());
    EXPECT_FALSE(parse_positive_finite_diff("-1").has_value());
    EXPECT_FALSE(parse_positive_finite_diff("inf").has_value());
    EXPECT_FALSE(parse_positive_finite_diff("nan").has_value());
    EXPECT_FALSE(parse_positive_finite_diff("").has_value());
}

// --- 3. "+N" fixed pseudoshare difficulty --------------------------------

TEST(StratumUsername, PlusSuffixValidDiff)
{
    std::string u = DASH_ADDR + "+512";
    auto d = strip_fixed_diff_suffix(u);
    EXPECT_EQ(u, DASH_ADDR);
    ASSERT_TRUE(d.has_value());
    EXPECT_DOUBLE_EQ(*d, 512.0);
}

TEST(StratumUsername, PlusSuffixInfNanRejectedButStripped)
{
    for (const char* bad : {"inf", "INF", "infinity", "nan", "0", "-8", "1e999"}) {
        std::string u = DASH_ADDR + "+" + bad;
        auto d = strip_fixed_diff_suffix(u);
        EXPECT_EQ(u, DASH_ADDR) << bad;
        EXPECT_FALSE(d.has_value()) << "suffix '+" << bad << "'";
    }
}

TEST(StratumUsername, PlusThenSlashDiff)
{
    // p2pool order: '+' (pseudoshare) stripped first, then '/' (share).
    std::string u = DASH_ADDR + "/4096+256";
    auto pseudo = strip_fixed_diff_suffix(u);
    ASSERT_TRUE(pseudo.has_value());
    EXPECT_DOUBLE_EQ(*pseudo, 256.0);
    auto r = parse_slash_tokens(u);
    EXPECT_EQ(u, DASH_ADDR);
    ASSERT_TRUE(r.share_diff.has_value());
    EXPECT_DOUBLE_EQ(*r.share_diff, 4096.0);
}

// --- 4. Preservation: LTC/DOGE merged tokens -----------------------------

TEST(StratumUsername, PreserveLtcDogeMergedToken)
{
    std::string u = LTC_ADDR + "/98:" + DOGE_ADDR;
    auto r = parse_slash_tokens(u);
    EXPECT_TRUE(r.had_slash);
    EXPECT_EQ(u, LTC_ADDR);
    ASSERT_EQ(r.merged_addresses.size(), 1u);
    EXPECT_EQ(r.merged_addresses.at(98), DOGE_ADDR);
    EXPECT_FALSE(r.share_diff.has_value());
}

TEST(StratumUsername, PreserveMultipleMergedTokensLastWins)
{
    std::string u = LTC_ADDR + "/98:" + DOGE_ADDR + "/99:OTHER/98:DSECOND";
    auto r = parse_slash_tokens(u);
    EXPECT_EQ(u, LTC_ADDR);
    ASSERT_EQ(r.merged_addresses.size(), 2u);
    EXPECT_EQ(r.merged_addresses.at(98), "DSECOND");
    EXPECT_EQ(r.merged_addresses.at(99), "OTHER");
    EXPECT_FALSE(r.share_diff.has_value());
}

TEST(StratumUsername, PreserveMalformedMergedTokensDropped)
{
    // Same drops as before: empty id, empty addr, non-numeric id.
    std::string u = LTC_ADDR + "/:" + DOGE_ADDR + "/98:/x:" + DOGE_ADDR;
    auto r = parse_slash_tokens(u);
    EXPECT_EQ(u, LTC_ADDR);
    EXPECT_TRUE(r.merged_addresses.empty());
    EXPECT_FALSE(r.share_diff.has_value());
}

TEST(StratumUsername, NoSlashUntouched)
{
    std::string u = LTC_ADDR + "," + DOGE_ADDR;
    auto r = parse_slash_tokens(u);
    EXPECT_FALSE(r.had_slash);
    EXPECT_EQ(u, LTC_ADDR + "," + DOGE_ADDR);
    EXPECT_FALSE(r.share_diff.has_value());
}

// --- 5. Worker dot-strip vs fractional "/<diff>" -------------------------
// Full handle_authorize order: '+' strip, worker strip, then '/' tokens.

namespace {

struct Login {
    std::string primary;
    std::string worker;
    SlashParse slash;
};

Login parse_login(std::string u)
{
    strip_fixed_diff_suffix(u);
    Login l;
    l.worker = strip_worker_suffix(u);
    l.slash = parse_slash_tokens(u);
    l.primary = u;
    return l;
}

} // namespace

TEST(StratumUsername, FractionalDiffNotTakenAsWorker)
{
    auto l = parse_login(DASH_ADDR + "/1.5");
    EXPECT_EQ(l.primary, DASH_ADDR);
    EXPECT_EQ(l.worker, "");
    ASSERT_TRUE(l.slash.share_diff.has_value());
    EXPECT_DOUBLE_EQ(*l.slash.share_diff, 1.5);
}

TEST(StratumUsername, FractionalDiffThenWorkerStillStripped)
{
    auto l = parse_login(DASH_ADDR + "/1.5.rig");
    EXPECT_EQ(l.primary, DASH_ADDR);
    EXPECT_EQ(l.worker, "rig");
    ASSERT_TRUE(l.slash.share_diff.has_value());
    EXPECT_DOUBLE_EQ(*l.slash.share_diff, 1.5);
}

TEST(StratumUsername, MergedTokenThenFractionalDiff)
{
    auto l = parse_login(LTC_ADDR + "/98:" + DOGE_ADDR + "/0.5");
    EXPECT_EQ(l.primary, LTC_ADDR);
    EXPECT_EQ(l.worker, "");
    ASSERT_EQ(l.slash.merged_addresses.size(), 1u);
    EXPECT_EQ(l.slash.merged_addresses.at(98), DOGE_ADDR);
    ASSERT_TRUE(l.slash.share_diff.has_value());
    EXPECT_DOUBLE_EQ(*l.slash.share_diff, 0.5);
}

TEST(StratumUsername, WorkerStripUnchangedWithoutDiffTail)
{
    auto a = parse_login(DASH_ADDR + ".rig1");
    EXPECT_EQ(a.primary, DASH_ADDR);
    EXPECT_EQ(a.worker, "rig1");

    auto b = parse_login(LTC_ADDR + "/98:" + DOGE_ADDR + ".rig2");
    EXPECT_EQ(b.primary, LTC_ADDR);
    EXPECT_EQ(b.worker, "rig2");
    EXPECT_EQ(b.slash.merged_addresses.at(98), DOGE_ADDR);
    EXPECT_FALSE(b.slash.share_diff.has_value());

    auto c = parse_login(DASH_ADDR + "/1024.rig3");
    EXPECT_EQ(c.primary, DASH_ADDR);
    EXPECT_EQ(c.worker, "rig3");
    ASSERT_TRUE(c.slash.share_diff.has_value());
    EXPECT_DOUBLE_EQ(*c.slash.share_diff, 1024.0);
}
