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
 *   5. The worker is cut from the user part only (the text before the first
 *      '+' or '/'): a ".worker" before the "/<diff>" is stripped (no B1
 *      lockout), a '.' inside a "/<diff>" tail is never a worker
 *   6. "d=N" start difficulty in the authorize password (wire units)
 *   7. p2pool parity (work.py get_user_details): "+N", "/N", "+N/M", "/M+N"
 *      in any order, multi-separator worker names, the two-address forms
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

// --- 5. Worker strip vs fractional "/<diff>" -----------------------------
// The production handle_authorize order (parse_login): '+' parameters out,
// worker cut from the user part, then the '/' tokens.

TEST(StratumUsername, FractionalDiffNotTakenAsWorker)
{
    auto l = parse_login(DASH_ADDR + "/1.5");
    EXPECT_EQ(l.user, DASH_ADDR);
    EXPECT_EQ(l.worker, "");
    ASSERT_TRUE(l.slash.share_diff.has_value());
    EXPECT_DOUBLE_EQ(*l.slash.share_diff, 1.5);
}

// p2pool float("1.5.rig") raises: the token sets nothing, and the worker is
// only ever in the user part (before the first '/').
TEST(StratumUsername, WorkerAfterSlashDiffIsNoWorkerAndNoDiff)
{
    auto l = parse_login(DASH_ADDR + "/1.5.rig");
    EXPECT_EQ(l.user, DASH_ADDR);
    EXPECT_EQ(l.worker, "");
    EXPECT_FALSE(l.slash.share_diff.has_value());

    auto c = parse_login(DASH_ADDR + "/1024.rig3");
    EXPECT_EQ(c.user, DASH_ADDR);
    EXPECT_EQ(c.worker, "");
    EXPECT_FALSE(c.slash.share_diff.has_value());
}

TEST(StratumUsername, MergedTokenThenFractionalDiff)
{
    auto l = parse_login(LTC_ADDR + "/98:" + DOGE_ADDR + "/0.5");
    EXPECT_EQ(l.user, LTC_ADDR);
    EXPECT_EQ(l.worker, "");
    ASSERT_EQ(l.slash.merged_addresses.size(), 1u);
    EXPECT_EQ(l.slash.merged_addresses.at(98), DOGE_ADDR);
    ASSERT_TRUE(l.slash.share_diff.has_value());
    EXPECT_DOUBLE_EQ(*l.slash.share_diff, 0.5);
}

TEST(StratumUsername, WorkerStripUnchangedWithoutDiffTail)
{
    auto a = parse_login(DASH_ADDR + ".rig1");
    EXPECT_EQ(a.user, DASH_ADDR);
    EXPECT_EQ(a.worker, "rig1");

    // A merged token's worker suffix: the DOGE address keeps no ".rig2".
    auto b = parse_login(LTC_ADDR + "/98:" + DOGE_ADDR + ".rig2");
    EXPECT_EQ(b.user, LTC_ADDR);
    EXPECT_EQ(b.worker, "rig2");
    EXPECT_EQ(b.slash.merged_addresses.at(98), DOGE_ADDR);
    EXPECT_FALSE(b.slash.share_diff.has_value());
}

// ltc-doge HOLD on 966846c9: "ADDR.rig/1024" kept "ADDR.rig" as the primary,
// so the #961 B1 door check rejected the login. The dot is before the "/",
// so it is a worker; the "/1024" tail must survive the strip.
TEST(StratumUsername, WorkerBeforeSlashDiffIsStripped)
{
    auto a = parse_login(LTC_ADDR + ".rig/1024");
    EXPECT_EQ(a.user, LTC_ADDR);
    EXPECT_EQ(a.worker, "rig");
    ASSERT_TRUE(a.slash.share_diff.has_value());
    EXPECT_DOUBLE_EQ(*a.slash.share_diff, 1024.0);

    auto b = parse_login(DASH_ADDR + ".rig/0.5");
    EXPECT_EQ(b.user, DASH_ADDR);
    EXPECT_EQ(b.worker, "rig");
    ASSERT_TRUE(b.slash.share_diff.has_value());
    EXPECT_DOUBLE_EQ(*b.slash.share_diff, 0.5);

    auto c = parse_login(LTC_ADDR + ".rig/98:" + DOGE_ADDR + "/1024");
    EXPECT_EQ(c.user, LTC_ADDR);
    EXPECT_EQ(c.worker, "rig");
    ASSERT_EQ(c.slash.merged_addresses.size(), 1u);
    EXPECT_EQ(c.slash.merged_addresses.at(98), DOGE_ADDR);
    ASSERT_TRUE(c.slash.share_diff.has_value());
    EXPECT_DOUBLE_EQ(*c.slash.share_diff, 1024.0);
}

// --- 6. "d=N" start difficulty in the mining.authorize password ------------
// Wire units; the whole password or one ","/";"-separated key=value token;
// the last "d=" token decides; a bad value sets nothing and is flagged.
TEST(StratumPasswordDiff, AcceptedForms)
{
    struct Case { const char* pw; double want; };
    for (const Case& c : {Case{"d=4096", 4096.0}, Case{"x,d=4096", 4096.0}, Case{"d=4096;x", 4096.0},
                          Case{"c=LTC, d = 0.5 ;x", 0.5}, Case{"D=1e3", 1000.0},
                          Case{"d=5,d=7", 7.0}, Case{"x;d=16;", 16.0}}) {
        SCOPED_TRACE(c.pw);
        const auto pd = parse_password_start_diff(c.pw);
        ASSERT_TRUE(pd.diff.has_value());
        EXPECT_DOUBLE_EQ(*pd.diff, c.want);
        EXPECT_FALSE(pd.bad);
    }
}

TEST(StratumPasswordDiff, NoTokenIsNotAnError)
{
    for (const char* pw : {"", "x", "password", "dd=5", "sd=5", "d", "xd=4"}) {
        SCOPED_TRACE(pw);
        const auto pd = parse_password_start_diff(pw);
        EXPECT_FALSE(pd.diff.has_value());
        EXPECT_FALSE(pd.bad);
    }
}

TEST(StratumPasswordDiff, GarbageIsIgnoredAndFlagged)
{
    for (const char* pw : {"d=abc", "d=-5", "d=0", "d=", "d=inf", "d=nan", "d=1e999", "d=0x10",
                           "x,d=4096x", "d=5,d=bad"}) {
        SCOPED_TRACE(pw);
        const auto pd = parse_password_start_diff(pw);
        EXPECT_FALSE(pd.diff.has_value());
        EXPECT_TRUE(pd.bad);
    }
}

// --- 7. p2pool parity: work.py get_user_details ---------------------------
// Expected values from python p2pool's own parse of each login (python3 -I,
// the get_user_details lines verbatim):
//   contents = re.split('([+/])', username); user, contents2 = contents[0], contents[1:]
//   if '_' in user: worker = user.split('_')[1]; user = user.split('_')[0]
//   elif '.' in user: worker = user.split('.')[1]; user = user.split('.')[0]
//   for symbol, parameter in zip(contents2[::2], contents2[1::2]):
//       '+': desired_pseudoshare_target = difficulty_to_target(float(parameter))
//       '/': desired_share_target = difficulty_to_target(float(parameter))
//       (a parameter float() or difficulty_to_target raises on is skipped)
// with A = DASH_ADDR. "user == A" for every case: the payout address is p2pool's.
namespace {
struct PyCase {
    const char* suffix;
    const char* worker;
    double pseudo;   // 0: none
    double share;    // 0: none
};
}

TEST(StratumUsernamePython, GetUserDetailsParity)
{
    const PyCase cases[] = {
        {"", "", 0, 0},
        {"+1024", "", 1024, 0},
        {"/512", "", 0, 512},
        {"+1024/512", "", 1024, 512},        // was: both lost (the '+' tail "1024/512" is no number)
        {"/512+1024", "", 1024, 512},
        {".a.b", "a", 0, 0},                 // was: primary "A.a" (no address), worker "b"
        {"_a.b", "a.b", 0, 0},               // was: worker "b"
        {"_a_b", "a", 0, 0},                 // was: primary "A_a" (no address), worker "b"
        {".rig+1024/512", "rig", 1024, 512}, // was: "+1024/512" lost
        {"_rig/512+16", "rig", 16, 512},     // was: worker "rig/512", "/512" lost
        {"+1024.rig", "", 0, 0},
        {"/1024.rig", "", 0, 0},             // was: share 1024, worker "rig"
        {"/1.5.rig", "", 0, 0},              // was: share 1.5, worker "rig"
        {"+512+abc", "", 512, 0},            // was: primary "A+512" (no address)
        {"/512/1024", "", 0, 1024},
        {"/abc", "", 0, 0},
        {".rig/0.5", "rig", 0, 0.5},
        {"/0.5.rig/2", "", 0, 2},            // was: worker "rig"
        {"/2/x+4+y", "", 4, 2},              // was: "+4" lost (the last '+' token only)
        {".a.b/64+8", "a", 8, 64},           // was: primary "A.a" (no address), worker "b"
        {"+", "", 0, 0},                     // was: primary "A+" (no address)
        {"/", "", 0, 0},
        // difficulty_to_target raises (the quotient overflows a double): skipped
        {"/512/1e-300", "", 0, 512},         // was: share 1e-300
        {"+1e-300", "", 0, 0},               // was: fixed difficulty 1e-300
        {"+16+1e-300", "", 16, 0},
        {"/1e-240", "", 0, 1e-240},          // still a target (2**256-1)
    };
    for (const auto& c : cases) {
        SCOPED_TRACE(std::string("login A") + c.suffix);
        const auto l = parse_login(DASH_ADDR + c.suffix);
        EXPECT_EQ(l.user, DASH_ADDR) << "the payout address p2pool takes";
        EXPECT_EQ(l.worker, c.worker);
        if (c.pseudo > 0) {
            ASSERT_TRUE(l.pseudo_diff.has_value());
            EXPECT_DOUBLE_EQ(*l.pseudo_diff, c.pseudo);
        } else {
            EXPECT_FALSE(l.pseudo_diff.has_value());
        }
        if (c.share > 0) {
            ASSERT_TRUE(l.slash.share_diff.has_value());
            EXPECT_DOUBLE_EQ(*l.slash.share_diff, c.share);
        } else {
            EXPECT_FALSE(l.slash.share_diff.has_value());
        }
        EXPECT_TRUE(l.slash.merged_addresses.empty());
    }
}

// "ADDR.a_b": p2pool's user is "A.a" ('_' wins: user.split('_')[0]), which is
// no address; the address is cut at the '.' too, so the payout stays A, as
// before. The worker is p2pool's ("b"; was "a_b").
TEST(StratumUsernamePython, DotBeforeUnderscoreKeepsTheAddress)
{
    const auto l = parse_login(DASH_ADDR + ".a_b");
    EXPECT_EQ(l.user, DASH_ADDR);
    EXPECT_EQ(l.worker, "b");
}

// Where c2pool departs from p2pool, on purpose: "0", "inf" (1e309 is one:
// std::stod fails, python's float gives inf), "nan", hex and
// whitespace-padded values are ignored and do not override an earlier one.
// p2pool would take "/0" as 2**256-1 (the easiest share, pre_target3).
TEST(StratumUsernamePython, IgnoredValuesKeepTheEarlierOne)
{
    for (const char* bad : {"0", "inf", "1e309", "nan", "0x10", " 8"}) {
        SCOPED_TRACE(bad);
        const auto s = parse_login(DASH_ADDR + "/512/" + bad);
        ASSERT_TRUE(s.slash.share_diff.has_value());
        EXPECT_DOUBLE_EQ(*s.slash.share_diff, 512.0);
        const auto p = parse_login(DASH_ADDR + "+16+" + bad);
        ASSERT_TRUE(p.pseudo_diff.has_value());
        EXPECT_DOUBLE_EQ(*p.pseudo_diff, 16.0);
    }
    EXPECT_FALSE(parse_login_diff("1e-241").has_value()) << "difficulty_to_target raises";
    EXPECT_TRUE(parse_login_diff("1e-240").has_value());
}

// A '|', ';' or ' ' after a worker suffix is part of the worker (p2pool
// splits no login at them): the login names no second address, its merged
// chains get the primary's key. Before, any of them split the login.
TEST(StratumUsernamePython, SeparatorAfterAWorkerSuffixIsTheWorkers)
{
    struct Case { std::string login; std::string worker; };
    const Case cases[] = {
        {LTC_ADDR + ".rig|" + DOGE_ADDR, "rig|" + DOGE_ADDR},
        {LTC_ADDR + ".rig " + DOGE_ADDR, "rig " + DOGE_ADDR},
        {LTC_ADDR + "_rig;" + DOGE_ADDR, "rig;" + DOGE_ADDR},
        {LTC_ADDR + ".my rig", "my rig"},
    };
    for (const auto& c : cases) {
        SCOPED_TRACE(c.login);
        const auto l = parse_login(c.login);
        EXPECT_EQ(l.user, LTC_ADDR);
        EXPECT_EQ(l.worker, c.worker);
        EXPECT_EQ(find_merged_separator(l.user), std::string::npos) << "no second address";
        EXPECT_FALSE(l.first_had_worker);
    }
    // c2pool's own forms without a suffix before the separator, as before:
    // "L|D" and "L|D.rig" name D.
    const auto a = parse_login(LTC_ADDR + "|" + DOGE_ADDR);
    EXPECT_EQ(a.user, LTC_ADDR + "|" + DOGE_ADDR);
    const auto b = parse_login(LTC_ADDR + "|" + DOGE_ADDR + ".rig");
    EXPECT_EQ(b.user, LTC_ADDR + "|" + DOGE_ADDR);
    EXPECT_EQ(b.worker, "rig");
}

// "D.rig,L": p2pool-merged-v36 tests the swapped order on "D.rig" (with its
// suffix: no address), so it does not swap; L is no DOGE address and is
// ignored, the primary is D (case 5). first_had_worker carries that to
// resolve_merged_login; "D,L" still swaps.
TEST(StratumUsernamePython, FirstAddressWorkerSuffixIsFlagged)
{
    const auto l = parse_login(DOGE_ADDR + ".rig," + LTC_ADDR);
    EXPECT_EQ(l.user, DOGE_ADDR + "," + LTC_ADDR);
    EXPECT_EQ(l.worker, "rig");
    EXPECT_TRUE(l.first_had_worker);
    EXPECT_FALSE(parse_login(DOGE_ADDR + "," + LTC_ADDR).first_had_worker);
    EXPECT_FALSE(parse_login(LTC_ADDR + "," + DOGE_ADDR + ".rig").first_had_worker);
    EXPECT_TRUE(parse_login(LTC_ADDR + "_a," + DOGE_ADDR + ".b").first_had_worker);
}

// The comma form splits where the comma is in the login as typed, even when
// cutting the first address's worker suffix leaves it at index 20 or before
// (merged_sep carries the decision): the second address stays named, as
// before. The first address, no address at all, is unusable either way.
TEST(StratumUsernamePython, CommaSplitDecidedOnTheLoginAsTyped)
{
    for (const std::string& login : {".|" + DOGE_ADDR + "," + DOGE_ADDR,
                                     "._x" + std::string(34, 'y') + ".a.b," + DOGE_ADDR}) {
        SCOPED_TRACE(login);
        const auto l = parse_login(login);
        EXPECT_EQ(l.user, "," + DOGE_ADDR);
        EXPECT_EQ(l.merged_sep, 0u);
        EXPECT_TRUE(l.first_had_worker);
    }
    EXPECT_EQ(parse_login(LTC_ADDR + "," + DOGE_ADDR).merged_sep, LTC_ADDR.size());
    EXPECT_EQ(parse_login(LTC_ADDR + ".rig," + DOGE_ADDR).merged_sep, LTC_ADDR.size());
    EXPECT_EQ(parse_login(LTC_ADDR + "|" + DOGE_ADDR + ".rig").merged_sep, LTC_ADDR.size());
    EXPECT_EQ(parse_login(LTC_ADDR + ".rig|" + DOGE_ADDR).merged_sep, std::string::npos);
    EXPECT_EQ(parse_login(LTC_ADDR).merged_sep, std::string::npos);
}

// The two-address forms (p2pool-merged-v36 splits the comma first): each
// address loses its own worker suffix; the merged address's worker comes
// first. "/N" and "+N" apply to the two-address login as to any.
TEST(StratumUsernamePython, TwoAddressFormsKeepBothAddresses)
{
    struct Case { std::string login; std::string user; const char* worker; };
    const Case cases[] = {
        {LTC_ADDR + "," + DOGE_ADDR, LTC_ADDR + "," + DOGE_ADDR, ""},
        {LTC_ADDR + "," + DOGE_ADDR + ".rig", LTC_ADDR + "," + DOGE_ADDR, "rig"},
        {LTC_ADDR + "," + DOGE_ADDR + "_rig", LTC_ADDR + "," + DOGE_ADDR, "rig"},
        {LTC_ADDR + "," + DOGE_ADDR + ".a.b", LTC_ADDR + "," + DOGE_ADDR, "a.b"},   // was: worker "b"
        {LTC_ADDR + ".rig," + DOGE_ADDR, LTC_ADDR + "," + DOGE_ADDR, "rig"},   // was: DOGE lost (worker "rig,D...")
        // was: primary "L.a" (no address). p2pool-merged-v36 keeps "L.a" too
        // (its LTC payout: case 4, hash160(D)); c2pool pays L. Same for "L_a".
        {LTC_ADDR + ".a," + DOGE_ADDR + ".b", LTC_ADDR + "," + DOGE_ADDR, "b"},
        {LTC_ADDR + "_a," + DOGE_ADDR + ".b", LTC_ADDR + "," + DOGE_ADDR, "b"},
        {LTC_ADDR + "|" + DOGE_ADDR + "_w", LTC_ADDR + "|" + DOGE_ADDR, "w"},
        // (server side, was: a '/' token stopped the comma split: primary "L,D")
        {LTC_ADDR + "," + DOGE_ADDR + ".rig/512+16", LTC_ADDR + "," + DOGE_ADDR, "rig"},
    };
    for (const auto& c : cases) {
        SCOPED_TRACE(c.login);
        const auto l = parse_login(c.login);
        EXPECT_EQ(l.user, c.user);
        EXPECT_EQ(l.worker, c.worker);
    }
    const auto l = parse_login(LTC_ADDR + "," + DOGE_ADDR + ".rig/512+16");
    ASSERT_TRUE(l.slash.share_diff.has_value());
    EXPECT_DOUBLE_EQ(*l.slash.share_diff, 512.0);
    ASSERT_TRUE(l.pseudo_diff.has_value());
    EXPECT_DOUBLE_EQ(*l.pseudo_diff, 16.0);
}

// Merged tokens with "+N"/"/N" in any order: "+N" before the merged token
// used to swallow it ("+1024/98:D..." is no number), losing the DOGE address.
TEST(StratumUsernamePython, MergedTokensWithBothSuffixes)
{
    for (const std::string& login : {LTC_ADDR + "+1024/98:" + DOGE_ADDR + "/512",
                                     LTC_ADDR + "/98:" + DOGE_ADDR + "+1024/512",
                                     LTC_ADDR + "/512/98:" + DOGE_ADDR + "+1024"}) {
        SCOPED_TRACE(login);
        const auto l = parse_login(login);
        EXPECT_EQ(l.user, LTC_ADDR);
        ASSERT_EQ(l.slash.merged_addresses.size(), 1u);
        EXPECT_EQ(l.slash.merged_addresses.at(98), DOGE_ADDR);
        ASSERT_TRUE(l.pseudo_diff.has_value());
        EXPECT_DOUBLE_EQ(*l.pseudo_diff, 1024.0);
        ASSERT_TRUE(l.slash.share_diff.has_value());
        EXPECT_DOUBLE_EQ(*l.slash.share_diff, 512.0);
    }
}
