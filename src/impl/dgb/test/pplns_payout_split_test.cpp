// SPDX-License-Identifier: AGPL-3.0-or-later
// DGB Phase B — PPLNS weights -> consensus-sorted payout outputs KAT.
//
// Locks dgb::coin::compute_pplns_payout_split() (coin/pplns_payout_split.hpp)
// against hand-computed oracle vectors derived from the p2pool v36 amount math
// (frstrtr/p2pool-merged-v36 data.py generate_transaction()). A PASS proves the
// extracted SSOT reproduces, satoshi-for-satoshi, steps 2-3 of
// share_check.hpp generate_share_transaction():
//
//   V36:     amounts[s] = subsidy * weight / total_weight ; donation floor >=1
//   Pre-V36: amounts[s] = subsidy * 199 * weight / (200 * total_weight)
//            + 0.5% (subsidy/200) finder fee
//   order:   ascending (amount, script), keep highest PPLNS_MAX_OUTPUTS
//
// Pure: weights + subsidy are fixed inputs, so the expected outputs are the
// oracle formula's outputs — not self-generated.

#include <gtest/gtest.h>
#include <impl/dgb/coin/pplns_payout_split.hpp>

#include <cstdint>
#include <map>
#include <utility>
#include <vector>

namespace {

using Script  = std::vector<unsigned char>;
using Payouts = std::vector<std::pair<Script, uint64_t>>;

const Script SA{0x01};
const Script SB{0x02};
const Script FINDER{0x09};

// --- V36: subsidy 10000, weights A:3 B:1 (total 4) --------------------------
// amounts: A = 10000*3/4 = 7500, B = 10000*1/4 = 2500 ; sum 10000, donation 0.
// V36 >=1 sat floor: deduct 1 from largest (A) -> A=7499, donation=1.
// order asc (amount,script): B(2500) then A(7499).
TEST(PplnsPayoutSplit, V36ExactAmountsAndDonationFloor)
{
    std::map<Script, uint288> w{{SA, uint288(3)}, {SB, uint288(1)}};
    auto r = dgb::coin::compute_pplns_payout_split(
        w, uint288(4), /*subsidy*/10000, /*use_v36*/true, /*finder*/{});

    Payouts expect{{SB, 2500}, {SA, 7499}};
    EXPECT_EQ(r.payout_outputs, expect);
    EXPECT_EQ(r.donation_amount, 1u);

    // Conservation: every satoshi of subsidy is accounted for.
    uint64_t sum = r.donation_amount;
    for (auto& [s, a] : r.payout_outputs) sum += a;
    EXPECT_EQ(sum, 10000u);
}

// --- Pre-V36: subsidy 20000, weights A:1 B:1 (total 2), 0.5% finder fee ------
// amounts: A = B = 20000*199*1/(200*2) = 9950 ; finder += 20000/200 = 100.
// sum 20000, donation 0. order asc (amount,script): finder(100), A(9950), B(9950).
TEST(PplnsPayoutSplit, PreV36AmountsPlusFinderFee)
{
    std::map<Script, uint288> w{{SA, uint288(1)}, {SB, uint288(1)}};
    auto r = dgb::coin::compute_pplns_payout_split(
        w, uint288(2), /*subsidy*/20000, /*use_v36*/false, /*finder*/FINDER);

    Payouts expect{{FINDER, 100}, {SA, 9950}, {SB, 9950}};
    EXPECT_EQ(r.payout_outputs, expect);
    EXPECT_EQ(r.donation_amount, 0u);

    uint64_t sum = r.donation_amount;
    for (auto& [s, a] : r.payout_outputs) sum += a;
    EXPECT_EQ(sum, 20000u);
}

// --- Empty weights (bootstrap): no payouts, whole subsidy is donation --------
// V36 floor is skipped when amounts is empty, so donation == subsidy exactly.
TEST(PplnsPayoutSplit, V36EmptyWeightsAllDonation)
{
    std::map<Script, uint288> w;
    auto r = dgb::coin::compute_pplns_payout_split(
        w, uint288(0), /*subsidy*/10000, /*use_v36*/true, /*finder*/{});

    EXPECT_TRUE(r.payout_outputs.empty());
    EXPECT_EQ(r.donation_amount, 10000u);
}

// --- Sub-satoshi weight dropped (amount==0 not emitted) ----------------------
// subsidy 100, weights BIG:1000000 TINY:1 (total 1000001): TINY -> 0, dropped.
TEST(PplnsPayoutSplit, V36ZeroAmountDropped)
{
    std::map<Script, uint288> w{{SA, uint288(1000000)}, {SB, uint288(1)}};
    auto r = dgb::coin::compute_pplns_payout_split(
        w, uint288(1000001), /*subsidy*/100, /*use_v36*/true, /*finder*/{});

    // Only SA survives (SA = 100*1000000/1000001 = 99; SB = 0, dropped).
    ASSERT_EQ(r.payout_outputs.size(), 1u);
    EXPECT_EQ(r.payout_outputs[0].first, SA);
    EXPECT_EQ(r.payout_outputs[0].second, 99u);
    EXPECT_EQ(r.donation_amount, 1u); // 100 - 99
}

// ============================================================================
// VALUE-INVARIANCE (before-vs-after) differential KAT.
//
// The #329 delegation replaces the inline steps 2-3 of
// share_check.hpp generate_share_transaction() with a call to
// compute_pplns_payout_split(). To prove that refactor moves ZERO payout value
// — identical scripts, identical satoshi splits, identical donation — we embed
// the PRE-REFACTOR inline algorithm here verbatim (transcribed line-for-line
// from the share_check.hpp generate_share_transaction() body that #329 removed)
// as legacy_inline_payout_split(), and assert the helper reproduces it
// satoshi-for-satoshi across a broad battery of inputs. A PASS is direct proof
// that emission/verification payout outputs are byte/value-identical before and
// after the SSOT extraction.
// ============================================================================

struct LegacySplit {
    Payouts payout_outputs;
    uint64_t donation_amount{0};
};

// Verbatim transcription of share_check.hpp generate_share_transaction()
// steps 2-3 as they stood BEFORE commit 57cb51db6 (the #329 delegation).
LegacySplit legacy_inline_payout_split(
    const std::map<Script, uint288>& weights,
    const uint288& total_weight,
    uint64_t subsidy,
    bool use_v36_pplns,
    const Script& finder_script)
{
    std::map<Script, uint64_t> amounts;

    if (!total_weight.IsNull())
    {
        for (auto& [script, weight] : weights)
        {
            uint64_t amount;
            if (use_v36_pplns)
            {
                uint288 num = uint288(subsidy) * weight;
                amount = (num / total_weight).GetLow64();
            }
            else
            {
                uint288 num = uint288(subsidy) * (weight * 199);
                uint288 den = total_weight * 200;
                amount = (num / den).GetLow64();
            }
            if (amount > 0)
                amounts[script] = amount;
        }
    }

    if (!use_v36_pplns)
        amounts[finder_script] += subsidy / 200;

    uint64_t sum_amounts = 0;
    for (auto& [s, a] : amounts)
        sum_amounts += a;
    uint64_t donation_amount = (subsidy > sum_amounts) ? (subsidy - sum_amounts) : 0;

    if (use_v36_pplns) {
        if (donation_amount < 1 && subsidy > 0 && !amounts.empty()) {
            auto largest = std::max_element(amounts.begin(), amounts.end(),
                [](const auto& a, const auto& b) {
                    if (a.second != b.second) return a.second < b.second;
                    return a.first < b.first;
                });
            if (largest != amounts.end() && largest->second > 0) {
                largest->second -= 1;
                sum_amounts -= 1;
                donation_amount = subsidy - sum_amounts;
            }
        }
    }

    LegacySplit out;
    out.donation_amount = donation_amount;
    out.payout_outputs.assign(amounts.begin(), amounts.end());
    std::sort(out.payout_outputs.begin(), out.payout_outputs.end(),
        [](const auto& a, const auto& b) {
            if (a.second != b.second) return a.second < b.second;
            return a.first < b.first;
        });
    constexpr size_t MAX_OUTPUTS = 4000;
    if (out.payout_outputs.size() > MAX_OUTPUTS)
        out.payout_outputs.erase(out.payout_outputs.begin(),
                                 out.payout_outputs.end() - MAX_OUTPUTS);
    return out;
}

// Deterministic varied scenario battery: every case asserts the extracted SSOT
// equals the legacy inline algorithm on scripts, amounts, ordering AND donation.
TEST(PplnsPayoutSplitInvariance, HelperEqualsLegacyInlineBattery)
{
    auto script_of = [](uint32_t i) {
        // 4-byte little-endian scriptPubKey surrogate (distinct per index).
        return Script{static_cast<unsigned char>(i & 0xff),
                      static_cast<unsigned char>((i >> 8) & 0xff),
                      static_cast<unsigned char>((i >> 16) & 0xff),
                      static_cast<unsigned char>((i >> 24) & 0xff)};
    };

    struct Case { uint64_t subsidy; bool v36; uint32_t n; uint32_t seed; };
    const std::vector<Case> cases = {
        {10000,   true,  2,   1},   // basic v36 + donation floor
        {20000,   false, 2,   2},   // pre-v36 + finder fee
        {100,     true,  2,   3},   // sub-satoshi drop
        {0,       true,  5,   4},   // zero subsidy
        {625000000, true, 17, 5},   // realistic DGB subsidy, many miners
        {625000000, false,17, 6},   // same, pre-v36 path
        {1,       true,  3,   7},   // 1-sat subsidy, donation-floor stress
        {7,       true,  9,   8},   // many miners, tiny subsidy (equal-amt ties)
        {999983,  true,  40,  9},   // primes -> rounding remainders
        {123456789,false,128, 10},  // large fan-out, pre-v36
        {500000000,true, 250, 11},  // wide payout set
        {50000000,true,  4096,12},  // EXCEEDS PPLNS_MAX_OUTPUTS (4000) -> truncation
    };

    for (const auto& c : cases) {
        std::map<Script, uint288> w;
        uint64_t acc = c.seed;
        uint288 total(0);
        for (uint32_t i = 0; i < c.n; ++i) {
            // Deterministic pseudo-weights (LCG), kept modest; some collide to 0.
            acc = acc * 6364136223846793005ull + 1442695040888963407ull;
            uint64_t wt = (acc >> 17) % 1000003ull;          // 0 .. ~1e6
            if (wt == 0) wt = 1;
            uint288 wu(wt);
            w[script_of(i)] = wu;
            total += wu;
        }
        Script finder = script_of(0); // share creator == first miner

        auto got = dgb::coin::compute_pplns_payout_split(
            w, total, c.subsidy, c.v36, finder);
        auto exp = legacy_inline_payout_split(
            w, total, c.subsidy, c.v36, finder);

        EXPECT_EQ(got.payout_outputs, exp.payout_outputs)
            << "payout outputs diverged: subsidy=" << c.subsidy
            << " v36=" << c.v36 << " n=" << c.n;
        EXPECT_EQ(got.donation_amount, exp.donation_amount)
            << "donation diverged: subsidy=" << c.subsidy
            << " v36=" << c.v36 << " n=" << c.n;

        // Conservation: every satoshi of subsidy is accounted for — but ONLY
        // when no [-4000:] truncation dropped outputs (truncation legitimately
        // sheds the smallest payouts in BOTH implementations identically).
        if (c.subsidy > 0 && c.n <= dgb::coin::PPLNS_MAX_OUTPUTS) {
            uint64_t sum = got.donation_amount;
            for (auto& [s, a] : got.payout_outputs) sum += a;
            EXPECT_EQ(sum, c.subsidy)
                << "value leaked/created: subsidy=" << c.subsidy;
        }

        // Truncation honoured identically.
        EXPECT_LE(got.payout_outputs.size(), dgb::coin::PPLNS_MAX_OUTPUTS);
    }
}

} // namespace