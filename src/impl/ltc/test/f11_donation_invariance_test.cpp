// SPDX-License-Identifier: AGPL-3.0-or-later
// F11 value-invariance KAT — guards the canonical exclude-then-append donation
// handling in the LTC v36 payout sort (src/impl/ltc/share_check.hpp,
// build_payout_outputs_excluding_donation).
//
// Backfills the coverage gap that let PR-0 S1 (133ae6bc) silently revert the
// original F11 (18dd9457) on a stale base: there was no test asserting the
// parity arithmetic, so the regression shipped unnoticed.
//
// Invariant under test (mirrors p2pool data.py generate_transaction):
//   - per-miner payout dests EXCLUDE both donation scripts (COMBINED P2SH + P2PK)
//   - COMBINED_DONATION_SCRIPT-keyed weight FOLDS into the single donation-last
//     output (moved, not destroyed)
//   - DONATION_SCRIPT (P2PK)-keyed weight is DROPPED — value-neutral ONLY because
//     that key never accrues weight in canonical v36 operation
//   - total coinbase value out == subsidy  (no value created/destroyed)
//
// Portable shape: BTC asserts the same invariant set against its own
// build_payout_outputs_excluding_donation + its own donation constants.
// Coordinated with btc-heap-opt-2026-05.

#include <gtest/gtest.h>

#include <map>
#include <vector>
#include <cstdint>
#include <numeric>

#include <impl/ltc/share.hpp>
#include <impl/ltc/config_pool.hpp>
#include <impl/ltc/share_check.hpp>

namespace {

using Script  = std::vector<unsigned char>;
using Amounts = std::map<Script, uint64_t>;

Script combined_script() {
    return Script(ltc::PoolConfig::COMBINED_DONATION_SCRIPT.begin(),
                  ltc::PoolConfig::COMBINED_DONATION_SCRIPT.end());
}
Script p2pk_script() {
    return Script(ltc::PoolConfig::DONATION_SCRIPT.begin(),
                  ltc::PoolConfig::DONATION_SCRIPT.end());
}
// Distinct miner payout scripts (P2PKH-shaped; bytes are arbitrary but != donation).
Script miner(unsigned char tag) {
    return Script{0x76, 0xa9, 0x14, tag, tag, tag, tag, tag, tag, tag, tag, tag, tag,
                  tag, tag, tag, tag, tag, tag, tag, tag, tag, tag, 0x88, 0xac};
}

uint64_t sum_amounts(const Amounts& a) {
    uint64_t s = 0; for (auto& kv : a) s += kv.second; return s;
}
uint64_t sum_outputs(const std::vector<std::pair<Script, uint64_t>>& o) {
    uint64_t s = 0; for (auto& kv : o) s += kv.second; return s;
}
bool contains_script(const std::vector<std::pair<Script, uint64_t>>& o, const Script& s) {
    for (auto& kv : o) if (kv.first == s) return true;
    return false;
}

// Reproduces the production pre-fold accounting at each gentx site:
//   donation_amount = subsidy - sum(amounts), then the helper folds COMBINED in.
struct FoldResult {
    std::vector<std::pair<Script, uint64_t>> payout_outputs;
    uint64_t donation_amount;
};
FoldResult run_fold(const Amounts& amounts, uint64_t subsidy) {
    uint64_t sa = sum_amounts(amounts);
    uint64_t donation_amount = (subsidy > sa) ? (subsidy - sa) : 0;
    auto outs = ltc::build_payout_outputs_excluding_donation(
        amounts, combined_script(), p2pk_script(), donation_amount);
    return {outs, donation_amount};
}

} // namespace

// Canonical case: COMBINED weight present, no P2PK weight. The fold must be
// fully value-invariant — every satoshi of subsidy is accounted for.
TEST(LTC_F11_DonationInvariance, CombinedFoldedNoP2PK) {
    const uint64_t subsidy = 1000;
    Amounts amounts{
        {miner(0x01), 100},
        {miner(0x02), 250},
        {miner(0x03),  75},
        {combined_script(), 40},   // donation weight keyed by COMBINED P2SH
    };

    auto r = run_fold(amounts, subsidy);

    // per-miner dests exclude the donation script
    EXPECT_EQ(r.payout_outputs.size(), 3u);
    EXPECT_FALSE(contains_script(r.payout_outputs, combined_script()));
    EXPECT_FALSE(contains_script(r.payout_outputs, p2pk_script()));
    EXPECT_TRUE(contains_script(r.payout_outputs, miner(0x01)));
    EXPECT_TRUE(contains_script(r.payout_outputs, miner(0x02)));
    EXPECT_TRUE(contains_script(r.payout_outputs, miner(0x03)));

    // known answer: donation-last output grew by exactly the COMBINED weight
    // donation_initial = 1000 - (100+250+75+40) = 535 ; +40 folded = 575
    EXPECT_EQ(r.donation_amount, 575u);
    EXPECT_EQ(sum_outputs(r.payout_outputs), 425u);

    // VALUE INVARIANCE: per-miner outputs + donation-last == subsidy
    EXPECT_EQ(sum_outputs(r.payout_outputs) + r.donation_amount, subsidy);
}

// Both donation scripts present; P2PK at canonical weight 0. Both excluded from
// per-miner dests; dropping the 0-weight P2PK key is value-neutral.
TEST(LTC_F11_DonationInvariance, BothDonationScriptsExcluded_P2PKZeroWeight) {
    const uint64_t subsidy = 5000;
    Amounts amounts{
        {miner(0x0a), 1200},
        {miner(0x0b),  800},
        {combined_script(), 333},
        {p2pk_script(), 0},        // canonical: P2PK never accrues weight
    };

    auto r = run_fold(amounts, subsidy);

    EXPECT_EQ(r.payout_outputs.size(), 2u);
    EXPECT_FALSE(contains_script(r.payout_outputs, combined_script()));
    EXPECT_FALSE(contains_script(r.payout_outputs, p2pk_script()));

    // donation_initial = 5000 - (1200+800+333+0) = 2667 ; +333 = 3000
    EXPECT_EQ(r.donation_amount, 3000u);
    EXPECT_EQ(sum_outputs(r.payout_outputs) + r.donation_amount, subsidy);
}

// No donation keys at all: the fold is an identity over the miner set and the
// donation-last output is unchanged.
TEST(LTC_F11_DonationInvariance, NoDonationKeys_Identity) {
    const uint64_t subsidy = 2000;
    Amounts amounts{
        {miner(0x21), 600},
        {miner(0x22), 400},
    };

    auto r = run_fold(amounts, subsidy);

    EXPECT_EQ(r.payout_outputs.size(), 2u);
    EXPECT_EQ(r.donation_amount, 1000u);  // 2000 - 1000, no fold
    EXPECT_EQ(sum_outputs(r.payout_outputs) + r.donation_amount, subsidy);
}

// Boundary documentation: if the P2PK key DID carry weight (non-canonical),
// dropping it would destroy exactly that many satoshis. This locks the reason
// the canonical invariant requires P2PK weight == 0, so a future change that
// starts keying weight on the P2PK script cannot pass silently.
TEST(LTC_F11_DonationInvariance, DroppedP2PKWeightLeaksExactlyThatWeight) {
    const uint64_t subsidy = 1000;
    const uint64_t p2pk_weight = 30;  // NON-canonical, for the boundary proof
    Amounts amounts{
        {miner(0x31), 200},
        {combined_script(), 50},
        {p2pk_script(), p2pk_weight},
    };

    auto r = run_fold(amounts, subsidy);

    // COMBINED still folds correctly; P2PK weight is dropped (not folded).
    EXPECT_FALSE(contains_script(r.payout_outputs, p2pk_script()));
    // Total is short by EXACTLY the dropped P2PK weight — value is conserved
    // iff p2pk_weight == 0.
    EXPECT_EQ(sum_outputs(r.payout_outputs) + r.donation_amount, subsidy - p2pk_weight);
}

// Pin the actual consensus donation bytes so a constant change trips this test.
TEST(LTC_F11_DonationInvariance, RealDonationConstantsPinned) {
    auto c = combined_script();
    ASSERT_EQ(c.size(), 23u);                 // P2SH: OP_HASH160 <20> OP_EQUAL
    EXPECT_EQ(c.front(), 0xa9);
    EXPECT_EQ(c[1], 0x14);
    EXPECT_EQ(c.back(), 0x87);

    auto p = p2pk_script();
    ASSERT_EQ(p.size(), 67u);                 // P2PK: OP_PUSHBYTES_65 <65> OP_CHECKSIG
    EXPECT_EQ(p.front(), 0x41);
    EXPECT_EQ(p.back(), 0xac);

    EXPECT_NE(c, p);
}