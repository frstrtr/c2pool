// SPDX-License-Identifier: AGPL-3.0-or-later
// LTC producer-target helper KAT (#859).
//
// Pins ltc::stratum::average_attempts_to_target -- the double->target inverse
// the LTC mint path (main_ltc.cpp ref_hash_fn) feeds from Cap 1 (1.67%
// pool-share) and Cap 2 (dust ease). Every expected value below was computed
// independently from the oracle integer formula (2**256 // n - 1, clamped to
// [1, 2**256-1]), NOT from the SUT -- a true byte-parity pin.
//
// The load-bearing case is SaturatesAboveU64: the previous inlined narrowing
// static_cast<uint64_t>(avg_attempts) is UNDEFINED above 2**64 and on x86-64
// yields 0 -> "Division by zero" thrown out of the producer-job path, which
// work_source catches and degrades to a non-producer coinbase -- minting
// silently STOPS on LTC production. This KAT is RED on the pre-fix inline
// (throws) and GREEN once the divisor saturates at UINT64_MAX.
//
// Pure / socket-free / node-free: runs on every Linux x86_64 ctest.

#include <gtest/gtest.h>

#include <impl/ltc/work_target.hpp>

using namespace ltc::stratum;

namespace {
constexpr const char* MAX_TARGET_HEX =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
}

// avg <= 1.0 means "no meaningful cap" -> MAX target.
TEST(LtcWorkTarget, AverageAttemptsToTargetNoCap)
{
    EXPECT_EQ(average_attempts_to_target(0.0).GetHex(), MAX_TARGET_HEX);
    EXPECT_EQ(average_attempts_to_target(1.0).GetHex(), MAX_TARGET_HEX);
}

// average_attempts_to_target(n) == 2**256 // n - 1.  Derive (python3):
//   n = 1197604790419 ; "%064x" % (2**256//n - 1)
TEST(LtcWorkTarget, AverageAttemptsToTargetExact)
{
    EXPECT_EQ(average_attempts_to_target(1197604790419.0).GetHex(),
        "0000000000eb08174d325a04e29e57c52c14f6dcfc48f79979535e202dcecf3d");
}

// #859: SATURATE instead of invoking UB / throwing when avg_attempts >= 2**64.
// Divisor saturates at UINT64_MAX = 2**64-1, so the result is
//   2**256 // (2**64-1) - 1 == 2**192 + 2**128 + 2**64.  Derive (python3):
//   "%064x" % (2**256//(2**64-1) - 1)
TEST(LtcWorkTarget, AverageAttemptsToTargetSaturatesAboveU64)
{
    const char* SAT_HEX =
        "0000000000000001000000000000000100000000000000010000000000000000";
    EXPECT_EQ(average_attempts_to_target(1e20).GetHex(), SAT_HEX);
    EXPECT_EQ(average_attempts_to_target(1e40).GetHex(), SAT_HEX);
    // The producer-job path must never throw, whatever the measured rate.
    EXPECT_NO_THROW((void)average_attempts_to_target(1e18));
    EXPECT_NO_THROW((void)average_attempts_to_target(1e30));
}

// Cap 2 (dust) applies at a zero local rate, as p2pool's get_work does
// (work.py 3020-3028: expected_payout_per_block = local_addr_rates.get(
// pubkey_hash, 0) / pool_aps * subsidy * (1 - donation) = 0 < DUST, whatever
// the rate). c2pool applied it only to a rate > 0, so a job without a rate
// (a new connection, no pseudoshare recorded yet) got the easiest target
// instead of the dust one. LTC mainnet: block bits 0x192d56b7 (difficulty
// ~94.7M), subsidy 6.25537917 LTC, DUST 0.03 LTC, SPREAD 3. Derive (python3):
//   t = 0x2d56b7 << 8*(0x19-3); a = 2**256 // (t+1)
//   n = int(float(a) * 3 * 3000000.0 / 625537917.0)
//   "%064x" % (2**256 // n - 1)
TEST(LtcWorkTarget, DustRuleAppliesAtZeroRate)
{
    JobTargetInputs in;
    in.local_hash_rate = 0.0;
    in.share_period = 15;
    in.pool_aps = 1.455e11;
    in.subsidy = 625537917;
    in.donation_percent = 1.0;
    in.dust_threshold = 3000000;
    in.spread = 3;
    in.block_bits = 0x192d56b7;
    const char* DUST_HEX = "0000000000000c4f3b94aabd0a821d4c4d169a5f7f3743232985928b86e61c38";
    EXPECT_EQ(job_desired_share_target(in).GetHex(), DUST_HEX) << "no rate: the dust target, not 2**256-1";

    // A rate too small for Cap 1 and for DUST: the same target.
    in.local_hash_rate = 1e-6;
    EXPECT_EQ(job_desired_share_target(in).GetHex(), DUST_HEX);

    // No chain an hour deep (no pool rate): no Cap 2; no rate: no Cap 1.
    in.local_hash_rate = 0.0;
    in.pool_aps = 0.0;
    EXPECT_EQ(job_desired_share_target(in).GetHex(), MAX_TARGET_HEX);
}
