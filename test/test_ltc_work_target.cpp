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
#include <core/stratum_username.hpp>

#include <string>

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

// p2pool bitcoin/data.py difficulty_to_target(float(N)) (chain::
// difficulty_to_target), the target of a login "/N". Derive (python3 -I):
//   d2t = lambda d: min(int((0xffff0000 * 2**(256-64) + 1)/d - 1 + 0.5), 2**256-1)
//   "%064x" % d2t(N)
// 1e-241: the quotient overflows a double, python's int() raises (get_user_details
// catches it: no target).
TEST(LtcWorkTarget, DifficultyToTargetIsPythons)
{
    struct Case { double n; const char* hex; };
    const Case cases[] = {
        {1.0, "00000000ffff0000000000000000000000000000000000000000000000000000"},
        {512.0, "00000000007fff80000000000000000000000000000000000000000000000000"},
        {0.5, "00000001fffe0000000000000000000000000000000000000000000000000000"},
        {1.5, "00000000aaaa0000000000000000000000000000000000000000000000000000"},
        {3.0, "0000000055550000000000000000000000000000000000000000000000000000"},
        {7.0, "0000000024922492492492000000000000000000000000000000000000000000"},
        {65536.0, "000000000000ffff000000000000000000000000000000000000000000000000"},
        {0.001, "000003e7fc180000000000000000000000000000000000000000000000000000"},
        {1e6, "00000000000010c6e6d9be4cd700000000000000000000000000000000000000"},
        {123.456, "000000000212d63ee7b6be400000000000000000000000000000000000000000"},
        {2.4e-10, "f859515061000000000000000000000000000000000000000000000000000000"},
        {2.3e-10, MAX_TARGET_HEX},   // min(..., 2**256-1)
        {1e-240, MAX_TARGET_HEX},
        {1e50, "00000000000000000000000000000000000000000000000003bdcb8b8b4da940"},
        {1e300, "0000000000000000000000000000000000000000000000000000000000000000"},
    };
    for (const auto& c : cases) {
        SCOPED_TRACE(c.n);
        const auto t = chain::difficulty_to_target(c.n);
        ASSERT_TRUE(t.has_value());
        EXPECT_EQ(t->GetHex(), c.hex);
    }
    EXPECT_FALSE(chain::difficulty_to_target(1e-241).has_value()) << "python: OverflowError";
    EXPECT_FALSE(chain::difficulty_to_target(0.0).has_value());
    EXPECT_FALSE(chain::difficulty_to_target(-1.0).has_value());
}

// A login "/N": p2pool get_work takes desired_share_target from
// get_user_details and runs neither cap (both under `if desired_share_target
// is None`), so the desired target is difficulty_to_target(N) whatever the
// rate and the dust rule (the band clip follows, in compute_share_target).
// N is in p2pool's units (difficulty 1 = 0x00000000ffff...), not scaled by
// DUMB_SCRYPT_DIFF. An N whose target python raises on: the caps, as without.
TEST(LtcWorkTarget, LoginShareDifficultyReplacesBothCaps)
{
    JobTargetInputs in;
    in.local_hash_rate = 5e9;
    in.share_period = 15;
    in.pool_aps = 1.455e11;
    in.subsidy = 625537917;
    in.donation_percent = 1.0;
    in.dust_threshold = 3000000;
    in.spread = 3;
    in.block_bits = 0x192d56b7;
    const std::string capped = job_desired_share_target(in).GetHex();
    in.share_difficulty = 512.0;
    EXPECT_EQ(job_desired_share_target(in).GetHex(),
              "00000000007fff80000000000000000000000000000000000000000000000000");
    in.local_hash_rate = 0.0;   // the dust rule would apply: not with "/N"
    EXPECT_EQ(job_desired_share_target(in).GetHex(),
              "00000000007fff80000000000000000000000000000000000000000000000000");
    in.local_hash_rate = 5e9;
    in.share_difficulty = 1e-241;
    EXPECT_EQ(job_desired_share_target(in).GetHex(), capped) << "no target from \"/N\": the caps";
    in.share_difficulty.reset();
    EXPECT_EQ(job_desired_share_target(in).GetHex(), capped) << "no \"/N\": unchanged";
}

// The stratum parser takes a login "+N" / "/N" exactly where
// chain::difficulty_to_target has a value (stratum_username::parse_login_diff),
// and both exactly where python's difficulty_to_target(float(N)) does not
// raise. Derive (python3 -I), the boundary pair included:
//   d2t = lambda d: min(int((0xffff0000 * 2**(256-64) + 1)/d - 1 + 0.5), 2**256-1)
//   d2t(float("1.4996739303382901e-241"))  -> OverflowError
//   d2t(float("1.4996739303382902e-241"))  -> 2**256-1
TEST(LtcWorkTarget, LoginDiffParseAcceptsWhatDifficultyToTargetDoes)
{
    struct Case { const char* n; bool python_takes; };
    const Case cases[] = {
        {"1e-300", false}, {"1e-242", false}, {"1e-241", false},
        {"1.4996739303382901e-241", false}, {"1.4996739303382902e-241", true},
        {"1.4996739303382903e-241", true}, {"2.7e-241", true}, {"1e-240", true}, {"2.3e-10", true},
        {"1", true}, {"512", true}, {"1e50", true}, {"1e300", true},
    };
    for (const auto& c : cases) {
        SCOPED_TRACE(c.n);
        EXPECT_EQ(core::stratum_username::parse_login_diff(c.n).has_value(), c.python_takes);
        EXPECT_EQ(chain::difficulty_to_target(std::stod(c.n)).has_value(), c.python_takes);
    }
}
