// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH S8 work-target MODULATION KAT.
//
// Pins dash::stratum::modulate_desired_share_target (+ its two caps) to
// oracle-EXACT arithmetic from frstrtr/p2pool-dash @9a0a609 work.py:308-326
// (the get_work() desired_share_target modulation). Every expected value below
// was computed independently from the oracle integer formulas (see the derive
// comment on each vector), NOT from the SUT — so this is a true byte-parity
// pin, not a tautology.
//
// Pure / socket-free / node-free: no VM200/201 dashd, no live sharechain. The
// accessor is a pure transform of frozen per-job inputs, so the KAT runs on
// every Linux x86_64 ctest.
//
// Inputs read from dash::SharechainConfig SSOT (config_pool.hpp): SHARE_PERIOD=20,
// SPREAD=10, DUST_THRESHOLD=100000 (mainnet).

#include <gtest/gtest.h>

#include <impl/dash/stratum/work_target.hpp>
#include <impl/dash/config_pool.hpp>

using namespace dash::stratum;

namespace {
constexpr const char* MAX_TARGET_HEX =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
}

// average_attempts_to_target: avg <= 1.0 means "no meaningful cap" -> MAX.
TEST(DashWorkTarget, AverageAttemptsToTargetNoCap)
{
    EXPECT_EQ(average_attempts_to_target(0.0).GetHex(), MAX_TARGET_HEX);
    EXPECT_EQ(average_attempts_to_target(1.0).GetHex(), MAX_TARGET_HEX);
}

// average_attempts_to_target(n) == 2**256 // n - 1.  Derive (python3):
//   n = 1197604790419 ; "%064x" % (2**256//n - 1)
TEST(DashWorkTarget, AverageAttemptsToTargetExact)
{
    EXPECT_EQ(average_attempts_to_target(1197604790419.0).GetHex(),
        "0000000000eb08174d325a04e29e57c52c14f6dcfc48f79979535e202dcecf3d");
}

// average_attempts_to_target SATURATES instead of invoking UB / throwing when
// avg_attempts >= 2**64. The uint64 narrowing is undefined there and on x86-64
// produces 0 -> "Division by zero" out of the divide. Cap 1 scales the miner's
// hashrate by SHARE_PERIOD/0.0167 (~1198x), so the boundary is only ~1.5e16 H/s
// of measured rate; a throw on the producer-job path would disable minting.
// Saturating at UINT64_MAX gives 2**256//2**64 - 1 -- harder than any chain
// band, so the band clip pins it to the edge (see the CapBand KATs).
TEST(DashWorkTarget, AverageAttemptsToTargetSaturatesAboveU64)
{
    const char* SAT_HEX =
        "0000000000000001000000000000000100000000000000010000000000000000";
    EXPECT_EQ(average_attempts_to_target(1e20).GetHex(), SAT_HEX);
    EXPECT_EQ(average_attempts_to_target(1e40).GetHex(), SAT_HEX);
    // Cap 1 must not throw for any plausible (or implausible) local rate.
    uint256 start; start.SetHex(MAX_TARGET_HEX);
    EXPECT_NO_THROW((void)cap_pool_share(start, 1e18,
                        dash::SharechainConfig::SHARE_PERIOD));
    EXPECT_NO_THROW((void)cap_pool_share(start, 1e30,
                        dash::SharechainConfig::SHARE_PERIOD));
}

// Cap 1 (pool-share, 1.67%): local_hash_rate=1e9 H/s, SHARE_PERIOD=20.
//   avg = int(1e9 * 20 / 0.0167) = 1197604790419
//   target = average_attempts_to_target(avg)  (same value as above)
TEST(DashWorkTarget, Cap1PoolShareExact)
{
    uint256 start; start.SetHex(MAX_TARGET_HEX);
    uint256 capped = cap_pool_share(start, /*local_hash_rate=*/1e9,
                                    dash::SharechainConfig::SHARE_PERIOD);
    EXPECT_EQ(capped.GetHex(),
        "0000000000eb08174d325a04e29e57c52c14f6dcfc48f79979535e202dcecf3d");
    // Cap must be strictly tighter than the unconstrained start.
    EXPECT_LT(capped, start);
}

// Cap 1 no-op when the miner has no measured hashrate (avg would be 0 -> MAX,
// and min() leaves the input untouched).
TEST(DashWorkTarget, Cap1NoHashrateNoOp)
{
    uint256 start; start.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000");
    EXPECT_EQ(cap_pool_share(start, 0.0, dash::SharechainConfig::SHARE_PERIOD).GetHex(),
              start.GetHex());
}

// ── Cap 1 at the LIVE production operating point ────────────────────────────
// Measured on the hotel DASH node: local_hash_rate ~= 43 TH/s, SHARE_PERIOD 20.
//   avg    = int(43e12 * 20 / 0.0167)     = 51497005988023952
//   target = 2**256 // avg - 1
// Derive (python3): "%064x" % (2**256//51497005988023952 - 1)
// The double->uint64 truncation in average_attempts_to_target is EXACTLY what
// python's int(43e12*20/0.0167) reproduces (both are IEEE-754 doubles), so this
// vector also pins the truncation, not just the big-int division.
TEST(DashWorkTarget, Cap1ProductionOperatingPoint)
{
    uint256 start; start.SetHex(MAX_TARGET_HEX);
    uint256 capped = cap_pool_share(start, /*local_hash_rate=*/43e12,
                                    dash::SharechainConfig::SHARE_PERIOD);
    EXPECT_EQ(capped.GetHex(),
        "000000000000016635c48b2e932ea609a3b4aa32cefaa1ba023ea945da766f85");
}

// ── Cap 1 is INERT for a small miner ────────────────────────────────────────
// The cap only ever binds once the miner exceeds 1.67% of the pool rate the
// current share target implies. Feed cap_pool_share the pool's own share
// target as `desired` (what the mint path effectively compares against after
// the band clip) and check the min() leaves it untouched.
//
// pre_target3 pinned at share difficulty 40000 (the value observed on the live
// node): pre3 = 0xFFFF*2**208 // 40000. Implied pool rate = ata(pre3)/20 =
// 8.59e12 H/s, so the cap binds only above 1.67% of that = 1.43e11 H/s.
//   100 GH/s  -> cap difficulty 27883 < 40000 -> cap target EASIER -> no-op.
TEST(DashWorkTarget, Cap1SmallMinerInert)
{
    uint256 pre3;
    pre3.SetHex("000000000001a36c8b4395810624dd2f1a9fbe76c8b4395810624dd2f1a9fbe7");
    EXPECT_EQ(cap_pool_share(pre3, /*local_hash_rate=*/1e11,
                             dash::SharechainConfig::SHARE_PERIOD).GetHex(),
              pre3.GetHex());
}

// ...and it DOES bind for a miner past that threshold: 1 TH/s -> cap difficulty
// 278834 > 40000, so the min() takes the (harder) cap target.
//   avg = int(1e12*20/0.0167) = 1197604790419161
// Derive (python3): "%064x" % (2**256//1197604790419161 - 1)
TEST(DashWorkTarget, Cap1LargeMinerBinds)
{
    uint256 pre3;
    pre3.SetHex("000000000001a36c8b4395810624dd2f1a9fbe76c8b4395810624dd2f1a9fbe7");
    uint256 capped = cap_pool_share(pre3, /*local_hash_rate=*/1e12,
                                    dash::SharechainConfig::SHARE_PERIOD);
    EXPECT_LT(capped, pre3);
    EXPECT_EQ(capped.GetHex(),
        "0000000000003c2b080360d2c25f6b37738a73ba1fd9f288bd67b93cf5e4af28");
}

// Cap 2 (dust ease): block_bits=0x1b00ffff, subsidy=5e8, SPREAD=10,
// DUST=100000, donation=0, local_hash_rate=1e9, pool_aps=1e9
// (-> expected_payout = (1e9/1e9)*5e8*1 = 5e8 satoshi... NOT below dust:
//  that path is the no-op test below). For the ease path we need a tiny
// expected_payout, so use local_hash_rate=1.0, pool_aps=1e15:
//   expected_payout = (1/1e15)*5e8 = 5e-7 < 100000 -> ease applies.
//   block_target = bits_to_target(0x1b00ffff)
//   block_aps = 2**256//(block_target+1) ; low64 = 281479271743489
//   dust_avg = int(281479271743489 * 10 * 100000 / 5e8) = 562958543486
//   target = average_attempts_to_target(562958543486)
TEST(DashWorkTarget, Cap2DustEaseExact)
{
    uint256 start; start.SetHex(MAX_TARGET_HEX);
    uint256 eased = cap_dust_threshold(start,
        /*local_hash_rate=*/1.0, /*pool_aps=*/1e15, /*subsidy=*/500000000ULL,
        /*block_bits=*/0x1b00ffffu, dash::SharechainConfig::SPREAD,
        dash::SharechainConfig::DUST_THRESHOLD, /*donation=*/0.0);
    EXPECT_EQ(eased.GetHex(),
        "0000000001f3fe0c0003bb0c8bcfc04043da7febb6bb21dd00bc321f5a6dda31");
}

// Cap 2 no-op when expected_payout >= dust (big miner, large payout).
TEST(DashWorkTarget, Cap2AboveDustNoOp)
{
    uint256 start; start.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000");
    uint256 r = cap_dust_threshold(start,
        /*local_hash_rate=*/1e9, /*pool_aps=*/1e9, /*subsidy=*/500000000ULL,
        /*block_bits=*/0x1b00ffffu, dash::SharechainConfig::SPREAD,
        dash::SharechainConfig::DUST_THRESHOLD, /*donation=*/0.0);
    EXPECT_EQ(r.GetHex(), start.GetHex());
}

// Cap 2 ungated (caller has no pool-aps estimate yet) -> no-op.
TEST(DashWorkTarget, Cap2UngatedNoOp)
{
    uint256 start; start.SetHex(MAX_TARGET_HEX);
    EXPECT_EQ(cap_dust_threshold(start, 1.0, /*pool_aps=*/0.0, 500000000ULL,
                  0x1b00ffffu, dash::SharechainConfig::SPREAD,
                  dash::SharechainConfig::DUST_THRESHOLD, 0.0).GetHex(),
              start.GetHex());
}

// Full modulation, Cap-1-only path (dust_gate=false): equals cap_pool_share.
TEST(DashWorkTarget, ModulateCap1OnlyPath)
{
    WorkTargetInputs in;
    in.local_hash_rate = 1e9;
    in.share_period    = dash::SharechainConfig::SHARE_PERIOD;
    in.dust_gate       = false;
    EXPECT_EQ(modulate_desired_share_target(in).GetHex(),
        "0000000000eb08174d325a04e29e57c52c14f6dcfc48f79979535e202dcecf3d");
}

// Full modulation, both gates: here Cap 1 (=0000..eb08..) is tighter than the
// Cap 2 ease (=0000..01f3..), so the pool-share cap dominates -> result == A.
TEST(DashWorkTarget, ModulateBothGatesPoolShareDominates)
{
    WorkTargetInputs in;
    in.local_hash_rate          = 1e9;
    in.share_period             = dash::SharechainConfig::SHARE_PERIOD;
    in.spread                   = dash::SharechainConfig::SPREAD;
    in.dust_threshold           = dash::SharechainConfig::DUST_THRESHOLD;
    in.dust_gate                = true;
    in.pool_attempts_per_second = 1e15;   // -> tiny expected payout -> ease armed
    in.subsidy                  = 500000000ULL;
    in.block_bits               = 0x1b00ffffu;
    in.donation_percentage      = 0.0;
    EXPECT_EQ(modulate_desired_share_target(in).GetHex(),
        "0000000000eb08174d325a04e29e57c52c14f6dcfc48f79979535e202dcecf3d");
}

// Unconstrained miner (no hashrate, no dust gate) keeps the max target.
TEST(DashWorkTarget, ModulateUnconstrainedIsMax)
{
    WorkTargetInputs in;  // all defaults: no hashrate, no gate
    EXPECT_EQ(modulate_desired_share_target(in).GetHex(), MAX_TARGET_HEX);
}