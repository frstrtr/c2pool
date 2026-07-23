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