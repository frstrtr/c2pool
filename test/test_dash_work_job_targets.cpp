// DASH S8 get_work() JOB-TARGET assembly KAT.
//
// Pins dash::stratum::{modulate_desired_pseudoshare_target, clip_to_sane,
// assemble_work_job_targets} to oracle-EXACT arithmetic from
// frstrtr/p2pool-dash @9a0a609 work.py:368-426 (the get_work() pseudoshare
// modulation + SANE clip + the two job-target fields of the stratum work blob).
// Every expected value below was computed independently from the oracle integer
// formulas (see the derive comment on each vector), NOT from the SUT — a true
// byte-parity pin, not a tautology.
//
// Pure / socket-free / node-free: no VM200/201 dashd, no live sharechain.
//
// SANE_TARGET_RANGE inputs read from dash::PoolConfig SSOT (config_pool.hpp).

#include <gtest/gtest.h>

#include <impl/dash/stratum/work_job_targets.hpp>
#include <impl/dash/config_pool.hpp>

using namespace dash::stratum;

namespace {
constexpr const char* MAX_HEX =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
// Oracle SANE_TARGET_RANGE, mainnet (networks/dash.py:33):
//   min = (0xFFFF*2**208)//10000 ; max = 0xFFFF*2**208
constexpr const char* SMIN_HEX =
    "0000000000068db22d0e5604189374bc6a7ef9db22d0e5604189374bc6a7ef9d";
constexpr const char* SMAX_HEX =
    "00000000ffff0000000000000000000000000000000000000000000000000000";

uint256 U(const char* h) { uint256 t; t.SetHex(h); return t; }
}  // namespace

// modulate_desired_pseudoshare_target: no measured rate -> unconstrained MAX
// (work.py:369 target = 2**256-1, local_hash_rate path skipped).
TEST(DashWorkJobTargets, PseudoshareNoRate)
{
    EXPECT_EQ(modulate_desired_pseudoshare_target(0.0).GetHex(), MAX_HEX);
}

// modulate_desired_pseudoshare_target(lhr) == average_attempts_to_target(lhr*1)
// == 2**256 // int(lhr) - 1 (work.py:372-373).  Derive (python3):
//   "%064x" % (2**256//10000000000 - 1)
TEST(DashWorkJobTargets, PseudoshareExact)
{
    EXPECT_EQ(modulate_desired_pseudoshare_target(1e10).GetHex(),
        "000000006df37f675ef6eadf5ab9a2072d44268d97df837e6748956e5c6c2116");
}

// clip_to_sane = math.clip(x, (lo, hi)) (work.py:393).
TEST(DashWorkJobTargets, ClipBelowMinReturnsMin)
{
    EXPECT_EQ(clip_to_sane(U("01"), U(SMIN_HEX), U(SMAX_HEX)).GetHex(), SMIN_HEX);
}
TEST(DashWorkJobTargets, ClipAboveMaxReturnsMax)
{
    EXPECT_EQ(clip_to_sane(U(MAX_HEX), U(SMIN_HEX), U(SMAX_HEX)).GetHex(), SMAX_HEX);
}
TEST(DashWorkJobTargets, ClipInRangeUnchanged)
{
    // MID = SMIN*2, derived in-range (python3): smin=(0xFFFF*2**208)//10000
    const char* MID =
        "00000000000d1b645a1cac083126e978d4fdf3b645a1cac083126e978d4fdf3a";
    EXPECT_EQ(clip_to_sane(U(MID), U(SMIN_HEX), U(SMAX_HEX)).GetHex(), MID);
}

// dash::PoolConfig SANE_TARGET_RANGE SSOT == oracle networks/dash.py:33 +
// dash_testnet.py:27.
TEST(DashWorkJobTargets, PoolConfigSaneMatchesOracleMainnet)
{
    dash::PoolConfig::is_testnet = false;
    EXPECT_EQ(dash::PoolConfig::sane_target_min().GetHex(), SMIN_HEX);
    EXPECT_EQ(dash::PoolConfig::sane_target_max().GetHex(), SMAX_HEX);
}
TEST(DashWorkJobTargets, PoolConfigSaneMatchesOracleTestnet)
{
    dash::PoolConfig::is_testnet = true;
    EXPECT_EQ(dash::PoolConfig::sane_target_min().GetHex(),
        "00000000000010c6f7a0b5ed8d36b4c7f34938583621fafc8b0079a2834d26f9");
    EXPECT_EQ(dash::PoolConfig::sane_target_max().GetHex(),
        "00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    dash::PoolConfig::is_testnet = false;  // restore SSOT default
}

// assemble: None-path, modulated pseudoshare in SANE range -> share_target is the
// modulated value unchanged; min_share_target = share bits (below sane_max).
//   SHAREBITS = SMIN*3 (in-range, < sane_max).  lhr=1e10 -> PseudoshareExact value.
TEST(DashWorkJobTargets, AssembleNonePathInRange)
{
    WorkJobTargetInputs in;
    in.share_info_bits_target =
        U("000000000013a916872b020c49ba5e353f7ced916872b020c49ba5e353f7ced7");
    in.sane_target_min = U(SMIN_HEX);
    in.sane_target_max = U(SMAX_HEX);
    in.have_desired_pseudoshare = false;
    in.local_hash_rate = 1e10;

    WorkJobTargets out = assemble_work_job_targets(in);
    EXPECT_EQ(out.share_target.GetHex(),
        "000000006df37f675ef6eadf5ab9a2072d44268d97df837e6748956e5c6c2116");
    EXPECT_EQ(out.min_share_target.GetHex(),
        "000000000013a916872b020c49ba5e353f7ced916872b020c49ba5e353f7ced7");
}

// assemble: client-SUPPLIED pseudoshare target above sane_max -> clipped to
// sane_max; share bits also above sane_max -> min_share_target floored to sane_max.
TEST(DashWorkJobTargets, AssembleSuppliedClippedAndFloored)
{
    WorkJobTargetInputs in;
    in.share_info_bits_target = U(MAX_HEX);   // above sane_max -> floored
    in.sane_target_min = U(SMIN_HEX);
    in.sane_target_max = U(SMAX_HEX);
    in.have_desired_pseudoshare = true;
    in.desired_pseudoshare_target = U(MAX_HEX);  // above sane_max -> clipped

    WorkJobTargets out = assemble_work_job_targets(in);
    EXPECT_EQ(out.share_target.GetHex(), SMAX_HEX);
    EXPECT_EQ(out.min_share_target.GetHex(), SMAX_HEX);
}
