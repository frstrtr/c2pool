// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH G1 difficulty / vardiff PARITY KAT.
//
// Pins the DASH sharechain difficulty floor and its per-share work accounting
// to oracle-EXACT arithmetic from frstrtr/p2pool-dash (networks/dash.py +
// bitcoin/data.py). Two independent surfaces:
//
//   1. dash::SharechainConfig::max_target() — the share-diff floor (easiest allowed
//      share target). Byte-exact to the oracle _DIFF1_TARGET (mainnet) and the
//      2**256//2**20-1 testnet floor.
//   2. chain::target_to_average_attempts(target) == 2**256 // (target+1) — the
//      per-share MINIMUM work that ShareIndex accumulates from m_max_bits
//      (share_chain.hpp:228). This is the quantity that drives cumulative-work
//      / APS retarget parity across the chain.
//
// Every expected value is derived INDEPENDENTLY from the oracle integer formula
// (see the derive comment on each vector), NOT read back from the SUT — a true
// byte-parity pin, not a tautology. The cross-coin APS-over-chain accumulation
// is already pinned LTC-instantiated in test_compute_share_target.cpp; this KAT
// pins the DASH-specific config floor + the min_work-per-share derivation those
// oracle numbers differ on (p2pool-dash, not p2pool-ltc).
//
// Pure / socket-free / node-free: no VM200/201 dashd, no live sharechain.
// Runs on every Linux x86_64 ctest.

#include <gtest/gtest.h>

#include <core/target_utils.hpp>
#include <core/uint256.hpp>
#include <impl/dash/config_pool.hpp>

namespace {
uint288 U288(const char* h) { uint288 t; t.SetHex(h); return t; }
}  // namespace

// ── 1. share-diff floor byte-exactness (networks/dash.py SHARE_MAX_TARGET) ──

// mainnet floor == 0xFFFF * 2**208 (standard bdiff difficulty-1 target).
TEST(DashDifficultyParity, MainnetMaxTargetFloorExact)
{
    dash::SharechainConfig::is_testnet = false;
    EXPECT_EQ(dash::SharechainConfig::max_target().GetHex(),
        "00000000ffff0000000000000000000000000000000000000000000000000000");
}

// testnet floor == 2**256 // 2**20 - 1. Derive (python3):
//   "%064x" % (2**256 // 2**20 - 1)
TEST(DashDifficultyParity, TestnetMaxTargetFloorExact)
{
    dash::SharechainConfig::is_testnet = true;
    EXPECT_EQ(dash::SharechainConfig::max_target().GetHex(),
        "00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    dash::SharechainConfig::is_testnet = false;
}

// ── 2. per-share min_work = target_to_average_attempts(floor) ───────────────
//
// ShareIndex(share).min_work = target_to_average_attempts(bits_to_target(
//   m_max_bits))  (share_chain.hpp:228). At the difficulty floor that reduces
// to target_to_average_attempts(max_target()).

// mainnet: attempts = 2**256 // (0xFFFF*2**208 + 1). Derive (python3):
//   (2**256)//(0xFFFF*(2**208)+1)  ==  4295032833  ==  0x100010001
TEST(DashDifficultyParity, MainnetPerShareMinWorkExact)
{
    dash::SharechainConfig::is_testnet = false;
    uint288 attempts = chain::target_to_average_attempts(dash::SharechainConfig::max_target());
    EXPECT_EQ(attempts.GetHex(), U288("100010001").GetHex());
    EXPECT_TRUE(attempts == static_cast<uint64_t>(4295032833ULL));
}

// testnet: attempts = 2**256 // (2**256//2**20). Derive (python3):
//   (2**256)//((2**256//2**20-1)+1)  ==  1048576  ==  2**20  ==  0x100000
TEST(DashDifficultyParity, TestnetPerShareMinWorkExact)
{
    dash::SharechainConfig::is_testnet = true;
    uint288 attempts = chain::target_to_average_attempts(dash::SharechainConfig::max_target());
    EXPECT_EQ(attempts.GetHex(), U288("100000").GetHex());
    EXPECT_TRUE(attempts == static_cast<uint64_t>(1048576ULL));
    dash::SharechainConfig::is_testnet = false;
}

// ── 3. ShareIndex min_work accumulation identity (dash floor) ───────────────
//
// Over N equal-floor shares the accumulated min_work == per_share * N, the same
// identity DeltaCache maintains (test_compute_share_target DeltaCacheAfterPruning,
// LTC). Pinned here with DASH-floor numbers so a config-floor regression is
// caught in the DASH lane directly.
TEST(DashDifficultyParity, MainnetMinWorkAccumulationIdentity)
{
    dash::SharechainConfig::is_testnet = false;
    uint288 per_share = chain::target_to_average_attempts(dash::SharechainConfig::max_target());
    // N=199 (default real_chain window sample). Derive (python3):
    //   4295032833 * 199 == 854711533767
    uint288 acc = per_share * static_cast<uint64_t>(199);
    EXPECT_TRUE(acc == static_cast<uint64_t>(854711533767ULL));
}

// ── 4. floor bits roundtrip (m_max_bits <-> floor target) ───────────────────
//
// ShareIndex derives min_work from m_max_bits via bits_to_target; the floor
// must survive the compact encode/decode used to carry it on the wire.
TEST(DashDifficultyParity, MainnetFloorBitsRoundtrip)
{
    dash::SharechainConfig::is_testnet = false;
    uint256 floor = dash::SharechainConfig::max_target();
    uint32_t bits = chain::target_to_bits_upper_bound(floor);
    uint256 decoded = chain::bits_to_target(bits);
    EXPECT_EQ(decoded, floor);          // exact roundtrip at the standard floor
    EXPECT_EQ(bits >> 24, 0x1du);       // 0xFFFF*2**208 -> exponent 0x1d (29 bytes)
}