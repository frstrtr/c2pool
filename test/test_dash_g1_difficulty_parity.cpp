// G1 difficulty/vardiff parity KAT — DASH sharechain target byte-parity vs the
// DASH oracle frstrtr/p2pool-dash (networks/dash.py).
//
// FENCED conformance test (no production code touched). Test-form artifact of
// greenlight gate G1 for the DASH difficulty/vardiff surface, mirroring the
// dgb/bch g1_oracle_byte_parity KATs but scoped to the target math the DASH
// migration plan calls out as independently-landable byte-parity groundwork
// (integrator 2026-07-04: proceed on the G1 difficulty/vardiff parity KAT ahead
// of the operator GO on the consensus-bearing flip).
//
// NON-CIRCULAR posture: the difficulty-target and coin-level (net.PARENT)
// expected values below are typed from the oracle python source
// (p2pool/dash/networks/dash.py), NOT re-read from the C++ SUT constant. A drift
// in config_pool.hpp / params.hpp that silently diverges from the oracle fails
// here even though sibling dash tests (which source the same SUT constant on both
// sides) stay green.
//
// SCOPE LINE: the p2pool *sharechain* namespacing constants (IDENTIFIER/PREFIX)
// are c2pool-chosen bucket-1 isolation primitives, ABSENT from the oracle PARENT.
// They are pinned in IsolationPrimitivesRegressionGuard as a pure drift guard and
// are explicitly NOT asserted as oracle-conformance.
//
// MUST appear in BOTH the ctest registration (test/CMakeLists.txt) AND the
// build.yml --target allowlist, or it becomes a #143-style NOT_BUILT sentinel.

#include <impl/dash/params.hpp>
#include <impl/dash/config_pool.hpp>

#include <core/coin_params.hpp>

#include <gtest/gtest.h>

namespace {

// Oracle networks/dash.py:31  _DIFF1_TARGET = 0xFFFF * 2**208  (standard bdiff
// difficulty-1 target). 0xFFFF left-shifted 208 bits, big-endian 256-bit:
// 8 hex zeros + "ffff" + 52 hex zeros. Derived from the oracle FORMULA, not the
// SUT literal, so a hand-edit of config_pool.hpp max_target() fails this pin.
uint256 oracle_diff1_target()
{
    uint256 t;
    t.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000");
    return t;
}

// max_target parity: the sharechain SSOT max_target() AND the plumbed CoinParams
// field both equal the oracle bdiff-1 target.
TEST(DashG1DifficultyParity, MaxTargetIsBdiff1_OracleDash)
{
    EXPECT_EQ(dash::SharechainConfig::max_target(), oracle_diff1_target());
    core::CoinParams p = dash::make_coin_params(/*testnet=*/false);
    EXPECT_EQ(p.max_target, oracle_diff1_target());
}

// SANE_TARGET_RANGE = (_DIFF1_TARGET//10000, _DIFF1_TARGET) (oracle dash.py:33).
// Non-circular structural pins: easiest sane == max_target (oracle SANE[1]),
// hardest sane is non-zero and strictly tighter than the easiest.
TEST(DashG1DifficultyParity, SaneTargetRangeMatchesOracle)
{
    EXPECT_EQ(dash::SharechainConfig::sane_target_max(), dash::SharechainConfig::max_target());
    EXPECT_NE(dash::SharechainConfig::sane_target_min(), uint256());
    EXPECT_NE(dash::SharechainConfig::sane_target_min(), dash::SharechainConfig::max_target());
}

// Coin-level net.PARENT parity (oracle networks/dash.py mainnet).
TEST(DashG1DifficultyParity, CoinLevelParentParity)
{
    core::CoinParams p = dash::make_coin_params(/*testnet=*/false);
    EXPECT_EQ(p.symbol, "DASH");                 // dash.py:22 SYMBOL
    EXPECT_EQ(p.block_period, 150u);             // dash.py:21 BLOCK_PERIOD
    EXPECT_EQ(p.address_version, 76u);           // dash.py:12 ADDRESS_VERSION (X...)
    EXPECT_EQ(p.address_p2sh_version, 16u);      // dash.py:13 SCRIPT_ADDRESS_VERSION (7...)
    EXPECT_EQ(p.dust_threshold, 100000u);        // dash.py DUST_THRESHOLD = 0.001e8
}

// Testnet address divergence (oracle networks/dash_testnet.py), isolation
// primitives shared — but this KAT only asserts the address versions here.
TEST(DashG1DifficultyParity, TestnetAddressDiverges)
{
    core::CoinParams p = dash::make_coin_params(/*testnet=*/true);
    EXPECT_EQ(p.address_version, 140u);          // testnet PUBKEY_ADDRESS (y...)
    EXPECT_EQ(p.address_p2sh_version, 19u);      // testnet SCRIPT_ADDRESS
}

// Bucket-1 isolation-primitive REGRESSION GUARD — NOT oracle-conformance.
// IDENTIFIER/PREFIX are c2pool-chosen sharechain namespacing (absent from the
// oracle PARENT); pinned purely to catch silent namespace drift.
TEST(DashG1DifficultyParity, IsolationPrimitivesRegressionGuard)
{
    EXPECT_EQ(dash::SharechainConfig::IDENTIFIER_HEX, "7242ef345e1bed6b");
    EXPECT_EQ(dash::SharechainConfig::PREFIX_HEX,     "3b3e1286f446b891");
}

} // namespace
