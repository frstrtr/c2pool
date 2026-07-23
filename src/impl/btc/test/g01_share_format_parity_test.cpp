// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <string>

#include <impl/btc/config_pool.hpp>
#include <core/version_gate.hpp>   // SSOT: V36_ACTIVATION_VERSION / is_v36_active

// G0/G1 — BTC share-format byte-parity against the BAKED p2pool baseline.
//
// Golden fixture: tools/conformance/fixtures/btc.g01.golden.json
//   provenance: p2pool-btc-jtoomim @ ece15b03fc23 (the canonical BTC fork pin),
//   emitted by tools/conformance/extract_share_format.py (static extraction).
//
// The fixture is the SSOT; the literals below are transcribed from it so the
// C++ port asserts byte-identity at run time. If the fixture is re-baked (a
// fork re-pin => a different --tree), update both in lockstep; the python
// `compare` subcommand guards the fixture against silent baseline drift.
//
// Bucket discipline (operator 3-bucket rule):
//   * ISOLATION PRIMITIVES (IDENTIFIER / PREFIX / P2P_PORT) — must be
//     byte-identical to the live sharechain or peers reject us. EQUALITY.
//   * Intentional / v36-native deltas — NOT asserted equal here:
//       - MINIMUM_PROTOCOL_VERSION: c2pool raises the floor (3500) above the
//         baseline (3301) to admit jtoomim-master/SPB and exclude forrestv-era
//         v17/v32. A floor RAISE is forward-compatible => assert >=, not ==.
//       - share-versions: c2pool is additive-v36 over the baseline [0..35]; the
//         v36 activation boundary is pinned separately by
//         BTC_version_gate.V36ActivationBoundary. Not re-asserted here.

namespace {

// --- transcribed from btc.g01.golden.json @ ece15b03fc23 ---------------------
constexpr const char* GOLDEN_IDENTIFIER = "fc70035c7a81bc6f";
constexpr const char* GOLDEN_PREFIX     = "2472ef181efcd37b";
constexpr uint16_t    GOLDEN_P2P_PORT   = 9333;
constexpr uint32_t    GOLDEN_SEGWIT_ACTIVATION_VERSION = 33;
constexpr uint32_t    GOLDEN_MINIMUM_PROTOCOL_VERSION  = 3301;

} // namespace

// Isolation primitives: byte-identical or we are off-network.
TEST(BTC_g01_share_format, IsolationPrimitivesMatchBaseline)
{
    EXPECT_EQ(btc::PoolConfig::DEFAULT_IDENTIFIER_HEX, std::string(GOLDEN_IDENTIFIER));
    EXPECT_EQ(btc::PoolConfig::DEFAULT_PREFIX_HEX,     std::string(GOLDEN_PREFIX));
    EXPECT_EQ(btc::PoolConfig::P2P_PORT,               GOLDEN_P2P_PORT);
    // Testnet shares the mainnet transport identity in this phase (config_pool).
    EXPECT_EQ(btc::PoolConfig::TESTNET_IDENTIFIER_HEX, std::string(GOLDEN_IDENTIFIER));
    EXPECT_EQ(btc::PoolConfig::TESTNET_PREFIX_HEX,     std::string(GOLDEN_PREFIX));
}

// Segwit activation version is a consensus byte — must match the baseline.
TEST(BTC_g01_share_format, SegwitActivationMatchesBaseline)
{
    EXPECT_EQ(btc::PoolConfig::SEGWIT_ACTIVATION_VERSION, GOLDEN_SEGWIT_ACTIVATION_VERSION);
}

// Protocol floor is an INTENTIONAL raise, not a parity break: forward-compatible.
TEST(BTC_g01_share_format, ProtocolFloorIsForwardCompatibleRaise)
{
    EXPECT_GE(btc::PoolConfig::MINIMUM_PROTOCOL_VERSION, GOLDEN_MINIMUM_PROTOCOL_VERSION)
        << "c2pool floor must not drop below the p2pool baseline";
}


// Share-version additive discipline (G1 bucket-2): the c2pool sharechain extends
// the p2pool baseline version set by EXACTLY ONE sanctioned version -- 36 -- the
// V36 share-format / consensus-revision boundary owned by the core::version_gate
// SSOT. c2pool has no p2pool-style share-version array to compare element-wise,
// so the additive is locked against the SSOT instead. The baseline set is
// transcribed from the golden fixture (constants.share_versions @ ece15b03fc23).
// This catches two drift modes the byte-parity TESTs above do not:
//   1. boundary drift -- V36_ACTIVATION_VERSION moving off 36 (an unsanctioned /
//      shifted version) fails here;
//   2. baseline-composition drift -- no baseline version may be treated as V36.
TEST(BTC_g01_share_format, ShareVersionAdditiveIsExactlyV36)
{
    // Transcribed from btc.g01.golden.json -> constants.share_versions.
    constexpr uint64_t GOLDEN_BASELINE_VERSIONS[] = {0, 17, 32, 33, 34, 35};

    // The SINGLE sanctioned additive over the p2pool baseline is the V36 boundary.
    EXPECT_EQ(core::version_gate::V36_ACTIVATION_VERSION, 36u)
        << "only sanctioned c2pool version added over the baseline is 36";

    // No baseline version is on the V36 side of the gate -- all pre-revision.
    for (uint64_t v : GOLDEN_BASELINE_VERSIONS)
        EXPECT_FALSE(core::version_gate::is_v36_active(v))
            << "baseline version " << v << " must remain pre-V36";

    // Boundary is exact: 36 activates, 35 (max baseline) does not.
    EXPECT_TRUE (core::version_gate::is_v36_active(36));
    EXPECT_FALSE(core::version_gate::is_v36_active(35));
}