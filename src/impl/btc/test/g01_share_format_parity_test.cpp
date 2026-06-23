#include <gtest/gtest.h>

#include <string>

#include <impl/btc/config_pool.hpp>

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
