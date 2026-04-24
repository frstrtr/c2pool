/// Regression tests for bugs found during the Dash testnet battle-test
/// of 2026-04-24. Each test pins a specific bug fix from that session
/// so future refactors don't silently re-introduce it.
///
/// Bugs covered:
///   Bug 4 (`73a287a3`)  — DifficultyAdjustmentEngine::set_network_difficulty
///                         div-by-zero on sub-1.0 testnet difficulty
///   Bug 7 (`1074f6ad`)  — make_coin_params(testnet) was using mainnet's
///                         MAX_TARGET, breaking p2pool sharechain interop
///   Bug 5 (`509cf204`)  — DashNodeImpl had no node.listen() call, so the
///                         sharechain accept socket was never bound. Pins
///                         that the BaseNode/Factory still exposes the
///                         listen() signature we depend on.

#include <gtest/gtest.h>

#include <impl/dash/coin/utxo_adapter.hpp>
#include <impl/dash/params.hpp>
#include <c2pool/difficulty/adjustment_engine.hpp>
#include <core/uint256.hpp>

using c2pool::difficulty::DifficultyAdjustmentEngine;

// ─── Bug 4: sub-1.0 network difficulty must not throw ──────────────────

TEST(DashBugRegressions, Bug4_SetNetworkDifficulty_TestnetSub1)
{
    // Dash testnet at low-hashrate periods: difficulty=0.000244140625
    // (per dashd-cli getblockchaininfo). Pre-fix:
    //   network_target_ = max_target / static_cast<uint64_t>(0.000244)
    //                   = max_target / 0
    //                   → uint_error("Division by zero") thrown
    // Fix: branch on diff >= 1.0; for sub-1.0 use max_target * (1/diff).
    DifficultyAdjustmentEngine eng;
    EXPECT_NO_THROW({
        eng.set_network_difficulty(0.000244140625);
    }) << "Bug 4 regressed: sub-1.0 difficulty throws div-by-zero again";
    EXPECT_NO_THROW({
        eng.set_network_difficulty(0.5);
    });
    EXPECT_NO_THROW({
        eng.set_network_difficulty(0.999999);
    });
}

TEST(DashBugRegressions, Bug4_SetNetworkDifficulty_MainnetTypical)
{
    // Sanity: mainnet-typical difficulty (>1.0) still works.
    DifficultyAdjustmentEngine eng;
    EXPECT_NO_THROW({
        eng.set_network_difficulty(1.0);
    });
    EXPECT_NO_THROW({
        eng.set_network_difficulty(123456.789);
    });
    EXPECT_NO_THROW({
        eng.set_network_difficulty(1e15);
    });
}

TEST(DashBugRegressions, Bug4_SetNetworkDifficulty_RejectsZeroOrNegative)
{
    // The original guard (`if (diff <= 0) return;`) is preserved.
    // No throw, no state change.
    DifficultyAdjustmentEngine eng;
    EXPECT_NO_THROW({
        eng.set_network_difficulty(0.0);
        eng.set_network_difficulty(-1.0);
        eng.set_network_difficulty(-0.000001);
    });
}

// ─── Bug 7: testnet max_target must differ from mainnet ────────────────

TEST(DashBugRegressions, Bug7_TestnetMaxTarget_IsP2PoolTestnetCompatible)
{
    auto mainnet = dash::make_coin_params(false);
    auto testnet = dash::make_coin_params(true);

    // Mainnet: 0xFFFF * 2^208 = standard bdiff difficulty 1.
    uint256 expected_mainnet;
    expected_mainnet.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000");
    EXPECT_EQ(mainnet.max_target, expected_mainnet)
        << "Mainnet MAX_TARGET regressed";

    // Testnet: 2**256//2**20 - 1 (per p2pool-dash networks/dash_testnet.py).
    // Hex form: top 20 bits zero, rest 1s. As stored: 0x00000fffff... pattern.
    uint256 expected_testnet;
    expected_testnet.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    EXPECT_EQ(testnet.max_target, expected_testnet)
        << "Bug 7 regressed: testnet max_target reverted to mainnet value, "
           "p2pool-dash will reject every share with 'share PoW invalid'";

    // Crucial property: testnet target MUST be larger (easier).
    // Compare uint256 numerically — testnet max_target > mainnet max_target.
    EXPECT_GT(testnet.max_target, mainnet.max_target)
        << "testnet max_target should be 'easier' (larger numerical value) "
           "than mainnet";
}

TEST(DashBugRegressions, TestnetSharechainPortDiffersFromMainnet)
{
    // Discovered 2026-04-24 while investigating the testbed wrong_port
    // filter: params.hpp set p.p2p_port = 8999 unconditionally. The
    // testnet branch never overrode it, so DashNodeImpl's outbound peer
    // dialer rejected every real testnet peer (port 18999) as wrong_port
    // (node.hpp:618 `addr.port() != expected_port`). Federation then
    // worked only via inbound connections; once the address store was
    // exhausted, outbound dialing died entirely.
    auto mainnet = dash::make_coin_params(false);
    auto testnet = dash::make_coin_params(true);

    EXPECT_EQ(mainnet.p2p_port, 8999u)
        << "mainnet sharechain port regressed";
    EXPECT_EQ(testnet.p2p_port, 18999u)
        << "testnet sharechain port regressed — outbound dialer will reject "
           "every real testnet peer as wrong_port";
    EXPECT_NE(testnet.p2p_port, mainnet.p2p_port)
        << "testnet must NOT inherit mainnet's sharechain port";
}

TEST(DashBugRegressions, Bug7_TestnetVsMainnetTargetRatio)
{
    // Sanity: the testnet target should be roughly 2^(228-208) = 2^20 ~= 1e6
    // larger than mainnet's. This ratio is what makes testnet "way easier"
    // for CPU miners.
    auto mainnet = dash::make_coin_params(false);
    auto testnet = dash::make_coin_params(true);

    // Both have leading zeros; check the highest non-zero byte position.
    int testnet_lead_zeros = 0;
    int mainnet_lead_zeros = 0;
    const uint8_t* tn = testnet.max_target.data();    // little-endian
    const uint8_t* mn = mainnet.max_target.data();
    for (int i = 31; i >= 0; --i) {
        if (tn[i] == 0) ++testnet_lead_zeros; else break;
    }
    for (int i = 31; i >= 0; --i) {
        if (mn[i] == 0) ++mainnet_lead_zeros; else break;
    }
    // Testnet has FEWER leading zeros = larger target = easier.
    EXPECT_LT(testnet_lead_zeros, mainnet_lead_zeros)
        << "testnet should have fewer leading zero bytes than mainnet "
           "(easier difficulty floor)";
}

// ─── Bug 5: BaseNode must expose listen() so main_dash can bind ─────────

#include <impl/dash/node.hpp>

TEST(DashBugRegressions, Bug5_DashNodeImpl_HasListenMethod)
{
    // Pre-fix: main_dash.cpp never called node.listen(port) so the
    // sharechain accept socket was never bound (silent showstopper for
    // p2pool-dash interop). Fix added node.listen(port) in main_dash.
    // This test pins that the API surface main_dash relies on still
    // exists — if BaseNode/Factory ever drops listen(), this fails to
    // compile (which is exactly what we want).
    //
    // We don't actually invoke listen() here (would need a live ioc and
    // would bind to a port). The compile-time existence check is enough.
    using NodeT = dash::DashNodeImpl;
    static_assert(
        requires(NodeT n, uint16_t p) { n.listen(p); },
        "DashNodeImpl must expose listen(port) — Bug 5 regression"
    );
    SUCCEED();
}
