/// Block-replay regression test harness — Phase 2 (test runner).
///
/// Loads all *.json fixtures from test/fixtures/dash_blocks/ and asserts
/// c2pool's pure-arithmetic Dash consensus formulas bit-exact against
/// the on-chain ground truth captured by dashd's getblock verbosity=2.
///
/// Design doc: frstrtr/the/docs/c2pool-dash-block-replay-test-harness.md
/// Day 1: block_dumper.hpp + 66 committed fixtures (commit cedc2655).
/// Day 2 (this file): per-block assertions on the formulas we can
/// validate without reconstructing in-memory state.
///
/// MVP coverage (Day 2):
///   1. Platform reward (Bug 15) — vout[0] OP_RETURN value matches
///      compute_dash_platform_reward_post_v20_mn_rr(height)
///   2. Subsidy formula — coinbase_total − sum(non-coinbase fees)
///      == compute_dash_block_reward_post_v20(height)
///   3. cbTx height self-consistency — block.cbTx.height == fixture height
///   4. Pre-MN_RR activation: no nulldata vout present; platform_reward=0
///
/// Future expansion (Day 3+ in design doc):
///   - Parse block_hex via c2pool's BlockType → run apply_block
///   - Validate find_expected_payee against the observed MN payee
///   - Validate SML root / quorums root
///
/// Runs in ~30s for 66 blocks. Fails fast: first MISMATCH gets a clear
/// per-block report; the rest still run so we see the full failure shape.

#include <gtest/gtest.h>

// utxo_adapter.hpp must come before subsidy.hpp so dash_txid is in scope
// for subsidy.hpp's computed_block_fees() helper. We don't use that helper
// directly but the header must compile cleanly.
#include <impl/dash/coin/utxo_adapter.hpp>
#include <impl/dash/coin/subsidy.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

using dash::coin::compute_dash_block_reward_post_v20;
using dash::coin::compute_dash_platform_reward_post_v20_mn_rr;
using dash::coin::DASH_MN_RR_HEIGHT_MAINNET;
using dash::coin::DASH_V20_HEIGHT_MAINNET;

// One fixture file → in-memory representation. Doesn't reconstruct the
// c2pool BlockType — uses only the JSON ground truth.
struct Fixture {
    uint32_t height = 0;
    std::string block_hash;
    int64_t coinbase_total_sat = 0;
    int64_t sum_non_coinbase_fees_sat = 0;
    // Platform burn — present (and positive) post-MN_RR; absent or zero pre-MN_RR.
    int64_t platform_burn_sat = 0;
    bool    has_platform_vout = false;
    // cbTx fields (decoded extraPayload — what dashd returned).
    uint32_t cbtx_height = 0;
    int32_t  cbtx_version = 0;
};

// DASH amounts in getblock verbosity=2 are floats (DASH not sat). Convert
// using lround to avoid double-to-int truncation surprises.
inline int64_t dash_to_sat(double dash)
{
    // 1 DASH = 100_000_000 sat. Round to nearest to handle floating noise.
    return static_cast<int64_t>(std::llround(dash * 1e8));
}

Fixture load_fixture(const std::filesystem::path& p)
{
    std::ifstream in(p);
    nlohmann::json j;
    in >> j;

    Fixture f;
    f.height     = j.at("height").get<uint32_t>();
    f.block_hash = j.at("block_hash").get<std::string>();

    const auto& bv = j.at("block_verbose");
    const auto& coinbase = bv.at("tx").at(0);

    for (const auto& vout : coinbase.at("vout")) {
        int64_t sat = dash_to_sat(vout.at("value").get<double>());
        f.coinbase_total_sat += sat;

        std::string type = vout.at("scriptPubKey").value("type", "");
        if (type == "nulldata") {
            // Platform burn output (DIP-0027). There should be at most one.
            f.platform_burn_sat += sat;
            f.has_platform_vout = true;
        }
    }

    // Non-coinbase fees. getblock verbosity=2 includes per-tx "fee" for
    // non-coinbase txs. Sum them.
    for (size_t i = 1; i < bv.at("tx").size(); ++i) {
        const auto& tx = bv.at("tx").at(i);
        if (tx.contains("fee")) {
            f.sum_non_coinbase_fees_sat += dash_to_sat(tx.at("fee").get<double>());
        }
    }

    if (coinbase.contains("cbTx")) {
        const auto& cb = coinbase.at("cbTx");
        f.cbtx_height  = cb.value("height",  0u);
        f.cbtx_version = cb.value("version", 0);
    }

    return f;
}

std::vector<std::filesystem::path> all_fixture_paths()
{
    // Resolve relative to the test source directory (passed by CMake at
    // configure time via -DTEST_FIXTURE_DIR=...). Fallback: try the
    // canonical path relative to the source tree.
#ifdef TEST_FIXTURE_DIR
    std::filesystem::path dir(TEST_FIXTURE_DIR);
#else
    std::filesystem::path dir("test/fixtures/dash_blocks");
#endif
    std::vector<std::filesystem::path> ps;
    if (!std::filesystem::exists(dir)) return ps;
    for (auto& entry : std::filesystem::directory_iterator(dir)) {
        if (entry.path().extension() == ".json") {
            ps.push_back(entry.path());
        }
    }
    std::sort(ps.begin(), ps.end());
    return ps;
}

} // anon namespace

// ─── Tests ──────────────────────────────────────────────────────────────────

TEST(BlockReplay, FixtureSetLoadable)
{
    auto paths = all_fixture_paths();
    ASSERT_GT(paths.size(), 50u)
        << "expected ≥50 fixtures; found " << paths.size()
        << ". Re-run `c2pool-dash --dump-blocks test/fixtures/dash_blocks "
           "--dashd-rpc HOST:PORT:U:P` to refresh.";
}

TEST(BlockReplay, CbTxHeightSelfConsistent)
{
    for (auto& path : all_fixture_paths()) {
        Fixture f = load_fixture(path);
        if (f.cbtx_version == 0) continue;  // pre-DIP-0008, no cbTx
        EXPECT_EQ(f.cbtx_height, f.height)
            << "fixture " << path.filename().string()
            << ": cbTx.height=" << f.cbtx_height
            << " but fixture.height=" << f.height;
    }
}

TEST(BlockReplay, PlatformRewardMatchesOPRETURNBurn)
{
    // Post-MN_RR every block has a nulldata vout for the platform burn.
    // Pre-MN_RR no such vout exists.
    for (auto& path : all_fixture_paths()) {
        Fixture f = load_fixture(path);
        int64_t computed = compute_dash_platform_reward_post_v20_mn_rr(f.height);

        if (f.height < static_cast<uint32_t>(DASH_MN_RR_HEIGHT_MAINNET)) {
            EXPECT_EQ(computed, 0)
                << "pre-MN_RR (h=" << f.height << ") must yield zero";
            EXPECT_FALSE(f.has_platform_vout)
                << "pre-MN_RR (h=" << f.height
                << ") must NOT have a nulldata vout";
        } else {
            EXPECT_TRUE(f.has_platform_vout)
                << "post-MN_RR (h=" << f.height
                << ") must have a nulldata vout (DIP-0027)";
            EXPECT_EQ(computed, f.platform_burn_sat)
                << "platform reward mismatch at h=" << f.height
                << " computed=" << computed
                << " on-chain=" << f.platform_burn_sat
                << " diff=" << (computed - f.platform_burn_sat);
        }
    }
}

TEST(BlockReplay, SubsidyFormulaMatchesCoinbaseMinusFees)
{
    // For every block: coinbase_total = subsidy + sum_fees. Therefore
    // computed_subsidy must == coinbase_total - sum_fees. (No platform
    // accounting needed here because platform comes OUT OF subsidy, so
    // coinbase_total still equals subsidy + fees.)
    //
    // Superblock heights are skipped: they carry additional treasury
    // outputs that inflate coinbase_total by ~7900 DASH. Mirrors the
    // existing [SUBSIDY-XCHECK] skip in main_dash.cpp.
    int checked = 0, skipped = 0;
    for (auto& path : all_fixture_paths()) {
        Fixture f = load_fixture(path);
        // Skip pre-V20: compute_dash_block_reward_post_v20 is documented
        // as post-V20 only; pre-V20 used a different schedule.
        if (f.height < static_cast<uint32_t>(DASH_V20_HEIGHT_MAINNET)) {
            ++skipped;
            continue;
        }
        if (dash::coin::is_superblock_height(f.height)) {
            ++skipped;
            continue;
        }
        int64_t computed_reward = compute_dash_block_reward_post_v20(f.height);
        int64_t observed_reward = f.coinbase_total_sat - f.sum_non_coinbase_fees_sat;
        EXPECT_EQ(computed_reward, observed_reward)
            << "subsidy formula mismatch at h=" << f.height
            << " computed=" << computed_reward
            << " observed=" << observed_reward
            << " (coinbase_total=" << f.coinbase_total_sat
            << " - fees=" << f.sum_non_coinbase_fees_sat << ")";
        ++checked;
    }
    EXPECT_GT(checked, 50) << "expected to check >50 non-superblock fixtures";
    // Make the skip count visible in successful runs (no log if all pass).
    if (skipped > 0) {
        std::cerr << "[BlockReplay] SubsidyFormulaMatchesCoinbaseMinusFees: "
                  << "checked=" << checked << " skipped(superblocks)=" << skipped
                  << std::endl;
    }
}

TEST(BlockReplay, KnownBug15AnchorHas3VoutsSplit)
{
    // Pin the original Bug 15 discovery shape: block 2,470,904 must have
    // 3 coinbase vouts with the specific values that surfaced the bug.
    // If anyone ever silently changes the fixture, this catches it.
    auto paths = all_fixture_paths();
    auto it = std::find_if(paths.begin(), paths.end(),
        [](const std::filesystem::path& p) {
            return p.filename().string() == "h2470904.json";
        });
    ASSERT_NE(it, paths.end()) << "Bug 15 anchor fixture missing";

    Fixture f = load_fixture(*it);
    EXPECT_EQ(f.platform_burn_sat, 49'787'579LL)
        << "Bug 15 anchor: expected platform=49,787,579 sat";
    EXPECT_EQ(f.coinbase_total_sat, 177'125'185LL)
        << "Bug 15 anchor: expected coinbase_total=177,125,185 sat";
    EXPECT_EQ(f.sum_non_coinbase_fees_sat, 102'680LL)
        << "Bug 15 anchor: expected fees=102,680 sat";
    EXPECT_TRUE(f.has_platform_vout);
}
