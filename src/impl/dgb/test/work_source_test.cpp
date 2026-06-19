// dgb::stratum::DGBWorkSource — Stage 4a skeleton construction + contract test.
//
// Proves the work source instantiates against the live coin types
// (c2pool::dgb::HeaderChain + dgb::coin::Mempool), satisfies the full
// core::stratum::IWorkSource pure-virtual contract (so core::StratumServer
// can hold it via shared_ptr<IWorkSource> in the next slice), and that its
// real-now surface (config defaults, atomic work-generation, share-target
// atomics, worker registry, best-share callback) behaves. The stubbed
// work-generation / submit methods are asserted to return their documented
// safe defaults so a regression that accidentally "implements" them with
// garbage is caught.
//
// MUST appear in BOTH this ctest registration AND the build.yml --target
// allowlist, or it becomes a #143-style NOT_BUILT sentinel that reds master.

#include <impl/dgb/stratum/work_source.hpp>
#include <impl/dgb/coin/header_chain.hpp>
#include <impl/dgb/coin/mempool.hpp>

#include <core/stratum_work_source.hpp>

#include <gtest/gtest.h>

#include <memory>

namespace {

// Construct a DGBWorkSource over default-constructed coin deps. The submit
// callback records whether it was invoked (it must NOT be in the 4a skeleton).
struct Fixture {
    c2pool::dgb::HeaderChain chain;
    dgb::coin::Mempool       mempool;
    bool                     submit_called = false;

    std::unique_ptr<dgb::stratum::DGBWorkSource> make()
    {
        auto fn = [this](const std::vector<unsigned char>&, uint32_t) -> bool {
            submit_called = true;
            return false;
        };
        return std::make_unique<dgb::stratum::DGBWorkSource>(
            chain, mempool, /*is_testnet=*/false, fn);
    }
};

TEST(DgbWorkSource, ConstructsAndSatisfiesIWorkSourceContract)
{
    Fixture fx;
    auto ws = fx.make();
    // Usable through the abstract interface core::StratumServer holds.
    core::stratum::IWorkSource* iface = ws.get();
    ASSERT_NE(iface, nullptr);
}

TEST(DgbWorkSource, ConfigDefaultsMatchStratumConfig)
{
    Fixture fx;
    auto ws = fx.make();
    const auto& cfg = ws->get_stratum_config();
    EXPECT_DOUBLE_EQ(cfg.min_difficulty, 0.0005);
    EXPECT_DOUBLE_EQ(cfg.max_difficulty, 65536.0);
    EXPECT_DOUBLE_EQ(cfg.target_time, 3.0);
    EXPECT_TRUE(cfg.vardiff_enabled);
}

TEST(DgbWorkSource, WorkGenerationStartsZeroAndBumps)
{
    Fixture fx;
    auto ws = fx.make();
    EXPECT_EQ(ws->get_work_generation(), 0u);
    ws->bump_work_generation();
    ws->bump_work_generation();
    EXPECT_EQ(ws->get_work_generation(), 2u);
}

TEST(DgbWorkSource, ShareTargetAtomicsRoundTrip)
{
    Fixture fx;
    auto ws = fx.make();
    EXPECT_EQ(ws->get_share_bits(), 0u);
    EXPECT_EQ(ws->get_share_max_bits(), 0u);
    ws->set_share_target(0x1d00ffff, 0x1e0fffff);
    EXPECT_EQ(ws->get_share_bits(), 0x1d00ffffu);
    EXPECT_EQ(ws->get_share_max_bits(), 0x1e0fffffu);
}

TEST(DgbWorkSource, NoMergedChainInDefaultBuild)
{
    Fixture fx;
    auto ws = fx.make();
    // DGB V36 default build is a standalone Scrypt parent (no merged mining;
    // -DAUX_DOGE dual-parent is a parked STRETCH).
    EXPECT_FALSE(ws->has_merged_chain(0x0001));
}

TEST(DgbWorkSource, BestShareHashFnEmptyUntilWired)
{
    Fixture fx;
    auto ws = fx.make();
    EXPECT_FALSE(static_cast<bool>(ws->get_best_share_hash_fn()));
    ws->set_best_share_hash_fn([]() { return uint256::ZERO; });
    auto fn = ws->get_best_share_hash_fn();
    ASSERT_TRUE(static_cast<bool>(fn));
    EXPECT_EQ(fn(), uint256::ZERO);
}

TEST(DgbWorkSource, WorkerRegistryRoundTrip)
{
    Fixture fx;
    auto ws = fx.make();
    core::stratum::WorkerInfo info;
    info.username    = "DGBaddr.worker1";
    info.worker_name = "worker1";
    ws->register_stratum_worker("sess-1", info);
    ws->update_stratum_worker("sess-1", /*hashrate=*/1.0e9, /*dead=*/0.0,
                              /*difficulty=*/16.0, /*accepted=*/3, /*rejected=*/0, /*stale=*/0);
    // No crash + idempotent unregister of a known + unknown session.
    ws->unregister_stratum_worker("sess-1");
    ws->unregister_stratum_worker("sess-unknown");
    SUCCEED();
}

TEST(DgbWorkSource, WorkGenStubsReturnSafeDefaults)
{
    Fixture fx;
    auto ws = fx.make();
    // 4a skeleton: every work-generation getter returns its documented
    // empty/default form (4c fills them in).
    EXPECT_TRUE(ws->get_current_gbt_prevhash().empty());
    EXPECT_TRUE(ws->get_current_work_template().is_object());
    EXPECT_TRUE(ws->get_current_work_template().empty());
    EXPECT_TRUE(ws->get_stratum_merkle_branches().empty());
    auto parts = ws->get_coinbase_parts();
    EXPECT_TRUE(parts.first.empty());
    EXPECT_TRUE(parts.second.empty());
}

TEST(DgbWorkSource, MiningSubmitStubRejectsWithoutCallingBroadcaster)
{
    Fixture fx;
    auto ws = fx.make();
    auto result = ws->mining_submit(
        "DGBaddr.worker1", "job-0", "en1", "en2", "ntime", "nonce", "rid-0",
        /*merged_addresses=*/{}, /*job=*/nullptr);
    // Stratum mining.submit response = [false, [code, msg, null]] reject form.
    ASSERT_TRUE(result.is_array());
    ASSERT_GE(result.size(), 1u);
    EXPECT_FALSE(result[0].get<bool>());
    // The 4a stub must NOT have reached the won-block broadcaster.
    EXPECT_FALSE(fx.submit_called);
}

TEST(DgbWorkSource, ComputeShareDifficultyReturnsNotYetSentinel)
{
    Fixture fx;
    auto ws = fx.make();
    // 4a skeleton: the per-coin (Scrypt) PoW-difficulty hook returns the
    // documented 0.0 parse-error/not-yet sentinel. The coin-agnostic
    // StratumServer's vardiff gate treats 0.0 as a hard reject, so no
    // garbage difficulty leaks into the rate monitor before 4b/4c land
    // the real scrypt_1024_1_1_256 assembly.
    double diff = ws->compute_share_difficulty(
        "coinb1", "coinb2", "en1", "en2", "ntime", "nonce",
        /*version=*/0x20000000u, "prevhash", "1e0ffff0",
        /*merkle_branches=*/{});
    EXPECT_DOUBLE_EQ(diff, 0.0);
}

}  // namespace
