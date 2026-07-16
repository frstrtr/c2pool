// SPDX-License-Identifier: AGPL-3.0-or-later
// dash::stratum::DASHWorkSource -- Stage 4b construction + contract KAT.
//
// Proves the work source instantiates against the live node-held coin-state
// (dash::coin::NodeCoinState) + the REQUIRED dashd fallback closure, satisfies
// the full core::stratum::IWorkSource pure-virtual contract (so a future
// core::StratumServer can hold it via shared_ptr<IWorkSource>), that its
// real-now surface (config defaults, work-generation counter, share-target
// atomics, worker registry, best-share callback) behaves, that the 4b-held
// work-generation / submit methods return their documented SAFE DEFAULTS (so a
// regression that accidentally "implements" them with garbage is caught), and
// that the fused get_work() adapter routes to the RETAINED dashd fallback on an
// unpopulated coin-state (the always-reachable [GBT-XCHECK] safety arm).
//
// MUST appear in BOTH this ctest registration AND the build.yml --target
// allowlist, or it becomes a #143-style NOT_BUILT sentinel that reds master.

#include <impl/dash/stratum/work_source.hpp>

#include <core/stratum_work_source.hpp>
#include <core/uint256.hpp>

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

namespace {

// Construct a DASHWorkSource over a default (unpopulated) NodeCoinState. The
// submit callback records whether it was invoked (it must NOT be in 4b); the
// dashd fallback returns a distinctive sentinel so a get_work() routed to the
// fallback arm is provable by the returned work.
struct Fixture {
    dash::coin::NodeCoinState coin_state;             // default: populated()==false
    bool                      submit_called = false;
    dash::coin::DashWorkData  fallback_work;          // sentinel, seeded in make()

    std::unique_ptr<dash::stratum::DASHWorkSource> make()
    {
        fallback_work.m_height        = 424242u;      // distinctive fallback marker
        fallback_work.m_coinbase_value = 500000000ULL;
        auto submit = [this](const std::vector<unsigned char>&, uint32_t) -> bool {
            submit_called = true;
            return false;
        };
        auto fallback = [this]() -> dash::coin::DashWorkData { return fallback_work; };
        return std::make_unique<dash::stratum::DASHWorkSource>(
            coin_state, fallback, submit);
    }
};

TEST(DashStratumWorkSource, ConstructsAndSatisfiesIWorkSourceContract)
{
    Fixture fx;
    auto ws = fx.make();
    core::stratum::IWorkSource* iface = ws.get();  // usable through the abstract iface
    ASSERT_NE(iface, nullptr);
}

TEST(DashStratumWorkSource, ConfigDefaultsMatchStratumConfig)
{
    Fixture fx;
    auto ws = fx.make();
    const auto& cfg = ws->get_stratum_config();
    EXPECT_DOUBLE_EQ(cfg.min_difficulty, 0.0005);
    EXPECT_DOUBLE_EQ(cfg.max_difficulty, 65536.0);
    EXPECT_DOUBLE_EQ(cfg.target_time, 3.0);
    EXPECT_TRUE(cfg.vardiff_enabled);
}

TEST(DashStratumWorkSource, WorkGenerationStartsZeroAndBumps)
{
    Fixture fx;
    auto ws = fx.make();
    EXPECT_EQ(ws->get_work_generation(), 0u);
    ws->bump_work_generation();
    ws->bump_work_generation();
    EXPECT_EQ(ws->get_work_generation(), 2u);
}

TEST(DashStratumWorkSource, ShareTargetAtomicsRoundTrip)
{
    Fixture fx;
    auto ws = fx.make();
    EXPECT_EQ(ws->get_share_bits(), 0u);
    EXPECT_EQ(ws->get_share_max_bits(), 0u);
    ws->set_share_target(0x1d00ffffu, 0x1e0fffffu);
    EXPECT_EQ(ws->get_share_bits(), 0x1d00ffffu);
    EXPECT_EQ(ws->get_share_max_bits(), 0x1e0fffffu);
}

TEST(DashStratumWorkSource, NoMergedChainInV36)
{
    Fixture fx;
    auto ws = fx.make();
    // DASH V36 is a standalone X11 parent (no merged mining).
    EXPECT_FALSE(ws->has_merged_chain(0x0001));
}

TEST(DashStratumWorkSource, BestShareHashFnEmptyUntilWired)
{
    Fixture fx;
    auto ws = fx.make();
    EXPECT_FALSE(static_cast<bool>(ws->get_best_share_hash_fn()));
    ws->set_best_share_hash_fn([]() { return uint256::ZERO; });
    auto fn = ws->get_best_share_hash_fn();
    ASSERT_TRUE(static_cast<bool>(fn));
    EXPECT_EQ(fn(), uint256::ZERO);
}

TEST(DashStratumWorkSource, WorkerRegistryRoundTrip)
{
    Fixture fx;
    auto ws = fx.make();
    core::stratum::WorkerInfo info;
    info.username    = "Xaddr.worker1";
    info.worker_name = "worker1";
    ws->register_stratum_worker("sess-1", info);
    ws->update_stratum_worker("sess-1", /*hashrate=*/1.0e9, /*dead=*/0.0,
                              /*difficulty=*/16.0, /*accepted=*/3, /*rejected=*/0, /*stale=*/0);
    // Idempotent: unregister of a known + unknown session must not crash, and an
    // update for an unregistered session is a safe drop.
    ws->update_stratum_worker("sess-unknown", 1.0, 0.0, 1.0, 0, 0, 0);
    ws->unregister_stratum_worker("sess-1");
    ws->unregister_stratum_worker("sess-unknown");
    SUCCEED();
}

TEST(DashStratumWorkSource, WorkGenStubsReturnSafeDefaults)
{
    Fixture fx;
    auto ws = fx.make();
    // 4b skeleton: every work-generation getter returns its documented
    // empty/default form (4c fills them in) -- no fabricated template state.
    EXPECT_TRUE(ws->get_current_gbt_prevhash().empty());
    EXPECT_TRUE(ws->get_current_work_template().is_object());
    EXPECT_TRUE(ws->get_current_work_template().empty());
    EXPECT_TRUE(ws->get_stratum_merkle_branches().empty());
    auto parts = ws->get_coinbase_parts();
    EXPECT_TRUE(parts.first.empty());
    EXPECT_TRUE(parts.second.empty());
    auto cb = ws->build_connection_coinbase(uint256::ZERO, "deadbeef", {}, {});
    EXPECT_TRUE(cb.coinb1.empty());
    EXPECT_TRUE(cb.coinb2.empty());
}

TEST(DashStratumWorkSource, MiningSubmitStubRejectsWithoutBroadcasting)
{
    Fixture fx;
    auto ws = fx.make();
    auto result = ws->mining_submit(
        "Xaddr.worker1", "job-0", "en1", "en2", "ntime", "nonce", "rid-0",
        /*merged_addresses=*/{}, /*job=*/nullptr);
    // Stratum reject form = [false, [code, msg, null]].
    ASSERT_TRUE(result.is_array());
    ASSERT_GE(result.size(), 1u);
    EXPECT_FALSE(result[0].get<bool>());
    // The 4b stub must NOT have reached the won-block broadcaster.
    EXPECT_FALSE(fx.submit_called);
}

TEST(DashStratumWorkSource, ComputeShareDifficultyReturnsNotYetSentinel)
{
    Fixture fx;
    auto ws = fx.make();
    // 4b: the per-coin (X11) PoW-difficulty hook returns the documented 0.0
    // parse-error/not-yet sentinel the vardiff gate treats as a hard reject.
    double diff = ws->compute_share_difficulty(
        "coinb1", "coinb2", "en1", "en2", "ntime", "nonce",
        /*version=*/0x20000000u, "prevhash", "1e0ffff0",
        /*merkle_branches=*/{});
    EXPECT_DOUBLE_EQ(diff, 0.0);
}

// The fused adapter: with an UNPOPULATED coin-state, get_work() routes to the
// RETAINED dashd fallback (always-reachable safety + [GBT-XCHECK] arm), and the
// returned work IS the fallback closure output -- proving the member is a thin
// node-bound wrapper over the #698 capstone, and that the fallback is never
// bypassed on a set-gap. Job targets are assembled over it (pure transform).
TEST(DashStratumWorkSource, GetWorkRoutesToDashdFallbackWhenCoinStateUnpopulated)
{
    Fixture fx;
    ASSERT_FALSE(fx.coin_state.populated());  // default bundle is a set-gap
    auto ws = fx.make();

    dash::stratum::WorkJobTargetInputs job_in;
    job_in.sane_target_min.SetHex(
        "0000000000000000000000000000000000000000000000000000000000000001");
    job_in.sane_target_max.SetHex(
        "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    job_in.share_info_bits_target.SetHex(
        "0000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    job_in.have_desired_pseudoshare = false;
    job_in.local_hash_rate = 0.0;

    dash::stratum::GetWork gw = ws->get_work(job_in);

    // Routed to the retained dashd fallback, returning ITS sentinel work.
    EXPECT_EQ(gw.source, dash::coin::WorkSource::DashdFallback);
    EXPECT_EQ(gw.work.m_height, 424242u);
    EXPECT_EQ(gw.work.m_coinbase_value, 500000000ULL);
    // Job targets assembled over the sourced template (clipped into sane range).
    EXPECT_EQ(gw.targets.share_target, job_in.sane_target_max);   // ffff.. clipped to max
    EXPECT_EQ(gw.targets.min_share_target, job_in.share_info_bits_target);  // < sane_max -> floor
}

}  // namespace
