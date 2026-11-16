// SPDX-License-Identifier: AGPL-3.0-or-later
// Deferred mint (core/deferred_mint.hpp + impl/dash/deferred_mint_dash.hpp).
//
// THE DEFECT. A stratum solve that meets the share target is minted on the io
// thread with ONE try_lock of the tracker. While the compute thread holds the
// lock (think / clean_tracker) the solve was DECLINED and its PPLNS credit
// lost: ~1.25% of local mints on a busy hotel node (11-09..11-16), of which
// ~2/3 could still have landed on the best chain.
//
// THE FIX. A declined solve is queued and minted at the next point the lock
// is free: the top of both IO-phase epilogues (think slot still held, so the
// batch gets one think) and the 2 s advert tick. The io thread never waits.
// --no-deferred-mint is the kill switch.
//
// What is pinned:
//   A. The queue (pure): FIFO; Busy keeps the item at the FRONT and stops; an
//      unmintable head item is dropped with its reason and later items still
//      mint; a throwing item is dropped as `threw` and the batch goes on; TTL,
//      capacity, shutdown counted; a won-block solve that stays busy goes to
//      the front; one think per batch; the kill switch is the old path.
//   B. The node (a REAL ctx-bound NodeImpl, REAL v36 solves through the real
//      mint body): a solve arriving while the tracker is held exclusively is
//      minted by the next think's IO epilogue (the old path loses it); two
//      queued solves where the second builds on the first mint in order in
//      one drain with ONE think; a queued copy of an already-minted solve is
//      dropped as `duplicate`.
//
// Folded into test_dash_node (needs the dash OBJECT lib + c2pool_storage).

#include <gtest/gtest.h>

#include "dash_v36_live_fixture.hpp"   // IdentityGuard, DataDirGuard, LiveNode
#include "dash_v36_mint_fixture.hpp"   // iso_prod_params, make_wd, solve_job, v36_of

#include <core/deferred_mint.hpp>
#include <impl/dash/deferred_mint_dash.hpp>
#include <impl/dash/mint_runloop.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <shared_mutex>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {

using core::DeferredMinter;
using core::DeferredMintQueue;
using core::MintAttempt;
using core::MintDropReason;
using core::MintOutcome;
using core::MintResult;
using namespace std::chrono_literals;

MintOutcome minted(int id) { uint256 h; h.begin()[0] = static_cast<uint32_t>(id); return {MintResult::Minted, MintDropReason::none, h}; }
MintOutcome busy() { return {MintResult::Busy, MintDropReason::none, uint256()}; }
MintOutcome dropped(MintDropReason r) { return {MintResult::Dropped, r, uint256()}; }

uint64_t drops(const core::DeferredMintCounters& c, MintDropReason r)
{
    return c.dropped[static_cast<size_t>(r)];
}

// Holds the node's REAL exclusive tracker lock from another thread for `hold`
// (the state a think()/clean cycle puts it in). Returns once it is held.
class ExclusiveHold {
public:
    ExclusiveHold(std::shared_mutex& mtx, std::chrono::milliseconds hold)
    {
        thread_ = std::thread([this, &mtx, hold] {
            std::unique_lock<std::shared_mutex> lk(mtx);
            held_.store(true);
            std::this_thread::sleep_for(hold);
        });
        while (!held_.load())
            std::this_thread::sleep_for(100us);
    }
    ~ExclusiveHold() { if (thread_.joinable()) thread_.join(); }
private:
    std::atomic<bool> held_{false};
    std::thread thread_;
};

} // namespace

// ═════════════════════════════════════════════════════════════════════════════
// A. The queue and the minter policy (pure)
// ═════════════════════════════════════════════════════════════════════════════

TEST(DeferredMintQueue, BusyKeepsTheItemAtTheFrontAndStops)
{
    DeferredMintQueue<int> q;
    ASSERT_TRUE(q.push_back(1));
    ASSERT_TRUE(q.push_back(2));
    std::vector<int> tried;
    auto st = q.drain([&](int i) { tried.push_back(i); return busy(); });
    EXPECT_TRUE(st.stopped_busy);
    EXPECT_EQ(tried, std::vector<int>({1})) << "a busy tracker stops the drain at the first item";
    EXPECT_EQ(q.size(), 2u);
    tried.clear();
    st = q.drain([&](int i) { tried.push_back(i); return minted(i); });
    EXPECT_EQ(tried, std::vector<int>({1, 2})) << "FIFO: item 1 is still first";
    EXPECT_EQ(st.minted, 2u);
    EXPECT_TRUE(q.empty());
    EXPECT_EQ(q.counters().busy_stops, 1u);
    EXPECT_EQ(q.counters().minted, 2u);
}

// KAT-2: an unmintable head item must not block the queue for its TTL.
TEST(DeferredMintQueue, UnmintableHeadIsDroppedAndLaterItemsStillMint)
{
    DeferredMintQueue<int> q;
    for (int i = 1; i <= 4; ++i) ASSERT_TRUE(q.push_back(i));
    const auto st = q.drain([&](int i) {
        if (i == 1) return dropped(MintDropReason::duplicate);
        if (i == 2) return dropped(MintDropReason::not_backable);
        return minted(i);
    });
    EXPECT_EQ(st.minted, 2u);
    EXPECT_EQ(st.dropped, 2u);
    EXPECT_TRUE(q.empty());
    EXPECT_EQ(drops(q.counters(), MintDropReason::duplicate), 1u);
    EXPECT_EQ(drops(q.counters(), MintDropReason::not_backable), 1u);
}

// KAT-3: a throwing attempt never escapes drain() and never stops the batch.
TEST(DeferredMintQueue, ThrowingItemIsDroppedAndTheBatchGoesOn)
{
    DeferredMintQueue<int> q;
    for (int i = 1; i <= 3; ++i) ASSERT_TRUE(q.push_back(i));
    core::DrainStats st;
    EXPECT_NO_THROW(st = q.drain([&](int i) -> MintOutcome {
        if (i == 2) throw std::runtime_error("producer threw");
        return minted(i);
    }));
    EXPECT_EQ(st.minted, 2u);
    EXPECT_EQ(drops(q.counters(), MintDropReason::threw), 1u);
    EXPECT_TRUE(q.empty());
}

// KAT-6: TTL, capacity, shutdown, per-drain cap.
TEST(DeferredMintQueue, TtlCapacityShutdownAndPerDrainCapAreCounted)
{
    const auto t0 = std::chrono::steady_clock::now();
    DeferredMintQueue<int> q(/*capacity=*/3, /*ttl=*/20000ms);
    ASSERT_TRUE(q.push_back(1, t0));
    ASSERT_TRUE(q.push_back(2, t0 + 15s));
    ASSERT_TRUE(q.push_back(3, t0 + 15s));
    EXPECT_FALSE(q.push_back(4, t0 + 15s)) << "full: the caller declines as before";
    EXPECT_EQ(drops(q.counters(), MintDropReason::queue_full), 1u);
    EXPECT_EQ(q.counters().max_depth, 3u);

    // At t0+21 s item 1 is past the TTL; per-drain cap 1 leaves item 3 queued.
    std::vector<int> tried;
    const auto st = q.drain([&](int i) { tried.push_back(i); return minted(i); }, 1, t0 + 21s);
    EXPECT_EQ(drops(q.counters(), MintDropReason::ttl), 1u);
    EXPECT_TRUE(tried.empty()) << "the expired item counts against the cap";
    EXPECT_EQ(st.dropped, 1u);
    EXPECT_EQ(q.size(), 2u);
    const auto st2 = q.drain([&](int i) { tried.push_back(i); return minted(i); }, 1, t0 + 21s);
    EXPECT_EQ(st2.minted, 1u);
    EXPECT_EQ(tried, std::vector<int>({2}));
    EXPECT_EQ(q.counters().max_age_ms_at_mint, 6000);

    EXPECT_EQ(q.clear_for_shutdown(), 1u);
    EXPECT_EQ(drops(q.counters(), MintDropReason::shutdown), 1u);
    EXPECT_TRUE(q.empty());
}

namespace {
struct ScriptedMint {
    std::vector<std::pair<int, MintAttempt>> calls;
    std::function<MintOutcome(int)> outcome;
    int thinks{0};
    std::unique_ptr<DeferredMinter<int>> make(bool enabled)
    {
        return std::make_unique<DeferredMinter<int>>(
            enabled,
            [this](const int& i, const MintAttempt& a) { calls.push_back({i, a}); return outcome(i); },
            [this]() { ++thinks; });
    }
};
} // namespace

// The kill switch is the old path: one synchronous attempt WITH its own think,
// nothing queued, drain points are no-ops.
TEST(DeferredMinter, KillSwitchIsTheOldSingleTryAndDecline)
{
    ScriptedMint s;
    s.outcome = [](int) { return busy(); };
    auto m = s.make(/*enabled=*/false);
    const auto r = m->on_solve(1, /*won_block=*/false);
    EXPECT_EQ(r.outcome.result, MintResult::Busy);
    EXPECT_FALSE(r.queued);
    EXPECT_EQ(m->depth(), 0u);
    ASSERT_EQ(s.calls.size(), 1u);
    EXPECT_TRUE(s.calls[0].second.think_after) << "the old path runs add_local_share's own think";
    EXPECT_FALSE(s.calls[0].second.from_queue);
    m->drain_point();
    EXPECT_EQ(s.calls.size(), 1u);
    EXPECT_EQ(m->counters().deferred, 0u);
    EXPECT_FALSE(m->snapshot().enabled);
}

// KAT-5: a drained batch gets ONE think; every attempt in it defers its think.
TEST(DeferredMinter, ABatchGetsOneThinkAndOrderIsKept)
{
    ScriptedMint s;
    bool lock_busy = true;
    s.outcome = [&](int i) { return lock_busy ? busy() : minted(i); };
    auto m = s.make(true);
    for (int i = 1; i <= 3; ++i) {
        const auto r = m->on_solve(i, false);
        EXPECT_TRUE(r.queued);
    }
    EXPECT_EQ(m->depth(), 3u);
    EXPECT_EQ(s.thinks, 0);
    lock_busy = false;
    s.calls.clear();
    const auto st = m->drain_point();
    EXPECT_EQ(st.minted, 3u);
    EXPECT_EQ(s.thinks, 1) << "one think for the whole batch";
    ASSERT_EQ(s.calls.size(), 3u);
    for (size_t k = 0; k < 3; ++k) {
        EXPECT_EQ(s.calls[k].first, static_cast<int>(k + 1)) << "arrival order";
        EXPECT_FALSE(s.calls[k].second.think_after);
        EXPECT_TRUE(s.calls[k].second.from_queue);
    }
}

// A fresh solve drains what is queued FIRST (order kept), then mints itself;
// one think covers both. While the queue cannot drain, the new solve goes
// behind it even though it was never tried.
TEST(DeferredMinter, AFreshSolveGoesBehindTheQueue)
{
    ScriptedMint s;
    bool lock_busy = true;
    s.outcome = [&](int i) { return lock_busy ? busy() : minted(i); };
    auto m = s.make(true);
    EXPECT_TRUE(m->on_solve(1, false).queued);
    s.calls.clear();
    EXPECT_TRUE(m->on_solve(2, false).queued);
    ASSERT_EQ(s.calls.size(), 1u);
    EXPECT_EQ(s.calls[0].first, 1) << "the queue head is tried first; the new solve is not";
    lock_busy = false;
    s.calls.clear();
    const auto r = m->on_solve(3, false);
    EXPECT_EQ(r.outcome.result, MintResult::Minted);
    ASSERT_EQ(s.calls.size(), 3u);
    EXPECT_EQ(s.calls[0].first, 1);
    EXPECT_EQ(s.calls[1].first, 2);
    EXPECT_EQ(s.calls[2].first, 3);
    EXPECT_FALSE(s.calls[2].second.from_queue);
    EXPECT_EQ(s.thinks, 1);
    EXPECT_EQ(m->depth(), 0u);
}

// KAT-4: a won-block solve keeps its synchronous attempt (never behind the
// queue); if it is still busy it goes to the FRONT.
TEST(DeferredMinter, WonBlockSolveGoesToTheFront)
{
    ScriptedMint s;
    bool lock_busy = true;
    s.outcome = [&](int i) { return lock_busy ? busy() : minted(i); };
    auto m = s.make(true);
    EXPECT_TRUE(m->on_solve(1, false).queued);
    s.calls.clear();
    const auto r = m->on_solve(99, /*won_block=*/true);
    EXPECT_TRUE(r.queued);
    ASSERT_EQ(s.calls.size(), 1u);
    EXPECT_EQ(s.calls[0].first, 99) << "the won block is tried at once, not behind the queue";
    EXPECT_FALSE(s.calls[0].second.from_queue) << "its one bounded wait";
    lock_busy = false;
    s.calls.clear();
    m->drain_point();
    ASSERT_EQ(s.calls.size(), 2u);
    EXPECT_EQ(s.calls[0].first, 99) << "front of the queue";
    EXPECT_TRUE(s.calls[0].second.from_queue) << "a retry never waits again";
    EXPECT_EQ(s.calls[1].first, 1);
}

TEST(DeferredMinter, NothingIsMintedAfterShutdown)
{
    ScriptedMint s;
    bool lock_busy = true;
    s.outcome = [&](int i) { return lock_busy ? busy() : minted(i); };
    auto m = s.make(true);
    EXPECT_TRUE(m->on_solve(1, false).queued);
    EXPECT_TRUE(m->on_solve(2, false).queued);
    EXPECT_EQ(m->shutdown(), 2u);
    lock_busy = false;
    s.calls.clear();
    m->drain_point();
    EXPECT_TRUE(s.calls.empty());
    EXPECT_EQ(drops(m->counters(), MintDropReason::shutdown), 2u);
    EXPECT_EQ(m->snapshot().counters.dropped_total(), 2u);
}

// ═════════════════════════════════════════════════════════════════════════════
// B. The node: REAL NodeImpl, REAL v36 solves, the real mint body
// ═════════════════════════════════════════════════════════════════════════════

namespace {

using Minter = DeferredMinter<dash::mint::DeferredSolve>;

std::shared_ptr<Minter> wire_minter(LiveNode& a, const core::CoinParams& p, bool enabled)
{
    auto m = std::make_shared<Minter>(
        enabled,
        [&a, p](const dash::mint::DeferredSolve& s, const MintAttempt& at) {
            return dash::mint::mint_solve_once(*a.node, p, s, at);
        },
        [&a]() { a.node->run_think(); });
    a.node->set_deferred_mint_drain([w = std::weak_ptr<Minter>(m)]() {
        if (auto x = w.lock()) x->drain_point();
    });
    return m;
}

dash::mint::DeferredSolve solve_of(const SolvedJob& j)
{
    return dash::mint::DeferredSolve{j.in, j.build.frozen, /*prev_was_tip=*/true};
}

struct TwoSolves {
    SolvedJob genesis, child;
    uint256 g, c;
};

// A genesis solve and a child solve on top of it (real X11 nonce searches).
TwoSolves make_two_solves(const core::CoinParams& p)
{
    TwoSolves t;
    const auto wd = make_wd();
    dash::ShareChain scratch;
    t.genesis = solve_job(scratch, p, uint256(), h160(0xa1), wd, 7, wd.m_curtime);
    EXPECT_TRUE(t.genesis.built && t.genesis.solved);
    const auto m1 = dash::mint::mint_from_inputs_any(scratch, p, t.genesis.in, t.genesis.build.frozen);
    EXPECT_TRUE(m1.has_value());
    const auto& g = v36_of(*m1);
    t.g = g.share.m_hash;
    scratch.add(new dash::DashV36Share(g.share));
    t.child = solve_job(scratch, p, t.g, h160(0xb2), wd, 8, wd.m_curtime + 20);
    EXPECT_TRUE(t.child.built && t.child.solved);
    t.c = t.child.in.pow_hash;   // X11 identity gate: share hash == pow hash
    return t;
}

bool chain_has(LiveNode& a, const uint256& h)
{
    bool has = false;
    EXPECT_TRUE(a.settled([&](dash::ShareTracker& t) { has = t.chain.contains(h); }));
    return has;
}

} // namespace

// ★ KAT-1. A solve arriving while the tracker is held exclusively is queued and
// minted by the next think's IO epilogue. Nothing else drains in this fixture
// (no advert timer: outbound connections are never started), so the share can
// only land through the epilogue drain. Negative control: the same sequence with
// the kill switch loses the share, exactly as before the fix.
TEST(DashDeferredMint, BusyTrackerSolveIsMintedByTheNextThinkEpilogue)
{
    for (const bool enabled : {true, false}) {
        SCOPED_TRACE(enabled ? "deferred mint ON" : "kill switch (--no-deferred-mint)");
        IdentityGuard guard;
        DataDirGuard dd(enabled ? "c2pool_dash_defer_on" : "c2pool_dash_defer_off");
        const auto p = iso_prod_params();
        const auto t = make_two_solves(p);
        LiveNode a(p, SharechainConfig::data_subdir(false) + "_a");
        auto m = wire_minter(a, p, enabled);

        {
            ExclusiveHold hold(a.node->tracker_mutex(), 300ms);
            const auto r = m->on_solve(solve_of(t.genesis), /*won_block=*/false);
            EXPECT_EQ(r.outcome.result, MintResult::Busy) << "the tracker is held: the try fails";
            EXPECT_EQ(r.queued, enabled);
            // A think cycle queued behind the holder (its compute phase blocks
            // on the lock), exactly as a peer share or a clean tick would start one.
            a.node->run_think();
        }
        if (enabled) {
            ASSERT_TRUE(a.pump_until([&](dash::ShareTracker& tr) { return tr.chain.contains(t.g); }))
                << "the queued solve was never minted";
            EXPECT_EQ(m->depth(), 0u);
            EXPECT_EQ(m->counters().deferred, 1u);
            EXPECT_EQ(m->counters().minted, 1u);
            EXPECT_EQ(m->counters().dropped_total(), 0u);
            EXPECT_TRUE(a.wait_best(t.g)) << "the deferred share is elected (its think ran)";
        } else {
            EXPECT_FALSE(chain_has(a, t.g)) << "the old path loses the solve";
            EXPECT_EQ(m->counters().deferred, 0u);
        }
    }
}

// Two queued solves, the second building on the first: one drain mints them
// in arrival order (the child can only be rebuilt once its parent is in the
// chain) and asks for ONE think.
TEST(DashDeferredMint, QueuedParentAndChildMintInOrderWithOneThink)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_defer_batch");
    const auto p = iso_prod_params();
    const auto t = make_two_solves(p);
    LiveNode a(p, SharechainConfig::data_subdir(false) + "_a");
    auto m = wire_minter(a, p, true);

    {
        ExclusiveHold hold(a.node->tracker_mutex(), 300ms);
        EXPECT_TRUE(m->on_solve(solve_of(t.genesis), false).queued);
        EXPECT_TRUE(m->on_solve(solve_of(t.child), false).queued);
        EXPECT_EQ(m->depth(), 2u);
        a.node->run_think();
    }
    ASSERT_TRUE(a.pump_until([&](dash::ShareTracker& tr) {
        return tr.chain.contains(t.g) && tr.chain.contains(t.c);
    })) << "both queued solves must land";
    EXPECT_EQ(m->counters().minted, 2u);
    EXPECT_EQ(m->counters().dropped_total(), 0u);
    EXPECT_EQ(m->thinks_requested(), 1u) << "one think for the drained batch";
    EXPECT_TRUE(a.wait_best(t.c)) << "the child is the tip after the batch think";
}

// A queued copy of a solve that is already in the chain is dropped as a
// duplicate (it does not sit at the head of the queue until its TTL).
TEST(DashDeferredMint, QueuedDuplicateIsDroppedNotRetried)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_defer_dup");
    const auto p = iso_prod_params();
    const auto t = make_two_solves(p);
    LiveNode a(p, SharechainConfig::data_subdir(false) + "_a");
    auto m = wire_minter(a, p, true);

    ASSERT_TRUE(a.settled([](dash::ShareTracker&) {}));
    const auto first = m->on_solve(solve_of(t.genesis), false);
    ASSERT_EQ(first.outcome.result, MintResult::Minted) << "a free tracker mints synchronously";
    EXPECT_EQ(first.outcome.hash, t.g);
    ASSERT_TRUE(a.settled([](dash::ShareTracker&) {}));

    {
        ExclusiveHold hold(a.node->tracker_mutex(), 300ms);
        EXPECT_TRUE(m->on_solve(solve_of(t.genesis), false).queued);
        a.node->run_think();
    }
    ASSERT_TRUE(a.pump_until([&](dash::ShareTracker&) { return m->depth() == 0; }));
    EXPECT_EQ(drops(m->counters(), MintDropReason::duplicate), 1u);
    EXPECT_EQ(m->counters().minted, 0u);
}
