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
// is free: both IO-phase epilogues (after the rig notify, think slot still
// held, so the batch gets one think) and the 2 s advert tick. The io thread
// never waits. --no-deferred-mint is the kill switch.
//
// What is pinned:
//   A. The queue and the policy (pure): FIFO; Busy keeps the item at the FRONT
//      and stops; an unmintable head item is dropped with its reason and later
//      items still mint; a throwing item is dropped as `threw` and the batch
//      goes on; TTL, capacity, shutdown counted and every final loss reaches
//      the coin's drop hook; a won-block solve that stays busy goes to the
//      front even past a full queue; one think per batch, kept even if the
//      fresh attempt throws; nothing mints after shutdown; the kill switch is
//      the old path with the old log wording; the prev_was_tip classifier; the
//      stats JSON shape.
//   B. The node (a REAL ctx-bound NodeImpl, REAL v36 solves through the real
//      mint body): a solve arriving while the tracker is held exclusively is
//      minted by the next think's IO epilogue (the kill switch loses it); the
//      clean_tracker epilogue drains too; a parent+child batch mints in order
//      in one drain, slot free (before any think) and inside the epilogue; a
//      busy EXCLUSIVE add (tracker held shared) is queued and the 2 s advert
//      tick mints it; a won-block share whose bounded wait expired goes first
//      and is not a forfeit, one lost from the queue is a counted forfeit; a
//      queued duplicate is dropped.
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

// Holds the node's REAL tracker lock from another thread, EXCLUSIVELY (the
// state a think()/clean cycle puts it in) or SHARED (a reader on another thread:
// the read step succeeds, the exclusive add is busy). Returns once it is held
// and keeps it until release() (no timing assumption about the test thread),
// but never for less than `min_hold` (to outlast a bounded wait).
class TrackerHold {
public:
    enum class Mode { exclusive, shared };
    TrackerHold(std::shared_mutex& mtx, Mode mode,
                std::chrono::milliseconds min_hold = std::chrono::milliseconds(0))
    {
        thread_ = std::thread([this, &mtx, mode, min_hold] {
            const auto t0 = std::chrono::steady_clock::now();
            auto hold = [&] {
                held_.store(true);
                while (!release_.load())
                    std::this_thread::sleep_for(std::chrono::microseconds(200));
                std::this_thread::sleep_until(t0 + min_hold);
            };
            if (mode == Mode::exclusive) {
                std::unique_lock<std::shared_mutex> lk(mtx);
                hold();
            } else {
                std::shared_lock<std::shared_mutex> lk(mtx);
                hold();
            }
        });
        while (!held_.load())
            std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
    void release()
    {
        release_.store(true);
        if (thread_.joinable()) thread_.join();
    }
    ~TrackerHold() { release(); }
private:
    std::atomic<bool> held_{false};
    std::atomic<bool> release_{false};
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
    const auto st = q.drain([&](int i) { tried.push_back(i); return minted(i); }, {}, 1, t0 + 21s);
    EXPECT_EQ(drops(q.counters(), MintDropReason::ttl), 1u);
    EXPECT_TRUE(tried.empty()) << "the expired item counts against the cap";
    EXPECT_EQ(st.dropped, 1u);
    EXPECT_EQ(q.size(), 2u);
    const auto st2 = q.drain([&](int i) { tried.push_back(i); return minted(i); }, {}, 1, t0 + 21s);
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
    std::vector<std::pair<int, MintDropReason>> lost;
    std::function<MintOutcome(int)> outcome;
    int thinks{0};
    std::unique_ptr<DeferredMinter<int>> make(bool enabled, size_t capacity = 64)
    {
        return std::make_unique<DeferredMinter<int>>(
            enabled,
            [this](const int& i, const MintAttempt& a) { calls.push_back({i, a}); return outcome(i); },
            [this]() { ++thinks; },
            [this](const int& i, MintDropReason r) { lost.push_back({i, r}); },
            capacity);
    }
};
} // namespace

// The kill switch is the old path: one synchronous attempt WITH its own think
// and the old log wording (deferrable=false), nothing queued, drains are no-ops.
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
    EXPECT_FALSE(s.calls[0].second.deferrable) << "the mint body keeps the old declined/FORFEIT lines";
    m->drain_point();
    EXPECT_EQ(s.calls.size(), 1u);
    EXPECT_EQ(m->counters().deferred, 0u);
    EXPECT_TRUE(s.lost.empty());
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
        EXPECT_EQ(r.behind_queue, i > 1) << "only the first one was tried";
    }
    EXPECT_TRUE(s.calls[0].second.deferrable);
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
    const auto r2 = m->on_solve(2, false);
    EXPECT_TRUE(r2.queued);
    EXPECT_TRUE(r2.behind_queue);
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
    EXPECT_FALSE(s.calls[2].second.think_after);
    EXPECT_EQ(s.thinks, 1);
    EXPECT_EQ(m->depth(), 0u);
}

// KAT-4: a won-block solve keeps its synchronous attempt (never behind the
// queue); if it is still busy it goes to the FRONT, even past a full queue.
TEST(DeferredMinter, WonBlockSolveGoesToTheFrontEvenWhenFull)
{
    ScriptedMint s;
    bool lock_busy = true;
    s.outcome = [&](int i) { return lock_busy ? busy() : minted(i); };
    auto m = s.make(true, /*capacity=*/2);
    EXPECT_TRUE(m->on_solve(1, false).queued);
    EXPECT_TRUE(m->on_solve(2, false).queued);
    EXPECT_FALSE(m->on_solve(3, false).queued) << "capacity 2: an ordinary solve is declined";
    ASSERT_EQ(s.lost.size(), 1u);
    EXPECT_EQ(s.lost[0], std::make_pair(3, MintDropReason::queue_full)) << "the coin is told";
    s.calls.clear();
    const auto r = m->on_solve(99, /*won_block=*/true);
    EXPECT_TRUE(r.queued) << "a won-block share is never refused for capacity";
    ASSERT_EQ(s.calls.size(), 1u);
    EXPECT_EQ(s.calls[0].first, 99) << "the won block is tried at once, not behind the queue";
    EXPECT_FALSE(s.calls[0].second.from_queue) << "its one bounded wait";
    lock_busy = false;
    s.calls.clear();
    m->drain_point();
    ASSERT_EQ(s.calls.size(), 3u);
    EXPECT_EQ(s.calls[0].first, 99) << "front of the queue";
    EXPECT_TRUE(s.calls[0].second.from_queue) << "a retry never waits again";
    EXPECT_EQ(s.calls[1].first, 1);
    EXPECT_EQ(s.calls[2].first, 2);
}

// Every queued item that is finally lost reaches the coin's hook (the DASH
// binding turns a lost block-winning share into a loud, counted forfeit).
TEST(DeferredMinter, EveryFinalLossReachesTheDropHook)
{
    ScriptedMint s;
    bool lock_busy = true;
    s.outcome = [&](int i) -> MintOutcome {
        if (lock_busy) return busy();
        if (i == 2) return dropped(MintDropReason::gate);
        if (i == 3) throw std::runtime_error("boom");
        return minted(i);
    };
    auto m = s.make(true);
    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 1; i <= 4; ++i) EXPECT_TRUE(m->on_solve(i, false, t0).queued);
    lock_busy = false;
    m->drain_point(t0 + 1s);
    ASSERT_EQ(s.lost.size(), 2u);
    EXPECT_EQ(s.lost[0], std::make_pair(2, MintDropReason::gate));
    EXPECT_EQ(s.lost[1], std::make_pair(3, MintDropReason::threw));
    lock_busy = true;
    EXPECT_TRUE(m->on_solve(5, false, t0).queued);
    m->drain_point(t0 + 25s);   // past the 20 s TTL
    ASSERT_EQ(s.lost.size(), 3u);
    EXPECT_EQ(s.lost[2], std::make_pair(5, MintDropReason::ttl));
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
    ASSERT_EQ(s.lost.size(), 2u);
    EXPECT_EQ(s.lost[0].second, MintDropReason::shutdown);
    lock_busy = false;
    s.calls.clear();
    m->drain_point();
    const auto late = m->on_solve(3, false);
    EXPECT_TRUE(s.calls.empty()) << "nothing is minted once the node stops";
    EXPECT_EQ(late.outcome.result, MintResult::Dropped);
    EXPECT_EQ(late.outcome.why, MintDropReason::shutdown);
    EXPECT_EQ(drops(m->counters(), MintDropReason::shutdown), 2u);
    EXPECT_EQ(m->snapshot().counters.dropped_total(), 2u);
}

// Shares a drain already minted keep their think even if the fresh attempt
// after it throws.
TEST(DeferredMinter, AThrowingFreshAttemptStillThinksForTheDrainedBatch)
{
    ScriptedMint s;
    bool lock_busy = true;
    s.outcome = [&](int i) -> MintOutcome {
        if (lock_busy) return busy();
        if (i == 9) throw std::runtime_error("producer threw");
        return minted(i);
    };
    auto m = s.make(true);
    EXPECT_TRUE(m->on_solve(1, false).queued);
    lock_busy = false;
    EXPECT_THROW(m->on_solve(9, false), std::runtime_error);
    EXPECT_EQ(m->counters().minted, 1u);
    EXPECT_EQ(s.thinks, 1) << "the drained share is elected";
}

// The soak's cause split.
TEST(DashDeferredMintClassify, PrevWasTipOnlyWhenNoShareOfOursClaimsIt)
{
    uint256 p, q;
    p.begin()[0] = 1;
    q.begin()[0] = 2;
    using dash::mint::classify_prev_was_tip;
    EXPECT_TRUE(classify_prev_was_tip(p, p, uint256())) << "on the tip, nothing of ours on it";
    EXPECT_TRUE(classify_prev_was_tip(p, p, q)) << "our last share built on something else";
    EXPECT_FALSE(classify_prev_was_tip(p, p, p))
        << "we already minted/queued a share on p and best has not moved yet: a sibling";
    EXPECT_FALSE(classify_prev_was_tip(q, p, uint256())) << "a stale job: prev is behind the tip";
}

TEST(DashDeferredMintClassify, StatsJsonShape)
{
    core::DeferredMintSnapshot snap;
    snap.enabled = true;
    snap.depth = 2;
    snap.thinks = 3;
    snap.counters.deferred = 7;
    snap.counters.minted = 4;
    snap.counters.dropped[static_cast<size_t>(MintDropReason::ttl)] = 1;
    dash::mint::LocalMintLedger tip, behind;
    uint256 h;
    h.begin()[0] = 5;
    tip.record_mint(h);
    const auto j = dash::mint::mint_defer_json(snap, tip, behind);
    EXPECT_EQ(j.at("enabled"), true);
    EXPECT_EQ(j.at("depth"), 2);
    EXPECT_EQ(j.at("deferred"), 7);
    EXPECT_EQ(j.at("minted"), 4);
    EXPECT_EQ(j.at("batch_thinks"), 3);
    EXPECT_EQ(j.at("dropped").size(), 1u);
    EXPECT_EQ(j.at("dropped").at("ttl"), 1);
    EXPECT_EQ(j.at("prev_was_tip").at("minted"), 1);
    EXPECT_EQ(j.at("prev_was_tip").at("pending"), 1);
    EXPECT_EQ(j.at("prev_was_behind").at("minted"), 0);
    for (const char* k : {"busy_stops", "max_depth", "max_age_ms_at_mint"})
        EXPECT_TRUE(j.contains(k)) << k;
}

// ═════════════════════════════════════════════════════════════════════════════
// B. The node: REAL NodeImpl, REAL v36 solves, the real mint body
// ═════════════════════════════════════════════════════════════════════════════

namespace {

using Minter = DeferredMinter<dash::mint::DeferredSolve>;
using Mode = TrackerHold::Mode;

// What main_dash wires: the real mint body, one run_think per batch, and the
// drop hook that turns a lost block-winning share into a counted forfeit.
struct Wired {
    std::shared_ptr<Minter> m;
    std::shared_ptr<std::vector<uint256>> queue_attempts = std::make_shared<std::vector<uint256>>();
};

Wired wire_minter(LiveNode& a, const core::CoinParams& p, bool enabled)
{
    Wired w;
    auto attempts = w.queue_attempts;
    w.m = std::make_shared<Minter>(
        enabled,
        [&a, p, attempts](const dash::mint::DeferredSolve& s, const MintAttempt& at) {
            if (at.from_queue) attempts->push_back(s.in.pow_hash);
            return dash::mint::mint_solve_once(*a.node, p, s, at);
        },
        [&a]() { a.node->run_think(); },
        [&a](const dash::mint::DeferredSolve& s, MintDropReason why) {
            if (s.in.won_block)
                a.node->record_block_share_forfeit(s.in.pow_hash, core::to_string(why));
        });
    a.node->set_deferred_mint_drain([wm = std::weak_ptr<Minter>(w.m)]() {
        if (auto x = wm.lock()) x->drain_point();
    });
    return w;
}

dash::mint::DeferredSolve solve_of(const SolvedJob& j, bool won_block = false)
{
    dash::mint::DeferredSolve s{j.in, j.build.frozen, /*prev_was_tip=*/true};
    s.in.won_block = won_block;
    return s;
}

struct Solves {
    SolvedJob genesis, child, other;   // other: a second genesis (another miner)
    uint256 g, c, o;
};

// Real X11 nonce searches: a genesis, a child on top of it, and an unrelated
// second genesis.
Solves make_solves(const core::CoinParams& p)
{
    Solves t;
    const auto wd = make_wd();
    dash::ShareChain scratch;
    t.genesis = solve_job(scratch, p, uint256(), h160(0xa1), wd, 7, wd.m_curtime);
    EXPECT_TRUE(t.genesis.built && t.genesis.solved);
    const auto m1 = dash::mint::mint_from_inputs_any(scratch, p, t.genesis.in, t.genesis.build.frozen);
    EXPECT_TRUE(m1.has_value());
    const auto& g = v36_of(*m1);
    t.g = g.share.m_hash;
    t.other = solve_job(scratch, p, uint256(), h160(0xc3), wd, 9, wd.m_curtime);
    EXPECT_TRUE(t.other.built && t.other.solved);
    t.o = t.other.in.pow_hash;   // X11 identity gate: share hash == pow hash
    scratch.add(new dash::DashV36Share(g.share));
    t.child = solve_job(scratch, p, t.g, h160(0xb2), wd, 8, wd.m_curtime + 20);
    EXPECT_TRUE(t.child.built && t.child.solved);
    t.c = t.child.in.pow_hash;
    return t;
}

bool chain_has(LiveNode& a, const uint256& h)
{
    bool has = false;
    EXPECT_TRUE(a.settled([&](dash::ShareTracker& t) { has = t.chain.contains(h); }));
    return has;
}

struct NodeCase {
    IdentityGuard guard;
    DataDirGuard dd;
    core::CoinParams p;
    Solves t;
    LiveNode a;
    explicit NodeCase(const std::string& tag)
        : dd(tag), p(iso_prod_params()), t(make_solves(p)),
          a(p, SharechainConfig::data_subdir(false) + "_a") {}
};

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
        NodeCase k(enabled ? "c2pool_dash_defer_on" : "c2pool_dash_defer_off");
        auto w = wire_minter(k.a, k.p, enabled);
        {
            TrackerHold hold(k.a.node->tracker_mutex(), Mode::exclusive);
            const auto r = w.m->on_solve(solve_of(k.t.genesis), /*won_block=*/false);
            EXPECT_EQ(r.outcome.result, MintResult::Busy) << "the tracker is held: the try fails";
            EXPECT_EQ(r.queued, enabled);
            // A think cycle queued behind the holder (its compute phase blocks
            // on the lock), as a peer share or a clean tick would start one.
            k.a.node->run_think();
            hold.release();
        }
        if (enabled) {
            ASSERT_TRUE(k.a.pump_until([&](dash::ShareTracker& tr) { return tr.chain.contains(k.t.g); }))
                << "the queued solve was never minted";
            EXPECT_EQ(w.m->depth(), 0u);
            EXPECT_EQ(w.m->counters().deferred, 1u);
            EXPECT_EQ(w.m->counters().minted, 1u);
            EXPECT_EQ(w.m->counters().dropped_total(), 0u);
            EXPECT_TRUE(k.a.wait_best(k.t.g)) << "the deferred share is elected (its think ran)";
        } else {
            EXPECT_FALSE(chain_has(k.a, k.t.g)) << "the old path loses the solve";
            EXPECT_EQ(w.m->counters().deferred, 0u);
        }
    }
}

// The clean_tracker IO epilogue drains too (same order and slot rule).
TEST(DashDeferredMint, CleanTrackerEpilogueDrainsTheQueue)
{
    NodeCase k("c2pool_dash_defer_clean");
    auto w = wire_minter(k.a, k.p, true);
    {
        TrackerHold hold(k.a.node->tracker_mutex(), Mode::exclusive);
        EXPECT_TRUE(w.m->on_solve(solve_of(k.t.genesis), false).queued);
        k.a.node->clean_tracker();   // its compute phase blocks behind the holder
        hold.release();
    }
    ASSERT_TRUE(k.a.pump_until([&](dash::ShareTracker& tr) { return tr.chain.contains(k.t.g); }))
        << "the clean epilogue never drained the queue";
    EXPECT_EQ(w.m->counters().minted, 1u);
}

// With the think slot FREE (the advert tick, or any drain outside an epilogue)
// two queued solves, the second building on the first, both mint in ONE drain:
// every attempt defers its think, so the first one's think cannot take the lock
// away from the second. Asserted synchronously, before any handler runs.
TEST(DashDeferredMint, SlotFreeDrainMintsTheWholeBatchBeforeAnyThink)
{
    NodeCase k("c2pool_dash_defer_batch");
    auto w = wire_minter(k.a, k.p, true);
    {
        TrackerHold hold(k.a.node->tracker_mutex(), Mode::exclusive);
        EXPECT_TRUE(w.m->on_solve(solve_of(k.t.genesis), false).queued);
        EXPECT_TRUE(w.m->on_solve(solve_of(k.t.child), false).queued);
        EXPECT_EQ(w.m->depth(), 2u);
        hold.release();
    }
    // The child's on_solve already retried the queued parent once (busy) before
    // queueing itself behind it: count only this drain's attempts.
    ASSERT_EQ(w.queue_attempts->size(), 1u);
    EXPECT_EQ(w.queue_attempts->front(), k.t.g) << "the queue head is retried before a new solve";
    w.queue_attempts->clear();
    k.a.node->run_deferred_mint_drain();   // what the advert tick calls
    EXPECT_EQ(w.m->counters().minted, 2u) << "both minted in one drain";
    EXPECT_EQ(w.m->depth(), 0u);
    EXPECT_EQ(w.m->thinks_requested(), 1u);
    ASSERT_EQ(w.queue_attempts->size(), 2u);
    EXPECT_EQ((*w.queue_attempts)[0], k.t.g) << "arrival order: the parent first";
    EXPECT_EQ((*w.queue_attempts)[1], k.t.c);
    EXPECT_TRUE(k.a.wait_best(k.t.c)) << "the batch think elects the child";
}

// Same batch, but drained inside the run_think IO epilogue (think slot held):
// the batch's think is served as the #854 pending re-think.
TEST(DashDeferredMint, EpilogueDrainMintsParentAndChildWithOneThink)
{
    NodeCase k("c2pool_dash_defer_batch_epi");
    auto w = wire_minter(k.a, k.p, true);
    {
        TrackerHold hold(k.a.node->tracker_mutex(), Mode::exclusive);
        EXPECT_TRUE(w.m->on_solve(solve_of(k.t.genesis), false).queued);
        EXPECT_TRUE(w.m->on_solve(solve_of(k.t.child), false).queued);
        k.a.node->run_think();
        hold.release();
    }
    ASSERT_TRUE(k.a.pump_until([&](dash::ShareTracker& tr) {
        return tr.chain.contains(k.t.g) && tr.chain.contains(k.t.c);
    })) << "both queued solves must land";
    EXPECT_EQ(w.m->counters().minted, 2u);
    EXPECT_EQ(w.m->counters().dropped_total(), 0u);
    EXPECT_EQ(w.m->thinks_requested(), 1u);
    EXPECT_TRUE(k.a.wait_best(k.t.c)) << "the re-think elects the child";
}

// A reader on another thread holds the tracker SHARED: the read step succeeds,
// the EXCLUSIVE add is busy (the share built so far is freed — ASan). The 2 s
// advert tick is the only drain point here (no think is ever started).
TEST(DashDeferredMint, BusyExclusiveAddIsQueuedAndTheAdvertTickMintsIt)
{
    NodeCase k("c2pool_dash_defer_timer");
    auto w = wire_minter(k.a, k.p, true);
    {
        TrackerHold hold(k.a.node->tracker_mutex(), Mode::shared);
        const auto r = w.m->on_solve(solve_of(k.t.genesis), false);
        EXPECT_EQ(r.outcome.result, MintResult::Busy);
        EXPECT_TRUE(r.queued);
        hold.release();
    }
    k.a.node->set_target_outbound_peers(0);   // timers only, no dialing
    k.a.node->start_outbound_connections();
    ASSERT_TRUE(k.a.pump_until([&](dash::ShareTracker& tr) { return tr.chain.contains(k.t.g); }))
        << "the advert tick never drained the queue";
    EXPECT_EQ(w.m->counters().minted, 1u);
}

// A block-winning solve whose bounded wait expires is queued at the FRONT,
// minted first, and NOT counted as a forfeit (it was not lost). A queued
// block-winning share that IS finally lost is counted and logged.
TEST(DashDeferredMint, WonBlockShareIsQueuedFirstAndCountedOnlyIfLost)
{
    NodeCase k("c2pool_dash_defer_won");
    auto w = wire_minter(k.a, k.p, true);
    {
        TrackerHold hold(k.a.node->tracker_mutex(), Mode::exclusive,
                         dash::tracker_acquire::BLOCK_SHARE_LOCK_BUDGET + 300ms);
        EXPECT_TRUE(w.m->on_solve(solve_of(k.t.genesis), false).queued);
        const auto r = w.m->on_solve(solve_of(k.t.other, /*won_block=*/true), true);
        EXPECT_EQ(r.outcome.result, MintResult::Busy) << "the bounded wait expired";
        EXPECT_TRUE(r.queued);
        EXPECT_EQ(k.a.node->block_share_lock_forfeits(), 0u) << "queued, not lost";
        hold.release();
    }
    k.a.node->run_deferred_mint_drain();
    EXPECT_EQ(w.m->counters().minted, 2u);
    ASSERT_EQ(w.queue_attempts->size(), 2u);
    EXPECT_EQ((*w.queue_attempts)[0], k.t.o) << "the won-block share goes first";
    EXPECT_EQ(k.a.node->block_share_lock_forfeits(), 0u);
}

// A queued block-winning share that stays queued past the TTL is a counted,
// logged forfeit (the bounded-wait expiry alone is not).
TEST(DashDeferredMint, QueuedWonBlockShareLostToTtlIsACountedForfeit)
{
    NodeCase k2("c2pool_dash_defer_won_lost");
    auto w2 = wire_minter(k2.a, k2.p, true);
    const auto t0 = std::chrono::steady_clock::now();
    {
        TrackerHold hold(k2.a.node->tracker_mutex(), Mode::exclusive,
                         dash::tracker_acquire::BLOCK_SHARE_LOCK_BUDGET + 300ms);
        EXPECT_TRUE(w2.m->on_solve(solve_of(k2.t.other, true), true, t0).queued);
        hold.release();
    }
    w2.m->drain_point(t0 + 25s);
    EXPECT_EQ(drops(w2.m->counters(), MintDropReason::ttl), 1u);
    EXPECT_EQ(k2.a.node->block_share_lock_forfeits(), 1u) << "a lost block-winning share is counted";
}

// A queued copy of a solve that is already in the chain is dropped as a
// duplicate (it does not sit at the head of the queue until its TTL).
TEST(DashDeferredMint, QueuedDuplicateIsDroppedNotRetried)
{
    NodeCase k("c2pool_dash_defer_dup");
    auto w = wire_minter(k.a, k.p, true);

    ASSERT_TRUE(k.a.settled([](dash::ShareTracker&) {}));
    const auto first = w.m->on_solve(solve_of(k.t.genesis), false);
    ASSERT_EQ(first.outcome.result, MintResult::Minted) << "a free tracker mints synchronously";
    EXPECT_EQ(first.outcome.hash, k.t.g);
    ASSERT_TRUE(k.a.settled([](dash::ShareTracker&) {}));

    {
        TrackerHold hold(k.a.node->tracker_mutex(), Mode::exclusive);
        EXPECT_TRUE(w.m->on_solve(solve_of(k.t.genesis), false).queued);
        hold.release();
    }
    k.a.node->run_deferred_mint_drain();
    EXPECT_EQ(w.m->depth(), 0u);
    EXPECT_EQ(drops(w.m->counters(), MintDropReason::duplicate), 1u);
    EXPECT_EQ(w.m->counters().minted, 0u);
}
