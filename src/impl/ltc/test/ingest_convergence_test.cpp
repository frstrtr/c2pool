// SPDX-License-Identifier: AGPL-3.0-or-later
//
// D-LTC.INGEST-CONVERGENCE: the ingest admission budget must not defeat the
// drop-OLDEST liveness policy it was layered on top of.
//
// MAX_PENDING_ADDS drops the OLDEST deferred batch and keeps the newest, on
// purpose: the newest batches carry the tip-extending shares a wedged think()
// needs in order to converge, and the pre-fix drop-newest behaviour starved the
// node of exactly those. The ingest budget added afterwards is a tighter bound
// sitting UPSTREAM of that cap, and by itself it silently reinstated the old
// starvation: a handful of large deferred batches consume the whole
// MAX_INFLIGHT_SHARES budget while m_pending_adds is still far below its cap,
// so the drop-OLDEST branch can never run, and every newer batch is refused at
// admission while the stale ones keep their reservation.
//
// These tests drive the REAL ltc::NodeImpl admission path over a REAL deferred
// queue built through processing_shares_phase2. The first one is RED on the
// budget-only behaviour (admission returns false: the tip-extending batch is
// refused) and GREEN once admission evicts the oldest deferred batch and
// retries.
//
// AN EVICTION IS AN EXCHANGE, NEVER A SACRIFICE. The reservation held by the
// queue head is summed BEFORE anything is erased, and the eviction happens only
// if that sum covers the shortfall. When the budget is held by something the
// queue cannot hand back — the phase-1 verify backlog, which is the biggest
// holder under an ingest storm — the attempt refuses and destroys NOTHING.
// Those two directions are the pair of tests at the bottom of this file.
//
// The bound is tested too, because eviction is still a scan over a queue: it
// must stop on an empty queue, never look or erase past MAX_ADMIT_EVICTIONS,
// never evict for a batch that could not fit an empty budget, take the MINIMUM
// number of batches rather than draining to the bound, and never drive the
// counters negative.
//
// Folded into the EXISTING allowlisted `share_test` target rather than a new
// add_executable: a standalone target is absent from build.yml's --target list,
// so CI would never build it and CTest would report it "Not Run" (the #769
// trap).

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <vector>

#include <core/uint256.hpp>
#include <impl/ltc/node.hpp>
#include <impl/ltc/share.hpp>

namespace {

uint256 H(uint64_t n) { return uint256(n); }

std::uint64_t destroyed() {
    return ltc::orphan_share_destroy_counter().load(std::memory_order_relaxed);
}

// Same scaffold as ingest_ownership_test / broadcast_lock_discipline_test: the
// default ltc::NodeImpl ctor takes no io_context, opens no LevelDB and starts
// no timers. m_think_running makes run_think take its first early return, as it
// does on a live node whose compute thread is busy.
struct TestNode : public ltc::NodeImpl
{
    TestNode() : ltc::NodeImpl()
    {
        m_chain = &m_tracker.chain;
        m_think_running.store(true);
    }

    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}

    using ltc::NodeImpl::admit_or_evict_oldest;
    using ltc::NodeImpl::processing_shares_phase2;
    using ltc::NodeImpl::PendingShareBatch;
    using ltc::NodeImpl::m_pending_adds;
    using ltc::NodeImpl::m_tracker;
    using ltc::NodeImpl::m_ingest_budget;
    using ltc::NodeImpl::m_think_running;
    using ltc::NodeImpl::MAX_PENDING_ADDS;
    using ltc::NodeImpl::MAX_INFLIGHT_SHARES;
    using ltc::NodeImpl::MAX_ADMIT_EVICTIONS;
    using ltc::NodeImpl::INGEST_BYTES_FALLBACK_PER_SHARE;
};

ltc::MergedMiningShare* mk(const uint256& hash, const uint256& prev)
{
    auto* s = new ltc::MergedMiningShare(hash, prev);
    s->m_bits = 0x1d00ffff;
    s->m_absheight = 1;
    return s;
}

ltc::ShareType var(ltc::MergedMiningShare* s)
{
    ltc::ShareType v;
    v = s;
    return v;
}

// Build a batch of `count` shares, reserve for it, and push it through phase 2
// with the tracker held exclusively by the CALLER, so it takes the deferred
// path and lands in m_pending_adds still holding its reservation. This is the
// wedged-think() shape the whole policy is about.
void queue_deferred_batch(TestNode& node, std::uint64_t first, std::size_t count,
                          std::size_t bytes)
{
    ltc::HandleSharesData d;
    for (std::size_t i = 0; i < count; ++i)
        d.add(var(mk(H(first + i), H(first + i - 1))), {});
    ASSERT_TRUE(node.m_ingest_budget.try_admit(count, bytes));
    d.attach_budget(&node.m_ingest_budget, count, bytes);
    const std::size_t before = node.m_pending_adds.size();
    node.processing_shares_phase2(d, NetService{});
    ASSERT_EQ(node.m_pending_adds.size(), before + 1)
        << "precondition: the batch must have taken the DEFERRED path";
}

// ── THE REGRESSION ──────────────────────────────────────────────────────
//
// RED without the remedy: admission returns false and the newest batch, the one
// extending the tip, is refused while eight stale batches hold the budget and
// m_pending_adds sits at 8 of 256, so the drop-OLDEST branch cannot fire.
TEST(LtcIngestConvergence, FullBudgetWithDeferredBatchesAdmitsNewestByEvictingOldest)
{
    TestNode node;

    // Hold the tracker exclusively so every batch takes the deferred path.
    std::unique_lock<std::shared_mutex> hold(node.tracker_mutex());
    ASSERT_TRUE(hold.owns_lock());

    // Eight sharereply-sized batches: 8000 shares of the 8192-share budget.
    constexpr std::size_t kBatch = 1000;
    const std::size_t kBytes = kBatch * TestNode::INGEST_BYTES_FALLBACK_PER_SHARE;
    for (std::uint64_t b = 0; b < 8; ++b)
        queue_deferred_batch(node, 1 + b * kBatch, kBatch, kBytes);

    // The shape of the regression, stated as a precondition: the budget is
    // effectively full while the deferred queue is nowhere near its cap, so the
    // drop-OLDEST branch in phase 2 is unreachable.
    ASSERT_EQ(node.m_pending_adds.size(), 8u);
    ASSERT_LT(node.m_pending_adds.size(), TestNode::MAX_PENDING_ADDS);
    ASSERT_EQ(node.m_ingest_budget.shares(), 8u * kBatch);
    ASSERT_FALSE(node.m_ingest_budget.try_admit(kBatch, kBytes))
        << "precondition: one more sharereply-sized batch does not fit";

    const uint256 oldest_first = node.m_pending_adds.front().data->m_items.front().hash();
    const uint256 newest_first = node.m_pending_adds.back().data->m_items.front().hash();
    const std::uint64_t before = destroyed();

    // THE ASSERTION: the newest, tip-extending batch gets in.
    EXPECT_TRUE(node.admit_or_evict_oldest(kBatch, kBytes, NetService{}))
        << "the newest batch was refused while stale deferred batches held the "
           "whole budget: the admission bound has defeated drop-OLDEST";

    // One eviction was enough, and it took the OLDEST, not the newest.
    EXPECT_EQ(node.m_pending_adds.size(), 7u);
    EXPECT_NE(node.m_pending_adds.front().data->m_items.front().hash(), oldest_first);
    EXPECT_EQ(node.m_pending_adds.back().data->m_items.front().hash(), newest_first);

    // The evicted batch freed its shares rather than orphaning them, and gave
    // its reservation back: 7 deferred batches plus the one just admitted.
    EXPECT_EQ(destroyed() - before, kBatch);
    EXPECT_EQ(node.m_ingest_budget.shares(), 8u * kBatch);
    EXPECT_LE(node.m_ingest_budget.shares(), TestNode::MAX_INFLIGHT_SHARES);
    EXPECT_LE(node.m_ingest_budget.bytes(), node.m_ingest_budget.max_bytes());

    // Nothing owns the reservation the call just took (there is no batch object
    // in this test), so hand it back before the node dies.
    node.m_ingest_budget.release(kBatch, kBytes);
}

// ── The memory bound is still a bound ───────────────────────────────────
//
// With nothing to evict, a full budget must still refuse. Eviction is a way to
// choose WHICH batch is dropped, never a way to exceed the ceiling.
TEST(LtcIngestConvergence, FullBudgetWithAnEmptyQueueStillRefuses)
{
    TestNode node;
    constexpr std::size_t kBatch = 1000;
    const std::size_t kBytes = kBatch * TestNode::INGEST_BYTES_FALLBACK_PER_SHARE;

    ASSERT_TRUE(node.m_ingest_budget.try_admit(8 * kBatch, 8 * kBytes));
    ASSERT_TRUE(node.m_pending_adds.empty());

    EXPECT_FALSE(node.admit_or_evict_oldest(kBatch, kBytes, NetService{}))
        << "with nothing to evict, the ingest budget must still bound the path";
    EXPECT_EQ(node.m_ingest_budget.shares(), 8u * kBatch);
    EXPECT_EQ(node.m_ingest_budget.bytes(), 8u * kBytes);

    node.m_ingest_budget.release(8 * kBatch, 8 * kBytes);
}

// ── A batch that could never fit must not destroy other work ────────────
TEST(LtcIngestConvergence, BatchLargerThanTheWholeBudgetEvictsNothing)
{
    TestNode node;
    std::unique_lock<std::shared_mutex> hold(node.tracker_mutex());
    ASSERT_TRUE(hold.owns_lock());

    constexpr std::size_t kBatch = 100;
    const std::size_t kBytes = kBatch * TestNode::INGEST_BYTES_FALLBACK_PER_SHARE;
    for (std::uint64_t b = 0; b < 5; ++b)
        queue_deferred_batch(node, 1 + b * kBatch, kBatch, kBytes);
    ASSERT_EQ(node.m_pending_adds.size(), 5u);

    const std::size_t huge = TestNode::MAX_INFLIGHT_SHARES + 1;
    EXPECT_FALSE(node.admit_or_evict_oldest(huge, huge * 64, NetService{}));
    EXPECT_EQ(node.m_pending_adds.size(), 5u)
        << "nothing may be evicted for a reservation that can never be granted";
    EXPECT_EQ(node.m_ingest_budget.shares(), 5u * kBatch);
}

// ── THE DEFECT THIS FILE USED TO ENSHRINE ───────────────────────────────
//
// The case that stood here, `EvictionRetryStopsAtItsBoundAndDoesNotSpin`,
// asserted that an admission attempt which CANNOT possibly succeed still
// destroys MAX_ADMIT_EVICTIONS already-verified batches on its way to refusing,
// and called the resulting counters "sane". That is the futile mode written
// down as a contract.
//
// It is the storm shape the budget exists for: under an ingest storm the
// largest holder of the reservation is the phase-1 scrypt verify backlog, which
// is NOT in m_pending_adds, so draining the queue cannot hand it back. The old
// loop erased 64 batches of finished work and refused anyway — strictly worse
// than budget-only admission (which lost only the newest batch) and than
// drop-OLDEST (one-for-one, and it always admitted). Worse still, PoW is only
// established in phase 1, i.e. AFTER admission, so a peer sending well-formed
// but PoW-invalid shares could pin the budget with junk and destroy up to 64
// honest batches per subsequent message.
//
// The corrected contract: with the budget held OUTSIDE the pending queue, an
// admission attempt refuses while destroying NOTHING.
TEST(LtcIngestConvergence, BudgetHeldOutsideTheQueueRefusesWithoutDestroyingAnything)
{
    TestNode node;
    std::unique_lock<std::shared_mutex> hold(node.tracker_mutex());
    ASSERT_TRUE(hold.owns_lock());

    // Verify-pool backlog: reserved, in flight, NOT in m_pending_adds, so no
    // number of evictions can hand it back.
    const std::size_t backlog = TestNode::MAX_INFLIGHT_SHARES - 1000;
    ASSERT_TRUE(node.m_ingest_budget.try_admit(backlog, 0));

    // A queue deeper than the eviction bound, holding one share per batch, so
    // everything the bound can reach still falls short of the deficit.
    const std::size_t queued = TestNode::MAX_ADMIT_EVICTIONS + 36;
    for (std::uint64_t i = 0; i < queued; ++i)
        queue_deferred_batch(node, 1 + i, 1, TestNode::INGEST_BYTES_FALLBACK_PER_SHARE);
    ASSERT_EQ(node.m_pending_adds.size(), queued);

    const std::size_t want = 1000;
    const std::size_t want_bytes = want * TestNode::INGEST_BYTES_FALLBACK_PER_SHARE;
    // Precondition, stated in the units the policy reasons in: the shortfall is
    // larger than every batch the bound can reach put together.
    const std::size_t shortfall =
        node.m_ingest_budget.shares() + want - TestNode::MAX_INFLIGHT_SHARES;
    ASSERT_GT(shortfall, TestNode::MAX_ADMIT_EVICTIONS)
        << "precondition: the queue head cannot fund this exchange";

    const uint256 oldest_first = node.m_pending_adds.front().data->m_items.front().hash();
    const std::uint64_t before = destroyed();

    EXPECT_FALSE(node.admit_or_evict_oldest(want, want_bytes, NetService{}));

    // THE ASSERTION: a refusal is not allowed to cost anything.
    EXPECT_EQ(node.m_pending_adds.size(), queued)
        << "the attempt destroyed verified batches for a reservation it could "
           "not be granted: an eviction must be an exchange, never a sacrifice";
    EXPECT_EQ(destroyed() - before, 0u)
        << "no share may be freed by an admission attempt that refuses";
    EXPECT_EQ(node.m_pending_adds.front().data->m_items.front().hash(), oldest_first);
    EXPECT_EQ(node.m_ingest_budget.shares(), backlog + queued);
    EXPECT_LE(node.m_ingest_budget.shares(), TestNode::MAX_INFLIGHT_SHARES);

    node.m_ingest_budget.release(backlog, 0);
}

// ── The genuine exchange: budget held BY the queue ──────────────────────
//
// The other direction of the same rule. When the reservation the queue holds
// DOES cover the shortfall, the exchange goes ahead — and takes the MINIMUM
// number of batches, not the whole bound.
TEST(LtcIngestConvergence, EvictsTheMinimumNeededNotTheWholeBound)
{
    TestNode node;
    std::unique_lock<std::shared_mutex> hold(node.tracker_mutex());
    ASSERT_TRUE(hold.owns_lock());

    constexpr std::size_t kBatch = 50;
    constexpr std::size_t kCount = 10;
    const std::size_t kBytes = kBatch * TestNode::INGEST_BYTES_FALLBACK_PER_SHARE;
    for (std::uint64_t b = 0; b < kCount; ++b)
        queue_deferred_batch(node, 1 + b * kBatch, kBatch, kBytes);
    ASSERT_EQ(node.m_pending_adds.size(), kCount);

    // Size the rest of the reservation so the shortfall is exactly two queued
    // batches: evicting two is enough, evicting ten would be destruction for
    // its own sake.
    const std::size_t want = 1000;
    const std::size_t want_bytes = want * TestNode::INGEST_BYTES_FALLBACK_PER_SHARE;
    const std::size_t backlog = TestNode::MAX_INFLIGHT_SHARES + 2 * kBatch
                              - want - kCount * kBatch;
    ASSERT_TRUE(node.m_ingest_budget.try_admit(backlog, 0));
    ASSERT_FALSE(node.m_ingest_budget.try_admit(want, want_bytes))
        << "precondition: the batch does not fit as things stand";

    const uint256 third_first = node.m_pending_adds[2].data->m_items.front().hash();
    const uint256 newest_first = node.m_pending_adds.back().data->m_items.front().hash();
    const std::uint64_t before = destroyed();

    EXPECT_TRUE(node.admit_or_evict_oldest(want, want_bytes, NetService{}))
        << "the queue held enough reservation to fund this exchange";

    EXPECT_EQ(node.m_pending_adds.size(), kCount - 2)
        << "exactly the minimum number of batches may be evicted";
    EXPECT_EQ(destroyed() - before, 2u * kBatch);
    // The two OLDEST went; the rest of the queue, newest included, is intact.
    EXPECT_EQ(node.m_pending_adds.front().data->m_items.front().hash(), third_first);
    EXPECT_EQ(node.m_pending_adds.back().data->m_items.front().hash(), newest_first);
    EXPECT_EQ(node.m_ingest_budget.shares(), TestNode::MAX_INFLIGHT_SHARES);
    EXPECT_LE(node.m_ingest_budget.bytes(), node.m_ingest_budget.max_bytes());

    node.m_ingest_budget.release(want, want_bytes);
    node.m_ingest_budget.release(backlog, 0);
}

// ── The bound is still a bound, and the loop still cannot spin ──────────
//
// Same shape as the case above, sized so the shortfall is exactly
// MAX_ADMIT_EVICTIONS single-share batches: the scan stops at the bound, the
// exchange is funded to the last share, and the queue beyond the bound is never
// touched. One admission attempt can therefore never walk more than
// MAX_ADMIT_EVICTIONS entries, whichever way it ends.
TEST(LtcIngestConvergence, EvictionNeverExceedsItsBoundAndStillAdmitsAtIt)
{
    TestNode node;
    std::unique_lock<std::shared_mutex> hold(node.tracker_mutex());
    ASSERT_TRUE(hold.owns_lock());

    const std::size_t queued = TestNode::MAX_ADMIT_EVICTIONS + 36;
    for (std::uint64_t i = 0; i < queued; ++i)
        queue_deferred_batch(node, 1 + i, 1, TestNode::INGEST_BYTES_FALLBACK_PER_SHARE);
    ASSERT_EQ(node.m_pending_adds.size(), queued);

    const std::size_t want = 1000;
    const std::size_t want_bytes = want * TestNode::INGEST_BYTES_FALLBACK_PER_SHARE;
    const std::size_t backlog = TestNode::MAX_INFLIGHT_SHARES
                              + TestNode::MAX_ADMIT_EVICTIONS - want - queued;
    ASSERT_TRUE(node.m_ingest_budget.try_admit(backlog, 0));
    ASSERT_FALSE(node.m_ingest_budget.try_admit(want, want_bytes));

    const std::uint64_t before = destroyed();

    EXPECT_TRUE(node.admit_or_evict_oldest(want, want_bytes, NetService{}));
    EXPECT_EQ(node.m_pending_adds.size(), queued - TestNode::MAX_ADMIT_EVICTIONS)
        << "an admission attempt may never evict past MAX_ADMIT_EVICTIONS";
    EXPECT_EQ(destroyed() - before, TestNode::MAX_ADMIT_EVICTIONS);
    EXPECT_EQ(node.m_ingest_budget.shares(), TestNode::MAX_INFLIGHT_SHARES);
    EXPECT_LE(node.m_ingest_budget.bytes(), node.m_ingest_budget.max_bytes());

    node.m_ingest_budget.release(want, want_bytes);
    node.m_ingest_budget.release(backlog, 0);
}

} // namespace
