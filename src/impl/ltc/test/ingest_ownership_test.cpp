// SPDX-License-Identifier: AGPL-3.0-or-later
//
// D-LTC.INGEST-OWNERSHIP — the real unbounded growth behind the LTC RSS
// self-abort, driven against a REAL ltc::NodeImpl.
//
// ltc::ShareType is a std::variant of RAW POINTERS with manual lifetime
// (sharechain/share.hpp: `new Args()` on load, freed only by an explicit
// destroy()). The ONLY container that ever frees a share is the sharechain
// itself. Every ingest path that deserialised a share the tracker did not adopt
// therefore leaked it, with no erase path anywhere:
//
//   * the batch the pending_adds cap DROPS  ("dropping OLDEST queued batch" —
//     the very line the production log prints just before each abort),
//   * every duplicate skipped in phase 2 (a relayed share we already hold, or
//     the overlap of an ancestor reply),
//   * every share whose phase-1 verification failed,
//   * every sharereply that arrived after its 15 s request timeout or after
//     cancel() on disconnect — got_share_reply swallows the matcher's
//     invalid_argument and the whole reply was dropped on the floor.
//
// ORACLE: ltc::orphan_share_destroy_counter(), bumped once per share object a
// container frees because nobody adopted it. It is used rather than
// LeakSanitizer because the ASAN CI leg runs with ASAN_OPTIONS detect_leaks=0
// (build.yml), so LSan is blind to exactly this leak class.
//
// Folded into the EXISTING allowlisted `share_test` target (#769 trap).

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

// Same scaffold as broadcast_lock_discipline_test: the default ltc::NodeImpl
// ctor takes no io_context, opens no LevelDB and starts no timers.
struct TestNode : public ltc::NodeImpl
{
    TestNode() : ltc::NodeImpl()
    {
        m_chain = &m_tracker.chain;
        // processing_shares_phase2 ends with run_think() when it admitted new
        // shares, and run_think arms an asio timer on m_context — which the
        // default ctor deliberately leaves null. The already-running flag makes
        // run_think take its first early return, exactly as it does on a live
        // node whose compute thread is busy.
        m_think_running.store(true);
    }

    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}

    using ltc::NodeImpl::processing_shares_phase2;
    using ltc::NodeImpl::m_pending_adds;
    using ltc::NodeImpl::m_tracker;
    using ltc::NodeImpl::m_raw_share_cache;
    using ltc::NodeImpl::m_ingest_budget;
    using ltc::NodeImpl::m_think_running;
};

ltc::MergedMiningShare* mk(const uint256& hash, const uint256& prev)
{
    auto* s = new ltc::MergedMiningShare(hash, prev);
    s->m_bits = 0x1d00ffff;   // a sane compact target; phase 2 logs its difficulty
    s->m_absheight = 1;
    return s;
}

ltc::ShareType var(ltc::MergedMiningShare* s)
{
    ltc::ShareType v;
    v = s;
    return v;
}

ltc::HandleSharesData one_share_batch(ltc::MergedMiningShare* s)
{
    ltc::HandleSharesData d;
    d.add(var(s), {});
    return d;
}

// ── A1a: the batch the pending_adds cap drops ───────────────────────────
//
// THE production line. Under the cap the queue erases its oldest entry; before
// this fix that erase freed the HandleSharesData's three vectors and left every
// deserialised share in it unreachable. Each "dropping OLDEST queued batch" in
// the contabo log was one whole batch of shares leaked.
TEST(LtcIngestOwnership, DroppedOldestPendingBatchFreesItsSharesAndItsBudget)
{
    TestNode node;
    const std::uint64_t before = destroyed();

    // Hold the tracker exclusively on THIS thread so phase 2's try_to_lock fails
    // and every batch takes the deferred-queue path — the wedged-think() shape.
    std::unique_lock<std::shared_mutex> hold(node.tracker_mutex());
    ASSERT_TRUE(hold.owns_lock());

    constexpr std::size_t kBytesPerBatch = 1000;
    for (int i = 1; i <= 257; ++i) {
        auto d = one_share_batch(mk(H(i), H(i - 1)));
        ASSERT_TRUE(node.m_ingest_budget.try_admit(1, kBytesPerBatch));
        d.attach_budget(&node.m_ingest_budget, 1, kBytesPerBatch);
        node.processing_shares_phase2(d, NetService{});
    }

    // The cap held (that part always worked) ...
    EXPECT_EQ(node.m_pending_adds.size(), 256u);
    // ... and the ONE batch it dropped actually released its share.
    EXPECT_EQ(destroyed() - before, 1u)
        << "the dropped batch must free its shares, not orphan them";
    // ... and gave its ingest reservation back, so the refused-newest bound
    // cannot slowly seize up as batches are dropped.
    EXPECT_EQ(node.m_ingest_budget.shares(), 256u);
    EXPECT_EQ(node.m_ingest_budget.bytes(), 256u * kBytesPerBatch);
}

// ── A1b: duplicate in phase 2 ───────────────────────────────────────────
//
// Identity here MUST be by pointer, not by hash: the batch's copy has the same
// hash as the object the chain owns and is a different allocation. Freeing by
// hash would free the chain's share.
TEST(LtcIngestOwnership, DuplicateIsFreedWhileTheChainCopySurvives)
{
    TestNode node;
    auto* original = mk(H(1), uint256::ZERO);
    node.m_tracker.chain.add(original);
    ASSERT_TRUE(node.m_tracker.chain.contains(H(1)));

    const std::uint64_t before = destroyed();
    {
        auto d = one_share_batch(mk(H(1), uint256::ZERO));  // same hash, new heap
        node.processing_shares_phase2(d, NetService{});
    }
    EXPECT_EQ(destroyed() - before, 1u)
        << "the duplicate the phase-2 dup branch skips must be freed";

    // The chain still owns the ORIGINAL allocation and it is readable.
    ASSERT_TRUE(node.m_tracker.chain.contains(H(1)));
    EXPECT_EQ(ltc::share_ptr_id(node.m_tracker.chain.get_share(H(1))),
              static_cast<const void*>(original));
    EXPECT_EQ(node.m_tracker.chain.get_share(H(1)).hash(), H(1));
}

// ── A1c: phase-1 verify failure ─────────────────────────────────────────
TEST(LtcIngestOwnership, ShareThatFailedVerificationIsFreed)
{
    TestNode node;
    const std::uint64_t before = destroyed();
    {
        // Null hash == "share_init_verify threw in phase 1"; phase 2 skips it.
        auto* s = new ltc::MergedMiningShare();
        ASSERT_TRUE(s->m_hash.IsNull());
        auto d = one_share_batch(s);
        node.processing_shares_phase2(d, NetService{});
    }
    EXPECT_EQ(destroyed() - before, 1u);
}

// ── The other half of the invariant: an ADOPTED share must NOT be freed ──
//
// This is what makes the fix safe rather than a double free. If the adoption
// pass were dropped or keyed on hash instead of pointer, the batch destructor
// would free memory the sharechain owns and later frees again.
TEST(LtcIngestOwnership, AdoptedShareIsHandedToTheChainAndNotFreedByTheBatch)
{
    TestNode node;
    auto* s = mk(H(5), uint256::ZERO);
    const std::uint64_t before = destroyed();
    {
        auto d = one_share_batch(s);
        node.processing_shares_phase2(d, NetService{});
    }
    EXPECT_EQ(destroyed() - before, 0u)
        << "the batch must not free a share the sharechain adopted";

    ASSERT_TRUE(node.m_tracker.chain.contains(H(5)));
    EXPECT_EQ(ltc::share_ptr_id(node.m_tracker.chain.get_share(H(5))),
              static_cast<const void*>(s));
    // Still alive and intact: read through the chain's own variant.
    EXPECT_EQ(node.m_tracker.chain.get_share(H(5)).prev_hash(), uint256::ZERO);
}

// ── A1d: sharereply that lost its request (timeout / disconnect cancel) ──
TEST(LtcIngestOwnership, ShareReplyForAnUnknownRequestIsFreedNotLeaked)
{
    TestNode node;
    const std::uint64_t before = destroyed();
    {
        ltc::ShareReplyData reply;
        auto& owned = reply.owned();
        owned.m_items.push_back(var(mk(H(7), H(6))));
        owned.m_items.push_back(var(mk(H(8), H(7))));
        ASSERT_EQ(reply.size(), 2u);

        // The matcher throws std::invalid_argument for an id it no longer holds
        // (timed out after 15 s, or cancel()led when the peer disconnected).
        // got_share_reply swallows it — which used to discard the payload.
        node.got_share_reply(H(4242), reply);
    }
    EXPECT_EQ(destroyed() - before, 2u)
        << "a reply whose request already died must free its shares";
}

// ── The raw-share cache had no erase path at all ────────────────────────
TEST(LtcIngestOwnership, RawShareCacheEntryIsDroppedWhenTheChainDropsTheShare)
{
    TestNode node;
    node.m_tracker.chain.add(mk(H(3), uint256::ZERO));
    ASSERT_TRUE(node.m_tracker.chain.contains(H(3)));

    chain::RawShare raw;
    raw.type = 36;
    node.m_raw_share_cache[H(3)] = raw;
    ASSERT_EQ(node.m_raw_share_cache.count(H(3)), 1u);

    ASSERT_TRUE(node.m_tracker.chain.remove(H(3)));
    EXPECT_EQ(node.m_raw_share_cache.count(H(3)), 0u)
        << "m_raw_share_cache retained the wire bytes of every share ever seen, "
           "including pruned challenger/fork shares";
}

// ── Regression invariant, stated once ───────────────────────────────────
// After any sequence of drops / duplicates / verify failures, the shares that
// are still alive are exactly the ones the chain owns, and the ingest budget
// returns to zero.
TEST(LtcIngestOwnership, MixedBatchLeavesOnlyChainMembersAliveAndBudgetAtZero)
{
    TestNode node;
    node.m_tracker.chain.add(mk(H(10), uint256::ZERO));   // pre-existing

    const std::uint64_t before = destroyed();
    {
        ltc::HandleSharesData d;
        d.add(var(mk(H(10), uint256::ZERO)), {});         // duplicate  -> freed
        d.add(var(new ltc::MergedMiningShare()), {});     // bad verify -> freed
        d.add(var(mk(H(11), H(10))), {});                 // new        -> adopted
        ASSERT_TRUE(node.m_ingest_budget.try_admit(3, 300));
        d.attach_budget(&node.m_ingest_budget, 3, 300);
        node.processing_shares_phase2(d, NetService{});
    }
    EXPECT_EQ(destroyed() - before, 2u);
    EXPECT_EQ(node.m_tracker.chain.size(), 2u);
    EXPECT_TRUE(node.m_tracker.chain.contains(H(11)));
    EXPECT_EQ(node.m_ingest_budget.shares(), 0u);
    EXPECT_EQ(node.m_ingest_budget.bytes(), 0u);
}

} // namespace
