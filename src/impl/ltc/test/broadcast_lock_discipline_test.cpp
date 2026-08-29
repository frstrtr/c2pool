// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Wiring regression for NodeImpl::broadcast_share, driven against a REAL
// ltc::NodeImpl and a REAL populated sharechain.
//
// The bug this pins is not a decision-function bug and no KAT over pure helpers
// can see it. broadcast_share opens with
//
//     std::shared_lock<std::shared_mutex> lock(m_tracker_mutex, std::try_to_lock);
//
// and a std::shared_mutex REFUSES a shared lock to a thread that already holds
// it exclusively. The stratum mining-submit path in main_ltc.cpp creates the
// local share while holding exactly that mutex under a unique_lock, and used to
// call broadcast_share inline inside that scope. So every broadcast of every
// locally minted share took the "tracker busy — deferring" early return, and
// this node put none of its own shares on the wire. Symmetrically, everything
// downstream of that early return — the tx-completeness gate, the per-peer send,
// the mark-only-what-was-sent bookkeeping — was unreachable code.
//
// The fix routes the submit path through post_broadcast_share(), which defers to
// the io thread so the caller's exclusive scope has ended by the time the shared
// try-lock is attempted. These cases hold that down from both sides: called
// under an exclusive lock nothing happens; called without one the walk runs and
// the per-peer send loop is entered.
//
// Folded into the EXISTING allowlisted `share_test` target (a new
// add_executable would be absent from build.yml's --target list and reported
// "Not Run" by CTest — the #769 trap).

#include <gtest/gtest.h>

#include <memory>
#include <mutex>
#include <shared_mutex>
#include <vector>

#include <core/uint256.hpp>
#include <impl/ltc/node.hpp>
#include <impl/ltc/share.hpp>

namespace {

uint256 H(uint64_t n) { return uint256(n); }

// Minimal concrete NodeImpl: the default ltc::NodeImpl ctor takes no
// io_context, opens no LevelDB and starts no timers, so a unit test can own one.
// We only have to satisfy the pure-virtual message sink and point m_chain at the
// tracker's chain (the io_context ctor is what normally does that).
struct TestNode : public ltc::NodeImpl
{
    TestNode() : ltc::NodeImpl() { m_chain = &m_tracker.chain; }

    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}

    using ltc::NodeImpl::broadcast_share;
    using ltc::NodeImpl::m_shared_share_hashes;
    using ltc::NodeImpl::m_tracker;

    // Append a v36 share (the version this lane mints — carries no new-tx list,
    // so the F3 gate is a no-op for it) on top of `prev`.
    void add_share(const uint256& hash, const uint256& prev)
    {
        auto* s = new ltc::MergedMiningShare(hash, prev);
        m_tracker.chain.add(s);
    }
};

// A two-share chain: genesis (null parent) then a tip on top of it, so the
// 5-deep walk in broadcast_share has something to collect.
std::unique_ptr<TestNode> make_node_with_chain(uint256& tip_out)
{
    auto node = std::make_unique<TestNode>();
    node->add_share(H(1), uint256::ZERO);
    node->add_share(H(2), H(1));
    tip_out = H(2);
    return node;
}

TEST(LtcBroadcastLockDiscipline, ExclusiveLockOnCallingThreadBlocksTheEntireBroadcast)
{
    // THE production defect, reproduced exactly: the caller holds the tracker
    // mutex exclusively and calls broadcast_share on the same thread.
    uint256 tip;
    auto node = make_node_with_chain(tip);

    {
        std::unique_lock<std::shared_mutex> exclusive(node->tracker_mutex());
        ASSERT_TRUE(exclusive.owns_lock());

        node->broadcast_share(tip);

        EXPECT_EQ(node->broadcast_deferred_count(), 1u);
        EXPECT_EQ(node->broadcast_acquired_count(), 0u)
            << "a shared_mutex cannot grant a shared lock to a thread already "
               "holding it exclusively";
        EXPECT_EQ(node->broadcast_reached_send_count(), 0u)
            << "nothing downstream of the try-lock runs — the gate, the per-peer "
               "send and the mark bookkeeping are all unreachable";
    }

    EXPECT_TRUE(node->m_shared_share_hashes.empty());
}

TEST(LtcBroadcastLockDiscipline, WithoutTheCallersLockTheBroadcastReachesTheSendLoop)
{
    // The post_broadcast_share shape: by the time the handler runs on the io
    // thread, the submit path's exclusive scope has ended.
    uint256 tip;
    auto node = make_node_with_chain(tip);

    node->broadcast_share(tip);

    EXPECT_EQ(node->broadcast_deferred_count(), 0u);
    EXPECT_EQ(node->broadcast_acquired_count(), 1u);
    EXPECT_EQ(node->broadcast_reached_send_count(), 1u)
        << "the walk produced a batch and the per-peer send_shares loop was "
           "entered — this is what stayed at zero in production";
}

TEST(LtcBroadcastLockDiscipline, DeferredThenRetriedSucceeds)
{
    // A deferral must be recoverable: the share is still in our chain and stays
    // un-marked, so the next cycle picks it up. This is the property that makes
    // the try-lock safe — and that the old inline call site could never reach,
    // because its lock was held on every attempt, not occasionally.
    uint256 tip;
    auto node = make_node_with_chain(tip);

    {
        std::unique_lock<std::shared_mutex> exclusive(node->tracker_mutex());
        node->broadcast_share(tip);
    }
    ASSERT_EQ(node->broadcast_reached_send_count(), 0u);

    node->broadcast_share(tip);
    EXPECT_EQ(node->broadcast_deferred_count(), 1u);
    EXPECT_EQ(node->broadcast_reached_send_count(), 1u);
}

TEST(LtcBroadcastLockDiscipline, ZeroPeersMarksNothingOnTheRealNode)
{
    // F2 on the real node: the walk ran and the send loop was entered, but with
    // no peers connected nothing reached a socket, so nothing may be marked
    // broadcast. Under the pre-fix ordering the walk itself inserted into
    // m_shared_share_hashes, which would have retired both shares here — and
    // the next walk breaks on a marked hash, with no retry path.
    uint256 tip;
    auto node = make_node_with_chain(tip);

    node->broadcast_share(tip);

    ASSERT_EQ(node->broadcast_reached_send_count(), 1u);
    EXPECT_TRUE(node->m_shared_share_hashes.empty())
        << "no peer, no byte on the wire, therefore no mark";

    // ...and because nothing was marked, a later attempt still has work to do.
    node->broadcast_share(tip);
    EXPECT_EQ(node->broadcast_reached_send_count(), 2u)
        << "an unmarked share is retried, not silently retired";
}

TEST(LtcBroadcastLockDiscipline, NullAndUnknownShareHashesAreRejectedNotWalked)
{
    // The broadcast is asynchronous now, so the share may be pruned between
    // mint and handler. Both guards must short-circuit before the chain walk.
    uint256 tip;
    auto node = make_node_with_chain(tip);

    node->broadcast_share(uint256::ZERO);
    EXPECT_EQ(node->broadcast_reached_send_count(), 0u);

    node->broadcast_share(H(9999));  // never added to the chain
    EXPECT_EQ(node->broadcast_reached_send_count(), 0u);

    node->broadcast_share(tip);      // still works for a live hash
    EXPECT_EQ(node->broadcast_reached_send_count(), 1u);
}

} // namespace
