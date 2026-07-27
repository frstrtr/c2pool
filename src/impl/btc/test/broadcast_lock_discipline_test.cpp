// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Wiring regression for btc::NodeImpl::broadcast_share, driven against a REAL
// btc::NodeImpl and a REAL populated sharechain.
//
// The bug this pins is not a decision-function bug and no KAT over the pure
// helpers (partition_backable / broadcast_and_mark, see broadcast_gate_test)
// can see it. broadcast_share opens with
//
//     std::shared_lock<std::shared_mutex> lock(m_tracker_mutex, std::try_to_lock);
//
// and a std::shared_mutex REFUSES a shared lock to a thread that already holds
// it EXCLUSIVELY. The stratum mining-submit path in main_btc.cpp creates the
// local share while holding exactly that mutex under a unique_lock. If it were
// to call broadcast_share inside that scope, every broadcast of every locally
// minted share would take the "tracker busy — deferring" early return and this
// node would put none of its own shares on the wire — and everything downstream
// of that return (the F3 tx-completeness gate this PR #880 routes through the
// send path, the per-peer send, the mark-only-what-was-sent bookkeeping) would
// be unreachable code. A gate on dead code passes every test while gating
// nothing; this is the failure mode this trace exists to rule out.
//
// The production caller does the right thing: main_btc create_share_fn drops
// the exclusive lock (lk.unlock()) BEFORE calling broadcast_share, so the send
// loop is reachable. These cases hold that down from both sides: called under
// an exclusive lock on the calling thread nothing downstream runs; called
// without one the walk runs and the per-peer send loop is entered. A future
// refactor that moves broadcast_share back inside the lock scope reddens this.
//
// Folded into the EXISTING allowlisted btc_share_test target (a new
// add_executable would be absent from build.yml -- reported "Not Run" by CTest,
// the #769 trap).

#include <gtest/gtest.h>

#include <memory>
#include <mutex>
#include <shared_mutex>

#include <core/uint256.hpp>
#include <impl/btc/node.hpp>
#include <impl/btc/share.hpp>

namespace {

uint256 H(uint64_t n) { return uint256(n); }

// Minimal concrete NodeImpl: the default btc::NodeImpl ctor takes no io_context,
// opens no LevelDB and starts no timers, so a unit test can own one. The
// io_context ctor is what normally points m_chain at the tracker chain; we do
// that by hand here.
struct TestNode : public btc::NodeImpl
{
    TestNode() : btc::NodeImpl() { m_chain = &m_tracker.chain; }

    // Satisfy core::ICommunicator: this unit test drives no sockets.
    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}

    using btc::NodeImpl::broadcast_share;
    using btc::NodeImpl::m_shared_share_hashes;
    using btc::NodeImpl::m_tracker;

    // Append a v36 share (the version this lane mints — carries no new-tx list,
    // so the F3 gate is a no-op for it) on top of `prev`.
    void add_share(const uint256& hash, const uint256& prev)
    {
        auto* s = new btc::MergedMiningShare(hash, prev);
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

} // namespace

TEST(BtcBroadcastLockDiscipline, ExclusiveLockOnCallingThreadBlocksTheEntireBroadcast)
{
    // THE defect this trace exists to rule out, reproduced exactly: the caller
    // holds the tracker mutex exclusively and calls broadcast_share on the same
    // thread.
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
            << "nothing downstream of the try-lock runs — the F3 gate, the "
               "per-peer send and the mark bookkeeping are all unreachable";
    }

    EXPECT_TRUE(node->m_shared_share_hashes.empty());
}

TEST(BtcBroadcastLockDiscipline, WithoutTheCallersLockTheBroadcastReachesTheSendLoop)
{
    // The main_btc create_share_fn shape: the submit path drops its exclusive
    // lock (lk.unlock()) before calling broadcast_share, so by the time we get
    // here no exclusive lock is held on this thread.
    uint256 tip;
    auto node = make_node_with_chain(tip);

    node->broadcast_share(tip);

    EXPECT_EQ(node->broadcast_deferred_count(), 0u);
    EXPECT_EQ(node->broadcast_acquired_count(), 1u);
    EXPECT_EQ(node->broadcast_reached_send_count(), 1u)
        << "the walk produced a batch and the per-peer send loop was entered — "
           "this is what stays at zero if the caller holds the exclusive lock";
}

TEST(BtcBroadcastLockDiscipline, DeferredThenRetriedSucceeds)
{
    // A deferral must be recoverable: the share is still in our chain and stays
    // un-marked, so the next cycle picks it up. This is the property that makes
    // the try-lock safe — and that an always-locked inline call site could
    // never reach, because its lock would be held on every attempt.
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

TEST(BtcBroadcastLockDiscipline, ZeroPeersMarksNothingOnTheRealNode)
{
    // F2 on the real node: the walk ran and the send loop was entered, but with
    // no peers connected nothing reached a socket, so nothing may be marked
    // broadcast. Marking at walk time would retire both shares here — the next
    // walk breaks on a marked hash, with no retry path.
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

TEST(BtcBroadcastLockDiscipline, NullAndUnknownShareHashesAreRejectedNotWalked)
{
    // Both guards must short-circuit before the chain walk: a null hash and a
    // hash that was never added to our chain must not reach the send loop.
    uint256 tip;
    auto node = make_node_with_chain(tip);

    node->broadcast_share(uint256::ZERO);
    EXPECT_EQ(node->broadcast_reached_send_count(), 0u);

    node->broadcast_share(H(9999));  // never added to the chain
    EXPECT_EQ(node->broadcast_reached_send_count(), 0u);

    node->broadcast_share(tip);      // still works for a live hash
    EXPECT_EQ(node->broadcast_reached_send_count(), 1u);
}
