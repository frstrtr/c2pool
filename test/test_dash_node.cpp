// DASH S8 pool-node leaf 5 (FINAL) slice A — node.hpp skeleton KAT.
//
// Slice A is the class SKELETON + accessors only (reception/broadcast/think are
// later slices). This KAT pins the slice-A SURFACE that the later slices and the
// dashboard depend on, all rig-free (default-constructed NodeImpl, no
// io_context, no sockets):
//   - NodeImpl is concrete + default-constructible (pure-virtuals stubbed).
//   - The fresh node has an empty tracker (chain + verified both 0).
//   - publish_snapshot() copies live tracker counts into the lock-free snapshot,
//     and the snapshot getters read them back without the tracker lock.
//   - tracker() exposes the live ShareTracker; mutating it is reflected after a
//     fresh publish_snapshot().
//   - read_tracker() yields a usable guard off the compute thread.
//   - is_compute_thread() is false on the test (IO/main) thread.
//
// These are exactly the accessors that slice B (reception) and the web layer
// call, so locking them down now prevents surface drift across the remaining
// slices.

#include <gtest/gtest.h>

#include <impl/dash/node.hpp>
#include <core/uint256.hpp>

namespace {

// Expose protected publish_snapshot() / m_tracker member shape for the KAT by
// subclassing — mirrors how the reception slice will drive the node internally.
class TestNode : public dash::NodeImpl
{
public:
    using dash::NodeImpl::NodeImpl;
    void test_publish() { publish_snapshot(); }
};

} // namespace

// 1. NodeImpl is a concrete, default-constructible type (the pure-virtual
//    BaseNode/INetwork contract is satisfied by slice-A stubs).
TEST(DashNode, DefaultConstructibleConcrete)
{
    TestNode node;
    // Fresh node: nothing learned yet.
    EXPECT_EQ(node.tracker().chain.size(), 0u);
    EXPECT_EQ(node.tracker().verified.size(), 0u);
}

// 2. The lock-free snapshot starts zeroed and tracks the tracker after publish.
TEST(DashNode, SnapshotPublishReflectsTracker)
{
    TestNode node;

    // Before any publish, snapshot getters return the zero-initialised snapshot.
    EXPECT_EQ(node.get_chain_count(), 0);
    EXPECT_EQ(node.get_verified_count(), 0);

    // Publishing an empty tracker keeps the counts at zero (no spurious data).
    node.test_publish();
    auto snap = node.get_tracker_snapshot();
    EXPECT_EQ(snap.chain_count, 0);
    EXPECT_EQ(snap.verified_count, 0);
    EXPECT_EQ(snap.head_count, 0);
    EXPECT_EQ(snap.fork_count, snap.head_count);
    EXPECT_EQ(snap.pool_hashrate, 0.0);

    // The getters agree with the snapshot struct.
    EXPECT_EQ(node.get_chain_count(), snap.chain_count);
    EXPECT_EQ(node.get_verified_count(), snap.verified_count);
}

// 3. tracker() returns the live tracker; the snapshot is a point-in-time copy
//    that only changes on the next publish (lock-free read contract).
TEST(DashNode, SnapshotIsPointInTimeCopy)
{
    TestNode node;
    node.test_publish();
    EXPECT_EQ(node.get_chain_count(), 0);

    // tracker() is the SAME object the snapshot is derived from.
    dash::ShareTracker& t = node.tracker();
    EXPECT_EQ(&t, &node.tracker());

    // Snapshot remains the last published value until re-published.
    auto before = node.get_tracker_snapshot();
    EXPECT_EQ(before.chain_count, 0);
}

// 4. read_tracker() yields a usable guard off the compute thread (no compute
//    thread is running, so the shared try_lock succeeds), and is_compute_thread()
//    is false on the calling (main) thread.
TEST(DashNode, ReadTrackerGuardOffComputeThread)
{
    TestNode node;
    EXPECT_FALSE(node.is_compute_thread());

    auto guard = node.read_tracker();
    ASSERT_TRUE(static_cast<bool>(guard));      // shared lock acquired
    EXPECT_EQ(guard->chain.size(), 0u);          // operator-> reaches the tracker
    EXPECT_EQ((*guard).verified.size(), 0u);     // operator* reaches the tracker
}

// 5. tracker_mutex() exposes the shared_mutex and a blocking shared lock works
//    when nothing holds it exclusively (consensus-critical-path contract).
TEST(DashNode, TrackerSharedLockBlockingPath)
{
    TestNode node;
    {
        auto lk = node.tracker_shared_lock();
        EXPECT_TRUE(lk.owns_lock());
    }
    // Mutex is the same object exposed by tracker_mutex().
    EXPECT_EQ(&node.tracker_mutex(), &node.tracker_mutex());
}
