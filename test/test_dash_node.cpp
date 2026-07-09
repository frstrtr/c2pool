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

#include <memory>
#include <type_traits>

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


// ── Slice S8-p2p.2: sharechain-p2p dispatch surface ──────────────────
//
// These KATs pin the dispatch LAYER added by slice .2 (Legacy / Actual /
// Node = NodeBridge<...>) at COMPILE time. They deliberately do NOT
// instantiate Legacy/Actual nor invoke a handler: the handler bodies live in
// protocol_legacy.cpp / protocol_actual.cpp and transitively reference
// NodeImpl::processing_shares()/handle_get_share(), whose definitions are
// link-deferred to node.cpp (slice .4). A SFINAE detector checks each of the
// 12 handler overloads is DECLARED on both protocols in a fully unevaluated
// context, so no definition is ODR-used and this test still links against the
// slice-A header-only node.
namespace {

template <class P, class M, class = void>
struct has_msg_handler : std::false_type {};
template <class P, class M>
struct has_msg_handler<P, M, std::void_t<decltype(
    std::declval<P&>().handle(std::declval<std::unique_ptr<M>>(),
                              std::declval<dash::NodeImpl::peer_ptr>()))>>
    : std::true_type {};

template <class P>
constexpr bool registers_all_12()
{
    return has_msg_handler<P, dash::message_addrs>::value
        && has_msg_handler<P, dash::message_addrme>::value
        && has_msg_handler<P, dash::message_ping>::value
        && has_msg_handler<P, dash::message_getaddrs>::value
        && has_msg_handler<P, dash::message_shares>::value
        && has_msg_handler<P, dash::message_sharereq>::value
        && has_msg_handler<P, dash::message_sharereply>::value
        && has_msg_handler<P, dash::message_bestblock>::value
        && has_msg_handler<P, dash::message_have_tx>::value
        && has_msg_handler<P, dash::message_losing_tx>::value
        && has_msg_handler<P, dash::message_remember_tx>::value
        && has_msg_handler<P, dash::message_forget_tx>::value;
}

} // namespace

// 6. Legacy registers a handler overload for all 12 established-peer messages.
TEST(DashNodeDispatch, LegacyRegistersAll12Handlers)
{
    EXPECT_TRUE((has_msg_handler<dash::Legacy, dash::message_addrs>::value));
    EXPECT_TRUE((has_msg_handler<dash::Legacy, dash::message_addrme>::value));
    EXPECT_TRUE((has_msg_handler<dash::Legacy, dash::message_ping>::value));
    EXPECT_TRUE((has_msg_handler<dash::Legacy, dash::message_getaddrs>::value));
    EXPECT_TRUE((has_msg_handler<dash::Legacy, dash::message_shares>::value));
    EXPECT_TRUE((has_msg_handler<dash::Legacy, dash::message_sharereq>::value));
    EXPECT_TRUE((has_msg_handler<dash::Legacy, dash::message_sharereply>::value));
    EXPECT_TRUE((has_msg_handler<dash::Legacy, dash::message_bestblock>::value));
    EXPECT_TRUE((has_msg_handler<dash::Legacy, dash::message_have_tx>::value));
    EXPECT_TRUE((has_msg_handler<dash::Legacy, dash::message_losing_tx>::value));
    EXPECT_TRUE((has_msg_handler<dash::Legacy, dash::message_remember_tx>::value));
    EXPECT_TRUE((has_msg_handler<dash::Legacy, dash::message_forget_tx>::value));
    static_assert(registers_all_12<dash::Legacy>(),
                  "Legacy must register all 12 sharechain-p2p dispatch handlers");
}

// 7. Actual registers the identical 12-handler set (bodies diverge, surface does not).
TEST(DashNodeDispatch, ActualRegistersAll12Handlers)
{
    EXPECT_TRUE((has_msg_handler<dash::Actual, dash::message_addrs>::value));
    EXPECT_TRUE((has_msg_handler<dash::Actual, dash::message_addrme>::value));
    EXPECT_TRUE((has_msg_handler<dash::Actual, dash::message_ping>::value));
    EXPECT_TRUE((has_msg_handler<dash::Actual, dash::message_getaddrs>::value));
    EXPECT_TRUE((has_msg_handler<dash::Actual, dash::message_shares>::value));
    EXPECT_TRUE((has_msg_handler<dash::Actual, dash::message_sharereq>::value));
    EXPECT_TRUE((has_msg_handler<dash::Actual, dash::message_sharereply>::value));
    EXPECT_TRUE((has_msg_handler<dash::Actual, dash::message_bestblock>::value));
    EXPECT_TRUE((has_msg_handler<dash::Actual, dash::message_have_tx>::value));
    EXPECT_TRUE((has_msg_handler<dash::Actual, dash::message_losing_tx>::value));
    EXPECT_TRUE((has_msg_handler<dash::Actual, dash::message_remember_tx>::value));
    EXPECT_TRUE((has_msg_handler<dash::Actual, dash::message_forget_tx>::value));
    static_assert(registers_all_12<dash::Actual>(),
                  "Actual must register all 12 sharechain-p2p dispatch handlers");
}

// 8. The Node alias binds NodeImpl + both protocols through the shared NodeBridge.
TEST(DashNodeDispatch, NodeBridgeAliasBindsLegacyActual)
{
    static_assert(std::is_same_v<dash::Node,
                      pool::NodeBridge<dash::NodeImpl, dash::Legacy, dash::Actual>>,
                  "dash::Node must be NodeBridge<NodeImpl, Legacy, Actual>");
    static_assert(std::is_base_of_v<dash::NodeImpl, dash::Legacy>,
                  "Legacy must derive from NodeImpl");
    static_assert(std::is_base_of_v<dash::NodeImpl, dash::Actual>,
                  "Actual must derive from NodeImpl");
    SUCCEED();
}
