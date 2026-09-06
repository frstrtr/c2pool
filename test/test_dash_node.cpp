// SPDX-License-Identifier: AGPL-3.0-or-later
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
#include <impl/dash/known_txs_retention.hpp>  // dash::select_standing_remember (#950)

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
constexpr bool registers_all_13()
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
        && has_msg_handler<P, dash::message_forget_tx>::value
        && has_msg_handler<P, dash::message_tx_inject>::value;   // #157 M2
}

} // namespace

// 6. Legacy registers a handler overload for all 13 established-peer messages
//    (the original 12 + the #157 M2 tx_inject subtype).
TEST(DashNodeDispatch, LegacyRegistersAll13Handlers)
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
    EXPECT_TRUE((has_msg_handler<dash::Legacy, dash::message_tx_inject>::value));
    static_assert(registers_all_13<dash::Legacy>(),
                  "Legacy must register all 13 sharechain-p2p dispatch handlers");
}

// 7. Actual registers the identical 13-handler set (bodies diverge, surface does not).
TEST(DashNodeDispatch, ActualRegistersAll13Handlers)
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
    EXPECT_TRUE((has_msg_handler<dash::Actual, dash::message_tx_inject>::value));
    static_assert(registers_all_13<dash::Actual>(),
                  "Actual must register all 13 sharechain-p2p dispatch handlers");
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

// ═══════════════════════════════════════════════════════════════════════════
// #889 — the BLOCK-WINNING mint must not be forfeited by a momentarily busy
//        tracker.
//
// THE DEFECT. add_local_share() acquires the exclusive tracker lock with
// std::try_to_lock and DECLINES when the compute thread is mid-think(). For an
// ordinary share that is a sound trade: the decline costs one share and the
// NEXT solve mints instead. A block-winning share has no next solve — the block
// is found once — so the same decline permanently forfeits the highest-work
// share the node will ever produce.
//
// AND IT IS NOT ONLY OUR SHARE WEIGHT. p2pool nodes do not learn about a pool
// block from a block announcement; they detect it THROUGH THE SHARECHAIN, by
// watching for a share with pow_hash <= header['bits'].target
// (p2pool/node.py:145-147). A block-winning share that never enters the
// sharechain is therefore a won block that NO peer — including our own oracle —
// can ever record. The try_to_lock decline reproduces the full #887 symptom,
// just intermittently and far harder to notice.
//
// WHAT THESE TESTS PIN. Nothing existing covers this: every prior mint KAT runs
// against a FREE tracker, where try_to_lock and a bounded wait are
// indistinguishable. These hold the real m_tracker_mutex EXCLUSIVELY from
// another thread — exactly the state think() puts it in — and drive the mint.
//
//   1. block-winning  + tracker held -> the share STILL LANDS (this is the fix)
//   2. ordinary share + tracker held -> still declines (the trade we must NOT
//      change; also the negative control that proves test 1 is not passing
//      merely because the lock happened to be free)
//   3. budget expiry  -> declines LOUDLY and COUNTED, never silently
//
// NOTE (#895): these are plain TESTs, not #ifdef-guarded, so gtest_add_tests
// (AUTO) registers cases that genuinely execute.

#include <impl/dash/tracker_acquire.hpp>

#include <atomic>
#include <chrono>
#include <thread>

namespace {

// Minimal locally-minted share. add_local_share() only needs a non-null
// identity hash and (for the F1-sub backability gate) an empty
// m_new_transaction_hashes — everything the real producer builds on top of that
// is share CONSTRUCTION, which #889 does not touch. Heap-allocated because
// dash::ShareType is a non-owning variant handle: the tracker takes ownership
// on a successful add, and the caller reclaims on a decline (main_dash.cpp).
dash::ShareType make_local_share(unsigned char tag)
{
    auto* s = new dash::DashShare();
    // NB uint256::begin() is a uint32_t* over 8 WORDS (core/uint256.hpp), not a
    // byte pointer. Word 7 is the most significant, so it renders first in
    // GetHex() -- the share is then identifiable in the very log lines these
    // tests pin the behaviour of.
    s->m_hash.begin()[7] = 0x89000000u | static_cast<uint32_t>(tag);
    return dash::ShareType(s);
}

void discard(dash::ShareType& share)
{
    share.invoke([](auto* obj) { delete obj; });
}

// Holds the node's REAL exclusive tracker lock for `hold`, i.e. reproduces a
// think() cycle in flight. Signals once the lock is actually held so the test
// body can never race ahead of it.
class ExclusiveTrackerHolder {
public:
    ExclusiveTrackerHolder(std::shared_mutex& mtx, std::chrono::milliseconds hold)
    {
        thread_ = std::thread([this, &mtx, hold] {
            std::unique_lock<std::shared_mutex> lk(mtx);
            held_.store(true);
            std::this_thread::sleep_for(hold);
            held_.store(false);
        });
        // Spin until the lock is genuinely held — no sleep-and-hope.
        while (!held_.load())
            std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
    ~ExclusiveTrackerHolder() { if (thread_.joinable()) thread_.join(); }
private:
    std::atomic<bool> held_{false};
    std::thread thread_;
};

} // namespace

// 9. ★ THE REGRESSION. Tracker held EXCLUSIVELY; a block-winning mint still
//    lands. Pre-#889 this returned ZERO and the share — and with it every
//    peer's only way of seeing the block — was gone for good.
TEST(DashBlockWinningMint, LandsWhileTrackerHeldExclusively)
{
    TestNode node;
    ASSERT_EQ(node.tracker().chain.size(), 0u);

    constexpr auto kHold = std::chrono::milliseconds(400);
    const auto t0 = std::chrono::steady_clock::now();

    uint256 minted;
    {
        ExclusiveTrackerHolder holder(node.tracker_mutex(), kHold);
        auto share = make_local_share(0xB1);
        minted = node.add_local_share(share, /*block_winning=*/true);
        if (minted.IsNull())
            discard(share);
    }
    const auto waited = std::chrono::steady_clock::now() - t0;

    // The share landed.
    EXPECT_FALSE(minted.IsNull())
        << "block-winning share forfeited by a busy tracker (#889)";
    EXPECT_EQ(node.tracker().chain.size(), 1u);
    // No forfeit was recorded — the wait succeeded, it did not merely give up.
    EXPECT_EQ(node.block_share_lock_forfeits(), 0u);

    // It genuinely WAITED for the holder rather than finding a free lock: the
    // call could not have returned before the holder released. This is what
    // makes the test a real exercise of the bounded acquire and not an
    // accidental pass on an idle mutex.
    EXPECT_GE(waited, kHold - std::chrono::milliseconds(50));
}

// 10. THE TRADE WE MUST NOT CHANGE (and the in-tree negative control for #9):
//     an ORDINARY share under the identical held lock still declines, exactly
//     as before. If #9 ever passed because the lock was free, this would fail
//     alongside it.
TEST(DashBlockWinningMint, OrdinaryShareStillDeclinesWhileTrackerHeld)
{
    TestNode node;

    uint256 minted;
    {
        ExclusiveTrackerHolder holder(node.tracker_mutex(),
                                      std::chrono::milliseconds(400));
        auto share = make_local_share(0xC2);
        minted = node.add_local_share(share, /*block_winning=*/false);
        if (minted.IsNull())
            discard(share);
    }

    EXPECT_TRUE(minted.IsNull())
        << "the ordinary share path must keep today's try_to_lock decline";
    EXPECT_EQ(node.tracker().chain.size(), 0u);
    EXPECT_EQ(node.block_share_lock_forfeits(), 0u);
}

// 11. Default argument keeps every existing caller on the ordinary path — the
//     fix cannot leak into share traffic by omission.
TEST(DashBlockWinningMint, DefaultArgumentIsTheOpportunisticPath)
{
    TestNode node;

    uint256 minted;
    {
        ExclusiveTrackerHolder holder(node.tracker_mutex(),
                                      std::chrono::milliseconds(300));
        auto share = make_local_share(0xD3);
        minted = node.add_local_share(share);   // no second argument
        if (minted.IsNull())
            discard(share);
    }
    EXPECT_TRUE(minted.IsNull());
}

// 12. THE BOUND IS REAL AND THE FORFEIT IS LOUD. Hold the tracker past the
//     whole budget: the mint declines (fail-closed, unchanged end state) but
//     now increments a counter and logs at ERROR. A silent drop is the defect;
//     an accounted one is the fix's failure mode.
//
//     Runtime is BLOCK_SHARE_LOCK_BUDGET + margin by construction — that is the
//     property under test, not incidental slowness.
TEST(DashBlockWinningMint, BudgetExpiryIsACountedForfeitNotASilentDrop)
{
    TestNode node;
    ASSERT_EQ(node.block_share_lock_forfeits(), 0u);

    const auto over_budget =
        dash::tracker_acquire::BLOCK_SHARE_LOCK_BUDGET
        + std::chrono::milliseconds(300);

    uint256 minted;
    std::chrono::steady_clock::duration waited{};
    {
        ExclusiveTrackerHolder holder(node.tracker_mutex(), over_budget);
        auto share = make_local_share(0xE4);
        const auto t0 = std::chrono::steady_clock::now();
        minted = node.add_local_share(share, /*block_winning=*/true);
        waited = std::chrono::steady_clock::now() - t0;
        if (minted.IsNull())
            discard(share);
    }

    EXPECT_TRUE(minted.IsNull());
    // It spent the WHOLE budget before giving up — not an instant try_to_lock
    // decline wearing a counter. (This is also what keeps the test a fix
    // detector: without the bounded wait it returns in ~0 ms.)
    EXPECT_GE(waited, dash::tracker_acquire::BLOCK_SHARE_LOCK_BUDGET
                          - std::chrono::milliseconds(100));
    EXPECT_EQ(node.tracker().chain.size(), 0u);
    EXPECT_EQ(node.block_share_lock_forfeits(), 1u)
        << "an expired budget must be COUNTED, not dropped silently";
}

// 13. The acquisition primitive itself: Opportunistic is one try (today's
//     behaviour, bit-for-bit), BlockWinning waits, and the compute-thread guard
//     never waits — the #878/#881 deadlock hazard, closed at the source.
TEST(DashBlockWinningMint, AcquirePrimitiveContract)
{
    using namespace dash::tracker_acquire;
    std::shared_mutex mtx;

    {   // free mutex: both urgencies succeed immediately
        auto a = exclusive(mtx, Urgency::Opportunistic);
        EXPECT_TRUE(a.owns_lock());
    }
    {
        auto a = exclusive(mtx, Urgency::BlockWinning);
        EXPECT_TRUE(a.owns_lock());
    }

    {   // held mutex: Opportunistic gives up at once, BlockWinning waits it out
        ExclusiveTrackerHolder holder(mtx, std::chrono::milliseconds(250));
        {
            auto a = exclusive(mtx, Urgency::Opportunistic);
            EXPECT_FALSE(a.owns_lock());
        }
        {
            // Compute-thread guard: already owns the exclusive lock, so it must
            // NEVER wait here — waiting would be the #878/#881 self-deadlock.
            auto a = exclusive(mtx, Urgency::BlockWinning,
                               /*on_compute_thread=*/true);
            EXPECT_FALSE(a.owns_lock());
        }
        {
            auto a = exclusive(mtx, Urgency::BlockWinning);
            EXPECT_TRUE(a.owns_lock());
        }
    }

    {   // budget expiry returns a NON-OWNING lock, so callers decline exactly
        // as they do today rather than proceeding unlocked
        ExclusiveTrackerHolder holder(mtx, std::chrono::milliseconds(400));
        auto a = exclusive(mtx, Urgency::BlockWinning, /*on_compute_thread=*/false,
                           std::chrono::milliseconds(50));
        EXPECT_FALSE(a.owns_lock());
    }
}


// ── #950 standing remembered-set selector ──────────────────────────────────
// Canonical p2pool seeds a freshly-connected peer with its whole mining-tx set
// (p2p.py:269), bounded by max_remembered_txs_size (p2p.py:30) because a peer
// DISCONNECTS if an inbound remember_tx overflows that bound (p2p.py:488).
// c2pool emitted NO standing remember, so peers showed txpool == 0 (#950).
// dash::select_standing_remember is what send_standing_remember(peer) (node.cpp,
// wired into handle_version at node.hpp) uses to pick the seed. REAL uint256
// keys; tx bytes stand in as ints exactly as test_dash_known_txs_retention.cpp
// does — the production call binds the SAME template to coin::Transaction + the
// pack() byte-sizer. These pin the two properties the fix must hold and pre-#950
// code did not: a non-empty pool yields a non-empty seed (vs the empty standing
// set that caused txpool==0), and the seed never overshoots the peer cap (vs an
// unbounded seed that trips p2p.py:488). Selector+cap KAT on real types, NOT a
// live-socket capture — the wire proof is the hotel #879 remember_tx-out / peer
// remembered_txs_size read after merge.
namespace {
std::size_t as_bytes(int b) { return static_cast<std::size_t>(b); }
}

TEST(DashStandingRemember, PopulatedPoolYieldsNonEmptySeed)
{
    std::map<uint256, int> known;
    known[uint256(1)] = 500;
    known[uint256(2)] = 500;
    known[uint256(3)] = 500;
    auto chosen = dash::select_standing_remember(known, 2500000u, as_bytes);
    EXPECT_EQ(chosen.size(), 3u);
}

TEST(DashStandingRemember, StopsBeforeExceedingPeerCap)
{
    std::map<uint256, int> known;
    for (uint64_t i = 0; i < 10; ++i)
        known[uint256(i)] = 400;
    auto chosen = dash::select_standing_remember(known, 1000u, as_bytes);
    EXPECT_EQ(chosen.size(), 2u);
}

TEST(DashStandingRemember, EmptyPoolSeedsNothing)
{
    std::map<uint256, int> known;
    auto chosen = dash::select_standing_remember(known, 2500000u, as_bytes);
    EXPECT_TRUE(chosen.empty());
}
