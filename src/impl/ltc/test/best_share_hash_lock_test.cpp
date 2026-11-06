// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// NodeImpl::best_share_hash() keeps the tracker's reader discipline (rides
// share_test).
//
// It elects the best share from m_best_share_hash and the verified chain
// (verified.contains, verified.get_heads / get_index), which the compute
// thread writes under the EXCLUSIVE tracker lock (think: verified.add,
// m_best_share_hash; clean_tracker: chain.remove). Its callers are the
// merged-mining RPC thread (the payout provider, the stack of the
// 2026-11-06 LTC+DOGE canary crash), the IO thread (work refresh,
// re-advertisement, the monitor) and the HTTP thread; it read all of that
// with no lock. Now: the compute thread reads directly (it holds the lock),
// any other thread under a shared try-lock, and while the lock is busy it
// gets the last VERIFIED best share published under the lock (never a read
// of the tracker). A caller already holding the lock passes its guard.
//   - while another thread holds the lock exclusively and moves the best
//     share, best_share_hash() returns the published one (RED before: it
//     read the half-updated tracker and returned the new one);
//   - a failed guard gets the published value; a held guard elects under it;
//   - readers on three threads against a compute thread adding verified
//     shares and moving the best share only ever see null or a share that was
//     a verified head, and end on the compute thread's last best share.
//     ThreadSanitizer-clean (RED before: the unlocked verified / best reads).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <set>
#include <shared_mutex>
#include <thread>
#include <vector>

#include <boost/log/core.hpp>

#include <core/uint256.hpp>
#include <impl/ltc/node.hpp>
#include <impl/ltc/share.hpp>

namespace {

uint256 H(uint64_t n) { return uint256(n); }

struct BestNode : public ltc::NodeImpl
{
    BestNode() : ltc::NodeImpl() { m_chain = &m_tracker.chain; }

    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}

    using ltc::NodeImpl::m_tracker;
    using ltc::NodeImpl::m_best_share_hash;
    using ltc::NodeImpl::publish_snapshot;

    /// A share on `prev`, in the raw chain and (optionally) verified.
    void add(const uint256& hash, const uint256& prev, bool verified = true)
    {
        auto* s = new ltc::MergedMiningShare(hash, prev);
        m_tracker.chain.add(s);
        if (verified)
            m_tracker.verified.add(m_tracker.chain.get_share(hash));
    }

    /// run_think's compute thread: this thread holds the lock exclusively.
    void become_compute_thread() { m_compute_thread_id.store(std::this_thread::get_id()); }
};

struct QuietLog {
    bool was;
    QuietLog() : was(boost::log::core::get()->get_logging_enabled())
    {
        boost::log::core::get()->set_logging_enabled(false);
    }
    ~QuietLog() { boost::log::core::get()->set_logging_enabled(was); }
};

} // namespace

// While another thread holds the tracker lock exclusively and changes the
// best share, a reader gets the best share published under the lock, not a
// read of the tracker mid-update.
TEST(LtcBestShareHash, BusyLockServesThePublishedBestNotTheTracker)
{
    QuietLog quiet;
    BestNode node;
    for (uint64_t i = 1; i <= 20; ++i)
        node.add(H(i), i == 1 ? uint256() : H(i - 1));
    node.m_best_share_hash = H(20);
    ASSERT_EQ(node.best_share_hash(), H(20)) << "lock free: elected under the shared lock";

    std::atomic<bool> holding{false}, release{false};
    std::thread compute([&] {
        std::unique_lock<std::shared_mutex> lk(node.tracker_mutex());
        node.add(H(21), H(20));
        node.m_best_share_hash = H(21);   // think() moved the best share
        holding = true;
        while (!release.load())
            std::this_thread::yield();
    });
    while (!holding.load())
        std::this_thread::yield();

    EXPECT_EQ(node.best_share_hash(), H(20))
        << "read the tracker while the compute thread held it exclusively";
    {
        auto guard = node.read_tracker();
        EXPECT_FALSE(guard);
        EXPECT_EQ(node.best_share_hash(guard), H(20)) << "a failed guard must not read the tracker";
    }
    release = true;
    compute.join();

    EXPECT_EQ(node.best_share_hash(), H(21)) << "lock free again: the new best share";
    {
        auto guard = node.read_tracker();
        ASSERT_TRUE(guard);
        EXPECT_EQ(node.best_share_hash(guard), H(21)) << "elected under the caller's own guard";
    }
}

// Before any verified best share was published, a busy lock gives ZERO (no
// work on an unknown head), never the raw chain.
TEST(LtcBestShareHash, NothingPublishedYetGivesZeroWhileBusy)
{
    QuietLog quiet;
    BestNode node;
    node.add(H(1), uint256(), /*verified=*/false);
    std::atomic<bool> holding{false}, release{false};
    std::thread compute([&] {
        std::unique_lock<std::shared_mutex> lk(node.tracker_mutex());
        holding = true;
        while (!release.load())
            std::this_thread::yield();
    });
    while (!holding.load())
        std::this_thread::yield();
    EXPECT_EQ(node.best_share_hash(), uint256::ZERO);
    release = true;
    compute.join();
    EXPECT_EQ(node.best_share_hash(), H(1)) << "genesis, no peers: the raw head, under the lock";
}

// Three reader threads (the merged-mining RPC thread, the IO thread, the HTTP
// thread) against the compute thread adding verified shares and moving the
// best share, sometimes onto a share not verified yet (the fallback walks the
// verified heads).
TEST(LtcBestShareHash, ReadersAgainstTheComputeThread)
{
    QuietLog quiet;
    BestNode node;
    constexpr uint64_t kInitial = 50, kRounds = 300;
    for (uint64_t i = 1; i <= kInitial; ++i)
        node.add(H(i), i == 1 ? uint256() : H(i - 1));
    node.m_best_share_hash = H(kInitial);

    // Every share that is ever verified (read-only once the threads run).
    std::set<uint256> ever_verified;
    for (uint64_t i = 1; i <= kInitial + kRounds; ++i)
        ever_verified.insert(H(i));

    std::atomic<bool> done{false};
    std::atomic<bool> writer_waiting{false};
    std::thread compute([&] {
        node.become_compute_thread();
        for (uint64_t r = 1; r <= kRounds; ++r) {
            writer_waiting = true;
            std::unique_lock<std::shared_mutex> lk(node.tracker_mutex());
            writer_waiting = false;
            const uint64_t h = kInitial + r;
            // Every 3rd share reaches the raw chain one round before it is
            // verified, and think() picks it at once (best not verified yet).
            node.add(H(h), H(h - 1), /*verified=*/false);
            node.m_best_share_hash = H(h);
            if (r % 3 == 1 && r > 1)   // last round's share, parent first
                node.m_tracker.verified.add(node.m_tracker.chain.get_share(H(h - 1)));
            if (r % 3 != 0)
                node.m_tracker.verified.add(node.m_tracker.chain.get_share(H(h)));
            node.publish_snapshot();
            (void)node.best_share_hash();   // the compute thread reads directly
            lk.unlock();
            std::this_thread::yield();
        }
        // Verify whatever is left so the end state is fully verified.
        std::unique_lock<std::shared_mutex> lk(node.tracker_mutex());
        for (uint64_t i = kInitial + 1; i <= kInitial + kRounds; ++i)
            if (!node.m_tracker.verified.contains(H(i)))
                node.m_tracker.verified.add(node.m_tracker.chain.get_share(H(i)));
        node.publish_snapshot();
        lk.unlock();
        done = true;
    });

    std::atomic<int> bad{0}, nonnull{0}, calls{0};
    auto reader = [&](bool with_guard) {
        while (!done.load()) {
            if (writer_waiting.load()) {
                std::this_thread::yield();
                continue;
            }
            uint256 b;
            if (with_guard) {
                auto guard = node.read_tracker();
                b = node.best_share_hash(guard);
            } else {
                b = node.best_share_hash();
            }
            ++calls;
            if (!b.IsNull()) {
                ++nonnull;
                if (!ever_verified.contains(b))
                    ++bad;
            }
        }
    };
    std::thread rpc(reader, false), io(reader, false), http(reader, true);
    compute.join();
    rpc.join();
    io.join();
    http.join();

    EXPECT_EQ(bad.load(), 0) << "a best share that was never a verified head";
    EXPECT_GT(nonnull.load(), 0);
    EXPECT_GT(calls.load(), 0);
    EXPECT_EQ(node.best_share_hash(), H(kInitial + kRounds));
}
