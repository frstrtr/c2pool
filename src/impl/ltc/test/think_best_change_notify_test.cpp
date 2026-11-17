// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The LTC think/clean cycles tell the miners about every best-share change,
// once (rides share_test).
//
// Driven on a REAL ltc::NodeImpl with its real compute thread (m_think_pool)
// and a test-owned io_context standing in for the io thread: run_think() and
// clean_tracker() post their compute phase to the compute thread, which posts
// the IO-phase epilogue to the io_context; the test runs that io_context until
// the pipeline is idle. The sharechain is a hand-built verified trunk, so the
// REAL ShareTracker::think() elects its tip.
//
//   - clean_tracker() runs think() twice. Step 1 set the best share silently
//     and Step 4 compared its own result against Step 1's, so a best share
//     Step 1 moved never reached m_on_best_share_changed: no work refresh,
//     miners kept the old prev_share_hash (stale work, the #854 class).
//     RED before: zero notifications for a moved tip.
//   - A run_think() that finds a cycle in flight was dropped. The flag stays
//     set after the compute thread released the tracker lock, until the
//     epilogue runs, so a share minted in that window (notify_local_share ->
//     run_think) was in the chain and never elected. Now the skipped request
//     is served by one think posted from the epilogue. RED before: the minted
//     share never became the best share, and a skipped think never ran.
//   - The think path: a best change made by run_think() is notified exactly
//     once, and a cycle that changes nothing notifies nothing (GREEN before
//     and after; it pins that the fixes add no spurious refresh).
//   - Peers learn a best share moved by a clean the way they learn one moved
//     by a think: the clean's IO phase re-pushes the head walk
//     (readvertise_best_share) to a connected peer, here a real loopback
//     socket. RED before: nothing reached the peer.
//
// Folded into the EXISTING allowlisted `share_test` target (the #769 trap).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <ctime>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <source_location>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio.hpp>
#include <boost/log/core.hpp>

#include <core/netaddress.hpp>
#include <core/socket.hpp>
#include <core/uint256.hpp>
#include <impl/ltc/config_pool.hpp>
#include <impl/ltc/node.hpp>
#include <impl/ltc/share.hpp>

namespace {

uint256 H(uint64_t n) { return uint256(0x100000 + n); }

constexpr uint32_t kBits      = 0x1e0fffff;   // uniform per-share work
constexpr uint32_t kBlockBits = 0x1b0fffff;   // the LTC block target (header bits)

struct QuietLog {
    bool was;
    QuietLog() : was(boost::log::core::get()->get_logging_enabled())
    {
        boost::log::core::get()->set_logging_enabled(false);
    }
    ~QuietLog() { boost::log::core::get()->set_logging_enabled(was); }
};

// The default ltc::NodeImpl ctor opens no LevelDB and starts no timers; the
// io_context is the test's, so the cycles' epilogues run when the test says.
struct ThinkNode : public ltc::NodeImpl
{
    explicit ThinkNode(boost::asio::io_context& ioc) : ltc::NodeImpl()
    {
        m_chain = &m_tracker.chain;
        m_context = &ioc;
    }

    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}

    using ltc::NodeImpl::m_tracker;
    using ltc::NodeImpl::m_best_share_hash;
    using ltc::NodeImpl::m_think_running;
    using ltc::NodeImpl::m_clean_running;
    using ltc::NodeImpl::m_think_generation;
    using ltc::NodeImpl::m_peers;

    /// A verified share on `prev` (the caller holds the tracker lock, or no
    /// cycle is running).
    void add_verified(const uint256& h, const uint256& prev)
    {
        const auto now = static_cast<uint32_t>(std::time(nullptr));
        auto* sh = new ltc::MergedMiningShare();
        sh->m_hash = h;
        sh->m_prev_hash = prev;
        sh->m_desired_version = 36;
        sh->m_bits = kBits;
        sh->m_max_bits = kBits;
        sh->m_timestamp = now;
        sh->m_min_header.m_bits = kBlockBits;
        sh->m_min_header.m_timestamp = now;
        ltc::ShareType st;
        st = sh;
        m_tracker.add(st);
        m_tracker.chain.get_index(h)->time_seen = now;
        m_tracker.verified.add(m_tracker.chain.get_share(h));
    }

    /// A rooted verified trunk H(1)..H(n); returns its tip.
    uint256 build_trunk(int n)
    {
        uint256 prev;
        for (int i = 1; i <= n; ++i) {
            add_verified(H(i), prev);
            prev = H(i);
        }
        return prev;
    }

    uint256 best_locked()
    {
        std::shared_lock<std::shared_mutex> lk(tracker_mutex());
        return m_best_share_hash;
    }
};

// Run the io_context until no cycle is in flight and nothing is left to run
// for a while: every compute phase has posted its epilogue, every epilogue
// ran, and every think an epilogue posted ran too.
::testing::AssertionResult settle(ThinkNode& node, boost::asio::io_context& ioc)
{
    using namespace std::chrono;
    const auto deadline = steady_clock::now() + seconds(60);
    int quiet = 0;
    while (steady_clock::now() < deadline) {
        ioc.restart();
        const std::size_t ran = ioc.poll();
        if (ran == 0 && !node.m_think_running.load() && !node.m_clean_running.load()) {
            if (++quiet >= 40)
                return ::testing::AssertionSuccess();
        } else {
            quiet = 0;
        }
        std::this_thread::sleep_for(milliseconds(5));
    }
    return ::testing::AssertionFailure() << "think/clean pipeline did not go idle in 60 s";
}

// Wait (bounded) until `pred` holds, without running the io_context.
template <typename Pred>
bool wait_for(Pred pred)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (!pred()) {
        if (std::chrono::steady_clock::now() > deadline)
            return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return true;
}

struct Fixture {
    boost::asio::io_context ioc;        // outlives the node (declared first)
    std::unique_ptr<ThinkNode> node = std::make_unique<ThinkNode>(ioc);
    std::atomic<int> notified{0};
    Fixture()
    {
        node->set_on_best_share_changed([this] { notified.fetch_add(1); });
    }
};

} // namespace

// ── clean_tracker: a best share moved by Step 1 is notified ────────────────

// The node's best share is H(11); H(12) has joined the chain on top of it and
// no think has elected it yet. The periodic clean's Step 1 think() elects
// H(12), Step 4 re-elects H(12). The miners must hear about H(12) once.
TEST(LtcThinkBestChangeNotify, CleanStep1MoveNotifiesOnce)
{
    QuietLog quiet;
    Fixture f;
    const uint256 tip = f.node->build_trunk(12);
    f.node->m_best_share_hash = H(11);

    f.node->clean_tracker();
    ASSERT_TRUE(settle(*f.node, f.ioc));

    EXPECT_EQ(f.node->best_locked(), tip) << "clean's think() elects the new tip";
    EXPECT_EQ(f.notified.load(), 1)
        << "a best share moved by clean_tracker Step 1 must fire m_on_best_share_changed "
           "exactly once (it fired 0 times: Step 4 compared against Step 1's own result)";

    // A clean that moves nothing notifies nothing.
    f.node->clean_tracker();
    ASSERT_TRUE(settle(*f.node, f.ioc));
    EXPECT_EQ(f.node->best_locked(), tip);
    EXPECT_EQ(f.notified.load(), 1) << "no change, no work refresh";
}

// The first election of a node (null -> tip) made by a clean is a change too.
TEST(LtcThinkBestChangeNotify, CleanFirstElectionNotifiesOnce)
{
    QuietLog quiet;
    Fixture f;
    const uint256 tip = f.node->build_trunk(10);

    f.node->clean_tracker();
    ASSERT_TRUE(settle(*f.node, f.ioc));

    EXPECT_EQ(f.node->best_locked(), tip);
    EXPECT_EQ(f.notified.load(), 1);
}

// A throwing work refresh in the clean epilogue must not leave the think slot
// held: the next run_think() still runs.
TEST(LtcThinkBestChangeNotify, CleanEpilogueThrowReleasesTheSlot)
{
    QuietLog quiet;
    Fixture f;
    std::atomic<int> threw{0};
    f.node->set_on_best_share_changed([&] {
        threw.fetch_add(1);
        throw std::runtime_error("work refresh failed");
    });
    f.node->build_trunk(10);

    f.node->clean_tracker();
    ASSERT_TRUE(settle(*f.node, f.ioc)) << "the slot stayed held after the epilogue threw";
    EXPECT_EQ(threw.load(), 1);
    EXPECT_FALSE(f.node->m_think_running.load());
    EXPECT_FALSE(f.node->m_clean_running.load());

    const auto gen = f.node->m_think_generation.load();
    f.node->run_think();
    ASSERT_TRUE(settle(*f.node, f.ioc));
    EXPECT_EQ(f.node->m_think_generation.load(), gen + 1) << "run_think() ran after the throw";
}

// ── the think path: one notification per change ─────────────────────────────

TEST(LtcThinkBestChangeNotify, RunThinkMoveNotifiesOnceAndNoChangeNotifiesNothing)
{
    QuietLog quiet;
    Fixture f;
    const uint256 tip = f.node->build_trunk(10);

    f.node->run_think();
    ASSERT_TRUE(settle(*f.node, f.ioc));
    EXPECT_EQ(f.node->best_locked(), tip);
    EXPECT_EQ(f.notified.load(), 1);

    f.node->run_think();
    ASSERT_TRUE(settle(*f.node, f.ioc));
    EXPECT_EQ(f.notified.load(), 1) << "an unchanged best share is not re-notified";

    // A new share on the tip, then a think: one more notification.
    {
        std::unique_lock<std::shared_mutex> lk(f.node->tracker_mutex());
        f.node->add_verified(H(11), tip);
    }
    f.node->run_think();
    ASSERT_TRUE(settle(*f.node, f.ioc));
    EXPECT_EQ(f.node->best_locked(), H(11));
    EXPECT_EQ(f.notified.load(), 2);
}

// ── a run_think() skipped while a cycle is in flight runs once afterwards ──

// Three requests land while the first cycle holds the slot: exactly one more
// think runs for all of them (think() is a full re-election), not zero, not
// three.
TEST(LtcThinkBestChangeNotify, SkippedRunThinkRunsExactlyOnceAfterTheCycle)
{
    QuietLog quiet;
    Fixture f;
    f.node->build_trunk(10);
    const auto gen0 = f.node->m_think_generation.load();

    f.node->run_think();                 // owns the slot until its epilogue runs
    ASSERT_TRUE(f.node->m_think_running.load());
    f.node->run_think();                 // skipped
    f.node->run_think();                 // skipped
    f.node->run_think();                 // skipped
    ASSERT_TRUE(settle(*f.node, f.ioc));

    EXPECT_EQ(f.node->m_think_generation.load(), gen0 + 2)
        << "the skipped run_think() requests must be served by exactly one more think "
           "(it was dropped: 1 cycle ran)";
    EXPECT_FALSE(f.node->m_think_running.load());

    // Nothing is owed any more: an idle node runs nothing on its own.
    ASSERT_TRUE(settle(*f.node, f.ioc));
    EXPECT_EQ(f.node->m_think_generation.load(), gen0 + 2);
}

// The production window: the compute thread has elected and released the
// tracker lock, the epilogue has not run yet, and a local share is minted on
// the new tip (notify_local_share -> run_think, skipped). The minted share
// must become the best share and the miners must hear about it.
TEST(LtcThinkBestChangeNotify, ShareMintedBetweenLockReleaseAndEpilogueIsElected)
{
    QuietLog quiet;
    Fixture f;
    const uint256 tip = f.node->build_trunk(10);
    std::atomic<int> decided{0};
    f.node->set_locked_best_hook([&](ltc::ShareTracker&, const uint256&) { decided.fetch_add(1); });

    f.node->run_think();
    ASSERT_TRUE(wait_for([&] { return decided.load() >= 1; })) << "cycle 1 never decided";
    {
        // Blocks until cycle 1's compute phase releases the lock; its
        // epilogue is then queued on the io_context, not run.
        std::unique_lock<std::shared_mutex> lk(f.node->tracker_mutex());
        f.node->add_verified(H(11), tip);
    }
    ASSERT_TRUE(f.node->m_think_running.load()) << "the epilogue must not have run yet";
    f.node->notify_local_share(H(11));   // the mint path's tail

    ASSERT_TRUE(settle(*f.node, f.ioc));
    EXPECT_EQ(f.node->best_locked(), H(11))
        << "the share minted in the window was never elected (its run_think was dropped)";
    EXPECT_EQ(f.notified.load(), 2) << "null -> H(10), then H(10) -> H(11)";
}

// A clean cycle holds the think slot too: a run_think() skipped during it is
// served when the clean releases.
TEST(LtcThinkBestChangeNotify, RunThinkSkippedDuringCleanRunsAfterIt)
{
    QuietLog quiet;
    Fixture f;
    const uint256 tip = f.node->build_trunk(10);
    std::atomic<int> decided{0};
    f.node->set_locked_best_hook([&](ltc::ShareTracker&, const uint256&) { decided.fetch_add(1); });

    f.node->clean_tracker();
    // Step 4's publish is the clean's last decision under the lock.
    ASSERT_TRUE(wait_for([&] { return decided.load() >= 2; })) << "clean never reached Step 4";
    {
        std::unique_lock<std::shared_mutex> lk(f.node->tracker_mutex());
        f.node->add_verified(H(11), tip);
    }
    ASSERT_TRUE(f.node->m_think_running.load());
    f.node->notify_local_share(H(11));

    ASSERT_TRUE(settle(*f.node, f.ioc));
    EXPECT_EQ(f.node->best_locked(), H(11));
    EXPECT_EQ(f.notified.load(), 2);
}

// ── a clean best change re-advertises the head, as a think's does ──────────

namespace {

using boost::asio::ip::tcp;

const std::vector<std::byte>& test_prefix()
{
    static const std::vector<std::byte> prefix{
        std::byte{0xfc}, std::byte{0xc1}, std::byte{0xb7}, std::byte{0xdc}};
    return prefix;
}

struct StubCommunicator : public core::ICommunicator
{
    void error(const message_error_type&, const NetService&,
               const std::source_location = std::source_location::current()) override {}
    void error(const boost::system::error_code&, const NetService&,
               const std::source_location = std::source_location::current()) override {}
    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}
    const std::vector<std::byte>& get_prefix() const override { return test_prefix(); }
};

// One connected peer on a real loopback socket (on the node's io_context);
// `theirs` is the far end, read to see what the node pushed.
struct PeerFixture {
    boost::asio::io_context ioc;
    StubCommunicator stub;
    std::unique_ptr<tcp::socket> theirs;
    std::unique_ptr<ThinkNode> node;      // destroyed first
    std::atomic<int> notified{0};

    PeerFixture()
    {
        tcp::acceptor acceptor(ioc, tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0));
        acceptor.listen();
        auto ours = std::make_unique<tcp::socket>(ioc);
        ours->connect(acceptor.local_endpoint());
        theirs = std::make_unique<tcp::socket>(acceptor.accept());
        theirs->non_blocking(true);

        node = std::make_unique<ThinkNode>(ioc);
        node->set_on_best_share_changed([this] { notified.fetch_add(1); });
        auto sock = std::make_shared<core::Socket>(
            std::move(ours), core::outgoing, &stub,
            std::weak_ptr<core::INetwork>{}, /*was_managed=*/false);
        sock->init();
        auto peer = std::make_shared<ltc::NodeImpl::peer_t>(sock);
        peer->m_other_version = ltc::PoolConfig::V3601_PROTOCOL_VERSION;
        peer->m_nonce = 0x5151;
        node->m_peers[0x5151] = peer;
    }

    // Everything the node wrote to the peer since the last call.
    std::string wire()
    {
        std::string out;
        char buf[65536];
        for (;;) {
            boost::system::error_code ec;
            const std::size_t n = theirs->read_some(boost::asio::buffer(buf), ec);
            if (ec || n == 0)
                break;
            out.append(buf, n);
        }
        return out;
    }
};

bool carries_shares(const std::string& wire) { return wire.find("shares") != std::string::npos; }

} // namespace

TEST(LtcThinkBestChangeNotify, CleanStep1MoveReadvertisesTheNewBest)
{
    QuietLog quiet;
    PeerFixture f;
    const uint256 tip = f.node->build_trunk(12);
    f.node->m_best_share_hash = H(11);

    f.node->clean_tracker();
    ASSERT_TRUE(settle(*f.node, f.ioc));
    EXPECT_EQ(f.node->best_locked(), tip);
    EXPECT_EQ(f.notified.load(), 1);
    EXPECT_TRUE(carries_shares(f.wire()))
        << "a best share moved by clean_tracker must be re-advertised to the peers, "
           "as run_think's IO phase does (nothing reached the peer)";

    // No change, no re-advertisement.
    f.node->clean_tracker();
    ASSERT_TRUE(settle(*f.node, f.ioc));
    EXPECT_EQ(f.notified.load(), 1);
    EXPECT_EQ(f.wire(), std::string());
}

// The think path it mirrors (GREEN before and after).
TEST(LtcThinkBestChangeNotify, RunThinkMoveReadvertisesTheNewBest)
{
    QuietLog quiet;
    PeerFixture f;
    const uint256 tip = f.node->build_trunk(12);
    f.node->m_best_share_hash = H(11);

    f.node->run_think();
    ASSERT_TRUE(settle(*f.node, f.ioc));
    EXPECT_EQ(f.node->best_locked(), tip);
    EXPECT_EQ(f.notified.load(), 1);
    EXPECT_TRUE(carries_shares(f.wire()));
}
