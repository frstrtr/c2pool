// SPDX-License-Identifier: AGPL-3.0-or-later
//
// A SHAREREQ that finds think() holding the tracker waits for it briefly
// instead of being answered empty at once.
//
// THE incident (2026-11-13, LTC): a node whose think() held the tracker lock
// ~57-59 s of every minute answered nearly every SHAREREQ with zero shares
// ("SHAREREPLY returning 0 shares"): the serve path may only try_to_lock (the
// io thread must never block on it), and a busy lock meant an empty reply. A
// peer missing a share this node held never got it.
//
// Now a busy request is kept and retried on a timer every 100 ms — the io
// thread never blocks — for up to 2 s, then answered with what the last try
// got (empty only if the tracker was busy the whole time). Bounded: at most
// SHAREREQ_DEFERRED_MAX requests wait; past that a busy one is answered empty
// at once, as before. A request whose peer has gone is dropped.
//
// Pinned on a REAL ltc::NodeImpl and sharechain with a peer on a real loopback
// socket; "think()" is a thread holding the tracker mutex exclusively.
//
// New API: does not build on master.
//
// Folded into the existing allowlisted `share_test` target (the #769 trap).

#include <gtest/gtest.h>

#include <impl/ltc/node.hpp>
#include <impl/ltc/share.hpp>

#include <core/netaddress.hpp>
#include <core/socket.hpp>
#include <core/uint256.hpp>

#include <boost/asio.hpp>

#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <vector>

namespace {

using boost::asio::ip::tcp;
using namespace std::chrono_literals;

uint256 H(uint64_t n) { return uint256(n); }

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

struct SocketPair
{
    boost::asio::io_context ioc;
    std::unique_ptr<tcp::acceptor> acceptor;
    std::unique_ptr<tcp::socket> theirs;
    std::unique_ptr<tcp::socket> ours;

    SocketPair()
    {
        acceptor = std::make_unique<tcp::acceptor>(
            ioc, tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0));
        acceptor->listen();
        ours = std::make_unique<tcp::socket>(ioc);
        ours->connect(acceptor->local_endpoint());
        theirs = std::make_unique<tcp::socket>(acceptor->accept());
    }
};

struct ServeNode : public ltc::NodeImpl
{
    explicit ServeNode(boost::asio::io_context& ioc) : ltc::NodeImpl()
    {
        m_chain = &m_tracker.chain;
        m_context = &ioc;
    }
    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}

    using ltc::NodeImpl::m_peers;
    using ltc::NodeImpl::m_tracker;
    using ltc::NodeImpl::m_tracker_mutex;

    uint256 build_chain(uint64_t n)
    {
        for (uint64_t i = 1; i <= n; ++i)
            m_tracker.chain.add(new ltc::MergedMiningShare(H(i), i == 1 ? uint256::ZERO : H(i - 1)));
        return H(n);
    }

    peer_ptr attach_peer(SocketPair& pair, StubCommunicator& stub, uint64_t nonce)
    {
        auto sock = std::make_shared<core::Socket>(
            std::move(pair.ours), core::outgoing, &stub,
            std::weak_ptr<core::INetwork>{}, /*was_managed=*/false);
        sock->init();
        auto peer = std::make_shared<ltc::NodeImpl::peer_t>(sock);
        peer->m_other_version = ltc::PoolConfig::V3601_PROTOCOL_VERSION;
        peer->m_nonce = nonce;
        m_peers[nonce] = peer;
        return peer;
    }
};

// "think()": holds the tracker exclusively until release().
class Think
{
public:
    explicit Think(std::shared_mutex& mtx)
        : m_thread([this, &mtx] {
              std::unique_lock lock(mtx);
              m_held.set_value();
              m_release.get_future().wait();
          })
    {
        m_held.get_future().wait();
    }
    void release()
    {
        if (!m_released) {
            m_released = true;
            m_release.set_value();
            m_thread.join();
        }
    }
    ~Think() { release(); }

private:
    std::promise<void> m_held;
    std::promise<void> m_release;
    bool m_released{false};
    std::thread m_thread;
};

} // namespace

// Busy at the request, free 300 ms later: the request is answered from the
// tracker, with the shares asked for, and bytes reach the peer.
TEST(LtcSharereqBusyWait, ABusyRequestIsServedOnceTheTrackerIsFree)
{
    SocketPair pair;
    StubCommunicator stub;
    ServeNode node(pair.ioc);
    const uint256 tip = node.build_chain(3);
    auto peer = node.attach_peer(pair, stub, 0xa1);

    Think think(node.m_tracker_mutex);
    bool busy = false;
    auto shares = node.handle_get_share({tip}, 2, {}, peer->addr(), &busy);
    ASSERT_TRUE(busy);
    ASSERT_TRUE(shares.empty());
    ASSERT_TRUE(node.defer_sharereq(peer, H(0x1d), {tip}, 2, {}));

    pair.ioc.run_for(300ms);   // three retries, all busy
    EXPECT_EQ(node.m_sharereq_defer_stats.served_after_wait, 0u);
    EXPECT_EQ(node.m_deferred_sharereqs.size(), 1u) << "still waiting, not answered empty";
    EXPECT_EQ(pair.theirs->available(), 0u) << "nothing written while it waits";

    think.release();
    pair.ioc.run_for(300ms);
    EXPECT_EQ(node.m_sharereq_defer_stats.served_after_wait, 1u);
    EXPECT_EQ(node.m_sharereq_defer_stats.last_reply_shares, 3u) << "the tip and its 2 parents";
    EXPECT_TRUE(node.m_deferred_sharereqs.empty());
    EXPECT_GT(pair.theirs->available(), 0u) << "the sharereply reached the peer";
}

// Busy for longer than the budget: answered empty at the deadline, as before.
TEST(LtcSharereqBusyWait, StillBusyAtTheDeadlineIsAnsweredEmpty)
{
    SocketPair pair;
    StubCommunicator stub;
    ServeNode node(pair.ioc);
    node.m_sharereq_busy_budget = 250ms;
    const uint256 tip = node.build_chain(3);
    auto peer = node.attach_peer(pair, stub, 0xa1);

    Think think(node.m_tracker_mutex);
    ASSERT_TRUE(node.defer_sharereq(peer, H(0x1d), {tip}, 2, {}));
    pair.ioc.run_for(600ms);
    EXPECT_EQ(node.m_sharereq_defer_stats.empty_after_wait, 1u);
    EXPECT_EQ(node.m_sharereq_defer_stats.last_reply_shares, 0u);
    EXPECT_TRUE(node.m_deferred_sharereqs.empty());
    EXPECT_GT(pair.theirs->available(), 0u) << "an (empty) sharereply was sent";
}

// The peer disconnected while its request waited: dropped, nothing written.
TEST(LtcSharereqBusyWait, ARequestWhosePeerIsGoneIsDropped)
{
    SocketPair pair;
    StubCommunicator stub;
    ServeNode node(pair.ioc);
    const uint256 tip = node.build_chain(3);
    auto peer = node.attach_peer(pair, stub, 0xa1);

    Think think(node.m_tracker_mutex);
    ASSERT_TRUE(node.defer_sharereq(peer, H(0x1d), {tip}, 2, {}));
    node.m_peers.clear();
    think.release();
    pair.ioc.run_for(300ms);
    EXPECT_EQ(node.m_sharereq_defer_stats.peer_gone, 1u);
    EXPECT_EQ(node.m_sharereq_defer_stats.served_after_wait, 0u);
    EXPECT_TRUE(node.m_deferred_sharereqs.empty());
}

// The wait list is bounded: past SHAREREQ_DEFERRED_MAX a busy request is not
// kept (the handler answers it empty at once, as before).
TEST(LtcSharereqBusyWait, TheWaitListIsBounded)
{
    SocketPair pair;
    StubCommunicator stub;
    ServeNode node(pair.ioc);
    const uint256 tip = node.build_chain(1);
    auto peer = node.attach_peer(pair, stub, 0xa1);

    Think think(node.m_tracker_mutex);
    for (size_t i = 0; i < ltc::NodeImpl::SHAREREQ_DEFERRED_MAX; ++i)
        ASSERT_TRUE(node.defer_sharereq(peer, H(0x100 + i), {tip}, 0, {}));
    EXPECT_FALSE(node.defer_sharereq(peer, H(0x9999), {tip}, 0, {}));
    EXPECT_EQ(node.m_sharereq_defer_stats.not_deferred, 1u);
    EXPECT_EQ(node.m_deferred_sharereqs.size(), ltc::NodeImpl::SHAREREQ_DEFERRED_MAX);
}
