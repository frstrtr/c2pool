// SPDX-License-Identifier: AGPL-3.0-or-later
//
// What is left of dba0be63d's "rejected share" mark, pinned.
//
// The mark exists to stop a reconnect loop. Canonical p2pool drops a peer that
// sends it a bad share (PeerMisbehavingError -> badPeerHappened ->
// abortConnection, a TCP RST), and c2pool used to keep re-pushing the same bad
// share of its own. What it may do now (own_share_reject_marks.hpp):
//   * hold off RE-broadcast of OUR OWN shares, and no others,
//   * only after a peer ABORT within 10 s of the push (timeout, EOF and our
//     own close do not count),
//   * for 10 min, after which the share is re-broadcast normally.
// Serving is never affected (serve_marked_shares_test.cpp).
//
// The NodeImpl cases drive a REAL ltc::NodeImpl, a REAL sharechain and a peer
// on a real loopback socket. The only seam is the hold-off clock
// (reject_mark_now), which the test steps. The policy cases drive the pure
// header that node.cpp wires in.
//
// The TTL cases FAIL on master by construction: master's mark never expires,
// and master has no clock seam, so this file does not even build there.
//
// Deliberately NOT guarded any more: the serve path. A marked own share is
// still advertised in the version message and served on sharereq
// (AbortedOwnBestIsStillAdvertisedAndServed pins that decision; see
// own_share_reject_marks.hpp for why it is bounded).
//
// Folded into the EXISTING allowlisted share_test target (#769 trap).

#include <gtest/gtest.h>

#include <impl/ltc/node.hpp>
#include <impl/ltc/own_share_reject_marks.hpp>
#include <impl/ltc/share.hpp>

#include <core/netaddress.hpp>
#include <core/socket.hpp>
#include <core/uint256.hpp>

#include <boost/asio.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace {

using boost::asio::ip::tcp;
using namespace std::chrono_literals;
using Marks = ltc::OwnShareRejectMarks<uint256, NetService>;

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

struct ClockedNode : public ltc::NodeImpl
{
    ClockedNode() : ltc::NodeImpl() { m_chain = &m_tracker.chain; }

    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}

    using ltc::NodeImpl::m_own_share_rejects;
    using ltc::NodeImpl::m_peers;
    using ltc::NodeImpl::m_shared_share_hashes;
    using ltc::NodeImpl::m_tracker;

    // The hold-off clock, stepped by the test.
    std::chrono::steady_clock::time_point clock_now = std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point reject_mark_now() const override { return clock_now; }

    uint256 build_chain(uint64_t n, const NetService* from)
    {
        for (uint64_t i = 1; i <= n; ++i) {
            auto* s = new ltc::MergedMiningShare(H(i), i == 1 ? uint256::ZERO : H(i - 1));
            if (from)
                s->peer_addr = *from;   // arrived from that peer, not ours
            m_tracker.chain.add(s);
        }
        return H(n);
    }

    NetService attach_peer(SocketPair& pair, StubCommunicator& stub, uint64_t nonce)
    {
        auto sock = std::make_shared<core::Socket>(
            std::move(pair.ours), core::outgoing, &stub,
            std::weak_ptr<core::INetwork>{}, /*was_managed=*/false);
        sock->init();
        auto peer = std::make_shared<ltc::NodeImpl::peer_t>(sock);
        peer->m_other_version = ltc::PoolConfig::V3601_PROTOCOL_VERSION;
        peer->m_nonce = nonce;
        m_peers[nonce] = peer;
        return peer->addr();
    }

    // Would broadcast_share put anything of the chain at `tip` on the wire
    // now? The de-dup set is cleared first so only the hold-off decides. The
    // send-loop counter moves only when the walk produced a non-empty batch.
    bool would_rebroadcast(const uint256& tip)
    {
        m_shared_share_hashes.clear();
        const auto before = broadcast_reached_send_count();
        broadcast_share(tip);
        return broadcast_reached_send_count() == before + 1;
    }
};

size_t served_count(ClockedNode& node, const uint256& tip, uint64_t parents)
{
    auto shares = node.handle_get_share({tip}, parents, {}, NetService{"10.9.9.9", 9326});
    const size_t n = shares.size();
    for (auto& s : shares) s.destroy();
    return n;
}

const NetService kOtherMiner{"10.1.2.3", 9326};

// ---- NodeImpl ---------------------------------------------------------------

TEST(LtcOwnShareRejectMarks, OwnShareAbortedOnIsHeldOffForTheTtlThenRebroadcast)
{
    SocketPair pair;
    StubCommunicator stub;
    ClockedNode node;
    const uint256 tip = node.build_chain(3, nullptr);   // all locally minted
    const NetService peer = node.attach_peer(pair, stub, 0xa1);

    node.broadcast_share(tip);                            // pushes H(3)..H(1)
    ASSERT_EQ(node.broadcast_reached_send_count(), 1u);

    node.clock_now += 2s;
    node.error("Connection reset by peer", peer);         // the canonical bad-share abort
    ASSERT_EQ(node.m_own_share_rejects.marked_count(), 3u);

    node.clock_now += Marks::MARK_TTL - 1s;  // still inside the TTL
    EXPECT_FALSE(node.would_rebroadcast(tip))
        << "our own share a peer aborted on is not re-pushed within the TTL";
    EXPECT_EQ(served_count(node, tip, 2), 3u)
        << "...but it is still served to anyone who asks for it";

    node.clock_now += 2s;  // past the TTL
    EXPECT_TRUE(node.would_rebroadcast(tip))
        << "the hold-off expires: dba0be63d's mark never did";
}

TEST(LtcOwnShareRejectMarks, ReadvertiseHonoursTheHoldOffThenResumes)
{
    // readvertise_best_share is the real re-push vector: it bypasses the
    // broadcast de-dup set and fires on every best change. It must skip our
    // held-off own shares, and push them again once the TTL is over.
    SocketPair p1, p2;
    StubCommunicator stub;
    ClockedNode node;
    const uint256 tip = node.build_chain(3, nullptr);
    const NetService a = node.attach_peer(p1, stub, 0xc1);

    node.broadcast_share(tip);
    node.clock_now += 1s;
    node.error("Connection reset by peer", a);
    ASSERT_EQ(node.m_own_share_rejects.marked_count(), 3u);

    node.attach_peer(p2, stub, 0xc2);
    node.readvertise_best_share();
    EXPECT_EQ(node.m_own_share_rejects.pending_push_count(), 0u)
        << "held-off own shares are not re-pushed to the next peer";

    node.clock_now += Marks::MARK_TTL + 1s;
    node.readvertise_best_share();
    EXPECT_EQ(node.m_own_share_rejects.pending_push_count(), 1u)
        << "after the TTL the head is re-pushed (and recorded) again";
}

TEST(LtcOwnShareRejectMarks, AbortedOwnBestIsStillAdvertisedAndServed)
{
    // The decision this change makes on purpose: dba0be63d's loop ran through
    // version best_share_hash -> sharereq -> serve. We keep advertising and
    // serving the share, as p2pool does; the hold-off covers re-pushes only.
    SocketPair p1;
    StubCommunicator stub;
    ClockedNode node;
    const uint256 tip = node.build_chain(1, nullptr);
    const NetService a = node.attach_peer(p1, stub, 0xd1);

    node.broadcast_share(tip);
    node.clock_now += 1s;
    node.error("Connection reset by peer", a);
    ASSERT_EQ(node.m_own_share_rejects.marked_count(), 1u);

    EXPECT_EQ(node.advertised_best_share(), tip);
    EXPECT_EQ(served_count(node, tip, 0), 1u) << "served on the reconnect's sharereq";
}

TEST(LtcOwnShareRejectMarks, OwnSharesReloadedFromLevelDbAreNeverMarked)
{
    // load_persisted_shares tags every reloaded share with peer_addr
    // "database", so after a restart our own older shares are not "local".
    SocketPair p1;
    StubCommunicator stub;
    ClockedNode node;
    const NetService db{"database", 0};
    node.build_chain(3, &db);
    const NetService a = node.attach_peer(p1, stub, 0xe1);

    node.readvertise_best_share();
    node.clock_now += 1s;
    node.error("Connection reset by peer", a);
    EXPECT_EQ(node.m_own_share_rejects.marked_count(), 0u);
}

TEST(LtcOwnShareRejectMarks, ErrorCodePathClassifiesOnTheCode)
{
    // Socket read errors reach NodeImpl as an error_code. A reset is an abort
    // whatever the (possibly localized) text says; EOF and timeouts are not.
    struct Case { boost::system::error_code ec; size_t marked; };
    const Case cases[] = {
        {boost::asio::error::connection_reset, 3u},
        {boost::asio::error::eof, 0u},
        {boost::asio::error::timed_out, 0u},
        {boost::asio::error::operation_aborted, 0u},
    };
    for (const auto& c : cases) {
        SocketPair pair;
        StubCommunicator stub;
        ClockedNode node;
        const uint256 tip = node.build_chain(3, nullptr);
        const NetService peer = node.attach_peer(pair, stub, 0xf1);

        node.broadcast_share(tip);
        node.clock_now += 1s;
        static_cast<core::ICommunicator&>(node).error(c.ec, peer);   // the socket's call
        EXPECT_EQ(node.m_own_share_rejects.marked_count(), c.marked) << c.ec.message();
        EXPECT_EQ(node.m_own_share_rejects.pending_push_count(), 0u) << c.ec.message();
    }
}

TEST(LtcOwnShareRejectMarks, ReceivedSharesAreNeverHeldOff)
{
    SocketPair pair;
    StubCommunicator stub;
    ClockedNode node;
    const uint256 tip = node.build_chain(3, &kOtherMiner);
    const NetService peer = node.attach_peer(pair, stub, 0xa2);

    node.readvertise_best_share();                        // pushes other miners' head
    node.clock_now += 1s;
    node.error("Connection reset by peer", peer);

    EXPECT_EQ(node.m_own_share_rejects.marked_count(), 0u);
    EXPECT_TRUE(node.would_rebroadcast(tip));
}

TEST(LtcOwnShareRejectMarks, TimeoutEofAndOurOwnTimeoutAreNotRejections)
{
    for (const char* reason : {"Connection timed out", "EOF, socket disconnected", "peer timeout!",
                               "Socket::write error: Broken pipe"}) {
        SocketPair pair;
        StubCommunicator stub;
        ClockedNode node;
        const uint256 tip = node.build_chain(3, nullptr);
        const NetService peer = node.attach_peer(pair, stub, 0xa3);

        node.broadcast_share(tip);
        node.clock_now += 1s;
        node.error(reason, peer);

        EXPECT_EQ(node.m_own_share_rejects.marked_count(), 0u) << reason;
        EXPECT_TRUE(node.would_rebroadcast(tip)) << reason;
    }
}

TEST(LtcOwnShareRejectMarks, OurOwnCloseIsNotARejection)
{
    SocketPair pair;
    StubCommunicator stub;
    ClockedNode node;
    const uint256 tip = node.build_chain(3, nullptr);
    const NetService peer = node.attach_peer(pair, stub, 0xa4);

    node.broadcast_share(tip);
    node.clock_now += 1s;
    node.close_connection(peer);

    EXPECT_EQ(node.m_own_share_rejects.marked_count(), 0u);
    EXPECT_EQ(node.m_own_share_rejects.pending_push_count(), 0u);
    EXPECT_TRUE(node.would_rebroadcast(tip));
}

TEST(LtcOwnShareRejectMarks, AbortOutsideTheWindowIsNotARejection)
{
    SocketPair pair;
    StubCommunicator stub;
    ClockedNode node;
    const uint256 tip = node.build_chain(3, nullptr);
    const NetService peer = node.attach_peer(pair, stub, 0xa5);

    node.broadcast_share(tip);
    node.clock_now += Marks::REJECT_WINDOW;
    node.error("Connection reset by peer", peer);

    EXPECT_EQ(node.m_own_share_rejects.marked_count(), 0u);
    EXPECT_TRUE(node.would_rebroadcast(tip));
}

// ---- pure policy ------------------------------------------------------------

TEST(LtcOwnShareRejectMarksPolicy, OnlyAPeerAbortCountsAsARejection)
{
    EXPECT_TRUE(ltc::disconnect_is_peer_abort(
        boost::system::error_code(boost::asio::error::connection_reset)));
    EXPECT_FALSE(ltc::disconnect_is_peer_abort(boost::system::error_code(boost::asio::error::eof)));
    EXPECT_FALSE(ltc::disconnect_is_peer_abort(boost::system::error_code(boost::asio::error::timed_out)));
    EXPECT_FALSE(ltc::disconnect_is_peer_abort(boost::system::error_code(boost::asio::error::broken_pipe)));
    EXPECT_FALSE(ltc::disconnect_is_peer_abort(boost::system::error_code()));

    EXPECT_TRUE(ltc::disconnect_is_peer_abort("Connection reset by peer"));
    EXPECT_TRUE(ltc::disconnect_is_peer_abort("Socket::write error: Connection reset by peer"));
    EXPECT_TRUE(ltc::disconnect_is_peer_abort(
        "An existing connection was forcibly closed by the remote host."));

    EXPECT_FALSE(ltc::disconnect_is_peer_abort("Connection timed out"));
    EXPECT_FALSE(ltc::disconnect_is_peer_abort("EOF, socket disconnected"));
    EXPECT_FALSE(ltc::disconnect_is_peer_abort("peer timeout!"));
    EXPECT_FALSE(ltc::disconnect_is_peer_abort("Socket::write error: Broken pipe"));
    EXPECT_FALSE(ltc::disconnect_is_peer_abort("prefix doesn't match"));
    EXPECT_FALSE(ltc::disconnect_is_peer_abort(""));
}

TEST(LtcOwnShareRejectMarksPolicy, LatestPushWinsAndAnEmptyPushClearsTheRecord)
{
    Marks m;
    const NetService p{"10.0.0.1", 9326};
    const auto t0 = std::chrono::steady_clock::now();

    m.note_push(p, {H(1)}, t0);
    m.note_push(p, {}, t0 + 1s);            // a push with none of our shares
    auto out = m.on_disconnect(p, "Connection reset by peer", t0 + 2s);
    EXPECT_EQ(out.verdict, Marks::Verdict::NoRecentPush);
    EXPECT_FALSE(m.suppressed(H(1), t0 + 2s));

    m.note_push(p, {H(1)}, t0);
    m.note_push(p, {H(2)}, t0 + 1s);
    out = m.on_disconnect(p, "Connection reset by peer", t0 + 2s);
    EXPECT_EQ(out.verdict, Marks::Verdict::Marked);
    EXPECT_EQ(out.newly_marked, std::vector<uint256>{H(2)});
    EXPECT_FALSE(m.suppressed(H(1), t0 + 2s));
    EXPECT_TRUE(m.suppressed(H(2), t0 + 2s));
    EXPECT_EQ(m.pending_push_count(), 0u) << "a disconnect consumes the record";
}

TEST(LtcOwnShareRejectMarksPolicy, PruneDropsExpiredMarksAndStalePushes)
{
    Marks m;
    const NetService a{"10.0.0.1", 9326}, b{"10.0.0.2", 9326};
    const auto t0 = std::chrono::steady_clock::now();

    m.note_push(a, {H(1)}, t0);
    m.on_disconnect(a, "Connection reset by peer", t0 + 1s);
    m.note_push(b, {H(2)}, t0 + 1s);
    ASSERT_EQ(m.marked_count(), 1u);
    ASSERT_EQ(m.pending_push_count(), 1u);

    m.prune(t0 + 1s + Marks::REJECT_WINDOW);
    EXPECT_EQ(m.pending_push_count(), 0u);
    EXPECT_EQ(m.marked_count(), 1u);

    m.prune(t0 + 1s + Marks::MARK_TTL);
    EXPECT_EQ(m.marked_count(), 0u);
}

TEST(LtcOwnShareRejectMarksPolicy, LiveMarksAreBounded)
{
    Marks m;
    const NetService p{"10.0.0.1", 9326};
    auto t = std::chrono::steady_clock::now();
    for (uint64_t i = 1; i <= Marks::MAX_MARKS + 50; ++i) {
        m.note_push(p, {H(i)}, t);
        m.on_disconnect(p, "Connection reset by peer", t);
        t += 1ms;
    }
    EXPECT_EQ(m.marked_count(), Marks::MAX_MARKS);
    EXPECT_FALSE(m.suppressed(H(1), t)) << "the earliest-expiring mark is evicted first";
    EXPECT_TRUE(m.suppressed(H(Marks::MAX_MARKS + 50), t));
}

} // namespace
