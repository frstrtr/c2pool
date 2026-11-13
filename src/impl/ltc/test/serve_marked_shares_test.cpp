// SPDX-License-Identifier: AGPL-3.0-or-later
//
// LTC getshares replies must be complete and contiguous, even for shares we
// pushed to a peer that dropped right after.
//
// dba0be63d added m_rejected_share_hashes. It was a never-expiring set of every
// hash pushed to a peer that disconnected within 10 s of the push, and
// handle_get_share / send_shares SKIPPED those hashes. readvertise_best_share()
// pushes the 5 head shares, mostly other miners' shares, to every peer on
// every best change. So any drop inside the window, overwhelmingly a plain
// "Connection timed out", punched permanent holes in our getshares replies:
// 725 main-chain shares, about 39%, on ltc.voidbind in about 7 h. Syncing
// peers then fail over (90 s retry each). Canonical handle_get_shares
// (p2pool-merged-v36 p2pool/node.py:141-152) skips nothing.
//
// These cases drive a REAL ltc::NodeImpl over a REAL sharechain. The push goes
// to a peer built on a real loopback TCP socket, through the real
// readvertise_best_share / broadcast_share -> send_shares path. The disconnect
// goes through the real error() / close_connection() paths, and the reply comes
// from the real handle_get_share. Only interfaces present on master are used,
// so this file builds against master and FAILS there:
//
//   TimedOutPeerAfterReadvertiseDoesNotPunchHoles     FAILS on master
//   AbortedPeerAfterOwnBroadcastStillServesTheShares  FAILS on master
//   OurOwnCloseAfterPushDoesNotPunchHoles             FAILS on master
//   EmptyHashListIsAnsweredEmpty                      pins the guard. On master
//       this is a division by zero (1000 / hashes.size()), which is UB. A
//       Release build happens to optimize the dead division away, so it is
//       not reliably red there.
//
// Folded into the EXISTING allowlisted share_test target (#769 trap).

#include <gtest/gtest.h>

#include <impl/ltc/node.hpp>
#include <impl/ltc/share.hpp>

#include <core/netaddress.hpp>
#include <core/socket.hpp>
#include <core/uint256.hpp>

#include <boost/asio.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace {

using boost::asio::ip::tcp;

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

// A real loopback TCP pair. `ours` is wrapped in the core::Socket the peer
// writes to. The io_context is never run here, so pushes queue and stay queued.
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

struct TestNode : public ltc::NodeImpl
{
    TestNode() : ltc::NodeImpl() { m_chain = &m_tracker.chain; }

    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}

    using ltc::NodeImpl::m_peers;
    using ltc::NodeImpl::m_tracker;

    // A v36 share (no new-tx list, so the F3 gate passes it). `from` empty
    // means locally minted; otherwise the share arrived from that peer.
    void add_share(const uint256& hash, const uint256& prev, const NetService* from)
    {
        auto* s = new ltc::MergedMiningShare(hash, prev);
        if (from)
            s->peer_addr = *from;
        m_tracker.chain.add(s);
    }

    // Chain H(1) <- H(2) <- ... <- H(n). Returns the tip.
    uint256 build_chain(uint64_t n, const NetService* from)
    {
        add_share(H(1), uint256::ZERO, from);
        for (uint64_t i = 2; i <= n; ++i)
            add_share(H(i), H(i - 1), from);
        return H(n);
    }

    // Register a 3601-capable peer on a real socket, as a finished handshake would.
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
};

// What a syncing peer gets back for "the chain ending at `tip`, `parents` deep".
std::vector<uint256> served(TestNode& node, const uint256& tip, uint64_t parents)
{
    auto shares = node.handle_get_share({tip}, parents, {}, NetService{"10.9.9.9", 9326});
    std::vector<uint256> out;
    for (auto& s : shares) {
        out.push_back(s.hash());
        s.destroy();   // handle_get_share hands back owned clones (#1130)
    }
    return out;
}

// H(n), H(n-1), ..., H(1): the complete, contiguous reply.
std::vector<uint256> expected_chain(uint64_t n)
{
    std::vector<uint256> out;
    for (uint64_t i = n; i >= 1; --i)
        out.push_back(H(i));
    return out;
}

const NetService kOtherMiner{"10.1.2.3", 9326};

TEST(LtcServeMarkedShares, TimedOutPeerAfterReadvertiseDoesNotPunchHoles)
{
    // The ltc.voidbind shape: the head is other miners' shares, a best change
    // re-pushes it to every peer, and one peer's link times out a moment later.
    SocketPair pair;
    StubCommunicator stub;
    TestNode node;
    const uint256 tip = node.build_chain(8, &kOtherMiner);
    const NetService peer = node.attach_peer(pair, stub, 0x1111);

    node.readvertise_best_share();                  // pushes H(8)..H(4)
    node.error("Connection timed out", peer);       // well inside 10 s

    EXPECT_EQ(served(node, tip, 7), expected_chain(8))
        << "a timeout says nothing about the shares. The reply must not skip "
           "the ones we happened to push to that peer";
}

TEST(LtcServeMarkedShares, AbortedPeerAfterOwnBroadcastStillServesTheShares)
{
    // Even the one case that may still hold our OWN shares off re-broadcast (a
    // peer abort right after the push) must never withhold them from a peer
    // that asks for them.
    SocketPair pair;
    StubCommunicator stub;
    TestNode node;
    const uint256 tip = node.build_chain(8, nullptr);   // locally minted
    const NetService peer = node.attach_peer(pair, stub, 0x2222);

    node.broadcast_share(tip);                          // pushes H(8)..H(4)
    ASSERT_EQ(node.broadcast_reached_send_count(), 1u);
    node.error("Connection reset by peer", peer);

    EXPECT_EQ(served(node, tip, 7), expected_chain(8))
        << "the hold-off is about RE-broadcast only, never about serving";
}

TEST(LtcServeMarkedShares, OurOwnCloseAfterPushDoesNotPunchHoles)
{
    // close_connection is only ever OUR decision (ban, duplicate swap, misfit
    // sender, admin drop). dba0be63d still branded what we had just pushed.
    SocketPair pair;
    StubCommunicator stub;
    TestNode node;
    const uint256 tip = node.build_chain(6, &kOtherMiner);
    const NetService peer = node.attach_peer(pair, stub, 0x3333);

    node.readvertise_best_share();                  // pushes H(6)..H(2)
    node.close_connection(peer);

    EXPECT_EQ(served(node, tip, 5), expected_chain(6));
}

TEST(LtcServeMarkedShares, EmptyHashListIsAnsweredEmpty)
{
    TestNode node;
    node.build_chain(2, &kOtherMiner);
    auto shares = node.handle_get_share({}, 5, {}, NetService{"10.9.9.9", 9326});
    EXPECT_TRUE(shares.empty());
    for (auto& s : shares) s.destroy();
}

} // namespace
