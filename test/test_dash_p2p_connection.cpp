// SPDX-License-Identifier: AGPL-3.0-or-later
/// Phase S8 — Dash coin-daemon P2P connection KATs
///
/// Exercises src/impl/dash/coin/p2p_connection.hpp — the per-peer
/// request/response router the S8 block-submission lane
/// (p2p_messages -> [p2p_connection] -> p2p_node -> broadcaster) builds on.
///
/// What is PINNED here (all socket-free; the live dashd-socket exchange is the
/// p2p_node integration leaf, NOT claimed):
///
///   - request_block emits the request through the wire-callback carrying the
///     EXACT hash asked for (the outbound half reaches the "wire").
///   - get_block(id, response) routes the reply to the matching request handler
///     and delivers the EXACT BlockType bytes (version/nonce/merkle preserved).
///   - request_header / get_header: same contract on the header matcher.
///   - id routing is key-SENSITIVE: a reply for an id that was never requested
///     is REJECTED (throws), proving the matcher pairs by id and does not fire
///     handlers blindly.
///   - two concurrent in-flight requests are each delivered their own reply,
///     not cross-wired.
///
/// SCOPE NOTE (honest): these drive Connection with a NULL socket — the
/// request/reply matcher logic is fully real, but write()/get_addr() on a live
/// boost::asio socket and the timeout-timer path are integration concerns
/// covered by the p2p_node leaf, not asserted here.

#include <gtest/gtest.h>

#include <impl/dash/coin/p2p_connection.hpp>
#include <impl/dash/coin/block.hpp>

#include <core/uint256.hpp>

#include <boost/asio.hpp>

#include <cstdint>

using namespace dash::coin;
using dash::coin::p2p::Connection;

namespace {

uint256 id_of(uint8_t b) { uint256 u; u.begin()[0] = b; return u; }

BlockType make_block(uint64_t version, uint32_t nonce, uint8_t merkle_tag)
{
    BlockType blk;
    blk.m_version = version;
    blk.m_nonce = nonce;
    blk.m_merkle_root = id_of(merkle_tag);
    return blk;
}

} // namespace

// request_block sends the request carrying the exact hash, and the reply is
// routed back to that request handler with byte-exact contents.
TEST(DashP2PConnection, BlockRequestEmitsHashAndReplyRoundtrips)
{
    boost::asio::io_context ctx;
    Connection conn(&ctx, nullptr);

    uint256 emitted_hash;
    int req_calls = 0;
    conn.init_requests(
        [&](uint256 h) { emitted_hash = h; ++req_calls; },   // block_req
        [&](uint256)   {});                                  // header_req

    const uint256 want_id   = id_of(0x11);
    const uint256 want_hash = id_of(0xAB);

    int handler_calls = 0;
    BlockType got;
    conn.request_block(want_id, want_hash, [&](BlockType b) { got = b; ++handler_calls; });

    // outbound half: the request reached the wire-callback with the exact hash.
    EXPECT_EQ(req_calls, 1);
    EXPECT_EQ(emitted_hash, want_hash);
    EXPECT_EQ(handler_calls, 0);   // not yet — reply has not arrived.

    // inbound half: the reply is delivered byte-exact to the matching handler.
    BlockType reply = make_block(/*version*/0xDEAD, /*nonce*/0xC0FFEE, /*merkle*/0x42);
    conn.get_block(want_id, reply);

    EXPECT_EQ(handler_calls, 1);
    EXPECT_EQ(got.m_version, 0xDEADu);
    EXPECT_EQ(got.m_nonce, 0xC0FFEEu);
    EXPECT_EQ(got.m_merkle_root, id_of(0x42));
}

// header matcher carries the same contract, on BlockHeaderType.
TEST(DashP2PConnection, HeaderRequestRoundtrips)
{
    boost::asio::io_context ctx;
    Connection conn(&ctx, nullptr);

    uint256 emitted_hash;
    conn.init_requests([&](uint256) {}, [&](uint256 h) { emitted_hash = h; });

    const uint256 id   = id_of(0x07);
    const uint256 hash = id_of(0x77);

    int handler_calls = 0;
    BlockHeaderType got;
    conn.request_header(id, hash, [&](BlockHeaderType h) { got = h; ++handler_calls; });
    EXPECT_EQ(emitted_hash, hash);

    BlockHeaderType reply;
    reply.m_version = 0xBEEF;
    reply.m_bits = 0x1d00ffff;
    conn.get_header(id, reply);

    EXPECT_EQ(handler_calls, 1);
    EXPECT_EQ(got.m_version, 0xBEEFu);
    EXPECT_EQ(got.m_bits, 0x1d00ffffu);
}

// A reply for an id that was never requested is REJECTED — proving the matcher
// pairs by id and does not fire blindly. (gate-b: routing is key-sensitive.)
TEST(DashP2PConnection, UnknownIdReplyIsRejected)
{
    boost::asio::io_context ctx;
    Connection conn(&ctx, nullptr);
    conn.init_requests([&](uint256) {}, [&](uint256) {});

    EXPECT_THROW(conn.get_block(id_of(0x99), make_block(1, 1, 1)), std::invalid_argument);
    EXPECT_THROW(conn.get_header(id_of(0x99), BlockHeaderType{}), std::invalid_argument);
}

// Two concurrent in-flight requests are each delivered their OWN reply — no
// cross-wiring between distinct ids.
TEST(DashP2PConnection, ConcurrentRequestsAreNotCrossWired)
{
    boost::asio::io_context ctx;
    Connection conn(&ctx, nullptr);
    conn.init_requests([&](uint256) {}, [&](uint256) {});

    const uint256 id_a = id_of(0x01), id_b = id_of(0x02);
    BlockType got_a, got_b;
    conn.request_block(id_a, id_of(0xA0), [&](BlockType b) { got_a = b; });
    conn.request_block(id_b, id_of(0xB0), [&](BlockType b) { got_b = b; });

    // deliver in reverse order: id_b first.
    conn.get_block(id_b, make_block(2, 200, 0xBB));
    conn.get_block(id_a, make_block(1, 100, 0xAA));

    EXPECT_EQ(got_a.m_nonce, 100u);
    EXPECT_EQ(got_a.m_merkle_root, id_of(0xAA));
    EXPECT_EQ(got_b.m_nonce, 200u);
    EXPECT_EQ(got_b.m_merkle_root, id_of(0xBB));
}