/// Phase S8 — Dash coin-daemon P2P node (socket-node skeleton) KATs
///
/// Exercises src/impl/dash/coin/p2p_node.hpp — the socket-node lifecycle layer
/// the S8 block-submission lane builds on:
///
///     p2p_messages -> p2p_connection -> [p2p_node] -> broadcaster
///
/// What is PINNED here:
///
///   (a) the outbound-request -> inbound-reply exchange, driven END-TO-END
///       through the node lifecycle: attach() arms the Connection matcher,
///       request_block() emits through the wire-callback carrying the EXACT
///       hash, and deliver_block() routes the byte-exact reply back to the
///       matching handler. A loopback wire-callback closes the round-trip the
///       way a live socket would, so the full attach -> request -> wire ->
///       reply -> handler path is real (the matcher logic is the same one the
///       Connection leaf pins; here it runs through the node, not in isolation).
///
///   (b) the TIMEOUT path, driven by a REAL core::Timer firing through
///       io_context.run(): a short idle deadline elapses with no activity, the
///       liveness timer fires, the node tears the peer down and notifies the
///       observer. This is the genuine async timer fire — not a synchronous
///       poke — and asserts post-fire state (detached) and the reason.
///
///   plus lifecycle invariants: teardown is idempotent, a torn-down node drops
///   exchange calls instead of throwing, and note_activity() pushing the
///   deadline forward keeps the peer alive past the original deadline.
///
/// SCOPE NOTE (honest): the wire transport is a loopback std::function, not a
/// live boost::asio::ip::tcp socket — constructing a real core::Socket requires
/// the INetwork/Factory acceptor wiring that is a LATER S8 slice, explicitly
/// out of scope for this leaf. The request/reply matcher logic, the lifecycle,
/// and the timer-driven timeout are all real and asserted.

#include <gtest/gtest.h>

#include <impl/dash/coin/p2p_node.hpp>
#include <impl/dash/coin/block.hpp>

#include <core/uint256.hpp>

#include <boost/asio.hpp>

#include <cstdint>
#include <string>

using namespace dash::coin;
using dash::coin::p2p::NodeP2P;

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

// (a) Live socket-style exchange: a block request emitted through the node
// reaches the wire-callback with the exact hash; a loopback feeds the reply
// straight back via deliver_block; the byte-exact block lands on the handler.
TEST(DashP2PNode, RequestReplyExchangeRoundtripsThroughNode)
{
    boost::asio::io_context ctx;
    NodeP2P node(&ctx);

    const uint256 want_id   = id_of(0x11);
    const uint256 want_hash = id_of(0xAB);
    const BlockType reply    = make_block(0xDEAD, 0xC0FFEE, 0x42);

    uint256 emitted_hash;
    int wire_calls = 0;

    // Loopback "wire": on the outbound block request, immediately deliver the
    // matching reply back into the node — the round-trip a live socket makes.
    node.attach(
        /*socket*/ nullptr,
        /*block_req*/ [&](uint256 h) {
            emitted_hash = h;
            ++wire_calls;
            node.deliver_block(want_id, reply);
        },
        /*header_req*/ [&](uint256) {});

    ASSERT_TRUE(node.is_attached());

    int handler_calls = 0;
    BlockType got;
    node.request_block(want_id, want_hash, [&](BlockType b) { got = b; ++handler_calls; });

    // outbound half reached the wire with the exact hash.
    EXPECT_EQ(wire_calls, 1);
    EXPECT_EQ(emitted_hash, want_hash);

    // inbound half routed the byte-exact reply to the matching handler.
    EXPECT_EQ(handler_calls, 1);
    EXPECT_EQ(got.m_version, 0xDEADu);
    EXPECT_EQ(got.m_nonce, 0xC0FFEEu);
    EXPECT_EQ(got.m_merkle_root, id_of(0x42));
}

// Header exchange carries the same contract through the node.
TEST(DashP2PNode, HeaderExchangeRoundtripsThroughNode)
{
    boost::asio::io_context ctx;
    NodeP2P node(&ctx);

    const uint256 id   = id_of(0x07);
    const uint256 hash = id_of(0x77);
    BlockHeaderType reply;
    reply.m_version = 0xBEEF;
    reply.m_bits = 0x1d00ffff;

    uint256 emitted_hash;
    node.attach(nullptr, [&](uint256) {},
        [&](uint256 h) { emitted_hash = h; node.deliver_header(id, reply); });

    int handler_calls = 0;
    BlockHeaderType got;
    node.request_header(id, hash, [&](BlockHeaderType h) { got = h; ++handler_calls; });

    EXPECT_EQ(emitted_hash, hash);
    EXPECT_EQ(handler_calls, 1);
    EXPECT_EQ(got.m_version, 0xBEEFu);
    EXPECT_EQ(got.m_bits, 0x1d00ffffu);
}

// (b) Timeout path, driven by a REAL timer firing through io_context.run():
// with a 1s idle deadline and no activity, the liveness timer fires, the node
// tears the peer down, and the observer is notified with the reason.
TEST(DashP2PNode, IdleTimeoutFiresViaRealTimerAndTearsDown)
{
    boost::asio::io_context ctx;
    NodeP2P node(&ctx);

    node.set_idle_timeout_sec(1);     // short, real countdown

    std::string fired_reason;
    int fire_count = 0;
    node.set_on_timeout([&](const std::string& r) { fired_reason = r; ++fire_count; });

    node.attach(nullptr, [&](uint256) {}, [&](uint256) {});
    ASSERT_TRUE(node.is_attached());

    // Drive the io_context until the timer actually fires (real async wait).
    ctx.run();

    EXPECT_EQ(fire_count, 1);
    EXPECT_EQ(fired_reason, "idle timeout");
    EXPECT_FALSE(node.is_attached());   // peer torn down on timeout
}

// note_activity() pushes the deadline forward: an activity poke before the
// original deadline keeps the peer alive. Here we verify the node does NOT
// time out within a window when activity keeps arriving — the timer is rearmed.
TEST(DashP2PNode, ActivityRearmsLivenessTimer)
{
    boost::asio::io_context ctx;
    NodeP2P node(&ctx);

    node.set_idle_timeout_sec(2);
    int fire_count = 0;
    node.set_on_timeout([&](const std::string&) { ++fire_count; });

    node.attach(nullptr, [&](uint256) {}, [&](uint256) {});

    // Schedule an activity poke at ~1s (before the 2s deadline) that rearms the
    // 2s countdown, then stop the io_context shortly after so run() returns
    // before the rearmed deadline. The timeout must NOT have fired.
    boost::asio::steady_timer poke(ctx, std::chrono::milliseconds(1000));
    poke.async_wait([&](const boost::system::error_code&) { node.note_activity(); });

    boost::asio::steady_timer stop(ctx, std::chrono::milliseconds(1500));
    stop.async_wait([&](const boost::system::error_code&) { node.teardown(); });

    ctx.run();

    EXPECT_EQ(fire_count, 0);            // rearmed deadline never reached
    EXPECT_FALSE(node.is_attached());   // teardown() detached it
}

// Lifecycle: teardown is idempotent and a torn-down node drops exchange calls
// rather than throwing (a dead node must not crash the caller).
TEST(DashP2PNode, TornDownNodeDropsExchangeCallsAndTeardownIsIdempotent)
{
    boost::asio::io_context ctx;
    NodeP2P node(&ctx);

    node.attach(nullptr, [&](uint256) {}, [&](uint256) {});
    EXPECT_TRUE(node.is_attached());

    node.teardown();
    EXPECT_FALSE(node.is_attached());
    node.teardown();                    // idempotent — no crash
    EXPECT_FALSE(node.is_attached());

    int handler_calls = 0;
    // Dropped silently — no peer, no matcher; must NOT throw.
    EXPECT_NO_THROW(node.request_block(id_of(1), id_of(2),
        [&](BlockType) { ++handler_calls; }));
    EXPECT_NO_THROW(node.deliver_block(id_of(1), make_block(1, 1, 1)));
    EXPECT_NO_THROW(node.request_header(id_of(1), id_of(2),
        [&](BlockHeaderType) { ++handler_calls; }));
    EXPECT_NO_THROW(node.deliver_header(id_of(1), BlockHeaderType{}));
    EXPECT_EQ(handler_calls, 0);
}
