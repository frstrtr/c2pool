// SPDX-License-Identifier: AGPL-3.0-or-later
// DASHD-CUT arm-authority + reconnect-thrash KAT (hotel-reserve 2026-08-15).
//
// Reproduces the naked-cut thrash RED on the pre-fix behaviour and proves it
// GREEN on the fix. Three seams, all exercised against the real production code
// (no fakes of the code under test):
//
//   SEAM 1 (arm authority, pure):  resolve_dashd_arm() — removing --coin-rpc must
//     truly DISARM the dashd-fallback CoindRPC, even when a stray ~/.dashcore/
//     dash.conf would satisfy conf.armed(). This is the root: at the reserve,
//     conf.armed() alone re-armed the arm to 127.0.0.1:9998, so pulling the flag
//     was cosmetic.
//
//   SEAM 2 (no hot spin) + SEAM 3 (invalidation decoupled from failure):
//     against a DEAD dashd, NodeRPC::sync_reconnect() must NOT (a) re-attempt the
//     socket ~30/s and must NOT (b) fire the churn observer (which drops a VALID
//     cached embedded template and bumps the work generation). At the reserve the
//     dead fallback arm produced 17804 reconnect attempts + 38474 cache
//     invalidations in ~13 min and starved the working embedded arm to 0 shares.
//     RED on old: attempts == calls, invalidations == calls. GREEN on fix:
//     attempts « calls (backoff), invalidations == 0 (decoupled).
//
//   WITH-dashd UNCHANGED: against a LIVE (reachable) endpoint the reconnect still
//     fires the churn observer exactly once (stale-payee class preserved) and
//     engages NO backoff.
//
// Links the real dash_rpc static lib (coin/rpc.cpp) — the first test to do so.

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>

#include <boost/asio.hpp>

#include <impl/dash/coin/rpc.hpp>
#include <impl/dash/coin/rpc_conf.hpp>
#include <impl/dash/coin/node_interface.hpp>
#include <core/netaddress.hpp>

using dash::coin::DashdArm;
using dash::coin::DashdArmDecision;
using dash::coin::resolve_dashd_arm;

// ───────────────────────── SEAM 1: arm authority ──────────────────────────

// THE root fix. Cut mode = neither --coin-rpc nor --coin-rpc-auth given. Even
// with a fully-armed stray dash.conf (creds_armed = true), the dashd-fallback
// arm must stay OFF. Pre-fix, `if (conf.armed())` alone armed it here — the
// hotel-reserve cosmetic-removal bug.
TEST(DashdCutArm, CutModeDisarmsDespiteStrayCreds)
{
    const DashdArmDecision d = resolve_dashd_arm(/*coin_rpc_requested=*/false,
                                                 /*creds_armed=*/true);
    EXPECT_FALSE(d.construct_rpc);
    EXPECT_EQ(d.arm, DashdArm::Disarmed);
}

// Bare --run with no creds and no request: also disarmed (unchanged daemonless
// default).
TEST(DashdCutArm, BareRunNoCredsDisarmed)
{
    const DashdArmDecision d = resolve_dashd_arm(false, false);
    EXPECT_FALSE(d.construct_rpc);
    EXPECT_EQ(d.arm, DashdArm::Disarmed);
}

// WITH-dashd UNCHANGED: an explicit --coin-rpc / --coin-rpc-auth request with
// creds resolved arms exactly as before.
TEST(DashdCutArm, RequestedWithCredsArmsLive)
{
    const DashdArmDecision d = resolve_dashd_arm(/*coin_rpc_requested=*/true,
                                                 /*creds_armed=*/true);
    EXPECT_TRUE(d.construct_rpc);
    EXPECT_EQ(d.arm, DashdArm::ArmedLive);
}

// Requested but creds unresolved: fail CLOSED (unarmed), never spin an
// endpoint with no auth.
TEST(DashdCutArm, RequestedWithoutCredsStaysDisarmed)
{
    const DashdArmDecision d = resolve_dashd_arm(true, false);
    EXPECT_FALSE(d.construct_rpc);
    EXPECT_EQ(d.arm, DashdArm::Disarmed);
}

// ──────────────── SEAM 2 + 3: reconnect thrash against a DEAD dashd ─────────

// Bind (but never connect to) an ephemeral loopback port, then release it so the
// port is (almost certainly) closed — connect() to it yields "Connection
// refused" instantly, exactly like a stopped dashd. Returns the freed port.
static uint16_t pick_dead_loopback_port()
{
    boost::asio::io_context probe;
    boost::asio::ip::tcp::acceptor acc(probe);
    boost::asio::ip::tcp::endpoint ep(
        boost::asio::ip::make_address("127.0.0.1"), 0);
    acc.open(ep.protocol());
    acc.bind(ep);
    const uint16_t port = acc.local_endpoint().port();
    acc.close();   // free it: subsequent connect() is refused
    return port;
}

TEST(DashdCutArm, DeadDashdNoReconnectSpinNoInvalidation)
{
    boost::asio::io_context ioc;
    dash::interfaces::Node coin_state;
    auto rpc = std::make_unique<dash::coin::NodeRPC>(&ioc, &coin_state, /*testnet=*/false);

    std::atomic<uint64_t> invalidations{0};
    rpc->set_on_reconnect([&invalidations]() { invalidations.fetch_add(1); });

    // Point the client at a dead endpoint. connect() only queues async ops on
    // ioc (which we never run), so it just records the target address that the
    // synchronous sync_reconnect() path below uses.
    const uint16_t dead_port = pick_dead_loopback_port();
    rpc->connect(NetService(std::string("127.0.0.1"), dead_port), "u:p");

    // Drive the exact serve-path retry loop: Send() calls sync_reconnect() on
    // every write/read failure. Simulate a burst of 200 such failures.
    constexpr int kCalls = 200;
    for (int i = 0; i < kCalls; ++i)
        rpc->sync_reconnect();

    // SEAM 3: a FAILED reconnect must invalidate NOTHING. (Old code: kCalls.)
    EXPECT_EQ(invalidations.load(), 0u)
        << "a dead dashd must not drop the cached embedded template";

    // SEAM 2: backoff must throttle the socket attempts far below the call
    // count. All 200 calls land inside the first (1 s) backoff window, so only
    // the first one (and possibly a straggler) actually touches the socket.
    // (Old code: attempts == kCalls == 200.)
    EXPECT_LT(rpc->sync_reconnect_attempts(), static_cast<uint64_t>(kCalls));
    EXPECT_LE(rpc->sync_reconnect_attempts(), 3u)
        << "sync_reconnect must not hot-spin against a dead dashd";

    // A backoff window is armed after the failure.
    EXPECT_GT(rpc->sync_backoff_secs(), 0);
}

// ──────────────── WITH-dashd UNCHANGED: LIVE endpoint still invalidates ─────

TEST(DashdCutArm, LiveDashdReconnectFiresObserverAndResetsBackoff)
{
    boost::asio::io_context ioc;
    dash::interfaces::Node coin_state;
    auto rpc = std::make_unique<dash::coin::NodeRPC>(&ioc, &coin_state, /*testnet=*/false);

    std::atomic<uint64_t> invalidations{0};
    rpc->set_on_reconnect([&invalidations]() { invalidations.fetch_add(1); });

    // A listening acceptor completes the TCP handshake from the kernel backlog
    // even without an accept() call, so the blocking connect() inside
    // sync_reconnect() succeeds — no dashd protocol needed (sync_reconnect does
    // connect + socket-timeouts + observer, never check()).
    boost::asio::io_context listener_ctx;
    boost::asio::ip::tcp::acceptor acc(listener_ctx);
    boost::asio::ip::tcp::endpoint ep(
        boost::asio::ip::make_address("127.0.0.1"), 0);
    acc.open(ep.protocol());
    acc.bind(ep);
    acc.listen();
    const uint16_t live_port = acc.local_endpoint().port();

    rpc->connect(NetService(std::string("127.0.0.1"), live_port), "u:p");
    rpc->sync_reconnect();

    // Stale-payee class preserved: a SUCCESSFUL reconnect fires the observer.
    EXPECT_EQ(invalidations.load(), 1u)
        << "a live reconnect must still invalidate (a moved tip => new payee)";
    EXPECT_GE(rpc->sync_reconnect_attempts(), 1u);
    // No backoff on a healthy path.
    EXPECT_EQ(rpc->sync_backoff_secs(), 0);
}
