// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// btc::coin::p2p::IdleProgressGate + core reply-matcher progress counter KATs.
//
// Milestone BTC-IDLE.PROGRESS: gate peer eviction on FORWARD PROGRESS (a real
// reply-matcher answer) rather than on raw inbound bytes. Pins the three
// inherited guard-rails (integrator 2026-07-30):
//   G1  single-peer coins (BCH) disable eviction -> gate is a pure no-op.
//   G2  a fully-synced, zero-pending idle peer is never armed for eviction.
//   G3  peer chatter must NOT reset a running window (the reset-on-any-byte bug).
// Plus the core signal the gate rides on: only got_response() (a genuine peer
// reply) advances progress; a per-request timeout does not.
//
// Pure logic + a synchronous reply-matcher drive -> no sockets, rides the
// already-allowlisted btc_share_test executable.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>

#include "../coin/idle_progress_gate.hpp"
#include <core/reply_matcher.hpp>

using btc::coin::p2p::IdleProgressGate;
using Action = btc::coin::p2p::IdleProgressGate::Action;

namespace {

// Convenience: eviction enabled unless a test says otherwise.
constexpr bool ENABLED  = true;
constexpr bool DISABLED = false;

// --- G2: a synced/idle peer (nothing pending) is never armed -----------------
TEST(IdleProgressGate, SyncedIdlePeerNeverArms)
{
    IdleProgressGate g;
    // No pending, no progress movement -> Stop, window never active.
    EXPECT_EQ(g.evaluate(ENABLED, /*pending=*/false, /*epoch=*/0), Action::Stop);
    EXPECT_FALSE(g.window_active());
    // Repeated idle samples stay Stop.
    EXPECT_EQ(g.evaluate(ENABLED, false, 0), Action::Stop);
    EXPECT_FALSE(g.window_active());
}

// --- Arm on the 0->pending edge, then hold across chatter (G3) ---------------
TEST(IdleProgressGate, PendingArmsThenChatterDoesNotReset)
{
    IdleProgressGate g;
    // First sample with a request outstanding and no progress -> Arm.
    EXPECT_EQ(g.evaluate(ENABLED, /*pending=*/true, /*epoch=*/0), Action::Arm);
    EXPECT_TRUE(g.window_active());
    // Subsequent chatter (still pending, epoch unchanged) must KEEP the running
    // window -- never Reset it. This is the whole point of the milestone.
    EXPECT_EQ(g.evaluate(ENABLED, true, 0), Action::KeepAsIs);
    EXPECT_EQ(g.evaluate(ENABLED, true, 0), Action::KeepAsIs);
    EXPECT_TRUE(g.window_active());
}

// --- Real forward progress resets the window; catching up stops it -----------
TEST(IdleProgressGate, ForwardProgressResetsThenSyncStops)
{
    IdleProgressGate g;
    EXPECT_EQ(g.evaluate(ENABLED, true, 0), Action::Arm);
    // A genuine answer arrived (epoch bumped) and more work remains -> Reset.
    EXPECT_EQ(g.evaluate(ENABLED, /*pending=*/true, /*epoch=*/1), Action::Reset);
    EXPECT_TRUE(g.window_active());
    // Another answer and now caught up (nothing pending) -> Stop.
    EXPECT_EQ(g.evaluate(ENABLED, /*pending=*/false, /*epoch=*/2), Action::Stop);
    EXPECT_FALSE(g.window_active());
}

// --- G1: eviction disabled (single-peer BCH) -> pure no-op -------------------
TEST(IdleProgressGate, EvictionDisabledIsAlwaysNoOp)
{
    IdleProgressGate g;
    // Even a chattering, non-progressing peer holding a pending request is never
    // armed when eviction is disabled -> the only connection is never dropped.
    EXPECT_EQ(g.evaluate(DISABLED, true,  0), Action::Stop);
    EXPECT_EQ(g.evaluate(DISABLED, true,  0), Action::Stop);
    EXPECT_EQ(g.evaluate(DISABLED, false, 5), Action::Stop);
    EXPECT_FALSE(g.window_active());
}

// --- reset() clears cross-connection state (reconnect safety) ----------------
TEST(IdleProgressGate, ResetClearsHighWaterMark)
{
    IdleProgressGate g;
    // Connection A climbs its progress high-water mark to 3.
    EXPECT_EQ(g.evaluate(ENABLED, true, 1), Action::Reset);
    EXPECT_EQ(g.evaluate(ENABLED, true, 2), Action::Reset);
    EXPECT_EQ(g.evaluate(ENABLED, true, 3), Action::Reset);
    // Connection A drops.
    g.reset();
    EXPECT_FALSE(g.window_active());
    // Connection B: its epoch restarts at 0. The first outstanding request (no
    // answer yet) must ARM. Without reset(), A stale high-water of 3 would make
    // every B epoch < 3 read as no-progress -- B could never Reset and a healthy
    // progressing peer would be wrongly evicted.
    EXPECT_EQ(g.evaluate(ENABLED, true, 0), Action::Arm);
    // B first genuine answer (epoch 1) IS real forward progress after the reset.
    EXPECT_EQ(g.evaluate(ENABLED, true, 1), Action::Reset);
}

// --- Core signal: only a REAL answer advances m_progress ---------------------
// Proves the discriminator the gate rides on. A synchronous got_response()
// increments m_progress and clears the watcher (has_pending -> false); a request
// that is merely outstanding does NOT advance it.
TEST(ReplyMatcherProgress, RealAnswerAdvancesProgressPendingClears)
{
    boost::asio::io_context ctx;
    using M = ReplyMatcher::ID<int>::RESPONSE<int>::REQUEST<int>;

    int last_response = -1;
    // request_func is a no-op here (we drive got_response directly).
    M m(&ctx, [](int){}, /*timeout_sec=*/30);

    EXPECT_EQ(m.m_progress, 0u);
    EXPECT_TRUE(m.m_watchers.empty());

    m.request(/*id=*/42, [&](int r){ last_response = r; }, /*arg=*/42);
    EXPECT_FALSE(m.m_watchers.empty());   // outstanding request -> pending
    EXPECT_EQ(m.m_progress, 0u);          // ...but no forward progress yet

    m.got_response(42, /*response=*/7);   // a genuine peer reply
    EXPECT_EQ(m.m_progress, 1u);          // forward progress advanced
    EXPECT_TRUE(m.m_watchers.empty());    // watcher cleared -> no longer pending
    EXPECT_EQ(last_response, 7);
}

} // namespace
