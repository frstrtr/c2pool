// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// btc::coin::TipReconcileGate KATs — pin the B5b tip-reconcile poll that
// unwedges the HeaderChain sync-lag self-collision livelock (btc/g3b-tip-
// reconcile-poll, observed on the vm130 G3b regtest rig 2026-08-16).
//
// The livelock: HeaderChain stalls one block behind bitcoind's real tip after
// a won-block submit (Core doesn't re-announce the connected block over the
// P2P leg it arrived on). Every new template then re-mines the SAME height, so
// each won block returns submitblock "inconclusive" -> STALE, forever. The fix
// re-issues getheaders(locator = tip) every 10s while a submit is pending,
// pulling the connected tip so HeaderChain advances and template production
// unwedges.
//
// These KATs run purely on discrete, hand-driven ticks (each tick == one
// kPollInterval elapse) — NO real timers, NO sockets — so the reproduction is
// deterministic. They ride the already-allowlisted btc_share_test executable.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

#include "../coin/tip_reconcile_gate.hpp"

using btc::coin::TipReconcileGate;
using Action = TipReconcileGate::Action;

namespace {

// --- Deterministic model of the HeaderChain / bitcoind / template interaction
// that produced the vm130 self-collision livelock. Advancing the local tip
// happens ONLY when a reconcile getheaders is issued — this encodes the real
// environmental fact that Core does not re-announce the connected block, so an
// explicit re-poll is the sole path by which HeaderChain learns the new tip.
struct LivelockSim {
    uint32_t bitcoind_tip   = 605;  // bitcoind's real active tip
    uint32_t local_tip      = 604;  // HeaderChain — pinned one behind post-submit
    bool     p2p_up         = true;
    bool     handshake      = true;
    int      pending        = 1;    // one won block awaiting roundtrip confirm
    int      stale_submits  = 0;    // submitblock "inconclusive" count
    int      getheaders_sent = 0;

    bool have_pending() const { return pending > 0; }

    // Template always builds on local_tip -> mines height local_tip + 1.
    uint32_t next_template_height() const { return local_tip + 1; }

    // Mine on the current local tip and submit. If we're mining a height that
    // bitcoind has ALREADY connected (local_tip + 1 <= bitcoind_tip) it's a
    // self-collision: submitblock returns "inconclusive"/STALE and the submit
    // stays pending. A genuinely new height is accepted and clears pending.
    void mine_and_submit() {
        if (next_template_height() <= bitcoind_tip)
            ++stale_submits;      // inconclusive -> still pending
        else
            pending = 0;          // new height -> accepted, roundtrip resolved
    }

    // The reconcile poll: re-issue getheaders(locator = tip). Core answers with
    // headers up to its real tip, so HeaderChain advances to bitcoind_tip.
    void reconcile_getheaders() {
        ++getheaders_sent;
        if (local_tip < bitcoind_tip)
            local_tip = bitcoind_tip;
    }
};

}  // namespace

// --- The cadence itself is a pinned constant -------------------------------
// "asserts the 10s re-poll": the poll that breaks the livelock fires on a
// 10-second cadence, and that interval is the SSOT shared with main_btc.cpp.
TEST(TipReconcileGate, PollIntervalIsTenSeconds)
{
    EXPECT_EQ(TipReconcileGate::kPollInterval, std::chrono::seconds(10));
}

// --- Gate truth table: fire IFF pending && p2p && handshake -----------------
TEST(TipReconcileGate, FiresOnlyWhenPendingAndP2pAndHandshake)
{
    // The one firing case.
    EXPECT_EQ(TipReconcileGate::evaluate(/*pending=*/true, /*p2p=*/true,
                                         /*handshake=*/true),
              Action::Poll);

    // Every case that must stay quiet (zero getheaders churn).
    EXPECT_EQ(TipReconcileGate::evaluate(false, true,  true),  Action::Skip);
    EXPECT_EQ(TipReconcileGate::evaluate(true,  false, true),  Action::Skip);
    EXPECT_EQ(TipReconcileGate::evaluate(true,  true,  false), Action::Skip);
    EXPECT_EQ(TipReconcileGate::evaluate(false, false, false), Action::Skip);
}

// --- Locator selection: tip hash when synced, else genesis ------------------
TEST(TipReconcileGate, LocatorPrefersTipElseGenesis)
{
    const std::string tip     = "tip-hash";
    const std::string genesis = "genesis-hash";
    EXPECT_EQ(TipReconcileGate::locator(/*have_tip=*/true,  tip, genesis), tip);
    EXPECT_EQ(TipReconcileGate::locator(/*have_tip=*/false, tip, genesis), genesis);
}

// --- REPRODUCTION: without the poll, the livelock never self-heals ----------
// This is the vm130 failure mode. Drive 50 ticks of "mine on the stale tip and
// submit" with NO reconcile: the local tip stays pinned at 604, the submit
// stays pending forever, and every single attempt is a stale self-collision.
TEST(TipReconcileGate, WithoutPollLivelockPersistsForever)
{
    LivelockSim sim;
    constexpr int kTicks = 50;
    for (int i = 0; i < kTicks; ++i)
        sim.mine_and_submit();

    EXPECT_EQ(sim.local_tip, 604u);          // never advanced
    EXPECT_TRUE(sim.have_pending());         // won block never confirmed
    EXPECT_EQ(sim.stale_submits, kTicks);    // every attempt was inconclusive
    EXPECT_EQ(sim.getheaders_sent, 0);       // nothing ever re-polled
}

// --- FIX: the gate-driven 10s re-poll breaks the livelock deterministically -
// Each tick: mine+submit on the current tip, then consult the SHIPPED gate; if
// it says Poll, issue the reconcile getheaders. The first tick self-collides
// (still pinned at 604), the gate fires because a submit is pending, the poll
// advances the local tip to bitcoind's 605, and the very next mine targets 606
// — a new height — which is accepted and clears the pending submit.
TEST(TipReconcileGate, GateDrivenRepollBreaksLivelock)
{
    LivelockSim sim;
    int ticks = 0;
    constexpr int kTickBudget = 10;  // must break in a bounded number of ticks

    while (sim.have_pending() && ticks < kTickBudget) {
        ++ticks;
        sim.mine_and_submit();
        if (TipReconcileGate::evaluate(sim.have_pending(), sim.p2p_up,
                                       sim.handshake) == Action::Poll)
            sim.reconcile_getheaders();
    }

    EXPECT_FALSE(sim.have_pending());        // roundtrip resolved -> unwedged
    EXPECT_EQ(sim.local_tip, 605u);          // HeaderChain caught up to bitcoind
    EXPECT_GE(sim.getheaders_sent, 1);       // the re-poll is what did it
    EXPECT_LE(ticks, 2);                     // and it broke within one poll cycle
}

// --- Once the submit clears, the gate goes quiet: no churn on a synced node -
TEST(TipReconcileGate, NoRepollAfterPendingClears)
{
    LivelockSim sim;
    // Drive it to resolution first.
    while (sim.have_pending()) {
        sim.mine_and_submit();
        if (TipReconcileGate::evaluate(sim.have_pending(), sim.p2p_up,
                                       sim.handshake) == Action::Poll)
            sim.reconcile_getheaders();
    }
    const int settled = sim.getheaders_sent;

    // Idle, caught-up ticks must not emit a single further getheaders.
    for (int i = 0; i < 20; ++i) {
        EXPECT_EQ(TipReconcileGate::evaluate(sim.have_pending(), sim.p2p_up,
                                             sim.handshake),
                  Action::Skip);
    }
    EXPECT_EQ(sim.getheaders_sent, settled);
}

// ===========================================================================
// Unknown-block resync KATs -- the second HeaderChain stall shape (.234 G3b
// testnet3 rig 2026-10-25): after a < 2000 batch marks sync caught up, bitcoind
// fell back to block INVs (min-diff storm reorg). Every INV'd block had an
// unknown header, full_block dropped it, and no getheaders was ever re-sent,
// so HeaderChain sat ~50k behind for 5 days (47097 dropped blocks).
// ===========================================================================

namespace {

using Clock = std::chrono::steady_clock;

// Deterministic model: bitcoind advances by INV only; HeaderChain advances
// ONLY when a getheaders is issued (the environmental fact behind the stall).
struct InvOnlyStallSim {
    uint32_t bitcoind_tip    = 5199630;
    uint32_t local_tip       = 5199630;
    int      getheaders_sent = 0;
    int      dropped_blocks  = 0;
    std::optional<Clock::duration> last_resync;  // sim-time of last resync

    bool header_known(uint32_t h) const { return h <= local_tip; }

    // One INV for a new bitcoind tip at sim-time t. use_gate=false is the
    // pre-fix behaviour (log + getdata only).
    void announce(Clock::duration t, bool use_gate) {
        ++bitcoind_tip;
        const bool known = header_known(bitcoind_tip);
        if (use_gate &&
            TipReconcileGate::on_block_announce(
                known, /*handshake_complete=*/true, last_resync.has_value(),
                last_resync ? t - *last_resync : Clock::duration::zero())
                == Action::Poll) {
            last_resync = t;
            ++getheaders_sent;
            local_tip = bitcoind_tip;  // Core answers up to its active tip
        }
        if (!header_known(bitcoind_tip))
            ++dropped_blocks;          // full_block: header unknown -> drop
    }
};

}  // namespace

TEST(TipReconcileGate, UnknownBlockResyncMinGapIsTwoSeconds)
{
    EXPECT_EQ(TipReconcileGate::kUnknownBlockResyncMinGap, std::chrono::seconds(2));
}

TEST(TipReconcileGate, KnownHeaderAnnounceNeverResyncs)
{
    // Normal sendheaders flow: header already landed before the INV/block.
    EXPECT_EQ(TipReconcileGate::on_block_announce(true, true, false, Clock::duration::zero()),
              Action::Skip);
    EXPECT_EQ(TipReconcileGate::on_block_announce(true, true, true, std::chrono::hours(1)),
              Action::Skip);
}

TEST(TipReconcileGate, UnknownHeaderAnnounceResyncs)
{
    EXPECT_EQ(TipReconcileGate::on_block_announce(false, true, false, Clock::duration::zero()),
              Action::Poll);
    EXPECT_EQ(TipReconcileGate::on_block_announce(false, true, true, std::chrono::seconds(2)),
              Action::Poll);
}

TEST(TipReconcileGate, UnknownHeaderWithoutHandshakeStaysQuiet)
{
    EXPECT_EQ(TipReconcileGate::on_block_announce(false, false, false, Clock::duration::zero()),
              Action::Skip);
}

TEST(TipReconcileGate, SiblingInvBurstCostsOneGetheaders)
{
    // 288 unknown-block INVs inside one throttle window -> exactly 1 resync.
    int polls = 0;
    std::optional<Clock::duration> last;
    for (int i = 0; i < 288; ++i) {
        const auto t = std::chrono::milliseconds(i);  // all within 288ms
        if (TipReconcileGate::on_block_announce(
                false, true, last.has_value(),
                last ? t - *last : Clock::duration::zero()) == Action::Poll) {
            ++polls;
            last = t;
        }
    }
    EXPECT_EQ(polls, 1);
}

TEST(TipReconcileGate, InvOnlyStallReproducesWithoutResync)
{
    // Pre-fix: 1000 INV'd tips at 10s spacing, zero getheaders, zero progress.
    InvOnlyStallSim sim;
    for (int i = 0; i < 1000; ++i)
        sim.announce(std::chrono::seconds(10 * i), /*use_gate=*/false);
    EXPECT_EQ(sim.getheaders_sent, 0);
    EXPECT_EQ(sim.local_tip, 5199630u);   // pinned -- the observed stall
    EXPECT_EQ(sim.dropped_blocks, 1000);
}

TEST(TipReconcileGate, InvOnlyStallBrokenByResync)
{
    InvOnlyStallSim sim;
    for (int i = 0; i < 1000; ++i)
        sim.announce(std::chrono::seconds(10 * i), /*use_gate=*/true);
    EXPECT_EQ(sim.local_tip, sim.bitcoind_tip);  // tracks bitcoind
    EXPECT_EQ(sim.dropped_blocks, 0);
    EXPECT_EQ(sim.getheaders_sent, 1000);        // one per new tip, no burst
}
