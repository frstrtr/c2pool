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

#include <cstdint>
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
