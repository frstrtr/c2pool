// SPDX-License-Identifier: AGPL-3.0-or-later
//
// D-LTC.PER-PEER-INGEST — KATs for the per-peer ingest-budget fairness that
// sub-divides the global admission ceiling (issue #1600).
//
// The global IngestBudget (issue #1599 / ingest_bounds_test) bounds TOTAL
// inflight shares+bytes but is fair-share blind: one peer could accumulate
// batch after batch and occupy the whole pipeline, crowding every other peer
// out of admission. try_admit_for_peer() adds a PER-PEER cap that is a strict
// SUB-DIVISION of the global ceiling (ceil(global/2) here). The contract:
//   * a peer that has NOT yet reached its slice always admits its next batch
//     (so a legitimate high-hashrate peer or a large single message is never
//     throttled; a single batch is bounded by the wire/socket cap anyway),
//   * a peer that has ALREADY reached its slice is refused (PeerCapped) while
//     OTHER peers still admit — this is what stops one peer monopolising,
//   * the GLOBAL counters NEVER exceed their existing ceiling (the per-peer cap
//     only decides WHICH peer is refused first; it never raises the hard bound),
//   * releasing a peer's reservation decrements its per-peer counters so it can
//     admit again.
//
// Folded into the EXISTING allowlisted `share_test` target — a standalone
// add_executable would be absent from build.yml's --target list and reported
// "Not Run" by CTest (the #769 trap).

#include <gtest/gtest.h>

#include <string>

#include <impl/ltc/ingest_budget.hpp>

namespace {

using ltc::IngestBudget;
using AR = ltc::IngestBudget::AdmitResult;

// 100 shares / 1,000,000 bytes global => per-peer cap ceil(100/2)=50 shares,
// ceil(1e6/2)=500,000 bytes.
static IngestBudget make_budget() { return IngestBudget(100, 1'000'000); }

// ── 1. Per-peer cap sub-divides the global ceiling ──────────────────────────
TEST(LtcPerPeerIngest, PerPeerCapMatchesCeilOfHalfTheGlobalCeiling)
{
    IngestBudget b = make_budget();
    EXPECT_EQ(b.per_peer_max_shares(), 50u);   // ceil(100/2)
    EXPECT_EQ(b.per_peer_max_bytes(), 500'000u);
    // ceil semantics: an odd/tiny global still admits at least 1 per peer.
    IngestBudget odd(1, 3);
    EXPECT_EQ(odd.per_peer_max_shares(), 1u);   // ceil(1/2)
    EXPECT_EQ(odd.per_peer_max_bytes(), 2u);    // ceil(3/2)
}

// ── 2. A peer at its slice cannot keep admitting while OTHERS still can ──────
TEST(LtcPerPeerIngest, PeerAtItsSliceIsFrozenWhileOthersStillAdmit)
{
    IngestBudget b = make_budget();

    // Peer A reaches its per-peer slice (50 shares).
    EXPECT_EQ(b.try_admit_for_peer(50, 10, "A"), AR::Admitted);
    EXPECT_EQ(b.peer_shares("A"), 50u);

    // A is now AT its slice, so its next batch is PeerCapped even though the
    // GLOBAL budget still has 50 shares free — and the refusal reserves NOTHING.
    EXPECT_EQ(b.try_admit_for_peer(1, 1, "A"), AR::PeerCapped);
    EXPECT_EQ(b.peer_shares("A"), 50u);
    EXPECT_EQ(b.shares(), 50u);

    // A DIFFERENT peer B still admits into the remaining global headroom.
    EXPECT_EQ(b.try_admit_for_peer(50, 10, "B"), AR::Admitted);
    EXPECT_EQ(b.peer_shares("B"), 50u);

    // Global is now exactly full; a third peer C (under its OWN slice) is
    // refused GlobalFull — the shared ceiling, not its slice, is the constraint.
    EXPECT_EQ(b.try_admit_for_peer(1, 1, "C"), AR::GlobalFull);

    // GLOBAL NEVER EXCEEDS ITS CEILING — the whole point of the sub-division.
    EXPECT_EQ(b.shares(), 100u);
    EXPECT_LE(b.shares(), b.max_shares());

    // A GlobalFull refusal rolled peer C's tentative reservation back to zero.
    EXPECT_EQ(b.peer_shares("C"), 0u);
}

// ── 3. A peer's FIRST batch is never throttled, even if it exceeds the slice ─
// The cap must not throttle a legitimate high-hashrate peer's single large
// message. A peer under its slice admits its next batch even when that batch
// alone overshoots the slice; only AFTER it has reached the slice is it frozen.
TEST(LtcPerPeerIngest, FirstBatchLargerThanSliceIsAdmittedThenPeerIsFrozen)
{
    IngestBudget b = make_budget();   // slice 50 shares
    EXPECT_EQ(b.try_admit_for_peer(60, 10, "A"), AR::Admitted);  // 60 > slice, still in
    EXPECT_EQ(b.peer_shares("A"), 60u);
    // Now A is over its slice: no further batch until it drains.
    EXPECT_EQ(b.try_admit_for_peer(1, 1, "A"), AR::PeerCapped);
    EXPECT_LE(b.shares(), b.max_shares());
}

// ── 4. Byte slice behaves the same and independently of the share slice ─────
TEST(LtcPerPeerIngest, PerPeerByteSliceIsEnforcedIndependentlyOfShares)
{
    IngestBudget b = make_budget();   // byte slice = 500,000
    // One share, byte-heavy: first batch admits though it reaches the byte slice.
    EXPECT_EQ(b.try_admit_for_peer(1, 500'000, "A"), AR::Admitted);
    EXPECT_EQ(b.peer_bytes("A"), 500'000u);
    // A now holds its byte slice (with only 1 share) -> next batch PeerCapped.
    EXPECT_EQ(b.try_admit_for_peer(1, 1, "A"), AR::PeerCapped);
    // Peer B still admits its own byte slice; global bytes reach the ceiling.
    EXPECT_EQ(b.try_admit_for_peer(1, 500'000, "B"), AR::Admitted);
    EXPECT_EQ(b.bytes(), 1'000'000u);
    EXPECT_LE(b.bytes(), b.max_bytes());
}

// ── 5. Releasing a peer's reservation lets it admit again (decrement correct) ─
TEST(LtcPerPeerIngest, ReleaseDecrementsPerPeerSoAFrozenPeerCanAdmitAgain)
{
    IngestBudget b = make_budget();

    ASSERT_EQ(b.try_admit_for_peer(50, 10, "A"), AR::Admitted);
    ASSERT_EQ(b.try_admit_for_peer(1, 1, "A"), AR::PeerCapped);   // at slice

    // Free the whole reservation: both the global and A's per-peer counters drop.
    b.release_for_peer(50, 10, "A");
    EXPECT_EQ(b.peer_shares("A"), 0u);
    EXPECT_EQ(b.shares(), 0u);
    EXPECT_EQ(b.tracked_peers(), 0u);   // emptied entry is pruned, no unbounded map

    // A can admit again — capacity is reusable, not spent.
    EXPECT_EQ(b.try_admit_for_peer(50, 10, "A"), AR::Admitted);

    // Partial release drops A back below its slice, so it admits once more.
    b.release_for_peer(10, 2, "A");         // A now holds 40 (< 50 slice)
    EXPECT_EQ(b.peer_shares("A"), 40u);
    EXPECT_EQ(b.try_admit_for_peer(10, 2, "A"), AR::Admitted);   // back to 50 (== slice)
    EXPECT_EQ(b.try_admit_for_peer(1, 1, "A"), AR::PeerCapped);  // frozen again
}

// ── 6. Global ceiling holds under many peers; per-peer never raises it ───────
TEST(LtcPerPeerIngest, GlobalCeilingNeverExceededAcrossManyPeers)
{
    IngestBudget b(10, 100);    // per-peer slice ceil(10/2)=5 shares
    ASSERT_EQ(b.per_peer_max_shares(), 5u);

    EXPECT_EQ(b.try_admit_for_peer(5, 1, "p1"), AR::Admitted);
    EXPECT_EQ(b.try_admit_for_peer(5, 1, "p2"), AR::Admitted);
    EXPECT_EQ(b.shares(), 10u);                 // exactly the global ceiling
    // Two peers at their slice already saturate the global budget: no third peer
    // can push it past the ceiling.
    EXPECT_EQ(b.try_admit_for_peer(1, 1, "p3"), AR::GlobalFull);
    EXPECT_EQ(b.shares(), 10u);
    EXPECT_LE(b.shares(), b.max_shares());
}

// ── 7. Releasing one peer frees only the global headroom it held ─────────────
TEST(LtcPerPeerIngest, OnePeerFreeingBudgetReopensGlobalHeadroomForOthers)
{
    IngestBudget b(10, 100);
    ASSERT_EQ(b.try_admit_for_peer(5, 1, "p1"), AR::Admitted);
    ASSERT_EQ(b.try_admit_for_peer(5, 1, "p2"), AR::Admitted);
    ASSERT_EQ(b.try_admit_for_peer(1, 1, "p3"), AR::GlobalFull);   // full

    b.release_for_peer(5, 1, "p1");             // p1 drains its slice
    EXPECT_EQ(b.shares(), 5u);
    // p3 now fits in the reopened global headroom (under its own slice too).
    EXPECT_EQ(b.try_admit_for_peer(5, 1, "p3"), AR::Admitted);
    EXPECT_EQ(b.shares(), 10u);
    EXPECT_LE(b.shares(), b.max_shares());
}

}  // namespace
