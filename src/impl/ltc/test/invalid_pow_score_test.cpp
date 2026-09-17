// SPDX-License-Identifier: AGPL-3.0-or-later
//
// D-LTC.INVALID-POW-SCORE — KATs for the conservative per-peer misbehavior
// scoring that penalizes peers streaming invalid-PoW shares (issue #1601).
//
// PUBLIC-POOL SAFETY is the whole design constraint: a false disconnect drops
// an honest miner's hashrate. So the scorer (ltc::PeerMisbehaviorScorer):
//   * is charged ONLY for a genuine cryptographic PoW-target miss — in
//     production, exactly the share_check.hpp SharePoWTargetMiss throw site.
//     Stale/duplicate/orphan/valid-but-losing shares NEVER call note_invalid_pow
//     (they do not throw that type), so this suite proves the score can only be
//     raised by the invalid-PoW note, and never by an untracked/honest peer.
//   * NEVER bans on the first offence: BAN_THRESHOLD is high (100).
//   * DECAYS over a time window (HALFLIFE_SECONDS), so a slow trickle decays
//     faster than it accumulates and only a sustained flood crosses the line.
//
// The score is a pure function of the (peer, time) note stream, so it is tested
// deterministically by injecting `now_s` (no wall clock, no sleeps).
//
// Folded into the EXISTING allowlisted `share_test` target (the #769 trap).

#include <gtest/gtest.h>

#include <string>

#include <impl/ltc/misbehavior.hpp>
#include <impl/ltc/share_check.hpp>   // is_scorable_invalid_pow, SharePoWTargetMiss

namespace {

using Scorer = ltc::PeerMisbehaviorScorer<std::string>;

// ── 1. Exactly BAN_THRESHOLD invalid-PoW shares trip the penalty ────────────
TEST(LtcInvalidPowScore, NInvalidPowSharesReachThresholdAndTrigger)
{
    Scorer s;
    const int N = static_cast<int>(Scorer::BAN_THRESHOLD / Scorer::SCORE_PER_INVALID_POW);
    // Same instant (no decay between them): the first N-1 stay BELOW threshold,
    // and only the Nth reaches it.
    for (int i = 1; i < N; ++i)
        EXPECT_FALSE(s.note_invalid_pow("flooder", 0.0)) << "note " << i;
    EXPECT_TRUE(s.note_invalid_pow("flooder", 0.0)) << "note " << N;
    EXPECT_GE(s.score("flooder", 0.0), Scorer::BAN_THRESHOLD);
}

// ── 2. A handful of invalid shares NEVER bans (no hair-trigger) ──────────────
TEST(LtcInvalidPowScore, AHandfulOfInvalidSharesNeverTriggers)
{
    Scorer s;
    for (int i = 0; i < 5; ++i)
        EXPECT_FALSE(s.note_invalid_pow("noisy", 0.0));
    EXPECT_LT(s.score("noisy", 0.0), Scorer::BAN_THRESHOLD);
}

// ── 3. An honest peer we never charge is never penalized ────────────────────
// Stale/duplicate/orphan/valid shares do not throw SharePoWTargetMiss, so the
// production path never calls note_invalid_pow for them. A peer for whom the
// note is never invoked has score 0 and can never be banned.
TEST(LtcInvalidPowScore, UntrackedHonestPeerHasZeroScoreAndIsNeverPenalized)
{
    Scorer s;
    // Flood a DIFFERENT peer to the threshold...
    for (int i = 0; i < 200; ++i) s.note_invalid_pow("flooder", 0.0);
    // ...the honest peer, never charged, is completely unaffected.
    EXPECT_EQ(s.score("honest", 0.0), 0.0);
    EXPECT_EQ(s.tracked_peers(), 1u);   // only the flooder is tracked
}

// ── 4. Just below threshold is never penalized ──────────────────────────────
TEST(LtcInvalidPowScore, JustBelowThresholdIsNeverPenalized)
{
    Scorer s;
    const int Nminus1 = static_cast<int>(Scorer::BAN_THRESHOLD /
                                         Scorer::SCORE_PER_INVALID_POW) - 1;
    bool tripped = false;
    for (int i = 0; i < Nminus1; ++i)
        tripped = tripped || s.note_invalid_pow("edge", 0.0);
    EXPECT_FALSE(tripped);
    EXPECT_LT(s.score("edge", 0.0), Scorer::BAN_THRESHOLD);
}

// ── 5. Time-decay: a slow trickle spread over the window NEVER bans ─────────
TEST(LtcInvalidPowScore, SlowTrickleDecaysFasterThanItAccumulates)
{
    Scorer s;
    // One invalid share every 60s (well inside the 600s half-life). Even after
    // far more than BAN_THRESHOLD notes, the decayed steady state stays tiny.
    bool tripped = false;
    double t = 0.0;
    for (int i = 0; i < 1000; ++i) { tripped = tripped || s.note_invalid_pow("trickle", t); t += 60.0; }
    EXPECT_FALSE(tripped);
    EXPECT_LT(s.score("trickle", t), Scorer::BAN_THRESHOLD);
    // The same 1000 notes delivered as a BURST (same instant) would have banned,
    // proving it is the SUSTAINED RATE, not the raw count, that matters.
    Scorer burst;
    bool burst_tripped = false;
    for (int i = 0; i < 1000; ++i) burst_tripped = burst_tripped || burst.note_invalid_pow("b", 0.0);
    EXPECT_TRUE(burst_tripped);
}

// ── 6. A past burst decays away, restoring the peer over time ───────────────
TEST(LtcInvalidPowScore, ScoreDecaysTowardZeroAfterBadBehaviourStops)
{
    Scorer s;
    for (int i = 0; i < 50; ++i) s.note_invalid_pow("reformed", 0.0);   // 50, under 100
    const double hot = s.score("reformed", 0.0);
    EXPECT_NEAR(hot, 50.0, 1e-9);
    // Ten half-lives later the score has decayed by 2^-10 (~0.001x).
    const double cold = s.score("reformed", 10.0 * Scorer::HALFLIFE_SECONDS);
    EXPECT_LT(cold, hot * 0.01);
    // prune() drops the now-negligible entry so the map cannot grow unbounded.
    // At 10 half-lives the score (~0.049) is still above the 0.01 default floor;
    // by 20 half-lives (~5e-5) it is well below and the entry is dropped.
    EXPECT_EQ(s.tracked_peers(), 1u);
    s.prune(20.0 * Scorer::HALFLIFE_SECONDS);
    EXPECT_EQ(s.tracked_peers(), 0u);
}

// ── 7. Per-peer isolation + clear() ─────────────────────────────────────────
TEST(LtcInvalidPowScore, PeersAreScoredIndependentlyAndClearResets)
{
    Scorer s;
    for (int i = 0; i < 99; ++i) s.note_invalid_pow("A", 0.0);   // A: just under
    EXPECT_TRUE(s.note_invalid_pow("A", 0.0));                    // A: crosses now
    EXPECT_FALSE(s.note_invalid_pow("B", 0.0));                   // B: one note only
    EXPECT_LT(s.score("B", 0.0), Scorer::BAN_THRESHOLD);
    // After a ban the caller clears A; it starts fresh.
    s.clear("A");
    EXPECT_EQ(s.score("A", 0.0), 0.0);
    EXPECT_FALSE(s.note_invalid_pow("A", 0.0));
}


// ── 8. CATCH-SITE CLASSIFICATION — only a genuine PoW-target miss scores ─────
// Pins the SAME predicate the production ingest catch uses
// (ltc::is_scorable_invalid_pow): a SharePoWTargetMiss scores the peer, a
// structural std::invalid_argument (and any other std::exception) does NOT. A
// regression that broadened the rule — e.g. scoring every std::exception — would
// flip these expectations and fail here.
TEST(LtcInvalidPowScore, OnlyGenuinePowTargetMissIsClassifiedScorable)
{
    // The dedicated type IS-A std::invalid_argument (so pre-existing broad
    // `catch (std::invalid_argument&)` / `catch (std::exception&)` verify-failure
    // handlers keep treating it as a failure) yet is distinguishable from a plain
    // structural reject.
    const ltc::SharePoWTargetMiss pow_miss("share PoW hash does not meet target");
    EXPECT_TRUE(dynamic_cast<const std::invalid_argument*>(&pow_miss) != nullptr);

    EXPECT_TRUE(ltc::is_scorable_invalid_pow(pow_miss));

    const std::invalid_argument structural("bad coinbase size");
    EXPECT_FALSE(ltc::is_scorable_invalid_pow(structural));   // structural -> not scored
    const std::runtime_error other("some other failure");
    EXPECT_FALSE(ltc::is_scorable_invalid_pow(other));        // anything else -> not scored

    // Drive the exact production dispatch (throw -> catch(std::exception&) ->
    // predicate gate -> note) and assert only the PoW miss moves the score.
    Scorer s;
    // Generic on the CONCRETE type so `throw thrown` re-throws the real derived
    // exception (no slicing to std::exception), faithfully reproducing the
    // production path: a share_init_verify throw travels through
    // catch (const std::exception&) and is then gated by the predicate.
    Scorer* sp = &s;
    auto feed = [sp](auto&& thrown, const std::string& ip) {
        try { throw thrown; }
        catch (const std::exception& e) {
            if (ltc::is_scorable_invalid_pow(e)) sp->note_invalid_pow(ip, 0.0);
        }
    };
    feed(structural, "peerX");
    feed(other,      "peerX");
    EXPECT_EQ(s.score("peerX", 0.0), 0.0);           // structural/other never scored
    EXPECT_EQ(s.tracked_peers(), 0u);
    feed(pow_miss, "peerX");
    EXPECT_GT(s.score("peerX", 0.0), 0.0);           // the PoW miss did score
}

}  // namespace
