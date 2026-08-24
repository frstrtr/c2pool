// SPDX-License-Identifier: AGPL-3.0-or-later
// KAT: PR-1 LATENCY-AWARE PEER SCORING (dashd-cut coin-P2P stack).
//
// Locks the two guarantees the reward-safety argument rests on, exercising the
// REAL dash::coin::DashPeerInfo::compute_score() (not a re-implementation):
//
//   (1) FLAG DEFAULT-OFF => BYTE-IDENTICAL TO MASTER. With the flag off, a peer
//       carrying arbitrary delivery-latency / ping-RTT samples scores EXACTLY
//       what the same peer with no samples scores — the latency term is 0, so
//       compute_score() reproduces master's value bit for bit. This is the
//       whole default-OFF safety claim, asserted directly.
//
//   (2) FLAG ON => the faster deliverer RANKS UP, as a BOUNDED, CLAMPED
//       tie-breaker. Two peers identical in every structural field but their
//       measured latency: the faster one scores strictly higher. The term is
//       monotonically decreasing in latency, clamped to +/-kLatencyScoreMax,
//       and the source preference (tip_body > other delivery class > ping RTT)
//       is exercised. The term NEVER changes eligibility — it is only ever
//       added to an already-computed score, so it can only reorder preference
//       within the eligible set.
//
// Header-only subject (coin_peer_manager.hpp is a dash coin leaf); links the
// core lib for NetService. Built under -DC2POOL_DASH_BLS=ON like the dash suite.

#include <impl/dash/coin/coin_peer_manager.hpp>

#include <cstdio>

using dash::coin::DashPeerInfo;
using dash::coin::DatumClass;
using dash::coin::peer_latency_score_enabled;
using dash::coin::set_peer_latency_score_enabled;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

// A default coin-daemon-learned peer: the deterministic baseline the master
// formula scores. No samples, no successes; every field left at its default so
// two of them are guaranteed to score identically.
static DashPeerInfo make_default_peer()
{
    DashPeerInfo p;
    p.source = DashPeerInfo::Source::coind;
    return p;
}

int main()
{
    // The emit flag must start OFF (the byte-identical-to-master guarantee).
    CHECK(peer_latency_score_enabled() == false);

    // ── MASTER BASELINE (flag OFF, no samples) ───────────────────────────────
    const int master_score = make_default_peer().compute_score();

    // ── (1) FLAG OFF => LATENCY IS INVISIBLE (byte-identical to master) ───────
    {
        DashPeerInfo fast = make_default_peer();
        fast.record_delivery(DatumClass::TipBody, 5);      // very fast
        fast.record_delivery(DatumClass::MnListDiff, 10);
        fast.record_ping_rtt(3);
        DashPeerInfo slow = make_default_peer();
        slow.record_delivery(DatumClass::TipBody, 5000);   // very slow
        slow.record_ping_rtt(9000);

        // Samples recorded, flag OFF: term is 0 for both, score == master.
        CHECK(fast.latency_score_term() == 0);
        CHECK(slow.latency_score_term() == 0);
        CHECK(fast.compute_score() == master_score);
        CHECK(slow.compute_score() == master_score);
        CHECK(fast.compute_score() == slow.compute_score());
    }

    // ── (2) FLAG ON => faster deliverer ranks up (bounded, clamped) ──────────
    set_peer_latency_score_enabled(true);
    CHECK(peer_latency_score_enabled() == true);

    {
        // Two peers identical but for tip_body delivery latency.
        DashPeerInfo fast = make_default_peer();
        fast.record_delivery(DatumClass::TipBody, 40);     // (200-40)*25/200 = 20
        DashPeerInfo slow = make_default_peer();
        slow.record_delivery(DatumClass::TipBody, 400);    // (200-400)*25/200 = -25

        CHECK(fast.latency_score_term() == 20);
        CHECK(slow.latency_score_term() == -25);
        CHECK(fast.compute_score() == master_score + 20);
        CHECK(slow.compute_score() == master_score - 25);
        // The reward-safe claim: the faster deliverer ranks strictly up.
        CHECK(fast.compute_score() > slow.compute_score());
    }

    // Exact term at the reference latency and the clamp boundaries.
    {
        DashPeerInfo ref = make_default_peer();
        ref.record_delivery(DatumClass::TipBody, 200);     // exactly reference
        CHECK(ref.latency_score_term() == 0);
        CHECK(ref.compute_score() == master_score);        // neutral, == master

        DashPeerInfo instant = make_default_peer();
        instant.record_delivery(DatumClass::TipBody, 0);   // (200-0)*25/200 = 25
        CHECK(instant.latency_score_term() == 25);         // = +max, not above

        DashPeerInfo glacial = make_default_peer();
        glacial.record_delivery(DatumClass::TipBody, 5000);// would be -600
        CHECK(glacial.latency_score_term() == -25);        // clamped at -max
    }

    // No sample at all, flag ON: neutral term (never penalises the unmeasured).
    {
        DashPeerInfo blank = make_default_peer();
        CHECK(blank.latency_score_term() == 0);
        CHECK(blank.compute_score() == master_score);
    }

    // Source preference: tip_body > other delivery class > ping RTT.
    {
        // Only a non-tip delivery class measured => it is used.
        DashPeerInfo mn_only = make_default_peer();
        mn_only.record_delivery(DatumClass::MnListDiff, 100); // (200-100)*25/200 = 12
        CHECK(mn_only.representative_latency_ms() == 100);
        CHECK(mn_only.latency_score_term() == 12);

        // Only ping RTT measured => it is the fallback.
        DashPeerInfo ping_only = make_default_peer();
        ping_only.record_ping_rtt(300);                       // (200-300)*25/200 = -12
        CHECK(ping_only.representative_latency_ms() == 300);
        CHECK(ping_only.latency_score_term() == -12);

        // tip_body present alongside a SLOW mnlistdiff => tip_body wins.
        DashPeerInfo tip_pref = make_default_peer();
        tip_pref.record_delivery(DatumClass::TipBody, 50);
        tip_pref.record_delivery(DatumClass::MnListDiff, 1000);
        CHECK(tip_pref.representative_latency_ms() == 50);     // not 1000
        CHECK(tip_pref.latency_score_term() == 18);            // (200-50)*25/200

        // Fastest of several non-tip classes is chosen when tip is absent.
        DashPeerInfo multi = make_default_peer();
        multi.record_delivery(DatumClass::MnListDiff, 300);
        multi.record_delivery(DatumClass::QrInfo, 120);
        CHECK(multi.representative_latency_ms() == 120);       // min of the two
    }

    // Monotonicity across a latency sweep (faster is never scored worse).
    {
        int prev_term = 1000;  // above any possible term
        for (int64_t lat = 0; lat <= 600; lat += 25) {
            DashPeerInfo p = make_default_peer();
            p.record_delivery(DatumClass::TipBody, lat);
            const int t = p.latency_score_term();
            CHECK(t <= prev_term);                    // non-increasing in latency
            CHECK(t <= DashPeerInfo::kLatencyScoreMax);
            CHECK(t >= -DashPeerInfo::kLatencyScoreMax);
            prev_term = t;
        }
    }

    // ── (3) FLAG OFF AGAIN => back to byte-identical to master ────────────────
    set_peer_latency_score_enabled(false);
    CHECK(peer_latency_score_enabled() == false);
    {
        DashPeerInfo fast = make_default_peer();
        fast.record_delivery(DatumClass::TipBody, 1);
        CHECK(fast.latency_score_term() == 0);
        CHECK(fast.compute_score() == master_score);
    }

    if (g_fail == 0) { std::printf("dash_latency_scoring_kat PASS\n"); return 0; }
    std::printf("dash_latency_scoring_kat FAIL (%d)\n", g_fail);
    return 1;
}
