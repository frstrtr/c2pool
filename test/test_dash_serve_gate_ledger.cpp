// SPDX-License-Identifier: AGPL-3.0-or-later
/// ServeGateLedger cross-restart never-a-reject accounting KAT.
///
/// THE DEFECT THIS PINS (critic, 2026-08-23): the EMBED-GATE roll-up and every
/// ServeGateJournal counter are in-process members fed a process-monotonic
/// steady_clock, so they WIPE on every restart. The dashd-cut acceptance gate
/// is a CUMULATIVE never-a-reject claim spanning >=3 restarts ("the null-arm
/// covered the 4.51% DKG floor, 0 rejects over N heights") — a claim the
/// journal structurally cannot carry across a restart.
///
/// RED (without ServeGateLedger, or with a journal-style wipe): after a
/// simulated restart every cumulative count reads 0 and the never-a-reject span
/// resets, so the standing claim is unprovable.
/// GREEN (with ServeGateLedger): counts survive save→load, epochs increments,
/// the open-segment carry folds exactly once (no double-count), and a reject
/// increments the reject counter AND breaks the never-a-reject span.
///
/// Pure-policy suite: the ledger takes caller-supplied monotonic seconds, no
/// clock of its own; persistence is a real atomic tmp+rename round-trip through
/// a temp file (the JSON companion), never a hand-rebuilt shape.

#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <string>

#include <impl/dash/coin/serve_gate_journal.hpp>
#include <impl/dash/coin/serve_gate_ledger.hpp>
#include <impl/dash/coin/serve_gate_ledger_json.hpp>

using dash::coin::ServeGateJournal;
using dash::coin::ServeGateLedger;
using Arm = ServeGateLedger::Arm;

namespace {

std::string temp_ledger_path(const char* stem) {
    auto p = std::filesystem::temp_directory_path() /
             (std::string("c2pool_ledger_kat_") + stem + "_" +
              std::to_string(::getpid()) + ".json");
    std::filesystem::remove(p);
    return p.string();
}

// A ledger banking the SAME Decision the journal returns must agree with the
// journal's own closed-segment histogram to the second — that is the whole
// point of feeding it Decision.prev_cause_sec rather than a re-derived number.
TEST(DashServeGateLedger, LedgerAndJournalCannotDisagree) {
    ServeGateJournal j(300);
    ServeGateLedger  led;
    const int64_t t0 = 1000;

    // A 40 s qc-plan-underivable segment, then a 10 s dmn-stale segment, then
    // resume. Feed every observation to both; bank the ledger from the journal
    // Decision so they read the same closed-segment durations.
    auto feed_decline = [&](const std::string& cause, int64_t t) {
        auto d = j.observe(false, cause, t);
        led.bank_serve(Arm::Fallback, cause, d, t);
    };
    auto feed_serve = [&](int64_t t) {
        auto d = j.observe(true, "", t);
        led.bank_serve(Arm::EmbeddedReal, "", d, t);
    };

    for (int64_t t = t0; t < t0 + 40; ++t) feed_decline("qc-plan-underivable", t);
    for (int64_t t = t0 + 40; t < t0 + 50; ++t) feed_decline("dmn-stale", t);
    feed_serve(t0 + 50);  // resume: closes the final (dmn-stale) segment

    auto roll = j.rollup(t0 + 50);
    const auto& T = led.totals();
    // off_embedded matches the journal's closed-segment total.
    EXPECT_EQ(T.off_embedded_sec, roll.off_embedded_sec);
    EXPECT_EQ(T.per_cause_sec.at("qc-plan-underivable"), 40);
    EXPECT_EQ(T.per_cause_sec.at("dmn-stale"), 10);
    // observed_sec = wall clock spanned by the banked deltas (t0 .. t0+50).
    EXPECT_EQ(T.observed_sec, 50);
}

// The load-bearing cross-restart test: counts survive save→load, epochs
// increments, and the open-segment carry folds EXACTLY once.
TEST(DashServeGateLedger, CrossRestartPersistsAndFoldsCarryOnce) {
    const std::string path = temp_ledger_path("restart");
    ServeGateJournal j(300);

    // ── epoch 1 ──────────────────────────────────────────────────────────
    ServeGateLedger led1;
    led1.set_writer_commit("deadbeefcafe");
    const int64_t t0 = 500;
    // 20 s serving (embedded_real), banking observed_sec deltas.
    for (int64_t t = t0; t < t0 + 20; ++t) {
        auto d = j.observe(true, "", t);
        led1.bank_serve(Arm::EmbeddedReal, "", d, t);
    }
    // Then decline into an OPEN qc-plan-underivable segment for 30 s, never
    // resumed (the process is about to "crash").
    for (int64_t t = t0 + 20; t < t0 + 50; ++t) {
        auto d = j.observe(false, "qc-plan-underivable", t);
        led1.bank_serve(Arm::Fallback, "qc-plan-underivable", d, t);
    }
    // A won embedded_real block at height 100 (extends the clean span).
    led1.record_block_won(Arm::EmbeddedReal, 100);
    led1.record_rpc_verdict(Arm::EmbeddedReal, 100, /*accepted=*/true, "");

    // Flush: snapshot the open 30 s segment into carry, write-through.
    led1.snapshot_carry_for_flush();
    ASSERT_TRUE(dash::coin::serve_gate_ledger_save(path, led1.totals()));

    const auto T1 = led1.totals();
    EXPECT_EQ(T1.serves_embedded_real, 20u);
    EXPECT_EQ(T1.serves_fallback, 30u);
    EXPECT_EQ(T1.off_embedded_sec, 0);         // segment still OPEN, not banked
    EXPECT_EQ(T1.carry_sec, 29);               // open-segment partial in carry
    EXPECT_EQ(T1.carry_cause, "qc-plan-underivable");
    EXPECT_EQ(T1.epochs, 0u);                  // not loaded yet
    EXPECT_EQ(T1.blocks_won_embedded_real, 1u);

    // ── restart: epoch 2 ─────────────────────────────────────────────────
    ServeGateLedger::Totals loaded;
    ASSERT_TRUE(dash::coin::serve_gate_ledger_load(path, loaded));
    ServeGateLedger led2;
    led2.load(loaded);
    const auto& T2 = led2.totals();

    // Counts SURVIVED the restart (the journal cannot do this).
    EXPECT_EQ(T2.serves_embedded_real, 20u);
    EXPECT_EQ(T2.serves_fallback, 30u);
    EXPECT_EQ(T2.blocks_won_embedded_real, 1u);
    EXPECT_EQ(T2.observed_sec, T1.observed_sec);        // wall clock preserved
    EXPECT_EQ(T2.last_writer_commit, "deadbeefcafe");
    // epochs incremented.
    EXPECT_EQ(T2.epochs, 1u);
    // Carry folded exactly once into the cumulative total, then cleared.
    EXPECT_EQ(T2.off_embedded_sec, 29);
    EXPECT_EQ(T2.per_cause_sec.at("qc-plan-underivable"), 29);
    EXPECT_EQ(T2.carry_sec, 0);
    EXPECT_TRUE(T2.carry_cause.empty());

    // ── save again + load AGAIN: the carry must NOT fold a second time ────
    ASSERT_TRUE(dash::coin::serve_gate_ledger_save(path, led2.totals()));
    ServeGateLedger::Totals loaded2;
    ASSERT_TRUE(dash::coin::serve_gate_ledger_load(path, loaded2));
    ServeGateLedger led3;
    led3.load(loaded2);
    const auto& T3 = led3.totals();
    EXPECT_EQ(T3.off_embedded_sec, 29);                 // NOT 58 — no double-count
    EXPECT_EQ(T3.per_cause_sec.at("qc-plan-underivable"), 29);
    EXPECT_EQ(T3.epochs, 2u);                           // three lifetimes total

    std::filesystem::remove(path);
}

// A reject increments the per-arm reject counter AND breaks the never-a-reject
// span; the never_a_reject() cut gate flips false and stays false.
TEST(DashServeGateLedger, RejectBreaksNeverARejectSpan) {
    ServeGateLedger led;
    EXPECT_TRUE(led.never_a_reject());
    EXPECT_EQ(led.clean_span_heights(), 0u);

    // Clean run: three embedded blocks accepted over heights 2000..2002.
    for (uint64_t h = 2000; h <= 2002; ++h) {
        led.record_block_won(Arm::EmbeddedReal, h);
        led.record_rpc_verdict(Arm::EmbeddedReal, h, /*accepted=*/true, "");
    }
    EXPECT_TRUE(led.never_a_reject());
    EXPECT_EQ(led.clean_span_heights(), 3u);            // 2000..2002 inclusive
    EXPECT_EQ(led.totals().nr_total_rejects, 0u);

    // A reject on an embedded_real block at 2003.
    led.record_block_won(Arm::EmbeddedReal, 2003);
    led.record_rpc_verdict(Arm::EmbeddedReal, 2003, /*accepted=*/false,
                           "bad-cb-payee");
    EXPECT_FALSE(led.never_a_reject());                 // hard gate tripped
    EXPECT_EQ(led.totals().rpc_rejected_embedded_real, 1u);
    EXPECT_EQ(led.totals().nr_total_rejects, 1u);
    EXPECT_EQ(led.totals().nr_last_reject_height, 2003u);
    EXPECT_EQ(led.totals().rpc_reject_reasons.at("bad-cb-payee"), 1u);
    // Span reset by the reject.
    EXPECT_EQ(led.clean_span_heights(), 0u);
}

// A validity-attributable orphan on an embedded arm is a SILENT reject: it
// breaks the span too. A race orphan (validity_attributable=false) does not.
TEST(DashServeGateLedger, ValidityOrphanBreaksSpanRaceOrphanDoesNot) {
    ServeGateLedger led;
    led.record_block_won(Arm::EmbeddedNull, 3000);
    led.record_block_won(Arm::EmbeddedNull, 3001);
    EXPECT_EQ(led.clean_span_heights(), 2u);

    // Race orphan: disambiguated by the RPC verdict as NOT validity-caused.
    led.record_orphan(Arm::EmbeddedNull, 3001, /*validity_attributable=*/false);
    EXPECT_TRUE(led.never_a_reject());
    EXPECT_EQ(led.clean_span_heights(), 2u);            // untouched

    // Validity orphan: a silent reject on the null arm.
    led.record_orphan(Arm::EmbeddedNull, 3001, /*validity_attributable=*/true);
    EXPECT_FALSE(led.never_a_reject());
    EXPECT_EQ(led.totals().orphaned_embedded_null, 1u);
    EXPECT_EQ(led.clean_span_heights(), 0u);
}

// Null-arm first class: a null served where NO real quorum existed is the
// correct DKG-floor case; a null served where a real quorum WAS available is
// the defect the cut gate forbids (must stay 0).
TEST(DashServeGateLedger, NullArmDkgFloorVsRealQuorumAvailable) {
    ServeGateLedger led;
    ServeGateJournal j(300);
    auto d = j.observe(true, "", 10);  // a serving decision

    // Correct: null over the DKG floor, no real quorum available.
    led.bank_serve(Arm::EmbeddedNull, "", d, 10, /*real_quorum_available=*/false);
    EXPECT_EQ(led.totals().serves_embedded_null, 1u);
    EXPECT_EQ(led.totals().null_dkg_floor_tips_served, 1u);
    EXPECT_EQ(led.totals().null_real_quorum_available_but_null_served, 0u);

    // Defect: a null served while a real committed quorum existed.
    led.bank_serve(Arm::EmbeddedNull, "", d, 11, /*real_quorum_available=*/true);
    EXPECT_EQ(led.totals().null_dkg_floor_tips_served, 1u);
    EXPECT_EQ(led.totals().null_real_quorum_available_but_null_served, 1u);
}

// observed_sec accumulates DELTAS, so it is monotone across a restart and never
// depends on the absolute (process-monotonic) clock value. A second process
// whose clock starts far lower must still ADD its wall clock, not reset.
TEST(DashServeGateLedger, ObservedSecIsDeltaAccumulatedAcrossRestart) {
    ServeGateJournal j(300);

    ServeGateLedger a;
    for (int64_t t = 9000; t < 9010; ++t)  // process A clock: high
        a.bank_serve(Arm::EmbeddedReal, "", j.observe(true, "", t), t);
    EXPECT_EQ(a.totals().observed_sec, 9);

    // Restart: process B clock starts LOW (5). Deltas, not absolutes.
    ServeGateLedger b;
    b.load(a.totals());
    EXPECT_EQ(b.totals().observed_sec, 9);              // carried forward
    ServeGateJournal j2(300);
    for (int64_t t = 5; t < 15; ++t)                    // 9 s more
        b.bank_serve(Arm::EmbeddedReal, "", j2.observe(true, "", t), t);
    EXPECT_EQ(b.totals().observed_sec, 18);             // 9 + 9, monotone
}

}  // namespace
