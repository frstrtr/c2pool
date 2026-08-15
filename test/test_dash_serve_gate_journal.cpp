// SPDX-License-Identifier: AGPL-3.0-or-later
/// ServeGateJournal per-cause time KAT.
///
/// THE DEFECT THIS PINS (measured at h=2518004, hotel, 2026-08-07): a
/// cause-change line attributes the WHOLE episode's duration to the cause it
/// names. A 512 s qc-plan-underivable episode that flips to
/// emit-bestcl-null-committed for its last ~1 s emits
///
///     trigger=cause-change cause=emit-bestcl-null-committed dur=512s
///
/// so every per-cause TIME histogram built from dur= is wrong: by count
/// emit-bestcl-null-committed read as 29% of the remaining gap; by time it is
/// 0.065% of wall clock while qc-plan-underivable owns 87% of decline time.
/// The prioritisation inverted on exactly this line.
///
/// episode_sec keeps its deliberate whole-episode semantics (it must NOT
/// shrink at a cause change — that is documented behaviour). The fix is two
/// fields BESIDE it:
///
///   cause_sec       — how long THIS line's cause has been the first-unmet
///                     condition (0 at a segment start, grows on heartbeats);
///   prev_cause_sec  — the duration of the segment a CauseChange/Resumed line
///                     CLOSES, attributed to previous_cause.
///
/// Suite is pure-policy: the journal takes caller-supplied monotonic seconds,
/// no I/O, no clock.

#include <gtest/gtest.h>

#include <impl/dash/coin/serve_gate_journal.hpp>
#include <impl/dash/coin/serve_gate_rollup_json.hpp>

#include <string>

using dash::coin::ServeGateJournal;
using Trigger = ServeGateJournal::Trigger;

namespace {

/// The h=2518004 scenario, verbatim: 512 s of qc-plan-underivable, then ONE
/// second of emit-bestcl-null-committed, then the arm resumes.
TEST(DashServeGateJournal, CauseChangeCarriesPerCauseTimeNotEpisodeTime) {
    ServeGateJournal j(300);  // production heartbeat
    const int64_t t0 = 1000;

    // t0 .. t0+511: qc-plan-underivable, one observation per second.
    auto first = j.observe(false, "qc-plan-underivable", t0);
    EXPECT_EQ(first.trigger, Trigger::First);
    for (int64_t t = t0 + 1; t < t0 + 512; ++t)
        j.observe(false, "qc-plan-underivable", t);

    // t0+512: the cause flips. THE line that used to mislead.
    auto change = j.observe(false, "emit-bestcl-null-committed", t0 + 512);
    ASSERT_EQ(change.trigger, Trigger::CauseChange);
    ASSERT_TRUE(change.emit());

    // Episode semantics UNCHANGED: whole-episode duration, from the first
    // decline, surviving the cause change. Removing/redefining this is a
    // regression, not a fix.
    EXPECT_EQ(change.episode_sec, 512);

    // THE FIX: the per-cause clock of the cause this line NAMES is ~0-1 s,
    // DISTINCT from the 512 s episode. On master this fails: Decision has no
    // cause_sec and the only duration on the line is 512.
    EXPECT_GE(change.cause_sec, 0);
    EXPECT_LE(change.cause_sec, 1);
    EXPECT_NE(change.cause_sec, change.episode_sec);

    // And the 512 s is attributed where it belongs: to the segment this line
    // CLOSES, named by previous_cause.
    EXPECT_EQ(change.previous_cause, "qc-plan-underivable");
    EXPECT_EQ(change.prev_cause_sec, 512);

    // t0+513: the arm resumes. The final segment (emit-bestcl-null-committed)
    // closes at 1 s — not 513.
    auto resumed = j.observe(true, "", t0 + 513);
    ASSERT_EQ(resumed.trigger, Trigger::Resumed);
    EXPECT_EQ(resumed.episode_sec, 513);  // whole episode, unchanged semantics
    EXPECT_EQ(resumed.previous_cause, "emit-bestcl-null-committed");
    EXPECT_EQ(resumed.prev_cause_sec, 1);
    EXPECT_EQ(resumed.cause_sec, -1);  // no active cause on a Resumed line
}

/// Per-cause segment durations must SUM to the episode: three causes, three
/// closures, no time lost or double-counted.
TEST(DashServeGateJournal, SegmentDurationsPartitionTheEpisode) {
    ServeGateJournal j(1000000);  // heartbeat effectively off
    const int64_t t0 = 50;

    j.observe(false, "cause-a", t0);                       // First
    auto c1 = j.observe(false, "cause-b", t0 + 10);        // a ran 10 s
    auto c2 = j.observe(false, "cause-c", t0 + 10 + 25);   // b ran 25 s
    auto r  = j.observe(true, "", t0 + 10 + 25 + 7);       // c ran 7 s

    ASSERT_EQ(c1.trigger, Trigger::CauseChange);
    ASSERT_EQ(c2.trigger, Trigger::CauseChange);
    ASSERT_EQ(r.trigger, Trigger::Resumed);

    EXPECT_EQ(c1.prev_cause_sec, 10);
    EXPECT_EQ(c2.prev_cause_sec, 25);
    EXPECT_EQ(r.prev_cause_sec, 7);
    EXPECT_EQ(c1.prev_cause_sec + c2.prev_cause_sec + r.prev_cause_sec,
              r.episode_sec);

    // Each cause-change line's own cause starts at zero.
    EXPECT_EQ(c1.cause_sec, 0);
    EXPECT_EQ(c2.cause_sec, 0);
}

/// A heartbeat of an UNCHANGED cause reports a growing per-cause clock (here
/// it equals the episode clock, because the episode has had one cause).
TEST(DashServeGateJournal, HeartbeatGrowsTheCauseClock) {
    ServeGateJournal j(300);
    const int64_t t0 = 0;

    j.observe(false, "dmn-stale", t0);
    auto hb = j.observe(false, "dmn-stale", t0 + 300);
    ASSERT_EQ(hb.trigger, Trigger::Heartbeat);
    EXPECT_EQ(hb.cause_sec, 300);
    EXPECT_EQ(hb.episode_sec, 300);
    EXPECT_EQ(hb.prev_cause_sec, -1);  // closes nothing
}

/// After a Resumed, a NEW episode's clocks both restart: no bleed of the
/// previous episode's 500 s into the new segment.
TEST(DashServeGateJournal, ClocksResetAcrossEpisodes) {
    ServeGateJournal j(300);

    j.observe(false, "cause-a", 100);
    j.observe(true, "", 600);                       // episode 1: 500 s
    auto t = j.observe(false, "cause-b", 700);      // episode 2 begins
    ASSERT_EQ(t.trigger, Trigger::Transition);
    EXPECT_EQ(t.episode_sec, 0);
    EXPECT_EQ(t.cause_sec, 0);
    EXPECT_EQ(t.prev_cause_sec, -1);  // previous segment closed by Resumed

    auto r = j.observe(true, "", 760);
    EXPECT_EQ(r.episode_sec, 60);
    EXPECT_EQ(r.prev_cause_sec, 60);
    EXPECT_EQ(r.previous_cause, "cause-b");
}

/// Serving-only history never invents a cause clock.
TEST(DashServeGateJournal, ServingLinesCarryNoCauseClock) {
    ServeGateJournal j(300);
    auto d = j.observe(true, "", 10);
    EXPECT_FALSE(d.emit());
    EXPECT_EQ(d.cause_sec, -1);
    EXPECT_EQ(d.prev_cause_sec, -1);
    EXPECT_EQ(d.episode_sec, -1);
}

/// THE THIRD-ARM DEFECT THIS PINS (daemonless soak, reconstructing the
/// integrator's 2026-08-09 three-edit spec): the serve gate knew only two arm
/// states, EMBEDDED and dashd-fallback, and recorded the THIRD real state --
/// SET-GAP / NO-WORK, where NEITHER arm produced a mineable template (the
/// disposition predicate m_bits==0 || previous_block.IsNull(), nothing is
/// served) -- as a plain "dashd-fallback DECLINED". A fallback serve and an
/// honest absence read IDENTICALLY, so an operator could not tell a node that
/// was serving real dashd templates from one serving nothing at all.
///
/// The fix is the three-valued observe(Served): NoWork shares the decline
/// path's timing with Fallback EXACTLY (both are off the embedded arm) but
/// carries a distinct disposition, so arm_name()/no_work() separate them while
/// every episode/partition invariant above is preserved.
///
/// RED ON MASTER: master's ServeGateJournal has no Served enum, so this TU does
/// not COMPILE there -- the intended failure this branch turns green.
TEST(DashServeGateJournal, NoWorkIsTheDistinctThirdArmState) {
    using Served = ServeGateJournal::Served;
    ServeGateJournal j(300);
    const int64_t t0 = 2000;

    // A genuine dashd-fallback serve: off the embedded arm, but a template WAS
    // served. The arm names the fallback, and it is NOT the no-work state.
    auto fb = j.observe(Served::Fallback, "qc-plan-underivable", t0);
    EXPECT_EQ(fb.trigger, Trigger::First);
    EXPECT_FALSE(j.no_work());
    EXPECT_STREQ(j.arm_name(), "dashd-fallback");

    // The arm flips to SET-GAP: neither arm produced mineable work. The
    // DISPOSITION changed, and that is the third state the journal must now
    // name distinctly from the fallback above.
    auto ng = j.observe(Served::NoWork, "set-gap", t0 + 5);
    EXPECT_TRUE(ng.emit());
    EXPECT_TRUE(j.no_work());
    EXPECT_STREQ(j.arm_name(), "none(set-gap/no-work)");
    EXPECT_STRNE(j.arm_name(), "dashd-fallback");

    // Timing STILL partitions: NoWork rides the identical decline path, so the
    // episode survives the disposition change (whole-episode semantics) and the
    // fallback segment it closes is attributed to the previous cause.
    ASSERT_EQ(ng.trigger, Trigger::CauseChange);
    EXPECT_EQ(ng.episode_sec, 5);
    EXPECT_EQ(ng.previous_cause, "qc-plan-underivable");
    EXPECT_EQ(ng.prev_cause_sec, 5);
    EXPECT_EQ(ng.cause_sec, 0);

    // Resuming onto the embedded arm clears the third state.
    auto up = j.observe(Served::Embedded, "", t0 + 12);
    ASSERT_EQ(up.trigger, Trigger::Resumed);
    EXPECT_FALSE(j.no_work());
    EXPECT_STREQ(j.arm_name(), "embedded");
    EXPECT_EQ(up.episode_sec, 12);
    EXPECT_EQ(up.previous_cause, "set-gap");
    EXPECT_EQ(up.prev_cause_sec, 7);
}

// ── #119 FOLLOW-UP: cumulative per-cause TIME roll-up with a denominator ─────
//
// THE DEFECT THIS PINS (soak-dl-master, 2026-08-09, 36,854 s window): the
// serve-gate log carried a duration for ONLY qc-plan-underivable; the cause
// with 10x the episodes (creditpool-stale, 107 episodes) carried NONE, so
// "what fraction of wall clock did each cause cost" was unanswerable and every
// serving-percentage claim rested on episode COUNTS. counts and seconds are not
// commensurable. The fix is a cumulative roll-up that (1) attributes seconds to
// EVERY cause and (2) prints the DENOMINATOR (wall clock observed) so a share
// is never implicit.

using Rollup = ServeGateJournal::Rollup;

// A short, high-count cause and a long, low-count cause — the brief's shape.
// By count creditpool-stale dominates (many episodes); by TIME qc-plan owns the
// loss. The roll-up must attribute NON-ZERO seconds to the high-count cause AND
// rank by time, not count.
TEST(DashServeGateJournal, RollupAttributesTimePerCauseNotCount) {
    ServeGateJournal j(1000000);  // heartbeat off; segments still bank on close
    int64_t t = 0;

    // 20 creditpool-stale episodes, ~1 s each (the "107 episodes, 0 s" cause):
    // each is decline -> resume, so each segment closes and banks ~1 s.
    for (int i = 0; i < 20; ++i) {
        j.observe(false, "creditpool-stale", t);
        j.observe(true, "", t + 1);
        t += 60;  // 59 s of serving between episodes
    }
    // ONE qc-plan-underivable episode of 500 s (few episodes, most of the loss).
    j.observe(false, "qc-plan-underivable", t);
    j.observe(true, "", t + 500);
    t += 500;

    const int64_t now = t + 10;  // arm serving now
    Rollup r = j.rollup(now);

    // Denominator present and is the WHOLE observed window, not just decline time.
    EXPECT_EQ(r.observed_sec, now);           // first observation was at t=0
    EXPECT_GT(r.observed_sec, r.off_embedded_sec);  // most of it was serving

    // BOTH causes carry seconds — the high-count cause is no longer 0 s.
    ASSERT_EQ(r.per_cause.size(), 2u);
    int64_t credit = 0, qc = 0;
    for (const auto& c : r.per_cause) {
        if (c.first == "creditpool-stale")    credit = c.second;
        if (c.first == "qc-plan-underivable") qc     = c.second;
    }
    EXPECT_EQ(credit, 20);   // 20 episodes x ~1 s
    EXPECT_EQ(qc, 500);

    // Ranked by TIME: qc-plan first despite having 1/20th the episode count.
    EXPECT_EQ(r.per_cause.front().first, "qc-plan-underivable");
    // Numerators sum to off_embedded (no time lost or double-counted).
    EXPECT_EQ(credit + qc, r.off_embedded_sec);
    EXPECT_EQ(r.off_embedded_sec, 520);
}

// A roll-up read MID-EPISODE includes the in-progress segment's partial, so a
// long-running cause is never undercounted until it happens to close.
TEST(DashServeGateJournal, RollupIncludesOpenSegmentPartial) {
    ServeGateJournal j(1000000);
    j.observe(false, "cause-a", 100);          // segment opens at 100, still open
    Rollup r = j.rollup(250);                   // 150 s into the open segment
    ASSERT_EQ(r.per_cause.size(), 1u);
    EXPECT_EQ(r.per_cause.front().first, "cause-a");
    EXPECT_EQ(r.per_cause.front().second, 150);
    EXPECT_EQ(r.off_embedded_sec, 150);
    EXPECT_EQ(r.observed_sec, 150);             // denominator = 250 - first obs (100)

    // The same cause re-observed across a cause change accumulates, and the open
    // partial does not double-count what already closed.
    j.observe(false, "cause-b", 260);           // closes cause-a segment (160 s)
    Rollup r2 = j.rollup(300);                   // cause-b open 40 s
    int64_t a = 0, b = 0;
    for (const auto& c : r2.per_cause) {
        if (c.first == "cause-a") a = c.second;
        if (c.first == "cause-b") b = c.second;
    }
    EXPECT_EQ(a, 160);   // closed segment, banked once
    EXPECT_EQ(b, 40);    // open partial
    EXPECT_EQ(r2.off_embedded_sec, 200);
}

// The denominator is wall clock since the FIRST observation, serving included.
TEST(DashServeGateJournal, RollupDenominatorIsObservedWallClock) {
    ServeGateJournal j(300);
    j.observe(true, "", 1000);                  // first observation: serving
    j.observe(false, "cause-a", 1010);          // 10 s of serving, then decline
    j.observe(true, "", 1015);                  // 5 s declining
    Rollup r = j.rollup(1020);
    EXPECT_EQ(r.observed_sec, 20);              // 1020 - 1000
    EXPECT_EQ(r.off_embedded_sec, 5);           // only the 5 s decline segment
    ASSERT_EQ(r.per_cause.size(), 1u);
    EXPECT_EQ(r.per_cause.front().second, 5);
}

// An empty journal names no cause and invents no denominator.
TEST(DashServeGateJournal, RollupEmptyBeforeAnyObservation) {
    ServeGateJournal j(300);
    Rollup r = j.rollup(500);
    EXPECT_EQ(r.observed_sec, 0);
    EXPECT_EQ(r.off_embedded_sec, 0);
    EXPECT_TRUE(r.per_cause.empty());
}

// seg_terminal_name gives every CLOSING decision a qc-shaped terminal, and
// nullptr for decisions that close no segment.
TEST(DashServeGateJournal, SegTerminalNamesCoverClosuresOnly) {
    using Trig = ServeGateJournal::Trigger;
    EXPECT_STREQ(ServeGateJournal::seg_terminal_name(Trig::Resumed), "resumed");
    EXPECT_STREQ(ServeGateJournal::seg_terminal_name(Trig::CauseChange),
                 "cause-change");
    EXPECT_EQ(ServeGateJournal::seg_terminal_name(Trig::Heartbeat), nullptr);
    EXPECT_EQ(ServeGateJournal::seg_terminal_name(Trig::First), nullptr);
    EXPECT_EQ(ServeGateJournal::seg_terminal_name(Trig::Transition), nullptr);
    EXPECT_EQ(ServeGateJournal::seg_terminal_name(Trig::None), nullptr);

    // The closing decisions the consumer emits a [EMBED-GATE-SEG] line for carry
    // BOTH a non-null terminal and a prev_cause_sec — they always co-occur.
    ServeGateJournal j(300);
    j.observe(false, "cause-a", 0);
    auto change = j.observe(false, "cause-b", 10);
    EXPECT_STREQ(ServeGateJournal::seg_terminal_name(change.trigger),
                 "cause-change");
    EXPECT_EQ(change.prev_cause_sec, 10);
    auto resumed = j.observe(true, "", 25);
    EXPECT_STREQ(ServeGateJournal::seg_terminal_name(resumed.trigger),
                 "resumed");
    EXPECT_EQ(resumed.prev_cause_sec, 15);
}

// ── #119 follow-up, WEB LEG: the JSON shape the operator surface publishes ───
//
// serve_gate_rollup_json is the ONE serializer shared by
// DASHWorkSource::embedded_arm_status_json (the `gate_rollup` field, forwarded
// by /api/node_topology as `serve_gate_rollup`) and this KAT — so this test
// pins the bytes the web actually serves, not a hand-rebuilt lookalike. Shape:
// {observed_sec, off_embedded_sec, per_cause:[{cause,sec}...]} with per_cause
// preserving the roll-up's by-TIME order. The web surface previously published
// only arm + last cause/value/threshold — count-shaped — which is the exact
// trap #119 closed in the log (by count dmn-stale looked like 97% of the
// problem; by time it was 5.6 s vs 351 s).
TEST(DashServeGateJournal, RollupJsonShapePinsTheWebField) {
    ServeGateJournal j(1000000);
    // 20 s of cause-b (closed), then cause-a open for 500 s: a ranks first.
    j.observe(false, "cause-b", 0);
    j.observe(false, "cause-a", 20);        // closes b at 20 s, opens a
    const int64_t now = 520;                 // a has 500 s of open partial

    nlohmann::json json = dash::coin::serve_gate_rollup_json(j.rollup(now));

    // The three fields, exactly — the denominator is never omitted.
    ASSERT_TRUE(json.contains("observed_sec"));
    ASSERT_TRUE(json.contains("off_embedded_sec"));
    ASSERT_TRUE(json.contains("per_cause"));
    EXPECT_EQ(json.size(), 3u);
    EXPECT_EQ(json["observed_sec"].get<int64_t>(), 520);
    EXPECT_EQ(json["off_embedded_sec"].get<int64_t>(), 520);

    // per_cause: array of {cause,sec}, ranked by TIME desc (a=500 before b=20)
    // — the same order the [EMBED-GATE-ROLLUP] log line prints.
    const auto& pc = json["per_cause"];
    ASSERT_TRUE(pc.is_array());
    ASSERT_EQ(pc.size(), 2u);
    EXPECT_EQ(pc[0]["cause"].get<std::string>(), "cause-a");
    EXPECT_EQ(pc[0]["sec"].get<int64_t>(), 500);
    EXPECT_EQ(pc[1]["cause"].get<std::string>(), "cause-b");
    EXPECT_EQ(pc[1]["sec"].get<int64_t>(), 20);
    EXPECT_EQ(pc[0].size(), 2u);  // {cause,sec} only — no extra fields

    // An unobserved journal serializes the honest empty shape, not fabricated
    // zeros-with-causes: empty array, zero denominator.
    ServeGateJournal fresh(300);
    nlohmann::json empty = dash::coin::serve_gate_rollup_json(fresh.rollup(99));
    EXPECT_EQ(empty["observed_sec"].get<int64_t>(), 0);
    EXPECT_EQ(empty["off_embedded_sec"].get<int64_t>(), 0);
    EXPECT_TRUE(empty["per_cause"].is_array());
    EXPECT_TRUE(empty["per_cause"].empty());
}

}  // namespace
