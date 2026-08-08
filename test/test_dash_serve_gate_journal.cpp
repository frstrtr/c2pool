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

}  // namespace
