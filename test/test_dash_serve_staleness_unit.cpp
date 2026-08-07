// SPDX-License-Identifier: AGPL-3.0-or-later
// dash::coin::ServeStalenessSentinel — the detector itself, driven off a FAKE
// clock and INJECTED heights.
//
// The brief this ships under is explicit that a compile-and-run RED of a class
// that does not exist on master is impossible, and says to say so rather than
// fake one. So the red witness for this change is the SEAM test
// (test_dash_serve_staleness_seam.cpp), which compiles against master and fails
// there. This file carries the OTHER half of the same obligation: proving the
// detector can FAIL — i.e. that the assertions here depend on the guard and not
// on the shape of the test.
//
// That is not a hypothetical concern on this repo. This week a KAT shipped that
// still passed with the guard it "tested" deleted. So the induced-skew case is
// run TWICE: once with the real threshold (must alarm) and once with the
// threshold neutered to the deleted-guard value (must NOT alarm). If the
// comparison were dead code, the second run would alarm too and this file would
// red.
//
// Numbers are the incident's, verbatim: served h=2518006, network h=2518028.

#include <impl/dash/coin/serve_staleness.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <limits>
#include <string>

namespace {

using dash::coin::ServeStalenessConfig;
using dash::coin::ServeStalenessSample;
using dash::coin::ServeStalenessSentinel;
using dash::coin::StaleServeCheck;

constexpr uint32_t kServedDead = 2518006u;   // what 26 rigs were given
constexpr uint32_t kNetwork    = 2518028u;   // where dashd actually was

// A fake clock. Nothing in the sentinel reads a real one — every input arrives
// through poll(), which is the property that makes an hour-long incident
// reproducible in microseconds.
struct FakeClock {
    int64_t t{1'000'000};
    int64_t advance(int64_t ms) { t += ms; return t; }
    int64_t now() const { return t; }
};

// A HEALTHY node: io ticking every second, template handed out every second at
// the network's own height, miners attached.
ServeStalenessSample healthy(const FakeClock& c, uint32_t h)
{
    ServeStalenessSample s;
    s.now_ms          = c.now();
    s.io_heartbeat_ms = c.now();
    s.served_height   = h;
    s.served_at_ms    = c.now();
    s.observed_height = h;
    s.observed_src    = "rpc";
    s.observed_independent = true;
    s.observed_independent = true;   // a real outside source answered
    s.sessions        = 26;
    return s;
}

}  // namespace

// ── HEALTHY: the detector must be SILENT. A detector that fires on a good node
// is worse than none — it is how [EMBED-STATUS] noise trained operators to
// stop reading the log in the first place.
TEST(DashServeStaleness, HealthyNodeNeverAlarms)
{
    FakeClock c;
    ServeStalenessSentinel sen{ServeStalenessConfig{}};

    uint32_t h = kNetwork;
    // 30 minutes at a 15 s poll, tip advancing every 2.5 min like mainnet.
    for (int i = 0; i < 120; ++i) {
        c.advance(15000);
        if (i % 10 == 0) ++h;
        const auto v = sen.poll(healthy(c, h));
        ASSERT_FALSE(v.fired)
            << "healthy poll " << i << " raised " << v.line;
        ASSERT_FALSE(v.stale);
    }
    EXPECT_EQ(sen.io_alarms(), 0u);
    EXPECT_EQ(sen.skew_alarms(), 0u);
    EXPECT_EQ(sen.serve_alarms(), 0u);
}

// ── ONE BLOCK BEHIND is NOT an alarm. This is the ordinary propagation race:
// a peer already has the block we are mid-way through hearing about. If the
// detector fired here it would fire several times an hour forever.
TEST(DashServeStaleness, OneBlockBehindIsNotAnAlarm)
{
    FakeClock c;
    ServeStalenessSentinel sen{ServeStalenessConfig{}};

    for (int i = 0; i < 60; ++i) {   // 15 minutes of being one block behind
        c.advance(15000);
        auto s = healthy(c, kNetwork - 1);
        s.observed_height = kNetwork;
        const auto v = sen.poll(s);
        ASSERT_FALSE(v.fired) << v.line;
        ASSERT_FALSE(v.stale);
    }
    EXPECT_EQ(sen.skew_alarms(), 0u);
}

// ── THE INCIDENT, D2. Served height frozen at the dead height while the
// observed height walks away. Must alarm — and must NOT alarm before the
// sustain window, or a reorg becomes a page.
TEST(DashServeStaleness, InducedSkewAlarms)
{
    FakeClock c;
    ServeStalenessConfig cfg;         // defaults: 2 blocks, 120 s sustain
    ServeStalenessSentinel sen{cfg};

    // Warm up healthy so the watchdogs are armed and the served cursor is real.
    for (int i = 0; i < 4; ++i) {
        c.advance(15000);
        ASSERT_FALSE(sen.poll(healthy(c, kServedDead)).fired);
    }

    // Now freeze the served height and let the network move. The io heartbeat
    // KEEPS TICKING on purpose: this case must stand on the height comparison
    // alone, so D1 cannot be what raises it.
    uint32_t obs   = kServedDead;
    bool     fired = false;
    std::string line;
    int64_t  fired_at = 0;
    const int64_t skew_started = c.now();

    for (int i = 0; i < 40 && !fired; ++i) {   // 10 minutes at 15 s
        c.advance(15000);
        if (i % 10 == 0) obs += 6;             // network pulls ahead

        ServeStalenessSample s;
        s.now_ms          = c.now();
        s.io_heartbeat_ms = c.now();           // io alive
        s.served_height   = kServedDead;       // FROZEN
        s.served_at_ms    = c.now();   // still SERVING -- just a dead height
        s.observed_height = obs;
        s.observed_src    = "rpc";
        s.observed_independent = true;
        s.sessions        = 26;

        const auto v = sen.poll(s);
        if (v.fired) {
            fired    = true;
            line     = v.line;
            fired_at = c.now();
            EXPECT_EQ(v.check, StaleServeCheck::HeightSkew)
                << "the height comparison must be what raised this, not D1/D3: "
                << v.line;
        }
    }

    ASSERT_TRUE(fired)
        << "the exact 2026-08-07 condition — 26 rigs on a dead height while the "
           "chain advanced — produced NO alarm";
    EXPECT_NE(line.find("[STALE-SERVE]"), std::string::npos)   << line;
    EXPECT_NE(line.find("check=height-skew"), std::string::npos) << line;
    EXPECT_NE(line.find("served=2518006"), std::string::npos)  << line;

    // Not before the sustain window: a 2.5-minute-block chain cannot get two
    // blocks ahead of us inside 120 s by propagation alone.
    EXPECT_GE(fired_at - skew_started, cfg.height_skew_sustain_ms)
        << "alarm raised before the sustain window — a reorg would page someone";
    EXPECT_EQ(sen.skew_alarms(), 1u);
    EXPECT_EQ(sen.io_alarms(), 0u);
}

// ── THE MUTATION CASE. Identical drive, guard neutered. If the skew comparison
// were dead code, this would alarm exactly like the case above and the test
// above would be proving nothing. It must be SILENT.
TEST(DashServeStaleness, InducedSkewIsSilentWhenTheGuardIsNeutered)
{
    FakeClock c;
    ServeStalenessConfig cfg;
    cfg.height_skew_blocks = std::numeric_limits<uint32_t>::max();  // guard deleted
    ServeStalenessSentinel sen{cfg};

    for (int i = 0; i < 4; ++i) {
        c.advance(15000);
        ASSERT_FALSE(sen.poll(healthy(c, kServedDead)).fired);
    }

    uint32_t obs = kServedDead;
    for (int i = 0; i < 40; ++i) {
        c.advance(15000);
        if (i % 10 == 0) obs += 6;

        ServeStalenessSample s;
        s.now_ms          = c.now();
        s.io_heartbeat_ms = c.now();
        s.served_height   = kServedDead;
        s.served_at_ms    = c.now();   // still SERVING -- just a dead height
        s.observed_height = obs;
        s.observed_src    = "rpc";
        s.observed_independent = true;
        s.sessions        = 26;

        const auto v = sen.poll(s);
        ASSERT_FALSE(v.fired)
            << "alarm fired with the skew threshold neutered — the assertion in "
               "InducedSkewAlarms does not depend on the guard: " << v.line;
        ASSERT_FALSE(v.stale);
    }
    EXPECT_EQ(sen.skew_alarms(), 0u);
}

// ── D1: the io thread stops ticking. This is the sub-check that would have
// fired FIRST in the incident — measured io handler-queue latency 13.145 s
// against 0.1 ms before — and it is the one that does not depend on any height
// source being available at all.
TEST(DashServeStaleness, IoHeartbeatSilenceAlarms)
{
    FakeClock c;
    ServeStalenessConfig cfg;
    ServeStalenessSentinel sen{cfg};

    for (int i = 0; i < 4; ++i) {
        c.advance(15000);
        ASSERT_FALSE(sen.poll(healthy(c, kNetwork)).fired);
    }

    // The io thread pegs: the heartbeat value stops advancing. EVERYTHING else
    // still looks perfect — served height equals observed height, sessions
    // attached — which is exactly how the incident presented to every
    // self-reported metric.
    const int64_t frozen_beat = c.now();
    bool fired = false;
    std::string line;
    for (int i = 0; i < 10 && !fired; ++i) {
        c.advance(15000);
        ServeStalenessSample s;
        s.now_ms          = c.now();
        s.io_heartbeat_ms = frozen_beat;   // FROZEN
        s.served_height   = kNetwork;
        s.served_at_ms    = frozen_beat;
        s.observed_height = kNetwork;
        s.observed_src    = "peer";
        s.observed_independent = true;
        s.sessions        = 26;
        const auto v = sen.poll(s);
        if (v.fired) {
            fired = true;
            line  = v.line;
            EXPECT_EQ(v.check, StaleServeCheck::IoSilence) << v.line;
        }
    }
    ASSERT_TRUE(fired) << "a wedged io thread raised nothing";
    EXPECT_NE(line.find("check=io-silence"), std::string::npos) << line;
    EXPECT_GE(sen.io_alarms(), 1u);
}

// D1 mutation: with the silence threshold pushed past the whole run, the same
// frozen heartbeat must NOT alarm.
TEST(DashServeStaleness, IoHeartbeatSilenceIsSilentWhenTheGuardIsNeutered)
{
    FakeClock c;
    ServeStalenessConfig cfg;
    cfg.io_silence_ms = std::numeric_limits<int32_t>::max();   // guard deleted
    ServeStalenessSentinel sen{cfg};

    for (int i = 0; i < 4; ++i) {
        c.advance(15000);
        ASSERT_FALSE(sen.poll(healthy(c, kNetwork)).fired);
    }
    const int64_t frozen_beat = c.now();
    for (int i = 0; i < 10; ++i) {
        c.advance(15000);
        ServeStalenessSample s;
        s.now_ms          = c.now();
        s.io_heartbeat_ms = frozen_beat;
        s.served_height   = kNetwork;
        s.served_at_ms    = frozen_beat;
        s.observed_height = kNetwork;
        s.observed_src    = "peer";
        s.observed_independent = true;
        s.sessions        = 26;
        ASSERT_FALSE(sen.poll(s).fired);
    }
    EXPECT_EQ(sen.io_alarms(), 0u);
}

// ── D3: nothing handed out at all while miners are attached. Distinct from D2:
// D2 needs an observed height to compare against, and a node whose only height
// source is its own frozen state has none. D3 needs nothing but a clock.
TEST(DashServeStaleness, ServeSilenceAlarmsOnlyWhileSessionsAreAttached)
{
    FakeClock c;
    const ServeStalenessConfig cfg{};          // serve_silence_ms = 300 s
    ServeStalenessSentinel sen{cfg};

    for (int i = 0; i < 4; ++i) {
        c.advance(15000);
        ASSERT_FALSE(sen.poll(healthy(c, kNetwork)).fired);
    }

    // No miners: silence is not a fault, it is an idle pool.
    const int64_t frozen_serve = c.now();
    for (int i = 0; i < 60; ++i) {   // 15 min of nothing served, 0 sessions
        c.advance(15000);
        ServeStalenessSample s;
        s.now_ms          = c.now();
        s.io_heartbeat_ms = c.now();
        s.served_height   = kNetwork;
        s.served_at_ms    = frozen_serve;
        s.observed_height = kNetwork;
        s.observed_src    = "rpc";
        s.observed_independent = true;
        s.sessions        = 0;
        const auto v = sen.poll(s);
        ASSERT_FALSE(v.fired)  << "alarmed on an idle pool";
        // The SURFACE must agree with the log here too: an idle pool is not a
        // stale one, and the D3 watchdog is disarmed so its age is not running.
        ASSERT_FALSE(v.stale)  << "an idle pool was published as stale";
        ASSERT_EQ(v.serve_quiet_ms, 0)
            << "the D3 age ran while the check was disarmed";
    }
    EXPECT_EQ(sen.serve_alarms(), 0u);

    // Miners attach and STILL nothing is served -> that is a fault.
    bool fired = false;
    std::string line;
    dash::coin::ServeStalenessVerdict at_fire{};
    int polls_after_attach = 0;
    for (int i = 0; i < 60 && !fired; ++i) {
        c.advance(15000);
        ++polls_after_attach;
        ServeStalenessSample s;
        s.now_ms          = c.now();
        s.io_heartbeat_ms = c.now();
        s.served_height   = kNetwork;
        s.served_at_ms    = frozen_serve;
        s.observed_height = kNetwork;
        s.observed_src    = "rpc";
        s.observed_independent = true;
        s.sessions        = 26;
        const auto v = sen.poll(s);
        // ── D3 CARRIES A REAL AGE, POLL BY POLL ─────────────────────────────
        // Round-2 mutation: hardwiring `v.serve_quiet_ms = 0`
        // (serve_staleness.hpp:333) left the suite green, because the only
        // assertion on this field anywhere was EXPECT_LT(..., 20000) — which 0
        // satisfies. One of the three "every check gets its own field" fields
        // was never shown to carry a value at all. It is the watchdog's own
        // elapsed clock, so it must equal the time since attach exactly.
        EXPECT_EQ(v.serve_quiet_ms,
                  static_cast<int64_t>(polls_after_attach - 1) * 15000)
            << "D3 age at poll " << polls_after_attach;
        if (v.fired) {
            fired   = true;
            line    = v.line;
            at_fire = v;
            EXPECT_EQ(v.check, StaleServeCheck::ServeSilence) << v.line;
        }
    }
    ASSERT_TRUE(fired) << "26 rigs attached, no template for 15 minutes, silence";
    EXPECT_NE(line.find("check=serve-silence"), std::string::npos) << line;

    // ── THE SURFACE, NOT ONLY THE LOG ───────────────────────────────────────
    // Round-2 mutation: `} else if (serve_cond) {` -> `} else if (false) {`
    // (serve_staleness.hpp:350) left the suite green. This test asserted only
    // v.fired — the LOG — so the D3 arm of the operator-visible verdict was
    // entirely uncovered and could be deleted silently. Exactly the C1 defect
    // (log knows, surface says healthy) reintroduced one sub-check at a time.
    EXPECT_TRUE(at_fire.stale)
        << "26 rigs attached, nothing served for 5 minutes, and the status "
           "surface still reported health";
    EXPECT_EQ(at_fire.stale_check, StaleServeCheck::ServeSilence);
    EXPECT_EQ(at_fire.stale_age_ms, at_fire.serve_quiet_ms)
        << "stale_age_ms must be the age of the check stale_check NAMES";
    EXPECT_GE(at_fire.serve_quiet_ms, cfg.serve_silence_ms)
        << "D3 raised before its own threshold";
    // D1 and D2 stayed quiet the whole time, so their ages must NOT have been
    // borrowed to satisfy the above.
    EXPECT_EQ(at_fire.io_silent_ms, 0) << "io heartbeat was ticking every poll";
    EXPECT_EQ(at_fire.skew_age_ms, 0)  << "served == observed the whole time";
}

// ── The detector must not go permanently loud once raised. A condition that
// stays true is re-stated on the repeat cadence, not on every poll.
TEST(DashServeStaleness, SustainedSkewIsRateLimitedNotFlooded)
{
    FakeClock c;
    ServeStalenessConfig cfg;
    cfg.repeat_ms = 60000;
    ServeStalenessSentinel sen{cfg};

    for (int i = 0; i < 4; ++i) {
        c.advance(15000);
        ASSERT_FALSE(sen.poll(healthy(c, kServedDead)).fired);
    }

    int fires = 0;
    // 60 minutes at 15 s = 240 polls, the incident's own duration.
    for (int i = 0; i < 240; ++i) {
        c.advance(15000);
        ServeStalenessSample s;
        s.now_ms          = c.now();
        s.io_heartbeat_ms = c.now();
        s.served_height   = kServedDead;
        s.served_at_ms    = c.now();   // still SERVING -- just a dead height
        s.observed_height = kNetwork;
        s.observed_src    = "rpc";
        s.observed_independent = true;
        s.sessions        = 26;
        if (sen.poll(s).fired) ++fires;
    }
    // ~1/min over ~58 alarming minutes, never 240.
    EXPECT_GT(fires, 30);
    EXPECT_LT(fires, 80) << "the alarm floods; " << fires << " lines in an hour";
}

// ── Recovery: once the served height catches up, the alarm must STOP. The
// incident recovered on a restart; a detector that keeps shouting afterwards is
// the same silence problem wearing the opposite mask.
TEST(DashServeStaleness, AlarmClearsWhenTheServedHeightCatchesUp)
{
    FakeClock c;
    ServeStalenessSentinel sen{ServeStalenessConfig{}};

    for (int i = 0; i < 4; ++i) {
        c.advance(15000);
        ASSERT_FALSE(sen.poll(healthy(c, kServedDead)).fired);
    }
    bool ever_fired = false;
    for (int i = 0; i < 40; ++i) {
        c.advance(15000);
        ServeStalenessSample s;
        s.now_ms          = c.now();
        s.io_heartbeat_ms = c.now();
        s.served_height   = kServedDead;
        s.served_at_ms    = c.now();   // still SERVING -- just a dead height
        s.observed_height = kNetwork;
        s.observed_src    = "rpc";
        s.observed_independent = true;
        s.sessions        = 26;
        if (sen.poll(s).fired) ever_fired = true;
    }
    ASSERT_TRUE(ever_fired);

    // Restart / recovery: we serve the current height again.
    for (int i = 0; i < 40; ++i) {
        c.advance(15000);
        const auto v = sen.poll(healthy(c, kNetwork));
        ASSERT_FALSE(v.fired) << "still alarming after recovery: " << v.line;
        ASSERT_FALSE(v.stale);
    }
}

// ── Unknown observed height must NOT be read as "we are current". A sentinel
// whose only height source is down knows nothing, and saying nothing is the
// honest answer for D2 specifically — D1/D3 still cover the case.
TEST(DashServeStaleness, UnknownObservedHeightDoesNotAlarmAndDoesNotClaimHealth)
{
    FakeClock c;
    ServeStalenessSentinel sen{ServeStalenessConfig{}};

    for (int i = 0; i < 40; ++i) {
        c.advance(15000);
        ServeStalenessSample s;
        s.now_ms          = c.now();
        s.io_heartbeat_ms = c.now();
        s.served_height   = kServedDead;
        s.served_at_ms    = c.now();   // still SERVING -- just a dead height
        s.observed_height = 0;             // no source answered
        s.observed_src    = "none";
        s.sessions        = 26;
        const auto v = sen.poll(s);
        EXPECT_EQ(v.check, StaleServeCheck::None) << v.line;
        EXPECT_FALSE(v.stale) << "claimed a skew verdict with no observation";
    }
    EXPECT_EQ(sen.skew_alarms(), 0u);
}

// ═══════════════════════════════════════════════════════════════════════════
// C1 — THE INCIDENT AS IT TRULY PRESENTED, AND WHAT THE SURFACE SAID
// ═══════════════════════════════════════════════════════════════════════════
//
// The first cut of this detector reproduced the incident with the SERVED height
// frozen and an INDEPENDENTLY MOVING observed height (InducedSkewAlarms above).
// That is not what happened. What happened is:
//
//   * the io thread pegged at 99.9% userspace, so EVERY value mirrored by an
//     `ioc` timer froze — including the observed-height mirror the sentinel
//     reads. observed_height therefore stayed EQUAL to the dead served height
//     for the whole hour and D2 could not see anything;
//   * the serve path still trickled h=2518006 out to 26 rigs, so served_at_ms
//     kept advancing and D3 could not see anything either;
//   * only D1 — "the io thread has stopped being able to write a number" —
//     could see it, and it did: 60 correct [STALE-SERVE] check=io-silence lines
//     across the hour.
//
// And the operator surface said `stale: false` for all sixty of them, because
// `stale` carried D2 alone. An operator refreshing /api/node_topology during the
// real event saw nothing wrong. The log and the surface must not be able to
// disagree; this test is that claim.
TEST(DashServeStaleness, IncidentAsItPresentedIsVisibleOnTheStatusSurface)
{
    FakeClock c;
    ServeStalenessSentinel sen{ServeStalenessConfig{}};

    for (int i = 0; i < 4; ++i) {
        c.advance(15000);
        ASSERT_FALSE(sen.poll(healthy(c, kServedDead)).fired);
    }

    // The peg. Both ioc-written mirrors freeze together — that is not two
    // faults, it is one fault seen twice.
    const int64_t frozen_beat = c.now();
    int  lines = 0, stale_polls = 0;
    dash::coin::ServeStalenessVerdict last{};
    for (int i = 0; i < 240; ++i) {          // one hour at a 15 s poll
        c.advance(15000);
        ServeStalenessSample s;
        s.now_ms          = c.now();
        s.io_heartbeat_ms = frozen_beat;     // io thread cannot write a number
        s.served_height   = kServedDead;     // dead height, still going out
        s.served_at_ms    = c.now();         // 26 rigs are still being served
        s.observed_height = kServedDead;     // mirror froze WITH the io thread
        s.observed_src    = "peer";
        s.observed_independent = true;       // the source is real, just stale
        s.sessions        = 26;

        last = sen.poll(s);
        if (last.fired) {
            ++lines;
            EXPECT_EQ(last.check, StaleServeCheck::IoSilence) << last.line;
        }
        if (last.stale) ++stale_polls;
    }

    // The log half — this already worked, and is asserted so the test fails
    // loudly if the fix breaks it.
    EXPECT_GT(lines, 30) << "the log went quiet on the incident it exists for";

    // THE SURFACE HALF — this is the C1 fix. Without it stale_polls is 0.
    // 237 of 240: the first three polls are inside the 60 s D1 threshold.
    EXPECT_GE(stale_polls, 236)
        << "the status surface reported HEALTH while the log printed " << lines
        << " [STALE-SERVE] lines about the same hour";
    EXPECT_TRUE(last.stale);
    EXPECT_EQ(last.stale_check, StaleServeCheck::IoSilence);
    EXPECT_GE(last.stale_age_ms, 3600000)
        << "the surface must carry HOW LONG, not just that something is wrong";

    // And D2 must say it was blind rather than say nothing was wrong: the
    // observed height equalled the served height only because the mirror died.
    EXPECT_EQ(last.skew_age_ms, 0);
}

// C1, mutation: if `stale` were still D2-only, the surface would stay silent for
// the whole hour. Driving the same incident with the height comparison as the
// ONLY thing that could set `stale` — by handing D2 nothing to work with —
// leaves stale false, which is precisely the state the fix removed.
TEST(DashServeStaleness, IncidentSurfaceClaimDependsOnDOneNotOnTheSkew)
{
    FakeClock c;
    ServeStalenessConfig cfg;
    cfg.io_silence_ms = std::numeric_limits<int32_t>::max();  // D1 neutered
    ServeStalenessSentinel sen{cfg};

    for (int i = 0; i < 4; ++i) {
        c.advance(15000);
        ASSERT_FALSE(sen.poll(healthy(c, kServedDead)).fired);
    }
    const int64_t frozen_beat = c.now();
    for (int i = 0; i < 240; ++i) {
        c.advance(15000);
        ServeStalenessSample s;
        s.now_ms          = c.now();
        s.io_heartbeat_ms = frozen_beat;
        s.served_height   = kServedDead;
        s.served_at_ms    = c.now();
        s.observed_height = kServedDead;
        s.observed_src    = "peer";
        s.observed_independent = true;
        s.sessions        = 26;
        const auto v = sen.poll(s);
        ASSERT_FALSE(v.stale)
            << "with D1 neutered nothing in this drive can see the fault — if "
               "the surface still claims staleness, the C1 assertion above is "
               "not testing D1: " << v.line;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// C5 — A HEALTHY BUSY NODE MUST NOT TRIP D1
// ═══════════════════════════════════════════════════════════════════════════
//
// notify_all() walks the session snapshot SERIALLY on the io thread
// (core/stratum_server.cpp:379-385) and one send_notify_work measured ~733 ms.
// 26 rigs is 19.06 s in a single round with the heartbeat timer unable to run,
// and a tip change landing mid-round makes that two rounds: 38.1 s. The
// original 10 s default sat BELOW one round, so it would have paged on a
// perfectly healthy pool of 14+ rigs.
TEST(DashServeStaleness, BusyHealthyNodeSerialNotifyRoundDoesNotTripIoSilence)
{
    constexpr int64_t kPerNotifyMs = 733;
    constexpr int64_t kSessions    = 26;
    constexpr int64_t kRoundMs     = kPerNotifyMs * kSessions;   // 19058
    static_assert(kRoundMs == 19058, "the measured round is 26 x 733 ms");

    FakeClock c;
    ServeStalenessConfig cfg;   // the shipped default
    ASSERT_GE(cfg.io_silence_ms, 2 * kRoundMs)
        << "io_silence_ms must clear TWO serial notify rounds (" << (2 * kRoundMs)
        << " ms); at " << cfg.io_silence_ms << " ms it fires on a healthy node";
    ServeStalenessSentinel sen{cfg};

    for (int i = 0; i < 4; ++i) {
        c.advance(15000);
        ASSERT_FALSE(sen.poll(healthy(c, kNetwork)).fired);
    }

    // An hour of a busy-but-healthy node: back-to-back double rounds (a tip
    // change landing inside a round), the heartbeat catching up between them.
    int64_t beat = c.now();
    for (int round = 0; round < 90; ++round) {
        c.advance(2 * kRoundMs);        // io thread is inside notify_all
        {
            ServeStalenessSample s = healthy(c, kNetwork);
            s.io_heartbeat_ms = beat;   // still the pre-round beat
            const auto v = sen.poll(s);
            ASSERT_FALSE(v.fired)
                << "round " << round << ": a healthy 26-rig notify round paged: "
                << v.line;
            ASSERT_FALSE(v.stale) << "round " << round;
        }
        beat = c.now();                 // round done, the 1 s timer runs again
        c.advance(1000);
        ASSERT_FALSE(sen.poll(healthy(c, kNetwork)).fired);
    }
    EXPECT_EQ(sen.io_alarms(), 0u)
        << "D1 cried wolf on a healthy node; an ignored detector is worth less "
           "than no detector";
}

// C5, mutation: the SAME healthy drive against the retired 10 s default must
// alarm. If it did not, the test above would be passing for a reason that has
// nothing to do with the threshold.
TEST(DashServeStaleness, BusyHealthyNodeWouldHaveTrippedTheOldTenSecondDefault)
{
    FakeClock c;
    ServeStalenessConfig cfg;
    cfg.io_silence_ms = 10000;          // the value this condition retired
    ServeStalenessSentinel sen{cfg};

    for (int i = 0; i < 4; ++i) {
        c.advance(15000);
        ASSERT_FALSE(sen.poll(healthy(c, kNetwork)).fired);
    }
    int64_t beat = c.now();
    bool fired = false;
    for (int round = 0; round < 90 && !fired; ++round) {
        c.advance(2 * 733 * 26);
        ServeStalenessSample s = healthy(c, kNetwork);
        s.io_heartbeat_ms = beat;
        if (sen.poll(s).fired) fired = true;
        beat = c.now();
        c.advance(1000);
        if (sen.poll(healthy(c, kNetwork)).fired) fired = true;
    }
    ASSERT_TRUE(fired)
        << "the 10 s default did NOT false-positive on the busy-node drive, so "
           "the raised default is unjustified by this test";
}

// ═══════════════════════════════════════════════════════════════════════════
// C6 — D2 REFUSES TO COMPARE THE NODE AGAINST ITSELF
// ═══════════════════════════════════════════════════════════════════════════
//
// peer_tip_height() is fed only from the coin-p2p peer-height callback, and
// header_chain exists only when coin_p2p does. Without coin-p2p there is no
// outside height, and the only number to hand is our own tip. Comparing the
// served height against our own tip is the node vouching for itself — the exact
// property that made every pre-existing signal blind. D2 must decline.
TEST(DashServeStaleness, DTwoRefusesToRunWithoutAnIndependentReference)
{
    FakeClock c;
    ServeStalenessSentinel sen{ServeStalenessConfig{}};

    // Drive a skew that is UNMISTAKABLE — 22 blocks, the incident's own gap,
    // sustained far past the window. The only thing wrong with it is that the
    // observed height did not come from outside this process.
    for (int i = 0; i < 240; ++i) {
        c.advance(15000);
        ServeStalenessSample s;
        s.now_ms          = c.now();
        s.io_heartbeat_ms = c.now();
        s.served_height   = kServedDead;
        s.served_at_ms    = c.now();
        s.observed_height = kNetwork;       // 22 ahead
        s.observed_src    = "hdr";          // OUR OWN header tip
        s.observed_independent = false;     // ...so it proves nothing
        s.sessions        = 26;

        const auto v = sen.poll(s);
        ASSERT_FALSE(v.d2_armed)
            << "D2 claimed to be armed on a self-sourced height";
        ASSERT_FALSE(v.stale)
            << "D2 compared the node against ITSELF and called the result a "
               "verdict: " << v.line;
        ASSERT_EQ(v.skew_age_ms, 0);
    }
    EXPECT_EQ(sen.skew_alarms(), 0u);
}

// C6, mutation: the SAME drive with the reference marked independent MUST
// alarm. Without this the refusal test would pass on a detector whose skew
// comparison was simply dead.
TEST(DashServeStaleness, DTwoRunsAndAlarmsOnceTheReferenceIsIndependent)
{
    FakeClock c;
    ServeStalenessSentinel sen{ServeStalenessConfig{}};

    bool fired = false;
    bool armed_seen = false;
    dash::coin::ServeStalenessVerdict at_fire{};
    for (int i = 0; i < 240 && !fired; ++i) {
        c.advance(15000);
        ServeStalenessSample s;
        s.now_ms          = c.now();
        s.io_heartbeat_ms = c.now();
        s.served_height   = kServedDead;
        s.served_at_ms    = c.now();
        s.observed_height = kNetwork;
        s.observed_src    = "peer";         // from OUTSIDE this process
        s.observed_independent = true;
        s.sessions        = 26;
        const auto v = sen.poll(s);
        if (v.d2_armed) armed_seen = true;
        if (v.fired) {
            fired   = true;
            at_fire = v;
            EXPECT_EQ(v.check, StaleServeCheck::HeightSkew) << v.line;
        }
    }
    EXPECT_TRUE(armed_seen);
    ASSERT_TRUE(fired)
        << "with a genuinely independent reference the 22-block skew raised "
           "nothing — the refusal test proves only that dead code is dead";

    // ── THE SURFACE, NOT ONLY THE LOG ───────────────────────────────────────
    // Round-2 mutation: `} else if (skew_sustained) {` -> `} else if (false) {`
    // in the standing-conditions block (serve_staleness.hpp:346) left the whole
    // suite green, because every D2 test asserted `fired` (the LOG) and the one
    // test that touched `stale` asserted it FALSE — which a hardwired-false arm
    // satisfies vacuously. D2 is the sub-check for this lane's entire reason to
    // exist: a dead height being served while the io thread is alive and
    // answering. Its contribution to the operator-visible verdict must be
    // asserted POSITIVELY, or it can be deleted and nothing notices.
    //
    // The refusal test (DTwoRefusesToRunWithoutAnIndependentReference) asserts
    // ASSERT_FALSE(v.stale) on the same drive with observed_independent=false.
    // These two together are the pair: same 22-block skew, opposite verdict,
    // and the ONLY difference is where the reference came from.
    EXPECT_TRUE(at_fire.stale)
        << "the log alarmed on a 22-block sustained skew and the STATUS SURFACE "
           "still said healthy — that exact disagreement is what left "
           "/api/node_topology clean for the whole incident hour";
    EXPECT_EQ(at_fire.stale_check, StaleServeCheck::HeightSkew)
        << "stale is standing but names the wrong check";
    EXPECT_EQ(at_fire.stale_age_ms, at_fire.skew_age_ms)
        << "stale_age_ms must be the age of the check stale_check NAMES";
    EXPECT_GE(at_fire.skew_age_ms, 120000)
        << "the sustain window is 120 s; a shorter age means D2 raised early";
}

// ═══════════════════════════════════════════════════════════════════════════
// C3 — EVERY AGE IS ITS OWN FIELD
// ═══════════════════════════════════════════════════════════════════════════
//
// The first cut set v.age_ms to the skew age and then OVERWROTE it with
// whichever check fired, and main_dash passed that same number on as the
// operator-visible stale_age. One field that means io-silence on one poll and
// height-skew on the next is how a true number produces a false conclusion.
// Drive a state where D1 and D2 are BOTH standing and their ages DIFFER, and
// require the surface to keep them apart.
TEST(DashServeStaleness, EachCheckCarriesItsOwnAgeAndTheVerdictNamesWhichOne)
{
    FakeClock c;
    ServeStalenessSentinel sen{ServeStalenessConfig{}};

    for (int i = 0; i < 4; ++i) {
        c.advance(15000);
        ASSERT_FALSE(sen.poll(healthy(c, kServedDead)).fired);
    }

    // Phase 1: skew ONLY. io keeps ticking, so the skew age runs ahead alone.
    for (int i = 0; i < 40; ++i) {
        c.advance(15000);
        ServeStalenessSample s;
        s.now_ms          = c.now();
        s.io_heartbeat_ms = c.now();
        s.served_height   = kServedDead;
        s.served_at_ms    = c.now();
        s.observed_height = kNetwork;
        s.observed_src    = "peer";
        s.observed_independent = true;
        s.sessions        = 26;
        sen.poll(s);
    }

    // Phase 2: the io thread now pegs too. Skew is ~600 s old; io-silence is
    // seconds old. A single shared field cannot express both.
    const int64_t frozen_beat = c.now();
    dash::coin::ServeStalenessVerdict v{};
    for (int i = 0; i < 8; ++i) {
        c.advance(15000);
        ServeStalenessSample s;
        s.now_ms          = c.now();
        s.io_heartbeat_ms = frozen_beat;
        s.served_height   = kServedDead;
        s.served_at_ms    = c.now();
        s.observed_height = kNetwork;
        s.observed_src    = "peer";
        s.observed_independent = true;
        s.sessions        = 26;
        v = sen.poll(s);
    }

    ASSERT_TRUE(v.stale);
    EXPECT_EQ(v.stale_check, StaleServeCheck::IoSilence)
        << "a dead io thread outranks the skew it causes";
    EXPECT_EQ(v.stale_age_ms, v.io_silent_ms)
        << "stale_age_ms must be the age of the check stale_check NAMES";
    EXPECT_GT(v.skew_age_ms, v.io_silent_ms)
        << "the two ages are genuinely different here (" << v.skew_age_ms
        << " vs " << v.io_silent_ms << "), which is the whole point";
    EXPECT_GE(v.skew_age_ms, 600000);
    EXPECT_LE(v.io_silent_ms, 130000);
    // D3 never raised: templates kept going out the whole time, so its age is
    // EXACTLY zero rather than merely small.
    EXPECT_EQ(v.serve_quiet_ms, 0);

    // ── PHASE 3: ALL THREE AGES RUNNING AT ONCE, AND ALL THREE DIFFERENT ────
    // The two phases above leave serve_quiet_ms pinned at 0, which is why the
    // round-2 mutation `v.serve_quiet_ms = 0` (serve_staleness.hpp:333) went
    // unnoticed: a field that is only ever asserted to be small is not
    // demonstrated to carry anything. Templates now stop going out as well —
    // 90 s of it, deliberately BELOW D3's 300 s threshold, so D3 does not fire
    // and the only thing under test is whether its age is real and its own.
    const int64_t frozen_serve = c.now();
    for (int i = 0; i < 6; ++i) {
        c.advance(15000);
        ServeStalenessSample s;
        s.now_ms          = c.now();
        s.io_heartbeat_ms = frozen_beat;    // io still pegged
        s.served_height   = kServedDead;
        s.served_at_ms    = frozen_serve;   // and now nothing is served either
        s.observed_height = kNetwork;
        s.observed_src    = "peer";
        s.observed_independent = true;
        s.sessions        = 26;
        v = sen.poll(s);
    }

    // Three conditions, three ages, three DIFFERENT numbers, from one poll.
    EXPECT_EQ(v.serve_quiet_ms, 90000)  << "D3 age is not the time since the "
                                           "last template left";
    EXPECT_EQ(v.io_silent_ms,  210000)  << "D1 age is not the time since the "
                                           "heartbeat froze";
    EXPECT_GE(v.skew_age_ms,   690000);
    EXPECT_NE(v.serve_quiet_ms, v.io_silent_ms);
    EXPECT_NE(v.serve_quiet_ms, v.skew_age_ms);
    EXPECT_NE(v.io_silent_ms,   v.skew_age_ms);
    // D1 still outranks, and stale_age_ms still tracks the check it names --
    // NOT the largest age, and not the one that happens to be newest.
    ASSERT_TRUE(v.stale);
    EXPECT_EQ(v.stale_check, StaleServeCheck::IoSilence);
    EXPECT_EQ(v.stale_age_ms, v.io_silent_ms);
}
