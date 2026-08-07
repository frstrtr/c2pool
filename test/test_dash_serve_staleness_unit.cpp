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
    ServeStalenessSentinel sen{ServeStalenessConfig{}};

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
        s.sessions        = 0;
        ASSERT_FALSE(sen.poll(s).fired) << "alarmed on an idle pool";
    }
    EXPECT_EQ(sen.serve_alarms(), 0u);

    // Miners attach and STILL nothing is served -> that is a fault.
    bool fired = false;
    std::string line;
    for (int i = 0; i < 60 && !fired; ++i) {
        c.advance(15000);
        ServeStalenessSample s;
        s.now_ms          = c.now();
        s.io_heartbeat_ms = c.now();
        s.served_height   = kNetwork;
        s.served_at_ms    = frozen_serve;
        s.observed_height = kNetwork;
        s.observed_src    = "rpc";
        s.sessions        = 26;
        const auto v = sen.poll(s);
        if (v.fired) {
            fired = true;
            line  = v.line;
            EXPECT_EQ(v.check, StaleServeCheck::ServeSilence) << v.line;
        }
    }
    ASSERT_TRUE(fired) << "26 rigs attached, no template for 15 minutes, silence";
    EXPECT_NE(line.find("check=serve-silence"), std::string::npos) << line;
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
