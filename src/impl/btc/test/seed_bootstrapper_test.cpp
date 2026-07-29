// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// btc::coin::SeedBootstrapper — fake-clock state-machine KATs.
//
// Pins the repeating, rate-limited seed-candidate refill policy that closes the
// merged::CoinPeerManager gap (one-shot fallback that never re-arms + gate on
// table entries not live connections). BTC drives this off NodeImpl's existing
// 30s dial loop, so the policy is a tick-driven escalation, unit-testable with
// a fake clock and zero sockets. Rides the already-allowlisted btc_share_test
// executable, so no build.yml --target change is needed.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "../coin/seed_bootstrapper.hpp"

using btc::coin::SeedBootstrapper;
using State = btc::coin::SeedBootstrapper::State;

namespace {

std::vector<NetService> make_seeds(std::size_t n, std::uint16_t port = 8333)
{
    std::vector<NetService> v;
    for (std::size_t i = 0; i < n; ++i)
        v.emplace_back("10.0." + std::to_string(i / 256) + "." + std::to_string(i % 256), port);
    return v;
}

// A driveable harness: mutable clock + snapshot, capturing sink.
struct Harness
{
    std::int64_t now = 1000;
    SeedBootstrapper::Snapshot snap;
    std::vector<NetService> injected;
    std::vector<std::vector<NetService>> tier_data;

    SeedBootstrapper make(SeedBootstrapper::Config cfg, std::uint64_t seed = 1)
    {
        std::vector<SeedBootstrapper::TierFn> tiers;
        for (std::size_t t = 0; t < tier_data.size(); ++t)
            tiers.emplace_back([this, t]() { return tier_data[t]; });
        return SeedBootstrapper(
            cfg,
            [this]() { return snap; },
            [this](const NetService& a) { injected.push_back(a); },
            [this]() { return now; },
            std::move(tiers),
            seed);
    }
};

// Config with jitter disabled so the timeline is deterministic.
SeedBootstrapper::Config no_jitter_cfg()
{
    SeedBootstrapper::Config c;
    c.startup_jitter_max = 0;
    return c;
}

} // namespace

TEST(SeedBootstrapper, HealthyAtTargetNeverInjects)
{
    Harness h;
    h.tier_data = {make_seeds(4)};
    h.snap = {8, 8, true};  // established == target, even if "exhausted"
    auto sb = h.make(no_jitter_cfg());

    for (int i = 0; i < 100; ++i) { h.now += 30; sb.tick(); }

    EXPECT_EQ(sb.state(), State::Healthy);
    EXPECT_TRUE(h.injected.empty());
}

TEST(SeedBootstrapper, ObservesDuringDebounceThenSeeds)
{
    Harness h;
    h.tier_data = {make_seeds(3)};
    h.snap = {0, 8, true};
    auto sb = h.make(no_jitter_cfg());  // starve=30, jitter=0

    auto r = sb.tick();                 // now=1000: start observing
    EXPECT_EQ(r.state, State::Observing);
    h.now = 1010; r = sb.tick();        // 10s < 30s
    EXPECT_EQ(r.state, State::Observing);
    EXPECT_TRUE(h.injected.empty());

    h.now = 1031; r = sb.tick();        // 31s >= 30s AND exhausted -> seed tier 0
    EXPECT_EQ(r.state, State::Seeding);
    EXPECT_EQ(r.tier, 0u);
    EXPECT_EQ(r.injected, 3u);
    EXPECT_EQ(h.injected.size(), 3u);
}

TEST(SeedBootstrapper, DoesNotSeedWhileConnectingThroughHealthyBook)
{
    // Under target but ESTABLISHED is non-zero and the normal dial path still
    // has candidates: the node is making genuine progress through a healthy
    // address book, so it must never seed-spam. (F1's hard-starve escape is
    // scoped to established==0, so it does not fire here — see
    // HardStarveEscapesStaleTableEvenWithoutExhaustion for the zero case.)
    Harness h;
    h.tier_data = {make_seeds(3)};
    h.snap = {4, 8, false};  // connecting, dial path NOT exhausted
    auto sb = h.make(no_jitter_cfg());

    for (int i = 0; i < 20; ++i) { auto r = sb.tick(); h.now += 30; EXPECT_NE(r.state, State::Seeding); }
    EXPECT_TRUE(h.injected.empty());
}

TEST(SeedBootstrapper, HardStarveEscapesStaleTableEvenWithoutExhaustion)
{
    // F1: a restored node with a large stale address table. The dial path keeps
    // yielding (dead) candidates, so candidates_exhausted stays FALSE forever,
    // yet ESTABLISHED never leaves zero. The exhaustion gate alone would trap
    // the node in Observing permanently — no tier ever tried. hard_starve_secs
    // must break out and escalate to seeds.
    Harness h;
    h.tier_data = {make_seeds(3)};
    h.snap = {0, 8, false};  // zero live peers, table NOT exhausted
    auto sb = h.make(no_jitter_cfg());

    sb.tick();                          // 1000: observing

    // Below hard_starve_secs (300): debounce long past, but still observing.
    h.now = 1000 + 299; auto r = sb.tick();
    EXPECT_EQ(r.state, State::Observing);
    EXPECT_TRUE(h.injected.empty());

    // Past hard_starve_secs with zero established: escalate despite !exhausted.
    h.now = 1000 + 301; r = sb.tick();
    EXPECT_EQ(r.state, State::Seeding);
    EXPECT_GT(r.injected, 0u);
}

TEST(SeedBootstrapper, EscalatesToNextTierAfterSettleWithoutAdmission)
{
    Harness h;
    h.tier_data = {make_seeds(2), make_seeds(2)};  // DNS then fixed
    h.snap = {0, 8, true};
    auto sb = h.make(no_jitter_cfg());

    sb.tick();                          // 1000: observing
    h.now = 1031; sb.tick();            // seed tier 0
    EXPECT_EQ(sb.tier(), 0u);
    h.now = 1040; auto r = sb.tick();   // within settle -> still seeding tier 0, no new inject
    EXPECT_EQ(r.injected, 0u);
    h.now = 1062; r = sb.tick();        // settle elapsed, still starving+exhausted -> tier 1
    EXPECT_EQ(r.tier, 1u);
    EXPECT_EQ(r.injected, 2u);
}

TEST(SeedBootstrapper, AdmittingTierIsNotMarkedFailed)
{
    // F2: target 10, established 2. Tier 0 injects; during settle the dial path
    // admits peers (established rises to 7, still < target). The tier must NOT
    // be recorded as failed / advanced — it is demonstrably working — and no
    // failed_cycle may accrue.
    Harness h;
    h.tier_data = {make_seeds(4), make_seeds(4)};
    h.snap = {2, 10, true};
    auto sb = h.make(no_jitter_cfg());

    sb.tick();                          // 1000: observing
    h.now = 1031; auto r = sb.tick();   // seed tier 0
    EXPECT_EQ(r.state, State::Seeding);
    EXPECT_EQ(r.tier, 0u);

    // Admissions during settle: established 2 -> 7 (still < 10).
    h.snap.established_outbound = 7;
    h.now = 1062; r = sb.tick();        // settle elapsed, but tier admitted 5
    EXPECT_EQ(r.tier, 0u);              // NOT advanced to tier 1
    EXPECT_EQ(sb.failed_cycles(), 0u);  // and NOT counted as a failed cycle
}

TEST(SeedBootstrapper, FullCycleExhaustionEntersCooldownAndBacksOff)
{
    Harness h;
    h.tier_data = {make_seeds(2), make_seeds(2)};
    h.snap = {0, 8, true};
    auto sb = h.make(no_jitter_cfg());

    // Drive one full starve -> two tiers -> cooldown cycle, return cooldown length.
    auto drive_cycle = [&](std::int64_t start) -> std::int64_t {
        h.now = start; sb.tick();                 // observe start
        h.now = start + 31; sb.tick();            // tier 0
        h.now = start + 62; sb.tick();            // tier 1
        h.now = start + 93; auto r = sb.tick();   // full cycle -> cooldown
        EXPECT_EQ(r.state, State::Cooldown);
        std::int64_t entry = h.now;
        // Advance second-by-second (coarse) until it leaves cooldown.
        std::int64_t k = 0;
        for (; k < 4000; ++k) {
            h.now = entry + k;
            if (sb.tick().state != State::Cooldown) break;
        }
        return k;
    };

    unsigned before = sb.failed_cycles();
    std::int64_t len1 = drive_cycle(1000);
    EXPECT_EQ(sb.failed_cycles(), before + 1);
    // len1 with base=60, jitter +0..25% -> in [60, 75].
    EXPECT_GE(len1, 60);
    EXPECT_LE(len1, 76);

    std::int64_t len2 = drive_cycle(h.now + 5);
    EXPECT_EQ(sb.failed_cycles(), before + 2);
    // Second full-cycle backoff doubles: base*2 = 120, +0..25% -> [120, 150].
    EXPECT_GT(len2, len1);
    EXPECT_GE(len2, 120);
}

TEST(SeedBootstrapper, RecoveryDoesNotResetFailedCyclesUntilHysteresisHeld)
{
    Harness h;
    h.tier_data = {make_seeds(2), make_seeds(2)};
    auto cfg = no_jitter_cfg();
    auto sb = h.make(cfg);

    // Force one full cycle -> failed_cycles == 1.
    h.snap = {0, 8, true};
    h.now = 1000; sb.tick();
    h.now = 1031; sb.tick();
    h.now = 1062; sb.tick();
    h.now = 1093; sb.tick();
    ASSERT_EQ(sb.failed_cycles(), 1u);

    // Brief recovery, shorter than hysteresis_hold (600s): must NOT reset.
    h.snap = {8, 8, false};
    h.now = 1200; sb.tick();
    h.now = 1400; sb.tick();  // 200s held < 600s
    EXPECT_EQ(sb.failed_cycles(), 1u);

    // Sustained recovery past hysteresis window: now it resets.
    h.now = 1200 + 601; sb.tick();
    EXPECT_EQ(sb.failed_cycles(), 0u);
}

TEST(SeedBootstrapper, SingleHealthyTickDoesNotCancelActiveCooldown)
{
    // F3: enter cooldown, then blip to target for ONE tick (far shorter than
    // hysteresis_hold). The cooldown must survive: dropping back under target
    // immediately must NOT trigger a fresh seed sweep. On the pre-fix code the
    // Healthy branch cleared cooldown_until unconditionally, so the very next
    // starving tick would seed again — this pins that regression closed.
    Harness h;
    h.tier_data = {make_seeds(2), make_seeds(2)};
    auto sb = h.make(no_jitter_cfg());

    // Drive one full cycle into cooldown.
    h.snap = {0, 8, true};
    h.now = 1000; sb.tick();
    h.now = 1031; sb.tick();
    h.now = 1062; sb.tick();
    h.now = 1093; auto r = sb.tick();
    ASSERT_EQ(r.state, State::Cooldown);
    const std::size_t injected_at_cooldown = h.injected.size();

    // One healthy tick, far shorter than hysteresis_hold (600s).
    h.snap = {8, 8, false};
    h.now = 1100; r = sb.tick();
    EXPECT_EQ(r.state, State::Healthy);

    // Immediately back under target: cooldown (>=60s from 1093) still in force,
    // and NOT a single fresh candidate injected.
    h.snap = {0, 8, true};
    h.now = 1110; r = sb.tick();
    EXPECT_EQ(r.state, State::Cooldown);
    EXPECT_EQ(h.injected.size(), injected_at_cooldown);
}

TEST(SeedBootstrapper, InjectionCappedRegardlessOfSeedListSize)
{
    Harness h;
    h.tier_data = {make_seeds(100)};  // deliberately huge tier
    h.snap = {6, 8, true};            // deficit == 2 -> cap = min(2*2, 8) = 4
    auto sb = h.make(no_jitter_cfg());

    sb.tick();
    h.now = 1031; auto r = sb.tick();
    EXPECT_EQ(r.injected, 4u);        // NOT 100 — cap is deficit/config driven, never seeds.size()
    EXPECT_EQ(h.injected.size(), 4u);

    // And when deficit is large, the fixed_batch_cap (8) is the ceiling.
    Harness h2;
    h2.tier_data = {make_seeds(100)};
    h2.snap = {0, 50, true};          // deficit 50 -> 2*50=100, clamped to 8
    auto sb2 = h2.make(no_jitter_cfg());
    sb2.tick();
    h2.now = 1031; auto r2 = sb2.tick();
    EXPECT_EQ(r2.injected, 8u);
}

TEST(SeedBootstrapper, StartupJitterWithinConfiguredBound)
{
    Harness h;
    h.tier_data = {make_seeds(2)};
    h.snap = {0, 8, true};
    for (std::uint64_t seed = 1; seed <= 32; ++seed) {
        auto sb = h.make(SeedBootstrapper::Config{}, seed);  // default jitter max = 30
        EXPECT_GE(sb.startup_jitter(), 0);
        EXPECT_LE(sb.startup_jitter(), 30);
    }
}

TEST(SeedBootstrapper, EmptyTierAdvancesWithoutBurningSettle)
{
    Harness h;
    h.tier_data = {make_seeds(0), make_seeds(2)};  // tier 0 resolves nothing (DNS down)
    h.snap = {0, 8, true};
    auto sb = h.make(no_jitter_cfg());

    sb.tick();                        // observe
    h.now = 1031; auto r = sb.tick(); // tier 0 empty -> injected 0
    EXPECT_EQ(r.tier, 0u);
    EXPECT_EQ(r.injected, 0u);
    h.now = 1032; r = sb.tick();      // next tick advances past the empty tier immediately
    EXPECT_EQ(r.tier, 1u);
    EXPECT_EQ(r.injected, 2u);
}
