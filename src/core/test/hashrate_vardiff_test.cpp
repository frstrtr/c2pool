// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Per-connection vardiff (c2pool::hashrate::HashrateTracker), core for every
// coin that serves miners through core::StratumServer.
//
// Field case (LTC, 15 ASIC rigs after a node restart): every rig came up at
// max_difficulty 65536 and four stayed there. A session starts at
// min_difficulty 0.0005; a ~15 GH/s rig answers with a burst of floor shares
// before it applies the first raise, the issued-difficulty grace accepts them,
// and every accepted share was timed as if found at the CURRENT difficulty:
// 12 floor shares in well under 36 s read as 10x per step, 0.0005 -> 65536 in
// ~109 floor shares. At 65536 the rig finds a pseudoshare every ~5 h, and it
// withholds every pool share below 65536 (the pool-share difficulty was ~660):
// ~99% of its PPLNS weight.
//
// These KATs drive the tracker on explicit clocks
// (record_mining_share_submission_at), so time is simulated, not slept:
//   1. A floor burst on the old job leaves the difficulty at one step (<= 0.005).
//   2. The ceiling (the job's pool-share difficulty) bounds every difficulty:
//      vardiff, hint ("d=N", mining.suggest_difficulty) and fixed ("+N").
//   3. A rig ramped high comes back down after one share at the bound.
//   4. A steady 15 GH/s rig that applies each new difficulty 250 ms late (its
//      in-flight work is credited at the old one) converges to ~3 s per share
//      and stays there. With the timing rule of master it runs away to 65536.
//   5. DASH's hashrate vardiff obeys the same bound (power-of-two grid).
//   6. A young session's hashrate is its work over its age, not over 600 s.

#include <gtest/gtest.h>

#include <c2pool/hashrate/tracker.hpp>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <random>
#include <utility>
#include <vector>

using c2pool::hashrate::HashrateTracker;

namespace {

constexpr double kTwo32 = 4294967296.0;
constexpr double kEpoch0 = 1.8e9;   // any epoch second; only differences matter

HashrateTracker::time_point at(HashrateTracker::time_point t0, double s)
{
    return t0 + std::chrono::duration_cast<HashrateTracker::clock::duration>(
                    std::chrono::duration<double>(s));
}

void setup(HashrateTracker& t, double target, bool hashrate_vardiff,
           double min_d = 0.0005, double max_d = 65536.0)
{
    t.set_difficulty_bounds(min_d, max_d);
    t.set_target_time_per_mining_share(target);
    t.set_hashrate_vardiff(hashrate_vardiff);
    t.enable_vardiff(true);
}

// A rig of constant hashrate H mining against the tracker. Each difficulty the
// tracker sets reaches the rig `latency` seconds later (set_difficulty + the
// new job's round trip and the firmware applying it); until then the rig keeps
// finding shares of its current job, credited at that job's difficulty (the
// issued-difficulty grace). Arrivals are Poisson; the PRNG is seeded, so a run
// is deterministic.
struct RigSim {
    HashrateTracker& t;
    double hashrate;
    double latency;
    std::mt19937_64 rng;
    HashrateTracker::time_point t0 = HashrateTracker::clock::now();
    double now = 0.0;
    double applied;                                  // difficulty the rig mines at
    std::deque<std::pair<double, double>> pending;   // (apply time, difficulty)
    std::vector<double> share_times;
    std::vector<double> diff_after;                  // tracker difficulty after each share
    double max_seen = 0.0;

    RigSim(HashrateTracker& tracker, double h, double lat, uint64_t seed)
        : t(tracker), hashrate(h), latency(lat), rng(seed),
          applied(tracker.get_current_difficulty()) {}

    double draw_exp(double mean)
    {
        const double u = static_cast<double>(rng() >> 11) * 0x1.0p-53;   // [0, 1)
        return -std::log1p(-u) * mean;
    }

    void run_for(double seconds)
    {
        const double end = now + seconds;
        while (now < end) {
            const double dt = draw_exp(applied * kTwo32 / hashrate);
            if (!pending.empty() && now + dt >= pending.front().first) {
                // memoryless: the rig switches job, draw again at the new rate
                now = pending.front().first;
                applied = pending.front().second;
                pending.pop_front();
                continue;
            }
            now += dt;
            if (now >= end) break;
            const double before = t.get_current_difficulty();
            t.record_mining_share_submission_at(applied, true, at(t0, now), kEpoch0 + now);
            const double after = t.get_current_difficulty();
            if (after != before)
                pending.emplace_back(now + latency, after);
            share_times.push_back(now);
            diff_after.push_back(after);
            max_seen = std::max(max_seen, after);
        }
    }
};

}  // namespace

// ── 1. Floor burst ─────────────────────────────────────────────────────────
// 120 accepted shares of the start job (issued at the 0.0005 floor) within
// 50 ms. The first 13 are timed (the floor IS the current difficulty then)
// and raise it one step; the rest are credited at 0.0005 but not timed.
TEST(HashrateVardiff, FloorBurstOnOldJobStaysAtOneStep)
{
    HashrateTracker t;
    setup(t, 3.0, /*hashrate_vardiff=*/false);
    const auto t0 = HashrateTracker::clock::now();
    for (int i = 0; i < 120; ++i)
        t.record_mining_share_submission_at(0.0005, true, at(t0, 0.05 * i / 120.0),
                                            kEpoch0 + 0.05 * i / 120.0);
    EXPECT_LE(t.get_current_difficulty(), 0.005 * (1.0 + 1e-9))
        << "floor burst ran the vardiff away (master: 65536)";
    EXPECT_GE(t.get_current_difficulty(), 0.0005);
}

// ── 2. The pool-share bound ─────────────────────────────────────────────────
TEST(HashrateVardiff, CeilingBoundsVardiffHintAndFixed)
{
    constexpr double kPool = 660.0;
    HashrateTracker t;
    setup(t, 3.0, false);
    t.set_difficulty_ceiling(kPool);
    EXPECT_DOUBLE_EQ(t.get_difficulty_ceiling(), kPool);

    // A rig that is always faster than target and applies every raise at
    // once: vardiff climbs, but never past the bound.
    const auto t0 = HashrateTracker::clock::now();
    double now = 0.0, max_seen = 0.0;
    for (int i = 0; i < 400; ++i) {
        now += 0.001;
        t.record_mining_share_submission_at(t.get_current_difficulty(), true, at(t0, now), kEpoch0 + now);
        max_seen = std::max(max_seen, t.get_current_difficulty());
    }
    EXPECT_LE(max_seen, kPool);
    EXPECT_DOUBLE_EQ(t.get_current_difficulty(), kPool);

    // A hint above it ("d=N", mining.suggest_difficulty) lands on it.
    t.set_difficulty_hint(1.0e6);
    EXPECT_DOUBLE_EQ(t.get_current_difficulty(), kPool);
    t.set_difficulty_hint(5.0);
    EXPECT_DOUBLE_EQ(t.get_current_difficulty(), 5.0);

    // A lower bound (the next job's share bits) pulls the difficulty down at
    // once; a higher one does not push a vardiff difficulty up.
    t.set_difficulty_hint(400.0);
    t.set_difficulty_ceiling(100.0);
    EXPECT_DOUBLE_EQ(t.get_current_difficulty(), 100.0);
    t.set_difficulty_ceiling(kPool);
    EXPECT_DOUBLE_EQ(t.get_current_difficulty(), 100.0);

    // "+N" fixed: bounded too, re-derived from the request as the bound moves,
    // vardiff and hints do not move it.
    t.set_fixed_difficulty(1000.0);
    EXPECT_TRUE(t.is_fixed_difficulty());
    EXPECT_DOUBLE_EQ(t.get_current_difficulty(), kPool);
    t.set_difficulty_ceiling(2000.0);
    EXPECT_DOUBLE_EQ(t.get_current_difficulty(), 1000.0);
    t.set_difficulty_hint(3.0);
    for (int i = 0; i < 50; ++i) {
        now += 0.001;
        t.record_mining_share_submission_at(1000.0, true, at(t0, now), kEpoch0 + now);
    }
    EXPECT_DOUBLE_EQ(t.get_current_difficulty(), 1000.0);
    t.set_fixed_difficulty(0.0);   // cleared: vardiff resumes from where it is
    EXPECT_FALSE(t.is_fixed_difficulty());
    EXPECT_DOUBLE_EQ(t.get_current_difficulty(), 1000.0);

    // No bound known (0): max_difficulty only.
    t.set_difficulty_ceiling(0.0);
    t.set_difficulty_hint(1.0e9);
    EXPECT_DOUBLE_EQ(t.get_current_difficulty(), 65536.0);
}

// The bound wins over the floor: a pool-share difficulty under min_difficulty
// is still never exceeded (the money guard first).
TEST(HashrateVardiff, CeilingBelowFloorWins)
{
    HashrateTracker t;
    setup(t, 3.0, false);
    t.set_difficulty_ceiling(0.0001);
    EXPECT_DOUBLE_EQ(t.get_current_difficulty(), 0.0001);
    t.set_difficulty_hint(1.0);
    EXPECT_DOUBLE_EQ(t.get_current_difficulty(), 0.0001);
}

// ── 3. A rig ramped high comes back after one share at the bound ───────────
// The rig was fast enough to ramp to max_difficulty (65536) while no bound was
// known. The next job carries the pool-share difficulty (660): the difficulty
// drops to it at once, and the first share the 15 GH/s rig finds there (~189 s
// later) brings the vardiff down a step toward its ~10.5 ideal. Unbounded, the
// same rig would wait ~5 h for its next share at 65536.
TEST(HashrateVardiff, MisRampedRigComesBackAfterOneShareAtTheBound)
{
    HashrateTracker t;
    setup(t, 3.0, false);
    const auto t0 = HashrateTracker::clock::now();
    double now = 0.0;
    while (t.get_current_difficulty() < 65536.0 && now < 10.0) {
        now += 0.001;
        t.record_mining_share_submission_at(t.get_current_difficulty(), true, at(t0, now), kEpoch0 + now);
    }
    ASSERT_DOUBLE_EQ(t.get_current_difficulty(), 65536.0) << "precondition: ramped to max";

    t.set_difficulty_ceiling(660.0);
    EXPECT_DOUBLE_EQ(t.get_current_difficulty(), 660.0) << "the next job is issued at the bound";

    const double interval = 660.0 * kTwo32 / 15.0e9;   // ~189 s at 15 GH/s
    now += interval;
    t.record_mining_share_submission_at(660.0, true, at(t0, now), kEpoch0 + now);
    EXPECT_LE(t.get_current_difficulty(), 66.0 + 1e-9)
        << "one share at the bound must bring the vardiff down a step";
    EXPECT_GE(t.get_current_difficulty(), 10.0);
}

// ── 4. Steady rig: converges to ~3 s per share and stays ───────────────────
TEST(HashrateVardiff, SteadyRigWithApplyLatencyConvergesAndStaysStable)
{
    constexpr double kH = 15.0e9;                 // 15 GH/s
    constexpr double kTarget = 3.0;
    const double ideal = kH * kTarget / kTwo32;   // ~10.48

    HashrateTracker t;
    setup(t, kTarget, false);
    RigSim sim(t, kH, /*latency=*/0.25, /*seed=*/20261117);
    sim.run_for(600.0);   // 10 minutes to converge
    EXPECT_LE(sim.max_seen, 10.0 * ideal) << "vardiff overshot (master: runs away to 65536)";
    printf("steady 15 GH/s rig: first 10 min max %.2f (ideal %.2f), %zu shares\n", sim.max_seen, ideal,
           sim.share_times.size());
    const size_t settled = sim.share_times.size();
    sim.run_for(7200.0);  // then 2 hours

    ASSERT_GT(sim.share_times.size(), settled + 1000);
    double lo = 1e300, hi = 0.0;
    for (size_t i = settled; i < sim.diff_after.size(); ++i) {
        lo = std::min(lo, sim.diff_after[i]);
        hi = std::max(hi, sim.diff_after[i]);
    }
    const double mean_interval = (sim.share_times.back() - sim.share_times[settled])
                                 / static_cast<double>(sim.share_times.size() - 1 - settled);
    printf("steady 15 GH/s rig: ideal %.2f, after 10 min: %.2f..%.2f, mean interval %.3f s over %zu shares,"
           " max %.2f\n", ideal, lo, hi, mean_interval, sim.share_times.size() - settled, sim.max_seen);
    EXPECT_GE(lo, ideal / 4.0) << "lo=" << lo << " ideal=" << ideal;
    EXPECT_LE(hi, ideal * 4.0) << "hi=" << hi << " ideal=" << ideal;
    EXPECT_GE(mean_interval, 0.8 * kTarget) << "mean interval " << mean_interval;
    EXPECT_LE(mean_interval, 1.3 * kTarget) << "mean interval " << mean_interval;
    EXPECT_LE(sim.max_seen, 10.0 * ideal);
}

// ── 5. DASH (hashrate vardiff): the same bound, on its power-of-two grid ──
TEST(HashrateVardiff, HashrateVardiffObeysTheBoundOnItsGrid)
{
    constexpr double kH = 15.0e9;
    constexpr double kTarget = 10.0;              // DASH's target time
    const double ideal = kH * kTarget / kTwo32;   // ~34.9 -> grid 32

    // Unbounded: converges to its grid step under the ideal.
    {
        HashrateTracker t;
        setup(t, kTarget, true);
        RigSim sim(t, kH, 0.25, 7);
        sim.run_for(3600.0);
        EXPECT_LE(sim.max_seen, ideal * 2.0);
        EXPECT_GE(t.get_current_difficulty(), ideal / 4.0);
    }
    // Bounded at 20: the grid step at or below it (16), never above.
    {
        HashrateTracker t;
        setup(t, kTarget, true);
        t.set_difficulty_ceiling(20.0);
        EXPECT_DOUBLE_EQ(t.get_difficulty_ceiling(), 16.0);
        RigSim sim(t, kH, 0.25, 7);
        sim.run_for(3600.0);
        EXPECT_LE(sim.max_seen, 16.0);
        EXPECT_DOUBLE_EQ(t.get_current_difficulty(), 16.0);
    }
    // A fixed "+N" is put on the grid too (rounded down), and bounded.
    {
        HashrateTracker t;
        setup(t, kTarget, true);
        t.set_fixed_difficulty(5000.0);
        EXPECT_DOUBLE_EQ(t.get_current_difficulty(), 4096.0);
        t.set_difficulty_ceiling(1000.0);
        EXPECT_DOUBLE_EQ(t.get_current_difficulty(), 512.0);
    }
    // Floor burst on the old job: bounded by the credited work, no runaway.
    {
        HashrateTracker t;
        setup(t, kTarget, true);
        const auto t0 = HashrateTracker::clock::now();
        for (int i = 0; i < 120; ++i)
            t.record_mining_share_submission_at(0.0005, true, at(t0, 0.05 * i / 120.0),
                                                kEpoch0 + 0.05 * i / 120.0);
        EXPECT_LE(t.get_current_difficulty(), 0.0625);
    }
}

// ── 6. A young session's hashrate ───────────────────────────────────────────
// 6 shares of difficulty 1 in a session younger than 2 * target (6 s): the
// work divided by 6 s (the floor), i.e. 2^32 H/s; master divides by 600 s.
TEST(HashrateVardiff, YoungSessionHashrateUsesItsAge)
{
    HashrateTracker t;
    t.set_target_time_per_mining_share(3.0);
    for (int i = 0; i < 6; ++i)
        t.record_mining_share_submission(1.0, true);
    const double hr = t.get_current_hashrate();
    // Up to 6 s of wall time may pass in the test; the span is then still 6 s.
    EXPECT_NEAR(hr, kTwo32, kTwo32 * 1e-9) << "hashrate " << hr;
}
