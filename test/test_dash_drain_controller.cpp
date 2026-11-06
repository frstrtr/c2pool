// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KATs for src/impl/dash/drain_controller.hpp (#866 action 2, coin side):
// the DASH staged ramp-down controller over the core drain hooks (#1870).
//
//   1. SCHEDULE: target_after_step = floor(initial*(N-k)/N). It is
//      non-increasing, ends at exactly 0, and the step period is
//      step_share_periods * SHARE_PERIOD.
//   2. CONTROLLER: begin() turns accept off and snapshots the live count. Each
//      step() closes exactly live - target (10 live, 4 steps: 3, 2, 3, 2).
//      Step N leaves 0 live and accept still off. A second begin() is refused.
//   3. REFUSAL METRIC: refused_while_draining is the core counter's delta
//      since begin(), not the process-lifetime total.
//   4. IO-THREAD GUARD: off-thread begin()/step() never reach set_accepting or
//      drop_sessions, and each one bumps off_thread_rejects.
//   5. SCHEDULER: on a real io_context with the real running_in_this_thread()
//      predicate, start() runs all N steps on the timer. The same controller
//      called from the test thread (outside ioc.run) is refused.
//   6. The controller instantiates against core::StratumServer, so the fake's
//      method names match the real core API (compile-time check).
//
// No sockets, no coin daemon, no sharechain.

#include <gtest/gtest.h>

#include <impl/dash/drain_controller.hpp>
#include <core/stratum_server.hpp>

#include <boost/asio.hpp>

#include <chrono>
#include <cstdint>
#include <vector>

using namespace dash::drain;
using namespace std::chrono_literals;

// Compile-time check that the core drain surface matches what the controller
// calls (test 6). main_dash instantiates the same specialization.
template class dash::drain::RampDownController<core::StratumServer>;

namespace {

// Same four methods as core::StratumServer's drain surface. drop_sessions
// closes exactly min(n, live), like the core hook (KAT 8 in
// test_stratum_interim_hardening).
struct FakeServer {
    bool     accepting{true};
    size_t   live{0};
    uint64_t refused{0};
    std::vector<size_t> drop_calls;   // the n passed to each drop_sessions call
    int      set_accepting_calls{0};

    void set_accepting(bool a) { accepting = a; ++set_accepting_calls; }
    size_t get_session_count() const { return live; }
    uint64_t get_refused_draining() const { return refused; }
    size_t drop_sessions(size_t n)
    {
        drop_calls.push_back(n);
        const size_t k = n < live ? n : live;
        live -= k;
        return k;
    }
};

auto on_io = [] { return true; };
auto off_io = [] { return false; };

} // namespace

// ── 1. Schedule ─────────────────────────────────────────────────────────────
TEST(DashDrainSchedule, FloorTargetsEndAtZero)
{
    // 10 live over 4 steps: floor(30/4)=7, floor(20/4)=5, floor(10/4)=2, 0.
    EXPECT_EQ(target_after_step(10, 4, 0), 10u);
    EXPECT_EQ(target_after_step(10, 4, 1), 7u);
    EXPECT_EQ(target_after_step(10, 4, 2), 5u);
    EXPECT_EQ(target_after_step(10, 4, 3), 2u);
    EXPECT_EQ(target_after_step(10, 4, 4), 0u);
    EXPECT_EQ(target_after_step(10, 4, 9), 0u);
    // Fewer miners than steps: some steps close nobody, the last closes all.
    EXPECT_EQ(target_after_step(3, 4, 1), 2u);
    EXPECT_EQ(target_after_step(3, 4, 2), 1u);
    EXPECT_EQ(target_after_step(3, 4, 3), 0u);
    EXPECT_EQ(target_after_step(0, 4, 1), 0u);
    // steps == 0 is treated as one step.
    EXPECT_EQ(target_after_step(5, 0, 0), 5u);
    EXPECT_EQ(target_after_step(5, 0, 1), 0u);

    for (size_t initial : {0u, 1u, 2u, 7u, 64u, 1000u})
        for (uint32_t n : {1u, 2u, 4u, 5u, 13u}) {
            size_t prev = initial;
            for (uint32_t k = 1; k <= n; ++k) {
                const size_t t = target_after_step(initial, n, k);
                EXPECT_LE(t, prev) << initial << "/" << n << " k=" << k;
                prev = t;
            }
            EXPECT_EQ(prev, 0u) << initial << "/" << n;
        }
}

TEST(DashDrainSchedule, StepPeriodAndValidation)
{
    DrainConfig cfg;   // defaults: 4 x 25 share periods
    EXPECT_EQ(cfg.steps, 4u);
    EXPECT_EQ(cfg.step_share_periods, 25u);
    EXPECT_EQ(cfg.steps * cfg.step_share_periods, 100u)   // TARGET_LOOKBEHIND
        << "default drain spans one retarget window";
    EXPECT_EQ(step_period(cfg, 20), 500s);
    EXPECT_TRUE(validate(cfg).empty());

    EXPECT_FALSE(validate({0, 25}).empty());
    EXPECT_FALSE(validate({4, 0}).empty());
    EXPECT_FALSE(validate({kMaxSteps + 1, 25}).empty());
    EXPECT_FALSE(validate({4, kMaxStepSharePeriods + 1}).empty());
    EXPECT_TRUE(validate({kMaxSteps, kMaxStepSharePeriods}).empty());
}

// ── 2. Controller ───────────────────────────────────────────────────────────
TEST(DashDrainController, RefusesThenShedsInEqualSteps)
{
    FakeServer srv;
    srv.live = 10;
    RampDownController<FakeServer> ctl(srv, {4, 25}, on_io);

    EXPECT_EQ(ctl.state(), DrainState::Idle);
    EXPECT_TRUE(srv.accepting);

    ASSERT_TRUE(ctl.begin());
    EXPECT_FALSE(srv.accepting) << "begin() must refuse new connections";
    EXPECT_EQ(srv.live, 10u) << "begin() closes nobody";
    EXPECT_TRUE(srv.drop_calls.empty());
    EXPECT_EQ(ctl.status().initial_sessions, 10u);

    EXPECT_EQ(ctl.step(), 3u);  EXPECT_EQ(srv.live, 7u);
    EXPECT_EQ(ctl.step(), 2u);  EXPECT_EQ(srv.live, 5u);
    EXPECT_EQ(ctl.step(), 3u);  EXPECT_EQ(srv.live, 2u);
    EXPECT_FALSE(ctl.done());
    EXPECT_EQ(ctl.step(), 2u);  EXPECT_EQ(srv.live, 0u);
    EXPECT_TRUE(ctl.done());
    EXPECT_EQ(srv.drop_calls, (std::vector<size_t>{3, 2, 3, 2}));

    EXPECT_FALSE(srv.accepting) << "accept stays off after the last step";
    EXPECT_EQ(srv.set_accepting_calls, 1) << "the controller never re-enables accept";

    const DrainStatus s = ctl.status();
    EXPECT_EQ(s.state, DrainState::Done);
    EXPECT_EQ(s.step, 4u);
    EXPECT_EQ(s.steps, 4u);
    EXPECT_EQ(s.target_sessions, 0u);
    EXPECT_EQ(s.dropped_total, 10u);

    // After done: step() is a no-op and begin() is refused.
    EXPECT_EQ(ctl.step(), 0u);
    EXPECT_EQ(srv.drop_calls.size(), 4u);
    EXPECT_FALSE(ctl.begin());
    EXPECT_EQ(srv.set_accepting_calls, 1);
}

TEST(DashDrainController, StepBeforeBeginIsNoop)
{
    FakeServer srv;
    srv.live = 4;
    RampDownController<FakeServer> ctl(srv, {2, 1}, on_io);
    EXPECT_EQ(ctl.step(), 0u);
    EXPECT_EQ(srv.live, 4u);
    EXPECT_TRUE(srv.accepting);
    EXPECT_TRUE(srv.drop_calls.empty());
}

TEST(DashDrainController, SessionsThatLeaveOnTheirOwnAreNotDoubleCounted)
{
    // Rigs that disconnect by themselves between steps count toward the
    // target, so the controller closes only the remainder.
    FakeServer srv;
    srv.live = 8;
    RampDownController<FakeServer> ctl(srv, {4, 25}, on_io);
    ASSERT_TRUE(ctl.begin());
    srv.live = 5;                     // 3 left on their own; target is 6
    EXPECT_EQ(ctl.step(), 0u);
    EXPECT_TRUE(srv.drop_calls.empty());
    EXPECT_EQ(ctl.step(), 1u);        // target 4
    EXPECT_EQ(srv.live, 4u);
}

// ── 3. Refusal metric ───────────────────────────────────────────────────────
TEST(DashDrainController, RefusalsCountedFromBegin)
{
    FakeServer srv;
    srv.live = 4;
    srv.refused = 7;   // core counter is process-lifetime; 7 from an earlier drain
    RampDownController<FakeServer> ctl(srv, {2, 25}, on_io);
    ASSERT_TRUE(ctl.begin());
    EXPECT_EQ(ctl.status().refused_while_draining, 0u);

    srv.refused += 3;                 // 3 rigs tried to reconnect
    ctl.step();
    EXPECT_EQ(ctl.status().refused_while_draining, 3u);

    srv.refused += 2;
    ctl.step();
    EXPECT_EQ(ctl.status().refused_while_draining, 5u);
    EXPECT_TRUE(ctl.done());
}

// ── 4. io-thread guard ──────────────────────────────────────────────────────
TEST(DashDrainController, OffThreadCallsNeverReachTheServer)
{
    FakeServer srv;
    srv.live = 6;
    RampDownController<FakeServer> ctl(srv, {3, 25}, off_io);

    EXPECT_FALSE(ctl.begin());
    EXPECT_TRUE(srv.accepting);
    EXPECT_EQ(srv.set_accepting_calls, 0);
    EXPECT_EQ(ctl.state(), DrainState::Idle);

    EXPECT_EQ(ctl.step(), 0u);
    EXPECT_TRUE(srv.drop_calls.empty());
    EXPECT_EQ(srv.live, 6u);
    EXPECT_EQ(ctl.status().off_thread_rejects, 2u);

    // An empty predicate is treated as off-thread too.
    RampDownController<FakeServer> ctl2(srv, {3, 25}, {});
    EXPECT_FALSE(ctl2.begin());
    EXPECT_TRUE(srv.accepting);
}

// ── 5. Scheduler on a real io_context ───────────────────────────────────────
TEST(DashDrainScheduler, TimerRunsAllStepsOnTheIoThread)
{
    boost::asio::io_context ioc;
    FakeServer srv;
    srv.live = 10;
    RampDownController<FakeServer> ctl(
        srv, {4, 25},
        [&ioc] { return ioc.get_executor().running_in_this_thread(); });

    // Called from the test thread, outside ioc.run(): refused.
    EXPECT_FALSE(ctl.begin());
    EXPECT_EQ(ctl.status().off_thread_rejects, 1u);

    RampDownScheduler<FakeServer> sched(ioc, ctl, 2ms);
    bool started = false;
    boost::asio::post(ioc, [&] { started = sched.start(); });
    ioc.run_for(5s);   // returns once the last step stops re-arming

    EXPECT_TRUE(started);
    EXPECT_TRUE(ctl.done());
    EXPECT_EQ(srv.drop_calls, (std::vector<size_t>{3, 2, 3, 2}));
    EXPECT_EQ(srv.live, 0u);
    EXPECT_FALSE(srv.accepting);
    EXPECT_EQ(ctl.status().off_thread_rejects, 1u)
        << "every timer step ran on the io thread";
}

TEST(DashDrainScheduler, IocStopDropsThePendingStep)
{
    // Plain SIGTERM path: main calls ioc.stop(). The pending step never runs,
    // so a drain cannot delay shutdown.
    boost::asio::io_context ioc;
    FakeServer srv;
    srv.live = 10;
    RampDownController<FakeServer> ctl(
        srv, {4, 25},
        [&ioc] { return ioc.get_executor().running_in_this_thread(); });
    RampDownScheduler<FakeServer> sched(ioc, ctl, 1h);
    boost::asio::post(ioc, [&] { sched.start(); ioc.stop(); });
    ioc.run();
    EXPECT_EQ(ctl.state(), DrainState::Draining);
    EXPECT_TRUE(srv.drop_calls.empty());
    EXPECT_FALSE(srv.accepting);
}
