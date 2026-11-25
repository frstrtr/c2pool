// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// ltc::think (think_gate.hpp): the think-slot protocol run_think() and
// clean_tracker() use (rides share_test).
//
//   - a request that loses the slot is remembered and served once by the
//     owner's release; any number of lost requests collapse into one;
//   - the CLEAN slot records nothing when it loses;
//   - clean_cycle_best_changed compares the tip at entry with the tip at exit;
//   - LTC run_think() is reached from the io thread AND the HTTP submit
//     thread, so acquire_think_slot() runs on several threads at once: under
//     contention the slot is never held twice, and when everything is quiet
//     the last cycle started after the last request (none lost) and nothing
//     is left pending.
//
// Folded into the EXISTING allowlisted `share_test` target (the #769 trap).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <thread>
#include <vector>

#include <core/uint256.hpp>
#include <impl/ltc/think_gate.hpp>

using namespace ltc::think;

TEST(LtcThinkGate, LostRequestsAreServedOnceByTheRelease)
{
    std::atomic<bool> running{false}, pending{false};

    ASSERT_TRUE(acquire_think_slot(running, pending));
    EXPECT_FALSE(acquire_think_slot(running, pending));
    EXPECT_FALSE(acquire_think_slot(running, pending));
    EXPECT_TRUE(pending.load());

    EXPECT_TRUE(release_think_slot(running, pending)) << "the owner must post one think";
    EXPECT_FALSE(running.load());
    EXPECT_FALSE(pending.load());

    // The posted think takes the slot; nothing else lost: its release owes nothing.
    ASSERT_TRUE(acquire_think_slot(running, pending));
    EXPECT_FALSE(release_think_slot(running, pending));
}

TEST(LtcThinkGate, CleanSlotRecordsNothingWhenItLoses)
{
    std::atomic<bool> running{false}, pending{false};

    ASSERT_TRUE(acquire_think_slot(running, pending));
    EXPECT_FALSE(acquire_clean_slot(running));
    EXPECT_FALSE(pending.load()) << "a skipped clean is not a lost election";
    EXPECT_FALSE(release_think_slot(running, pending));

    ASSERT_TRUE(acquire_clean_slot(running));
    EXPECT_FALSE(acquire_think_slot(running, pending)) << "clean holds the think slot";
    EXPECT_TRUE(release_think_slot(running, pending)) << "and serves what it blocked";
}

TEST(LtcThinkGate, CleanCycleBestChangedIsEntryAgainstExit)
{
    const uint256 a(1), b(2);
    EXPECT_TRUE(clean_cycle_best_changed(a, b));             // Step 1 (or 4) moved it
    EXPECT_FALSE(clean_cycle_best_changed(a, a));            // moved and moved back, or never
    EXPECT_TRUE(clean_cycle_best_changed(uint256(), a));     // first election
    EXPECT_FALSE(clean_cycle_best_changed(uint256(), uint256()));  // nothing elected
}

// Requesters on several threads, each owner running its cycle and, when its
// release owes a think, taking the slot again for it (the posted run_think).
TEST(LtcThinkGate, ConcurrentRequestersNeverDoubleHoldAndNeverLoseARequest)
{
    std::atomic<bool> running{false}, pending{false};
    std::atomic<uint64_t> tickets{0};
    std::atomic<uint64_t> last_start{0};   // tickets seen when the last cycle started
    std::atomic<int> in_cycle{0};
    std::atomic<int> double_held{0};
    std::atomic<uint64_t> cycles{0};

    auto run_cycles = [&] {   // the caller owns the slot
        for (;;) {
            if (in_cycle.fetch_add(1) != 0)
                double_held.fetch_add(1);
            last_start.store(tickets.load());
            cycles.fetch_add(1);
            in_cycle.fetch_sub(1);
            if (!release_think_slot(running, pending))
                return;
            if (!acquire_think_slot(running, pending))
                return;   // another thread took it: its release serves the debt
        }
    };

    constexpr int kThreads = 6;
    constexpr int kRequests = 20000;
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t)
        threads.emplace_back([&] {
            for (int i = 0; i < kRequests; ++i) {
                tickets.fetch_add(1);
                if (acquire_think_slot(running, pending))
                    run_cycles();
            }
        });
    for (auto& th : threads)
        th.join();

    EXPECT_EQ(double_held.load(), 0) << "two cycles held the slot at once";
    EXPECT_FALSE(running.load());
    EXPECT_FALSE(pending.load()) << "a request was left pending with no cycle to serve it";
    EXPECT_EQ(last_start.load(), tickets.load())
        << "the last request was not followed by a cycle";
    EXPECT_GT(cycles.load(), 0u);
}
