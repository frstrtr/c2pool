// SPDX-License-Identifier: AGPL-3.0-or-later
//
// core::WorkerPools / core::stop_and_join_within: the shutdown joins the
// worker pools before the stores their tasks use are closed, within a
// deadline. A queued task is dropped, the running one finishes; a task that
// never ends does not hold the shutdown past the deadline.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <thread>

#include <boost/asio/post.hpp>

#include <core/worker_pools.hpp>

namespace {

using namespace std::chrono_literals;

// A running task finishes, the queued ones are dropped, the join is prompt.
TEST(WorkerPools, StopDropsQueuedTasksAndJoinsTheRunningOne)
{
    core::WorkerPools pools;
    auto pool = pools.make(1, "headers");
    std::promise<void> started;
    std::atomic<int> ran{0};
    boost::asio::post(*pool, [&]() {
        started.set_value();
        std::this_thread::sleep_for(50ms);
        ++ran;
    });
    for (int i = 0; i < 100; ++i)
        boost::asio::post(*pool, [&]() {
            std::this_thread::sleep_for(50ms);
            ++ran;
        });
    started.get_future().wait();
    const auto t0 = std::chrono::steady_clock::now();
    EXPECT_TRUE(pools.stop_and_join(2s).empty());
    EXPECT_LT(std::chrono::steady_clock::now() - t0, 1s) << "the queued tasks ran";
    EXPECT_EQ(ran.load(), 1);
}

// A task that does not end within the deadline: the join gives up at the
// deadline and names the pool; the pool is left running (not destroyed
// under its task) and finishes once the task does.
TEST(WorkerPools, ATaskThatDoesNotEndDoesNotHoldTheShutdown)
{
    core::WorkerPools pools;
    auto quick = pools.make(1, "quick");
    auto stuck = pools.make(1, "stuck");
    std::promise<void> release;
    auto released = release.get_future().share();
    std::promise<void> started;
    std::atomic<bool> finished{false};
    boost::asio::post(*stuck, [&, released]() {
        started.set_value();
        released.wait();
        finished = true;
    });
    started.get_future().wait();
    std::weak_ptr<boost::asio::thread_pool> watch = stuck;
    stuck.reset();

    const auto t0 = std::chrono::steady_clock::now();
    const auto left = pools.stop_and_join(200ms);
    const auto took = std::chrono::steady_clock::now() - t0;
    ASSERT_EQ(left.size(), 1u);
    EXPECT_EQ(left[0], "stuck");
    EXPECT_GE(took, 150ms);
    EXPECT_LT(took, 1s);
    EXPECT_FALSE(finished.load());
    EXPECT_FALSE(watch.expired()) << "the pool was destroyed under its running task";

    release.set_value();
    const auto until = std::chrono::steady_clock::now() + 2s;
    while (!finished.load() && std::chrono::steady_clock::now() < until)
        std::this_thread::sleep_for(10ms);
    EXPECT_TRUE(finished.load()) << "the abandoned pool never ran its task to the end";
}

// stop_and_join_within on a single pool, and on no pool.
TEST(WorkerPools, StopAndJoinWithin)
{
    EXPECT_TRUE(core::stop_and_join_within(nullptr, 0ms));
    auto pool = std::make_shared<boost::asio::thread_pool>(1);
    std::atomic<int> ran{0};
    boost::asio::post(*pool, [&]() { ++ran; });
    std::this_thread::sleep_for(20ms);
    EXPECT_TRUE(core::stop_and_join_within(pool, 1s));
    EXPECT_EQ(ran.load(), 1);
}

} // namespace
