// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Worker pools that serve callbacks (a header-validation pool, a lane's
/// pool) and must be joined before the stores and chains their tasks use are
/// closed. A pool captured by a callback otherwise lives until the callback's
/// owner (an io_context handler, a broadcaster) is destroyed, after those
/// stores: a task running then uses closed stores (an abort), or blocks for
/// good and the pool's destructor joins it for good (a hang).
///
/// Register each pool where it is made; the shutdown stops them (queued
/// tasks are dropped, the one running finishes) and joins them, in
/// registration order, within a deadline. A pool that does not finish in
/// time is left running: the caller must then not close what it uses.

#include <boost/asio/thread_pool.hpp>

#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace core {

/// Stop `pool` and join it within `deadline`. True when it finished; false
/// when its running task outlived the deadline (the pool is left running and
/// joined by nobody: the process is expected to exit).
inline bool stop_and_join_within(const std::shared_ptr<boost::asio::thread_pool>& pool,
                                 std::chrono::milliseconds deadline)
{
    if (!pool)
        return true;
    pool->stop();
    auto joined = std::make_shared<std::promise<void>>();
    auto done = joined->get_future();
    // The joiner holds the pool: if it is abandoned, the pool outlives this call.
    std::thread joiner([pool, joined]() {
        pool->join();
        joined->set_value();
    });
    if (done.wait_for(deadline) == std::future_status::ready) {
        joiner.join();
        return true;
    }
    joiner.detach();
    return false;
}

class WorkerPools {
public:
    /// A pool of `threads` threads, registered under `name`.
    std::shared_ptr<boost::asio::thread_pool> make(std::size_t threads, std::string name)
    {
        auto pool = std::make_shared<boost::asio::thread_pool>(threads);
        add(pool, std::move(name));
        return pool;
    }

    void add(std::shared_ptr<boost::asio::thread_pool> pool, std::string name)
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_pools.emplace_back(std::move(name), std::move(pool));
    }

    /// Stop and join every pool within `deadline` in all. Returns the names
    /// of the pools that did not finish (empty: all joined).
    std::vector<std::string> stop_and_join(std::chrono::milliseconds deadline)
    {
        std::vector<std::pair<std::string, std::shared_ptr<boost::asio::thread_pool>>> pools;
        {
            std::lock_guard<std::mutex> lock(m_mu);
            pools = m_pools;
        }
        for (auto& [name, pool] : pools)
            pool->stop();  // all of them first: no pool feeds another meanwhile
        const auto until = std::chrono::steady_clock::now() + deadline;
        std::vector<std::string> left;
        for (auto& [name, pool] : pools) {
            const auto now = std::chrono::steady_clock::now();
            const auto rest = now < until ? std::chrono::duration_cast<std::chrono::milliseconds>(until - now)
                                          : std::chrono::milliseconds(0);
            if (!stop_and_join_within(pool, rest))
                left.push_back(name);
        }
        return left;
    }

    std::size_t size() const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        return m_pools.size();
    }

private:
    mutable std::mutex m_mu;
    std::vector<std::pair<std::string, std::shared_ptr<boost::asio::thread_pool>>> m_pools;
};

} // namespace core
