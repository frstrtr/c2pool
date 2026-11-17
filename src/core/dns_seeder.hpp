// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Async DNS seed resolver for Bitcoin-derived coin P2P networks.
/// Resolves DNS seed hostnames to peer IP addresses using Boost.ASIO.
/// Supports parallel queries, rate limiting, and timeout per seed.

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <functional>
#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <system_error>
#include <thread>

#include <boost/asio.hpp>
#include <core/log.hpp>
#include <core/netaddress.hpp>

namespace c2pool {
namespace dns {

/// One DNS seed entry: hostname + default P2P port for resolved IPs.
struct DnsSeed
{
    std::string hostname;
    uint16_t    default_port;
};

/// Configuration for DNS seed resolution.
struct DnsSeedConfig
{
    int  timeout_sec{10};           // per-seed resolution timeout
    int  rate_limit_sec{1800};      // don't re-query same seed within this window
    int  max_results_per_seed{256}; // cap IPs returned per seed
};

/// Async DNS seed resolver.
/// Usage:
///   DnsSeeder seeder(ioc, {{"seed-a.example.com", 9333}, ...});
///   seeder.resolve_all([](std::vector<NetService> peers) { ... });
class DnsSeeder
{
public:
    using ResultCallback = std::function<void(std::vector<NetService>)>;

    DnsSeeder(boost::asio::io_context& ioc,
              std::vector<DnsSeed> seeds,
              DnsSeedConfig config = {})
        : m_ioc(ioc)
        , m_resolver(ioc)
        , m_seeds(std::move(seeds))
        , m_config(config)
    {
    }

    /// Resolve all seeds in parallel. Callback receives aggregated results.
    void resolve_all(ResultCallback cb)
    {
        if (m_seeds.empty()) {
            if (cb) cb({});
            return;
        }

        auto ctx = std::make_shared<ResolveContext>();
        ctx->callback = std::move(cb);
        ctx->pending = static_cast<int>(m_seeds.size());

        for (auto& seed : m_seeds) {
            // Rate limit: skip if queried recently
            auto now = std::chrono::steady_clock::now();
            auto it = m_last_query.find(seed.hostname);
            if (it != m_last_query.end()) {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    now - it->second).count();
                if (elapsed < m_config.rate_limit_sec) {
                    // Rate-limited: skip this seed
                    if (--ctx->pending == 0) finalize(ctx);
                    continue;
                }
            }
            m_last_query[seed.hostname] = now;

            resolve_one(seed, ctx);
        }
    }

    /// Synchronous resolve: blocks the calling thread, one seed after the
    /// other, with no timeout of its own. Never call it on an io_context
    /// thread; the peer managers use ParallelSeedResolver below.
    std::vector<NetService> resolve_all_sync()
    {
        std::vector<NetService> result;
        for (auto& seed : m_seeds) {
            auto now = std::chrono::steady_clock::now();
            auto it = m_last_query.find(seed.hostname);
            if (it != m_last_query.end()) {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    now - it->second).count();
                if (elapsed < m_config.rate_limit_sec) continue;
            }
            m_last_query[seed.hostname] = now;

            try {
                boost::asio::ip::tcp::resolver resolver(m_ioc);
                auto results = resolver.resolve(
                    seed.hostname, std::to_string(seed.default_port));
                int count = 0;
                for (auto& ep : results) {
                    if (count >= m_config.max_results_per_seed) break;
                    result.emplace_back(
                        ep.endpoint().address().to_string(),
                        seed.default_port);
                    ++count;
                }
                LOG_INFO << "[DNS] " << seed.hostname << " → " << count << " peers";
            } catch (const std::exception& e) {
                LOG_WARNING << "[DNS] Failed to resolve " << seed.hostname
                            << ": " << e.what();
            }
        }
        return result;
    }

    const std::vector<DnsSeed>& seeds() const { return m_seeds; }

private:
    struct ResolveContext
    {
        ResultCallback callback;
        std::vector<NetService> results;
        std::mutex mutex;
        int pending{0};
    };

    void resolve_one(const DnsSeed& seed, std::shared_ptr<ResolveContext> ctx)
    {
        auto timer = std::make_shared<boost::asio::steady_timer>(m_ioc);
        timer->expires_after(std::chrono::seconds(m_config.timeout_sec));

        // Start async resolve
        m_resolver.async_resolve(
            seed.hostname, std::to_string(seed.default_port),
            [this, seed, ctx, timer](
                const boost::system::error_code& ec,
                boost::asio::ip::tcp::resolver::results_type results)
            {
                timer->cancel();

                if (!ec) {
                    std::lock_guard<std::mutex> lock(ctx->mutex);
                    int count = 0;
                    for (auto& ep : results) {
                        if (count >= m_config.max_results_per_seed) break;
                        ctx->results.emplace_back(
                            ep.endpoint().address().to_string(),
                            seed.default_port);
                        ++count;
                    }
                    LOG_INFO << "[DNS] " << seed.hostname << " → " << count << " peers";
                } else {
                    LOG_WARNING << "[DNS] " << seed.hostname << " failed: " << ec.message();
                }

                if (--ctx->pending == 0) finalize(ctx);
            });

        // Timeout handler
        timer->async_wait(
            [this, seed, ctx, timer](const boost::system::error_code& ec) {
                if (!ec) {
                    LOG_WARNING << "[DNS] " << seed.hostname << " timed out";
                    m_resolver.cancel();
                }
            });
    }

    void finalize(std::shared_ptr<ResolveContext> ctx)
    {
        std::lock_guard<std::mutex> lock(ctx->mutex);
        LOG_INFO << "[DNS] Seed resolution complete: " << ctx->results.size() << " total peers";
        if (ctx->callback) {
            boost::asio::post(m_ioc, [ctx]() {
                ctx->callback(std::move(ctx->results));
            });
        }
    }

    boost::asio::io_context& m_ioc;
    boost::asio::ip::tcp::resolver m_resolver;
    std::vector<DnsSeed> m_seeds;
    DnsSeedConfig m_config;
    std::map<std::string, std::chrono::steady_clock::time_point> m_last_query;
};

/// Resolves DNS seeds off the calling thread: every seed on a worker thread
/// of its own, all at once, each bounded by a hard timeout.
///
/// getaddrinfo() cannot be cancelled and can take seconds per dead or slow
/// seed (a late NXDOMAIN, a lame delegation that times out). Run on an
/// io_context thread, one seed after the other, it stalls the event loop for
/// the sum of them: a fresh c2pool-ltc node aborted on its 40 s event-loop
/// freeze watchdog while the LTC and DOGE peer managers re-resolved their
/// seeds inside the emergency re-arm timer handler.
///
/// resolve() called from a handler running on `ioc` returns at once, and the
/// peers reach on_done on `ioc` when the round completes. Called anywhere else
/// (start-up, before the event loop runs) it waits for the round and calls
/// on_done before it returns, so the caller's first dial plan still has the
/// seeds' peers. Either way a round lasts at most seed_timeout: a seed that has
/// not answered by then is logged as timed out and its answer is dropped; its
/// worker finishes on its own, bounded by the system resolver's timeouts.
///
/// One round at a time: a round started from a handler is in flight until its
/// peers have been handed to on_done on `ioc`, and resolve() returns false
/// (with busy() true) meanwhile. cancel() and the destructor drop every round
/// not yet delivered, a delivery already queued on `ioc` included, and join
/// the coordinator at once, so on_done never runs after them. An exception out
/// of on_done in a delivery on `ioc` is caught and logged. Call resolve() and
/// cancel() from one thread (the one that runs `ioc`), and destroy the resolver
/// before `ioc`, like any timer on it.
class ParallelSeedResolver
{
public:
    using Callback = std::function<void(std::vector<NetService>)>;

    /// Per-seed bound. Seeds resolve in parallel, so it bounds a whole round
    /// too. Headroom over glibc's 5 s per-query timeout: on a host whose first
    /// nameserver does not answer, every lookup (good seeds too) takes 5 s.
    static constexpr std::chrono::milliseconds kDefaultSeedTimeout{10000};
    /// Worker threads alive at once, process wide. An abandoned worker counts
    /// until its getaddrinfo() returns; a seed over the cap is skipped.
    static constexpr int kMaxLiveWorkers = 64;

    explicit ParallelSeedResolver(boost::asio::io_context& ioc,
                                  std::chrono::milliseconds seed_timeout = kDefaultSeedTimeout,
                                  int max_results_per_seed = 256)
        : m_ioc(ioc)
        , m_seed_timeout(seed_timeout)
        , m_max_results(max_results_per_seed)
    {
    }

    ~ParallelSeedResolver() { cancel(); }

    ParallelSeedResolver(const ParallelSeedResolver&) = delete;
    ParallelSeedResolver& operator=(const ParallelSeedResolver&) = delete;

    /// A round started from an io_context handler has been neither delivered
    /// on `ioc` nor cancelled yet.
    bool busy() const { return m_busy.load(); }

    /// Resolve `seeds` and hand the peers to on_done (see the class comment
    /// for which thread, and when). False if a round is already in flight
    /// (busy() is then true) or no coordinator thread could be started (logged
    /// here; busy() is then false).
    bool resolve(std::vector<DnsSeed> seeds, Callback on_done)
    {
        if (m_busy.load())
            return false;
        if (m_coordinator.joinable())
            m_coordinator.join();   // the previous round's, already finished

        auto round = std::make_shared<Round>();
        {
            std::lock_guard<std::mutex> lock(m_round_mutex);
            m_round = round;
        }

        if (!m_ioc.get_executor().running_in_this_thread()) {
            // No handler of `ioc` runs on this thread: waiting here (at most
            // seed_timeout) stalls no event loop.
            auto peers = run_round(round, seeds, m_seed_timeout, m_max_results);
            if (!round->is_cancelled())
                on_done(std::move(peers));
            return true;
        }

        m_busy = true;
        auto alive = m_alive;
        try {
            m_coordinator = std::thread(
                [this, round, alive, seeds = std::move(seeds), on_done = std::move(on_done)]() mutable {
                    auto peers = run_round(round, seeds, m_seed_timeout, m_max_results);
                    if (round->is_cancelled())
                        return;              // cancel() is joining this thread
                    boost::asio::post(m_ioc,
                        [this, alive, on_done = std::move(on_done), peers = std::move(peers)]() mutable {
                            // cancel() ran after the post (stop, destruction):
                            // drop the round, and `this` may be gone.
                            if (!alive->load())
                                return;
                            m_busy = false;  // over once delivered, not once posted
                            try {
                                on_done(std::move(peers));
                            } catch (const std::exception& e) {
                                LOG_WARNING << "[DNS] Seed round delivery failed: " << e.what();
                            }
                        });
                });
        } catch (const std::system_error& e) {
            m_busy = false;
            LOG_WARNING << "[DNS] Cannot start a seed resolver thread: " << e.what();
            return false;
        }
        return true;
    }

    /// Drop every round not yet delivered, including one whose delivery is
    /// already queued on `ioc`: on_done is not called for it. Returns at once
    /// (abandoned getaddrinfo() calls are not waited for).
    void cancel()
    {
        // Every delivery posted so far holds this token; later rounds get a
        // fresh one.
        m_alive->store(false);
        m_alive = std::make_shared<std::atomic<bool>>(true);
        std::shared_ptr<Round> round;
        {
            std::lock_guard<std::mutex> lock(m_round_mutex);
            round = std::move(m_round);
        }
        if (round)
            round->cancel();
        if (m_coordinator.joinable())
            m_coordinator.join();
        m_busy = false;
    }

private:
    /// One round's answers, shared with its workers (which may outlive it).
    struct Round
    {
        std::mutex mutex;
        std::condition_variable cv;
        std::vector<std::optional<std::vector<NetService>>> answers;  // nullopt: no answer yet
        size_t pending{0};
        bool closed{false};      // collected: later answers are dropped
        bool cancelled{false};

        /// Record seed i's answer; false if the round was already collected.
        bool answer(size_t i, std::vector<NetService> peers)
        {
            {
                std::lock_guard<std::mutex> lock(mutex);
                if (closed)
                    return false;
                answers[i] = std::move(peers);
                --pending;
            }
            cv.notify_all();
            return true;
        }

        bool is_closed()
        {
            std::lock_guard<std::mutex> lock(mutex);
            return closed;
        }

        bool is_cancelled()
        {
            std::lock_guard<std::mutex> lock(mutex);
            return cancelled;
        }

        void cancel()
        {
            {
                std::lock_guard<std::mutex> lock(mutex);
                cancelled = true;
            }
            cv.notify_all();
        }
    };

    static std::atomic<int>& live_workers()
    {
        static std::atomic<int> count{0};
        return count;
    }

    /// The blocking lookup, on a worker thread (never on an io thread).
    static std::vector<NetService> resolve_seed(const DnsSeed& seed, int max_results)
    {
        boost::asio::io_context local;
        boost::asio::ip::tcp::resolver resolver(local);
        auto results = resolver.resolve(seed.hostname, std::to_string(seed.default_port));
        std::vector<NetService> peers;
        for (auto& ep : results) {
            if (static_cast<int>(peers.size()) >= max_results)
                break;
            peers.emplace_back(ep.endpoint().address().to_string(), seed.default_port);
        }
        return peers;
    }

    /// Start a worker per seed and collect what answers within `timeout`.
    static std::vector<NetService> run_round(const std::shared_ptr<Round>& round,
                                             const std::vector<DnsSeed>& seeds,
                                             std::chrono::milliseconds timeout,
                                             int max_results)
    {
        const auto started = std::chrono::steady_clock::now();
        {
            std::lock_guard<std::mutex> lock(round->mutex);
            round->answers.assign(seeds.size(), std::nullopt);
            round->pending = seeds.size();
        }

        for (size_t i = 0; i < seeds.size(); ++i) {
            if (live_workers().fetch_add(1) >= kMaxLiveWorkers) {
                live_workers().fetch_sub(1);
                LOG_WARNING << "[DNS] Skipping " << seeds[i].hostname << ": "
                            << kMaxLiveWorkers << " resolver threads are still busy";
                round->answer(i, {});
                continue;
            }
            try {
                std::thread([round, i, seed = seeds[i], max_results]() {
                    std::vector<NetService> peers;
                    std::string error;
                    try {
                        peers = resolve_seed(seed, max_results);
                    } catch (const std::exception& e) {
                        error = e.what();
                    }
                    if (!round->is_closed()) {
                        if (error.empty())
                            LOG_INFO << "[DNS] " << seed.hostname << " → " << peers.size() << " peers";
                        else
                            LOG_WARNING << "[DNS] Failed to resolve " << seed.hostname << ": " << error;
                    }
                    round->answer(i, std::move(peers));
                    live_workers().fetch_sub(1);
                }).detach();
            } catch (const std::system_error& e) {
                live_workers().fetch_sub(1);
                LOG_WARNING << "[DNS] Cannot start a resolver thread for "
                            << seeds[i].hostname << ": " << e.what();
                round->answer(i, {});
            }
        }

        std::vector<NetService> peers;
        std::vector<std::string> late;
        size_t answered = 0;
        bool cancelled = false;
        {
            std::unique_lock<std::mutex> lock(round->mutex);
            round->cv.wait_until(lock, started + timeout,
                                 [&] { return round->pending == 0 || round->cancelled; });
            round->closed = true;
            cancelled = round->cancelled;
            for (size_t i = 0; i < seeds.size(); ++i) {
                if (!round->answers[i]) {
                    late.push_back(seeds[i].hostname);
                    continue;
                }
                ++answered;
                peers.insert(peers.end(), round->answers[i]->begin(), round->answers[i]->end());
            }
        }
        if (cancelled)
            return {};

        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count();
        for (auto& host : late)
            LOG_WARNING << "[DNS] " << host << " timed out after " << timeout.count()
                        << " ms (answer dropped)";
        LOG_INFO << "[DNS] Seed round: " << peers.size() << " peers from " << answered
                 << "/" << seeds.size() << " seeds in " << ms << " ms";
        return peers;
    }

    boost::asio::io_context& m_ioc;
    const std::chrono::milliseconds m_seed_timeout;
    const int m_max_results;
    std::atomic<bool> m_busy{false};
    std::shared_ptr<std::atomic<bool>> m_alive = std::make_shared<std::atomic<bool>>(true);
    std::thread m_coordinator;
    std::mutex m_round_mutex;
    std::shared_ptr<Round> m_round;
};

} // namespace dns
} // namespace c2pool