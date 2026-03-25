#pragma once

/// Async DNS seed resolver for Bitcoin-derived coin P2P networks.
/// Resolves DNS seed hostnames to peer IP addresses using Boost.ASIO.
/// Supports parallel queries, rate limiting, and timeout per seed.

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <functional>

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

    /// Synchronous resolve (blocks current thread). For startup bootstrap.
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

} // namespace dns
} // namespace c2pool
