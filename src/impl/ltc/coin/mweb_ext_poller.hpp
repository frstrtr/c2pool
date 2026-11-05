// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// The getblocktemplate poller of the hybrid MWEB extension (#2137 S3).
///
/// A worker thread of its own fetches G = litecoind getblocktemplate
/// {rules:[mweb,segwit]} over HTTP JSON-RPC, so a slow or dead litecoind
/// never stalls the io thread: every fetch is bounded by a timeout (connect,
/// write and read; the host is an IP address, no name is resolved), and the
/// template builder only ever reads the
/// last G the worker stored (MwebExtSource), never waits for one.
///
/// When (PollSchedule):
///   - at once on every tip change (notify_tip), and again at once when the
///     tip changed while a fetch was running;
///   - every `period` (5 s) while G is for the tip -- litecoind rebuilds its
///     own template at most every 5 s while its mempool changes;
///   - every `retry` (0.5 s) while G is not for the tip yet, for `fast_window`
///     (10 s) after the tip change (litecoind has not seen the block yet),
///     then every `period`;
///   - after a failed fetch: 1 s, 2 s, 4 s, then every `period`.
/// So the RPC load is about one getblocktemplate per 5 s, plus a few around
/// each block.

#include "mweb_ext_import.hpp"

#include <core/log.hpp>
#include <core/uint256.hpp>

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/core/detail/base64.hpp>
#include <boost/beast/http.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

namespace ltc {
namespace coin {
namespace mweb_ext {

/// litecoind's RPC endpoint (the LTC RPC settings).
struct RpcEndpoint {
    std::string host;
    uint16_t port{0};
    std::string userpass;  // "user:password"
};

/// One fetch.
struct FetchResult {
    bool ok{false};           // a "result" object came back
    bool timeout{false};
    std::string error;
    nlohmann::json result;    // G
    int64_t ms{0};
    std::chrono::steady_clock::time_point at{};  // when the answer arrived
};

/// The largest getblocktemplate answer read (a full 4 MWU template is about
/// 10 MB of JSON).
inline constexpr size_t kMaxGbtResponseBytes = 64u * 1024u * 1024u;

/// One getblocktemplate {rules:[mweb,segwit]} over HTTP JSON-RPC, bounded by
/// `timeout` from the start. `ep.host` must be an IP address: no name is
/// resolved (a DNS query is not bounded by the timeout). Never throws.
inline FetchResult fetch_gbt(const RpcEndpoint& ep, std::chrono::milliseconds timeout)
{
    namespace beast = boost::beast;
    namespace http = beast::http;
    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    FetchResult r;
    const auto t0 = std::chrono::steady_clock::now();
    auto finish = [&]() {
        r.at = std::chrono::steady_clock::now();
        r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(r.at - t0).count();
    };
    try {
        boost::system::error_code addr_ec;
        const auto addr = net::ip::make_address(ep.host, addr_ec);
        if (addr_ec) {
            finish();
            r.error = "not an IP address: " + ep.host;
            return r;
        }
        const tcp::endpoint target(addr, ep.port);
        net::io_context io;
        beast::tcp_stream stream(io);

        std::string auth;
        auth.resize(beast::detail::base64::encoded_size(ep.userpass.size()));
        auth.resize(beast::detail::base64::encode(&auth[0], ep.userpass.data(), ep.userpass.size()));

        http::request<http::string_body> req{http::verb::post, "/", 11};
        req.set(http::field::host, ep.host + ":" + std::to_string(ep.port));
        req.set(http::field::content_type, "application/json");
        req.set(http::field::authorization, "Basic " + auth);
        req.body() = R"({"jsonrpc":"1.0","id":"c2pool-mweb-ext","method":"getblocktemplate","params":[{"rules":["mweb","segwit"]}]})";
        req.prepare_payload();

        beast::flat_buffer buffer;
        http::response_parser<http::string_body> parser;
        parser.body_limit(kMaxGbtResponseBytes);
        bool done = false;
        beast::error_code result_ec;

        stream.expires_after(timeout);
        stream.async_connect(target, [&](beast::error_code ec) {
            if (ec) {
                result_ec = ec;
                done = true;
                return;
            }
            http::async_write(stream, req, [&](beast::error_code ec2, std::size_t) {
                if (ec2) {
                    result_ec = ec2;
                    done = true;
                    return;
                }
                http::async_read(stream, buffer, parser, [&](beast::error_code ec3, std::size_t) {
                    result_ec = ec3;
                    done = true;
                });
            });
        });
        io.run_for(timeout);
        finish();
        if (!done) {
            // Pending handlers are destroyed with `io`, never run.
            r.timeout = true;
            r.error = "no answer within " + std::to_string(timeout.count()) + " ms";
            return r;
        }
        if (result_ec) {
            r.timeout = result_ec == beast::error::timeout;
            r.error = result_ec.message();
            return r;
        }
        beast::error_code ignored;
        stream.socket().shutdown(tcp::socket::shutdown_both, ignored);

        const auto& resp = parser.get();
        auto j = nlohmann::json::parse(resp.body(), nullptr, false);
        if (j.is_discarded() || !j.is_object()) {
            r.error = "HTTP " + std::to_string(resp.result_int()) + ": not a JSON-RPC answer";
            return r;
        }
        if (j.contains("error") && !j["error"].is_null()) {
            r.error = j["error"].is_object() ? j["error"].value("message", std::string("RPC error"))
                                             : j["error"].dump();
            return r;
        }
        if (!j.contains("result") || !j["result"].is_object()) {
            r.error = "HTTP " + std::to_string(resp.result_int()) + ": no result object";
            return r;
        }
        r.result = std::move(j["result"]);
        r.ok = true;
        return r;
    } catch (const std::exception& e) {
        finish();
        r.error = e.what();
        return r;
    }
}

/// When the poller fetches next (pure).
struct PollSchedule {
    std::chrono::milliseconds period{5000};
    std::chrono::milliseconds retry{500};
    std::chrono::milliseconds fast_window{10000};
    std::chrono::milliseconds error_base{1000};

    /// After a fetch: `ok` = it returned G, `for_tip` = G's prev is the tip
    /// the fetch was for, `since_tip` = time since that tip appeared,
    /// `errors` = failed fetches in a row (this one included).
    std::chrono::milliseconds next_delay(bool ok, bool for_tip, std::chrono::milliseconds since_tip,
                                         unsigned errors) const
    {
        if (!ok) {
            const unsigned shift = std::min(errors > 0 ? errors - 1 : 0u, 3u);
            return std::min(period, error_base * (1u << shift));
        }
        if (for_tip)
            return period;
        return since_tip < fast_window ? retry : period;
    }
};

/// The worker. `fetch` runs on it and `deliver` is called on it with every
/// result, in order (the owner stores G, MwebExtSource is thread-safe, and
/// posts whatever must run on the io thread).
class MwebExtPoller {
public:
    using clock = std::chrono::steady_clock;
    using FetchFn = std::function<FetchResult()>;
    using DeliverFn = std::function<void(FetchResult&&, const uint256& tip)>;

    MwebExtPoller(FetchFn fetch, DeliverFn deliver, PollSchedule schedule = {})
        : m_fetch(std::move(fetch)), m_deliver(std::move(deliver)), m_schedule(schedule)
    {
    }
    ~MwebExtPoller() { stop(); }

    MwebExtPoller(const MwebExtPoller&) = delete;
    MwebExtPoller& operator=(const MwebExtPoller&) = delete;

    /// Start the worker; the first fetch is at once.
    void start()
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        if (m_thread.joinable())
            return;
        m_stop = false;
        m_next_due = clock::now();
        m_thread = std::thread([this] { run(); });
    }

    /// Stop and join (a fetch in flight ends within its timeout).
    void stop()
    {
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            m_stop = true;
        }
        m_cv.notify_all();
        if (m_thread.joinable() && m_thread.get_id() != std::this_thread::get_id())
            m_thread.join();
    }

    /// The tip changed (any thread): fetch now.
    void notify_tip(const uint256& tip)
    {
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            if (tip == m_tip)
                return;
            m_tip = tip;
            m_tip_at = clock::now();
            ++m_tip_seq;
        }
        m_cv.notify_all();
    }

    uint64_t fetches() const { return m_fetches.load(std::memory_order_relaxed); }

private:
    void run()
    {
        std::unique_lock<std::mutex> lk(m_mutex);
        unsigned errors = 0;
        while (!m_stop) {
            m_cv.wait_until(lk, m_next_due, [this] { return m_stop || m_tip_seq != m_fetched_seq || clock::now() >= m_next_due; });
            if (m_stop)
                break;
            const uint256 tip = m_tip;
            const uint64_t seq = m_tip_seq;
            const clock::time_point tip_at = m_tip_at;
            lk.unlock();

            FetchResult r;
            try {
                r = m_fetch();
            } catch (const std::exception& e) {
                r = FetchResult{};
                r.error = e.what();
                r.at = clock::now();
            }
            const bool ok = r.ok;
            const bool for_tip = ok && r.result.is_object() && r.result.contains("previousblockhash")
                && r.result["previousblockhash"].is_string()
                && r.result["previousblockhash"].get<std::string>() == tip.GetHex();
            try {
                m_deliver(std::move(r), tip);
            } catch (const std::exception& e) {
                LOG_WARNING << "[EMB-LTC] MWEB extension: delivering litecoind's template failed: " << e.what();
            }
            m_fetches.fetch_add(1, std::memory_order_relaxed);
            errors = ok ? 0 : errors + 1;

            lk.lock();
            m_fetched_seq = seq;
            const auto now = clock::now();
            m_next_due = now + m_schedule.next_delay(
                ok, for_tip, std::chrono::duration_cast<std::chrono::milliseconds>(now - tip_at), errors);
        }
    }

    FetchFn m_fetch;
    DeliverFn m_deliver;
    const PollSchedule m_schedule;

    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::thread m_thread;
    bool m_stop{false};
    uint256 m_tip;
    clock::time_point m_tip_at{};
    uint64_t m_tip_seq{0};
    uint64_t m_fetched_seq{0};
    clock::time_point m_next_due{};
    std::atomic<uint64_t> m_fetches{0};
};

} // namespace mweb_ext
} // namespace coin
} // namespace ltc
