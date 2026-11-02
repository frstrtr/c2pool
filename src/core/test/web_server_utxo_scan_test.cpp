// SPDX-License-Identifier: AGPL-3.0-or-later
//
// GET /api/utxo/scan, the web server's half (c2wallet Scan & Plan, N1): the
// scan fn runs on the MiningInterface's dedicated scan thread, one at a time,
// one started per kUtxoScanMinInterval (a refusal before the pass does not
// use it), the HTTP side waits up to the scan timeout, and the route answers
// only a direct local request. The coin side (the set, the posture, the rows)
// is test/test_dash_utxo_scan.cpp.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include <core/web_server.hpp>

namespace {

namespace net   = boost::asio;
namespace beast = boost::beast;
namespace http  = boost::beast::http;
using tcp = boost::asio::ip::tcp;
using namespace std::chrono_literals;

http::response<http::string_body> fetch(uint16_t port, const std::string& target,
                                        const std::vector<std::pair<std::string, std::string>>& headers = {})
{
    net::io_context ioc;
    tcp::socket sock(ioc);
    sock.connect(tcp::endpoint(net::ip::make_address("127.0.0.1"), port));
    http::request<http::string_body> req{http::verb::get, target, 11};
    req.set(http::field::host, "127.0.0.1");
    for (const auto& [n, v] : headers) req.set(n, v);
    http::write(sock, req);
    beast::flat_buffer buffer;
    http::response<http::string_body> res;
    http::read(sock, buffer, res);
    beast::error_code ec;
    sock.shutdown(tcp::socket::shutdown_both, ec);
    return res;
}

nlohmann::json scanned_reply(const std::string& query)
{
    return {{"ok", true}, {"scanned", 3}, {"query", query}, {"http_status", 200}};
}

} // namespace

TEST(WebUtxoScan, RouteIsDirectLocalAndUnwiredAnswers404)
{
    net::io_context ioc;
    core::WebServer ws(ioc, "127.0.0.1", 0, false);
    ws.set_stratum_port(0);
    ws.start();
    const uint16_t port = ws.bound_port();

    auto res = fetch(port, "/api/utxo/scan?script=51");
    EXPECT_EQ(res.result_int(), 404);
    EXPECT_NE(res.body().find("utxo-scan-not-wired"), std::string::npos) << res.body();

    std::atomic<int> calls{0};
    std::atomic<bool> other_thread{false};
    const auto http_caller = std::this_thread::get_id();
    ws.get_mining_interface()->set_utxo_scan_fn([&](const std::string& q, const std::atomic<bool>&) {
        ++calls;
        other_thread = std::this_thread::get_id() != http_caller;
        return scanned_reply(q);
    });

    // A same-host reverse proxy connects from 127.0.0.1 but adds a header.
    for (const char* h : {"X-Forwarded-For", "Forwarded", "X-Real-IP", "X-Forwarded-Host", "X-Forwarded-Proto"}) {
        res = fetch(port, "/api/utxo/scan?script=51", {{h, "203.0.113.7"}});
        EXPECT_EQ(res.result_int(), 403) << h;
        EXPECT_NE(res.body().find("utxo-scan-local-only"), std::string::npos) << res.body();
    }
    EXPECT_EQ(calls.load(), 0) << "a refused request never reaches the scan";

    res = fetch(port, "/api/utxo/scan?address=Xabc&script=76a9&limit=5");
    ASSERT_EQ(res.result_int(), 200) << res.body();
    const auto j = nlohmann::json::parse(res.body());
    EXPECT_EQ(j["query"], "address=Xabc&script=76a9&limit=5") << "the raw query reaches the fn";
    EXPECT_FALSE(j.contains("http_status")) << "the hint is consumed by the route";
    EXPECT_EQ(calls.load(), 1);
    EXPECT_TRUE(other_thread.load());
    // That pass used the interval: the next request is refused by the rate.
    res = fetch(port, "/api/utxo/scan?script=51");
    EXPECT_EQ(res.result_int(), 429);
    EXPECT_NE(res.body().find("utxo-scan-rate"), std::string::npos) << res.body();
    EXPECT_EQ(calls.load(), 1);
    ws.stop();
}

TEST(WebUtxoScan, TheFnsStatusHintIsTheWireStatus)
{
    net::io_context ioc;
    core::WebServer ws(ioc, "127.0.0.1", 0, false);
    ws.set_stratum_port(0);
    ws.get_mining_interface()->set_utxo_scan_fn([](const std::string&, const std::atomic<bool>&) {
        return nlohmann::json{{"ok", false}, {"error", "utxo-set-catching-up"}, {"http_status", 409}};
    });
    ws.start();
    for (int i = 0; i < 2; ++i) {   // a refusal before the pass: the interval stays free
        const auto res = fetch(ws.bound_port(), "/api/utxo/scan?script=51");
        EXPECT_EQ(res.result_int(), 409) << i;
        EXPECT_NE(res.body().find("utxo-set-catching-up"), std::string::npos) << res.body();
        EXPECT_EQ(res.body().find("http_status"), std::string::npos) << res.body();
    }
    ws.stop();
}

TEST(WebUtxoScan, RunsOnTheScanThreadOneAtATime)
{
    core::MiningInterface mi(false, nullptr, c2pool::address::Blockchain::DASH);
    std::promise<void> release;
    auto released = release.get_future().share();
    std::atomic<bool> started{false};
    std::thread::id scan_thread;
    mi.set_utxo_scan_fn([&](const std::string& q, const std::atomic<bool>&) {
        scan_thread = std::this_thread::get_id();
        started = true;
        released.wait();
        return scanned_reply(q);
    });
    ASSERT_TRUE(mi.has_utxo_scan_fn());
    auto first = std::async(std::launch::async, [&] { return mi.rest_utxo_scan("script=51"); });
    while (!started.load()) std::this_thread::sleep_for(1ms);

    const auto busy = mi.rest_utxo_scan("script=52");
    EXPECT_EQ(busy["http_status"], 409);
    EXPECT_EQ(busy["error"], "utxo-scan-busy");

    release.set_value();
    const auto j = first.get();
    EXPECT_EQ(j["http_status"], 200);
    EXPECT_EQ(j["query"], "script=51");
    EXPECT_NE(scan_thread, std::this_thread::get_id());
    mi.stop_utxo_scan();
}

TEST(WebUtxoScan, OneScanPerIntervalAndRefusalsDoNotUseIt)
{
    core::MiningInterface mi(false, nullptr, c2pool::address::Blockchain::DASH);
    bool refuse = true;
    mi.set_utxo_scan_fn([&](const std::string& q, const std::atomic<bool>&) {
        if (refuse) return nlohmann::json{{"ok", false}, {"error", "utxo-scan-bad-script"}, {"http_status", 400}};
        return scanned_reply(q);
    });
    // Refused before any pass: no "scanned", the interval stays free.
    EXPECT_EQ(mi.rest_utxo_scan("script=zz")["http_status"], 400);
    EXPECT_EQ(mi.rest_utxo_scan("script=zz")["http_status"], 400);
    refuse = false;
    EXPECT_EQ(mi.rest_utxo_scan("script=51")["http_status"], 200);
    const auto rate = mi.rest_utxo_scan("script=51");
    EXPECT_EQ(rate["http_status"], 429);
    EXPECT_EQ(rate["error"], "utxo-scan-rate");
    ASSERT_TRUE(rate.contains("retry_after_ms"));
    EXPECT_GT(rate["retry_after_ms"].get<int64_t>(), 0);
    EXPECT_LE(rate["retry_after_ms"].get<int64_t>(),
              std::chrono::duration_cast<std::chrono::milliseconds>(core::MiningInterface::kUtxoScanMinInterval).count());
    // A request refused by the rate is itself no scan: still 429, not busy.
    EXPECT_EQ(mi.rest_utxo_scan("script=51")["http_status"], 429);
}

TEST(WebUtxoScan, TheWaitIsCappedAndTheScanFinishesAlone)
{
    core::MiningInterface mi(false, nullptr, c2pool::address::Blockchain::DASH);
    mi.set_utxo_scan_timeout(50ms);
    std::atomic<bool> finished{false};
    mi.set_utxo_scan_fn([&](const std::string& q, const std::atomic<bool>&) {
        std::this_thread::sleep_for(400ms);
        finished = true;
        return scanned_reply(q);
    });
    const auto t = mi.rest_utxo_scan("script=51");
    EXPECT_EQ(t["http_status"], 504);
    EXPECT_EQ(t["error"], "utxo-scan-timeout");
    EXPECT_FALSE(finished.load());
    EXPECT_EQ(mi.rest_utxo_scan("script=51")["error"], "utxo-scan-busy") << "the pass still runs";
    while (!finished.load()) std::this_thread::sleep_for(5ms);
    std::this_thread::sleep_for(20ms);
    EXPECT_EQ(mi.rest_utxo_scan("script=51")["error"], "utxo-scan-rate") << "it used the interval";
}

TEST(WebUtxoScan, StopCancelsTheRunningScanAndUnwires)
{
    core::MiningInterface mi(false, nullptr, c2pool::address::Blockchain::DASH);
    std::atomic<bool> started{false}, saw_cancel{false};
    mi.set_utxo_scan_fn([&](const std::string&, const std::atomic<bool>& cancel) {
        started = true;
        const auto until = std::chrono::steady_clock::now() + 5s;
        while (!cancel.load() && std::chrono::steady_clock::now() < until) std::this_thread::sleep_for(1ms);
        saw_cancel = cancel.load();
        return nlohmann::json{{"ok", false}, {"error", "utxo-scan-cancelled"}, {"scanned", 0}, {"http_status", 503}};
    });
    auto running = std::async(std::launch::async, [&] { return mi.rest_utxo_scan("script=51"); });
    while (!started.load()) std::this_thread::sleep_for(1ms);
    mi.stop_utxo_scan();
    EXPECT_TRUE(saw_cancel.load());
    EXPECT_EQ(running.get()["http_status"], 503);
    EXPECT_FALSE(mi.has_utxo_scan_fn());
    EXPECT_EQ(mi.rest_utxo_scan("script=51")["error"], "utxo-scan-not-wired");
    // Installing after stop is a no-op (the thread is gone for good).
    mi.set_utxo_scan_fn([](const std::string& q, const std::atomic<bool>&) { return scanned_reply(q); });
    EXPECT_FALSE(mi.has_utxo_scan_fn());
}

TEST(WebUtxoScan, AThrowingScanAnswers500)
{
    core::MiningInterface mi(false, nullptr, c2pool::address::Blockchain::DASH);
    mi.set_utxo_scan_fn([](const std::string&, const std::atomic<bool>&) -> nlohmann::json {
        throw std::runtime_error("boom");
    });
    const auto j = mi.rest_utxo_scan("script=51");
    EXPECT_EQ(j["http_status"], 500);
    EXPECT_EQ(j["error"], "utxo-scan-failed");
    EXPECT_EQ(j["detail"], "boom");
    // The thread survives: a later request is served (no "scanned": the interval is free).
    mi.set_utxo_scan_fn([](const std::string& q, const std::atomic<bool>&) { return scanned_reply(q); });
    EXPECT_EQ(mi.rest_utxo_scan("script=51")["http_status"], 200);
}

// WebServer::stop() cancels a running pass before it joins the HTTP thread
// (which waits for the pass), so shutdown never waits a pass out.
TEST(WebUtxoScan, StopDoesNotWaitOutARunningPass)
{
    net::io_context ioc;
    auto ws = std::make_unique<core::WebServer>(ioc, "127.0.0.1", 0, false);
    ws->set_stratum_port(0);
    std::atomic<bool> started{false}, saw_cancel{false};
    ws->get_mining_interface()->set_utxo_scan_fn([&](const std::string&, const std::atomic<bool>& cancel) {
        started = true;
        const auto until = std::chrono::steady_clock::now() + 10s;
        while (!cancel.load() && std::chrono::steady_clock::now() < until) std::this_thread::sleep_for(1ms);
        saw_cancel = cancel.load();
        return nlohmann::json{{"ok", false}, {"error", "utxo-scan-cancelled"}, {"scanned", 0}, {"http_status", 503}};
    });
    ws->start();
    const uint16_t port = ws->bound_port();
    std::thread client([port] {
        try {
            fetch(port, "/api/utxo/scan?script=51");
        } catch (...) {
        }
    });
    while (!started.load()) std::this_thread::sleep_for(1ms);
    const auto t0 = std::chrono::steady_clock::now();
    ws->stop();
    const auto took = std::chrono::steady_clock::now() - t0;
    EXPECT_TRUE(saw_cancel.load()) << "the pass was cancelled by stop()";
    EXPECT_LT(took, 3s) << "stop() waited the pass out";
    ws.reset();
    client.join();
}
