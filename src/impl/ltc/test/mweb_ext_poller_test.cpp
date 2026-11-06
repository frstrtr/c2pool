// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The getblocktemplate poller of the hybrid MWEB extension (#2137 S3; rides
// share_test): a slow or dead litecoind never stalls the io thread.
//   - PollSchedule: every 5 s while G is for the tip, 0.5 s for 10 s after a
//     tip change while it is not, 1-2-4-5 s after failures;
//   - MwebExtPoller: a fetch at once on start and on every tip change, the
//     retry cadence, the period, nothing after stop();
//   - fetch_gbt against a local JSON-RPC server (the request litecoind
//     needs, the credentials, the result; an RPC error), a server that never
//     answers (one timeout), a closed port and a host name (at once: only IP
//     addresses, no name is resolved);
//   - a live litecoind when C2POOL_LTC_MWEB_EXT_LIVE names one (skipped
//     otherwise).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio.hpp>

#include <nlohmann/json.hpp>

#include "ltc_mweb_ext_fixtures.hpp"
#include "ltc_mweb_tx_fixtures.hpp"

#include <impl/ltc/coin/mweb_ext_poller.hpp>

namespace {

namespace mx = ltc::coin::mweb_ext;
namespace xf = ltc_mweb_ext_fixture;
namespace tf = ltc_mweb_tx_fixture;

uint256 u256(const char* hex)
{
    uint256 v;
    v.SetHex(hex);
    return v;
}

} // namespace

TEST(LtcMwebExtPoller, PollScheduleCadence)
{
    using ms = std::chrono::milliseconds;
    const mx::PollSchedule s;
    EXPECT_EQ(s.next_delay(true, true, ms(0), 0), ms(5000)) << "G for the tip: every 5 s";
    EXPECT_EQ(s.next_delay(true, false, ms(200), 0), ms(500)) << "litecoind behind just after a block";
    EXPECT_EQ(s.next_delay(true, false, ms(9999), 0), ms(500));
    EXPECT_EQ(s.next_delay(true, false, ms(10000), 0), ms(5000)) << "litecoind elsewhere for long: every 5 s";
    EXPECT_EQ(s.next_delay(false, false, ms(0), 1), ms(1000));
    EXPECT_EQ(s.next_delay(false, false, ms(0), 2), ms(2000));
    EXPECT_EQ(s.next_delay(false, false, ms(0), 3), ms(4000));
    EXPECT_EQ(s.next_delay(false, false, ms(0), 4), ms(5000));
    EXPECT_EQ(s.next_delay(false, false, ms(0), 40), ms(5000));
}

// A fetch at once on start and on every tip change; the retry cadence while
// litecoind's answer is not for the tip, the period once it is; stop()
// joins.
TEST(LtcMwebExtPoller, PollerFetchesOnTipChangeAndThenOnItsCadence)
{
    using clock = std::chrono::steady_clock;
    std::mutex mu;
    std::string answer_prev = std::string(64, '0');
    std::vector<clock::time_point> fetched;
    std::vector<std::string> delivered;
    mx::PollSchedule sched;
    sched.period = std::chrono::milliseconds(400);
    sched.retry = std::chrono::milliseconds(60);
    sched.fast_window = std::chrono::milliseconds(2000);
    mx::MwebExtPoller poller(
        [&]() {
            std::lock_guard<std::mutex> lk(mu);
            fetched.push_back(clock::now());
            mx::FetchResult r;
            r.ok = true;
            r.result = {{"previousblockhash", answer_prev}};
            r.at = clock::now();
            return r;
        },
        [&](mx::FetchResult&& r, const uint256&) {
            std::lock_guard<std::mutex> lk(mu);
            delivered.push_back(r.result["previousblockhash"].get<std::string>());
        },
        sched);
    auto count = [&] {
        std::lock_guard<std::mutex> lk(mu);
        return fetched.size();
    };
    auto wait_for = [&](size_t n, std::chrono::milliseconds limit) {
        const auto until = clock::now() + limit;
        while (count() < n && clock::now() < until)
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        return count() >= n;
    };

    uint256 tip = u256(xf::kHash3200604);
    poller.notify_tip(tip);
    poller.start();
    ASSERT_TRUE(wait_for(1, std::chrono::milliseconds(1000))) << "a fetch at once";
    // litecoind is not at our tip yet: the retry cadence (60 ms).
    ASSERT_TRUE(wait_for(4, std::chrono::milliseconds(1500)));
    {
        std::lock_guard<std::mutex> lk(mu);
        const auto gap = fetched[3] - fetched[2];
        EXPECT_LT(gap, std::chrono::milliseconds(300)) << "retry, not the period";
        answer_prev = tip.GetHex();  // litecoind has the block now
    }
    // The next answer is for the tip: the period (400 ms) follows.
    const size_t n0 = count();
    ASSERT_TRUE(wait_for(n0 + 1, std::chrono::milliseconds(1000)));
    const size_t n1 = count();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_LE(count(), n1 + 1) << "no retry once G is for the tip";
    // A tip change: a fetch at once, not at the end of the period.
    const auto t_change = clock::now();
    const size_t before = count();
    {
        std::lock_guard<std::mutex> lk(mu);
        answer_prev = tip.GetHex();
    }
    poller.notify_tip(u256(xf::kHash3200603));
    ASSERT_TRUE(wait_for(before + 1, std::chrono::milliseconds(1000)));
    {
        std::lock_guard<std::mutex> lk(mu);
        EXPECT_LT(fetched.back() - t_change, std::chrono::milliseconds(300)) << "on the tip change";
    }
    poller.stop();
    const size_t stopped = count();
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    EXPECT_EQ(count(), stopped) << "nothing after stop()";
    std::lock_guard<std::mutex> lk(mu);
    EXPECT_EQ(delivered.size(), fetched.size());
}

namespace {

// A one-connection HTTP server on 127.0.0.1: answers `response` (or nothing
// when empty, holding the connection) and keeps the request it read.
struct LocalRpc {
    boost::asio::io_context io;
    boost::asio::ip::tcp::acceptor acceptor{io, {boost::asio::ip::make_address("127.0.0.1"), 0}};
    std::string response;
    std::string request;
    std::thread th;
    std::atomic<bool> stop{false};

    uint16_t port() const { return acceptor.local_endpoint().port(); }
    void run()
    {
        th = std::thread([this] {
            boost::system::error_code ec;
            boost::asio::ip::tcp::socket sock(io);
            acceptor.accept(sock, ec);
            if (ec)
                return;
            char buf[8192];
            std::string got;
            while (got.find("\r\n\r\n") == std::string::npos) {
                const size_t n = sock.read_some(boost::asio::buffer(buf), ec);
                if (ec)
                    return;
                got.append(buf, n);
            }
            const auto cl = got.find("Content-Length: ");
            const size_t body_at = got.find("\r\n\r\n") + 4;
            const size_t len = cl == std::string::npos ? 0 : std::stoul(got.substr(cl + 16));
            while (got.size() < body_at + len) {
                const size_t n = sock.read_some(boost::asio::buffer(buf), ec);
                if (ec)
                    return;
                got.append(buf, n);
            }
            request = got;
            if (response.empty()) {
                while (!stop.load())
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                return;
            }
            boost::asio::write(sock, boost::asio::buffer(response), ec);
        });
    }
    ~LocalRpc()
    {
        stop = true;
        boost::system::error_code ec;
        acceptor.close(ec);
        if (th.joinable())
            th.join();
    }
};

std::string http_ok(const std::string& body)
{
    return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(body.size())
         + "\r\n\r\n" + body;
}

} // namespace

// fetch_gbt asks litecoind for getblocktemplate {rules:[mweb,segwit]} with
// the RPC credentials and returns its result; an RPC error is no G.
TEST(LtcMwebExtPoller, FetchGbtFromALocalJsonRpcServer)
{
    {
        LocalRpc srv;
        const std::string body = std::string(R"({"result":)") + tf::kGbt3200605Json + R"(,"error":null,"id":"c2pool-mweb-ext"})";
        srv.response = http_ok(body);
        srv.run();
        auto r = mx::fetch_gbt({"127.0.0.1", srv.port(), "u:p"}, std::chrono::milliseconds(2000));
        ASSERT_TRUE(r.ok) << r.error;
        EXPECT_EQ(r.result["previousblockhash"].get<std::string>(), xf::kHash3200604);
        EXPECT_NE(srv.request.find("\"method\":\"getblocktemplate\""), std::string::npos);
        EXPECT_NE(srv.request.find(R"("rules":["mweb","segwit"])"), std::string::npos);
        EXPECT_NE(srv.request.find("Basic dTpw"), std::string::npos) << "base64(u:p)";
        EXPECT_TRUE(mx::parse_extension(r.result).bundle);
    }
    {
        LocalRpc srv;
        srv.response = http_ok(R"({"result":null,"error":{"code":-10,"message":"Litecoin is downloading blocks..."},"id":1})");
        srv.run();
        auto r = mx::fetch_gbt({"127.0.0.1", srv.port(), "u:p"}, std::chrono::milliseconds(2000));
        EXPECT_FALSE(r.ok);
        EXPECT_FALSE(r.timeout);
        EXPECT_EQ(r.error, "Litecoin is downloading blocks...");
    }
}

// A litecoind that accepts and never answers costs one timeout, on the
// poller's thread; a closed port fails at once.
TEST(LtcMwebExtPoller, FetchGbtIsBoundedByItsTimeout)
{
    using clock = std::chrono::steady_clock;
    {
        LocalRpc srv;  // no response: holds the connection
        srv.run();
        const auto t0 = clock::now();
        auto r = mx::fetch_gbt({"127.0.0.1", srv.port(), "u:p"}, std::chrono::milliseconds(300));
        const auto took = clock::now() - t0;
        EXPECT_FALSE(r.ok);
        EXPECT_TRUE(r.timeout) << r.error;
        EXPECT_GE(took, std::chrono::milliseconds(250));
        EXPECT_LT(took, std::chrono::milliseconds(1500));
    }
    {
        uint16_t closed = 0;
        {
            boost::asio::io_context io;
            boost::asio::ip::tcp::acceptor a(io, {boost::asio::ip::make_address("127.0.0.1"), 0});
            closed = a.local_endpoint().port();
        }
        const auto t0 = clock::now();
        auto r = mx::fetch_gbt({"127.0.0.1", closed, "u:p"}, std::chrono::milliseconds(2000));
        EXPECT_FALSE(r.ok);
        EXPECT_LT(clock::now() - t0, std::chrono::milliseconds(1500));
    }
    {
        // A name is never resolved (no DNS query, whose time no timeout
        // bounds): refused at once.
        const auto t0 = clock::now();
        auto r = mx::fetch_gbt({"litecoind.invalid", 9332, "u:p"}, std::chrono::milliseconds(2000));
        EXPECT_FALSE(r.ok);
        EXPECT_FALSE(r.timeout);
        EXPECT_NE(r.error.find("not an IP address"), std::string::npos) << r.error;
        EXPECT_LT(clock::now() - t0, std::chrono::milliseconds(100));
    }
}

// A live litecoind, when C2POOL_LTC_MWEB_EXT_LIVE=HOST:PORT:USER:PASSWORD is
// set (read-only: one getblocktemplate); skipped otherwise. The answer
// parses as an extension when MWEB is active there, else as no-mweb.
TEST(LtcMwebExtPoller, LiveLitecoindWhenConfigured)
{
    const char* env = std::getenv("C2POOL_LTC_MWEB_EXT_LIVE");
    if (!env || !*env)
        GTEST_SKIP() << "C2POOL_LTC_MWEB_EXT_LIVE not set";
    const std::string spec = env;
    const auto a = spec.find(':'), b = spec.find(':', a + 1), c = spec.find(':', b + 1);
    ASSERT_TRUE(a != std::string::npos && b != std::string::npos && c != std::string::npos);
    const mx::RpcEndpoint ep{spec.substr(0, a), static_cast<uint16_t>(std::stoi(spec.substr(a + 1, b - a - 1))),
                             spec.substr(b + 1)};
    auto r = mx::fetch_gbt(ep, std::chrono::milliseconds(3000));
    ASSERT_TRUE(r.ok) << r.error;
    ASSERT_TRUE(r.result.contains("previousblockhash"));
    auto p = mx::parse_extension(r.result);
    std::cout << "live getblocktemplate: height " << r.result.value("height", 0) << ", "
              << r.result["transactions"].size() << " txs, " << r.ms << " ms, parse "
              << (p.bundle ? std::string("ok") : p.reason) << std::endl;
    if (r.result.contains("mweb"))
        EXPECT_TRUE(p.bundle) << p.reason << ": " << p.detail;
    else
        EXPECT_EQ(p.reason, mx::kNoMweb);
}
