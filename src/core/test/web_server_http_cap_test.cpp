// SPDX-License-Identifier: AGPL-3.0-or-later
//
// WebServer's HTTP session cap (set_max_http_connections, the HTTP share of
// the node's fd plan, doge::coin::FdPlan): a connection accepted beyond it
// is closed at once, a session's slot is freed when its connection ends,
// and 0 leaves HTTP unlimited. And a session's request-read deadlines
// (set_http_timeouts): a connection that sends nothing is closed, a client
// sending its request slowly but steadily is answered, one slower than the
// whole-request deadline is closed, and the event stream
// (/sharechain/stream) outlives both and keeps its place under the cap.

#include <gtest/gtest.h>

#include <chrono>
#include <functional>
#include <string>
#include <thread>
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

tcp::endpoint local(uint16_t port) { return tcp::endpoint(net::ip::make_address("127.0.0.1"), port); }

bool wait_until(const std::function<bool()>& done)
{
    for (int i = 0; i < 1000; ++i) {
        if (done())
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return done();
}

/// The server closed the connection (EOF or reset) within five seconds.
bool closed_by_server(tcp::socket& s)
{
    s.non_blocking(true);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    char ch = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        beast::error_code ec;
        s.read_some(net::buffer(&ch, 1), ec);
        if (ec == net::error::would_block) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }
        return ec == net::error::eof || ec == net::error::connection_reset;
    }
    return false;
}

/// A GET answered: the response's status code (0 when none was read).
unsigned get_status(uint16_t port, const std::string& target)
{
    net::io_context ioc;
    tcp::socket sock(ioc);
    beast::error_code ec;
    sock.connect(local(port), ec);
    if (ec)
        return 0;
    http::request<http::string_body> req{http::verb::get, target, 11};
    req.set(http::field::host, "127.0.0.1");
    http::write(sock, req, ec);
    if (ec)
        return 0;
    beast::flat_buffer buffer;
    http::response<http::string_body> res;
    http::read(sock, buffer, res, ec);
    if (ec)
        return 0;
    sock.shutdown(tcp::socket::shutdown_both, ec);
    return res.result_int();
}

/// What the server sent within `limit`, and whether it then closed.
struct Received {
    std::string bytes;
    bool closed = false;
};
Received receive(tcp::socket& s, std::chrono::milliseconds limit)
{
    Received r;
    s.non_blocking(true);
    const auto deadline = std::chrono::steady_clock::now() + limit;
    char buf[4096];
    while (std::chrono::steady_clock::now() < deadline) {
        beast::error_code ec;
        const std::size_t n = s.read_some(net::buffer(buf), ec);
        if (ec == net::error::would_block) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }
        if (ec) {
            r.closed = ec == net::error::eof || ec == net::error::connection_reset;
            break;
        }
        r.bytes.append(buf, n);
    }
    return r;
}

/// `request` sent in `pieces` parts, `gap` apart.
void send_slowly(tcp::socket& s, const std::string& request, int pieces, std::chrono::milliseconds gap)
{
    const std::size_t step = (request.size() + pieces - 1) / pieces;
    for (std::size_t off = 0; off < request.size(); off += step) {
        beast::error_code ec;
        net::write(s, net::buffer(request.data() + off, std::min(step, request.size() - off)), ec);
        if (ec)
            return;
        std::this_thread::sleep_for(gap);
    }
}

const std::string kStatsRequest = "GET /stratum_stats HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: kat\r\n\r\n";

} // namespace

TEST(WebServerHttpCap, AConnectionBeyondTheCapIsClosedAndASlotFreesWhenItsConnectionEnds)
{
    net::io_context ioc;
    core::WebServer ws(ioc, "127.0.0.1", 0, false);
    ws.set_stratum_port(0);
    ws.set_max_http_connections(2);
    ws.start();
    const uint16_t port = ws.bound_port();

    // Two connections that send nothing yet: each holds a session.
    net::io_context cio;
    tcp::socket a(cio), b(cio);
    a.connect(local(port));
    b.connect(local(port));
    ASSERT_TRUE(wait_until([&]() { return ws.http_sessions() == 2; })) << ws.http_sessions();

    // A third, beyond the cap: closed by the server, no session made.
    tcp::socket c(cio);
    c.connect(local(port));
    EXPECT_TRUE(closed_by_server(c));
    EXPECT_EQ(ws.http_sessions(), 2u);

    // One ends: its slot is freed, and a request is answered again.
    a.close();
    ASSERT_TRUE(wait_until([&]() { return ws.http_sessions() == 1; })) << ws.http_sessions();
    EXPECT_NE(get_status(port, "/stratum_stats"), 0u);
    ASSERT_TRUE(wait_until([&]() { return ws.http_sessions() == 1; })) << ws.http_sessions();
    b.close();
    EXPECT_TRUE(wait_until([&]() { return ws.http_sessions() == 0; })) << ws.http_sessions();
    ws.stop();
}

TEST(WebServerHttpCap, NoCapLeavesHttpUnlimited)
{
    net::io_context ioc;
    core::WebServer ws(ioc, "127.0.0.1", 0, false);
    ws.set_stratum_port(0);
    ws.start();
    const uint16_t port = ws.bound_port();
    net::io_context cio;
    std::vector<tcp::socket> held;
    for (int i = 0; i < 8; ++i) {
        held.emplace_back(cio);
        held.back().connect(local(port));
    }
    ASSERT_TRUE(wait_until([&]() { return ws.http_sessions() == 8; })) << ws.http_sessions();
    EXPECT_NE(get_status(port, "/stratum_stats"), 0u);
    held.clear();
    EXPECT_TRUE(wait_until([&]() { return ws.http_sessions() == 0; })) << ws.http_sessions();
    ws.stop();
}

TEST(WebServerHttpDeadline, AConnectionThatSendsNothingIsClosed)
{
    net::io_context ioc;
    core::WebServer ws(ioc, "127.0.0.1", 0, false);
    ws.set_stratum_port(0);
    ws.set_http_timeouts(std::chrono::milliseconds(200), std::chrono::milliseconds(2000));
    ws.start();
    const uint16_t port = ws.bound_port();
    net::io_context cio;
    tcp::socket a(cio);
    const auto t0 = std::chrono::steady_clock::now();
    a.connect(local(port));
    const Received r = receive(a, std::chrono::seconds(5));
    const auto waited = std::chrono::steady_clock::now() - t0;
    EXPECT_TRUE(r.closed);
    EXPECT_TRUE(r.bytes.empty());
    EXPECT_GE(waited, std::chrono::milliseconds(150));
    EXPECT_LT(waited, std::chrono::seconds(2)) << "the idle deadline, not the whole-request one";
    EXPECT_TRUE(wait_until([&]() { return ws.http_sessions() == 0; })) << ws.http_sessions();
    ws.stop();
}

TEST(WebServerHttpDeadline, AClientSendingSlowlyButSteadilyIsAnswered)
{
    net::io_context ioc;
    core::WebServer ws(ioc, "127.0.0.1", 0, false);
    ws.set_stratum_port(0);
    ws.set_http_timeouts(std::chrono::milliseconds(400), std::chrono::milliseconds(10000));
    ws.start();
    const uint16_t port = ws.bound_port();
    net::io_context cio;
    tcp::socket a(cio);
    a.connect(local(port));
    // 8 parts 150 ms apart: 1.2 s in all, three times the idle deadline.
    send_slowly(a, kStatsRequest, 8, std::chrono::milliseconds(150));
    const Received r = receive(a, std::chrono::seconds(5));
    EXPECT_EQ(r.bytes.rfind("HTTP/1.1 200", 0), 0u) << r.bytes.substr(0, 80);
    EXPECT_TRUE(r.closed) << "closed after the response, as every response";
    ws.stop();
}

TEST(WebServerHttpDeadline, AClientSlowerThanTheWholeRequestDeadlineIsClosed)
{
    net::io_context ioc;
    core::WebServer ws(ioc, "127.0.0.1", 0, false);
    ws.set_stratum_port(0);
    ws.set_http_timeouts(std::chrono::milliseconds(400), std::chrono::milliseconds(700));
    ws.start();
    const uint16_t port = ws.bound_port();
    net::io_context cio;
    tcp::socket a(cio);
    a.connect(local(port));
    // 16 parts 100 ms apart: never idle for 400 ms, but 1.6 s in all.
    send_slowly(a, kStatsRequest, 16, std::chrono::milliseconds(100));
    const Received r = receive(a, std::chrono::seconds(5));
    EXPECT_TRUE(r.closed);
    EXPECT_TRUE(r.bytes.empty()) << r.bytes.substr(0, 80);
    EXPECT_TRUE(wait_until([&]() { return ws.http_sessions() == 0; })) << ws.http_sessions();
    ws.stop();
}

TEST(WebServerHttpDeadline, TheEventStreamOutlivesTheDeadlinesAndKeepsItsPlace)
{
    net::io_context ioc;
    core::WebServer ws(ioc, "127.0.0.1", 0, false);
    ws.set_stratum_port(0);
    ws.set_max_http_connections(1);
    ws.set_http_timeouts(std::chrono::milliseconds(200), std::chrono::milliseconds(400));
    ws.start();
    const uint16_t port = ws.bound_port();
    net::io_context cio;
    tcp::socket a(cio);
    a.connect(local(port));
    net::write(a, net::buffer(std::string("GET /sharechain/stream HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")));
    // Past both deadlines the stream is open: its head, and no close.
    const Received r = receive(a, std::chrono::milliseconds(1200));
    EXPECT_NE(r.bytes.find("text/event-stream"), std::string::npos) << r.bytes.substr(0, 120);
    EXPECT_FALSE(r.closed);
    EXPECT_EQ(ws.http_sessions(), 1u) << "the stream holds its session's place under the cap";
    // The cap is reached: another connection is closed at once.
    tcp::socket b(cio);
    b.connect(local(port));
    EXPECT_TRUE(closed_by_server(b));
    ws.stop();
}
