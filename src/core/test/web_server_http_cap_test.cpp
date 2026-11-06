// SPDX-License-Identifier: AGPL-3.0-or-later
//
// WebServer's HTTP session cap (set_max_http_connections, the HTTP share of
// the node's fd plan, doge::coin::FdPlan): a connection accepted beyond it
// is closed at once, a session's slot is freed when its connection ends,
// and 0 leaves HTTP unlimited.

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
