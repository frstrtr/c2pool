// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Local-only gate for the sensitive web routes.
//
// /web/log and /logs/export show peer and miner IP addresses; /control/*
// changes pool state; /api/config, /api/admin/* and /api/tx-inject/* are
// documented local-only. Before this gate they trusted a loopback peer
// address alone, and /web/log, /logs/export and /control/* were fully open
// when no auth token was set (no main sets one). A reverse proxy on the same
// host (Caddy, nginx) connects from 127.0.0.1, so every proxied internet
// request looked local.
//
// Now, without an auth token, these routes answer only a direct local
// request: loopback peer AND no X-Forwarded-For / Forwarded / X-Real-IP
// header. With a token set, /web/log, /logs/export and /control/* need
// ?token= as before.
//
// The end-to-end cases run real HTTP requests through WebServer +
// HttpSession on 127.0.0.1; a proxied request is modelled by adding the
// header a reverse proxy adds. Non-loopback peers are covered through
// is_direct_local_request() directly.
#include <gtest/gtest.h>

#include <string>
#include <utility>
#include <vector>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include <core/web_server.hpp>
#include <core/config_endpoint.hpp>
#include <core/settings_file.hpp>
#include <core/param_catalog.hpp>

namespace {

namespace net   = boost::asio;
namespace beast = boost::beast;
namespace http  = boost::beast::http;
using tcp = boost::asio::ip::tcp;

namespace ce = c2pool::config_endpoint;
using namespace c2pool::settings;

using Headers = std::vector<std::pair<std::string, std::string>>;

// One loopback GET through the real server.
http::response<http::string_body> fetch(uint16_t port, const std::string& target,
                                        const Headers& headers)
{
    net::io_context ioc;
    tcp::socket sock(ioc);
    sock.connect(tcp::endpoint(net::ip::make_address("127.0.0.1"), port));

    http::request<http::string_body> req{http::verb::get, target, 11};
    req.set(http::field::host, "127.0.0.1");
    for (const auto& [name, value] : headers)
        req.set(name, value);
    http::write(sock, req);

    beast::flat_buffer buffer;
    http::response<http::string_body> res;
    http::read(sock, buffer, res);

    beast::error_code ec;
    sock.shutdown(tcp::socket::shutdown_both, ec);
    return res;
}

int get_status(uint16_t port, const std::string& target, const Headers& headers = {})
{
    return fetch(port, target, headers).result_int();
}

std::string get_body(uint16_t port, const std::string& target, const Headers& headers = {})
{
    return fetch(port, target, headers).body();
}

std::unique_ptr<core::WebServer> make_server(net::io_context& ioc)
{
    auto ws = std::make_unique<core::WebServer>(ioc, "127.0.0.1", 0, false);
    ws->set_stratum_port(0);
    auto* mi = ws->get_mining_interface();
    mi->set_config_fns(
        []() { return ce::resolved_config_json(); },
        []() { return ce::catalog_schema_json(); });
    ws->start();
    return ws;
}

void publish_config()
{
    auto rc = std::make_shared<ResolvedConfig>();
    rc->seed_compiled_defaults(c2pool::catalog::C_DASH);
    ce::publish_resolved(rc, c2pool::catalog::C_DASH, "/tmp/x.toml");
}

http::fields with_header(const std::string& name, const std::string& value)
{
    http::fields f;
    f.set(name, value);
    return f;
}

}  // namespace

// ── is_direct_local_request(): peer address × proxy headers ────────────────

TEST(WebLocalOnly, LoopbackPeersWithoutProxyHeaderAreLocal)
{
    const http::fields none;
    EXPECT_TRUE(core::is_direct_local_request(net::ip::make_address("127.0.0.1"), none));
    EXPECT_TRUE(core::is_direct_local_request(net::ip::make_address("127.8.9.10"), none));
    EXPECT_TRUE(core::is_direct_local_request(net::ip::make_address("::1"), none));
    EXPECT_TRUE(core::is_direct_local_request(net::ip::make_address("::ffff:127.0.0.1"), none));
}

TEST(WebLocalOnly, NonLoopbackPeersAreNotLocal)
{
    const http::fields none;
    for (const char* a : {"10.0.0.5", "192.168.1.2", "203.0.113.7", "0.0.0.0",
                          "2001:db8::1", "::ffff:203.0.113.7", "::"})
        EXPECT_FALSE(core::is_direct_local_request(net::ip::make_address(a), none)) << a;
}

TEST(WebLocalOnly, LoopbackPeerBehindProxyIsNotLocal)
{
    const auto lo = net::ip::make_address("127.0.0.1");
    EXPECT_FALSE(core::is_direct_local_request(lo, with_header("X-Forwarded-For", "203.0.113.7")));
    EXPECT_FALSE(core::is_direct_local_request(lo, with_header("x-forwarded-for", "203.0.113.7")));
    EXPECT_FALSE(core::is_direct_local_request(lo, with_header("Forwarded", "for=203.0.113.7")));
    EXPECT_FALSE(core::is_direct_local_request(lo, with_header("X-Real-IP", "203.0.113.7")));
    EXPECT_FALSE(core::is_direct_local_request(lo, with_header("X-Forwarded-Host", "pool.example")));
    EXPECT_FALSE(core::is_direct_local_request(lo, with_header("X-Forwarded-Proto", "https")));
    // Even a proxy that forwards a loopback client is still a proxy.
    EXPECT_FALSE(core::is_direct_local_request(lo, with_header("X-Forwarded-For", "127.0.0.1")));
    EXPECT_FALSE(core::is_direct_local_request(lo, with_header("X-Forwarded-For", "")));
}

// ── End to end, no auth token (every production main today) ────────────────

TEST(WebLocalOnly, LogsAndControlServeDirectLocalWithoutToken)
{
    net::io_context ioc;
    auto ws = make_server(ioc);
    const uint16_t port = ws->bound_port();

    EXPECT_EQ(get_status(port, "/web/log"), 200);
    EXPECT_EQ(get_status(port, "/logs/export?scope=all&format=csv"), 200);
    EXPECT_EQ(get_status(port, "/control/mining/unban?target=x"), 200);
}

TEST(WebLocalOnly, LogsAndControlRefuseProxiedRequestWithoutToken)
{
    net::io_context ioc;
    auto ws = make_server(ioc);
    const uint16_t port = ws->bound_port();
    const Headers xff{{"X-Forwarded-For", "203.0.113.7"}};

    EXPECT_EQ(get_status(port, "/web/log", xff), 403);
    EXPECT_EQ(get_status(port, "/logs/export?scope=all&format=csv", xff), 403);
    EXPECT_EQ(get_status(port, "/web/log", {{"Forwarded", "for=203.0.113.7"}}), 403);
    EXPECT_EQ(get_status(port, "/web/log", {{"X-Real-IP", "203.0.113.7"}}), 403);
    EXPECT_EQ(get_status(port, "/control/mining/stop", xff), 403);
    EXPECT_EQ(get_status(port, "/control/mining/ban?target=x", xff), 403);
    // The 403 comes from the new gate, not from another handler.
    EXPECT_NE(get_body(port, "/web/log", xff).find("Logs and control are local-only"),
              std::string::npos);
    // A public route is not gated by the header.
    EXPECT_NE(get_status(port, "/local_rate", xff), 403);
}

TEST(WebLocalOnly, ConfigApiRefusesProxiedRequest)
{
    publish_config();
    net::io_context ioc;
    auto ws = make_server(ioc);
    const uint16_t port = ws->bound_port();

    EXPECT_EQ(get_status(port, "/api/config"), 200);
    EXPECT_EQ(get_status(port, "/api/config", {{"X-Forwarded-For", "203.0.113.7"}}), 403);
    EXPECT_EQ(get_status(port, "/api/config/schema", {{"X-Forwarded-For", "203.0.113.7"}}), 403);
    EXPECT_EQ(get_status(port, "/api/admin/pool/bans/list", {{"X-Forwarded-For", "203.0.113.7"}}), 403);
}

// ── With an auth token set: the token is required, local or not ────────────

TEST(WebLocalOnly, TokenStillRequiredWhenSet)
{
    net::io_context ioc;
    auto ws = make_server(ioc);
    ws->get_mining_interface()->set_auth_token("t0k-local-only-test");
    const uint16_t port = ws->bound_port();
    const Headers xff{{"X-Forwarded-For", "203.0.113.7"}};

    EXPECT_EQ(get_status(port, "/web/log"), 401);
    EXPECT_EQ(get_status(port, "/web/log", xff), 401);
    EXPECT_EQ(get_status(port, "/web/log?token=wrong", xff), 401);
    EXPECT_EQ(get_status(port, "/web/log?token=t0k-local-only-test", xff), 200);
    EXPECT_EQ(get_status(port, "/logs/export?format=csv&token=t0k-local-only-test", xff), 200);
}
