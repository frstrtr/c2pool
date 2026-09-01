// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Control-plane M1 (SAFE half) PRESENT-CHECK: a REAL loopback HTTP request
// through the actual WebServer + HttpSession routing (NOT a stubbed method
// call). Stands up a WebServer on 127.0.0.1:<ephemeral>, installs the config
// fns, publishes a resolved snapshot, and issues genuine boost::beast GET/POST
// requests:
//
//   GET  /api/config          -> 200 + resolved-config JSON (keys, money row)
//   GET  /api/config/schema   -> 200 + catalog schema (tri key type)
//   POST /api/config/apply     -> 503 + {"armed":false}  (dormancy present-checked)
//   GET  /api/config (unwired) -> 404                     (harmless fail-safe)
//
// Coin-genericity is proven by publishing DASH and DGB snapshots and asserting
// the coin field + mask-applicable keys track the published coin.
#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include <nlohmann/json.hpp>

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

// One synchronous loopback HTTP request through the real server.
std::string do_request(uint16_t port, http::verb method, const std::string& target,
                       int& status_out) {
    net::io_context ioc;
    tcp::socket sock(ioc);
    sock.connect(tcp::endpoint(net::ip::make_address("127.0.0.1"), port));

    http::request<http::string_body> req{method, target, 11};
    req.set(http::field::host, "127.0.0.1");
    req.set(http::field::user_agent, "m1-present-check");
    if (method == http::verb::post) {
        req.body() = "{}";
        req.prepare_payload();
    }
    http::write(sock, req);

    beast::flat_buffer buffer;
    http::response<http::string_body> res;
    http::read(sock, buffer, res);
    status_out = res.result_int();

    beast::error_code ec;
    sock.shutdown(tcp::socket::shutdown_both, ec);
    return res.body();
}

// Stand up a WebServer with config fns installed; caller publishes first.
std::unique_ptr<core::WebServer> make_wired_server(net::io_context& ioc) {
    auto ws = std::make_unique<core::WebServer>(ioc, "127.0.0.1", 0, false);
    ws->set_stratum_port(0);  // no stratum acceptor for this test
    auto* mi = ws->get_mining_interface();
    mi->set_config_fns(
        []() { return ce::resolved_config_json(); },
        []() { return ce::catalog_schema_json(); });
    ws->start();
    return ws;
}

std::shared_ptr<ResolvedConfig> dash_snapshot() {
    auto rc = std::make_shared<ResolvedConfig>();
    rc->seed_compiled_defaults(c2pool::catalog::C_DASH);
    rc->set("web.port", "8080", Source::Cli);
    return rc;
}

} // namespace

TEST(ConfigEndpointHttp, GetConfigReturnsResolvedJson) {
    ce::publish_resolved(dash_snapshot(), c2pool::catalog::C_DASH, "/tmp/x.toml");
    net::io_context ioc;
    auto ws = make_wired_server(ioc);

    int status = 0;
    auto body = do_request(ws->bound_port(), http::verb::get, "/api/config", status);
    EXPECT_EQ(status, 200);
    auto j = nlohmann::json::parse(body);
    EXPECT_EQ(j.value("coin", std::string()), "dash");
    EXPECT_FALSE(j.value("apply_armed", true));
    ASSERT_TRUE(j.contains("keys"));
    ASSERT_TRUE(j["keys"].contains("web.port"));
    EXPECT_EQ(j["keys"]["web.port"].value("value", std::string()), "8080");
    // A money-class row carries its mutability + money flag.
    ASSERT_TRUE(j["keys"].contains("embedded.tx_serve_own_set"));
    EXPECT_TRUE(j["keys"]["embedded.tx_serve_own_set"].value("money", false));
    EXPECT_FALSE(j["keys"]["embedded.tx_serve_own_set"].value("mutability",
                                                              std::string()).empty());
}

TEST(ConfigEndpointHttp, GetSchemaReturnsCatalog) {
    ce::publish_resolved(dash_snapshot(), c2pool::catalog::C_DASH, "/tmp/x.toml");
    net::io_context ioc;
    auto ws = make_wired_server(ioc);

    int status = 0;
    auto body = do_request(ws->bound_port(), http::verb::get, "/api/config/schema", status);
    EXPECT_EQ(status, 200);
    auto j = nlohmann::json::parse(body);
    ASSERT_TRUE(j.contains("params"));
    bool found_tri = false;
    for (const auto& p : j["params"]) {
        if (p.value("canon", std::string()) == "embedded.serve_mempool_txs") {
            found_tri = (p.value("type", std::string()) == "tristate_bool");
        }
    }
    EXPECT_TRUE(found_tri) << "schema must carry embedded.serve_mempool_txs as tristate_bool";
}

TEST(ConfigEndpointHttp, PostApplyIsInert503) {
    ce::publish_resolved(dash_snapshot(), c2pool::catalog::C_DASH, "/tmp/x.toml");
    net::io_context ioc;
    auto ws = make_wired_server(ioc);

    int status = 0;
    auto body = do_request(ws->bound_port(), http::verb::post, "/api/config/apply", status);
    EXPECT_EQ(status, 503) << "runtime mutation must be inert (operator-gated)";
    auto j = nlohmann::json::parse(body);
    EXPECT_FALSE(j.value("armed", true)) << "apply endpoint must report armed:false";
}

TEST(ConfigEndpointHttp, UnwiredInterfaceReturns404) {
    // A server WITHOUT set_config_fns must 404 (a main that forgot to wire).
    net::io_context ioc;
    auto ws = std::make_unique<core::WebServer>(ioc, "127.0.0.1", 0, false);
    ws->set_stratum_port(0);
    ws->start();

    int status = 0;
    do_request(ws->bound_port(), http::verb::get, "/api/config", status);
    EXPECT_EQ(status, 404);
}

TEST(ConfigEndpointHttp, CoinGenericDgb) {
    // Re-publish a DGB snapshot: the same shared endpoint must report the DGB
    // coin and only DGB-applicable catalog rows (mask-driven, coin-generic).
    auto rc = std::make_shared<ResolvedConfig>();
    rc->seed_compiled_defaults(c2pool::catalog::C_DGB);
    ce::publish_resolved(rc, c2pool::catalog::C_DGB, "/tmp/dgb.toml");
    net::io_context ioc;
    auto ws = make_wired_server(ioc);

    int status = 0;
    auto body = do_request(ws->bound_port(), http::verb::get, "/api/config", status);
    EXPECT_EQ(status, 200);
    auto j = nlohmann::json::parse(body);
    EXPECT_EQ(j.value("coin", std::string()), "dgb");
    // A DASH-only embedded lever must NOT appear under the DGB mask.
    EXPECT_FALSE(j["keys"].contains("embedded.tx_serve_own_set"))
        << "DGB config must not carry DASH-only embedded keys";
}
