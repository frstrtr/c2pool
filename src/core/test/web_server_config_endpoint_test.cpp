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

// One synchronous loopback HTTP request through the real server. `post_body`
// is used only for POST (defaults to an empty JSON object).
std::string do_request(uint16_t port, http::verb method, const std::string& target,
                       int& status_out, const std::string& post_body = "{}") {
    net::io_context ioc;
    tcp::socket sock(ioc);
    sock.connect(tcp::endpoint(net::ip::make_address("127.0.0.1"), port));

    http::request<http::string_body> req{method, target, 11};
    req.set(http::field::host, "127.0.0.1");
    req.set(http::field::user_agent, "m1-present-check");
    if (method == http::verb::post) {
        req.set(http::field::content_type, "application/json");
        req.body() = post_body;
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

// Slice A (#157): stand up a server whose POST /api/config/apply is WIRED to the
// live gated-apply path. The caller must still arm it by registering a control
// token (ce::set_control_token) — an unarmed wired server stays 503.
std::unique_ptr<core::WebServer> make_apply_server(net::io_context& ioc) {
    auto ws = std::make_unique<core::WebServer>(ioc, "127.0.0.1", 0, false);
    ws->set_stratum_port(0);
    auto* mi = ws->get_mining_interface();
    mi->set_config_fns(
        []() { return ce::resolved_config_json(); },
        []() { return ce::catalog_schema_json(); });
    mi->set_config_apply_fn([](const std::string& body) {
        auto req  = ce::parse_apply_request(body);
        auto resp = ce::apply_config(req);
        auto j    = resp.to_json();
        j["http_status"] = resp.http_status;
        return j;
    });
    ws->start();
    return ws;
}

// Reset all process-global Slice A gate state so each armed test is isolated.
void reset_apply_state() {
    ce::clear_control_token();
    ce::clear_money_nonces();
    ce::reset_tripwire();
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

// DORMANT posture (Slice A): with NO apply fn installed, POST stays 503
// {"armed":false} — the M1 inert behavior is preserved for every production
// main (none wire the apply fn).
TEST(ConfigEndpointHttp, PostApplyDormantWhenUnwired) {
    ce::publish_resolved(dash_snapshot(), c2pool::catalog::C_DASH, "/tmp/x.toml");
    net::io_context ioc;
    auto ws = make_wired_server(ioc);   // read fns only; no apply fn

    int status = 0;
    auto body = do_request(ws->bound_port(), http::verb::post, "/api/config/apply", status);
    EXPECT_EQ(status, 503) << "unwired apply must be inert (operator-gated)";
    auto j = nlohmann::json::parse(body);
    EXPECT_FALSE(j.value("armed", true)) << "apply endpoint must report armed:false";
}

// DORMANT posture (Slice A): even with the apply fn WIRED, the endpoint stays
// 503 {"armed":false} until an operator registers the loopback control token.
TEST(ConfigEndpointHttp, PostApplyWiredButUnarmedStays503) {
    reset_apply_state();  // no control token
    ce::publish_resolved(dash_snapshot(), c2pool::catalog::C_DASH, "/tmp/x.toml");
    net::io_context ioc;
    auto ws = make_apply_server(ioc);

    int status = 0;
    nlohmann::json changes = {{"changes", {{"web.port", "9091"}}}};
    auto body = do_request(ws->bound_port(), http::verb::post, "/api/config/apply",
                           status, changes.dump());
    EXPECT_EQ(status, 503) << "wired-but-unarmed apply must report 503";
    auto j = nlohmann::json::parse(body);
    EXPECT_FALSE(j.value("armed", true));
}

// A non-money write applies behind a valid control token + schema validation,
// and the resolved-config mirror reflects it.
TEST(ConfigEndpointHttp, PostApplyNonMoneyAppliesWithToken) {
    reset_apply_state();
    ce::publish_resolved(dash_snapshot(), c2pool::catalog::C_DASH, "/tmp/x.toml");
    ce::set_control_token("tok-abc");
    net::io_context ioc;
    auto ws = make_apply_server(ioc);

    int status = 0;
    nlohmann::json req = {{"control_token", "tok-abc"},
                          {"changes", {{"web.port", "9091"}}}};
    auto body = do_request(ws->bound_port(), http::verb::post, "/api/config/apply",
                           status, req.dump());
    EXPECT_EQ(status, 200) << body;
    auto j = nlohmann::json::parse(body);
    EXPECT_TRUE(j.value("applied", false)) << body;

    // The mirror behind GET /api/config now reports the applied value.
    auto cfg = nlohmann::json::parse(
        do_request(ws->bound_port(), http::verb::get, "/api/config", status));
    EXPECT_EQ(cfg["keys"]["web.port"].value("value", std::string()), "9091");
    // apply_armed flips true once the token is registered.
    EXPECT_TRUE(cfg.value("apply_armed", false));
}

// A valid token is REQUIRED: an armed endpoint refuses a request that omits it.
TEST(ConfigEndpointHttp, PostApplyRefusesWithoutToken) {
    reset_apply_state();
    ce::publish_resolved(dash_snapshot(), c2pool::catalog::C_DASH, "/tmp/x.toml");
    ce::set_control_token("tok-abc");
    net::io_context ioc;
    auto ws = make_apply_server(ioc);

    int status = 0;
    nlohmann::json req = {{"changes", {{"web.port", "9091"}}}};  // no token
    do_request(ws->bound_port(), http::verb::post, "/api/config/apply",
               status, req.dump());
    EXPECT_EQ(status, 403) << "missing control token must be refused";
}

// An unknown / not-applicable key is rejected with a named cause; nothing applies.
TEST(ConfigEndpointHttp, PostApplyRejectsUnknownKey) {
    reset_apply_state();
    ce::publish_resolved(dash_snapshot(), c2pool::catalog::C_DASH, "/tmp/x.toml");
    ce::set_control_token("tok-abc");
    net::io_context ioc;
    auto ws = make_apply_server(ioc);

    int status = 0;
    nlohmann::json req = {{"control_token", "tok-abc"},
                          {"changes", {{"no.such.key", "1"}}}};
    auto body = do_request(ws->bound_port(), http::verb::post, "/api/config/apply",
                           status, req.dump());
    EXPECT_EQ(status, 400) << body;
    auto j = nlohmann::json::parse(body);
    EXPECT_EQ(j.value("status", std::string()), "validation");
    EXPECT_EQ(j.value("offending_key", std::string()), "no.such.key");
}

// A money-path write WITHOUT a nonce does NOT apply: it issues a confirm nonce
// and leaves the config untouched (the tripwire does NOT fire — this is the
// sanctioned confirmation request).
TEST(ConfigEndpointHttp, PostApplyMoneyWithoutNonceIssuesConfirmAndAppliesNothing) {
    reset_apply_state();
    ce::publish_resolved(dash_snapshot(), c2pool::catalog::C_DASH, "/tmp/x.toml");
    ce::set_control_token("tok-abc");
    net::io_context ioc;
    auto ws = make_apply_server(ioc);

    int status = 0;
    nlohmann::json req = {{"control_token", "tok-abc"},
                          {"changes", {{"money.node_owner_fee_pct", "0.5"}}}};
    auto body = do_request(ws->bound_port(), http::verb::post, "/api/config/apply",
                           status, req.dump());
    EXPECT_EQ(status, 200) << body;
    auto j = nlohmann::json::parse(body);
    EXPECT_TRUE(j.value("need_confirm", false)) << body;
    EXPECT_FALSE(j.value("applied", true));
    EXPECT_FALSE(j.value("money_nonce", std::string()).empty());
    EXPECT_EQ(ce::tripwire_state().count, 0u)
        << "a phase-1 confirmation request must not trip the money wire";

    // The mirror is unchanged (the money key was never applied: a seeded-but-
    // unset compiled default reports an empty value).
    auto cfg = nlohmann::json::parse(
        do_request(ws->bound_port(), http::verb::get, "/api/config", status));
    EXPECT_EQ(cfg["keys"]["money.node_owner_fee_pct"].value("value", std::string()), "");
}

// The two-phase nonce is BOUND TO THE EXACT diff: a nonce issued for one diff
// must not confirm a different diff (that trips the wire + refuses), and it
// applies only when the confirmed diff matches.
TEST(ConfigEndpointHttp, PostApplyMoneyTwoPhaseNonceMustMatchDiff) {
    reset_apply_state();
    ce::publish_resolved(dash_snapshot(), c2pool::catalog::C_DASH, "/tmp/x.toml");
    ce::set_control_token("tok-abc");
    net::io_context ioc;
    auto ws = make_apply_server(ioc);

    // Phase 1: issue a nonce bound to fee=0.5.
    int status = 0;
    nlohmann::json issue = {{"control_token", "tok-abc"},
                            {"changes", {{"money.node_owner_fee_pct", "0.5"}}}};
    auto body = do_request(ws->bound_port(), http::verb::post, "/api/config/apply",
                           status, issue.dump());
    auto j = nlohmann::json::parse(body);
    const std::string nonce = j.value("money_nonce", std::string());
    ASSERT_FALSE(nonce.empty());

    // Phase 2a: present the nonce against a DIFFERENT diff (fee=0.7) -> refuse
    // + tripwire fires. No apply.
    nlohmann::json wrong = {{"control_token", "tok-abc"},
                            {"money_nonce", nonce},
                            {"changes", {{"money.node_owner_fee_pct", "0.7"}}}};
    body = do_request(ws->bound_port(), http::verb::post, "/api/config/apply",
                      status, wrong.dump());
    EXPECT_EQ(status, 409) << body;
    j = nlohmann::json::parse(body);
    EXPECT_EQ(j.value("status", std::string()), "money_gate");
    EXPECT_GE(ce::tripwire_state().count, 1u)
        << "a diff-mismatched nonce must trip the money wire";

    // Phase 2b: present the nonce against the ORIGINAL diff (fee=0.5) -> applied.
    nlohmann::json confirm = {{"control_token", "tok-abc"},
                              {"money_nonce", nonce},
                              {"changes", {{"money.node_owner_fee_pct", "0.5"}}}};
    body = do_request(ws->bound_port(), http::verb::post, "/api/config/apply",
                      status, confirm.dump());
    EXPECT_EQ(status, 200) << body;
    j = nlohmann::json::parse(body);
    EXPECT_TRUE(j.value("applied", false)) << body;

    auto cfg = nlohmann::json::parse(
        do_request(ws->bound_port(), http::verb::get, "/api/config", status));
    EXPECT_EQ(cfg["keys"]["money.node_owner_fee_pct"].value("value", std::string()), "0.5");
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
