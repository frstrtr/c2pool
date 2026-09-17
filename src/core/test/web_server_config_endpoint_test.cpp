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

#include <algorithm>
#include <cctype>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <string>
#include <thread>

#include <boost/asio/connect.hpp>
#include <boost/asio/executor_work_guard.hpp>
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

// Slice B (#157): stand up a server whose POST /api/tx-inject/submit is WIRED to
// a caller-supplied submit fn (the same seam main_dash uses via
// set_tx_inject_submit_fn). An UNWIRED server (make_wired_server) stays 503
// {"armed":false} on this route — the fail-closed dormant posture.
std::unique_ptr<core::WebServer> make_submit_server(
        net::io_context& ioc,
        std::function<nlohmann::json(const std::string&)> submit_fn) {
    auto ws = std::make_unique<core::WebServer>(ioc, "127.0.0.1", 0, false);
    ws->set_stratum_port(0);
    auto* mi = ws->get_mining_interface();
    mi->set_config_fns(
        []() { return ce::resolved_config_json(); },
        []() { return ce::catalog_schema_json(); });
    mi->set_tx_inject_submit_fn(std::move(submit_fn));
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
    // web.external_ip is a LIVE (non-money) key. After the runtime-setter
    // precondition (money-mirror-lie guard), a key applies at runtime ONLY when
    // a registered ParamApplier setter can actually enact it -- a mirror swap
    // with no setter is refused. Register a live setter so this exercises a
    // genuine non-money live apply (a main that wants runtime web.external_ip
    // would register the analogous real setter). (web.port is RESTART-class and
    // is refused by the design-F1 restart guard -- see PostApplyRefusesRestartClassKey.)
    ce::applier().register_setter("web.external_ip",
                                  [](const std::string&) { return true; });
    net::io_context ioc;
    auto ws = make_apply_server(ioc);

    int status = 0;
    nlohmann::json req = {{"control_token", "tok-abc"},
                          {"changes", {{"web.external_ip", "1.2.3.4"}}}};
    auto body = do_request(ws->bound_port(), http::verb::post, "/api/config/apply",
                           status, req.dump());
    EXPECT_EQ(status, 200) << body;
    auto j = nlohmann::json::parse(body);
    EXPECT_TRUE(j.value("applied", false)) << body;

    // The mirror behind GET /api/config now reports the applied value.
    auto cfg = nlohmann::json::parse(
        do_request(ws->bound_port(), http::verb::get, "/api/config", status));
    EXPECT_EQ(cfg["keys"]["web.external_ip"].value("value", std::string()), "1.2.3.4");
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
    // Drive a money key that IS runtime-appliable (embedded.tx_inject has a
    // registered setter). A money key with NO setter (e.g. money.node_owner_fee_pct)
    // is now refused by the runtime-setter precondition BEFORE a confirm nonce
    // could ever be issued -- see PostApplyRefusesKeyWithNoRuntimeSetter -- so it
    // can no longer stand in for "money write issues a confirm".
    ce::applier().register_setter("embedded.tx_inject",
                                  [](const std::string&) { return true; });
    net::io_context ioc;
    auto ws = make_apply_server(ioc);

    int status = 0;
    nlohmann::json req = {{"control_token", "tok-abc"},
                          {"changes", {{"embedded.tx_inject", "true"}}}};
    auto body = do_request(ws->bound_port(), http::verb::post, "/api/config/apply",
                           status, req.dump());
    EXPECT_EQ(status, 200) << body;
    auto j = nlohmann::json::parse(body);
    EXPECT_TRUE(j.value("need_confirm", false)) << body;
    EXPECT_FALSE(j.value("applied", true));
    EXPECT_FALSE(j.value("money_nonce", std::string()).empty());
    EXPECT_EQ(ce::tripwire_state().count, 0u)
        << "a phase-1 confirmation request must not trip the money wire";

    // The mirror is unchanged (the arm was never applied: a seeded-but-unset
    // compiled default reports an empty value, exactly like any other unset key).
    auto cfg = nlohmann::json::parse(
        do_request(ws->bound_port(), http::verb::get, "/api/config", status));
    EXPECT_EQ(cfg["keys"]["embedded.tx_inject"].value("value", std::string()), "");
}

// The two-phase nonce is BOUND TO THE EXACT diff: a nonce issued for one diff
// must not confirm a different diff (that trips the wire + refuses), and it
// applies only when the confirmed diff matches.
TEST(ConfigEndpointHttp, PostApplyMoneyTwoPhaseNonceMustMatchDiff) {
    reset_apply_state();
    ce::publish_resolved(dash_snapshot(), c2pool::catalog::C_DASH, "/tmp/x.toml");
    ce::set_control_token("tok-abc");
    // Diff-binding on a runtime-appliable money key (embedded.tx_inject has a
    // setter). The two distinct diffs are the arm ON ("true") vs OFF ("false").
    ce::applier().register_setter("embedded.tx_inject",
                                  [](const std::string&) { return true; });
    net::io_context ioc;
    auto ws = make_apply_server(ioc);

    // Phase 1: issue a nonce bound to arm=true.
    int status = 0;
    nlohmann::json issue = {{"control_token", "tok-abc"},
                            {"changes", {{"embedded.tx_inject", "true"}}}};
    auto body = do_request(ws->bound_port(), http::verb::post, "/api/config/apply",
                           status, issue.dump());
    auto j = nlohmann::json::parse(body);
    const std::string nonce = j.value("money_nonce", std::string());
    ASSERT_FALSE(nonce.empty());

    // Phase 2a: present the nonce against a DIFFERENT diff (arm=false) -> refuse
    // + tripwire fires. No apply.
    nlohmann::json wrong = {{"control_token", "tok-abc"},
                            {"money_nonce", nonce},
                            {"changes", {{"embedded.tx_inject", "false"}}}};
    body = do_request(ws->bound_port(), http::verb::post, "/api/config/apply",
                      status, wrong.dump());
    EXPECT_EQ(status, 409) << body;
    j = nlohmann::json::parse(body);
    EXPECT_EQ(j.value("status", std::string()), "money_gate");
    EXPECT_GE(ce::tripwire_state().count, 1u)
        << "a diff-mismatched nonce must trip the money wire";

    // Phase 2b: present the nonce against the ORIGINAL diff (arm=true) -> applied.
    nlohmann::json confirm = {{"control_token", "tok-abc"},
                              {"money_nonce", nonce},
                              {"changes", {{"embedded.tx_inject", "true"}}}};
    body = do_request(ws->bound_port(), http::verb::post, "/api/config/apply",
                      status, confirm.dump());
    EXPECT_EQ(status, 200) << body;
    j = nlohmann::json::parse(body);
    EXPECT_TRUE(j.value("applied", false)) << body;

    auto cfg = nlohmann::json::parse(
        do_request(ws->bound_port(), http::verb::get, "/api/config", status));
    EXPECT_EQ(cfg["keys"]["embedded.tx_inject"].value("value", std::string()), "true");
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

// ── Slice B (#157): tx-injection ARM is a MONEY-path config write ──────────
// Observed by a static so the process-global ParamApplier setter never holds a
// dangling stack reference after the test returns.
static bool s_tx_inject_setter_saw = false;

// Reclassification present-check: embedded.tx_inject must now report as a
// money-path key (Mut::MONEY_LIVE) over GET /api/config, so a qt/operator sees
// that arming it demands the full money gate — not a plain RESTART write.
TEST(ConfigEndpointHttp, SliceBTxInjectIsMoneyClassified) {
    ce::publish_resolved(dash_snapshot(), c2pool::catalog::C_DASH, "/tmp/x.toml");
    net::io_context ioc;
    auto ws = make_wired_server(ioc);

    int status = 0;
    auto body = do_request(ws->bound_port(), http::verb::get, "/api/config", status);
    EXPECT_EQ(status, 200) << body;
    auto j = nlohmann::json::parse(body);
    ASSERT_TRUE(j["keys"].contains("embedded.tx_inject")) << body;
    EXPECT_TRUE(j["keys"]["embedded.tx_inject"].value("money", false))
        << "the tx-injection arm must be money-classified (Slice B)";
    EXPECT_EQ(j["keys"]["embedded.tx_inject"].value("mutability", std::string()),
              "money_live");
}

// The arm routed THROUGH apply_config: a change to embedded.tx_inject without a
// nonce issues a confirm (money gate, nothing applied, no tripwire); presenting
// the matching nonce applies it AND invokes the registered runtime arm setter.
// This is exactly the path the QT arm/disarm uses (Slice A gate reused, no
// second write path).
TEST(ConfigEndpointHttp, SliceBTxInjectArmGoesThroughMoneyGateAndFiresSetter) {
    reset_apply_state();
    ce::publish_resolved(dash_snapshot(), c2pool::catalog::C_DASH, "/tmp/x.toml");
    ce::set_control_token("tok-arm");
    // Register the runtime arm setter (main_dash registers the real one that
    // flips node_coin_state + the p2p sink; here we prove apply invokes it).
    s_tx_inject_setter_saw = false;
    ce::applier().register_setter(
        "embedded.tx_inject",
        [](const std::string& v) {
            s_tx_inject_setter_saw = (v == "true" || v == "1" || v == "on");
            return true;
        });

    net::io_context ioc;
    auto ws = make_apply_server(ioc);

    // Phase 1: no nonce -> confirm issued, nothing applied, wire not tripped.
    int status = 0;
    nlohmann::json issue = {{"control_token", "tok-arm"},
                            {"changes", {{"embedded.tx_inject", "true"}}}};
    auto body = do_request(ws->bound_port(), http::verb::post, "/api/config/apply",
                           status, issue.dump());
    EXPECT_EQ(status, 200) << body;
    auto j = nlohmann::json::parse(body);
    EXPECT_TRUE(j.value("need_confirm", false)) << body;
    EXPECT_FALSE(j.value("applied", true));
    const std::string nonce = j.value("money_nonce", std::string());
    ASSERT_FALSE(nonce.empty());
    EXPECT_EQ(ce::tripwire_state().count, 0u);
    EXPECT_FALSE(s_tx_inject_setter_saw)
        << "a phase-1 confirmation request must not fire the arm setter";

    // Phase 2: matching nonce -> applied + setter fired.
    nlohmann::json confirm = {{"control_token", "tok-arm"},
                              {"money_nonce", nonce},
                              {"changes", {{"embedded.tx_inject", "true"}}}};
    body = do_request(ws->bound_port(), http::verb::post, "/api/config/apply",
                      status, confirm.dump());
    EXPECT_EQ(status, 200) << body;
    j = nlohmann::json::parse(body);
    EXPECT_TRUE(j.value("applied", false)) << body;
    EXPECT_TRUE(s_tx_inject_setter_saw)
        << "a confirmed money-gated apply must fire the runtime arm setter";

    // The reporting mirror now shows the arm ON.
    auto cfg = nlohmann::json::parse(
        do_request(ws->bound_port(), http::verb::get, "/api/config", status));
    EXPECT_EQ(cfg["keys"]["embedded.tx_inject"].value("value", std::string()), "true");
}

// ── Slice B (#157): POST /api/tx-inject/submit — raw-tx submit route ────────
// A main that never installs the submit fn keeps the route INERT: http_session
// answers 503 {"armed":false} (has_tx_inject_submit_fn() gate). This is the
// fail-closed dormant posture every production main starts in.
TEST(ConfigEndpointHttp, SliceBTxInjectSubmitDormantWhenUnwired) {
    ce::publish_resolved(dash_snapshot(), c2pool::catalog::C_DASH, "/tmp/x.toml");
    net::io_context ioc;
    auto ws = make_wired_server(ioc);   // config read fns only; NO submit fn

    int status = 0;
    nlohmann::json body_j = {{"raw_tx", "00"}};
    auto body = do_request(ws->bound_port(), http::verb::post, "/api/tx-inject/submit",
                           status, body_j.dump());
    EXPECT_EQ(status, 503) << "an unwired submit endpoint must be inert";
    auto j = nlohmann::json::parse(body);
    EXPECT_FALSE(j.value("armed", true)) << "the submit route must report armed:false";
    EXPECT_NE(j.value("error", std::string()).find("not wired"), std::string::npos) << body;
}

// The wired submit route, end to end through the REAL http_session dispatch.
//
// NOTE ON SCOPE: core_test does not link the dash node library, so a real
// NodeCoinState / submit_inject cannot be constructed here — the arm gate
// itself (submit_inject returns "inject-disabled" whenever embedded.tx_inject
// is OFF, which is the default) is pinned at the node layer. This test double
// mirrors main_dash's submit-fn HTTP contract so the CORE-owned pieces are
// exercised for real: the /api/tx-inject/submit route match, verbatim body
// pass-through into rest_tx_inject_submit, and http_session's http_status
// mapping (+ erase from the emitted body) for the two money-safety causes —
// a malformed/non-hex raw-tx (400, not a crash, not a silent accept) and a
// well-formed tx on a DISARMED node (409 inject-disabled, fail-closed).
TEST(ConfigEndpointHttp, SliceBTxInjectSubmitRouteMapsDisarmedAndBadHex) {
    reset_apply_state();
    ce::publish_resolved(dash_snapshot(), c2pool::catalog::C_DASH, "/tmp/x.toml");
    ce::set_control_token("tok-map");   // the submit route now gates on the token

    std::string seen_body;
    auto submit_double = [&seen_body](const std::string& body) -> nlohmann::json {
        seen_body = body;
        auto req = nlohmann::json::parse(body, nullptr, /*allow_exceptions=*/false);
        if (!req.is_object() || !req.contains("raw_tx") || !req["raw_tx"].is_string())
            return nlohmann::json{{"ok", false}, {"cause", "missing raw_tx hex"},
                                  {"http_status", 400}};
        const std::string hex = req["raw_tx"].get<std::string>();
        const bool even_hex = !hex.empty() && (hex.size() % 2 == 0) &&
            std::all_of(hex.begin(), hex.end(),
                        [](unsigned char c) { return std::isxdigit(c) != 0; });
        if (!even_hex)
            return nlohmann::json{{"ok", false}, {"cause", "raw_tx must be even-length hex"},
                                  {"http_status", 400}};
        // Well-formed hex, but the tx-inject arm is OFF by default
        // (embedded.tx_inject default false) => submit_inject refuses.
        return nlohmann::json{{"ok", false}, {"cause", "inject-disabled"},
                              {"armed", false}, {"http_status", 409}};
    };

    net::io_context ioc;
    auto ws = make_submit_server(ioc, submit_double);

    // (a) malformed / non-hex raw_tx => 400 (bad request), never a silent accept.
    int status = 0;
    nlohmann::json bad = {{"control_token", "tok-map"}, {"raw_tx", "zz"}};  // non-hex chars
    auto body = do_request(ws->bound_port(), http::verb::post, "/api/tx-inject/submit",
                           status, bad.dump());
    EXPECT_EQ(status, 400) << body;
    auto j = nlohmann::json::parse(body);
    EXPECT_FALSE(j.value("ok", true));
    EXPECT_FALSE(j.contains("http_status"))
        << "http_session must strip the transport http_status from the body";
    EXPECT_EQ(seen_body, bad.dump())
        << "the raw POST body must reach the submit fn verbatim";

    // (b) well-formed hex on a DISARMED node => 409 inject-disabled (fail-closed).
    nlohmann::json ok_hex = {{"control_token", "tok-map"}, {"raw_tx", "0100000000"}};
    body = do_request(ws->bound_port(), http::verb::post, "/api/tx-inject/submit",
                      status, ok_hex.dump());
    EXPECT_EQ(status, 409) << body;
    j = nlohmann::json::parse(body);
    EXPECT_EQ(j.value("cause", std::string()), "inject-disabled");
    EXPECT_FALSE(j.value("armed", true)) << "a disarmed submit must not report armed";
    ce::clear_control_token();
}

// Money gate, ADDRESS-key branch (config_endpoint.cpp:668-686). The existing
// money KATs only ever drive a PCT key; an ADDR_COIN money key with an INVALID
// address must, once the two-phase nonce confirms, be rejected by the
// server-side AddressValidator with RejectMoneyGate (409) and the M0 tripwire
// must fire — proving a bad payout/owner address can never be applied.
TEST(ConfigEndpointHttp, SliceBMoneyGateRejectsInvalidAddressAndTripsWire) {
    reset_apply_state();
    ce::publish_resolved(dash_snapshot(), c2pool::catalog::C_DASH, "/tmp/x.toml");
    ce::set_control_token("tok-addr");
    // Register a setter for the address key so the apply reaches the money-gate
    // ADDRESS branch (the subject of this KAT). The runtime-setter precondition
    // runs before the money gate and would otherwise refuse a no-setter key; the
    // server-side AddressValidator (step 4) still rejects the bad address before
    // the setter is ever invoked, so the branch under test is exercised for real.
    ce::applier().register_setter("money.node_owner_address",
                                  [](const std::string&) { return true; });
    net::io_context ioc;
    auto ws = make_apply_server(ioc);

    const std::string bad_addr = "not-a-valid-dash-address";

    // Phase 1: no nonce -> confirm issued, nothing applied, wire NOT tripped
    // (a bad address passes the cheap schema pass; validity is a money-gate
    // check applied only AFTER the nonce confirms).
    int status = 0;
    nlohmann::json issue = {{"control_token", "tok-addr"},
                            {"changes", {{"money.node_owner_address", bad_addr}}}};
    auto body = do_request(ws->bound_port(), http::verb::post, "/api/config/apply",
                           status, issue.dump());
    EXPECT_EQ(status, 200) << body;
    auto j = nlohmann::json::parse(body);
    EXPECT_TRUE(j.value("need_confirm", false)) << body;
    const std::string nonce = j.value("money_nonce", std::string());
    ASSERT_FALSE(nonce.empty());
    EXPECT_EQ(ce::tripwire_state().count, 0u);

    // Phase 2: matching nonce -> the AddressValidator rejects the bad address.
    nlohmann::json confirm = {{"control_token", "tok-addr"},
                              {"money_nonce", nonce},
                              {"changes", {{"money.node_owner_address", bad_addr}}}};
    body = do_request(ws->bound_port(), http::verb::post, "/api/config/apply",
                      status, confirm.dump());
    EXPECT_EQ(status, 409) << body;
    j = nlohmann::json::parse(body);
    EXPECT_EQ(j.value("status", std::string()), "money_gate");
    EXPECT_EQ(j.value("offending_key", std::string()), "money.node_owner_address");
    EXPECT_GE(ce::tripwire_state().count, 1u)
        << "an invalid money-path address must trip the M0 wire";
    EXPECT_EQ(ce::tripwire_state().last_key, "money.node_owner_address");

    // Nothing applied: the address key stays empty in the reporting mirror.
    auto cfg = nlohmann::json::parse(
        do_request(ws->bound_port(), http::verb::get, "/api/config", status));
    EXPECT_EQ(cfg["keys"]["money.node_owner_address"].value("value", std::string()), "");
}

// Nonce single-use / replay: a confirmed money nonce is CONSUMED on a
// successful apply. Re-presenting the SAME nonce for the SAME diff a second
// time must be REFUSED (the pending nonce is gone) with money_gate (409) + a
// tripwire fire — proving the two-phase nonce cannot be replayed.
TEST(ConfigEndpointHttp, SliceBMoneyNonceIsSingleUseReplayRefused) {
    reset_apply_state();
    ce::publish_resolved(dash_snapshot(), c2pool::catalog::C_DASH, "/tmp/x.toml");
    ce::set_control_token("tok-replay");
    // Single-use / replay proven on a runtime-appliable money key (the arm has
    // a setter; a no-setter money key is refused before a nonce can issue).
    ce::applier().register_setter("embedded.tx_inject",
                                  [](const std::string&) { return true; });
    net::io_context ioc;
    auto ws = make_apply_server(ioc);

    // Phase 1: issue a nonce bound to arm=true.
    int status = 0;
    nlohmann::json issue = {{"control_token", "tok-replay"},
                            {"changes", {{"embedded.tx_inject", "true"}}}};
    auto body = do_request(ws->bound_port(), http::verb::post, "/api/config/apply",
                           status, issue.dump());
    auto j = nlohmann::json::parse(body);
    const std::string nonce = j.value("money_nonce", std::string());
    ASSERT_FALSE(nonce.empty());

    // Phase 2: confirm -> applied. This CONSUMES the nonce (single-use).
    nlohmann::json confirm = {{"control_token", "tok-replay"},
                              {"money_nonce", nonce},
                              {"changes", {{"embedded.tx_inject", "true"}}}};
    body = do_request(ws->bound_port(), http::verb::post, "/api/config/apply",
                      status, confirm.dump());
    EXPECT_EQ(status, 200) << body;
    j = nlohmann::json::parse(body);
    EXPECT_TRUE(j.value("applied", false)) << body;
    const uint64_t trip_after_apply = ce::tripwire_state().count;
    EXPECT_EQ(trip_after_apply, 0u) << "a sanctioned confirm must not trip the wire";

    // Phase 3 (REPLAY): re-present the SAME now-consumed nonce for the SAME
    // diff -> refused, since the pending nonce was erased on first use.
    body = do_request(ws->bound_port(), http::verb::post, "/api/config/apply",
                      status, confirm.dump());
    EXPECT_EQ(status, 409) << body;
    j = nlohmann::json::parse(body);
    EXPECT_EQ(j.value("status", std::string()), "money_gate");
    EXPECT_GT(ce::tripwire_state().count, trip_after_apply)
        << "a consumed nonce must not confirm a second time (single-use)";
}


// ── Slice B (#157): POST /api/tx-inject/submit control-token gate ───────────
// Once the lane is armed, the submit route must NOT let just any local process
// spend the operator's reserved inject rate-budget: the request body carries
// the SAME loopback control token that arms the money gate. Fail-closed — 403
// while no token is registered (default) and 403 on any mismatch; only the
// exact token reaches the (wired) submit fn.
TEST(ConfigEndpointHttp, SliceBSubmitRequiresControlToken) {
    reset_apply_state();
    ce::publish_resolved(dash_snapshot(), c2pool::catalog::C_DASH, "/tmp/x.toml");

    int calls = 0;
    auto submit_double = [&calls](const std::string&) -> nlohmann::json {
        ++calls;
        return nlohmann::json{{"ok", true}, {"cause", "ok"}, {"http_status", 200}};
    };
    net::io_context ioc;
    auto ws = make_submit_server(ioc, submit_double);

    // (a) NO token registered at all => any submit is refused 403, fn untouched.
    int status = 0;
    nlohmann::json b = {{"raw_tx", "0100000000"}};
    auto body = do_request(ws->bound_port(), http::verb::post, "/api/tx-inject/submit",
                           status, b.dump());
    EXPECT_EQ(status, 403) << body;
    EXPECT_EQ(calls, 0) << "a token-less submit must never reach the submit fn";

    // Arm a token; a WRONG token is still 403 and still never reaches the fn.
    ce::set_control_token("tok-submit");
    nlohmann::json wrong = {{"control_token", "nope"}, {"raw_tx", "0100000000"}};
    body = do_request(ws->bound_port(), http::verb::post, "/api/tx-inject/submit",
                      status, wrong.dump());
    EXPECT_EQ(status, 403) << body;
    EXPECT_EQ(calls, 0) << "a wrong-token submit must never reach the submit fn";

    // The EXACT token reaches the fn.
    nlohmann::json good = {{"control_token", "tok-submit"}, {"raw_tx", "0100000000"}};
    body = do_request(ws->bound_port(), http::verb::post, "/api/tx-inject/submit",
                      status, good.dump());
    EXPECT_EQ(status, 200) << body;
    EXPECT_EQ(calls, 1) << "the correct token must reach the wired submit fn exactly once";
    ce::clear_control_token();
}

// The submit fn is installed through thread_safe_wrap, so it must execute on the
// node producer io_context thread (submit_inject / m_inject_pool are IO-thread-
// confined and lock-free), NEVER on the web thread. Drive a real HTTP request
// and assert the thread id the fn records equals the producer io_context thread.
TEST(ConfigEndpointHttp, SliceBSubmitRunsOnProducerThread) {
    reset_apply_state();
    ce::publish_resolved(dash_snapshot(), c2pool::catalog::C_DASH, "/tmp/x.toml");
    ce::set_control_token("tok-thr");

    net::io_context ioc;
    net::io_context producer;
    auto guard = net::make_work_guard(producer);

    auto ws = std::make_unique<core::WebServer>(ioc, "127.0.0.1", 0, false);
    ws->set_stratum_port(0);
    auto* mi = ws->get_mining_interface();
    mi->set_config_fns([]() { return ce::resolved_config_json(); },
                       []() { return ce::catalog_schema_json(); });

    std::promise<std::thread::id> ready;
    std::thread producer_thread([&]() {
        // set_io_context stamps m_main_thread_id = THIS (producer) thread, so a
        // call arriving on the web thread is dispatched here. Called before
        // ws->start() (main waits on `ready`), honoring the wiring order.
        mi->set_io_context(&producer);
        ready.set_value(std::this_thread::get_id());
        producer.run();
    });
    const std::thread::id producer_tid = ready.get_future().get();

    std::atomic<bool> saw{false};
    std::thread::id fn_tid{};
    mi->set_tx_inject_submit_fn([&](const std::string&) -> nlohmann::json {
        fn_tid = std::this_thread::get_id();
        saw.store(true);
        return nlohmann::json{{"ok", true}, {"cause", "ok"}, {"http_status", 200}};
    });
    ASSERT_TRUE(mi->has_io_context());
    ws->start();

    int status = 0;
    nlohmann::json b = {{"control_token", "tok-thr"}, {"raw_tx", "0100000000"}};
    auto body = do_request(ws->bound_port(), http::verb::post, "/api/tx-inject/submit",
                           status, b.dump());
    EXPECT_EQ(status, 200) << body;
    ASSERT_TRUE(saw.load()) << "the submit fn must have run";
    EXPECT_EQ(fn_tid, producer_tid)
        << "the submit fn must run on the node producer io_context thread, not the web thread";

    guard.reset();
    producer.stop();
    if (producer_thread.joinable()) producer_thread.join();
    ce::clear_control_token();
}

// A wedged producer io_context (nobody servicing it) must degrade the submit to
// a 5xx within the thread_safe_wrap dispatch timeout (~10s), NEVER hang the web
// thread past the liveness watchdog. We point set_io_context at an io_context we
// deliberately never run, then time the request.
TEST(ConfigEndpointHttp, SliceBSubmitTimeoutIs5xxNotHang) {
    reset_apply_state();
    ce::publish_resolved(dash_snapshot(), c2pool::catalog::C_DASH, "/tmp/x.toml");
    ce::set_control_token("tok-to");

    net::io_context ioc;
    net::io_context producer;   // NEVER run: the posted submit task is never serviced

    auto ws = std::make_unique<core::WebServer>(ioc, "127.0.0.1", 0, false);
    ws->set_stratum_port(0);
    auto* mi = ws->get_mining_interface();
    mi->set_config_fns([]() { return ce::resolved_config_json(); },
                       []() { return ce::catalog_schema_json(); });
    // set_io_context on THIS (test) thread => m_main_thread_id = test thread, so
    // the web-thread call is dispatched to `producer` (which never runs).
    mi->set_io_context(&producer);
    mi->set_tx_inject_submit_fn([](const std::string&) -> nlohmann::json {
        return nlohmann::json{{"ok", true}, {"http_status", 200}};   // never reached
    });
    ws->start();

    int status = 0;
    nlohmann::json b = {{"control_token", "tok-to"}, {"raw_tx", "0100000000"}};
    const auto t0 = std::chrono::steady_clock::now();
    auto body = do_request(ws->bound_port(), http::verb::post, "/api/tx-inject/submit",
                           status, b.dump());
    const auto elapsed = std::chrono::steady_clock::now() - t0;

    EXPECT_GE(status, 500) << body;
    EXPECT_LT(status, 600) << body;
    EXPECT_LT(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(), 12)
        << "a wedged producer must degrade to 5xx within the dispatch timeout, not hang";
    ce::clear_control_token();
}

// Design F1: a RESTART-class key is partitioned but has no runtime applier, so
// applying it like a LIVE key would swap the reporting mirror while the running
// process keeps the OLD value (a mirror-vs-runtime lie). The apply path must
// REFUSE a RESTART-class key by a named cause. (embedded.tx_inject is now
// MONEY_LIVE and takes the money-nonce path instead; embedded.fold_checkscripts
// is a plain RESTART key that exercises this refusal.)
TEST(ConfigEndpointHttp, PostApplyRefusesRestartClassKey) {
    reset_apply_state();
    ce::publish_resolved(dash_snapshot(), c2pool::catalog::C_DASH, "/tmp/x.toml");
    ce::set_control_token("tok-restart");
    net::io_context ioc;
    auto ws = make_apply_server(ioc);

    int status = 0;
    nlohmann::json apply = {{"control_token", "tok-restart"},
                            {"changes", {{"embedded.fold_checkscripts", "true"}}}};
    auto body = do_request(ws->bound_port(), http::verb::post, "/api/config/apply",
                           status, apply.dump());
    EXPECT_EQ(status, 400) << body;
    auto j = nlohmann::json::parse(body);
    EXPECT_EQ(j.value("status", std::string()), "validation");
    EXPECT_EQ(j.value("offending_key", std::string()), "embedded.fold_checkscripts");
    EXPECT_NE(j.value("error", std::string()).find("restart-class"), std::string::npos) << body;

    // Nothing applied: no money nonce was ever issued, wire not tripped.
    EXPECT_EQ(ce::tripwire_state().count, 0u);
    ce::clear_control_token();
}

// Money-mirror-lie guard: a MONEY-class key with NO registered runtime setter
// (money.node_owner_fee_pct is MONEY_RESTART and no main wires a setter for it)
// must be REFUSED by the runtime-setter precondition -- BEFORE a confirm nonce
// is issued -- so the reporting mirror can never advertise a fee the coinbase
// never adopts. The money key partitions past the plain RESTART refusal, so this
// precondition (not that partition) is what closes the hole for it.
TEST(ConfigEndpointHttp, PostApplyRefusesKeyWithNoRuntimeSetter) {
    reset_apply_state();
    ce::publish_resolved(dash_snapshot(), c2pool::catalog::C_DASH, "/tmp/x.toml");
    ce::set_control_token("tok-nosetter");
    // Deliberately register NO setter for money.node_owner_fee_pct.
    net::io_context ioc;
    auto ws = make_apply_server(ioc);

    // Even presenting a (bogus) nonce cannot get past the precondition: the key
    // is refused before the money gate, and no nonce was ever issued for it.
    int status = 0;
    nlohmann::json apply = {{"control_token", "tok-nosetter"},
                            {"money_nonce", "deadbeef"},
                            {"changes", {{"money.node_owner_fee_pct", "0.5"}}}};
    auto body = do_request(ws->bound_port(), http::verb::post, "/api/config/apply",
                           status, apply.dump());
    EXPECT_EQ(status, 400) << body;
    auto j = nlohmann::json::parse(body);
    EXPECT_EQ(j.value("status", std::string()), "no_runtime_setter");
    EXPECT_EQ(j.value("offending_key", std::string()), "money.node_owner_fee_pct");
    EXPECT_FALSE(j.value("applied", true));
    EXPECT_FALSE(j.value("need_confirm", false))
        << "a no-setter key must never even issue a confirm nonce";

    // The mirror was NOT swapped: the fee key stays at its empty compiled default.
    auto cfg = nlohmann::json::parse(
        do_request(ws->bound_port(), http::verb::get, "/api/config", status));
    EXPECT_EQ(cfg["keys"]["money.node_owner_fee_pct"].value("value", std::string()), "");
    // And the money wire never fired (this is a precondition refusal, not a
    // money-path write attempt without a nonce).
    EXPECT_EQ(ce::tripwire_state().count, 0u);
    ce::clear_control_token();
}
