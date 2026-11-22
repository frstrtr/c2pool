// SPDX-License-Identifier: AGPL-3.0-or-later
//
// HTTP on the stratum port: the switch and the stratum side
// (core/stratum_http.hpp). The wire behaviour (same answers as the web port,
// read-only, local-only routes, the handshake deadline) is in
// stratum_port_http_wire_test.cpp; this file covers:
//
//   * --stratum-http: the flag, and how auto follows the web server's bind
//     address and the stratum listener's (127.0.0.1 / ::1 / localhost: off;
//     ::: on; 0.0.0.0: on for an IPv4 stratum bind; a LAN or public address:
//     on for the same stratum bind; no web server: off), and the startup line
//     it logs;
//   * the request-line sniff;
//   * off (=false, or auto behind a loopback-only web server) keeps the old
//     behaviour: an HTTP request is an invalid stratum line;
//   * an HTTP connection is never a stratum session: the session count, the
//     notify fan-out and the miner registry do not see it, before, during or
//     after its request, and its slot is gone once it is answered;
//   * the connection caps (node cap and per-IP cap) count a live HTTP
//     connection;
//   * with no web server to answer (none configured, or stopped), a 503;
//   * the per-request log line is rate-limited;
//   * the handshake deadline and the response write deadline: a stratum-port
//     session closes at min(hand-off bound, write start + write_timeout), no
//     re-arm is later than the hand-off bound, and the slot it holds is
//     released when it closes;
//   * the event stream is refused on the stratum port.

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

#include <boost/log/core.hpp>
#include <boost/log/sinks/basic_sink_backend.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks/sync_frontend.hpp>
#include <boost/log/sinks/text_ostream_backend.hpp>
#include <boost/make_shared.hpp>
#include <boost/shared_ptr.hpp>

#include <core/param_catalog.hpp>
#include <core/settings_file.hpp>
#include <core/stratum_http.hpp>
#include <core/stratum_server.hpp>
#include <core/web_server.hpp>

#include "stratum_port_http_test_util.hpp"

#ifdef __linux__
#include <netinet/in.h>
#include <sys/socket.h>
#endif

using namespace stratum_http_test;
using json = nlohmann::json;
using core::StratumHttpMode;

// A timing precondition of a test (an event that must happen before a bound
// for the assertions to mean anything): in a ThreadSanitizer or
// AddressSanitizer build, not met skips the test with the reason; elsewhere it
// fails it.
#if defined(__SANITIZE_THREAD__) || defined(__SANITIZE_ADDRESS__)
constexpr bool kSanitizerBuild = true;
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer) || __has_feature(address_sanitizer)
constexpr bool kSanitizerBuild = true;
#else
constexpr bool kSanitizerBuild = false;
#endif
#else
constexpr bool kSanitizerBuild = false;
#endif
#define TIMING_PRECONDITION(cond, why)                                                  \
    do {                                                                                \
        if (!(cond)) {                                                                  \
            if (kSanitizerBuild)                                                        \
                GTEST_SKIP() << "timing precondition not met in a sanitizer build: " << why; \
            FAIL() << "timing precondition not met: " << why;                           \
        }                                                                               \
    } while (0)

namespace {

const char* kSubscribe = R"({"id":1,"method":"mining.subscribe","params":[]})";

bool wait_until(const std::function<bool()>& done, std::chrono::milliseconds timeout = 5000ms)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (done()) return true;
        std::this_thread::sleep_for(10ms);
    }
    return done();
}

// An HTTP request line was taken for a stratum line ("Invalid JSON").
bool answered_as_stratum(const std::string& addr, uint16_t port)
{
    RawClient c;
    if (!c.connect(addr, port)) return false;
    c.send(request("GET", "/global_stats"));
    auto line = c.read_line();
    if (!line) return false;
    auto j = json::parse(*line, nullptr, false);
    return j.is_object() && j["error"].is_array() && j["error"][1] == "Invalid JSON";
}

bool subscribed(RawClient& c)
{
    for (int i = 0; i < 10; ++i) {
        auto line = c.read_line();
        if (!line) return false;
        auto j = json::parse(*line, nullptr, false);
        if (j.is_object() && j.value("id", json()) == 1)
            return j["error"].is_null() && j["result"].is_array();
    }
    return false;
}

// A StratumServer with its own work source and, optionally, a separate
// WebServer: the shape of the DASH / BTC / DGB / BCH / BIP110 lanes.
class SplitNode {
public:
    net::io_context ioc;
    std::shared_ptr<core::MiningInterface> work = std::make_shared<core::MiningInterface>(false);
    std::unique_ptr<core::WebServer> web;
    std::unique_ptr<core::StratumServer> stratum;
    core::StratumHttpDecision decision;
    core::StratumHttpLimits limits;   // --stratum-http-budget / --stratum-http-per-ip
    uint16_t port = 0;

    bool start(bool with_web, StratumHttpMode mode, const core::stratum::StratumConfig& cfg = {},
               const std::string& web_bind = "127.0.0.1", const std::string& stratum_bind = "127.0.0.1",
               const std::function<void(core::WebServer&)>& before_web_start = {})
    {
        work->set_stratum_config(cfg);
        if (with_web) {
            web = std::make_unique<core::WebServer>(ioc, web_bind, 0, false);
            web->set_stratum_port(0);
            if (before_web_start) before_web_start(*web);
            if (!web->start()) return false;
        }
        for (int attempt = 0; attempt < 20 && !stratum; ++attempt) {
            auto s = std::make_unique<core::StratumServer>(ioc, stratum_bind, free_port(stratum_bind), work);
            if (s->start()) stratum = std::move(s);
        }
        if (!stratum) return false;
        port = stratum->get_port();
        decision = core::configure_stratum_http(*stratum, web.get(), mode, limits);
        guard_.emplace(net::make_work_guard(ioc));
        th_ = std::thread([this] { ioc.run(); });
        return true;
    }

    template <typename F>
    auto on_io(F&& fn) -> decltype(fn())
    {
        std::promise<decltype(fn())> prom;
        auto fut = prom.get_future();
        net::post(ioc, [&] { prom.set_value(fn()); });
        return fut.get();
    }

    // Stop and destroy the stratum server on its io thread (destroyed in a
    // later handler: the accept stop() cancelled completes first).
    void stop_and_destroy_stratum()
    {
        std::promise<void> done;
        net::post(ioc, [&] {
            stratum->stop();
            net::post(ioc, [&] { stratum.reset(); done.set_value(); });
        });
        done.get_future().wait();
    }

    ~SplitNode()
    {
        if (stratum && th_.joinable()) {
            std::promise<void> done;
            net::post(ioc, [&] { stratum->stop(); done.set_value(); });
            done.get_future().wait();
        }
        guard_.reset();
        ioc.stop();
        if (th_.joinable()) th_.join();
        web.reset();
        stratum.reset();
    }

private:
    std::optional<net::executor_work_guard<net::io_context::executor_type>> guard_;
    std::thread th_;
};

}  // namespace

// ── The switch ──────────────────────────────────────────────────────────────

TEST(StratumHttpMode, AutoIsOffBehindALoopbackWebBind)
{
    using core::resolve_stratum_http;
    for (const char* host : {"127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1", "localhost"}) {
        // Whatever the stratum listener's address.
        for (const char* stratum : {"0.0.0.0", "127.0.0.1", host}) {
            const auto d = resolve_stratum_http(StratumHttpMode::Auto, true, host, stratum);
            EXPECT_FALSE(d.on) << host << " / " << stratum;
            EXPECT_EQ(d.summary, std::string("OFF (web bound to ") + host + " \xE2\x80\x94 proxy-only)");
        }
    }
    const auto name = resolve_stratum_http(StratumHttpMode::Auto, true, "pool.example", "0.0.0.0");
    EXPECT_FALSE(name.on);
    EXPECT_EQ(name.summary, "OFF (web bind address 'pool.example' is not an IP address)");
    // No web server: auto is off whatever the addresses.
    for (const char* host : {"0.0.0.0", "127.0.0.1", ""}) {
        const auto d = resolve_stratum_http(StratumHttpMode::Auto, false, host, "0.0.0.0");
        EXPECT_FALSE(d.on) << host;
        EXPECT_EQ(d.summary, "OFF (web server disabled)");
    }
}

TEST(StratumHttpMode, AutoFollowsTheStratumBindToo)
{
    using core::resolve_stratum_http;
    struct Case { const char* web; const char* stratum; bool on; const char* summary; };
    for (const Case& c : {
             // 0.0.0.0 answers on every IPv4 interface: an IPv4 stratum bind.
             Case{"0.0.0.0", "0.0.0.0", true, "ON (web bound to 0.0.0.0)"},
             Case{"0.0.0.0", "127.0.0.1", true, "ON (web bound to 0.0.0.0, stratum to 127.0.0.1)"},
             Case{"0.0.0.0", "192.168.86.50", true, "ON (web bound to 0.0.0.0, stratum to 192.168.86.50)"},
             Case{"0.0.0.0", "::ffff:192.168.86.50", true,
                  "ON (web bound to 0.0.0.0, stratum to ::ffff:192.168.86.50)"},
             // 0.0.0.0 and an IPv6 (or dual-stack ::) stratum bind: off.
             Case{"0.0.0.0", "::", false, "OFF (web bound to 0.0.0.0, stratum to ::)"},
             Case{"0.0.0.0", "2001:db8::7", false, "OFF (web bound to 0.0.0.0, stratum to 2001:db8::7)"},
             Case{"0.0.0.0", "", false, "OFF (web bound to 0.0.0.0, stratum to )"},
             // :: answers on every interface, IPv4 and IPv6.
             Case{"::", "::", true, "ON (web bound to ::)"},
             Case{"::", "0.0.0.0", true, "ON (web bound to ::, stratum to 0.0.0.0)"},
             Case{"::", "2001:db8::7", true, "ON (web bound to ::, stratum to 2001:db8::7)"},
             // The same single address for both (the LTC lane binds them together).
             Case{"192.168.86.50", "192.168.86.50", true, "ON (web bound to 192.168.86.50)"},
             Case{"203.0.113.7", "203.0.113.7", true, "ON (web bound to 203.0.113.7)"},
             // A web server kept on one LAN / VPN address, stratum wider or elsewhere.
             Case{"10.8.0.1", "0.0.0.0", false, "OFF (web bound to 10.8.0.1, stratum to 0.0.0.0)"},
             Case{"10.8.0.1", "::", false, "OFF (web bound to 10.8.0.1, stratum to ::)"},
             Case{"192.168.86.50", "203.0.113.7", false, "OFF (web bound to 192.168.86.50, stratum to 203.0.113.7)"},
             Case{"192.168.86.50", "", false, "OFF (web bound to 192.168.86.50, stratum to )"}}) {
        const auto d = resolve_stratum_http(StratumHttpMode::Auto, true, c.web, c.stratum);
        EXPECT_EQ(d.on, c.on) << c.web << " / " << c.stratum;
        EXPECT_EQ(d.web, c.on) << c.web << " / " << c.stratum;
        EXPECT_EQ(d.summary, c.summary) << c.web << " / " << c.stratum;
    }
}

TEST(StratumHttpMode, AutoIsOffForAnIpv4WildcardWebServerAndAnIpv6WildcardStratum)
{
    // Web on 0.0.0.0 (IPv4 only), stratum on :: (IPv4 and IPv6).
    const auto d = core::resolve_stratum_http(StratumHttpMode::Auto, true, "0.0.0.0", "::");
    EXPECT_FALSE(d.on) << d.summary;
    EXPECT_FALSE(d.web) << d.summary;
    EXPECT_EQ(d.summary, "OFF (web bound to 0.0.0.0, stratum to ::)");
}

TEST(StratumHttpMode, TrueAndFalseOverrideAuto)
{
    using core::resolve_stratum_http;
    for (const char* host : {"127.0.0.1", "::1", "0.0.0.0", "192.168.1.10"}) {
        const auto on = resolve_stratum_http(StratumHttpMode::On, true, host, "0.0.0.0");
        EXPECT_TRUE(on.on) << host;
        EXPECT_TRUE(on.web) << host;
        EXPECT_EQ(on.summary, std::string("ON (--stratum-http=true; web bound to ") + host + ")");
        const auto off = resolve_stratum_http(StratumHttpMode::Off, true, host, host);
        EXPECT_FALSE(off.on) << host;
        EXPECT_EQ(off.summary, "OFF (--stratum-http=false)");
    }
    // Forced on with no web server: on, answered 503 by the stratum port.
    const auto bare = resolve_stratum_http(StratumHttpMode::On, false, "", "0.0.0.0");
    EXPECT_TRUE(bare.on);
    EXPECT_FALSE(bare.web);
    EXPECT_NE(bare.summary.find("503"), std::string::npos);
}

TEST(StratumHttpMode, FlagSpellings)
{
    auto parse = [](const char* arg, StratumHttpMode start = StratumHttpMode::Auto) {
        StratumHttpMode m = start;
        const bool ok = core::parse_stratum_http_flag(arg, m);
        return std::make_pair(ok, m);
    };
    EXPECT_EQ(parse("--stratum-http"), std::make_pair(true, StratumHttpMode::On));
    for (const char* v : {"true", "on", "yes", "1"})
        EXPECT_EQ(parse((std::string("--stratum-http=") + v).c_str()), std::make_pair(true, StratumHttpMode::On)) << v;
    for (const char* v : {"false", "off", "no", "0"})
        EXPECT_EQ(parse((std::string("--stratum-http=") + v).c_str()), std::make_pair(true, StratumHttpMode::Off)) << v;
    EXPECT_EQ(parse("--stratum-http=auto", StratumHttpMode::Off), std::make_pair(true, StratumHttpMode::Auto));
    // Not this flag, or a bad value: refused, the mode untouched.
    for (const char* a : {"--stratum-http=maybe", "--stratum-http=", "--stratum-httpx",
                          "--stratum-http-port=1", "--stratum", "stratum-http"})
        EXPECT_EQ(parse(a, StratumHttpMode::Off), std::make_pair(false, StratumHttpMode::Off)) << a;
    EXPECT_STREQ(core::stratum_http_mode_name(StratumHttpMode::Auto), "auto");
    EXPECT_STREQ(core::stratum_http_mode_name(StratumHttpMode::On), "true");
    EXPECT_STREQ(core::stratum_http_mode_name(StratumHttpMode::Off), "false");
}

TEST(StratumHttpMode, RequestLineSniff)
{
    using core::looks_like_http_request_line;
    for (const char* l : {"GET /global_stats HTTP/1.1", "GET / HTTP/1.0\r", "HEAD /fee HTTP/1.1\r",
                          "POST / HTTP/1.1", "OPTIONS * HTTP/1.1", "PUT /x HTTP/1.1",
                          "DELETE /x HTTP/1.1", "PATCH /x HTTP/1.1", "TRACE / HTTP/1.1",
                          "CONNECT host:443 HTTP/1.1", "GET /a?b=c%20d HTTP/1.1"})
        EXPECT_TRUE(looks_like_http_request_line(l)) << l;
    for (const char* l : {R"({"id":1,"method":"mining.subscribe","params":[]})", "{", "",
                          "GET /", "GET / HTTP/2.0", "GET / HTTP/1.", "GET  HTTP/1.1", "get / HTTP/1.1",
                          "GETX / HTTP/1.1", "BREW /pot HTTP/1.1", "GET / HTTP/1.1 extra",
                          "GET / HTTPS/1.1", "hello there"})
        EXPECT_FALSE(looks_like_http_request_line(l)) << l;
}

// ── Off keeps the old behaviour ─────────────────────────────────────────────

TEST(StratumHttpSwitch, FalseKeepsTheOldBehaviour)
{
    StratumHttpMode mode = StratumHttpMode::Auto;
    ASSERT_TRUE(core::parse_stratum_http_flag("--stratum-http=false", mode));
    WebNode node;
    ASSERT_TRUE(node.start("0.0.0.0", [&](core::WebServer& w) { w.set_stratum_http_mode(mode); }));
    EXPECT_FALSE(node.web->get_stratum_server()->http_on());
    EXPECT_TRUE(answered_as_stratum("127.0.0.1", node.stratum_port));
    // The web port is unchanged.
    EXPECT_EQ(exchange("127.0.0.1", node.web_port, request("GET", "/fee")).status, 200u);
}

TEST(StratumHttpSwitch, AutoIsOffBehindALoopbackOnlyWebServer)
{
    {
        WebNode node;   // the LTC lane binds both ports to the web address
        ASSERT_TRUE(node.start("127.0.0.1"));
        EXPECT_FALSE(node.web->get_stratum_server()->http_on());
        EXPECT_TRUE(answered_as_stratum("127.0.0.1", node.stratum_port));
    }
    {
        WebNode node;
        ASSERT_TRUE(node.start("127.0.0.1", [](core::WebServer& w) {
            w.set_stratum_http_mode(StratumHttpMode::On);
        }));
        EXPECT_TRUE(node.web->get_stratum_server()->http_on());
        EXPECT_EQ(exchange("127.0.0.1", node.stratum_port, request("GET", "/fee")).status, 200u);
    }
    {   // A separate web server on loopback (the DASH relay shape).
        SplitNode node;
        ASSERT_TRUE(node.start(true, StratumHttpMode::Auto));
        EXPECT_FALSE(node.decision.on);
        EXPECT_EQ(node.decision.summary, "OFF (web bound to 127.0.0.1 \xE2\x80\x94 proxy-only)");
        EXPECT_TRUE(answered_as_stratum("127.0.0.1", node.port));
    }
}

// ── Not a stratum session ───────────────────────────────────────────────────

TEST(StratumHttpSessions, AnHttpRequestIsNeverAStratumSession)
{
    SplitNode node;
    ASSERT_TRUE(node.start(true, StratumHttpMode::On));
    ASSERT_TRUE(node.decision.on);
    auto& ss = *node.stratum;

    RawClient miner;
    ASSERT_TRUE(miner.connect("127.0.0.1", node.port));
    miner.send(std::string(kSubscribe) + "\n");
    ASSERT_TRUE(subscribed(miner));
    ASSERT_TRUE(wait_until([&] { return ss.get_session_count() == 1; }));

    for (int i = 0; i < 10; ++i) {
        const auto r = exchange("127.0.0.1", node.port, request(i % 2 ? "HEAD" : "GET", "/global_stats"));
        ASSERT_TRUE(r.ok) << i << ": '" << r.raw << "'";
        EXPECT_EQ(r.status, 200u);
        EXPECT_EQ(ss.get_session_count(), 1u) << i;
    }
    EXPECT_EQ(ss.get_http_requests(), 10u);
    EXPECT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 0; }));

    // While a request is open it holds an HTTP slot, never a session.
    RawClient slow;
    ASSERT_TRUE(slow.connect("127.0.0.1", node.port));
    slow.send("GET /fee HTTP/1.1\r\nHost: t\r\n");
    ASSERT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 1; }));
    EXPECT_EQ(ss.get_session_count(), 1u);
    // A notify fan-out meanwhile walks the miner's session only, and not one
    // stratum byte reaches the HTTP connection: its answer starts with the
    // status line.
    EXPECT_EQ(node.on_io([&] { ss.notify_all(); return ss.get_session_count(); }), 1u);
    slow.send("\r\n");
    const auto r = parse_response(slow.read_all());
    EXPECT_EQ(r.status, 200u);
    EXPECT_EQ(r.raw.rfind("HTTP/1.1 200 OK\r\n", 0), 0u) << r.raw.substr(0, 120);
    EXPECT_TRUE(slow.closed());
    EXPECT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 0; }));
    EXPECT_EQ(ss.get_session_count(), 1u);

    // No miner registered by any of it (the miner never authorized either).
    EXPECT_TRUE(node.work->get_stratum_workers().empty());
    // The miner's session still works.
    miner.send(R"({"id":7,"method":"mining.suggest_difficulty","params":[1]})" "\n");
    bool replied = false;
    for (int i = 0; i < 10 && !replied; ++i) {
        auto line = miner.read_line();
        if (!line) break;
        replied = json::parse(*line, nullptr, false).value("id", json()) == 7;
    }
    EXPECT_TRUE(replied);
}

TEST(StratumHttpSwitch, AnUnsetFlagIsOff)
{
    // The default of --stratum-http is false: an HTTP request line on the
    // stratum port is an invalid stratum line, as before. auto and true are
    // unchanged.
    EXPECT_EQ(core::stratum_http_mode_setting(), StratumHttpMode::Off);
    {   // The web server's own stratum acceptor (the LTC lane), mode not set.
        WebNode node;
        node.mode = std::nullopt;
        ASSERT_TRUE(node.start("0.0.0.0"));
        EXPECT_EQ(node.web->get_stratum_http_mode(), StratumHttpMode::Off);
        EXPECT_TRUE(answered_as_stratum("127.0.0.1", node.stratum_port));
    }
    {   // A separate stratum server (the other lanes), the process setting.
        SplitNode node;
        ASSERT_TRUE(node.start(true, core::stratum_http_mode_setting(), {}, "0.0.0.0", "0.0.0.0"));
        EXPECT_FALSE(node.decision.on);
        EXPECT_TRUE(answered_as_stratum("127.0.0.1", node.port));
    }
    for (const auto mode : {StratumHttpMode::Auto, StratumHttpMode::On}) {
        WebNode node;
        node.mode = mode;
        ASSERT_TRUE(node.start("0.0.0.0"));
        const auto r = exchange("127.0.0.1", node.stratum_port, request("GET", "/fee"));
        ASSERT_TRUE(r.ok) << core::stratum_http_mode_name(mode) << ": '" << r.raw.substr(0, 120) << "'";
        EXPECT_EQ(r.status, 200u) << core::stratum_http_mode_name(mode);
    }
}

// ── The caps count HTTP connections ─────────────────────────────────────────

TEST(StratumHttpCaps, NodeCapCountsAnOpenHttpRequest)
{
    core::stratum::StratumConfig cfg;
    cfg.max_stratum_connections = 2;
    SplitNode node;
    ASSERT_TRUE(node.start(true, StratumHttpMode::On, cfg));
    auto& ss = *node.stratum;

    RawClient miner;
    ASSERT_TRUE(miner.connect("127.0.0.1", node.port));
    miner.send(std::string(kSubscribe) + "\n");
    ASSERT_TRUE(subscribed(miner));

    RawClient slow;
    ASSERT_TRUE(slow.connect("127.0.0.1", node.port));
    slow.send("GET /fee HTTP/1.1\r\n");
    ASSERT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 1; }));
    EXPECT_EQ(ss.get_session_count(), 1u);

    // 1 session + 1 HTTP request = the cap: the next connection is refused.
    RawClient third;
    ASSERT_TRUE(third.connect("127.0.0.1", node.port));
    third.send(std::string(kSubscribe) + "\n");
    EXPECT_TRUE(third.read_all(3000ms).empty());
    EXPECT_TRUE(third.closed());
    EXPECT_EQ(ss.get_refused_connections(), 1u);

    // Answered and closed: its slot is free again.
    slow.send("Host: t\r\n\r\n");
    EXPECT_EQ(parse_response(slow.read_all()).status, 200u);
    ASSERT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 0; }));
    RawClient fourth;
    ASSERT_TRUE(fourth.connect("127.0.0.1", node.port));
    fourth.send(std::string(kSubscribe) + "\n");
    EXPECT_TRUE(subscribed(fourth));
    EXPECT_EQ(ss.get_refused_connections(), 1u);
}

TEST(StratumHttpCaps, PerIpCapCountsAnOpenHttpRequest)
{
    core::stratum::StratumConfig cfg;
    cfg.max_stratum_connections = 0;
    cfg.max_stratum_connections_per_ip = 1;
    SplitNode node;
    ASSERT_TRUE(node.start(true, StratumHttpMode::On, cfg));
    auto& ss = *node.stratum;

    RawClient slow;
    ASSERT_TRUE(slow.connect("127.0.0.1", node.port));
    slow.send("GET /fee HTTP/1.1\r\n");
    ASSERT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 1; }));
    EXPECT_EQ(ss.get_session_count(), 0u);

    RawClient same_ip;
    ASSERT_TRUE(same_ip.connect("127.0.0.1", node.port));
    EXPECT_TRUE(same_ip.read_all(3000ms).empty());
    EXPECT_TRUE(same_ip.closed());
    EXPECT_EQ(ss.get_refused_per_ip(), 1u);

    // Another address is not held back by it (127.0.0.2 is local on Linux).
    RawClient other;
    if (other.connect("127.0.0.1", node.port, "127.0.0.2")) {
        other.send(std::string(kSubscribe) + "\n");
        EXPECT_TRUE(subscribed(other));
        EXPECT_EQ(ss.get_refused_per_ip(), 1u);
    }

    slow.send("Host: t\r\n\r\n");
    EXPECT_EQ(parse_response(slow.read_all()).status, 200u);
    ASSERT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 0; }));
    RawClient again;
    ASSERT_TRUE(again.connect("127.0.0.1", node.port));
    again.send(std::string(kSubscribe) + "\n");
    EXPECT_TRUE(subscribed(again));
}

// ── No web server to answer ─────────────────────────────────────────────────

TEST(StratumHttpNoWeb, ForcedOnWithoutAWebServerAnswers503)
{
    SplitNode node;
    ASSERT_TRUE(node.start(false, StratumHttpMode::On));
    ASSERT_TRUE(node.decision.on);
    ASSERT_FALSE(node.decision.web);

    const auto get = exchange("127.0.0.1", node.port, request("GET", "/global_stats"));
    ASSERT_TRUE(get.ok) << "'" << get.raw << "'";
    EXPECT_EQ(get.status, 503u);
    EXPECT_EQ(get.header("connection"), "close");
    EXPECT_EQ(get.header("content-type"), "application/json");
    EXPECT_EQ(get.header("x-content-type-options"), "nosniff");
    EXPECT_EQ(get.header("x-frame-options"), "DENY");
    EXPECT_EQ(get.header("referrer-policy"), "no-referrer");
    EXPECT_TRUE(json::parse(get.body, nullptr, false).contains("error"));
    EXPECT_EQ(get.header("content-length"), std::to_string(get.body.size()));

    const auto head = exchange("127.0.0.1", node.port, request("HEAD", "/global_stats"));
    ASSERT_TRUE(head.ok);
    EXPECT_EQ(head.status, 503u);
    EXPECT_TRUE(head.body.empty());
    EXPECT_EQ(head.header("content-length"), std::to_string(get.body.size()));

    EXPECT_EQ(node.stratum->get_session_count(), 0u);
    EXPECT_TRUE(wait_until([&] { return node.stratum->get_http_connection_count() == 0; }));

    // A miner on the same port is unaffected.
    RawClient miner;
    ASSERT_TRUE(miner.connect("127.0.0.1", node.port));
    miner.send(std::string(kSubscribe) + "\n");
    EXPECT_TRUE(subscribed(miner));
}

TEST(StratumHttpNoWeb, AutoWithoutAWebServerIsOff)
{
    SplitNode node;
    ASSERT_TRUE(node.start(false, StratumHttpMode::Auto));
    EXPECT_FALSE(node.decision.on);
    EXPECT_EQ(node.decision.summary, "OFF (web server disabled)");
    EXPECT_TRUE(answered_as_stratum("127.0.0.1", node.port));
}

TEST(StratumHttpNoWeb, AStoppedWebServerDeclinesWith503)
{
    SplitNode node;
    ASSERT_TRUE(node.start(true, StratumHttpMode::On));
    EXPECT_EQ(exchange("127.0.0.1", node.port, request("GET", "/fee")).status, 200u);
    node.web->stop();
    const auto r = exchange("127.0.0.1", node.port, request("GET", "/fee"));
    ASSERT_TRUE(r.ok) << "'" << r.raw << "'";
    EXPECT_EQ(r.status, 503u);
}

// ── Logging ─────────────────────────────────────────────────────────────────

namespace {

// Every log record written while it lives, as text.
class LogCapture {
public:
    LogCapture()
    {
        auto backend = boost::make_shared<boost::log::sinks::text_ostream_backend>();
        backend->add_stream(os_);
        backend->auto_flush(true);
        sink_ = boost::make_shared<Sink>(backend);
        sink_->set_formatter(boost::log::expressions::stream << boost::log::expressions::smessage);
        boost::log::core::get()->add_sink(sink_);
    }
    ~LogCapture() { boost::log::core::get()->remove_sink(sink_); }
    std::string text()
    {
        sink_->flush();
        auto backend = sink_->locked_backend();
        return os_->str();
    }
    size_t count(const std::string& needle)
    {
        const auto t = text();
        size_t n = 0;
        for (auto p = t.find(needle); p != std::string::npos; p = t.find(needle, p + 1)) ++n;
        return n;
    }

private:
    using Sink = boost::log::sinks::synchronous_sink<boost::log::sinks::text_ostream_backend>;
    boost::shared_ptr<std::ostringstream> os_ = boost::make_shared<std::ostringstream>();
    boost::shared_ptr<Sink> sink_;
};

}  // namespace

TEST(StratumHttpLog, OneLinePerWindowAndNoQueryString)
{
    LogCapture log;
    SplitNode node;
    ASSERT_TRUE(node.start(true, StratumHttpMode::On));
    for (int i = 0; i < 6; ++i)
        EXPECT_EQ(exchange("127.0.0.1", node.port,
                           request(i == 5 ? "POST" : "GET", "/fee?token=SEKRIT-" + std::to_string(i))).status,
                  i == 5 ? 405u : 200u);
    EXPECT_EQ(node.stratum->get_http_requests(), 6u);
    // The first request is logged in full; the rest are counted into the
    // summary written with the first request after the 60 s.
    EXPECT_EQ(node.stratum->get_http_log_lines(), 1u);
    EXPECT_EQ(log.count("HTTP request on stratum port from 127.0.0.1: GET /fee -> 200"), 1u) << log.text();
    EXPECT_EQ(log.count("SEKRIT"), 0u) << "a query string reached the log";
    EXPECT_EQ(log.count("Error processing Stratum message"), 0u);
}

TEST(StratumHttpLog, FailedRequestsAreRateLimitedToo)
{
    LogCapture log;
    SplitNode node;
    ASSERT_TRUE(node.start(true, StratumHttpMode::On));
    for (int i = 0; i < 5; ++i) {
        const auto r = exchange("127.0.0.1", node.port,
                                "GET /fee?token=SEKRIT HTTP/1.1\r\nBad Header\r\n\r\n");
        EXPECT_FALSE(r.ok) << r.raw;
    }
    ASSERT_TRUE(wait_until([&] { return node.stratum->get_http_connection_count() == 0; }));
    EXPECT_EQ(node.stratum->get_http_error_log_lines(), 1u);
    EXPECT_EQ(log.count("HTTP request on stratum port from 127.0.0.1 failed: read_request: "), 1u)
        << log.text();
    EXPECT_EQ(log.count("HTTP Session error"), 0u) << "an unthrottled per-request warning";
    EXPECT_EQ(log.count("SEKRIT"), 0u);
}

// ── Settings file ───────────────────────────────────────────────────────────

TEST(StratumHttpSettings, FileValuesParseLikeTheCommandLine)
{
    using namespace c2pool::settings;
    struct Case { const char* literal; bool ok; StratumHttpMode mode; };
    for (const Case& c : {Case{"\"true\"", true, StratumHttpMode::On}, Case{"true", true, StratumHttpMode::On},
                          Case{"\"on\"", true, StratumHttpMode::On}, Case{"\"yes\"", true, StratumHttpMode::On},
                          Case{"\"1\"", true, StratumHttpMode::On}, Case{"\"false\"", true, StratumHttpMode::Off},
                          Case{"false", true, StratumHttpMode::Off}, Case{"\"off\"", true, StratumHttpMode::Off},
                          Case{"\"no\"", true, StratumHttpMode::Off}, Case{"\"0\"", true, StratumHttpMode::Off},
                          Case{"\"auto\"", true, StratumHttpMode::Auto}, Case{"\"AUTO\"", true, StratumHttpMode::Auto},
                          Case{"\"maybe\"", false, StratumHttpMode::On}, Case{"\"\"", false, StratumHttpMode::On}}) {
        const std::string path = ::testing::TempDir() + "stratum_http_settings_test.toml";
        {
            std::ofstream f(path);
            f << "[ltc.stratum]\nhttp = " << c.literal << "\n";
        }
        CliTracker cli;
        ResolvedConfig rc;
        rc.seed_compiled_defaults(c2pool::catalog::C_LTC);
        const auto r = SettingsFile::load(path, c2pool::catalog::C_LTC, cli, rc);
        std::remove(path.c_str());
        ASSERT_EQ(r.status, LoadStatus::Ok) << c.literal << (r.messages.empty() ? "" : r.messages.front());
        ASSERT_TRUE(rc.file_set("stratum.http")) << c.literal;
        // A value the CLI does not take is refused and leaves the mode as it
        // was (never silently off); here it was on.
        StratumHttpMode mode = StratumHttpMode::On;
        EXPECT_EQ(core::apply_stratum_http_setting(rc.get_string("stratum.http").value_or(""), mode), c.ok)
            << c.literal;
        EXPECT_EQ(mode, c.mode) << c.literal;
    }
}

// ── auto follows the stratum bind ───────────────────────────────────────────

TEST(StratumHttpSwitch, AutoFollowsTheStratumListenersBind)
{
    {   // wildcard web server, stratum on one address: on, and the startup
        // line names both binds (the stratum bind reached the resolver).
        SplitNode node;
        ASSERT_TRUE(node.start(true, StratumHttpMode::Auto, {}, "0.0.0.0", "127.0.0.1"));
        EXPECT_TRUE(node.decision.on);
        EXPECT_EQ(node.decision.summary, "ON (web bound to 0.0.0.0, stratum to 127.0.0.1)");
        EXPECT_EQ(exchange("127.0.0.1", node.port, request("GET", "/fee")).status, 200u);
    }
    // A web server kept on one LAN address, stratum on every interface: off.
    const auto ip = non_loopback_local_ipv4();
    if (!ip)
        return;   // the split-bind rule itself is covered by AutoFollowsTheStratumBindToo
    SplitNode node;
    ASSERT_TRUE(node.start(true, StratumHttpMode::Auto, {}, *ip, "0.0.0.0"));
    EXPECT_FALSE(node.decision.on);
    EXPECT_EQ(node.decision.summary, "OFF (web bound to " + *ip + ", stratum to 0.0.0.0)");
    EXPECT_TRUE(answered_as_stratum("127.0.0.1", node.port));
}

// ── Strictly read-only ──────────────────────────────────────────────────────

TEST(StratumHttpReadOnly, ATokenOpensNothingOnTheStratumPort)
{
    WebNode node;
    ASSERT_TRUE(node.start("0.0.0.0", [](core::WebServer& w) {
        w.get_mining_interface()->set_auth_token("t0k");
    }));
    for (const char* method : {"GET", "HEAD"})
        for (const char* target : {"/control/mining/ban?target=a&token=t0k", "/control/mining/stop?token=t0k",
                                   "/web/log?token=t0k", "/logs/export?scope=all&token=t0k"}) {
            const auto st = exchange("127.0.0.1", node.stratum_port, request(method, target));
            ASSERT_TRUE(st.ok) << method << " " << target << ": '" << st.raw << "'";
            EXPECT_EQ(st.status, 403u) << method << " " << target;
        }
    // HEAD on the web port never runs a route that changes state on GET.
    const auto head = exchange("127.0.0.1", node.web_port, request("HEAD", "/control/mining/ban?target=b&token=t0k"));
    ASSERT_TRUE(head.ok);
    EXPECT_EQ(head.status, 405u);
    EXPECT_EQ(head.header("allow"), "GET");
    // The token still works on the web port: this is the only ban made.
    const auto get = exchange("127.0.0.1", node.web_port, request("GET", "/control/mining/ban?target=c&token=t0k"));
    ASSERT_TRUE(get.ok);
    EXPECT_EQ(get.status, 200u);
    EXPECT_EQ(json::parse(get.body, nullptr, false).value("banned_count", -1), 1) << get.body;
}

TEST(StratumHttpReadOnly, HeadNeverRunsAStateChangingRoute)
{
    WebNode node;
    ASSERT_TRUE(node.start("0.0.0.0"));
    // Web port, direct local (GET would run these): HEAD is refused.
    for (const char* target : {"/control/mining/stop", "/control/mining/ban?target=x",
                               "/control/mining/unban?target=x", "/control/mining/restart"}) {
        const auto r = exchange("127.0.0.1", node.web_port, request("HEAD", target));
        ASSERT_TRUE(r.ok) << target;
        EXPECT_EQ(r.status, 405u) << target;
        EXPECT_EQ(r.header("allow"), "GET") << target;
        EXPECT_TRUE(r.body.empty()) << target;
    }
    for (const char* target : {"/api/admin/pool/bans/add?ip=1.2.3.4", "/api/admin/pool/peers/drop?ip=1.2.3.4",
                               "/api/admin/coin/peer/add?host=1.2.3.4:9333"}) {
        const auto r = exchange("127.0.0.1", node.web_port, request("HEAD", target));
        ASSERT_TRUE(r.ok) << target;
        EXPECT_EQ(r.status, 405u) << target;
        EXPECT_EQ(r.header("allow"), "GET, POST") << target;
    }
    // A read-only route answers HEAD on both ports.
    EXPECT_EQ(exchange("127.0.0.1", node.web_port, request("HEAD", "/global_stats")).status, 200u);
    EXPECT_EQ(exchange("127.0.0.1", node.stratum_port, request("HEAD", "/global_stats")).status, 200u);
}

TEST(StratumHttpReadOnly, CorsAdvertisesOnlyGetAndHeadOnTheStratumPort)
{
    WebNode node;
    ASSERT_TRUE(node.start("0.0.0.0", [](core::WebServer& w) {
        w.get_mining_interface()->set_cors_origin("https://stats.example");
    }));
    const auto st = exchange("127.0.0.1", node.stratum_port, request("GET", "/fee"));
    const auto web = exchange("127.0.0.1", node.web_port, request("GET", "/fee"));
    ASSERT_TRUE(st.ok);
    ASSERT_TRUE(web.ok);
    EXPECT_EQ(st.header("access-control-allow-origin"), "https://stats.example");
    EXPECT_EQ(st.header("access-control-allow-methods"), "GET, HEAD");
    EXPECT_EQ(web.header("access-control-allow-methods"), "GET, POST, OPTIONS");
    const auto post = exchange("127.0.0.1", node.stratum_port, request("POST", "/", {}, "{}"));
    EXPECT_EQ(post.header("allow"), "GET, HEAD");
}

TEST(StratumHttpSniff, LeadingEmptyLinesBeforeTheRequestLine)
{
    WebNode node;
    ASSERT_TRUE(node.start("0.0.0.0"));
    for (const char* lead : {"\r\n", "\n", "\r\n\r\n"}) {
        const auto r = exchange("127.0.0.1", node.stratum_port, lead + request("GET", "/fee"));
        ASSERT_TRUE(r.ok) << "'" << r.raw << "'";
        EXPECT_EQ(r.status, 200u);
    }
    // HTTP off: an empty first line is an invalid stratum line, as before.
    WebNode off;
    ASSERT_TRUE(off.start("0.0.0.0", [](core::WebServer& w) { w.set_stratum_http_mode(StratumHttpMode::Off); }));
    RawClient c;
    ASSERT_TRUE(c.connect("127.0.0.1", off.stratum_port));
    c.send("\r\n");
    auto line = c.read_line();
    ASSERT_TRUE(line);
    EXPECT_NE(line->find("Invalid JSON"), std::string::npos) << *line;
}

// ── The handshake deadline ends the exchange ───────────────────────────────

TEST(StratumHttpDeadline, CountsFromTheHandOffNotFromTheHttpThread)
{
    core::stratum::StratumConfig cfg;
    cfg.handshake_timeout_sec = 2;
    SplitNode node;
    // /slow keeps the web server's single HTTP thread busy for 3 s.
    ASSERT_TRUE(node.start(true, StratumHttpMode::On, cfg, "127.0.0.1", "127.0.0.1",
                           [](core::WebServer& w) {
                               w.get_mining_interface()->set_rest_override_fn(
                                   [](const std::string& path) -> std::optional<nlohmann::json> {
                                       if (path != "/slow") return std::nullopt;
                                       std::this_thread::sleep_for(3s);
                                       return nlohmann::json{{"slow", true}};
                                   });
                           }));
    auto& ss = *node.stratum;
    auto busy = std::async(std::launch::async, [&] {
        return exchange("127.0.0.1", node.web->bound_port(), request("GET", "/slow"), {}, 8000ms).status;
    });
    std::this_thread::sleep_for(200ms);   // the HTTP thread is inside /slow now

    const auto t0 = std::chrono::steady_clock::now();
    RawClient c;
    ASSERT_TRUE(c.connect("127.0.0.1", node.port));
    c.send("GET /fee HTTP/1.1\r\n");   // handed off, its headers never finish
    ASSERT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 1; }));
    ASSERT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 0; }, 6000ms));
    const double s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    // The HTTP thread frees up at about 2.8 s, after the 2 s deadline: the
    // session closes as soon as it runs, not 2 s after that.
    EXPECT_LT(s, 4.0);
    EXPECT_TRUE(c.read_all(2000ms).empty());
    EXPECT_TRUE(c.closed());
    EXPECT_EQ(busy.get(), 200u);
}

TEST(StratumHttpDeadline, SlotFreedAtTheDeadline)
{
    core::stratum::StratumConfig cfg;
    cfg.handshake_timeout_sec = 2;
    SplitNode node;
    ASSERT_TRUE(node.start(true, StratumHttpMode::On, cfg));
    auto& ss = *node.stratum;
    RawClient c;
    const auto t0 = std::chrono::steady_clock::now();
    ASSERT_TRUE(c.connect("127.0.0.1", node.port));
    c.send("GET /fee HTTP/1.1\r\nHost: t\r\n");
    ASSERT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 1; }));
    ASSERT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 0; }, 6000ms));
    const double s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    EXPECT_GT(s, 1.5);
    EXPECT_LT(s, 3.5);
    EXPECT_TRUE(c.read_all(1000ms).empty());
}

// ── The response write deadline on the stratum port ────────────────────────

namespace core {
// HttpSession's write-deadline steps, for the tests below.
struct HttpSessionTestAccess {
    static void begin_write(HttpSession& s) { s.begin_write(); }
    static void arm_write_deadline(HttpSession& s) { s.arm_write_deadline(); }
    static void end_writing(HttpSession& s) { s.end_writing(); }
    static std::chrono::steady_clock::time_point write_started(const HttpSession& s) { return s.write_started_; }
    static std::chrono::steady_clock::time_point write_expiry(const HttpSession& s)
    {
        return s.write_deadline_.expiry();
    }
};
}  // namespace core

namespace {

using clock_type = std::chrono::steady_clock;

double seconds_since(clock_type::time_point t0)
{
    return std::chrono::duration<double>(clock_type::now() - t0).count();
}

// SO_SNDBUF + SO_RCVBUF of a connected socket, as getsockopt reports them.
std::size_t socket_buffer_bytes(tcp::socket& s)
{
    net::socket_base::send_buffer_size snd;
    net::socket_base::receive_buffer_size rcv;
    s.get_option(snd);
    s.get_option(rcv);
    return static_cast<std::size_t>(snd.value()) + static_cast<std::size_t>(rcv.value());
}

// A temporary dashboard directory.
class StaticDir {
public:
    StaticDir()
    {
        std::random_device rd;
        path_ = std::filesystem::temp_directory_path()
              / ("c2pool-stratum-http-" + std::to_string(rd()) + "-" + std::to_string(rd()));
        std::filesystem::create_directories(path_);
    }
    ~StaticDir()
    {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }
    std::string path() const { return path_.string(); }
    void write(const std::string& name, std::size_t bytes) const
    {
        std::ofstream f(path_ / name, std::ios::binary | std::ios::trunc);
        const std::string block(1 << 16, 'x');
        for (std::size_t left = bytes; left > 0; ) {
            const std::size_t n = std::min(left, block.size());
            f.write(block.data(), static_cast<std::streamsize>(n));
            left -= n;
        }
    }

private:
    std::filesystem::path path_;
};

// A SplitNode whose web server serves `dir` and has these HTTP timeouts
// (idle = the stratum-port write_timeout).
bool start_write_node(SplitNode& node, const StaticDir& dir, uint32_t handshake_s,
                      std::chrono::milliseconds idle, std::chrono::milliseconds request = 10000ms)
{
    core::stratum::StratumConfig cfg;
    cfg.handshake_timeout_sec = handshake_s;
    return node.start(true, StratumHttpMode::On, cfg, "127.0.0.1", "127.0.0.1",
                      [&](core::WebServer& w) {
                          w.set_dashboard_dir(dir.path());
                          w.set_http_timeouts(idle, request);
                      });
}

// A stratum-port GET of a static file 4 x (SO_SNDBUF + SO_RCVBUF) of the
// client's socket, from a client that never reads. Times in seconds from
// the connect.
struct StalledWrite {
    std::size_t response_bytes = 0;
    double first_byte_s = -1;   // the first response byte is in the client's buffer
    double released_s = -1;     // the stratum slot is released (count back to 0)
    bool held = false;          // the stratum slot was taken
    bool http_cap_untouched = true;   // the web server's HTTP slot count stayed 0
};

// hold_stratum_until: from the hand-off on, the stratum io thread is held
// until that long after the connect (0: not held).
StalledWrite stalled_get(SplitNode& node, const StaticDir& dir,
                         const std::function<void(RawClient&)>& send_request = {},
                         std::chrono::milliseconds limit = 8000ms,
                         std::chrono::milliseconds hold_stratum_until = 0ms)
{
    StalledWrite r;
    auto& ss = *node.stratum;
    RawClient c;
    const auto t0 = clock_type::now();
    bool hold_posted = false;
    if (!c.connect("127.0.0.1", node.port))
        return r;
    r.response_bytes = 4 * socket_buffer_bytes(c.socket());
    dir.write("big.txt", r.response_bytes);
    if (send_request)
        send_request(c);
    else
        c.send(request("GET", "/big.txt"));
    while (clock_type::now() - t0 < limit) {
        if (node.web->http_sessions() != 0)
            r.http_cap_untouched = false;
        boost::system::error_code ec;
        if (r.first_byte_s < 0 && c.socket().available(ec) > 0 && !ec)
            r.first_byte_s = seconds_since(t0);
        const size_t live = ss.get_http_connection_count();
        if (live == 1)
            r.held = true;
        if (r.held && !hold_posted && hold_stratum_until.count() > 0) {
            net::post(node.ioc, [t0, hold_stratum_until] { std::this_thread::sleep_until(t0 + hold_stratum_until); });
            hold_posted = true;
        }
        if (r.held && live == 0) {
            r.released_s = seconds_since(t0);
            break;
        }
        std::this_thread::sleep_for(5ms);
    }
    c.close();
    return r;
}

}  // namespace

TEST(StratumHttpWriteDeadline, ANonReadingClientIsClosedAtTheHandOffBoundWhenThatIsEarlier)
{
    // Hand-off bound 1 s after the accept; write_timeout 3 s. The stratum io
    // thread is held from the hand-off to 2.5 s: the session's own write
    // deadline closes the connection.
    StaticDir dir;
    SplitNode node;
    ASSERT_TRUE(start_write_node(node, dir, 1, 3000ms));
    const auto r = stalled_get(node, dir, {}, 8000ms, 2500ms);
    ASSERT_TRUE(r.held);
    TIMING_PRECONDITION(r.first_byte_s > 0.0 && r.first_byte_s < 0.95,
                        "the response write started at " << r.first_byte_s << " s, before the 1 s bound");
    ASSERT_GT(r.released_s, 0.0) << "the stratum slot was not released";
    EXPECT_GE(r.released_s, 0.95) << r.response_bytes << " bytes fit the socket buffers";
    EXPECT_LT(r.released_s, 1.5);
    EXPECT_TRUE(r.http_cap_untouched);
    EXPECT_EQ(node.stratum->get_http_connection_count(), 0u);
    EXPECT_EQ(node.web->http_sessions(), 0u);
}

TEST(StratumHttpWriteDeadline, ANonReadingClientIsClosedAtTheWriteTimeoutWhenThatIsEarlier)
{
    // Hand-off bound 4 s after the accept; write_timeout 600 ms.
    StaticDir dir;
    SplitNode node;
    ASSERT_TRUE(start_write_node(node, dir, 4, 600ms));
    const auto r = stalled_get(node, dir);
    ASSERT_TRUE(r.held);
    TIMING_PRECONDITION(r.first_byte_s > 0.0 && r.first_byte_s < 3.0,
                        "the response write started at " << r.first_byte_s << " s, before the 4 s bound");
    ASSERT_GT(r.released_s, 0.0) << "the stratum slot was not released";
    const double from_write = r.released_s - r.first_byte_s;
    EXPECT_GE(from_write, 0.55) << r.response_bytes << " bytes fit the socket buffers";
    EXPECT_LT(from_write, 1.0);
    EXPECT_LT(r.released_s, 2.0);
    EXPECT_TRUE(r.http_cap_untouched);
    EXPECT_EQ(node.stratum->get_http_connection_count(), 0u);
    EXPECT_EQ(node.web->http_sessions(), 0u);
}

TEST(StratumHttpWriteDeadline, AReadRearmNeverMovesPastTheHandOffBound)
{
    // Every header byte re-arms the read deadline (idle 400 ms; whole request
    // 10 s); the hand-off bound is 1 s after the accept. The stratum io thread
    // is held from the hand-off to 2.5 s: the session's own read deadline
    // closes the connection.
    StaticDir dir;
    SplitNode node;
    ASSERT_TRUE(start_write_node(node, dir, 1, 400ms, 10000ms));
    auto& ss = *node.stratum;
    RawClient c;
    const auto t0 = clock_type::now();
    ASSERT_TRUE(c.connect("127.0.0.1", node.port));
    c.send("GET /big.txt HTTP/1.1\r\n");
    ASSERT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 1; }));
    net::post(node.ioc, [t0] { std::this_thread::sleep_until(t0 + 2500ms); });
    double released = -1;
    while (seconds_since(t0) < 4.0) {
        c.send("X-Slow: 1\r\n");
        if (ss.get_http_connection_count() == 0) {
            released = seconds_since(t0);
            break;
        }
        std::this_thread::sleep_for(100ms);
    }
    ASSERT_GT(released, 0.0) << "still open past the hand-off bound";
    EXPECT_GE(released, 0.95);
    EXPECT_LT(released, 1.5);
    EXPECT_TRUE(c.read_all(500ms).empty());
}

TEST(StratumHttpWriteDeadline, AWriteStartedLateEndsAtTheHandOffBound)
{
    // The request completes about 700 ms after the accept; write_timeout 2 s;
    // the hand-off bound is 1 s after the accept: the write ends at 1 s, not
    // at 700 ms + 2 s.
    StaticDir dir;
    SplitNode node;
    ASSERT_TRUE(start_write_node(node, dir, 1, 2000ms));
    const auto r = stalled_get(node, dir, [](RawClient& c) {
        c.send("GET /big.txt HTTP/1.1\r\n");
        for (int i = 0; i < 7; ++i) {
            std::this_thread::sleep_for(100ms);
            c.send("X-Slow: 1\r\n");
        }
        c.send("\r\n");
    });
    ASSERT_TRUE(r.held);
    TIMING_PRECONDITION(r.first_byte_s > 0.6 && r.first_byte_s < 0.95,
                        "the response write started at " << r.first_byte_s
                        << " s, after the request (0.7 s) and before the 1 s bound");
    ASSERT_GT(r.released_s, 0.0) << "the stratum slot was not released";
    EXPECT_GE(r.released_s, 0.95) << r.response_bytes << " bytes fit the socket buffers";
    EXPECT_LT(r.released_s, 1.5);
    EXPECT_TRUE(r.http_cap_untouched);
}

TEST(StratumHttpWriteDeadline, ASessionRunPastTheHandOffBoundAnswersNothing)
{
    // The web server's one HTTP thread is busy for 3 s; the hand-off bound is
    // 1 s after the accept. A complete request queued behind it is never
    // routed or answered: shut down at the bound, closed when the HTTP thread
    // runs, and its slot released then.
    core::stratum::StratumConfig cfg;
    cfg.handshake_timeout_sec = 1;
    std::atomic<int> routed{0};
    SplitNode node;
    ASSERT_TRUE(node.start(true, StratumHttpMode::On, cfg, "127.0.0.1", "127.0.0.1",
                           [&](core::WebServer& w) {
                               w.get_mining_interface()->set_rest_override_fn(
                                   [&](const std::string& path) -> std::optional<nlohmann::json> {
                                       if (path == "/counted") {
                                           ++routed;
                                           return nlohmann::json{{"counted", true}};
                                       }
                                       if (path != "/slow") return std::nullopt;
                                       std::this_thread::sleep_for(3s);
                                       return nlohmann::json{{"slow", true}};
                                   });
                           }));
    auto& ss = *node.stratum;
    auto busy = std::async(std::launch::async, [&] {
        return exchange("127.0.0.1", node.web->bound_port(), request("GET", "/slow"), {}, 8000ms).status;
    });
    std::this_thread::sleep_for(200ms);
    RawClient c;
    ASSERT_TRUE(c.connect("127.0.0.1", node.port));
    c.send(request("GET", "/counted"));
    ASSERT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 1; }));
    const std::string got = c.read_all(6000ms);
    EXPECT_TRUE(c.closed());
    EXPECT_TRUE(got.empty()) << "answered past the hand-off bound: " << got.substr(0, 80);
    EXPECT_EQ(busy.get(), 200u);
    EXPECT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 0; }, 1000ms));
    EXPECT_EQ(routed.load(), 0) << "routed past the hand-off bound";
}

TEST(StratumHttpWriteDeadline, TheSlotIsReleasedRightAfterACompletedResponse)
{
    // write_timeout 5 s, hand-off bound 10 s: an answered request releases
    // its slot at once, on either port.
    StaticDir dir;
    SplitNode node;
    ASSERT_TRUE(start_write_node(node, dir, 10, 5000ms));
    auto& ss = *node.stratum;
    for (int i = 0; i < 3; ++i) {
        const auto t0 = clock_type::now();
        const auto st = exchange("127.0.0.1", node.port, request(i == 1 ? "HEAD" : "GET", "/fee"));
        ASSERT_TRUE(st.ok) << st.raw;
        EXPECT_EQ(st.status, 200u);
        EXPECT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 0; }, 1000ms));
        EXPECT_LT(seconds_since(t0), 2.0);
    }
    const auto web = exchange("127.0.0.1", node.web->bound_port(), request("GET", "/fee"));
    ASSERT_TRUE(web.ok) << web.raw;
    EXPECT_TRUE(wait_until([&] { return node.web->http_sessions() == 0; }, 1000ms));
}

TEST(StratumHttpWriteDeadline, EachSessionReleasesTheSlotItHolds)
{
    // Web port: the HTTP-cap slot, never a stratum slot. Stratum port: the
    // stratum slot, never an HTTP-cap slot. Each released when its
    // connection closes.
    StaticDir dir;
    SplitNode node;
    ASSERT_TRUE(start_write_node(node, dir, 10, 5000ms));
    auto& ss = *node.stratum;
    {
        RawClient web;
        ASSERT_TRUE(web.connect("127.0.0.1", node.web->bound_port()));
        web.send("GET /fee HTTP/1.1\r\n");
        ASSERT_TRUE(wait_until([&] { return node.web->http_sessions() == 1; }));
        EXPECT_EQ(ss.get_http_connection_count(), 0u);
        web.close();
    }
    EXPECT_TRUE(wait_until([&] { return node.web->http_sessions() == 0; }, 1000ms));
    {
        RawClient st;
        ASSERT_TRUE(st.connect("127.0.0.1", node.port));
        st.send("GET /fee HTTP/1.1\r\n");
        ASSERT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 1; }));
        EXPECT_EQ(node.web->http_sessions(), 0u);
        st.close();
    }
    EXPECT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 0; }, 1000ms));
    EXPECT_EQ(node.web->http_sessions(), 0u);
}

TEST(StratumHttpWriteDeadline, AResponseFinishedAfterTheHandOffBoundIsNotWritten)
{
    // Hand-off bound 1 s. The request is read at once; its route takes 1.5 s,
    // so the response is ready after the bound: closed, nothing written. The
    // stratum io thread is held from the hand-off to 2.5 s, so the bound's
    // shutdown has not run when the response is ready.
    core::stratum::StratumConfig cfg;
    cfg.handshake_timeout_sec = 1;
    std::atomic<int64_t> route_returned_ms{-1};
    const auto t0 = clock_type::now();
    SplitNode node;
    ASSERT_TRUE(node.start(true, StratumHttpMode::On, cfg, "127.0.0.1", "127.0.0.1",
                           [&](core::WebServer& w) {
                               w.get_mining_interface()->set_rest_override_fn(
                                   [&](const std::string& path) -> std::optional<nlohmann::json> {
                                       if (path != "/slow") return std::nullopt;
                                       std::this_thread::sleep_for(1500ms);
                                       route_returned_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                           clock_type::now() - t0).count();
                                       return nlohmann::json{{"slow", true}};
                                   });
                           }));
    RawClient c;
    ASSERT_TRUE(c.connect("127.0.0.1", node.port));
    c.send(request("GET", "/slow"));
    ASSERT_TRUE(wait_until([&] { return node.stratum->get_http_connection_count() == 1; }));
    net::post(node.ioc, [t0] { std::this_thread::sleep_until(t0 + 2500ms); });
    const std::string got = c.read_all(5000ms);
    const double closed_at = seconds_since(t0);
    TIMING_PRECONDITION(route_returned_ms >= 0 && route_returned_ms < 2200,
                        "the route returned at " << route_returned_ms
                        << " ms, before the stratum io thread is free at 2500 ms");
    EXPECT_TRUE(c.closed());
    EXPECT_TRUE(got.empty()) << "answered past the 1 s hand-off bound (closed at " << closed_at
                             << " s): " << got.substr(0, 60);
    EXPECT_LT(closed_at, 2.2) << "closed by the shutdown, not by the session";
    EXPECT_TRUE(wait_until([&] { return node.stratum->get_http_connection_count() == 0; }, 2000ms));
}

TEST(StratumHttpWriteDeadline, TheWriteTermCountsFromTheWriteStart)
{
    // write_timeout 600 ms; the request takes about 500 ms to arrive (a header
    // line every 100 ms); hand-off bound 10 s: the write ends about 600 ms
    // after it starts.
    StaticDir dir;
    SplitNode node;
    ASSERT_TRUE(start_write_node(node, dir, 10, 600ms, 10000ms));
    const auto r = stalled_get(node, dir, [](RawClient& c) {
        c.send("GET /big.txt HTTP/1.1\r\n");
        for (int i = 0; i < 5; ++i) {
            std::this_thread::sleep_for(100ms);
            c.send("X-Slow: 1\r\n");
        }
        c.send("\r\n");
    });
    ASSERT_TRUE(r.held);
    TIMING_PRECONDITION(r.first_byte_s > 0.45,
                        "the response write started at " << r.first_byte_s << " s, after the request (0.5 s)");
    ASSERT_GT(r.released_s, 0.0);
    const double from_write = r.released_s - r.first_byte_s;
    EXPECT_GE(from_write, 0.55) << "released " << r.released_s << " s, first byte " << r.first_byte_s;
    EXPECT_LT(from_write, 1.0);
}

TEST(StratumHttpWriteDeadline, ASecondArmDoesNotMoveTheWriteTermLater)
{
    using core::HttpSessionTestAccess;
    struct Case { std::optional<std::chrono::seconds> owner_in; bool owner_earlier; };
    for (const Case& c : {Case{std::nullopt, false}, Case{60s, false}, Case{5s, true}}) {
        net::io_context io;
        core::HttpSessionOptions opts;
        opts.stratum_port = true;
        opts.write_timeout = 10s;
        if (c.owner_in)
            opts.deadline = clock_type::now() + *c.owner_in;
        const auto owner = opts.deadline;
        auto s = std::make_shared<core::HttpSession>(tcp::socket(io), nullptr, nullptr,
                                                     core::HttpSession::kIdleTimeout,
                                                     core::HttpSession::kRequestTimeout, opts);
        HttpSessionTestAccess::begin_write(*s);
        const auto started = HttpSessionTestAccess::write_started(*s);
        const auto first = HttpSessionTestAccess::write_expiry(*s);
        EXPECT_EQ(first, c.owner_earlier ? *owner : started + 10s);
        std::this_thread::sleep_for(150ms);
        HttpSessionTestAccess::arm_write_deadline(*s);
        EXPECT_EQ(HttpSessionTestAccess::write_started(*s), started);
        EXPECT_EQ(HttpSessionTestAccess::write_expiry(*s), first);
        HttpSessionTestAccess::end_writing(*s);
        io.poll();
    }
}

TEST(StratumHttpWriteDeadline, TheEventStreamIsRefusedOnTheStratumPort)
{
    StaticDir dir;
    SplitNode node;
    ASSERT_TRUE(start_write_node(node, dir, 10, 5000ms));
    auto& ss = *node.stratum;
    for (const char* method : {"GET", "HEAD"}) {
        const auto st = exchange("127.0.0.1", node.port, request(method, "/sharechain/stream"), {}, 3000ms);
        ASSERT_TRUE(st.ok) << method << " '" << st.raw.substr(0, 120) << "'";
        EXPECT_EQ(st.status, 405u) << method;
        EXPECT_EQ(st.headers.count("allow"), 1u) << method;
        EXPECT_EQ(st.header("allow"), "") << method;
        EXPECT_EQ(st.header("connection"), "close") << method;
        EXPECT_EQ(st.raw.find("text/event-stream"), std::string::npos) << method;
        EXPECT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 0; }, 1000ms)) << method;
    }
    EXPECT_EQ(node.web->get_mining_interface()->sse_subscriber_count(), 0u);
}

namespace core {
// StratumSession's 503 writer, for the test below.
struct StratumSessionTestAccess {
    static void answer_http_unavailable(std::shared_ptr<StratumHttpRequest> req, const std::string& method,
                                        const std::string& target, StratumHttpUnavailable kind)
    {
        StratumSession::answer_http_unavailable(std::move(req), method, target, kind);
    }
};
}  // namespace core

TEST(StratumHttpWriteDeadline, TheStratumSide503WriteIsClosedAtItsDeadline)
{
    // The stratum side's 503 on a socket whose send buffer is full and whose
    // peer never reads, with a deadline 300 ms on: the write is closed at the
    // deadline and the request's slot released.
    net::io_context io;
    tcp::acceptor acc(io, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
    tcp::socket c(io), sv(io);
    c.connect(acc.local_endpoint());
    acc.accept(sv);
    sv.non_blocking(true);
    const std::string chunk(1 << 16, 'x');
    for (;;) {
        boost::system::error_code ec;
        sv.write_some(net::buffer(chunk), ec);
        if (ec == net::error::would_block)
            break;
        ASSERT_FALSE(ec) << ec.message();
    }
    auto released = std::make_shared<std::atomic<bool>>(false);
    auto req = std::make_shared<core::StratumHttpRequest>(
        core::StratumHttpRequest{std::move(sv), {}, {}, {}, {}, {}, {}});
    req->slot = std::shared_ptr<void>(new int(0), [released](void* p) {
        delete static_cast<int*>(p);
        *released = true;
    });
    const auto t0 = clock_type::now();
    req->deadline = t0 + 300ms;
    core::StratumSessionTestAccess::answer_http_unavailable(std::move(req), "GET", "/fee",
                                                            core::StratumHttpUnavailable::Busy);
    double released_at = -1;
    while (seconds_since(t0) < 3.0 && released_at < 0) {
        io.run_for(20ms);
        if (*released)
            released_at = seconds_since(t0);
    }
    EXPECT_GE(released_at, 0.25) << "released before the deadline, or never";
    EXPECT_LT(released_at, 1.0) << "the stalled 503 write was not closed at its deadline";
    boost::system::error_code ignore;
    c.close(ignore);
    io.restart();
    io.run_for(500ms);
}

// ── The hand-off deadline's shutdown ──────────────────────────────────────

namespace {

// Server-side descriptors of this process: open TCP sockets whose local port
// is `port`, listeners excluded. Walks this process's own descriptors
// (/proc/self/fd, getsockname, SO_ACCEPTCONN): O(open descriptors).
std::size_t open_sockets_on_port(uint16_t port)
{
#ifdef __linux__
    std::size_t n = 0;
    std::error_code ec;
    for (const auto& e : std::filesystem::directory_iterator("/proc/self/fd", ec)) {
        int fd = -1;
        try {
            fd = std::stoi(e.path().filename().string());
        } catch (...) {
            continue;
        }
        sockaddr_storage addr{};
        socklen_t len = sizeof(addr);
        if (::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0)
            continue;
        uint16_t local = 0;
        if (addr.ss_family == AF_INET)
            local = ntohs(reinterpret_cast<const sockaddr_in*>(&addr)->sin_port);
        else if (addr.ss_family == AF_INET6)
            local = ntohs(reinterpret_cast<const sockaddr_in6*>(&addr)->sin6_port);
        else
            continue;
        int type = 0, listening = 0;
        socklen_t ilen = sizeof(int);
        if (local != port || ::getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &ilen) != 0 || type != SOCK_STREAM)
            continue;
        ilen = sizeof(int);
        if (::getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &listening, &ilen) != 0 || listening != 0)
            continue;
        ++n;
    }
    return n;
#else
    (void)port;
    return 0;
#endif
}

// A web route (/block) that holds the HTTP thread until release().
class HttpThreadHook {
public:
    void install(core::WebServer& w)
    {
        w.get_mining_interface()->set_rest_override_fn(
            [this](const std::string& path) -> std::optional<nlohmann::json> {
                if (path != "/block") return std::nullopt;
                std::unique_lock<std::mutex> lk(m_);
                entered_ = true;
                ++entries_;
                cv_.notify_all();
                cv_.wait_for(lk, 15s, [this] { return released_; });
                return nlohmann::json{{"blocked", true}};
            });
    }
    bool wait_entered(std::chrono::milliseconds limit = 3000ms)
    {
        std::unique_lock<std::mutex> lk(m_);
        return cv_.wait_for(lk, limit, [this] { return entered_; });
    }
    void release()
    {
        std::lock_guard<std::mutex> lk(m_);
        released_ = true;
        cv_.notify_all();
    }
    // Times the route was entered.
    int entries()
    {
        std::lock_guard<std::mutex> lk(m_);
        return entries_;
    }

private:
    std::mutex m_;
    std::condition_variable cv_;
    bool entered_ = false;
    bool released_ = false;
    int entries_ = 0;
};

// A pair of connected loopback sockets on `io`: {client, server}.
std::pair<tcp::socket, tcp::socket> socket_pair(net::io_context& io, tcp::acceptor& acc)
{
    tcp::socket c(io), sv(io);
    c.connect(acc.local_endpoint());
    acc.accept(sv);
    return {std::move(c), std::move(sv)};
}

// Each pair still carries one byte each way (a shut-down end reads EOF).
// broken: how many do not.
bool pairs_carry_bytes(std::vector<std::pair<tcp::socket, tcp::socket>>& pairs, int& broken)
{
    broken = 0;
    for (auto& [c, sv] : pairs) {
        boost::system::error_code ec;
        char ch = 0;
        net::write(c, net::buffer(std::string("p")), ec);
        if (!ec) sv.read_some(net::buffer(&ch, 1), ec);
        if (!ec) net::write(sv, net::buffer(std::string("q")), ec);
        if (!ec) c.read_some(net::buffer(&ch, 1), ec);
        if (ec) ++broken;
    }
    return broken == 0;
}

// open_sockets_on_port(port) every 10 ms on its own thread, until stop():
// the most seen at once, how many samples were taken, and the longest time
// between two samples.
class FdSampler {
public:
    explicit FdSampler(uint16_t port)
        : port_(port), th_([this] {
              auto last = clock_type::now();
              while (!stop_) {
                  const std::size_t n = open_sockets_on_port(port_);
                  std::size_t m = max_.load();
                  while (n > m && !max_.compare_exchange_weak(m, n)) {}
                  ++samples_;
                  const auto now = clock_type::now();
                  const auto gap = std::chrono::duration_cast<std::chrono::milliseconds>(now - last).count();
                  int64_t g = max_gap_ms_.load();
                  while (gap > g && !max_gap_ms_.compare_exchange_weak(g, gap)) {}
                  last = now;
                  std::this_thread::sleep_for(10ms);
              }
          })
    {
    }
    ~FdSampler() { stop(); }
    void stop()
    {
        stop_ = true;
        if (th_.joinable()) th_.join();
    }
    std::size_t max() const { return max_.load(); }
    uint64_t samples() const { return samples_.load(); }
    std::chrono::milliseconds max_gap() const { return std::chrono::milliseconds(max_gap_ms_.load()); }

private:
    uint16_t port_;
    std::atomic<bool> stop_{false};
    std::atomic<std::size_t> max_{0};
    std::atomic<uint64_t> samples_{0};
    std::atomic<int64_t> max_gap_ms_{0};
    std::thread th_;
};

const std::string kBusyBody = R"({"error":"busy, try again later"})";
const std::string kNotServedBody = R"({"error":"the web API is not served on this node"})";

// A 503 with the busy body (HEAD: the head, Content-Length of the busy body).
bool is_busy_503(const Response& r)
{
    return r.ok && r.status == 503
        && (r.body == kBusyBody
            || (r.body.empty() && r.header("content-length") == std::to_string(kBusyBody.size())));
}
// A 503 with the not-served body (HEAD likewise).
bool is_not_served_503(const Response& r)
{
    return r.ok && r.status == 503
        && (r.body == kNotServedBody
            || (r.body.empty() && r.header("content-length") == std::to_string(kNotServedBody.size())));
}

}  // namespace

TEST(StratumHttpHandOffShutdown, AtTheHandOffBoundTheConnectionIsShutDownWhileTheHttpThreadIsBlocked)
{
#ifndef __linux__
    GTEST_SKIP() << "counts descriptors through /proc";
#endif
    // Cap 2 (hand-off budget 1), hand-off bound 1 s. The HTTP thread is held
    // by a web route; one stratum-port HTTP request holds a slot. The
    // server-side descriptors on the stratum port are sampled every 10 ms
    // throughout, with no gap of 250 ms or more.
    core::stratum::StratumConfig cfg;
    cfg.handshake_timeout_sec = 1;
    cfg.max_stratum_connections = 2;
    HttpThreadHook hook;
    SplitNode node;
    ASSERT_TRUE(node.start(true, StratumHttpMode::On, cfg, "127.0.0.1", "127.0.0.1",
                           [&](core::WebServer& w) { hook.install(w); }));
    auto& ss = *node.stratum;
    auto blocked = std::async(std::launch::async, [&] {
        return exchange("127.0.0.1", node.web->bound_port(), request("GET", "/block"), {}, 20000ms).status;
    });
    ASSERT_TRUE(hook.wait_entered());
    const auto t0 = clock_type::now();
    RawClient h;
    ASSERT_TRUE(h.connect("127.0.0.1", node.port));
    FdSampler sampler(node.port);
    h.send("GET /fee HTTP/1.1\r\n");
    ASSERT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 1; }));
    // At the bound the connection is shut down: the client reads its end,
    // while the HTTP thread is still held.
    const std::string got = h.read_all(2500ms);
    const double closed_at = seconds_since(t0);
    EXPECT_TRUE(h.closed()) << "not shut down at the hand-off bound";
    EXPECT_TRUE(got.empty()) << got.substr(0, 60);
    EXPECT_GE(closed_at, 0.95);
    EXPECT_LT(closed_at, 1.6);
    // Past the bound with the HTTP thread held: the slot is still counted and
    // its descriptor still open (one sample here, and the sampler's samples
    // from the bound to the release).
    const uint64_t samples_at_bound = sampler.samples();
    EXPECT_EQ(blocked.wait_for(0s), std::future_status::timeout);
    EXPECT_EQ(ss.get_http_connection_count(), 1u);
    EXPECT_EQ(open_sockets_on_port(node.port), 1u);
    std::this_thread::sleep_for(100ms);
    EXPECT_EQ(blocked.wait_for(0s), std::future_status::timeout);
    EXPECT_GT(sampler.samples(), samples_at_bound) << "no sample while held past the bound";
    // The HTTP thread runs: the slot is released at once, and a miner is
    // admitted at the cap.
    hook.release();
    EXPECT_EQ(blocked.get(), 200u);
    EXPECT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 0; }, 1000ms));
    RawClient miner;
    ASSERT_TRUE(miner.connect("127.0.0.1", node.port));
    miner.send(std::string(kSubscribe) + "\n");
    EXPECT_TRUE(subscribed(miner));
    sampler.stop();
    EXPECT_LE(sampler.max(), cfg.max_stratum_connections);
    EXPECT_LT(sampler.max_gap(), 250ms) << "a gap between descriptor samples";
    EXPECT_EQ(ss.get_refused_connections(), 0u);
}

TEST(StratumHttpHandOffShutdown, SlotsPastTheHandOffBoundWhileTheHttpThreadIsBusy)
{
#ifndef __linux__
    GTEST_SKIP() << "counts descriptors through /proc";
#endif
    // Cap 3 (hand-off budget 2), hand-off bound 1 s. A web route keeps the
    // HTTP thread busy for 3 s; two stratum-port HTTP requests are handed off.
    // At 1.6 s both connections are shut down and both slots still held; a
    // third request is answered 503 busy, and a miner is admitted while the
    // HTTP thread is still busy. Once it runs, both slots are released.
    core::stratum::StratumConfig cfg;
    cfg.handshake_timeout_sec = 1;
    cfg.max_stratum_connections = 3;
    SplitNode node;
    ASSERT_TRUE(node.start(true, StratumHttpMode::On, cfg, "127.0.0.1", "127.0.0.1",
                           [](core::WebServer& w) {
                               w.get_mining_interface()->set_rest_override_fn(
                                   [](const std::string& path) -> std::optional<nlohmann::json> {
                                       if (path != "/slow") return std::nullopt;
                                       std::this_thread::sleep_for(3s);
                                       return nlohmann::json{{"slow", true}};
                                   });
                           }));
    auto& ss = *node.stratum;
    auto busy = std::async(std::launch::async, [&] {
        return exchange("127.0.0.1", node.web->bound_port(), request("GET", "/slow"), {}, 8000ms).status;
    });
    std::this_thread::sleep_for(200ms);
    const auto t0 = clock_type::now();
    RawClient h1, h2;
    ASSERT_TRUE(h1.connect("127.0.0.1", node.port));
    ASSERT_TRUE(h2.connect("127.0.0.1", node.port));
    h1.send("GET /fee HTTP/1.1\r\n");
    h2.send("GET /fee HTTP/1.1\r\n");
    ASSERT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 2; }));
    std::this_thread::sleep_for(std::chrono::milliseconds(1600) - (clock_type::now() - t0));
    EXPECT_TRUE(h1.read_all(200ms).empty());
    EXPECT_TRUE(h1.closed()) << "not shut down at the hand-off bound";
    EXPECT_TRUE(h2.read_all(200ms).empty());
    EXPECT_TRUE(h2.closed()) << "not shut down at the hand-off bound";
    EXPECT_EQ(ss.get_http_connection_count(), 2u);
    EXPECT_LE(open_sockets_on_port(node.port), 2u);
    const auto third = exchange("127.0.0.1", node.port, request("GET", "/fee"), {}, 1000ms);
    EXPECT_TRUE(is_busy_503(third)) << "'" << third.raw.substr(0, 120) << "'";
    EXPECT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 2; }, 1000ms));
    RawClient miner;
    ASSERT_TRUE(miner.connect("127.0.0.1", node.port));
    miner.send(std::string(kSubscribe) + "\n");
    EXPECT_TRUE(subscribed(miner)) << "a miner refused while the hand-offs are held past the bound";
    EXPECT_EQ(ss.get_refused_connections(), 0u);
    EXPECT_EQ(busy.wait_for(0s), std::future_status::timeout) << "the HTTP thread was no longer busy";
    EXPECT_EQ(busy.get(), 200u);
    EXPECT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 0; }, 1000ms));
}

TEST(StratumHttpHandOffShutdown, AFireAfterTheHttpSideClosedIssuesNoShutdown)
{
    net::io_context io;
    tcp::acceptor acc(io, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
    auto [c1, s1] = socket_pair(io, acc);
    const auto fd = s1.native_handle();
    core::StratumHttpDeadlineShutdown shutdown(fd);
    // The HTTP side closes first.
    shutdown.mark_closed();
    s1.close();
    // A new connection; Linux gives it the lowest free descriptor number.
    auto [c2, s2] = socket_pair(io, acc);
    const bool same_number = c2.native_handle() == fd || s2.native_handle() == fd;
    // The timer fires late: nothing is shut down.
    EXPECT_FALSE(shutdown.fire());
    EXPECT_EQ(shutdown.shutdowns(), 0u);
    EXPECT_TRUE(shutdown.closed());
    // The new connection still carries bytes both ways.
    net::write(c2, net::buffer(std::string("ping")));
    std::string in(4, '\0');
    net::read(s2, net::buffer(in));
    EXPECT_EQ(in, "ping");
    net::write(s2, net::buffer(std::string("pong")));
    net::read(c2, net::buffer(in));
    EXPECT_EQ(in, "pong") << "same descriptor number: " << same_number;
}

TEST(StratumHttpHandOffShutdown, AFireOnAnOpenConnectionShutsItDownOnce)
{
    net::io_context io;
    tcp::acceptor acc(io, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
    auto [c, sv] = socket_pair(io, acc);
    core::StratumHttpDeadlineShutdown shutdown(sv.native_handle());
    int cancels = 0;
    shutdown.set_cancel([&] { ++cancels; });
    EXPECT_TRUE(shutdown.fire());
    EXPECT_EQ(shutdown.shutdowns(), 1u);
    // The peer reads its end.
    char ch = 0;
    boost::system::error_code ec;
    c.read_some(net::buffer(&ch, 1), ec);
    EXPECT_EQ(ec, net::error::eof);
    // Marked closed: the cancel runs once, a second fire issues nothing.
    shutdown.mark_closed();
    shutdown.mark_closed();
    EXPECT_EQ(cancels, 1);
    EXPECT_FALSE(shutdown.fire());
    EXPECT_EQ(shutdown.shutdowns(), 1u);
}

TEST(StratumHttpHandOffShutdown, AnAnsweredRequestLeavesOtherConnectionsOpenAtTheBound)
{
#ifndef __linux__
    GTEST_SKIP() << "takes the lowest free descriptor numbers";
#endif
    // Hand-off bound 1 s. A request is answered and its session ends; 16 new
    // connections take the lowest free descriptor numbers; past the bound each
    // still carries bytes both ways.
    core::stratum::StratumConfig cfg;
    cfg.handshake_timeout_sec = 1;
    SplitNode node;
    ASSERT_TRUE(node.start(true, StratumHttpMode::On, cfg));
    auto& ss = *node.stratum;
    net::io_context io;
    tcp::acceptor acc(io, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
    const auto t0 = clock_type::now();
    const auto r = exchange("127.0.0.1", node.port, request("GET", "/fee"));
    ASSERT_EQ(r.status, 200u);
    ASSERT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 0; }));
    std::vector<std::pair<tcp::socket, tcp::socket>> pairs;
    for (int i = 0; i < 16; ++i)
        pairs.push_back(socket_pair(io, acc));
    std::this_thread::sleep_until(t0 + 1500ms);
    int broken = 0;
    EXPECT_TRUE(pairs_carry_bytes(pairs, broken)) << broken << " other connection(s) shut down at the bound";
}

TEST(StratumHttpHandOffShutdown, AnAbandonedSessionLeavesOtherConnectionsOpenAtTheBound)
{
#ifndef __linux__
    GTEST_SKIP() << "takes the lowest free descriptor numbers";
#endif
    // Hand-off bound 1 s. The web server stops with a request open (its
    // session closes the socket and lives on in the stopped HTTP loop); 16
    // new connections take the lowest free descriptor numbers; past the bound
    // each still carries bytes both ways.
    core::stratum::StratumConfig cfg;
    cfg.handshake_timeout_sec = 1;
    SplitNode node;
    ASSERT_TRUE(node.start(true, StratumHttpMode::On, cfg));
    auto& ss = *node.stratum;
    net::io_context io;
    tcp::acceptor acc(io, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
    const auto t0 = clock_type::now();
    RawClient h;
    ASSERT_TRUE(h.connect("127.0.0.1", node.port));
    h.send("GET /fee HTTP/1.1\r\n");
    ASSERT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 1; }));
    node.web->stop();
    ASSERT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 0; }));
    std::vector<std::pair<tcp::socket, tcp::socket>> pairs;
    for (int i = 0; i < 16; ++i)
        pairs.push_back(socket_pair(io, acc));
    std::this_thread::sleep_until(t0 + 1500ms);
    int broken = 0;
    EXPECT_TRUE(pairs_carry_bytes(pairs, broken)) << broken << " other connection(s) shut down at the bound";
}

// ── Lifetime and accounting ─────────────────────────────────────────────────

TEST(StratumHttpLifetime, PipelinedStratumLinesInOneSegment)
{
    WebNode node;
    ASSERT_TRUE(node.start("0.0.0.0"));
    RawClient c;
    ASSERT_TRUE(c.connect("127.0.0.1", node.stratum_port));
    c.send(std::string(kSubscribe) + "\n"
           + R"({"id":7,"method":"mining.suggest_difficulty","params":[1]})" + "\n"
           + "GET /fee HTTP/1.1\r\n");   // a request line after the first line is stratum
    bool sub = false, sugg = false, invalid = false;
    for (int i = 0; i < 12; ++i) {
        auto line = c.read_line(1500ms);
        if (!line) break;
        const auto j = json::parse(*line, nullptr, false);
        if (!j.is_object()) continue;
        sub = sub || j.value("id", json()) == 1;
        sugg = sugg || j.value("id", json()) == 7;
        invalid = invalid || (j.contains("error") && j["error"].is_array() && j["error"].size() > 1
                              && j["error"][1] == "Invalid JSON");
    }
    EXPECT_TRUE(sub);
    EXPECT_TRUE(sugg);
    EXPECT_TRUE(invalid) << "a later HTTP-looking line must stay a stratum line";
    EXPECT_FALSE(c.closed());
}

TEST(StratumHttpLifetime, BodyBoundOnTheStratumPort)
{
    WebNode node;
    ASSERT_TRUE(node.start("0.0.0.0"));
    const auto small = exchange("127.0.0.1", node.stratum_port,
                                "GET /fee HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\n\r\nhello");
    ASSERT_TRUE(small.ok) << small.raw;
    EXPECT_EQ(small.status, 200u);
    const auto big = exchange("127.0.0.1", node.stratum_port,
                              "GET /fee HTTP/1.1\r\nHost: t\r\nContent-Length: 4097\r\n\r\n");
    ASSERT_TRUE(big.ok) << big.raw;
    EXPECT_EQ(big.status, 413u);
    std::string chunked = "GET /fee HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n";
    chunked += "1400\r\n" + std::string(0x1400, 'x') + "\r\n0\r\n\r\n";
    const auto ch = exchange("127.0.0.1", node.stratum_port, chunked);
    ASSERT_TRUE(ch.ok) << ch.raw.substr(0, 200);
    EXPECT_EQ(ch.status, 413u);
}

TEST(StratumHttpLifetime, LoopbackPeerRefusedOnEveryLocalOnlyRoute)
{
    WebNode node;
    ASSERT_TRUE(node.start("0.0.0.0"));
    const std::vector<std::string> targets = {
        "/control/mining/start", "/control/mining/ban?target=1.2.3.4",
        "/web/log", "/logs/export?scope=all&format=csv",
        "/api/config", "/api/config/schema",
        "/api/admin/pool/bans/list", "/api/admin/pool/bans/add?ip=1.2.3.4",
        "/api/admin/coin/peers/list", "/api/admin/coin/peer/add?host=1.2.3.4",
        "/api/tx-inject-status", "/api/tx-inject/ledger",
        "/mempool_entry?txid=" + std::string(64, 'a'), "/api/utxo/scan",
        "/api/explorer/getblockchaininfo", "/api/explorer/getblock?hash=00"};
    for (const auto& target : targets) {
        const auto web = exchange("127.0.0.1", node.web_port, request("GET", target));
        ASSERT_TRUE(web.ok) << target;
        EXPECT_NE(web.status, 403u) << "web port refused a direct local GET: " << target;
        for (const char* method : {"GET", "HEAD"})
            for (const char* extra : {"", "X-Forwarded-For: 127.0.0.1\r\n", "X-Real-IP: 127.0.0.1\r\n"}) {
                const auto st = exchange("127.0.0.1", node.stratum_port, request(method, target, extra));
                ASSERT_TRUE(st.ok) << method << " " << target << ": '" << st.raw << "'";
                EXPECT_EQ(st.status, 403u) << method << " " << target << " " << extra;
                if (std::string(method) == "HEAD") EXPECT_TRUE(st.body.empty()) << target;
            }
    }
}

TEST(StratumHttpLifetime, SlotReleasedOnEveryErrorPath)
{
    core::stratum::StratumConfig cfg;
    cfg.handshake_timeout_sec = 3;
    SplitNode node;
    ASSERT_TRUE(node.start(true, StratumHttpMode::On, cfg));
    auto& ss = *node.stratum;
    {   // request line, then the client resets
        RawClient c;
        ASSERT_TRUE(c.connect("127.0.0.1", node.port));
        c.send("GET /fee HTTP/1.1\r\n");
        ASSERT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 1; }));
        c.close();
    }
    EXPECT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 0; }, 6000ms));
    EXPECT_FALSE(exchange("127.0.0.1", node.port, "GET /fee HTTP/1.1\r\nBad Header\r\n\r\n").ok);
    EXPECT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 0; }));
    // A header over beast's 8 KiB bound (the first line fits the 16 KiB stratum line).
    EXPECT_FALSE(exchange("127.0.0.1", node.port,
                          "GET /" + std::string(12000, 'a') + " HTTP/1.1\r\nHost: t\r\n\r\n").ok);
    EXPECT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 0; }));
    {   // a first line over 16 KiB: the stratum oversized-line drop, never HTTP
        const auto before = ss.get_http_requests();
        EXPECT_FALSE(exchange("127.0.0.1", node.port,
                              "GET /" + std::string(20000, 'a') + " HTTP/1.1\r\nHost: t\r\n\r\n").ok);
        EXPECT_EQ(ss.get_http_requests(), before);
    }
    {   // answered, but the client never reads, then leaves
        RawClient c;
        ASSERT_TRUE(c.connect("127.0.0.1", node.port));
        c.send(request("GET", "/global_stats"));
        std::this_thread::sleep_for(300ms);
        c.close();
    }
    EXPECT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 0; }));
    {   // never completes the header: closed at the handshake deadline
        RawClient c;
        ASSERT_TRUE(c.connect("127.0.0.1", node.port));
        c.send("GET /fee HTTP/1.1\r\nHost: t\r\n");
        ASSERT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 1; }));
        const auto got = c.read_all(6000ms);
        EXPECT_TRUE(c.closed());
        EXPECT_TRUE(got.empty()) << got;
    }
    EXPECT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 0; }));
    // The oversized-line session is closed but pruned lazily (notify_all).
    EXPECT_EQ(node.on_io([&] { ss.notify_all(); return ss.get_session_count(); }), 0u);
}

TEST(StratumHttpLifetime, StratumServerDestroyedMidRequest)
{
    SplitNode node;
    ASSERT_TRUE(node.start(true, StratumHttpMode::On));
    RawClient c;
    ASSERT_TRUE(c.connect("127.0.0.1", node.port));
    c.send("GET /fee HTTP/1.1\r\n");
    ASSERT_TRUE(wait_until([&] { return node.stratum->get_http_connection_count() == 1; }));
    node.stop_and_destroy_stratum();
    c.send("Host: t\r\n\r\n");
    const auto r = parse_response(c.read_all());
    ASSERT_TRUE(r.ok) << r.raw;
    EXPECT_EQ(r.status, 200u);
}

TEST(StratumHttpLifetime, WebServerStopReleasesInFlightSlots)
{
    SplitNode node;
    ASSERT_TRUE(node.start(true, StratumHttpMode::On));
    auto& ss = *node.stratum;
    RawClient c;
    ASSERT_TRUE(c.connect("127.0.0.1", node.port));
    c.send("GET /fee HTTP/1.1\r\n");
    ASSERT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 1; }));
    node.web->stop();
    // Stopped, not destroyed: the slot and the connection go at once.
    EXPECT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 0; }, 2000ms));
    c.read_all(2000ms);
    EXPECT_TRUE(c.closed());
    // A new HTTP request gets the 503.
    const auto r = exchange("127.0.0.1", node.port, request("GET", "/fee"));
    ASSERT_TRUE(r.ok) << r.raw;
    EXPECT_EQ(r.status, 503u);
    node.web.reset();
    EXPECT_EQ(exchange("127.0.0.1", node.port, request("GET", "/fee")).status, 503u);
}

TEST(StratumHttpLifetime, ConcurrentRequestsRacingWebStop)
{
    for (int round = 0; round < 3; ++round) {
        core::stratum::StratumConfig cfg;
        cfg.max_stratum_connections = 64;
        cfg.handshake_timeout_sec = 5;
        SplitNode node;
        node.limits = {16, 8};   // one share per client thread
        ASSERT_TRUE(node.start(true, StratumHttpMode::On, cfg));
        auto& ss = *node.stratum;
        std::atomic<bool> go{true};
        std::atomic<int> answered{0}, unavailable{0};
        std::vector<std::thread> clients;
        for (int t = 0; t < 8; ++t)
            clients.emplace_back([&, t] {
                while (go.load()) {
                    const auto r = exchange("127.0.0.1", node.port,
                                            t % 2 ? request("HEAD", "/fee") : request("GET", "/global_stats"),
                                            {}, 3000ms);
                    if (r.ok && r.status == 200) ++answered;
                    else if (is_not_served_503(r)) ++unavailable;   // the declined hand-off
                }
            });
        std::this_thread::sleep_for(std::chrono::milliseconds(150 + 40 * round));
        node.web->stop();
        std::this_thread::sleep_for(200ms);
        node.web.reset();
        std::this_thread::sleep_for(200ms);
        go = false;
        for (auto& th : clients) th.join();
        EXPECT_GT(answered.load(), 0) << round;
        EXPECT_GT(unavailable.load(), 0) << round;
        EXPECT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 0; })) << round;
        EXPECT_TRUE(wait_until([&] { return node.on_io([&] { return ss.get_session_count(); }) == 0; })) << round;
    }
}

TEST(StratumHttpLifetime, BurstOverTheCapDoesNotLeakSlots)
{
    // Cap 17, hand-off budget 16, share 16. 16 open HTTP requests hold the
    // budget; each of a burst of 48 x 2 is refused at the accept or answered
    // 503 busy, never 200.
    core::stratum::StratumConfig cfg;
    cfg.max_stratum_connections = 17;
    cfg.handshake_timeout_sec = 5;
    SplitNode node;
    node.limits = {16, 16};
    ASSERT_TRUE(node.start(true, StratumHttpMode::On, cfg));
    auto& ss = *node.stratum;
    {
        std::vector<std::unique_ptr<RawClient>> holders;
        for (int i = 0; i < 16; ++i) {
            holders.push_back(std::make_unique<RawClient>());
            ASSERT_TRUE(holders.back()->connect("127.0.0.1", node.port));
            holders.back()->send("GET /fee HTTP/1.1\r\n");
        }
        ASSERT_TRUE(wait_until([&] { return ss.get_http_handoffs() == 16; }));
        const uint64_t refused_before = ss.get_refused_connections();
        std::vector<std::thread> clients;
        std::atomic<int> answered{0}, busy{0};
        for (int t = 0; t < 48; ++t)
            clients.emplace_back([&] {
                for (int i = 0; i < 2; ++i) {
                    const auto r = exchange("127.0.0.1", node.port, request("GET", "/fee"), {}, 3000ms);
                    if (r.ok && r.status == 200) ++answered;
                    else if (is_busy_503(r)) ++busy;
                }
            });
        for (auto& th : clients) th.join();
        EXPECT_EQ(answered.load(), 0);
        EXPECT_EQ(ss.get_refused_connections() - refused_before + static_cast<uint64_t>(busy.load()), 96u);
        EXPECT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 16; }, 2000ms));
        EXPECT_EQ(ss.get_http_handoffs(), 16u);
    }
    ASSERT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 0; }));
    // Then 48 x 10 with no holder.
    std::vector<std::thread> clients;
    std::atomic<int> ok{0};
    for (int t = 0; t < 48; ++t)
        clients.emplace_back([&] {
            for (int i = 0; i < 10; ++i) {
                const auto r = exchange("127.0.0.1", node.port, request("GET", "/fee"), {}, 3000ms);
                if (r.ok && r.status == 200) ++ok;
            }
        });
    for (auto& th : clients) th.join();
    EXPECT_GT(ok.load(), 0);
    ASSERT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 0; }));
    RawClient miner;
    ASSERT_TRUE(miner.connect("127.0.0.1", node.port));
    miner.send(std::string(kSubscribe) + "\n");
    EXPECT_TRUE(subscribed(miner));
}

// ── The hand-off budget ─────────────────────────────────────────────────────

namespace {

// Calls `on` with the message of every log record written while it lives, on
// the thread that writes the record.
class LogHook {
public:
    explicit LogHook(std::function<void(const std::string&)> on)
    {
        sink_ = boost::make_shared<Sink>(boost::make_shared<Backend>(std::move(on)));
        sink_->set_formatter(boost::log::expressions::stream << boost::log::expressions::smessage);
        boost::log::core::get()->add_sink(sink_);
    }
    ~LogHook() { boost::log::core::get()->remove_sink(sink_); }

private:
    struct Backend
        : boost::log::sinks::basic_formatted_sink_backend<char, boost::log::sinks::synchronized_feeding> {
        explicit Backend(std::function<void(const std::string&)> on) : on_(std::move(on)) {}
        void consume(const boost::log::record_view&, const string_type& message) { on_(message); }
        std::function<void(const std::string&)> on_;
    };
    using Sink = boost::log::sinks::synchronous_sink<Backend>;
    boost::shared_ptr<Sink> sink_;
};

// A SplitNode with the HTTP thread hook installed (/block), a connection cap,
// hand-off limits and a handshake deadline.
bool start_budget_node(SplitNode& node, HttpThreadHook& hook, std::size_t cap,
                       core::StratumHttpLimits limits, uint32_t handshake_s = 30)
{
    core::stratum::StratumConfig cfg;
    cfg.max_stratum_connections = cap;
    cfg.handshake_timeout_sec = handshake_s;
    node.limits = limits;
    return node.start(true, StratumHttpMode::On, cfg, "127.0.0.1", "127.0.0.1",
                      [&](core::WebServer& w) { hook.install(w); });
}

// The HTTP thread held in /block (a web-port request) until hook.release().
std::future<unsigned> hold_http_thread(SplitNode& node)
{
    const uint16_t web_port = node.web->bound_port();
    return std::async(std::launch::async, [web_port] {
        return exchange("127.0.0.1", web_port, request("GET", "/block"), {}, 40000ms).status;
    });
}

// A stratum-port GET /fee from `from` (empty: any local address), left open.
std::unique_ptr<RawClient> open_request(SplitNode& node, const std::string& from = {})
{
    auto c = std::make_unique<RawClient>();
    if (!c->connect("127.0.0.1", node.port, from))
        return nullptr;
    c->send(request("GET", "/fee"));
    return c;
}

bool miner_subscribes(SplitNode& node, RawClient& m)
{
    if (!m.connect("127.0.0.1", node.port))
        return false;
    m.send(std::string(kSubscribe) + "\n");
    return subscribed(m);
}

}  // namespace

TEST(StratumHttpBudget, EffectiveBudgetTable)
{
    using core::stratum_http_budget;
    struct Row { std::size_t cap, budget, handoffs; };
    for (const Row& r : {Row{0, 16, 16}, Row{1, 16, 0}, Row{2, 16, 1}, Row{17, 16, 16},
                         Row{100, 16, 16}, Row{0, 0, 0}, Row{100, 0, 0}})
        EXPECT_EQ(stratum_http_budget(r.cap, r.budget, 6).handoffs, r.handoffs)
            << "cap " << r.cap << ", budget " << r.budget;
    // per_key = min(per_ip, handoffs); per_ip 0 gives handoffs.
    EXPECT_EQ(stratum_http_budget(4, 16, 6).per_key, 3u);     // handoffs 3, per_ip 6
    EXPECT_EQ(stratum_http_budget(0, 16, 0).per_key, 16u);    // handoffs 16, per_ip 0
    EXPECT_EQ(stratum_http_budget(100, 16, 6).per_key, 6u);
    EXPECT_EQ(stratum_http_budget(100, 0, 0).per_key, 0u);
}

TEST(StratumHttpBudget, MinersAreAdmittedBesideAFullHandOffBudget)
{
    // Cap 4, budget 2, the HTTP thread held: two requests are handed off, a
    // third is answered 503 busy; two miners take the other two slots, and a
    // third miner is refused.
    HttpThreadHook hook;
    SplitNode node;
    ASSERT_TRUE(start_budget_node(node, hook, 4, {2, 6}));
    auto& ss = *node.stratum;
    auto blocked = hold_http_thread(node);
    ASSERT_TRUE(hook.wait_entered());
    auto h1 = open_request(node), h2 = open_request(node);
    ASSERT_TRUE(h1 && h2);
    ASSERT_TRUE(wait_until([&] { return ss.get_http_handoffs() == 2; }));
    const auto t = clock_type::now();
    const auto over = exchange("127.0.0.1", node.port, request("GET", "/fee"), {}, 1500ms);
    EXPECT_TRUE(is_busy_503(over)) << "'" << over.raw.substr(0, 120) << "'";
    EXPECT_LT(seconds_since(t), 1.0);
    ASSERT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 2; }, 1000ms));
    RawClient m1, m2, m3;
    EXPECT_TRUE(miner_subscribes(node, m1));
    EXPECT_TRUE(miner_subscribes(node, m2));
    EXPECT_EQ(ss.get_refused_connections(), 0u);
    EXPECT_FALSE(miner_subscribes(node, m3));
    EXPECT_EQ(ss.get_refused_connections(), 1u);
    hook.release();
    EXPECT_EQ(blocked.get(), 200u);
}

TEST(StratumHttpBudget, TheBudgetLeavesOneSlotForMiners)
{
    // Budget 16 at caps 2 and 3: cap - 1 requests are handed off and held,
    // the cap-th is answered 503 busy, and then a miner is admitted.
    for (std::size_t cap : {std::size_t{2}, std::size_t{3}}) {
        HttpThreadHook hook;
        SplitNode node;
        ASSERT_TRUE(start_budget_node(node, hook, cap, {16, 6})) << cap;
        auto& ss = *node.stratum;
        auto blocked = hold_http_thread(node);
        ASSERT_TRUE(hook.wait_entered()) << cap;
        std::vector<std::unique_ptr<RawClient>> held;
        for (std::size_t i = 0; i + 1 < cap; ++i) {
            held.push_back(open_request(node));
            ASSERT_TRUE(held.back()) << cap;
        }
        ASSERT_TRUE(wait_until([&] { return ss.get_http_handoffs() == cap - 1; })) << cap;
        const auto last = exchange("127.0.0.1", node.port, request("GET", "/fee"), {}, 1500ms);
        EXPECT_TRUE(is_busy_503(last)) << cap << ": '" << last.raw.substr(0, 120) << "'";
        EXPECT_TRUE(wait_until([&] { return ss.get_http_connection_count() == cap - 1; }, 1000ms)) << cap;
        RawClient miner;
        EXPECT_TRUE(miner_subscribes(node, miner)) << cap;
        EXPECT_EQ(ss.get_refused_connections(), 0u) << cap;
        hook.release();
        EXPECT_EQ(blocked.get(), 200u) << cap;
    }
}

TEST(StratumHttpBudget, OverflowIsAnswered503AndFreesItsSlotWhileTheHttpThreadIsHeld)
{
    // Cap 10, budget 2, share 6 (all clients are 127.0.0.1), the HTTP thread
    // held: the overflow request is answered 503 busy within 1 s and its slot
    // is free again within 1 s, both while the HTTP thread is held.
    HttpThreadHook hook;
    SplitNode node;
    ASSERT_TRUE(start_budget_node(node, hook, 10, {2, 6}));
    auto& ss = *node.stratum;
    auto blocked = hold_http_thread(node);
    ASSERT_TRUE(hook.wait_entered());
    auto h1 = open_request(node), h2 = open_request(node);
    ASSERT_TRUE(h1 && h2);
    ASSERT_TRUE(wait_until([&] { return ss.get_http_handoffs() == 2; }));
    const auto t = clock_type::now();
    const auto over = exchange("127.0.0.1", node.port, request("GET", "/fee"), {}, 1500ms);
    EXPECT_TRUE(is_busy_503(over)) << "'" << over.raw.substr(0, 120) << "'";
    EXPECT_LT(seconds_since(t), 1.0);
    const auto t2 = clock_type::now();
    EXPECT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 2; }, 1000ms));
    EXPECT_LT(seconds_since(t2), 1.0);
    EXPECT_EQ(blocked.wait_for(0s), std::future_status::timeout);
    EXPECT_EQ(hook.entries(), 1);
    hook.release();
    EXPECT_EQ(blocked.get(), 200u);
}

TEST(StratumHttpBudget, AnOverflow503HoldsItsSlotUntilItsWriteCompletes)
{
    // Cap 10, budget 1, the HTTP thread held, one hand-off. The stratum io
    // thread is held from the moment the overflow request's 503 is logged
    // (its write is started next, its completion runs after the hold): the
    // 503 connection holds a stratum slot until then, and releases it once.
    std::mutex m;
    std::condition_variable cv;
    bool posted = false, holding = false, released = false;
    HttpThreadHook hook;
    SplitNode node;
    ASSERT_TRUE(start_budget_node(node, hook, 10, {1, 6}));
    auto& ss = *node.stratum;
    auto blocked = hold_http_thread(node);
    ASSERT_TRUE(hook.wait_entered());
    auto h1 = open_request(node);
    ASSERT_TRUE(h1);
    ASSERT_TRUE(wait_until([&] { return ss.get_http_handoffs() == 1 && ss.get_http_connection_count() == 1; }));
    {
        LogHook log_hook([&](const std::string& line) {
            if (line.find("HTTP request on stratum port") == std::string::npos
                || line.find("-> 503") == std::string::npos)
                return;
            std::lock_guard<std::mutex> lk(m);
            if (posted)
                return;
            posted = true;
            net::post(node.ioc, [&] {
                std::unique_lock<std::mutex> lk2(m);
                holding = true;
                cv.notify_all();
                cv.wait_for(lk2, 10s, [&] { return released; });
            });
        });
        RawClient over;
        ASSERT_TRUE(over.connect("127.0.0.1", node.port));
        over.send(request("GET", "/fee"));
        {
            std::unique_lock<std::mutex> lk(m);
            ASSERT_TRUE(cv.wait_for(lk, 3s, [&] { return holding; })) << "no 503 logged";
        }
        // The 503's write is started and its completion not yet run: the
        // hand-off's slot and the 503's slot.
        EXPECT_EQ(ss.get_http_connection_count(), 2u);
        EXPECT_EQ(ss.get_http_handoffs(), 1u);
        {
            std::lock_guard<std::mutex> lk(m);
            released = true;
            cv.notify_all();
        }
        EXPECT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 1; }, 1000ms));
        std::this_thread::sleep_for(200ms);
        EXPECT_EQ(ss.get_http_connection_count(), 1u);
        EXPECT_EQ(ss.get_http_handoffs(), 1u);
        const auto r = parse_response(over.read_all(2000ms));
        EXPECT_TRUE(is_busy_503(r)) << "'" << r.raw.substr(0, 120) << "'";
    }
    hook.release();
    EXPECT_EQ(blocked.get(), 200u);
}

TEST(StratumHttpBudget, RepeatedOverflowAtTheCap)
{
    // Cap 3 (budget 2), two hand-offs held: 50 requests in a row are each
    // answered 503 busy, the slot count is back to 2, and a miner is admitted.
    HttpThreadHook hook;
    SplitNode node;
    ASSERT_TRUE(start_budget_node(node, hook, 3, {16, 6}));
    auto& ss = *node.stratum;
    auto blocked = hold_http_thread(node);
    ASSERT_TRUE(hook.wait_entered());
    auto h1 = open_request(node), h2 = open_request(node);
    ASSERT_TRUE(h1 && h2);
    ASSERT_TRUE(wait_until([&] { return ss.get_http_handoffs() == 2; }));
    int busy = 0;
    for (int i = 0; i < 50; ++i) {
        const auto r = exchange("127.0.0.1", node.port, request("GET", "/fee"), {}, 1500ms);
        if (is_busy_503(r)) ++busy;
    }
    EXPECT_EQ(busy, 50);
    EXPECT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 2; }, 1000ms));
    EXPECT_EQ(ss.get_http_handoffs(), 2u);
    RawClient miner;
    EXPECT_TRUE(miner_subscribes(node, miner));
    hook.release();
    EXPECT_EQ(blocked.get(), 200u);
}

TEST(StratumHttpBudget, DeclinedHandOffReturnsItsBudget)
{
    // Cap 4, budget 1. The handler declines the first hand-off (answered 503
    // not served) and serves the next: the budget is back after the decline.
    HttpThreadHook hook;
    SplitNode node;
    ASSERT_TRUE(start_budget_node(node, hook, 4, {1, 6}));
    auto& ss = *node.stratum;
    auto web_handler = node.web->stratum_http_handler();
    std::atomic<int> calls{0};
    ss.set_http(true,
                [&calls, web_handler](core::StratumHttpRequest& req) {
                    if (calls++ == 0) return false;
                    return web_handler(req);
                },
                {1, 6});
    const auto r1 = exchange("127.0.0.1", node.port, request("GET", "/fee"));
    EXPECT_TRUE(is_not_served_503(r1)) << "'" << r1.raw.substr(0, 120) << "'";
    EXPECT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 0 && ss.get_http_handoffs() == 0; },
                           1000ms));
    const auto r2 = exchange("127.0.0.1", node.port, request("GET", "/fee"));
    EXPECT_EQ(r2.status, 200u) << "'" << r2.raw.substr(0, 120) << "'";
    EXPECT_EQ(calls.load(), 2);
    EXPECT_EQ(ss.get_http_refused_budget(), 0u);
}

TEST(StratumHttpBudget, PerAddressShare)
{
#ifndef __linux__
    GTEST_SKIP() << "binds client sockets to 127.0.0.2 and 127.0.0.3";
#endif
    // Cap 20, budget 4, share 2, the HTTP thread held. From 127.0.0.1: two
    // hand-offs and a share 503. From .2: two hand-offs. From .3: a budget
    // 503. Once released, a .1 request is handed off again and no key is left.
    HttpThreadHook hook;
    SplitNode node;
    ASSERT_TRUE(start_budget_node(node, hook, 20, {4, 2}));
    auto& ss = *node.stratum;
    auto blocked = hold_http_thread(node);
    ASSERT_TRUE(hook.wait_entered());
    auto a1 = open_request(node, "127.0.0.1"), a2 = open_request(node, "127.0.0.1");
    ASSERT_TRUE(a1 && a2);
    ASSERT_TRUE(wait_until([&] { return ss.get_http_handoffs() == 2; }));
    const auto a3 = exchange("127.0.0.1", node.port, request("GET", "/fee"), "127.0.0.1", 1500ms);
    EXPECT_TRUE(is_busy_503(a3)) << "'" << a3.raw.substr(0, 120) << "'";
    auto b1 = open_request(node, "127.0.0.2");
    ASSERT_TRUE(b1) << "cannot bind 127.0.0.2";
    auto b2 = open_request(node, "127.0.0.2");
    ASSERT_TRUE(b2) << "cannot bind 127.0.0.2";
    ASSERT_TRUE(wait_until([&] { return ss.get_http_handoffs() == 4; }));
    RawClient probe3;
    ASSERT_TRUE(probe3.connect("127.0.0.1", node.port, "127.0.0.3")) << "cannot bind 127.0.0.3";
    probe3.send(request("GET", "/fee"));
    const auto c1 = parse_response(probe3.read_all(1500ms));
    EXPECT_TRUE(is_busy_503(c1)) << "'" << c1.raw.substr(0, 120) << "'";
    EXPECT_EQ(ss.get_http_refused_share(), 1u);
    EXPECT_EQ(ss.get_http_refused_budget(), 1u);
    EXPECT_EQ(ss.get_http_handoff_keys(), 2u);
    hook.release();
    EXPECT_EQ(blocked.get(), 200u);
    for (auto* c : {a1.get(), a2.get(), b1.get(), b2.get()})
        EXPECT_EQ(parse_response(c->read_all(3000ms)).status, 200u);
    EXPECT_TRUE(wait_until([&] { return ss.get_http_handoffs() == 0 && ss.get_http_connection_count() == 0; }));
    const auto again = exchange("127.0.0.1", node.port, request("GET", "/fee"), "127.0.0.1", 3000ms);
    EXPECT_EQ(again.status, 200u) << "'" << again.raw.substr(0, 120) << "'";
    EXPECT_TRUE(wait_until([&] { return ss.get_http_handoffs() == 0; }));
    EXPECT_EQ(ss.get_http_handoff_keys(), 0u);
    EXPECT_EQ(ss.get_http_handoffs_peak(), 4u);
}

TEST(StratumHttpBudget, ShareKeyIsTheIpv6Slash64)
{
    // Through try_acquire_http_handoff with raw addresses (cap 100, budget
    // 16, share 2): one IPv6 /64 is one share; another /64 is another; an
    // IPv4-mapped address and its IPv4 address are one share.
    net::io_context io;
    auto work = std::make_shared<core::MiningInterface>(false);
    core::StratumServer ss(io, "127.0.0.1", 0, work);
    const core::StratumHttpLimits limits{16, 2};
    using Refusal = core::StratumServer::HttpRefusal;
    std::vector<std::shared_ptr<void>> held;
    auto take = [&](const char* a) {
        auto r = ss.try_acquire_http_handoff(net::ip::make_address(a), 100, limits);
        if (r.slot) held.push_back(r.slot);
        return r.refusal;
    };
    EXPECT_EQ(take("2001:db8:1:2::1"), Refusal::None);
    EXPECT_EQ(take("2001:db8:1:2:aaaa:bbbb:cccc:2"), Refusal::None);
    EXPECT_EQ(take("2001:db8:1:2:ffff:ffff:ffff:ffff"), Refusal::Share);
    EXPECT_EQ(take("2001:db8:1:3::1"), Refusal::None);
    EXPECT_EQ(take("::ffff:192.0.2.1"), Refusal::None);
    EXPECT_EQ(take("192.0.2.1"), Refusal::None);
    EXPECT_EQ(take("::ffff:192.0.2.1"), Refusal::Share);
    EXPECT_EQ(take("192.0.2.1"), Refusal::Share);
    EXPECT_EQ(ss.get_http_handoffs(), 5u);
    EXPECT_EQ(ss.get_http_handoff_keys(), 3u);
    held.clear();
    EXPECT_EQ(ss.get_http_handoffs(), 0u);
    EXPECT_EQ(ss.get_http_handoff_keys(), 0u);
}

TEST(StratumHttpBudget, RefusalCountersAndBodies)
{
    // Budget 2, share 1, the HTTP thread held. One hand-off; a GET and a HEAD
    // over the share get the busy 503 (226 bytes; HEAD: the 193-byte head);
    // then budget 1: a GET gets the busy 503 counted as budget. Every request
    // is counted once.
    {
        HttpThreadHook hook;
        SplitNode node;
        ASSERT_TRUE(start_budget_node(node, hook, 10, {2, 1}));
        auto& ss = *node.stratum;
        auto blocked = hold_http_thread(node);
        ASSERT_TRUE(hook.wait_entered());
        auto h1 = open_request(node);
        ASSERT_TRUE(h1);
        ASSERT_TRUE(wait_until([&] { return ss.get_http_handoffs() == 1; }));
        const auto get = exchange("127.0.0.1", node.port, request("GET", "/fee"), {}, 1500ms);
        EXPECT_TRUE(is_busy_503(get));
        EXPECT_EQ(get.body, kBusyBody);
        EXPECT_EQ(get.raw.size(), 226u);
        EXPECT_EQ(ss.get_http_refused_share(), 1u);
        EXPECT_EQ(ss.get_http_refused_budget(), 0u);
        const auto head = exchange("127.0.0.1", node.port, request("HEAD", "/fee"), {}, 1500ms);
        EXPECT_TRUE(is_busy_503(head));
        EXPECT_TRUE(head.body.empty());
        EXPECT_EQ(head.raw.size(), 193u);
        EXPECT_EQ(ss.get_http_refused_share(), 2u);
        ss.set_http(true, node.web->stratum_http_handler(), {1, 6});
        const auto get2 = exchange("127.0.0.1", node.port, request("GET", "/fee"), {}, 1500ms);
        EXPECT_TRUE(is_busy_503(get2));
        EXPECT_EQ(ss.get_http_refused_budget(), 1u);
        EXPECT_EQ(ss.get_http_refused_share(), 2u);
        EXPECT_EQ(ss.get_http_requests(), 4u);
        hook.release();
        EXPECT_EQ(blocked.get(), 200u);
    }
    // No web server: the not-served 503 (243 bytes; HEAD: the head), nothing
    // counted as a refusal.
    {
        SplitNode node;
        ASSERT_TRUE(node.start(false, StratumHttpMode::On));
        auto& ss = *node.stratum;
        const auto get = exchange("127.0.0.1", node.port, request("GET", "/fee"));
        EXPECT_TRUE(is_not_served_503(get));
        EXPECT_EQ(get.body, kNotServedBody);
        EXPECT_EQ(get.raw.size(), 243u);
        const auto head = exchange("127.0.0.1", node.port, request("HEAD", "/fee"));
        EXPECT_TRUE(is_not_served_503(head));
        EXPECT_TRUE(head.body.empty());
        EXPECT_EQ(ss.get_http_refused_budget() + ss.get_http_refused_share(), 0u);
        EXPECT_EQ(ss.get_http_requests(), 2u);
    }
    // Budget 1 held, hand-off bound 1 s: a request whose first line is read
    // after its bound (the stratum io thread held from its accept to 1.3 s)
    // is closed with no answer and counts no refusal.
    {
        HttpThreadHook hook;
        SplitNode node;
        ASSERT_TRUE(start_budget_node(node, hook, 10, {1, 6}, 1));
        auto& ss = *node.stratum;
        auto blocked = hold_http_thread(node);
        ASSERT_TRUE(hook.wait_entered());
        auto h1 = open_request(node);
        ASSERT_TRUE(h1);
        ASSERT_TRUE(wait_until([&] { return ss.get_http_handoffs() == 1; }));
        RawClient late;
        const auto t0 = clock_type::now();
        ASSERT_TRUE(late.connect("127.0.0.1", node.port));
        ASSERT_TRUE(wait_until([&] { return node.on_io([&] { return ss.get_session_count(); }) == 1; }));
        std::atomic<bool> holding{false};
        net::post(node.ioc, [&holding, t0] {
            holding = true;
            std::this_thread::sleep_until(t0 + 1300ms);
        });
        ASSERT_TRUE(wait_until([&] { return holding.load(); }));
        late.send(request("GET", "/fee"));
        const std::string got = late.read_all(3000ms);
        EXPECT_TRUE(late.closed());
        EXPECT_TRUE(got.empty()) << got.substr(0, 80);
        EXPECT_EQ(ss.get_http_refused_budget(), 0u);
        EXPECT_EQ(ss.get_http_refused_share(), 0u);
        EXPECT_EQ(ss.get_http_requests(), 2u);
        hook.release();
        EXPECT_EQ(blocked.get(), 200u);
    }
}

TEST(StratumHttpBudget, CapOfOneAnswersEveryRequest503)
{
    // Cap 1: budget 0. A stratum-port GET /block is answered 503 busy and
    // never reaches the web server; a miner is admitted after.
    HttpThreadHook hook;
    SplitNode node;
    ASSERT_TRUE(start_budget_node(node, hook, 1, {16, 6}));
    auto& ss = *node.stratum;
    const auto r = exchange("127.0.0.1", node.port, request("GET", "/block"), {}, 1500ms);
    EXPECT_TRUE(is_busy_503(r)) << "'" << r.raw.substr(0, 120) << "'";
    EXPECT_EQ(hook.entries(), 0);
    EXPECT_TRUE(wait_until([&] { return ss.get_http_connection_count() == 0; }, 1000ms));
    RawClient miner;
    EXPECT_TRUE(miner_subscribes(node, miner));
    hook.release();
}

TEST(StratumHttpBudget, ZeroBudgetAndZeroShare)
{
    // Budget 0 (cap 100): a stratum-port GET /block is answered 503 busy and
    // never reaches the web server.
    {
        HttpThreadHook hook;
        SplitNode node;
        ASSERT_TRUE(start_budget_node(node, hook, 100, {0, 6}));
        auto& ss = *node.stratum;
        const auto r = exchange("127.0.0.1", node.port, request("GET", "/block"), {}, 1500ms);
        EXPECT_TRUE(is_busy_503(r)) << "'" << r.raw.substr(0, 120) << "'";
        EXPECT_EQ(hook.entries(), 0);
        EXPECT_EQ(ss.get_http_refused_budget(), 1u);
        hook.release();
    }
    // Share 0 (cap 10, budget 3), the HTTP thread held: one address gets
    // three hand-offs, and the fourth request a budget 503.
    {
        HttpThreadHook hook;
        SplitNode node;
        ASSERT_TRUE(start_budget_node(node, hook, 10, {3, 0}));
        auto& ss = *node.stratum;
        auto blocked = hold_http_thread(node);
        ASSERT_TRUE(hook.wait_entered());
        std::vector<std::unique_ptr<RawClient>> held;
        for (int i = 0; i < 3; ++i) {
            held.push_back(open_request(node));
            ASSERT_TRUE(held.back());
        }
        EXPECT_TRUE(wait_until([&] { return ss.get_http_handoffs() == 3; }));
        const auto r = exchange("127.0.0.1", node.port, request("GET", "/fee"), {}, 1500ms);
        EXPECT_TRUE(is_busy_503(r)) << "'" << r.raw.substr(0, 120) << "'";
        EXPECT_EQ(ss.get_http_refused_budget(), 1u);
        EXPECT_EQ(ss.get_http_refused_share(), 0u);
        hook.release();
        EXPECT_EQ(blocked.get(), 200u);
    }
}
