// SPDX-License-Identifier: AGPL-3.0-or-later
//
// HTTP on the stratum port, seen from the wire (core/stratum_http.hpp).
//
// python p2pool answered its web API on the worker (stratum) port, and
// p2pool-aware trackers poll it there: http://host:9327/global_stats on LTC.
// These tests run a real WebServer with its own stratum acceptor (the LTC
// lane's wiring) and talk raw TCP to both ports:
//
//   * a GET on the stratum port gets the web port's answer (same status, JSON
//     and headers, Connection: close); HEAD gets the headers and no body; a
//     request arriving in pieces is answered;
//   * the stratum port is read-only: POST / OPTIONS / PUT get 405 there, also
//     with a body too large to read;
//   * a remote peer gets the same refusal on every local-only route as on the
//     web port, and on the stratum port even a loopback peer is not local;
//   * the event stream answers 405 there (empty Allow);
//   * a stratum line, also split across TCP segments, and garbage take the
//     stratum path as before;
//   * a request whose headers never finish is closed at the stratum handshake
//     deadline, with nothing written to it.
//
// They use only web server API that predates the stratum-port change; auto
// (the default) is on for a web server bound to 0.0.0.0 or a LAN address.
// The mode, the caps, the session accounting, the write deadline and the 503
// path are covered by stratum_port_http_test.cpp.

#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

#include <core/web_server.hpp>
#include <impl/ltc/stratum_defaults.hpp>

#include "stratum_port_http_test_util.hpp"

using namespace stratum_http_test;
using json = nlohmann::json;

namespace {

// /global_stats carries uptime_seconds, which may tick between two requests.
json stats_without_uptime(const std::string& body)
{
    auto j = json::parse(body, nullptr, false);
    if (j.is_object()) j.erase("uptime_seconds");
    return j;
}

const char* kSubscribe = R"({"id":1,"method":"mining.subscribe","params":[]})";

}  // namespace

TEST(StratumPortHttpWire, GlobalStatsMatchesTheWebPort)
{
    WebNode node;
    ASSERT_TRUE(node.start("0.0.0.0"));

    const auto web = exchange("127.0.0.1", node.web_port, request("GET", "/global_stats"));
    const auto st  = exchange("127.0.0.1", node.stratum_port, request("GET", "/global_stats"));
    ASSERT_TRUE(web.ok) << web.raw;
    ASSERT_TRUE(st.ok) << "stratum port gave no HTTP response: '" << st.raw << "'";
    EXPECT_EQ(st.status, 200u);
    EXPECT_EQ(st.status, web.status);
    const auto j = stats_without_uptime(st.body);
    ASSERT_TRUE(j.is_object()) << st.body;
    EXPECT_EQ(j, stats_without_uptime(web.body));
    for (const char* h : {"content-type", "server", "x-content-type-options", "x-frame-options",
                          "referrer-policy", "connection"})
        EXPECT_EQ(st.header(h), web.header(h)) << h;
    EXPECT_EQ(st.header("connection"), "close");
    EXPECT_EQ(st.header("content-length"), std::to_string(st.body.size()));
}

TEST(StratumPortHttpWire, TrackerRoutesAnswerAsOnTheWebPort)
{
    WebNode node;
    ASSERT_TRUE(node.start("0.0.0.0"));
    for (const char* target : {"/fee", "/local_stats", "/current_payouts", "/users",
                               "/recent_blocks", "/web/version", "/web/currency_info",
                               "/p2pool_global_stats", "/no/such/route"}) {
        const auto web = exchange("127.0.0.1", node.web_port, request("GET", target));
        const auto st  = exchange("127.0.0.1", node.stratum_port, request("GET", target));
        ASSERT_TRUE(st.ok) << target << ": '" << st.raw << "'";
        EXPECT_EQ(st.status, web.status) << target;
        EXPECT_EQ(st.header("content-type"), web.header("content-type")) << target;
    }
    // A deterministic body is byte-identical.
    EXPECT_EQ(exchange("127.0.0.1", node.stratum_port, request("GET", "/fee")).body,
              exchange("127.0.0.1", node.web_port, request("GET", "/fee")).body);
}

TEST(StratumPortHttpWire, HeadGetsTheHeadersWithoutTheBody)
{
    WebNode node;
    ASSERT_TRUE(node.start("0.0.0.0"));
    const auto get  = exchange("127.0.0.1", node.stratum_port, request("GET", "/fee"));
    const auto head = exchange("127.0.0.1", node.stratum_port, request("HEAD", "/fee"));
    ASSERT_TRUE(get.ok) << get.raw;
    ASSERT_TRUE(head.ok) << "'" << head.raw << "'";
    EXPECT_EQ(head.status, 200u);
    EXPECT_TRUE(head.body.empty()) << "HEAD sent a body: " << head.body;
    EXPECT_EQ(head.header("content-length"), std::to_string(get.body.size()));
    EXPECT_EQ(head.header("content-type"), get.header("content-type"));
    EXPECT_EQ(head.header("connection"), "close");
}

TEST(StratumPortHttpWire, OnlyGetAndHeadAreServed)
{
    WebNode node;
    ASSERT_TRUE(node.start("0.0.0.0"));
    const std::string rpc = R"({"jsonrpc":"2.0","id":1,"method":"getinfo","params":[]})";

    // The web port answers JSON-RPC; the stratum port refuses every method but
    // GET and HEAD.
    const auto web_post = exchange("127.0.0.1", node.web_port, request("POST", "/", {}, rpc));
    ASSERT_TRUE(web_post.ok);
    EXPECT_NE(web_post.status, 405u);

    for (const auto& req : {request("POST", "/", {}, rpc),
                            request("POST", "/api/admin/pool/bans/add?ip=1.2.3.4", {}, "{}"),
                            request("POST", "/api/config/apply", {}, "{}"),
                            request("OPTIONS", "/global_stats"),
                            request("PUT", "/global_stats", "Content-Length: 0\r\n"),
                            request("DELETE", "/global_stats")}) {
        const auto st = exchange("127.0.0.1", node.stratum_port, req);
        ASSERT_TRUE(st.ok) << req << " -> '" << st.raw << "'";
        EXPECT_EQ(st.status, 405u) << req;
        EXPECT_EQ(st.header("allow"), "GET, HEAD") << req;
        EXPECT_EQ(st.header("connection"), "close") << req;
    }

    // A body over the stratum port's bound is not read: still a 405.
    const auto big = exchange("127.0.0.1", node.stratum_port,
                              "POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 100000\r\n\r\n");
    ASSERT_TRUE(big.ok) << "'" << big.raw << "'";
    EXPECT_EQ(big.status, 405u);
}

TEST(StratumPortHttpWire, RequestArrivingInPiecesIsAnswered)
{
    WebNode node;
    ASSERT_TRUE(node.start("0.0.0.0"));
    RawClient c;
    ASSERT_TRUE(c.connect("127.0.0.1", node.stratum_port));
    for (const char* piece : {"GE", "T /fee HTTP/1.1\r\nHo", "st: test\r\n", "Accept: */*\r\n", "\r\n"}) {
        c.send(piece);
        std::this_thread::sleep_for(60ms);
    }
    const auto r = parse_response(c.read_all());
    ASSERT_TRUE(r.ok) << "'" << r.raw << "'";
    EXPECT_EQ(r.status, 200u);
    EXPECT_TRUE(c.closed());
}

TEST(StratumPortHttpWire, StratumSubscribeOnTheSamePortStillWorks)
{
    WebNode node;
    ASSERT_TRUE(node.start("0.0.0.0"));

    auto subscribed = [](RawClient& c) {
        for (int i = 0; i < 10; ++i) {
            auto line = c.read_line();
            if (!line) return false;
            auto j = json::parse(*line, nullptr, false);
            if (j.is_object() && j.value("id", json()) == 1)
                return j["error"].is_null() && j["result"].is_array() && j["result"].size() == 3;
        }
        return false;
    };

    {   // whole line
        RawClient c;
        ASSERT_TRUE(c.connect("127.0.0.1", node.stratum_port));
        c.send(std::string(kSubscribe) + "\n");
        EXPECT_TRUE(subscribed(c));
    }
    {   // "{" then the rest, in a second TCP segment
        RawClient c;
        ASSERT_TRUE(c.connect("127.0.0.1", node.stratum_port));
        c.send("{");
        std::this_thread::sleep_for(150ms);
        c.send(std::string(kSubscribe).substr(1) + "\n");
        EXPECT_TRUE(subscribed(c));
    }
    {   // three pieces, the first line ending in \r\n
        RawClient c;
        ASSERT_TRUE(c.connect("127.0.0.1", node.stratum_port));
        const std::string line = std::string(kSubscribe) + "\r\n";
        c.send(line.substr(0, 7));
        std::this_thread::sleep_for(80ms);
        c.send(line.substr(7, 20));
        std::this_thread::sleep_for(80ms);
        c.send(line.substr(27));
        EXPECT_TRUE(subscribed(c));
    }
}

TEST(StratumPortHttpWire, GarbageIsAnInvalidStratumLineAsBefore)
{
    WebNode node;
    ASSERT_TRUE(node.start("0.0.0.0"));
    // Neither HTTP nor JSON; and request lines that are not HTTP/1.x.
    for (const char* first : {"hello there\n", "GET /\n", "get /global_stats HTTP/1.1\n",
                              "GET /global_stats HTTP/2.0\n", "BREW /pot HTTP/1.1\n"}) {
        RawClient c;
        ASSERT_TRUE(c.connect("127.0.0.1", node.stratum_port));
        c.send(first);
        auto line = c.read_line();
        ASSERT_TRUE(line) << first;
        auto j = json::parse(*line, nullptr, false);
        ASSERT_TRUE(j.is_object()) << first << " -> " << *line;
        EXPECT_TRUE(j["result"].is_null()) << first;
        ASSERT_TRUE(j["error"].is_array()) << first;
        EXPECT_EQ(j["error"][0], -2) << first;
        EXPECT_EQ(j["error"][1], "Invalid JSON") << first;
        // Still a stratum session: a subscribe on it is answered.
        c.send(std::string(kSubscribe) + "\n");
        auto reply = c.read_line();
        ASSERT_TRUE(reply) << first;
        EXPECT_EQ(json::parse(*reply, nullptr, false).value("id", json()), 1) << first;
    }
}

TEST(StratumPortHttpWire, LocalOnlyRoutesRefuseARemotePeerAsTheWebPortDoes)
{
    const std::vector<std::string> targets = {
        "/control/mining/stop", "/control/mining/ban?target=1.2.3.4",
        "/web/log", "/logs/export?scope=all&format=csv",
        "/api/config", "/api/config/schema",
        "/api/admin/pool/bans/list", "/api/admin/coin/peers/list",
        "/api/tx-inject-status", "/api/tx-inject/ledger",
        "/mempool_entry?txid=" + std::string(64, 'a'), "/api/utxo/scan"};

    // Always (no address needed): the web port's answer to a client that is
    // not direct local -- a loopback peer behind a proxy header, the branch
    // every remote client takes -- is the stratum port's answer to a peer
    // with no header at all.
    {
        WebNode node;
        ASSERT_TRUE(node.start("0.0.0.0"));
        for (const auto& target : targets) {
            const auto web = exchange("127.0.0.1", node.web_port,
                                      request("GET", target, "X-Forwarded-For: 203.0.113.7\r\n"));
            const auto st  = exchange("127.0.0.1", node.stratum_port, request("GET", target));
            ASSERT_TRUE(web.ok) << target;
            ASSERT_TRUE(st.ok) << target << ": '" << st.raw << "'";
            EXPECT_GE(web.status, 400u) << target;
            EXPECT_EQ(st.status, web.status) << target;
            EXPECT_EQ(st.body, web.body) << target;
        }
        // The explorer's own guard reads the peer address alone; the stratum
        // port refuses it whatever the address.
        const auto ex = exchange("127.0.0.1", node.stratum_port, request("GET", "/api/explorer/getblockchaininfo"));
        ASSERT_TRUE(ex.ok);
        EXPECT_EQ(ex.status, 403u);
    }

    // And with a real non-loopback peer, when this host has an address for it.
    const auto ip = non_loopback_local_ipv4();
    if (!ip)
        return;
    WebNode node;
    ASSERT_TRUE(node.start(*ip));   // a LAN address for both: auto turns HTTP on
    auto all = targets;
    all.push_back("/api/explorer/getblockchaininfo");
    const std::vector<std::string> extras = {"", "X-Forwarded-For: 127.0.0.1\r\n"};
    for (const auto& target : all) {
        for (const auto& extra : extras) {
            const auto web = exchange(*ip, node.web_port, request("GET", target, extra), *ip);
            const auto st  = exchange(*ip, node.stratum_port, request("GET", target, extra), *ip);
            ASSERT_TRUE(web.ok) << target;
            ASSERT_TRUE(st.ok) << target << ": '" << st.raw << "'";
            EXPECT_GE(web.status, 400u) << target;
            EXPECT_EQ(st.status, web.status) << target;
            EXPECT_EQ(st.body, web.body) << target;
        }
    }
}

TEST(StratumPortHttpWire, LoopbackPeerIsNotLocalOnTheStratumPort)
{
    WebNode node;
    ASSERT_TRUE(node.start("0.0.0.0"));
    // The web port lets a direct local request past the local-only gate (no
    // auth token configured: 200, or 404 where the feature is not wired); the
    // stratum port answers it as from a remote client.
    for (const char* target : {"/control/mining/unban?target=x", "/web/log", "/api/admin/pool/bans/list",
                               "/api/explorer/getblockchaininfo"}) {
        const auto web = exchange("127.0.0.1", node.web_port, request("GET", target));
        const auto st  = exchange("127.0.0.1", node.stratum_port, request("GET", target));
        ASSERT_TRUE(web.ok) << target;
        ASSERT_TRUE(st.ok) << target << ": '" << st.raw << "'";
        EXPECT_NE(web.status, 403u) << target;
        EXPECT_EQ(st.status, 403u) << target;
    }
    EXPECT_NE(exchange("127.0.0.1", node.stratum_port, request("GET", "/web/log")).body
                  .find("local-only"), std::string::npos);
}

TEST(StratumPortHttpWire, EventStreamIsRefusedOnTheStratumPort)
{
    WebNode node;
    ASSERT_TRUE(node.start("0.0.0.0"));
    for (const char* method : {"GET", "HEAD"}) {
        const auto st = exchange("127.0.0.1", node.stratum_port, request(method, "/sharechain/stream"),
                                 {}, 3000ms);
        ASSERT_TRUE(st.ok) << method << " '" << st.raw.substr(0, 120) << "'";
        EXPECT_EQ(st.status, 405u) << method;
        EXPECT_EQ(st.headers.count("allow"), 1u) << method;
        EXPECT_EQ(st.header("allow"), "") << method;
        EXPECT_EQ(st.header("connection"), "close") << method;
    }
}

TEST(StratumPortHttpWire, UnfinishedRequestIsClosedAtTheHandshakeDeadline)
{
    auto cfg = ltc::default_stratum_config();
    cfg.handshake_timeout_sec = 2;
    WebNode node;
    ASSERT_TRUE(node.start("0.0.0.0", [&](core::WebServer& w) {
        w.get_mining_interface()->set_stratum_config(cfg);
    }));

    // Headers that never end: a header line every 300 ms.
    {
        RawClient c;
        ASSERT_TRUE(c.connect("127.0.0.1", node.stratum_port));
        const auto t0 = std::chrono::steady_clock::now();
        c.send("GET /global_stats HTTP/1.1\r\n");
        std::string got;
        while (!c.closed() && std::chrono::steady_clock::now() - t0 < 8s) {
            c.send("X-Slow: 1\r\n");
            got += c.read_all(300ms);
        }
        const double s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        EXPECT_TRUE(c.closed());
        EXPECT_GT(s, 1.5);
        EXPECT_LT(s, 4.5);
        EXPECT_TRUE(got.empty()) << "answered an unfinished request: " << got;
    }
    // A request line that never ends (the stratum session's own deadline).
    {
        RawClient c;
        ASSERT_TRUE(c.connect("127.0.0.1", node.stratum_port));
        const auto t0 = std::chrono::steady_clock::now();
        c.send("GET /global_stats");
        std::string got;
        while (!c.closed() && std::chrono::steady_clock::now() - t0 < 8s) {
            c.send("x");
            got += c.read_all(300ms);
        }
        const double s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        EXPECT_TRUE(c.closed());
        EXPECT_LT(s, 4.5);
        EXPECT_TRUE(got.empty()) << got;
    }
}
