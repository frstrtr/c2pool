// SPDX-License-Identifier: AGPL-3.0-or-later
//
// #1985: miner and peer IPs are masked for web viewers that are not direct
// local.
//
// /stratum_stats showed every miner's "ip:port" (workers[*].remote_endpoint)
// and grouped them by bare IP (pool.ip_connections / pool.ip_workers keys) to
// any internet viewer. /peer_list, /pings, /peer_versions and
// /peer_txpool_sizes did the same for incoming sharechain peers, and
// /ban_stats for banned IPs. Now a viewer that is not
// core::is_direct_local_request() gets "h:" + 8 hex of HMAC-SHA256 with a
// per-process random key instead. The port is dropped, the JSON shape is
// unchanged, and a direct local viewer still sees the raw address.
// /peer_addresses drops incoming peers for a viewer that is not direct local
// instead of masking them (its entries are dial targets). This departs from
// p2pool on purpose, for non-local viewers only.
//
// The no-IP checks are scoped: the address-carrying fields must each be a
// token, and the whole-body IPv4 / IPv6 patterns are written so that the
// numeric fields of a real /stratum_stats body (hashrates, difficulties,
// timestamps, rates) never match them.
#include <gtest/gtest.h>

#include <chrono>
#include <regex>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <nlohmann/json.hpp>

#include <core/ip_mask.hpp>
#include <core/web_server.hpp>

namespace {

namespace net   = boost::asio;
namespace beast = boost::beast;
namespace http  = boost::beast::http;
using tcp = boost::asio::ip::tcp;
using core::MiningInterface;
using Headers = std::vector<std::pair<std::string, std::string>>;

const Headers kProxied{{"X-Forwarded-For", "198.18.0.1"}};

const std::regex kToken("^h:[0-9a-f]{8}$");
// A dotted quad not part of a longer number ("1.5e9" and "0.25" never match).
const std::regex kIpv4("(^|[^0-9.])([0-9]{1,3}\\.){3}[0-9]{1,3}($|[^0-9.])");
// Two colons with only hex digits between them ("2001:db8::5"). In a JSON
// dump every key/value colon is next to a quote, so JSON syntax never matches.
const std::regex kIpv6("[0-9A-Fa-f]*:[0-9A-Fa-f]*:");

bool is_token(const std::string& s) { return std::regex_match(s, kToken); }

std::string fetch(uint16_t port, const std::string& target, const Headers& headers = {})
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
    return res.body();
}

MiningInterface::WorkerInfo worker(const std::string& name, const std::string& endpoint)
{
    MiningInterface::WorkerInfo w;
    w.username = "LTCpayoutAddr";
    w.worker_name = name;
    w.remote_endpoint = endpoint;
    w.connected_at = std::chrono::steady_clock::now() - std::chrono::seconds(60);
    w.hashrate = 1.5e9;
    w.difficulty = 0.25;
    return w;
}

void register_miners(MiningInterface* mi)
{
    mi->register_stratum_worker("s1", worker("rig1", "203.0.113.7:4321"));
    mi->register_stratum_worker("s2", worker("rig2", "203.0.113.7:4999"));
    mi->register_stratum_worker("s3", worker("rig3", "[2001:db8::5]:3333"));
}

nlohmann::json peers()
{
    return nlohmann::json::array({
        {{"address", "198.51.100.9:40312"}, {"incoming", true}, {"version", "c2pool"},
         {"ping_ms", 12.0}, {"txpool_size", 3}},
        {{"address", "192.0.2.4:9326"}, {"incoming", false}, {"version", "p2pool"},
         {"ping_ms", 40.0}, {"txpool_size", 5}},
        {{"address", "198.51.100.77:50000"}, {"version", "unknown-direction"}},
    });
}

std::set<std::string> strings(const nlohmann::json& arr)
{
    std::set<std::string> out;
    for (const auto& v : arr)
        out.insert(v.get<std::string>());
    return out;
}

std::set<std::string> keys(const nlohmann::json& j)
{
    std::set<std::string> out;
    for (auto it = j.begin(); it != j.end(); ++it)
        out.insert(it.key());
    return out;
}

}  // namespace

// ── the token ───────────────────────────────────────────────────────────────

// RFC 4231 test case 2 pins the HMAC-SHA256 underneath the token.
TEST(IpMask, TokenIsTruncatedHmacSha256)
{
    const std::string key = "Jefe";
    EXPECT_EQ(core::mask_host_with_key(
                  reinterpret_cast<const unsigned char*>(key.data()), key.size(),
                  "what do ya want for nothing?"),
              "h:5bdcc146");
}

TEST(IpMask, PortDroppedAndFamiliesNormalised)
{
    const auto a = core::mask_ip_endpoint("203.0.113.7:4321");
    EXPECT_TRUE(is_token(a)) << a;
    EXPECT_EQ(a, core::mask_ip_endpoint("203.0.113.7:4999"));
    EXPECT_EQ(a, core::mask_ip_endpoint("203.0.113.7"));
    EXPECT_NE(a, core::mask_ip_endpoint("203.0.113.8:4321"));

    const auto b = core::mask_ip_endpoint("[2001:db8::5]:3333");
    EXPECT_TRUE(is_token(b)) << b;
    EXPECT_EQ(b, core::mask_ip_endpoint("2001:db8::5"));
    EXPECT_NE(a, b);
}

TEST(IpMask, IpLiteralDetection)
{
    EXPECT_TRUE(core::is_ip_endpoint("203.0.113.7"));
    EXPECT_TRUE(core::is_ip_endpoint("203.0.113.7:3333"));
    EXPECT_TRUE(core::is_ip_endpoint("[2001:db8::5]:3333"));
    EXPECT_TRUE(core::is_ip_endpoint("2001:db8::5"));
    EXPECT_FALSE(core::is_ip_endpoint("LTCpayoutAddr"));
    EXPECT_FALSE(core::is_ip_endpoint("LTCpayoutAddr.rig1"));
    EXPECT_FALSE(core::is_ip_endpoint(""));
}

// The whole-body patterns: they find real IP literals and do not fire on the
// numeric fields of a /stratum_stats body.
TEST(IpMask, BodyPatternsOnlyMatchAddresses)
{
    EXPECT_TRUE(std::regex_search(std::string(R"({"remote_endpoint":"203.0.113.7:4321"})"), kIpv4));
    EXPECT_TRUE(std::regex_search(std::string(R"({"203.0.113.7":2})"), kIpv4));
    EXPECT_TRUE(std::regex_search(std::string(R"({"remote_endpoint":"[2001:db8::5]:3333"})"), kIpv6));
    const std::string numeric =
        R"({"hash_rate":1500000000.0,"difficulty":0.25,"rtt_ms":12.5,)"
        R"("first_seen":1791600000,"submission_rate":0.0123,"uptime":3600.0,)"
        R"("connection_difficulties":[0.25,1.0],"remote_endpoint":"h:5bdcc146"})";
    EXPECT_FALSE(std::regex_search(numeric, kIpv4));
    EXPECT_FALSE(std::regex_search(numeric, kIpv6));
}

// ── /stratum_stats over real HTTP ───────────────────────────────────────────

TEST(IpMask, StratumStatsMaskedForProxiedViewer)
{
    net::io_context ioc;
    core::WebServer ws(ioc, "127.0.0.1", 0, false);
    ws.set_stratum_port(0);
    register_miners(ws.get_mining_interface());
    ws.start();
    const uint16_t port = ws.bound_port();

    const std::string body = fetch(port, "/stratum_stats", kProxied);
    EXPECT_EQ(body.find("203.0.113.7"), std::string::npos) << body;
    EXPECT_EQ(body.find("2001:db8"), std::string::npos) << body;
    EXPECT_FALSE(std::regex_search(body, kIpv4)) << body;
    EXPECT_FALSE(std::regex_search(body, kIpv6)) << body;

    const auto j = nlohmann::json::parse(body);
    ASSERT_EQ(j["workers"].size(), 3u);
    for (const auto& [name, w] : j["workers"].items())
        EXPECT_TRUE(is_token(w["remote_endpoint"].get<std::string>())) << name;

    // Per-IP grouping survives: two connections from one host, one from another.
    const auto& conns = j["pool"]["ip_connections"];
    ASSERT_EQ(conns.size(), 2u);
    for (const auto& [ip, n] : conns.items())
        EXPECT_TRUE(is_token(ip)) << ip;
    EXPECT_EQ(conns.at(core::mask_ip_endpoint("203.0.113.7")), 2);
    EXPECT_EQ(conns.at(core::mask_ip_endpoint("2001:db8::5")), 1);
    for (const auto& [ip, n] : j["pool"]["ip_workers"].items())
        EXPECT_TRUE(is_token(ip)) << ip;
}

TEST(IpMask, StratumStatsRawForDirectLocalViewerAndSameShape)
{
    net::io_context ioc;
    core::WebServer ws(ioc, "127.0.0.1", 0, false);
    ws.set_stratum_port(0);
    register_miners(ws.get_mining_interface());
    ws.start();
    const uint16_t port = ws.bound_port();

    const auto local = nlohmann::json::parse(fetch(port, "/stratum_stats"));
    const auto proxied = nlohmann::json::parse(fetch(port, "/stratum_stats", kProxied));

    EXPECT_EQ(local["workers"]["LTCpayoutAddr.rig1"]["remote_endpoint"], "203.0.113.7:4321");
    EXPECT_EQ(local["workers"]["LTCpayoutAddr.rig3"]["remote_endpoint"], "[2001:db8::5]:3333");
    EXPECT_EQ(local["pool"]["ip_connections"]["203.0.113.7"], 2);

    // The whole-body patterns, checked on this real serializer output: they
    // find the raw addresses, and nothing once the address fields are removed.
    EXPECT_TRUE(std::regex_search(local.dump(), kIpv4));
    EXPECT_TRUE(std::regex_search(local.dump(), kIpv6));
    auto stripped = local;
    stripped["pool"].erase("ip_connections");
    stripped["pool"].erase("ip_workers");
    for (auto& [name, w] : stripped["workers"].items())
        w.erase("remote_endpoint");
    EXPECT_FALSE(std::regex_search(stripped.dump(), kIpv4)) << stripped.dump();
    EXPECT_FALSE(std::regex_search(stripped.dump(), kIpv6)) << stripped.dump();

    EXPECT_EQ(keys(local), keys(proxied));
    EXPECT_EQ(keys(local["pool"]), keys(proxied["pool"]));
    EXPECT_EQ(keys(local["workers"]), keys(proxied["workers"]));
    for (const auto& [name, w] : local["workers"].items())
        EXPECT_EQ(keys(w), keys(proxied["workers"][name])) << name;
}

// Fail closed: a caller that does not say who is viewing gets tokens.
TEST(IpMask, StratumStatsDefaultIsMasked)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::LITECOIN);
    register_miners(&mi);
    const auto j = mi.rest_stratum_stats();
    EXPECT_TRUE(is_token(j["workers"]["LTCpayoutAddr.rig1"]["remote_endpoint"].get<std::string>()));
}

// ── peer views: incoming masked, outgoing kept ──────────────────────────────

TEST(IpMask, PeerViewsMaskIncomingOnly)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::LITECOIN);
    mi.set_peer_info_fn([] { return peers(); });

    const auto list = mi.rest_peer_list(/*reveal_ips=*/false);
    ASSERT_EQ(list.size(), 3u);
    EXPECT_EQ(list[0]["address"], core::mask_ip_endpoint("198.51.100.9"));
    EXPECT_EQ(list[1]["address"], "192.0.2.4:9326");  // outgoing: a public node we dialed
    EXPECT_TRUE(is_token(list[2]["address"].get<std::string>()));  // no flag: fail closed
    EXPECT_EQ(list[0]["version"], "c2pool");

    for (const auto& view : {mi.rest_pings(false), mi.rest_peer_versions(false),
                             mi.rest_peer_txpool_sizes(false)}) {
        EXPECT_EQ(view.dump().find("198.51.100."), std::string::npos) << view.dump();
        EXPECT_TRUE(view.contains("192.0.2.4:9326")) << view.dump();
    }
    EXPECT_EQ(mi.rest_pings(false)[core::mask_ip_endpoint("198.51.100.9")], 12.0);

    const auto raw = mi.rest_peer_list(/*reveal_ips=*/true);
    EXPECT_EQ(raw[0]["address"], "198.51.100.9:40312");
    EXPECT_TRUE(mi.rest_pings(true).contains("198.51.100.9:40312"));

    // /peer_addresses departs from p2pool on purpose, for non-local viewers
    // only: incoming and unflagged peers are dropped, outgoing peers are kept.
    const auto pub = mi.rest_peer_addresses(/*reveal_ips=*/false);
    EXPECT_EQ(pub, "192.0.2.4:9326");
    EXPECT_EQ(pub.find("198.51.100.9:40312"), std::string::npos);
    EXPECT_EQ(mi.rest_peer_addresses(), pub);  // default is the non-local view
    const auto local = mi.rest_peer_addresses(/*reveal_ips=*/true);
    EXPECT_NE(local.find("198.51.100.9:40312"), std::string::npos);
    EXPECT_NE(local.find("192.0.2.4:9326"), std::string::npos);
    EXPECT_NE(local.find("198.51.100.77:50000"), std::string::npos);
}

// ── /ban_stats: banned IPs masked, banned addresses shown ───────────────────

TEST(IpMask, BanStatsMasksIpTargetsOnly)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::LITECOIN);
    mi.rest_control_mining_ban("203.0.113.50");
    mi.rest_control_mining_ban("LTCpayoutAddr");

    const auto masked = mi.rest_ban_stats(/*reveal_ips=*/false);
    EXPECT_EQ(masked["total_banned"], 2u);
    const auto m = strings(masked.at("banned_targets"));
    EXPECT_TRUE(m.count(core::mask_ip_endpoint("203.0.113.50")));
    EXPECT_TRUE(m.count("LTCpayoutAddr"));
    EXPECT_EQ(masked.dump().find("203.0.113.50"), std::string::npos);

    const auto r = strings(mi.rest_ban_stats(/*reveal_ips=*/true).at("banned_targets"));
    EXPECT_TRUE(r.count("203.0.113.50"));
}
