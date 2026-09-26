// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_web_dashboard_kat -- XMR-WEB: c2pool-v37-xmr serves the SAME web
// dashboard every coin binary serves (core::WebServer + web-static/), fed by
// the read-only XmrWebDashboard provider (xmr/xmr_web_dashboard.hpp).
//
// The provider is started on a fixture XmrWebState (a fixed clock, a known
// share stream, known relay receipts, a known owed ledger and found blocks)
// and every endpoint is fetched over REAL loopback HTTP from the running
// server; each JSON field is checked against the value the fixture implies:
//   /local_stats /global_stats /current_payouts /current_merged_payouts
//   /recent_blocks /v37_status /xmr/payouts /web/currency_info /node_info
// plus GET / == the dashboard HTML with NO "PPLNS" anywhere in it (the payout
// scheme is WRS / PPR), and a stock LITECOIN WebServer serving the same file
// byte-for-byte (the relabel is per-coin: no other coin's UI changes).
//
// RED on the base (no provider, no --web-port: the endpoints do not exist and
// this TU does not build); GREEN with XMR-WEB. Harness: stdlib + the core web
// server (the provider's own link shape); returns nonzero on any failure.
#include "c2pool/v37/xmr/xmr_web_dashboard.hpp"
#include "c2pool/v37/xmr/xmr_fee_model.hpp"
#include "c2pool/v37/xmr/relay/xmr_address.hpp"

#include <core/web_server.hpp>
#include <nlohmann/json.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cmath>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>

namespace xweb = ::c2pool::v37n::xmr::web;
namespace fee  = ::c2pool::v37n::xmr::fee;

static int g_fail = 0, g_pass = 0;
#define CHECK(cond, what) do { if (cond) { ++g_pass; } else { ++g_fail; \
    std::printf("FAIL: %s  (%s:%d)\n", what, __FILE__, __LINE__); } } while (0)
static bool near(double a, double b) { return std::fabs(a - b) <= 1e-6 * std::max(1.0, std::fabs(b)); }

static double g_now = 0;
static double fake_now() { return g_now; }

struct Resp { int status = 0; std::string body; };
static Resp http_get(std::uint16_t port, const std::string& path) {
    Resp r;
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return r;
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(port);
    ::inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) { ::close(fd); return r; }
    const std::string req = "GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    (void)!::send(fd, req.data(), req.size(), 0);
    std::string raw; char buf[65536];
    for (ssize_t n; (n = ::recv(fd, buf, sizeof buf, 0)) > 0;) raw.append(buf, static_cast<std::size_t>(n));
    ::close(fd);
    if (raw.rfind("HTTP/1.1 ", 0) == 0) r.status = std::atoi(raw.c_str() + 9);
    const auto h = raw.find("\r\n\r\n");
    if (h != std::string::npos) r.body = raw.substr(h + 4);
    return r;
}
static nlohmann::json get_json(std::uint16_t port, const std::string& path) {
    const Resp r = http_get(port, path);
    CHECK(r.status == 200, ("HTTP 200 for " + path).c_str());
    return nlohmann::json::parse(r.body, nullptr, /*allow_exceptions=*/false);
}
static std::string slurp(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

static const char* kA = "addrA-4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2684Rge";
static const char* kB = "addrB-44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A";

static xweb::XmrWebState fixture(std::uint64_t foreign) {
    xweb::XmrWebState s;
    s.version = "kat-1.0"; s.network = "regtest"; s.coinbase_mode = "v37-settlement";
    s.stratum_host = "127.0.0.1"; s.stratum_port = 7251;
    s.chain_height = 3000; s.network_difficulty = 120000; s.template_height = 3001; s.share_difficulty = 1000;
    s.d_conf = 10; s.finalize_cursor = 2990; s.hw = 3000; s.ledger_seq = 77;
    s.owed_digest_hex = std::string(64, 'a');
    s.relay_enabled = true; s.relay_ready = 2; s.relay_conns = 2; s.relay_foreign_receipts = foreign;
    s.fee_model = "off"; s.donation_address = fee::donation_address(fee::DonationNet::Regtest);
    s.payout_address = kA;
    s.stratum_connections = 3; s.stratum_active = 2; s.stratum_shares = 45; s.stratum_rejected = 1;
    s.found_registered = 2; s.found_settled = 1; s.found_orphaned = 1;
    s.owed = {{kA, 600000000000LL}, {kB, 400000000000LL}, {"key:00112233", -5}};
    xweb::XmrWebBlock b1; b1.height = 2999; b1.id_hex = std::string(64, 'b'); b1.time = 1700000000;
    b1.status = "main"; b1.own = true; b1.coinbase_known = true; b1.coinbase_total_pico = 1000000000000ULL;
    b1.booked_pico = 1000000000000ULL;
    b1.payouts = {{kA, 700000000000ULL}, {kB, 300000000000ULL}};
    xweb::XmrWebBlock b2; b2.height = 2995; b2.id_hex = std::string(64, 'c'); b2.time = 1699999000;
    b2.status = "orphan"; b2.booked_pico = 900000000000ULL;   // a chain-booked block: full coinbase unknown
    s.blocks = {b1, b2};
    return s;
}

int main() {
    // ── the relabel primitive: words -> label, identifier-glued -> ident ─────
    {
        std::string t = "loadMainPPLNS(); t='PPLNS Distribution'; COIN_PPLNS_X; <a>PPLNS</a>";
        const std::size_t n = core::rewrite_payout_scheme_label(t, xweb::kPayoutScheme);
        CHECK(n == 4, "4 PPLNS rewritten");
        CHECK(t == "loadMainWRS(); t='WRS / PPR Distribution'; COIN_WRS_X; <a>WRS / PPR</a>", "relabel shape");
        std::string u = "no scheme here"; CHECK(core::rewrite_payout_scheme_label(u, "X") == 0 && u == "no scheme here", "no-op");
    }
    // ── the display address encoder is decode's exact inverse ───────────────
    {
        const std::string d = fee::donation_address(fee::DonationNet::Mainnet);
        const auto da = ::c2pool::v37n::xmr::relay::decode_address(d);
        CHECK(da.has_value(), "donation address decodes");
        if (da) CHECK(::c2pool::v37n::xmr::relay::address_of(da->ref(), 18, 42) == d, "encode(decode(addr)) == addr");
    }

    xweb::XmrWebDashboard dash("127.0.0.1", 0, C2POOL_WEB_STATIC, /*testnet=*/true, /*window_s=*/300);
    g_now = 1000000.0; dash.set_clock_for_test(&fake_now);       // start_s = T0
    g_now += 400; dash.publish(fixture(0));                       // relay sample (T0+400, 0)
    for (int i = 0; i < 30; ++i) { g_now += 1; dash.on_share(1000, kA, "w1"); }
    for (int i = 0; i < 15; ++i) { g_now += 1; dash.on_share(1000, kB, "w2"); }
    g_now = 1000000.0 + 500; dash.publish(fixture(20));           // (T0+500, 20): 20 x 1000 / 100 s = 200 H/s
    CHECK(dash.endpoint_json("/not-an-xmr-path").empty(), "unknown path falls through");
    CHECK(dash.start(), "dashboard binds");
    const std::uint16_t port = dash.bound_port();
    CHECK(port != 0, "ephemeral port bound");
    // local = 45 shares x 1000 / 300 s = 150 H/s; pool = 150 + 200 = 350 H/s.

    const auto ls = get_json(port, "/local_stats");
    CHECK(near(ls.value("local_hashps", -1.0), 150.0), "/local_stats local_hashps == 150");
    CHECK(near(ls.value("pool_hash_rate", -1.0), 350.0), "/local_stats pool_hash_rate == 350");
    CHECK(near(ls.value("network_hashrate", -1.0), 1000.0), "/local_stats network_hashrate == diff/120");
    CHECK(ls.value("network_block_difficulty", 0ULL) == 120000ULL, "/local_stats network difficulty");
    CHECK(ls.contains("miner_hash_rates") && near(ls["miner_hash_rates"].value(std::string(kA) + ".w1", -1.0), 100.0) &&
          near(ls["miner_hash_rates"].value(std::string(kB) + ".w2", -1.0), 50.0), "/local_stats per-worker hashrate");
    CHECK(ls.value("payout_scheme", std::string()) == "WRS / PPR", "/local_stats payout_scheme");
    CHECK(ls.value("version", std::string()) == "kat-1.0", "/local_stats version");
    CHECK(near(ls.value("block_value", -1.0), 1.0), "/local_stats block_value == the last known coinbase");

    const auto gs = get_json(port, "/global_stats");
    CHECK(near(gs.value("pool_hash_rate", -1.0), 350.0), "/global_stats pool_hash_rate");
    CHECK(gs.value("current_height", 0ULL) == 3000ULL, "/global_stats height");
    CHECK(gs.value("found_blocks", 0ULL) == 2ULL && gs.value("last_block", 0ULL) == 2999ULL, "/global_stats blocks");
    CHECK(gs.value("unique_miners", 0ULL) == 2ULL, "/global_stats unique miners");

    const auto cp = get_json(port, "/current_payouts");
    CHECK(cp.is_object() && cp.size() == 2, "/current_payouts: the two positive owed payees");
    CHECK(near(cp.value(kA, -1.0), 0.6) && near(cp.value(kB, -1.0), 0.4), "/current_payouts XMR amounts");
    const auto cm = get_json(port, "/current_merged_payouts");
    CHECK(cm.contains(kA) && near(cm[kA].value("amount", -1.0), 0.6), "/current_merged_payouts card shape");

    const auto rb = get_json(port, "/recent_blocks");
    CHECK(rb.is_array() && rb.size() == 2, "/recent_blocks two rows");
    if (rb.is_array() && rb.size() == 2) {
        CHECK(rb[0].value("number", 0ULL) == 2999ULL && rb[0].value("hash", std::string()) == std::string(64, 'b'), "row0 id");
        CHECK(rb[0].value("main_chain", false) && rb[0].value("found_by", std::string()) == "local", "row0 main/own");
        CHECK(rb[0].value("coinbase_total_pico", 0ULL) == 1000000000000ULL && near(rb[0].value("coinbase_total", 0.0), 1.0), "row0 coinbase");
        CHECK(rb[0]["payouts"].size() == 2 && rb[0]["payouts"][0].value("pico", 0ULL) == 700000000000ULL, "row0 payouts");
        CHECK(rb[1].value("orphan", false) && rb[1].value("status", std::string()) == "orphan", "row1 orphan");
        CHECK(rb[1]["coinbase_total_pico"].is_null() && rb[1].value("booked_payout_pico", 0ULL) == 900000000000ULL,
              "row1: unknown coinbase is null (never a fabricated 0), the booked amount is shown");
    }

    const auto vs = get_json(port, "/v37_status");
    CHECK(vs.value("payout_scheme", std::string()) == "WRS / PPR" && vs.value("version", std::string()) == "kat-1.0", "/v37_status scheme+version");
    CHECK(vs.contains("lane") && vs["lane"].value("d_conf", 0ULL) == 10ULL && vs["lane"].value("finalize_cursor", 0ULL) == 2990ULL &&
          vs["lane"].value("owed_digest", std::string()) == std::string(64, 'a') && vs["lane"].value("ledger_seq", 0ULL) == 77ULL,
          "/v37_status lane: D_conf, cursor, owed_digest, ledger_seq");
    CHECK(vs.contains("relay") && vs["relay"].value("ready", 0ULL) == 2ULL && vs["relay"].value("conns", 0ULL) == 2ULL, "/v37_status relay");
    CHECK(vs.contains("stratum") && vs["stratum"].value("port", 0) == 7251 && vs["stratum"].value("host", std::string()) == "127.0.0.1",
          "/v37_status stratum endpoint");
    CHECK(vs.contains("fee") && vs["fee"].value("model", std::string()) == "off" &&
          vs["fee"].value("donation_address", std::string()) == fee::donation_address(fee::DonationNet::Regtest), "/v37_status fee+donation");
    CHECK(vs.contains("found") && vs["found"].value("registered", 0ULL) == 2ULL, "/v37_status found registered");
    CHECK(vs.contains("chain") && vs["chain"].value("height", 0ULL) == 3000ULL && vs["chain"].value("difficulty", 0ULL) == 120000ULL, "/v37_status chain");

    const auto xp = get_json(port, "/xmr/payouts");
    CHECK(xp.value("owed_total_pico", 0LL) == 999999999995LL, "/xmr/payouts owed total (EffectiveOwed, pico)");
    CHECK(xp.contains("owed") && xp["owed"].size() == 3 && xp["owed"][0].value("owed_pico", 0LL) == 600000000000LL &&
          near(xp["owed"][0].value("owed_xmr", 0.0), 0.6), "/xmr/payouts rows pico+XMR");
    CHECK(xp.contains("last_block") && xp["last_block"].value("height", 0ULL) == 2999ULL && xp["last_block"]["payouts"].size() == 2,
          "/xmr/payouts last found block's coinbase payouts");

    const auto ci = get_json(port, "/web/currency_info");
    CHECK(ci.value("symbol", std::string()) == "XMR" && ci.value("payout_scheme", std::string()) == "WRS / PPR" &&
          ci.value("block_period", 0) == 120, "/web/currency_info");
    const auto ni = get_json(port, "/node_info");
    CHECK(ni.value("symbol", std::string()) == "XMR" && ni.value("worker_port", 0) == 7251, "/node_info");

    // ── the served UI: the dashboard HTML, relabelled, with no PPLNS anywhere ──
    const std::string file = slurp(std::string(C2POOL_WEB_STATIC) + "/dashboard.html");
    CHECK(file.find("PPLNS") != std::string::npos, "fixture sanity: the on-disk dashboard says PPLNS");
    const Resp root = http_get(port, "/");
    CHECK(root.status == 200, "GET / 200");
    CHECK(root.body.find("<html") != std::string::npos && root.body.size() > 100000, "GET / is the dashboard HTML");
    CHECK(root.body.find("PPLNS") == std::string::npos, "GET / has NO \"PPLNS\"");
    CHECK(root.body.find("WRS / PPR Distribution") != std::string::npos, "GET / says WRS / PPR");
    for (const char* p : {"/share.html", "/sharechain-explorer/dist/sharechain-explorer.js", "/sharechain-explorer/dist/pplns-view.js"}) {
        const Resp r = http_get(port, p);
        CHECK(r.status == 200 && !r.body.empty() && r.body.find("PPLNS") == std::string::npos, (std::string("no PPLNS in ") + p).c_str());
    }
    dash.stop();

    // ── per-coin: a stock LITECOIN WebServer still serves the file byte-for-byte ──
    {
        boost::asio::io_context ioc;
        core::WebServer ws(ioc, "127.0.0.1", 0, false, std::shared_ptr<core::IMiningNode>{},
                           c2pool::address::Blockchain::LITECOIN);
        ws.get_mining_interface()->set_dashboard_always_ready(true);
        ws.set_dashboard_dir(C2POOL_WEB_STATIC);
        ws.set_stratum_port(0);
        CHECK(ws.start(), "LTC web server binds");
        const Resp r = http_get(ws.bound_port(), "/dashboard.html");
        CHECK(r.status == 200 && r.body == file, "LTC dashboard.html byte-identical (PPLNS kept for PPLNS coins)");
        const Resp v = http_get(ws.bound_port(), "/v37_status");
        CHECK(v.status == 404, "LTC has no /v37_status (the override is per-coin)");
        ws.stop();
    }

    std::printf("v37_xmr_web_dashboard_kat: %d passed, %d failed\n", g_pass, g_fail);
    if (g_fail == 0 && g_pass < 40) { std::printf("FAIL: hollow green (%d checks)\n", g_pass); return 1; }
    return g_fail == 0 ? 0 : 1;
}
