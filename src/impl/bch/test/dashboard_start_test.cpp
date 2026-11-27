// SPDX-License-Identifier: AGPL-3.0-or-later
// BCH dashboard start on a port that is already bound (bch::start_dashboard,
// dashboard_start.hpp).
//
// standup_pool_run installs hooks that hold the dashboard's MiningInterface as
// a raw pointer before it starts the WebServer: the node's best-share callback
// (refresh_tip_sensitive_caches), the work source's Best Share sink
// (update_best_difficulty) and its found-block sink (record_found_block). It
// used to reset the WebServer when the bind failed, freeing that
// MiningInterface, so the next share or rig submit called into freed memory.
//
//   [1] a pre-bound port: start_dashboard returns false and the WebServer, with
//       the same MiningInterface the hooks captured, is still owned;
//   [2] the hooks then run against it: a tip-driven cache refreshes, the Best
//       Share legs rise, the found block is recorded;
//   [3] a free port: start_dashboard returns true;
//   [4] pool_entrypoint.hpp resets the WebServer only before any hook
//       captures `mi` (the MiningInterface-null branch), and starts it through
//       start_dashboard.
//
// Built into bch_dashboard_pplns_current_test (its main runs these checks).
// Under -fsanitize=address a reset in start_dashboard turns [2] into a
// heap-use-after-free report.

#include <impl/bch/dashboard_start.hpp>

#include <core/uint256.hpp>
#include <core/web_server.hpp>

#include <boost/asio.hpp>

#include <cstdint>
#include <ctime>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <string>

#ifndef BCH_POOL_ENTRYPOINT_SRC
#error "BCH_POOL_ENTRYPOINT_SRC must be defined (path of impl/bch/pool_entrypoint.hpp)"
#endif

namespace {

int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ dashboard_start_test.cpp:" << __LINE__ << "\n"; ++failures; } } while (0)

namespace net = boost::asio;

std::string slurp(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

void bind_failure_keeps_the_server()
{
    net::io_context ioc;

    // [1] The HTTP port is taken.
    net::ip::tcp::acceptor holder(ioc, net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
    const uint16_t port = holder.local_endpoint().port();

    auto web_server = std::make_unique<core::WebServer>(
        ioc, "127.0.0.1", port, false, std::shared_ptr<core::IMiningNode>{},
        c2pool::address::Blockchain::BITCOIN);
    core::MiningInterface* mi = web_server->get_mining_interface();
    CHECK(mi != nullptr);
    if (!mi) return;
    mi->set_io_context(&ioc);

    // The hooks standup_pool_run installs before start(), each holding `mi`.
    int stats_refreshes = 0;
    mi->set_sharechain_stats_fn([&stats_refreshes]() {
        ++stats_refreshes;
        return nlohmann::json{{"chain_height", 1}};
    });
    mi->mark_last_cache_tip_driven();
    std::function<void()> on_best_share_changed = [mi]() { mi->refresh_tip_sensitive_caches(); };
    std::function<void(double, const std::string&)> best_share_sink =
        [mi](double diff, const std::string& miner) {
            mi->update_best_difficulty(diff, miner, "", /*update_merged=*/false);
        };
    std::function<void(uint32_t, const uint256&)> found_block_sink =
        [mi](uint32_t height, const uint256& block_hash) {
            mi->record_found_block(height, block_hash, static_cast<uint64_t>(std::time(nullptr)),
                                   "BCH", "miner", block_hash.GetHex(),
                                   mi->get_network_difficulty(), 0.0, 0.0, 0);
        };

    const bool bound = bch::start_dashboard(web_server, "127.0.0.1", port);
    CHECK(!bound);
    CHECK(web_server != nullptr);
    CHECK(web_server && web_server->get_mining_interface() == mi);

    // [2] The hooks fire against the kept MiningInterface.
    const int before = stats_refreshes;
    on_best_share_changed();
    CHECK(stats_refreshes == before + 1);

    best_share_sink(4321.0, "bchminer");
    const nlohmann::json bs = mi->rest_best_share();
    CHECK(bs["all_time"].value("difficulty", 0.0) == 4321.0);
    CHECK(bs["session"].value("difficulty", 0.0) == 4321.0);

    uint256 h;
    h.SetHex("00000000000000000123456789abcdef00000000000000000000000000000001");
    found_block_sink(900000, h);
    bool recorded = false;
    for (const auto& fb : mi->get_found_blocks())
        if (fb.hash == h.GetHex()) recorded = true;
    CHECK(recorded);
}

void free_port_starts()
{
    net::io_context ioc;
    uint16_t port = 0;
    {
        net::ip::tcp::acceptor probe(ioc, net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
        port = probe.local_endpoint().port();
    }
    auto web_server = std::make_unique<core::WebServer>(
        ioc, "127.0.0.1", port, false, std::shared_ptr<core::IMiningNode>{},
        c2pool::address::Blockchain::BITCOIN);
    CHECK(bch::start_dashboard(web_server, "127.0.0.1", port));
    CHECK(web_server != nullptr);
    std::unique_ptr<core::WebServer> none;
    CHECK(!bch::start_dashboard(none, "127.0.0.1", port));
}

// Comments blanked out (string literals kept), so a commented-out call does not count.
std::string code_of(const std::string& s)
{
    std::string out;
    std::size_t i = 0;
    while (i < s.size()) {
        if (s.compare(i, 2, "//") == 0) {
            while (i < s.size() && s[i] != '\n') ++i;
        } else if (s.compare(i, 2, "/*") == 0) {
            const std::size_t e = s.find("*/", i + 2);
            i = (e == std::string::npos) ? s.size() : e + 2;
        } else if (s[i] == '"') {
            out += s[i++];
            while (i < s.size() && s[i] != '"' && s[i] != '\n') {
                if (s[i] == '\\' && i + 1 < s.size()) out += s[i++];
                out += s[i++];
            }
            if (i < s.size()) out += s[i++];
        } else {
            out += s[i++];
        }
    }
    return out;
}

void entrypoint_never_frees_a_hooked_server()
{
    const std::string code = code_of(slurp(BCH_POOL_ENTRYPOINT_SRC));
    CHECK(!code.empty());
    const std::size_t first_capture = code.find("[mi]");
    CHECK(first_capture != std::string::npos);
    int resets = 0;
    for (std::size_t p = code.find("web_server.reset()"); p != std::string::npos;
         p = code.find("web_server.reset()", p + 1)) {
        ++resets;
        CHECK(p < first_capture);   // only before any hook holds `mi`
    }
    CHECK(resets <= 1);
    CHECK(code.find("start_dashboard(web_server") != std::string::npos);
    CHECK(code.find("web_server->start()") == std::string::npos);
}

} // namespace

int run_dashboard_start_checks()
{
    bind_failure_keeps_the_server();
    free_port_starts();
    entrypoint_never_frees_a_hooked_server();
    if (failures == 0)
        std::cout << "bch dashboard start (bind failure keeps the server): ALL PASS\n";
    else
        std::cerr << "bch dashboard start: " << failures << " FAILURE(S)\n";
    return failures;
}
