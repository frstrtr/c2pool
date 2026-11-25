// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The coin daemon's template refresh over RPC (rides core_test).
//
// c2pool-ltc starts its web server early (the loading page is served during
// sync), before its coin node exists. WebServer::start() arms the RPC
// template refresh (a one-shot fetch; in --no-embedded mode a 2 s
// getblocktemplate poll) only for a coin node it already has, so a
// --no-embedded-ltc pool never fetched a template on its own: it waited for
// a sharechain event (a peer's share or bestblock, a merged-chain work
// change). Pinned here, on a REAL WebServer over a mock coin node:
//   - an RPC-only node attached after start() gets the one-shot fetch and the
//     poll, armed once however often it is attached;
//   - an embedded node attached after start() is left to its header sync, as
//     before (no fetch, no poll);
//   - a node attached before start() is armed by start(), as before;
//   - a block the daemon's own P2P link announces refreshes at once, once
//     per block hash (c2pool-ltc subscribes coin_node.new_block to it).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <chrono>
#include <string>

#include <nlohmann/json.hpp>

#include <core/coin/node_iface.hpp>
#include <core/coin/work_view.hpp>
#include <core/uint256.hpp>
#include <core/web_server.hpp>

namespace {

using std::chrono::milliseconds;

struct RpcCoinNode : public core::coin::ICoinNode {
    int builds = 0;
    bool embedded = false;
    core::coin::WorkView get_work_view() override
    {
        ++builds;
        core::coin::WorkView v;
        v.m_data = {
            {"previousblockhash", std::string(62, '0') + "ab"},
            {"version", 0x20000000},
            {"height", 100},
            {"bits", "207fffff"},
            {"curtime", 1600000000},
            {"coinbasevalue", 5000000000LL},
            {"transactions", nlohmann::json::array()},
            {"rules", nlohmann::json::array({"segwit"})},
            {"mweb", ""},
        };
        return v;
    }
    bool submit_block_hex(const std::string&, bool) override { return true; }
    bool is_embedded() const override { return embedded; }
    bool has_rpc() const override { return true; }
};

void run(boost::asio::io_context& ioc, milliseconds d)
{
    ioc.restart();
    ioc.run_for(d);
}

} // namespace

TEST(WebServerRpcRefresh, RpcNodeAttachedAfterStartIsPolledOnce)
{
    boost::asio::io_context ioc;
    core::WebServer ws(ioc, "127.0.0.1", 0, /*testnet=*/true);
    ws.set_stratum_port(0);
    ASSERT_TRUE(ws.start());   // as c2pool-ltc does: before its coin node exists
    RpcCoinNode node;
    run(ioc, milliseconds(700));
    EXPECT_EQ(node.builds, 0);

    ws.set_coin_node(&node);
    run(ioc, milliseconds(700));
    EXPECT_GE(node.builds, 1) << "the one-shot fetch";
    run(ioc, milliseconds(2100));
    EXPECT_GE(node.builds, 2) << "the 2 s poll";

    // Attached again: nothing more is armed (one poll: two builds in ~4 s,
    // a second one-shot and poll would make at least four).
    ws.set_coin_node(&node);
    const int before = node.builds;
    run(ioc, milliseconds(4100));
    EXPECT_GE(node.builds - before, 1);
    EXPECT_LE(node.builds - before, 3);
    ws.stop();
}

TEST(WebServerRpcRefresh, EmbeddedNodeAttachedAfterStartIsLeftToItsHeaderSync)
{
    boost::asio::io_context ioc;
    core::WebServer ws(ioc, "127.0.0.1", 0, /*testnet=*/true);
    ws.set_stratum_port(0);
    ASSERT_TRUE(ws.start());
    RpcCoinNode node;
    node.embedded = true;   // embedded, with an RPC daemon beside it
    ws.set_coin_node(&node);
    run(ioc, milliseconds(2700));
    EXPECT_EQ(node.builds, 0) << "embedded mode refreshes on its header sync, as before";
    ws.stop();
}

// RPC mode: a block the daemon's own P2P link announces (coin_node.new_block,
// wired in c2pool-ltc) refreshes the template at once, once per block hash.
TEST(WebServerRpcRefresh, ParentBlockFromTheDaemonsP2pLinkRefreshesAtOnce)
{
    boost::asio::io_context ioc;
    core::WebServer ws(ioc, "127.0.0.1", 0, /*testnet=*/true);
    ws.set_stratum_port(0);
    ASSERT_TRUE(ws.start());
    RpcCoinNode node;
    ws.set_coin_node(&node);   // the timers fire only while ioc runs: not here
    uint256 a, b;
    a.SetHex("01");
    b.SetHex("02");
    ws.refresh_on_parent_block(a);
    EXPECT_EQ(node.builds, 1) << "at once";
    ws.refresh_on_parent_block(a);
    EXPECT_EQ(node.builds, 1) << "the same block (inv, then the block): once";
    ws.refresh_on_parent_block(uint256());
    EXPECT_EQ(node.builds, 1);
    ws.refresh_on_parent_block(b);
    EXPECT_EQ(node.builds, 2);
    const auto stats = ws.get_mining_interface()->rest_local_stats();
    EXPECT_EQ(stats["template_refresh"]["by_cause"]["block"].get<uint64_t>(), 2u);
    ws.stop();
}

TEST(WebServerRpcRefresh, NodeAttachedBeforeStartIsArmedByStart)
{
    boost::asio::io_context ioc;
    core::WebServer ws(ioc, "127.0.0.1", 0, /*testnet=*/true);
    ws.set_stratum_port(0);
    RpcCoinNode node;
    ws.set_coin_node(&node);
    run(ioc, milliseconds(700));
    EXPECT_EQ(node.builds, 0) << "not running yet";
    ASSERT_TRUE(ws.start());
    run(ioc, milliseconds(2700));
    EXPECT_GE(node.builds, 2) << "the one-shot fetch and the poll";
    ws.set_coin_node(&node);   // attached again while running: armed once only
    const int before = node.builds;
    run(ioc, milliseconds(4100));
    EXPECT_LE(node.builds - before, 3);
    ws.stop();
}
