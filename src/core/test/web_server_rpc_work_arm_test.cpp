// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <stdexcept>

#include <boost/asio/io_context.hpp>

#include <core/web_server.hpp>
#include <core/coin/node_iface.hpp>
#include <core/coin/work_view.hpp>

// ---------------------------------------------------------------------------
// The template refresh of an RPC-only coin node must be armed whether the node
// is attached before or after WebServer::start().
//
// main_ltc starts the web server early (the loading page is served during
// sync) and calls set_coin_node() later. start() armed the one-shot template
// fetch and the no-embedded getblocktemplate poll only for a node already
// attached, so with --no-embedded-ltc nothing was ever armed and the node
// never got a template. The first test fails on a tree without the fix: zero
// get_work_view() calls.
//
// An embedded node keeps its event-driven refresh (on_new_headers): attaching
// one after start() arms nothing, as before.
// ---------------------------------------------------------------------------

namespace {

using std::chrono::milliseconds;

struct CountingCoinNode : public core::coin::ICoinNode {
    bool embedded = false;
    bool rpc      = true;
    std::atomic<int> work_calls{0};

    core::coin::WorkView get_work_view() override {
        ++work_calls;
        throw std::runtime_error("no template (test double)");
    }
    bool submit_block_hex(const std::string&, bool) override { return false; }
    bool is_embedded() const override { return embedded; }
    bool has_rpc()     const override { return rpc; }
};

struct Rig {
    boost::asio::io_context ioc;
    core::WebServer ws{ioc, "127.0.0.1", 0, /*testnet=*/true};
    Rig() { ws.set_stratum_port(0); }
    ~Rig() { ws.stop(); }
    void run(milliseconds d) { ioc.restart(); ioc.run_for(d); }
};

// One-shot at 500 ms + first poll at 2 s fall inside 2.7 s.
constexpr milliseconds kWindow{2700};

} // namespace

TEST(WebServerRpcWorkArm, RpcOnlyNodeAttachedAfterStartGetsTemplateRefresh)
{
    Rig r;
    CountingCoinNode node;
    ASSERT_TRUE(r.ws.start());
    r.ws.set_coin_node(&node);  // main_ltc order: start() first, node later
    r.run(kWindow);
    EXPECT_GE(node.work_calls.load(), 2)
        << "one-shot fetch + GBT poll were not armed for a node attached after start()";
}

TEST(WebServerRpcWorkArm, RpcOnlyNodeAttachedBeforeStartUnchanged)
{
    Rig r;
    CountingCoinNode node;
    r.ws.set_coin_node(&node);
    ASSERT_TRUE(r.ws.start());
    r.run(kWindow);
    EXPECT_GE(node.work_calls.load(), 2);
}

TEST(WebServerRpcWorkArm, EmbeddedNodeAttachedAfterStartArmsNothing)
{
    Rig r;
    CountingCoinNode node;
    node.embedded = true;  // embedded + RPC fallback: the LTC prod topology
    ASSERT_TRUE(r.ws.start());
    r.ws.set_coin_node(&node);
    r.run(kWindow);
    EXPECT_EQ(node.work_calls.load(), 0);
}

TEST(WebServerRpcWorkArm, NodeWithoutRpcAttachedAfterStartArmsNothing)
{
    Rig r;
    CountingCoinNode node;
    node.rpc = false;
    ASSERT_TRUE(r.ws.start());
    r.ws.set_coin_node(&node);
    r.run(kWindow);
    EXPECT_EQ(node.work_calls.load(), 0);
}

TEST(WebServerRpcWorkArm, ArmedAtMostOnce)
{
    // Attached before start(), then re-attached after it: one set of timers.
    // In 4.7 s one set makes 3 calls (500 ms, 2 s, 4 s); a second set would
    // make 6.
    Rig r;
    CountingCoinNode node;
    r.ws.set_coin_node(&node);
    ASSERT_TRUE(r.ws.start());
    r.ws.set_coin_node(&node);
    r.ws.set_coin_node(&node);
    r.run(milliseconds{4700});
    EXPECT_GE(node.work_calls.load(), 2);
    EXPECT_LE(node.work_calls.load(), 4);
}
