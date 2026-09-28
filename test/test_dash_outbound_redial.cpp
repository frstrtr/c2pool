// SPDX-License-Identifier: AGPL-3.0-or-later
//
// #1835 -- a failed outbound DASH sharechain dial must stay retryable.
//
// try_connect_peers() marks an address as "being dialed" (m_pending_outbound)
// and skips any address already marked. Before #1835 the mark was cleared only
// by connected(), error() and close_connection(), and all three need a socket.
// A dial refused or timed out at the TCP level never gets a socket: core::Factory
// reports it through INetwork::connect_failed(addr) instead, which the DASH
// sharechain node did not override. The address therefore stayed marked for
// the rest of the process lifetime and no maintenance pass dialed it again, so
// a node started with --connect/--addnode while that peer was down never
// reached it once it came back.
//
// These KATs drive the REAL dash::NodeImpl (real io_context, real
// core::Factory dial path, shared_ptr-owned + set_lifetime exactly as
// main_dash.cpp owns it) against a loopback port that refuses connections.
// The maintenance pass is driven directly through try_connect_peers(), so no
// 30 s timer wait is involved.
//
// Folded into the EXISTING allowlisted test_dash_node target (it already links
// the `dash` OBJECT lib that carries node.cpp); a standalone add_executable
// would be missing from the build.yml --target list and report "Not Run".

#include <gtest/gtest.h>

#include <impl/dash/node.hpp>
#include <core/filesystem.hpp>
#include <core/netaddress.hpp>

#include <boost/asio.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <string>
#include <system_error>

namespace {

// A loopback port with nothing listening on it: bind an ephemeral port to learn
// a free number, then close the acceptor. A connect to it is refused at once
// (ECONNREFUSED), which is the socket-less failure #1835 is about.
std::uint16_t refused_loopback_port()
{
    boost::asio::io_context ioc;
    boost::asio::ip::tcp::acceptor acceptor(
        ioc, boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
    const auto port = acceptor.local_endpoint().port();
    acceptor.close();
    return port;
}

// Per-run config name, so the AddrStore file this node writes under the config
// dir never carries addresses from an earlier run into this one.
std::string unique_config_name(const char* tag)
{
    const auto ticks = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::string("dash-redial-kat-") + tag + "-" + std::to_string(ticks);
}

struct ConfigDirCleanup
{
    std::string name;
    ~ConfigDirCleanup()
    {
        std::error_code ec;
        std::filesystem::remove_all(core::filesystem::config_path() / name, ec);
    }
};

// The real NodeImpl with read-only views of its dial bookkeeping and a counter
// on the Factory's dial-failure hook. The override forwards to NodeImpl's own
// connect_failed, so the node under test behaves exactly as shipped; on a tree
// without the #1835 override the forward lands on the INetwork no-op default.
class RedialProbeNode : public dash::NodeImpl
{
public:
    using dash::NodeImpl::NodeImpl;

    // Shared so the count stays readable after the node itself is destroyed.
    std::shared_ptr<std::map<NetService, int>> failures =
        std::make_shared<std::map<NetService, int>>();

    void connect_failed(const NetService& addr) override
    {
        ++(*failures)[addr];
        dash::NodeImpl::connect_failed(addr);
    }

    bool is_pending(const NetService& addr) const { return m_pending_outbound.contains(addr); }
    bool is_outbound(const NetService& addr) const { return m_outbound_addrs.contains(addr); }
};

int failures_for(const std::map<NetService, int>& m, const NetService& addr)
{
    auto it = m.find(addr);
    return it == m.end() ? 0 : it->second;
}

// Run the io_context in short slices until `done()` holds or the budget runs
// out. The node keeps timers armed (ping), so a plain run() would never return.
template <typename Pred>
bool pump_until(boost::asio::io_context& ioc, Pred done, std::chrono::milliseconds budget)
{
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (!done() && std::chrono::steady_clock::now() < deadline)
    {
        ioc.restart();
        ioc.run_for(std::chrono::milliseconds(20));
    }
    return done();
}

// A refused loopback connect resolves in well under a second on Linux/macOS;
// Windows retries the SYN before reporting refusal, so leave headroom.
constexpr std::chrono::milliseconds kDialBudget{8000};

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// 1. The #1835 defect and its fix. An --addnode-style seed whose peer is down:
//    the first pass dials it, the dial is refused, and the NEXT maintenance
//    pass must dial it again. Pre-fix the address is still marked as being
//    dialed after the refusal and the second pass skips it, so it is dialed
//    exactly once for the life of the process.
// ─────────────────────────────────────────────────────────────────────────────
TEST(DashOutboundRedial, RefusedDialIsRetriedOnNextMaintenancePass)
{
    boost::asio::io_context ioc;
    ConfigDirCleanup cleanup{unique_config_name("retry")};
    dash::Config cfg{cleanup.name};

    const NetService dead("127.0.0.1", refused_loopback_port());
    cfg.pool()->m_bootstrap_addrs = {dead};   // the --addnode / --connect seed

    auto node = std::make_shared<RedialProbeNode>(&ioc, &cfg);
    node->set_lifetime(node);                 // main_dash.cpp ownership shape
    auto failures = node->failures;

    // Pass 1: the seed is dialed and marked as being dialed.
    node->try_connect_peers();
    EXPECT_TRUE(node->is_pending(dead)) << "pass 1 must dial the seed";

    ASSERT_TRUE(pump_until(ioc, [&] { return failures_for(*failures, dead) >= 1; }, kDialBudget))
        << "harness: the dial to a refused loopback port must fail and reach connect_failed";
    EXPECT_EQ(failures_for(*failures, dead), 1);

    EXPECT_FALSE(node->is_pending(dead))
        << "#1835: a refused dial left the address marked as being dialed, so no "
           "later maintenance pass will ever dial it again";
    EXPECT_FALSE(node->is_outbound(dead))
        << "a dial that never connected must not count as an outbound peer";

    // Pass 2 (the next 30 s tick): the same seed must be dialed again.
    node->try_connect_peers();
    EXPECT_TRUE(node->is_pending(dead)) << "pass 2 must redial the seed";
    EXPECT_TRUE(pump_until(ioc, [&] { return failures_for(*failures, dead) >= 2; }, kDialBudget))
        << "#1835: the next maintenance pass did not dial the refused seed again "
           "(dial failures seen: " << failures_for(*failures, dead) << ", want 2)";
    EXPECT_EQ(failures_for(*failures, dead), 2);
    EXPECT_FALSE(node->is_pending(dead))
        << "the second refusal must leave the seed retryable too";
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. The fix keeps retrying, one dial per pass: p2pool's behaviour is to keep
//    retrying a configured peer, and no pass may stack a second in-flight dial
//    to an address that is already being dialed.
// ─────────────────────────────────────────────────────────────────────────────
TEST(DashOutboundRedial, EachPassDialsTheDeadSeedExactlyOnce)
{
    boost::asio::io_context ioc;
    ConfigDirCleanup cleanup{unique_config_name("each")};
    dash::Config cfg{cleanup.name};

    const NetService dead("127.0.0.1", refused_loopback_port());
    cfg.pool()->m_bootstrap_addrs = {dead};

    auto node = std::make_shared<RedialProbeNode>(&ioc, &cfg);
    node->set_lifetime(node);
    auto failures = node->failures;

    constexpr int kPasses = 3;
    for (int pass = 1; pass <= kPasses; ++pass)
    {
        node->try_connect_peers();
        // A second pass while the first dial is still in flight must not dial
        // again (the pending mark is what prevents it).
        node->try_connect_peers();
        ASSERT_TRUE(pump_until(ioc, [&] { return failures_for(*failures, dead) >= pass; }, kDialBudget))
            << "#1835: pass " << pass << " did not dial the refused seed";
        // Drain briefly so a stacked duplicate dial, if any, would be counted.
        pump_until(ioc, [] { return false; }, std::chrono::milliseconds(100));
        EXPECT_EQ(failures_for(*failures, dead), pass)
            << "pass " << pass << " must dial the seed exactly once";
        EXPECT_FALSE(node->is_pending(dead));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Teardown window (factory_connect_failed_uaf_test.cpp lesson): connect_failed
//    can fire while the owner is letting the node go. With the node
//    shared_ptr-owned + set_lifetime, the Factory pins it for the in-flight
//    dial, so the hook runs on a LIVE node and the node is destroyed only after
//    the handler returns. Under ASan any touch of a freed node aborts here.
// ─────────────────────────────────────────────────────────────────────────────
TEST(DashOutboundRedial, OwnerReleasedMidDialHookRunsOnLiveNodeThenNodeIsFreed)
{
    boost::asio::io_context ioc;
    ConfigDirCleanup cleanup{unique_config_name("teardown")};
    dash::Config cfg{cleanup.name};

    const NetService dead("127.0.0.1", refused_loopback_port());
    cfg.pool()->m_bootstrap_addrs = {dead};

    auto node = std::make_shared<RedialProbeNode>(&ioc, &cfg);
    node->set_lifetime(node);
    auto failures = node->failures;
    std::weak_ptr<RedialProbeNode> weak = node;

    node->try_connect_peers();
    node.reset();   // the owner lets go while the dial is still in flight
    EXPECT_FALSE(weak.expired()) << "the in-flight dial must pin the node";

    EXPECT_TRUE(pump_until(ioc, [&] { return weak.expired(); }, kDialBudget))
        << "the node must be released once the failed dial's handler returns";
    EXPECT_EQ(failures_for(*failures, dead), 1)
        << "the dial failure must be delivered to the (still live) node exactly once";
}
