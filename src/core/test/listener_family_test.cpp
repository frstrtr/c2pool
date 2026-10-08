// SPDX-License-Identifier: AGPL-3.0-or-later
//
// #965 Phase-1 dual-stack listener KAT for core::bind_listener (core/factory.hpp).
//
// Before #965 the listener was hard-bound to tcp::v4() in Server::listen(), so a
// v6-primary / CGNAT host that had no public IPv4 got 0 inbound peers while its
// dual-stack dashd thrived (issue 963/965: 0 tip advances vs 58 over loopback).
// The fix binds a dual-stack IPv6 socket by default and falls back to IPv4 only
// when IPv6 is unavailable or the host forces v6-only.
//
// These cases drive the REAL core::bind_listener over a REAL boost::asio
// acceptor on an ephemeral port -- no mock, no node rig -- so they are rig-free
// and FOLDED into the EXISTING allowlisted core_test target (never a new
// add_executable: the #769 "Not Run" trap). One KAT covers every coin because
// core::Server::listen() is the single shared listener path all lanes route
// through. Without the fix the file does not compile (bind_listener/ListenFamily
// are absent) and AutoPrefersDualStackIPv6 asserts the exact IPv4-only->dual
// behaviour change.

#include <gtest/gtest.h>

#include <chrono>

#include <boost/asio.hpp>

#include <core/factory.hpp>

namespace {

namespace io = boost::asio;
using core::bind_listener;
using core::ListenFamily;

// Usable IPv6 loopback on this runner? Guards v6-dependent asserts so the KAT
// does not flake on a v6-disabled CI container (the fix's v4 fallback path is
// covered unconditionally by V4BindsIPv4Only).
bool ipv6_available()
{
    io::io_context ctx;
    io::ip::tcp::acceptor a(ctx);
    boost::system::error_code ec;
    a.open(io::ip::tcp::v6(), ec);
    if (ec) return false;
    a.bind(io::ip::tcp::endpoint(io::ip::tcp::v6(), 0), ec);
    return !ec;
}

TEST(ListenerFamily, V4BindsIPv4Only)
{
    io::io_context ctx;
    io::ip::tcp::acceptor a(ctx);
    boost::system::error_code ec;
    auto r = bind_listener(a, 0, ListenFamily::V4, ec);
    ASSERT_TRUE(r.ok) << ec.message();
    EXPECT_FALSE(r.ipv6);
    EXPECT_FALSE(r.ipv4_mapped);
    EXPECT_NE(r.port, 0);
    EXPECT_TRUE(a.is_open());
}

TEST(ListenerFamily, AutoPrefersDualStackIPv6)
{
    if (!ipv6_available()) GTEST_SKIP() << "no IPv6 loopback on this runner";
    io::io_context ctx;
    io::ip::tcp::acceptor a(ctx);
    boost::system::error_code ec;
    auto r = bind_listener(a, 0, ListenFamily::Auto, ec);
    ASSERT_TRUE(r.ok) << ec.message();
    // The point of #965: the DEFAULT is no longer hard IPv4. On a host with
    // IPv6 and the default bindv6only=0, Auto yields a dual-stack IPv6 socket.
    EXPECT_TRUE(r.ipv6);
    EXPECT_TRUE(r.ipv4_mapped);
    EXPECT_NE(r.port, 0);
}

TEST(ListenerFamily, V6Binds)
{
    if (!ipv6_available()) GTEST_SKIP() << "no IPv6 loopback on this runner";
    io::io_context ctx;
    io::ip::tcp::acceptor a(ctx);
    boost::system::error_code ec;
    auto r = bind_listener(a, 0, ListenFamily::V6, ec);
    ASSERT_TRUE(r.ok) << ec.message();
    EXPECT_TRUE(r.ipv6);
}

// Behavioural proof that the new dual-stack default still serves IPv4 miners:
// an actual IPv4 client connects to the Auto-bound port.
TEST(ListenerFamily, AutoAcceptsIPv4Client)
{
    if (!ipv6_available()) GTEST_SKIP() << "no IPv6 loopback on this runner";
    io::io_context ctx;
    io::ip::tcp::acceptor a(ctx);
    boost::system::error_code ec;
    auto r = bind_listener(a, 0, ListenFamily::Auto, ec);
    ASSERT_TRUE(r.ok) << ec.message();
    if (!r.ipv4_mapped) GTEST_SKIP() << "host forced v6-only; Auto fell back to v4 (V4 case covers it)";

    a.listen(io::socket_base::max_listen_connections, ec);
    ASSERT_FALSE(ec) << ec.message();

    io::ip::tcp::socket accepted(ctx);
    bool got = false;
    a.async_accept(accepted, [&](boost::system::error_code aec) { got = !aec; });

    io::ip::tcp::socket client(ctx);
    io::ip::tcp::endpoint v4ep(io::ip::make_address_v4("127.0.0.1"), r.port);
    boost::system::error_code cec;
    client.connect(v4ep, cec);  // kernel completes the handshake via the listen backlog
    ctx.run_for(std::chrono::seconds(2));
    EXPECT_FALSE(cec) << "IPv4 client connect: " << cec.message();
    EXPECT_TRUE(got) << "acceptor did not accept the IPv4 client";
}

}  // namespace
