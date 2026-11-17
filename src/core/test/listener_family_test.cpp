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
#include <string>

#ifndef _WIN32
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#endif

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

// ── --listen HOST:PORT honours HOST (DASH, 2026-11-17) ───────────────────────
// main_dash parsed --listen [HOST:]PORT but bound every interface: a node
// started with --listen 127.0.0.1:N was reachable on its LAN address while its
// startup line said 127.0.0.1. bind_listener_at binds exactly one address.

// A non-loopback IPv4 address of this host, or "" when there is none (a
// network-less container): the reachability half of the KAT then skips.
std::string non_loopback_ipv4()
{
#ifndef _WIN32
    ifaddrs* ifs = nullptr;
    if (getifaddrs(&ifs) != 0) return "";
    std::string out;
    for (ifaddrs* i = ifs; i; i = i->ifa_next) {
        if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET) continue;
        if (i->ifa_flags & IFF_LOOPBACK) continue;
        char buf[INET_ADDRSTRLEN] = {};
        const auto* sin = reinterpret_cast<const sockaddr_in*>(i->ifa_addr);
        if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf))) { out = buf; break; }
    }
    freeifaddrs(ifs);
    return out;
#else
    return "";
#endif
}

bool connects(io::io_context& ctx, const std::string& ip, uint16_t port)
{
    io::ip::tcp::socket client(ctx);
    boost::system::error_code ec;
    client.connect(io::ip::tcp::endpoint(io::ip::make_address(ip), port), ec);
    return !ec;
}

TEST(ListenerHost, LoopbackHostIsNotReachableOnTheLanAddress)
{
    io::io_context ctx;
    io::ip::tcp::acceptor a(ctx);
    boost::system::error_code ec;
    const auto r = core::bind_listener_at(a, "127.0.0.1", 0, ec);
    ASSERT_TRUE(r.ok) << ec.message();
    EXPECT_FALSE(r.ipv6);
    EXPECT_EQ(a.local_endpoint().address().to_string(), "127.0.0.1")
        << "bound to exactly the requested address, not the wildcard";
    a.listen(io::socket_base::max_listen_connections, ec);
    ASSERT_FALSE(ec) << ec.message();

    EXPECT_TRUE(connects(ctx, "127.0.0.1", r.port)) << "reachable on the address it was asked for";
    const std::string lan = non_loopback_ipv4();
    if (lan.empty()) GTEST_SKIP() << "no non-loopback IPv4 on this runner";
    EXPECT_FALSE(connects(ctx, lan, r.port))
        << "a 127.0.0.1 listener must not accept on the LAN address " << lan;

    // Control: the wildcard path (every interface) DOES accept there, so the
    // refusal above is the host binding, not a firewall.
    io::ip::tcp::acceptor w(ctx);
    const auto rw = core::bind_listener(w, 0, core::ListenFamily::V4, ec);
    ASSERT_TRUE(rw.ok) << ec.message();
    w.listen(io::socket_base::max_listen_connections, ec);
    ASSERT_FALSE(ec);
    EXPECT_TRUE(connects(ctx, lan, rw.port)) << "control: the wildcard listener is reachable on " << lan;
}

TEST(ListenerHost, IPv6LiteralWithBracketsBindsThatAddress)
{
    if (!ipv6_available()) GTEST_SKIP() << "no IPv6 loopback on this runner";
    io::io_context ctx;
    io::ip::tcp::acceptor a(ctx);
    boost::system::error_code ec;
    const auto r = core::bind_listener_at(a, "[::1]", 0, ec);
    ASSERT_TRUE(r.ok) << ec.message();
    EXPECT_TRUE(r.ipv6);
    EXPECT_FALSE(r.ipv4_mapped) << "a specific IPv6 address is bound v6-only";
    EXPECT_EQ(a.local_endpoint().address().to_string(), "::1");
}

TEST(ListenerHost, HostnameOrForeignAddressIsRefusedNotWidened)
{
    io::io_context ctx;
    boost::system::error_code ec;
    {
        io::ip::tcp::acceptor a(ctx);
        const auto r = core::bind_listener_at(a, "localhost", 0, ec);
        EXPECT_FALSE(r.ok) << "a hostname is refused (numeric address required)";
        EXPECT_TRUE(ec);
        EXPECT_FALSE(a.is_open());
    }
    {
        io::ip::tcp::acceptor a(ctx);
        ec.clear();
        // TEST-NET-3 (RFC 5737): never an address of this host.
        const auto r = core::bind_listener_at(a, "203.0.113.7", 0, ec);
        EXPECT_FALSE(r.ok) << "an address this host does not have cannot be bound";
        EXPECT_FALSE(a.is_open()) << "and nothing is left listening anywhere else";
    }
}

TEST(ListenerHost, WildcardSpellings)
{
    for (const char* h : {"", "0.0.0.0", "::", "[::]", "*"})
        EXPECT_TRUE(core::is_wildcard_listen_host(h)) << "'" << h << "'";
    for (const char* h : {"127.0.0.1", "::1", "[::1]", "192.168.1.5", "localhost"})
        EXPECT_FALSE(core::is_wildcard_listen_host(h)) << h;
}

}  // namespace
