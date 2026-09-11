// SPDX-License-Identifier: AGPL-3.0-or-later
//
// #965 Phase-2 KAT for core::parse_host_port (core/host_port.hpp), the shared
// IPv6-aware "host[:port]" parser that replaces the naive rfind(':')/find(':')
// splits at http_session.cpp:658/738, web_server.cpp:2813 and
// dash/coin/rpc_conf.hpp:90. The naive splits leave brackets in the host for
// "[2a00::1]:9999" and shred a bare IPv6 literal; these cases pin the correct
// behaviour. Header-only over core, so FOLDED into the EXISTING core_test
// target (never a new add_executable -- the #769 "Not Run" trap).

#include <gtest/gtest.h>

#include <core/host_port.hpp>

namespace {

using core::parse_host_port;

TEST(HostPort, BareHostNoPort)
{
    auto r = parse_host_port("example.com");
    EXPECT_EQ(r.host, "example.com");
    EXPECT_FALSE(r.port.has_value());
}

TEST(HostPort, HostColonPort)
{
    auto r = parse_host_port("example.com:9999");
    EXPECT_EQ(r.host, "example.com");
    ASSERT_TRUE(r.port.has_value());
    EXPECT_EQ(*r.port, 9999);
}

TEST(HostPort, IPv4WithPort)
{
    auto r = parse_host_port("1.2.3.4:8999");
    EXPECT_EQ(r.host, "1.2.3.4");
    ASSERT_TRUE(r.port.has_value());
    EXPECT_EQ(*r.port, 8999);
}

TEST(HostPort, BracketedIPv6WithPort)
{
    // The core defect: naive rfind(':') keeps the brackets in the host.
    auto r = parse_host_port("[2a00:62c0:429a:3000::1]:9999");
    EXPECT_EQ(r.host, "2a00:62c0:429a:3000::1");
    ASSERT_TRUE(r.port.has_value());
    EXPECT_EQ(*r.port, 9999);
}

TEST(HostPort, BracketedIPv6NoPort)
{
    auto r = parse_host_port("[::1]");
    EXPECT_EQ(r.host, "::1");
    EXPECT_FALSE(r.port.has_value());
}

TEST(HostPort, BareIPv6NoPort)
{
    // Unbracketed multi-colon literal is a bare IPv6 address, NOT host+port.
    auto r = parse_host_port("2a00:62c0:429a:3000::1");
    EXPECT_EQ(r.host, "2a00:62c0:429a:3000::1");
    EXPECT_FALSE(r.port.has_value());
}

TEST(HostPort, LoopbackV6WithPort)
{
    auto r = parse_host_port("[::1]:18999");
    EXPECT_EQ(r.host, "::1");
    ASSERT_TRUE(r.port.has_value());
    EXPECT_EQ(*r.port, 18999);
}

TEST(HostPort, InvalidPortLeavesHost)
{
    auto r = parse_host_port("host:notaport");
    EXPECT_EQ(r.host, "host");
    EXPECT_FALSE(r.port.has_value());
}

TEST(HostPort, OutOfRangePortRejected)
{
    auto r = parse_host_port("host:70000");
    EXPECT_EQ(r.host, "host");
    EXPECT_FALSE(r.port.has_value());
    EXPECT_FALSE(parse_host_port("host:0").port.has_value());
}

TEST(HostPort, Empty)
{
    auto r = parse_host_port("");
    EXPECT_EQ(r.host, "");
    EXPECT_FALSE(r.port.has_value());
}

}  // namespace
