// DASH external-dashd RPC creds-resolution KAT (launcher slice 4).
//
// Exercises the dash.conf credential parser + endpoint-override + arm-gating
// that main_dash.cpp --run consults before constructing a NodeRPC and ARMing the
// submitblock fallback. The submitblock RPC itself needs a live dashd (the G2
// won-block-reaches-network leg, driven by --submit-block against VM200/201) and
// is deliberately NOT faked here: a synthetic submit pass does not earn
// block-viable. This KAT pins the creds/arm seam that gates that submit.
//
// Header-only over impl/dash/coin/rpc_conf.hpp (pure std); no ltc/pool SCC dep.

#include <gtest/gtest.h>

#include <fstream>
#include <string>

#include <impl/dash/coin/rpc_conf.hpp>

using dash::coin::RpcConf;
using dash::coin::load_rpc_conf;
using dash::coin::apply_endpoint_override;

namespace {
std::string write_conf(const std::string& body)
{
    const std::string path = ::testing::TempDir() + "/dash_rpc_conf_kat.conf";
    std::ofstream(path) << body;
    return path;
}
} // namespace

// dash.conf rpcuser/rpcpassword/rpcport/rpcconnect parse + armed() + userpass().
TEST(DashRpcConf, ParsesCredsEndpointAndArms)
{
    const auto p = write_conf(
        "# dash.conf\n"
        "rpcuser=alice\n"
        "rpcpassword=s3cr3t\n"
        "rpcport=19998\n"
        "rpcconnect=10.0.0.5\n");
    RpcConf c;
    ASSERT_TRUE(load_rpc_conf(p, c));
    EXPECT_EQ(c.user, "alice");
    EXPECT_EQ(c.pass, "s3cr3t");
    EXPECT_EQ(c.port, 19998);
    EXPECT_EQ(c.host, "10.0.0.5");
    EXPECT_TRUE(c.armed());
    EXPECT_EQ(c.userpass(), "alice:s3cr3t");
}

// c2pool aliases + whitespace trim + inline-comment stripping.
TEST(DashRpcConf, AcceptsAliasesAndTrims)
{
    const auto p = write_conf(
        "  # comment line\n"
        "dash_rpc_user = bob \n"
        "dash_rpc_password = pw   # trailing comment\n");
    RpcConf c;
    ASSERT_TRUE(load_rpc_conf(p, c));
    EXPECT_EQ(c.user, "bob");
    EXPECT_EQ(c.pass, "pw");
}

// arm-gating: the single gate main_dash --run consults. No creds OR no port
// keeps the submit arm UNARMED (submit_block_hex never reached).
TEST(DashRpcConf, UnarmedWithoutCredsOrPort)
{
    RpcConf c;                       // defaults: empty creds, port 0
    EXPECT_FALSE(c.armed());
    c.user = "u"; c.pass = "p";      // creds present, port still 0
    EXPECT_FALSE(c.armed());
    c.port = 9998;
    EXPECT_TRUE(c.armed());
}

// --coin-rpc HOST:PORT override (endpoint only; carries no secret). Bare HOST
// leaves the conf/default port untouched.
TEST(DashRpcConf, EndpointOverride)
{
    RpcConf c;
    apply_endpoint_override("192.168.1.9:19998", c);
    EXPECT_EQ(c.host, "192.168.1.9");
    EXPECT_EQ(c.port, 19998);

    RpcConf d;
    d.port = 9998;
    apply_endpoint_override("myhost", d);   // bare host: port preserved
    EXPECT_EQ(d.host, "myhost");
    EXPECT_EQ(d.port, 9998);

    RpcConf e;
    apply_endpoint_override("", e);          // empty arg: no-op
    EXPECT_EQ(e.host, "127.0.0.1");
    EXPECT_EQ(e.port, 0);
}

// A missing conf leaves the struct unarmed (the daemon-less default build path).
TEST(DashRpcConf, MissingFileLeavesUnarmed)
{
    RpcConf c;
    EXPECT_FALSE(load_rpc_conf("/nonexistent/path/dash.conf.xyz", c));
    EXPECT_FALSE(c.armed());
}
