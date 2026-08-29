// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// btc::coin::rpc_conf KATs -- bitcoin.conf credential resolution for the
// submitblock RPC BACKUP arm (ARM B of the dual-path broadcaster, #82/#744).
//
// Locks the gate main_btc consults before arming the submitblock backup:
//   - armed() is true ONLY with user + pass + a non-zero port,
//   - the parser reads rpcuser/rpcpassword/rpcport/rpcconnect (and the c2pool
//     btc_rpc_user/btc_rpc_password aliases), honours '#' comments,
//   - a --coin-rpc HOST:PORT endpoint override carries no secret.
// No creds => UNARMED => submit_block_hex returns false LOUDLY (daemonless
// default). Direct twin of the dgb rpc_conf helper (the #82 reference).
//
// Rides the already-allowlisted btc_share_test executable (no build.yml target
// allowlist change; no #137 NOT_BUILT sentinel risk). p2pool-merged-v36
// surface: NONE -- broadcast-config parse only; no PoW/share/PPLNS math.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>
#include <string>

#include "../coin/rpc_conf.hpp"

namespace
{
// Write `body` to a unique temp path under gtest's temp dir and return it.
std::string write_temp_conf(const std::string& tag, const std::string& body)
{
    static int counter = 0;
    std::string path = ::testing::TempDir() + "btc_rpc_conf_" + tag + "_"
                     + std::to_string(counter++) + ".conf";
    std::ofstream f(path);
    f << body;
    f.close();
    return path;
}
} // namespace

// 1) A well-formed bitcoin.conf arms the backup: user+pass+port all resolved.
TEST(BtcRpcConf, WellFormedConfArms)
{
    const std::string path = write_temp_conf("wellformed",
        "rpcuser=alice\n"
        "rpcpassword=s3cr3t\n"
        "rpcport=8332\n"
        "rpcconnect=10.0.0.5\n");
    btc::coin::RpcConf c;
    ASSERT_TRUE(btc::coin::load_rpc_conf(path, c));
    EXPECT_TRUE(c.armed());
    EXPECT_EQ(c.user, "alice");
    EXPECT_EQ(c.pass, "s3cr3t");
    EXPECT_EQ(c.port, 8332);
    EXPECT_EQ(c.host, "10.0.0.5");
    EXPECT_EQ(c.userpass(), "alice:s3cr3t");
    std::remove(path.c_str());
}

// 2) No creds => NOT armed (daemonless default; submit backup stays dark).
TEST(BtcRpcConf, MissingCredsUnarmed)
{
    const std::string path = write_temp_conf("nocreds",
        "# only an endpoint, no secret\n"
        "rpcport=8332\n"
        "rpcconnect=127.0.0.1\n");
    btc::coin::RpcConf c;
    EXPECT_FALSE(btc::coin::load_rpc_conf(path, c));  // false: no user/pass
    EXPECT_FALSE(c.armed());
    std::remove(path.c_str());
}

// 3) A missing file is a clean UNARMED, never a throw.
TEST(BtcRpcConf, MissingFileUnarmed)
{
    btc::coin::RpcConf c;
    EXPECT_FALSE(btc::coin::load_rpc_conf("/nonexistent/path/bitcoin.conf", c));
    EXPECT_FALSE(c.armed());
}

// 4) c2pool aliases + '#' comments are honoured; port still required to arm.
TEST(BtcRpcConf, AliasesAndCommentsNoPortStillUnarmed)
{
    const std::string path = write_temp_conf("aliases",
        "btc_rpc_user=bob    # inline comment stripped\n"
        "btc_rpc_password=hunter2\n");
    btc::coin::RpcConf c;
    ASSERT_TRUE(btc::coin::load_rpc_conf(path, c));  // user+pass found
    EXPECT_EQ(c.user, "bob");
    EXPECT_EQ(c.pass, "hunter2");
    EXPECT_FALSE(c.armed());  // port==0 => not armed until caller fills default
    std::remove(path.c_str());
}

// 5) --coin-rpc HOST:PORT endpoint override (no secret) overrides endpoint only.
TEST(BtcRpcConf, EndpointOverride)
{
    btc::coin::RpcConf c;
    c.user = "u"; c.pass = "p"; c.host = "127.0.0.1"; c.port = 8332;
    btc::coin::apply_endpoint_override("192.168.1.9:18332", c);
    EXPECT_EQ(c.host, "192.168.1.9");
    EXPECT_EQ(c.port, 18332);
    EXPECT_EQ(c.user, "u");   // creds untouched by the endpoint override
    EXPECT_EQ(c.pass, "p");
    EXPECT_TRUE(c.armed());

    // Bare HOST leaves the port at whatever the conf/default supplied.
    btc::coin::apply_endpoint_override("10.1.2.3", c);
    EXPECT_EQ(c.host, "10.1.2.3");
    EXPECT_EQ(c.port, 18332);

    // Empty override is a no-op.
    btc::coin::apply_endpoint_override("", c);
    EXPECT_EQ(c.host, "10.1.2.3");
    EXPECT_EQ(c.port, 18332);
}

// ── #744/#787 B2: a malformed conf must degrade to UNARMED, never abort ──
// The default ~/.bitcoin/bitcoin.conf is read with NO flags, so a junk rpcport
// must not throw std::invalid_argument/out_of_range out of the parser and abort
// the node at startup for an operator who never opted in.

// 6) rpcport=abc (non-numeric): no throw; port stays 0 => UNARMED.
TEST(BtcRpcConf, MalformedPortNoThrowUnarmed) {
    const std::string path = write_temp_conf("badport",
        "rpcuser=alice\n"
        "rpcpassword=s3cr3t\n"
        "rpcport=abc\n");
    btc::coin::RpcConf c;
    EXPECT_NO_THROW({ btc::coin::load_rpc_conf(path, c); });
    EXPECT_EQ(c.port, 0);          // junk ignored, default left for caller
    EXPECT_FALSE(c.armed());       // no port => not armed
    EXPECT_EQ(c.user, "alice");    // creds still parsed
    std::remove(path.c_str());
}

// 7) rpcport out of uint16 range: no throw; port stays 0.
TEST(BtcRpcConf, OutOfRangePortNoThrow) {
    const std::string path = write_temp_conf("bigport",
        "rpcuser=u\nrpcpassword=p\nrpcport=99999\n");
    btc::coin::RpcConf c;
    EXPECT_NO_THROW({ btc::coin::load_rpc_conf(path, c); });
    EXPECT_EQ(c.port, 0);          // 99999 > 65535 rejected (no silent truncation)
    EXPECT_FALSE(c.armed());
    std::remove(path.c_str());
}

// 8) --coin-rpc host:notaport endpoint override: no throw; host applied, port kept.
TEST(BtcRpcConf, MalformedEndpointOverrideNoThrow) {
    btc::coin::RpcConf c;
    c.user = "u"; c.pass = "p"; c.port = 8332;
    EXPECT_NO_THROW({ btc::coin::apply_endpoint_override("10.0.0.9:notaport", c); });
    EXPECT_EQ(c.host, "10.0.0.9");  // host applied
    EXPECT_EQ(c.port, 8332);        // junk port ignored, prior value stands
}
