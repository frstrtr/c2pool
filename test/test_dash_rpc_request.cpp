// ---------------------------------------------------------------------------
// DASH launcher-slice-3 RPC request-shape regression guard.
//
// Pins the oracle-conformed external-dashd-RPC contract values NodeRPC depends
// on, guarding against silent drift of:
//
//   1. the getnetworkinfo["version"] accept floor (Dash Core 0.17 line, the
//      first returning the DIP3/DIP4 masternode + coinbase_payload GBT fields),
//   2. the getblocktemplate body shape: DASH is X11 with NO segwit, so -- unlike
//      DGB -- the body carries NO "algo" param and injects NO "segwit" rule
//      (the KEY DASH<->DGB divergence), and
//   3. the DASH chain-identity genesis hashes (mainnet/testnet) check() probes.
//
// Links ONLY the pure SSOT header (rpc_request.hpp) + nlohmann + gtest -- no
// boost::beast/jsonrpccxx transport, so it builds standalone without the dash
// RPC transport TU.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <impl/dash/coin/rpc_request.hpp>

using namespace dash::coin;

// --- Daemon-version accept floor (Dash Core 0.17 = 170000) ------------------

TEST(DashRpcRequest, VersionFloorIsOracleValue)
{
    EXPECT_EQ(DASH_MIN_DAEMON_VERSION, 170000);  // Dash Core 0.17.0.0
}

TEST(DashRpcRequest, VersionAtFloorAccepts)
{
    EXPECT_TRUE(daemon_version_acceptable(170000));
}

TEST(DashRpcRequest, VersionAboveFloorAccepts)
{
    EXPECT_TRUE(daemon_version_acceptable(170001));
    EXPECT_TRUE(daemon_version_acceptable(190100));  // Dash Core 0.19.1
}

TEST(DashRpcRequest, VersionBelowFloorRejects)
{
    EXPECT_FALSE(daemon_version_acceptable(169999));
    EXPECT_FALSE(daemon_version_acceptable(120300));  // pre-DIP3 line
    EXPECT_FALSE(daemon_version_acceptable(0));
}

// --- getblocktemplate request body shape (DASH = X11, NO segwit) ------------

TEST(DashRpcRequest, GbtCarriesNoAlgoParam)
{
    // Regression guard for the DGB divergence: DASH is X11, NOT scrypt -- the
    // body must NEVER carry an "algo" key (that is DGB-only).
    auto j = make_gbt_request();
    EXPECT_FALSE(j.contains("algo"));
}

TEST(DashRpcRequest, GbtDefaultRulesAreEmpty)
{
    // DASH has no segwit, so the default GBT carries an empty rules array (no
    // injected "segwit" rule). dashd's base template already supplies the
    // masternode/superblock + coinbasevalue/coinbase_payload fields.
    auto j = make_gbt_request();
    ASSERT_TRUE(j.contains("rules"));
    ASSERT_TRUE(j["rules"].is_array());
    EXPECT_EQ(j["rules"].size(), 0u);
}

TEST(DashRpcRequest, GbtNeverInjectsSegwitRule)
{
    auto j = make_gbt_request();
    for (const auto& r : j["rules"])
        EXPECT_NE(r.get<std::string>(), "segwit");
}

TEST(DashRpcRequest, GbtPreservesCallerRulesVerbatim)
{
    auto j = make_gbt_request({"!extra", "custom"});
    ASSERT_EQ(j["rules"].size(), 2u);
    EXPECT_EQ(j["rules"][0].get<std::string>(), "!extra");
    EXPECT_EQ(j["rules"][1].get<std::string>(), "custom");
    EXPECT_FALSE(j.contains("algo"));
}

// --- chain-identity genesis hashes ------------------------------------------

TEST(DashRpcRequest, GenesisHashesAreDashChainparams)
{
    EXPECT_STREQ(DASH_GENESIS_MAIN,
        "00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6");
    EXPECT_STREQ(DASH_GENESIS_TEST,
        "00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c");
}

TEST(DashRpcRequest, GenesisSelectorPicksByNetwork)
{
    EXPECT_STREQ(dash_genesis_hash(false), DASH_GENESIS_MAIN);
    EXPECT_STREQ(dash_genesis_hash(true),  DASH_GENESIS_TEST);
}
