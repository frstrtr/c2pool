// ---------------------------------------------------------------------------
// dgb M3 RPC request-shape regression guard.
//
// Pins the two oracle-conformed external-RPC contract values that NodeRPC
// depends on, BEFORE the deferred wiring (CMake + OBJECT-lib reg + ctor swap)
// lands post-#145 and rpc.cpp finally CI-links. Guards against silent drift of:
//
//   1. the getnetworkinfo["version"] accept floor (oracle p2pool-dgb-scrypt
//      VERSION_CHECK == 82202, DigiByte Core 7.17.2), and
//   2. the getblocktemplate body shape: DGB requires the "segwit" rule AND a
//      SEPARATE top-level "algo":"scrypt" param -- "scrypt" must NOT leak into
//      the rules array (the prior Path-A stub bug rules=["scrypt"]).
//
// Links ONLY the pure SSOT header (rpc_request.hpp) + nlohmann + gtest -- no
// boost::beast/jsonrpccxx transport, so it builds standalone without entering
// the dgb OBJECT lib.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <impl/dgb/coin/rpc_request.hpp>

using namespace dgb::coin;

// --- Daemon-version accept floor (oracle VERSION_CHECK 82202) ---------------

TEST(DgbRpcRequest, VersionFloorIsOracleValue)
{
    EXPECT_EQ(DGB_MIN_DAEMON_VERSION, 82202);  // DigiByte Core 7.17.2
}

TEST(DgbRpcRequest, VersionAtFloorAccepts)
{
    EXPECT_TRUE(daemon_version_acceptable(82202));
}

TEST(DgbRpcRequest, VersionAboveFloorAccepts)
{
    EXPECT_TRUE(daemon_version_acceptable(82203));
    EXPECT_TRUE(daemon_version_acceptable(90000));
}

TEST(DgbRpcRequest, VersionBelowFloorRejects)
{
    EXPECT_FALSE(daemon_version_acceptable(82201));
    EXPECT_FALSE(daemon_version_acceptable(71700));  // old placeholder floor
    EXPECT_FALSE(daemon_version_acceptable(0));
}

// --- getblocktemplate request body shape ------------------------------------

TEST(DgbRpcRequest, GbtCarriesSeparateScryptAlgo)
{
    auto j = make_gbt_request({"segwit"});
    ASSERT_TRUE(j.contains("algo"));
    EXPECT_EQ(j["algo"].get<std::string>(), "scrypt");
}

TEST(DgbRpcRequest, GbtRulesContainSegwit)
{
    auto j = make_gbt_request({"segwit"});
    ASSERT_TRUE(j.contains("rules"));
    ASSERT_TRUE(j["rules"].is_array());
    ASSERT_EQ(j["rules"].size(), 1u);
    EXPECT_EQ(j["rules"][0].get<std::string>(), "segwit");
}

TEST(DgbRpcRequest, ScryptIsAlgoNotRule)
{
    // Regression guard for the Path-A bug: "scrypt" is the mining algorithm,
    // NOT a BIP9 rule -- it must never appear in the rules array.
    auto j = make_gbt_request({"segwit"});
    for (const auto& r : j["rules"])
        EXPECT_NE(r.get<std::string>(), "scrypt");
}

TEST(DgbRpcRequest, GbtPreservesCallerRulesAndForcesScrypt)
{
    auto j = make_gbt_request({"segwit", "!extra"});
    ASSERT_EQ(j["rules"].size(), 2u);
    EXPECT_EQ(j["rules"][0].get<std::string>(), "segwit");
    EXPECT_EQ(j["rules"][1].get<std::string>(), "!extra");
    EXPECT_EQ(j["algo"].get<std::string>(), "scrypt");
}
