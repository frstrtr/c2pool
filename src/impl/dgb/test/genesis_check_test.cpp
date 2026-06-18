// ---------------------------------------------------------------------------
// dgb M3 chain-identity (genesis) regression guard.
//
// Pins the DigiByte genesis hashes that NodeRPC::check() probes via
// getblockheader(dgb_genesis_hash(IS_TESTNET)) to confirm the external
// digibyted is a real DigiByte node on the selected network. These are a
// bucket-1 ISOLATION PRIMITIVE -- coin-identity, KEEP per-coin in v36 AND
// v37, never standardized -- so this guard locks them against accidental
// drift (a copy/paste from another coin, or main<->test swap) BEFORE the
// deferred transport wiring lands post-#145 and rpc.cpp finally CI-links.
//
// Links ONLY the pure SSOT header (rpc_request.hpp) + gtest -- no
// boost::beast/jsonrpccxx transport, so it builds standalone without
// entering the dgb OBJECT lib.
// ---------------------------------------------------------------------------

#include <cstring>

#include <gtest/gtest.h>

#include <impl/dgb/coin/rpc_request.hpp>

using namespace dgb::coin;

// Canonical values from DigiByte Core kernel/chainparams.cpp. Independent
// literals so the test fails loudly if the SSOT constant is ever edited.
static const char* CANON_MAIN =
    "7497ea1b465eb39f1c8f507bc877078fe016d6fcb6dfad3a64c98dcc6e1e8496";
static const char* CANON_TEST =
    "308ea0711d5763be2995670dd9ca9872753561285a84da1d58be58acaa822252";

TEST(DgbGenesis, MainnetHashIsCanonical)
{
    EXPECT_STREQ(DGB_GENESIS_MAIN, CANON_MAIN);
}

TEST(DgbGenesis, TestnetHashIsCanonical)
{
    EXPECT_STREQ(DGB_GENESIS_TEST, CANON_TEST);
}

TEST(DgbGenesis, MainAndTestDiffer)
{
    // Guards against a copy/paste that would make both networks probe the
    // same hash -- a wrong-coin daemon could then pass the testnet check.
    EXPECT_STRNE(DGB_GENESIS_MAIN, DGB_GENESIS_TEST);
}

TEST(DgbGenesis, HashesAre64HexChars)
{
    EXPECT_EQ(std::strlen(DGB_GENESIS_MAIN), 64u);
    EXPECT_EQ(std::strlen(DGB_GENESIS_TEST), 64u);
    for (const char* h : {DGB_GENESIS_MAIN, DGB_GENESIS_TEST})
        for (const char* c = h; *c; ++c)
            EXPECT_TRUE(std::isxdigit(static_cast<unsigned char>(*c))) << "non-hex in " << h;
}

// --- Network selector NodeRPC::check() relies on ---------------------------

TEST(DgbGenesis, SelectorPicksMainnet)
{
    EXPECT_STREQ(dgb_genesis_hash(false), DGB_GENESIS_MAIN);
}

TEST(DgbGenesis, SelectorPicksTestnet)
{
    EXPECT_STREQ(dgb_genesis_hash(true), DGB_GENESIS_TEST);
}

TEST(DgbGenesis, SelectorBranchesDiffer)
{
    EXPECT_STRNE(dgb_genesis_hash(true), dgb_genesis_hash(false));
}
