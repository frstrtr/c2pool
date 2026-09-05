// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// dgb::seed_sharechain_bootstrap KAT -- pins the pure sharechain bootstrap-addr
// resolver + builder added for the contabo DGB revival (2026-09-05).
//
// THE INCIDENT: run_node (main_dgb.cpp) hand-builds dgb::Config WITHOUT
// PoolConfig::load() -- the YAML load() was the ONLY populator of
// m_bootstrap_addrs. On master DEFAULT_BOOTSTRAP_HOSTS was ALSO empty AND there
// was no --sharechain-addnode flag, so a public DGB node had 0 outbound
// sharechain seeds and never joined the kr1z1s DGB (scrypt) sharechain. Section 1
// pins the fix's empty -> populated directly: the exact no-explicit-peers/
// mainnet inputs run_node now feeds must yield a NON-empty bootstrap set (the
// broken baseline was 0).
//
// The resolver/builder are PURE (no I/O, no network), so this KAT is header-only
// over config_pool.hpp + <core/netaddress.hpp>. Folded into the allowlisted
// dgb_share_test executable (per the DGB test CMakeLists convention) so it is
// actually built and run -- no NOT_BUILT sentinel.
//
// REWARD-SAFETY: this seam decides ONLY which transport addresses are dialed.
// PREFIX/IDENTIFIER, P2P_PORT, protocol versions, share format, PPLNS and
// coinbase are untouched -- section 6 asserts the compiled-in identity
// constants are the live p2pool-dgb-scrypt oracle values, so a bootstrap edit
// can never silently fork the net.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <core/netaddress.hpp>
#include "../config_pool.hpp"

namespace {
using dgb::PoolConfig;
using dgb::SharechainBootstrapMode;
using dgb::select_sharechain_bootstrap_mode;
using dgb::build_sharechain_bootstrap;

using AddNodes = std::vector<std::pair<std::string, uint16_t>>;
} // namespace

// ---- 1) REGRESSION WITNESS: empty BEFORE seed -> populated AFTER -----------
// The pre-fix live state: run_node never populated m_bootstrap_addrs (empty
// DEFAULT_BOOTSTRAP_HOSTS, no --sharechain-addnode), so it stayed default-empty
// (0 sharechain peers). The fix, fed the exact inputs run_node now uses (no
// explicit peers, mainnet), must produce a NON-empty set -- a proven
// empty(0) -> populated. Deleting the 92.53.224.27 seed (or the seam) flips
// this red.
TEST(DgbSharechainBootstrap, EmptyBeforeSeedPopulatedAfter)
{
    auto after = build_sharechain_bootstrap(
        select_sharechain_bootstrap_mode(/*has_explicit_peers=*/false, /*regtest=*/false),
        AddNodes{});
    EXPECT_FALSE(after.empty());                         // populated AFTER the fix
    EXPECT_GT(after.size(), 0u);
}

// ---- 2) mode selection precedence: explicit > regtest > public ------------
TEST(DgbSharechainBootstrap, ModeSelectionPrecedence)
{
    EXPECT_EQ(select_sharechain_bootstrap_mode(/*explicit=*/true,  /*regtest=*/false),
              SharechainBootstrapMode::ExplicitPeers);
    EXPECT_EQ(select_sharechain_bootstrap_mode(/*explicit=*/true,  /*regtest=*/true),
              SharechainBootstrapMode::ExplicitPeers);   // explicit wins over regtest
    EXPECT_EQ(select_sharechain_bootstrap_mode(/*explicit=*/false, /*regtest=*/true),
              SharechainBootstrapMode::RegtestIsolated);
    EXPECT_EQ(select_sharechain_bootstrap_mode(/*explicit=*/false, /*regtest=*/false),
              SharechainBootstrapMode::PublicDefault);
}

// ---- 3) PublicDefault seeds ALL default hosts on :5024 --------------------
// The kr1z1s DGB sharechain node 92.53.224.27 must be present, dialed at
// P2P_PORT (5024).
TEST(DgbSharechainBootstrap, PublicDefaultSeedsAllHostsOnP2pPort)
{
    auto addrs = build_sharechain_bootstrap(
        SharechainBootstrapMode::PublicDefault, AddNodes{});
    EXPECT_EQ(addrs.size(), PoolConfig::DEFAULT_BOOTSTRAP_HOSTS.size());
    EXPECT_FALSE(addrs.empty());
    bool saw_kr1z1s = false;
    for (const auto& a : addrs) {
        EXPECT_EQ(a.port(), PoolConfig::P2P_PORT);       // every entry on 5024
        if (a.to_string() == "92.53.224.27:5024") saw_kr1z1s = true;
    }
    EXPECT_TRUE(saw_kr1z1s);                              // anchor seed present
}

// ---- 4) ExplicitAddnode pins EXACTLY the given peer(s) --------------------
// The load-bearing contabo revival lever: --sharechain-addnode 92.53.224.27:5024
// (the live kr1z1s DGB sharechain) must be the ONLY dialed peer when pinned.
TEST(DgbSharechainBootstrap, ExplicitAddnodePinsExactly)
{
    AddNodes pin = { {"92.53.224.27", 5024} };
    auto addrs = build_sharechain_bootstrap(
        select_sharechain_bootstrap_mode(/*explicit=*/true, /*regtest=*/false), pin);
    ASSERT_EQ(addrs.size(), 1u);
    EXPECT_EQ(addrs.at(0).to_string(), "92.53.224.27:5024");
}

TEST(DgbSharechainBootstrap, ExplicitAddnodeRepeatableOrderPreserved)
{
    // Repeatable: two pins accumulate, both preserved, order kept, per-pin port.
    AddNodes pins = { {"92.53.224.27", 5024}, {"5.8.79.155", 5030} };
    auto addrs = build_sharechain_bootstrap(
        SharechainBootstrapMode::ExplicitPeers, pins);
    ASSERT_EQ(addrs.size(), 2u);
    EXPECT_EQ(addrs.at(0).to_string(), "92.53.224.27:5024");
    EXPECT_EQ(addrs.at(1).to_string(), "5.8.79.155:5030");   // per-pin port honored
}

// ---- 5) RegtestIsolated is EMPTY (never dial public 5024 seeds) -----------
TEST(DgbSharechainBootstrap, RegtestIsolatedIsEmpty)
{
    auto addrs = build_sharechain_bootstrap(
        SharechainBootstrapMode::RegtestIsolated, AddNodes{});
    EXPECT_TRUE(addrs.empty());
    // Explicit peer STILL wins over regtest (a tuned isolated peer is OK).
    AddNodes pin = { {"127.0.0.1", 15024} };
    auto ex = build_sharechain_bootstrap(
        select_sharechain_bootstrap_mode(/*explicit=*/true, /*regtest=*/true), pin);
    ASSERT_EQ(ex.size(), 1u);
    EXPECT_EQ(ex.at(0).to_string(), "127.0.0.1:15024");
}

// ---- 6) REWARD-SAFETY: sharechain identity constants UNCHANGED -------------
// A bootstrap edit must not touch the values that decide which chain we join.
// These pin the live p2pool-dgb-scrypt oracle DGB sharechain identity: any
// change here would be the fork vector -- this seam leaves them alone.
TEST(DgbSharechainBootstrap, RewardSafeIdentityConstants)
{
    EXPECT_EQ(PoolConfig::P2P_PORT, 5024);
    EXPECT_EQ(PoolConfig::DEFAULT_PREFIX_HEX, "1c0553f23ebfcffe");
    EXPECT_EQ(PoolConfig::IDENTIFIER_HEX,     "4b62545b1a631afe");
    EXPECT_EQ(PoolConfig::MINIMUM_PROTOCOL_VERSION,    1400u);
    EXPECT_EQ(PoolConfig::ADVERTISED_PROTOCOL_VERSION, 3501u);
}
