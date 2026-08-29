// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// btc::sharechain_net_name isolation KATs.
//
// Regression guard for the .121 standup incident (2026-06-26): under --regtest
// main_btc resets CoinConfig::m_testnet to false (it drives only the parent
// chainparams), so the sharechain LevelDB + P2P-listen namespace -- which had
// resolved off m_testnet ALONE -- silently namespaced to "bitcoin" = MAINNET
// and joined the production p2pool sharechain. A won regtest block would then
// have relayed an on_block_found share to real mainnet peers (a prod touch on
// an isolated VM). The fix evaluates regtest FIRST in a pure helper; these
// KATs lock that ordering so the silent-mainnet-join can never recur.
//
// Rides the already-allowlisted btc_share_test executable -- no build.yml
// --target allowlist change is needed and there is no NOT_BUILT sentinel risk.
// p2pool-merged-v36 surface: NONE (transport namespace, not consensus).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include "../config_coin.hpp"
#include "../config_pool.hpp"

// The incident itself: regtest=true with testnet=false (main_btc resets it).
// This MUST isolate to bitcoin_regtest; the pre-fix code returned "bitcoin".
TEST(RegtestSharechainIsolation, RegtestWithTestnetResetDoesNotJoinMainnet)
{
    EXPECT_EQ(btc::sharechain_net_name(/*regtest=*/true, /*testnet=*/false),
              "bitcoin_regtest");
    // Red-able: if regtest were not checked first, this would be "bitcoin".
    EXPECT_NE(btc::sharechain_net_name(true, false), "bitcoin");
}

// regtest takes precedence even if a testnet flag is somehow also set.
TEST(RegtestSharechainIsolation, RegtestWinsOverTestnet)
{
    EXPECT_EQ(btc::sharechain_net_name(true, true), "bitcoin_regtest");
}

// The two non-regtest paths are unchanged (no regression for prod/testnet).
TEST(RegtestSharechainIsolation, TestnetAndMainnetUnchanged)
{
    EXPECT_EQ(btc::sharechain_net_name(false, true),  "bitcoin_testnet");
    EXPECT_EQ(btc::sharechain_net_name(false, false), "bitcoin");
}

// The three namespaces are pairwise distinct -- no two nets can ever share a
// sharechain LevelDB dir / listen namespace.
TEST(RegtestSharechainIsolation, AllThreeNamespacesDistinct)
{
    const auto rt = btc::sharechain_net_name(true,  false);
    const auto tn = btc::sharechain_net_name(false, true);
    const auto mn = btc::sharechain_net_name(false, false);
    EXPECT_NE(rt, tn);
    EXPECT_NE(rt, mn);
    EXPECT_NE(tn, mn);
}
// ---------------------------------------------------------------------------
// Sharechain bootstrap-source precedence KATs (select_sharechain_bootstrap_mode).
//
// Regression guard for the btc.voidbind federation-dial incident: a node with
// a custom --network-id (federation identity) still loaded the PUBLIC BTC
// p2pool seed list, so it perpetually dialed the open network it can never
// handshake (prefix mismatch), never sharing the federation sharechain. These
// KATs pin the precedence: explicit peers > regtest > custom-net > public.
// ---------------------------------------------------------------------------
using btc::SharechainBootstrapMode;
using btc::select_sharechain_bootstrap_mode;

// Explicit peers (--sharechain-addnode/--p2pool) win over everything, even a
// custom net or regtest also being set.
TEST(SharechainBootstrap, ExplicitPeersWinAlways)
{
    EXPECT_EQ(select_sharechain_bootstrap_mode(true, false, false),
              SharechainBootstrapMode::ExplicitPeers);
    EXPECT_EQ(select_sharechain_bootstrap_mode(true, true,  true),
              SharechainBootstrapMode::ExplicitPeers);
    EXPECT_EQ(select_sharechain_bootstrap_mode(true, false, true),
              SharechainBootstrapMode::ExplicitPeers);
}

// regtest (no explicit peers) → isolated, never the public seeds.
TEST(SharechainBootstrap, RegtestIsolatedWhenNoExplicitPeers)
{
    EXPECT_EQ(select_sharechain_bootstrap_mode(false, true, false),
              SharechainBootstrapMode::RegtestIsolated);
    // regtest beats custom-net when both set but no explicit peers.
    EXPECT_EQ(select_sharechain_bootstrap_mode(false, true, true),
              SharechainBootstrapMode::RegtestIsolated);
}

// The incident itself: a custom network-id with NO explicit peer must NOT
// dial the public seeds — it selects the suppressed mode, not PublicDefault.
TEST(SharechainBootstrap, CustomNetSuppressesPublicSeeds)
{
    EXPECT_EQ(select_sharechain_bootstrap_mode(false, false, true),
              SharechainBootstrapMode::CustomNetSuppressed);
    EXPECT_NE(select_sharechain_bootstrap_mode(false, false, true),
              SharechainBootstrapMode::PublicDefault);
}

// Public net, no explicit peers, not regtest → the historical default path.
TEST(SharechainBootstrap, PublicDefaultUnchanged)
{
    EXPECT_EQ(select_sharechain_bootstrap_mode(false, false, false),
              SharechainBootstrapMode::PublicDefault);
}
