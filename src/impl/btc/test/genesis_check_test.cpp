// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// btc::coin::btc_genesis_hash KATs (#744/#787 B1).
//
// NodeRPC::check() probes getblockheader(btc_genesis_hash(IS_TESTNET)) to
// confirm the external daemon is a real bitcoind on the selected network. The
// pre-fix code hard-coded the LITECOIN genesis, so the mainnet
// `is_main_chain && !has_block` gate always failed -> a permanent 15s reconnect
// loop and a degraded ARM B on mainnet. These KATs pin the correct per-net BTC
// genesis so a future copy-paste drift is caught at build time WITHOUT linking
// the beast transport (mirrors dgb/test/genesis_check_test.cpp).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <string>

#include "../coin/genesis.hpp"

// The historical wrong value: the Litecoin genesis that check() used to probe.
static constexpr const char* LTC_GENESIS =
    "12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2";

TEST(BtcGenesisCheck, MainnetIsBitcoinGenesis) {
    EXPECT_STREQ(btc::coin::btc_genesis_hash(false),
                 "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
}

TEST(BtcGenesisCheck, TestnetIsBitcoinTestnet3Genesis) {
    EXPECT_STREQ(btc::coin::btc_genesis_hash(true),
                 "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943");
}

TEST(BtcGenesisCheck, MainAndTestDiffer) {
    EXPECT_STRNE(btc::coin::btc_genesis_hash(false), btc::coin::btc_genesis_hash(true));
}

// The regression guard: neither per-net probe may be the Litecoin genesis again.
TEST(BtcGenesisCheck, NotTheLitecoinGenesis) {
    EXPECT_STRNE(btc::coin::btc_genesis_hash(false), LTC_GENESIS);
    EXPECT_STRNE(btc::coin::btc_genesis_hash(true),  LTC_GENESIS);
}
