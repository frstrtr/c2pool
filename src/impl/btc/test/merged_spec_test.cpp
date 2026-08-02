// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// btc::parse_merged_spec KATs — NMC PE host-wire slice 3. Pin the c2pool
// --merged SPEC grammar (SYMBOL:CHAIN_ID:HOST:PORT:USER:PASS[:P2P_PORT]) that
// feeds the embedded merged-mined NMC backend. Pure parse — no daemon, no I/O.
// NMC AuxPoW chain_id is 1 (share_tracker maps NMC -> 0x0001); DOGE is 98.
// Rides the already-allowlisted btc_share_test executable — no build.yml change.
// ---------------------------------------------------------------------------
#include <gtest/gtest.h>
#include <impl/btc/coin/merged_spec.hpp>

TEST(BtcMergedSpec, ValidFullSpec) {
    c2pool::merged::AuxChainConfig cfg; std::string err;
    ASSERT_TRUE(btc::parse_merged_spec("NMC:1:192.168.86.29:8336:nmcrpc:secret", cfg, err)) << err;
    EXPECT_EQ(cfg.symbol, "NMC");
    EXPECT_EQ(cfg.chain_id, 1u);
    EXPECT_EQ(cfg.rpc_host, "192.168.86.29");
    EXPECT_EQ(cfg.rpc_port, 8336);
    EXPECT_EQ(cfg.rpc_userpass, "nmcrpc:secret");
    EXPECT_TRUE(cfg.multiaddress);
    EXPECT_EQ(cfg.p2p_port, 0);              // absent 7th field -> disabled
    EXPECT_EQ(cfg.p2p_address, "192.168.86.29");
}

TEST(BtcMergedSpec, OptionalP2PPort) {
    c2pool::merged::AuxChainConfig cfg; std::string err;
    ASSERT_TRUE(btc::parse_merged_spec("NMC:1:127.0.0.1:8336:u:p:8334", cfg, err)) << err;
    EXPECT_EQ(cfg.p2p_port, 8334);
}

TEST(BtcMergedSpec, RejectsTooFewFields) {
    c2pool::merged::AuxChainConfig cfg; std::string err;
    EXPECT_FALSE(btc::parse_merged_spec("NMC:1:127.0.0.1:8336:u", cfg, err));
    EXPECT_FALSE(err.empty());
}

TEST(BtcMergedSpec, RejectsTooManyFields) {
    c2pool::merged::AuxChainConfig cfg; std::string err;
    EXPECT_FALSE(btc::parse_merged_spec("NMC:1:h:8336:u:p:8334:extra", cfg, err));
}

TEST(BtcMergedSpec, RejectsNonNumericChainId) {
    c2pool::merged::AuxChainConfig cfg; std::string err;
    EXPECT_FALSE(btc::parse_merged_spec("NMC:xx:127.0.0.1:8336:u:p", cfg, err));
}

TEST(BtcMergedSpec, RejectsZeroChainId) {
    c2pool::merged::AuxChainConfig cfg; std::string err;
    EXPECT_FALSE(btc::parse_merged_spec("NMC:0:127.0.0.1:8336:u:p", cfg, err));
}

TEST(BtcMergedSpec, RejectsBadPort) {
    c2pool::merged::AuxChainConfig cfg; std::string err;
    EXPECT_FALSE(btc::parse_merged_spec("NMC:1:127.0.0.1:99999:u:p", cfg, err));
}

TEST(BtcMergedSpec, RejectsEmptyHost) {
    c2pool::merged::AuxChainConfig cfg; std::string err;
    EXPECT_FALSE(btc::parse_merged_spec("NMC:1::8336:u:p", cfg, err));
}
