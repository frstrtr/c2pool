// SPDX-License-Identifier: AGPL-3.0-or-later
// G1 greenlight-gate KAT — DGB net/consensus byte-parity vs the oracle.
//
// FENCED conformance test (no production code touched). This is the test-form
// artifact of greenlight gate G1 (per dgb-greenlight-g0-artifact): it pins the
// fully-assembled dgb::make_coin_params() output — every isolation primitive
// (bucket-1: PREFIX / IDENTIFIER) and every consensus/net constant — against
// values hand-transcribed from the DGB oracle frstrtr/p2pool-dgb-scrypt
// (operator switch-oracle ruling 2026-06-17, Option B):
//   networks/digibyte.py  — coin params, ports, address versions, MAX_TARGET
//   bitcoin/p2p.py:28      — Protocol.VERSION (advertised) = 3501
//   bitcoin/networks ...   — IDENTIFIER 4B62545B1A631AFE, PREFIX, SHARE_PERIOD
//
// NON-CIRCULAR: the expected side below is literal bytes/ints typed from the
// oracle python source, NOT a second read of the same C++ SUT constant. A drift
// in config_coin.hpp / config_pool.hpp that silently diverges from the oracle
// fails here even though every other dgb test (which sources the same SUT
// constant on both sides) stays green.
//
// 3-bucket posture (operator 2026-06-17): IDENTIFIER + PREFIX are bucket-1
// ISOLATION PRIMITIVES — pinned here as the per-coin/per-instance sharechain
// namespacing boundary; this KAT guards them against accidental
// "standardization", it does NOT propose unifying them.
//
// MUST appear in BOTH the ctest registration (this dir CMakeLists.txt) AND the
// build.yml --target allowlist, or it becomes a #143-style NOT_BUILT sentinel.

#include <impl/dgb/params.hpp>

#include <core/coin_params.hpp>

#include <string>

#include <gtest/gtest.h>

namespace {

// ---- Oracle expected values (frstrtr/p2pool-dgb-scrypt, transcribed) --------

// networks/digibyte.py PARENT + pool block
constexpr char     ORACLE_SYMBOL[]            = "DGB";
constexpr uint16_t ORACLE_P2P_PORT            = 5024;   // sharechain P2P
constexpr uint16_t ORACLE_WORKER_PORT         = 5025;   // Stratum
constexpr uint8_t  ORACLE_ADDR_VERSION_MAIN   = 30;     // 0x1e, "D"
constexpr uint8_t  ORACLE_ADDR_P2SH_MAIN      = 63;     // 0x3f, "S"
constexpr uint8_t  ORACLE_ADDR_VERSION_TEST   = 126;    // 0x7e
constexpr uint32_t ORACLE_SHARE_PERIOD        = 15;     // s
constexpr uint32_t ORACLE_CHAIN_LENGTH        = 2880;   // 12h / 15s
constexpr uint32_t ORACLE_SPREAD              = 24;
constexpr uint32_t ORACLE_TARGET_LOOKBEHIND   = 100;
constexpr uint32_t ORACLE_MIN_PROTO_VERSION   = 1400;   // oracle cold floor: p2p.py:153 getattr fallback (digibyte.py sets no MINIMUM_PROTOCOL_VERSION)
constexpr uint32_t ORACLE_ADV_PROTO_VERSION   = 3501;   // p2p.py:28 Protocol.VERSION
constexpr uint32_t ORACLE_SEGWIT_ACT_VERSION  = 35;     // digibyte.py:27
constexpr uint64_t ORACLE_DUST_THRESHOLD      = 100000; // 0.001 DGB

// IDENTIFIER / PREFIX — bucket-1 isolation primitives, same on both nets.
constexpr char ORACLE_IDENTIFIER_HEX[] = "4b62545b1a631afe";
constexpr char ORACLE_PREFIX_HEX[]     = "1c0553f23ebfcffe";

// MAX_TARGET = 2**256 // 2**20 - 1  == 2^236 - 1 (digibyte.py).
// 236 one-bits = 59 'f' nibbles, with the top 20 bits (5 nibbles) zero.
uint256 oracle_max_target() {
    uint256 t;
    t.SetHex(std::string(5, '0') + std::string(59, 'f'));  // 5+59 = 64 nibbles
    return t;
}

TEST(G1OracleByteParity, MainnetNetConstants) {
    core::CoinParams p = dgb::make_coin_params(/*testnet=*/false);

    EXPECT_EQ(p.symbol, ORACLE_SYMBOL);
    EXPECT_EQ(p.p2p_port, ORACLE_P2P_PORT);
    EXPECT_EQ(p.worker_port, ORACLE_WORKER_PORT);
    EXPECT_EQ(p.address_version, ORACLE_ADDR_VERSION_MAIN);
    EXPECT_EQ(p.address_p2sh_version, ORACLE_ADDR_P2SH_MAIN);
    EXPECT_EQ(p.share_period, ORACLE_SHARE_PERIOD);
    EXPECT_EQ(p.chain_length, ORACLE_CHAIN_LENGTH);
    EXPECT_EQ(p.real_chain_length, ORACLE_CHAIN_LENGTH);
    EXPECT_EQ(p.spread, ORACLE_SPREAD);
    EXPECT_EQ(p.target_lookbehind, ORACLE_TARGET_LOOKBEHIND);
    EXPECT_EQ(p.minimum_protocol_version, ORACLE_MIN_PROTO_VERSION);
    EXPECT_EQ(p.advertised_protocol_version, ORACLE_ADV_PROTO_VERSION);
    EXPECT_EQ(p.segwit_activation_version, ORACLE_SEGWIT_ACT_VERSION);
    EXPECT_EQ(p.dust_threshold, ORACLE_DUST_THRESHOLD);
}

TEST(G1OracleByteParity, IsolationPrimitivesPrefixIdentifier) {
    // bucket-1: never standardized; pinned per-coin on both nets.
    core::CoinParams p = dgb::make_coin_params(/*testnet=*/false);
    EXPECT_EQ(p.identifier_hex, ORACLE_IDENTIFIER_HEX);
    EXPECT_EQ(p.prefix_hex, ORACLE_PREFIX_HEX);
    EXPECT_EQ(p.testnet_identifier_hex, ORACLE_IDENTIFIER_HEX);
    EXPECT_EQ(p.testnet_prefix_hex, ORACLE_PREFIX_HEX);
}

TEST(G1OracleByteParity, MaxTargetIs2Pow236Minus1) {
    core::CoinParams p = dgb::make_coin_params(/*testnet=*/false);
    EXPECT_EQ(p.max_target, oracle_max_target());
}

TEST(G1OracleByteParity, TestnetAddressVersionDiverges) {
    // Testnet keeps its own address version but SHARES the isolation primitives.
    core::CoinParams p = dgb::make_coin_params(/*testnet=*/true);
    EXPECT_EQ(p.address_version, ORACLE_ADDR_VERSION_TEST);
    EXPECT_EQ(p.identifier_hex, ORACLE_IDENTIFIER_HEX);
    EXPECT_EQ(p.prefix_hex, ORACLE_PREFIX_HEX);
}

TEST(G1OracleByteParity, DonationScriptVersionGate) {
    // Pre-V36 share -> forrestv P2PK (67B, 0x41 ... 0xac).
    auto pre = dgb::PoolConfig::get_donation_script(/*share_version=*/35);
    ASSERT_EQ(pre.size(), 67u);
    EXPECT_EQ(pre.front(), 0x41);  // OP_PUSHBYTES_65
    EXPECT_EQ(pre.back(),  0xac);  // OP_CHECKSIG
    EXPECT_EQ(pre[1], 0x04);       // uncompressed pubkey marker

    // V36+ share -> combined P2SH 1-of-2 (23B, 0xa9 0x14 <20B> 0x87).
    auto v36 = dgb::PoolConfig::get_donation_script(/*share_version=*/36);
    ASSERT_EQ(v36.size(), 23u);
    EXPECT_EQ(v36[0], 0xa9);       // OP_HASH160
    EXPECT_EQ(v36[1], 0x14);       // push 20
    EXPECT_EQ(v36.back(), 0x87);   // OP_EQUAL
}

} // namespace