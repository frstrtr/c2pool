/**
 * Tests for merged mining address resolution:
 *   - Cases 2a-2c: Auto-derivation (LTC P2PKH/P2WPKH/P2SH → merged chain script)
 *   - Case 5: DOGE-as-primary detection (no comma separator)
 *   - Cases 7-9: P2WSH/P2TR non-convertible detection
 *   - Script building correctness for each address type
 *
 * Uses real testnet addresses (valid checksums) sharing the same hash160
 * to verify cross-chain pubkey_hash preservation.
 *
 * All addresses below encode hash160 = cf4e868df4f58a824a7c1dbcc8b4b99dfa7021b0
 */

#include <gtest/gtest.h>
#include <core/address_utils.hpp>
#include <string>
#include <vector>
#include <cstdint>

using namespace core;

// ============================================================================
// Valid testnet addresses — all share hash160 cf4e868df4f58a824a7c1dbcc8b4b99dfa7021b0
// ============================================================================

// LTC testnet bech32 (P2WPKH) — witness v0, 20-byte program
static const std::string LTC_BECH32 = "tltc1qea8gdr057k9gyjnurk7v3d9enha8qgds58ajt0";

// LTC testnet legacy (P2PKH) — version byte 0x6f
static const std::string LTC_P2PKH = "mzR6EpNLy1w1wKw2qHYVeFTWDckQMN8jaa";

// DOGE testnet (P2PKH) — version byte 0x71
static const std::string DOGE_TESTNET = "no6JD2xvPNrmaCDCt8D8cW15UdGHjCF5D1";

// LTC testnet P2SH — version byte 0xc4
static const std::string LTC_P2SH = "2NC9Mw3hqKMKVTAnPuwrarubNiVeapadhcs";

// DOGE mainnet (P2PKH) — version byte 0x1e
static const std::string DOGE_MAINNET = "DQ3EV2E1TQQ3hDe1rJZgN6QnEkszjR1T3x";

// Known hash160 for all above
static const std::string EXPECTED_H160 = "cf4e868df4f58a824a7c1dbcc8b4b99dfa7021b0";

// P2WSH: witness v0, 32-byte script hash (non-convertible)
static const std::string LTC_P2WSH = "tltc1qea8gdr057k9gyjnurk7v3d9enha8qgds42aueh0wluqpzg3n42as8c9e2u";

// P2TR: witness v1, 32-byte tweaked pubkey (non-convertible, bech32m)
static const std::string LTC_P2TR = "tltc1pea8gdr057k9gyjnurk7v3d9enha8qgdszy3rx3z4vemc3xd2hvqqly6uy4";

// ============================================================================
// Suite 1: address_to_hash160 — basic decoding
// ============================================================================

TEST(AddressResolution, DecodeLtcBech32P2WPKH)
{
    std::string atype;
    auto h160 = address_to_hash160(LTC_BECH32, atype);
    EXPECT_EQ(atype, "p2wpkh");
    ASSERT_EQ(h160.size(), 40u);
    EXPECT_EQ(h160, EXPECTED_H160);
}

TEST(AddressResolution, DecodeLtcP2PKH)
{
    std::string atype;
    auto h160 = address_to_hash160(LTC_P2PKH, atype);
    EXPECT_EQ(atype, "p2pkh");
    ASSERT_EQ(h160.size(), 40u);
    EXPECT_EQ(h160, EXPECTED_H160);
}

TEST(AddressResolution, DecodeDogeTestnet)
{
    // DOGE addresses decode successfully — base58check is chain-agnostic
    std::string atype;
    auto h160 = address_to_hash160(DOGE_TESTNET, atype);
    EXPECT_EQ(atype, "p2pkh");
    ASSERT_EQ(h160.size(), 40u);
    EXPECT_EQ(h160, EXPECTED_H160);
}

TEST(AddressResolution, DecodeLtcP2SH)
{
    std::string atype;
    auto h160 = address_to_hash160(LTC_P2SH, atype);
    EXPECT_EQ(atype, "p2sh");
    ASSERT_EQ(h160.size(), 40u);
    EXPECT_EQ(h160, EXPECTED_H160);
}

TEST(AddressResolution, DecodeDogeMainnet)
{
    std::string atype;
    auto h160 = address_to_hash160(DOGE_MAINNET, atype);
    EXPECT_EQ(atype, "p2pkh");
    ASSERT_EQ(h160.size(), 40u);
    EXPECT_EQ(h160, EXPECTED_H160);
}

TEST(AddressResolution, InvalidAddressReturnsEmpty)
{
    std::string atype;
    auto h160 = address_to_hash160("not_a_real_address", atype);
    EXPECT_TRUE(h160.empty());
}

TEST(AddressResolution, EmptyAddressReturnsEmpty)
{
    std::string atype;
    auto h160 = address_to_hash160("", atype);
    EXPECT_TRUE(h160.empty());
}

// ============================================================================
// Suite 2: P2WSH/P2TR detection (Cases 7-9)
// ============================================================================

TEST(AddressResolution, DetectP2WSH)
{
    std::string atype;
    auto h160 = address_to_hash160(LTC_P2WSH, atype);
    EXPECT_EQ(atype, "p2wsh");
    EXPECT_TRUE(h160.empty());  // non-convertible — no hash160 returned
}

TEST(AddressResolution, DetectP2TR)
{
    std::string atype;
    auto h160 = address_to_hash160(LTC_P2TR, atype);
    EXPECT_EQ(atype, "p2tr");
    EXPECT_TRUE(h160.empty());  // non-convertible
}

// ============================================================================
// Suite 3: Cases 2a-2c — auto-derivation script building
// ============================================================================

TEST(AddressResolution, AutoDeriveFromP2PKH)
{
    // Case 2a: LTC P2PKH → merged P2PKH script
    std::string atype;
    auto h160 = address_to_hash160(LTC_P2PKH, atype);
    ASSERT_EQ(h160.size(), 40u);
    ASSERT_EQ(atype, "p2pkh");

    auto script = hash160_to_merged_script(h160, atype);
    // P2PKH: 76 a9 14 <20-byte hash> 88 ac
    ASSERT_EQ(script.size(), 25u);
    EXPECT_EQ(script[0], 0x76);  // OP_DUP
    EXPECT_EQ(script[1], 0xa9);  // OP_HASH160
    EXPECT_EQ(script[2], 0x14);  // PUSH 20 bytes
    EXPECT_EQ(script[23], 0x88); // OP_EQUALVERIFY
    EXPECT_EQ(script[24], 0xac); // OP_CHECKSIG
}

TEST(AddressResolution, AutoDeriveFromP2WPKH)
{
    // Case 2b: LTC P2WPKH → merged P2PKH script (DOGE doesn't support SegWit)
    std::string atype;
    auto h160 = address_to_hash160(LTC_BECH32, atype);
    ASSERT_EQ(h160.size(), 40u);
    ASSERT_EQ(atype, "p2wpkh");

    auto script = hash160_to_merged_script(h160, atype);
    // P2WPKH addr_type falls through to P2PKH script in merged context
    ASSERT_EQ(script.size(), 25u);
    EXPECT_EQ(script[0], 0x76);  // OP_DUP — P2PKH, not 0x00 (P2WPKH)
    EXPECT_EQ(script[1], 0xa9);  // OP_HASH160
    EXPECT_EQ(script[2], 0x14);  // PUSH 20 bytes
    EXPECT_EQ(script[23], 0x88); // OP_EQUALVERIFY
    EXPECT_EQ(script[24], 0xac); // OP_CHECKSIG
}

TEST(AddressResolution, AutoDeriveFromP2SH)
{
    // Case 2c: LTC P2SH → merged P2SH script
    std::string atype;
    auto h160 = address_to_hash160(LTC_P2SH, atype);
    ASSERT_EQ(h160.size(), 40u);
    ASSERT_EQ(atype, "p2sh");

    auto script = hash160_to_merged_script(h160, atype);
    // P2SH: a9 14 <20-byte hash> 87
    ASSERT_EQ(script.size(), 23u);
    EXPECT_EQ(script[0], 0xa9);  // OP_HASH160
    EXPECT_EQ(script[1], 0x14);  // PUSH 20 bytes
    EXPECT_EQ(script[22], 0x87); // OP_EQUAL
}

// ============================================================================
// Suite 4: Cross-chain hash160 preservation
// ============================================================================

TEST(AddressResolution, Hash160IdenticalAcrossChains)
{
    // All addresses (LTC bech32, LTC P2PKH, DOGE testnet, LTC P2SH, DOGE mainnet)
    // share the same hash160 — this is what makes auto-derivation work
    std::string at1, at2, at3, at4, at5;
    auto h1 = address_to_hash160(LTC_BECH32, at1);
    auto h2 = address_to_hash160(LTC_P2PKH, at2);
    auto h3 = address_to_hash160(DOGE_TESTNET, at3);
    auto h4 = address_to_hash160(LTC_P2SH, at4);
    auto h5 = address_to_hash160(DOGE_MAINNET, at5);

    ASSERT_EQ(h1.size(), 40u);
    EXPECT_EQ(h1, h2);
    EXPECT_EQ(h2, h3);
    EXPECT_EQ(h3, h4);
    EXPECT_EQ(h4, h5);
}

TEST(AddressResolution, MergedScriptsShareHash160Bytes)
{
    // Case 5: DOGE hash160 → LTC P2PKH script has same hash160 bytes as DOGE script
    std::string atype;
    auto h160 = address_to_hash160(DOGE_TESTNET, atype);
    ASSERT_EQ(h160.size(), 40u);

    auto ltc_script = hash160_to_merged_script(h160, "p2pkh");
    auto doge_script = hash160_to_merged_script(h160, atype);
    ASSERT_EQ(ltc_script.size(), 25u);
    ASSERT_EQ(doge_script.size(), 25u);

    // Both scripts use the same hash160 (bytes 3-22)
    for (int i = 3; i < 23; ++i)
        EXPECT_EQ(ltc_script[i], doge_script[i]);
}

// ============================================================================
// Suite 5: is_address_for_chain — chain identification
// ============================================================================

TEST(AddressResolution, IdentifyLtcBech32)
{
    std::vector<std::string> ltc_hrps = {"ltc", "tltc"};
    std::vector<uint8_t> ltc_versions = {0x30, 0x32, 0x05, 0x6f, 0xc4, 0x3a};
    EXPECT_TRUE(is_address_for_chain(LTC_BECH32, ltc_hrps, ltc_versions));
}

TEST(AddressResolution, IdentifyLtcP2PKH)
{
    std::vector<std::string> ltc_hrps = {"ltc", "tltc"};
    std::vector<uint8_t> ltc_versions = {0x30, 0x32, 0x05, 0x6f, 0xc4, 0x3a};
    EXPECT_TRUE(is_address_for_chain(LTC_P2PKH, ltc_hrps, ltc_versions));
}

TEST(AddressResolution, IdentifyDogeNotLtc)
{
    std::vector<std::string> ltc_hrps = {"ltc", "tltc"};
    std::vector<uint8_t> ltc_versions = {0x30, 0x32, 0x05, 0x6f, 0xc4, 0x3a};
    // DOGE testnet version 0x71 is NOT in LTC version list
    EXPECT_FALSE(is_address_for_chain(DOGE_TESTNET, ltc_hrps, ltc_versions));
}

TEST(AddressResolution, IdentifyDogeTestnetChain)
{
    std::vector<std::string> doge_hrps = {};
    std::vector<uint8_t> doge_versions = {0x1e, 0x16, 0x71};
    EXPECT_TRUE(is_address_for_chain(DOGE_TESTNET, doge_hrps, doge_versions));
}

TEST(AddressResolution, IdentifyDogeMainnetChain)
{
    std::vector<std::string> doge_hrps = {};
    std::vector<uint8_t> doge_versions = {0x1e, 0x16, 0x71};
    EXPECT_TRUE(is_address_for_chain(DOGE_MAINNET, doge_hrps, doge_versions));
}

TEST(AddressResolution, DogeMainnetNotIdentifiedAsLtc)
{
    // DOGE mainnet version 0x1e is not in LTC versions
    std::vector<std::string> ltc_hrps = {"ltc", "tltc"};
    std::vector<uint8_t> ltc_versions = {0x30, 0x32, 0x05, 0x6f, 0xc4, 0x3a};
    EXPECT_FALSE(is_address_for_chain(DOGE_MAINNET, ltc_hrps, ltc_versions));
}

// ============================================================================
// Suite 6: address_to_script — unified conversion
// ============================================================================

TEST(AddressResolution, ScriptFromBech32)
{
    auto script = address_to_script(LTC_BECH32);
    // P2WPKH: 00 14 <20-byte witness program>
    ASSERT_EQ(script.size(), 22u);
    EXPECT_EQ(script[0], 0x00);  // witness version 0
    EXPECT_EQ(script[1], 0x14);  // 20-byte program
}

TEST(AddressResolution, ScriptFromP2PKH)
{
    auto script = address_to_script(LTC_P2PKH);
    // P2PKH: 76 a9 14 <20-byte hash> 88 ac
    ASSERT_EQ(script.size(), 25u);
    EXPECT_EQ(script[0], 0x76);
}

TEST(AddressResolution, ScriptFromDogeAddress)
{
    // DOGE address also produces a valid script (for Case 5 LTC payout)
    auto script = address_to_script(DOGE_TESTNET);
    ASSERT_EQ(script.size(), 25u);
    EXPECT_EQ(script[0], 0x76);  // P2PKH
}

TEST(AddressResolution, ScriptFromP2SH)
{
    auto script = address_to_script(LTC_P2SH);
    // P2SH: a9 14 <20-byte hash> 87
    ASSERT_EQ(script.size(), 23u);
    EXPECT_EQ(script[0], 0xa9);  // OP_HASH160
}

TEST(AddressResolution, ScriptFromInvalidReturnsEmpty)
{
    auto script = address_to_script("invalid_address");
    EXPECT_TRUE(script.empty());
}

// ============================================================================
// Suite 7: End-to-end auto-derivation scenarios
// ============================================================================

TEST(AddressResolution, Case2b_MergedScriptIsP2PKH_NotP2WPKH)
{
    // When auto-deriving DOGE from LTC bech32, the merged script must be P2PKH
    // because DOGE doesn't support SegWit. hash160_to_merged_script treats
    // "p2wpkh" as P2PKH (the else clause).
    std::string atype;
    auto h160 = address_to_hash160(LTC_BECH32, atype);
    ASSERT_EQ(atype, "p2wpkh");

    auto merged_script = hash160_to_merged_script(h160, atype);
    ASSERT_EQ(merged_script.size(), 25u);
    EXPECT_EQ(merged_script[0], 0x76);  // OP_DUP → P2PKH, NOT 0x00 (witness)
}

TEST(AddressResolution, Case2c_MergedScriptIsP2SH)
{
    // P2SH auto-derivation preserves script type
    std::string atype;
    auto h160 = address_to_hash160(LTC_P2SH, atype);
    ASSERT_EQ(atype, "p2sh");

    auto merged_script = hash160_to_merged_script(h160, atype);
    ASSERT_EQ(merged_script.size(), 23u);
    EXPECT_EQ(merged_script[0], 0xa9);  // OP_HASH160 → P2SH
}

TEST(AddressResolution, Cases7_9_P2WSH_NoMergedScript)
{
    // P2WSH address → address_to_hash160 returns empty → no merged script possible
    std::string atype;
    auto h160 = address_to_hash160(LTC_P2WSH, atype);

    EXPECT_TRUE(h160.empty());
    EXPECT_EQ(atype, "p2wsh");
    auto script = hash160_to_merged_script(h160, atype);
    EXPECT_TRUE(script.empty());
}

TEST(AddressResolution, Cases7_9_P2TR_NoMergedScript)
{
    // P2TR address → no merged script possible
    std::string atype;
    auto h160 = address_to_hash160(LTC_P2TR, atype);

    EXPECT_TRUE(h160.empty());
    EXPECT_EQ(atype, "p2tr");
    auto script = hash160_to_merged_script(h160, atype);
    EXPECT_TRUE(script.empty());
}

TEST(AddressResolution, ConvertibleCheckP2WPKH)
{
    // P2WPKH is convertible (20-byte witness program)
    std::string atype;
    auto h160 = address_to_hash160(LTC_BECH32, atype);
    EXPECT_EQ(atype, "p2wpkh");
    EXPECT_FALSE(h160.empty());
    bool convertible = (atype == "p2pkh" || atype == "p2wpkh" || atype == "p2sh");
    EXPECT_TRUE(convertible);
}

TEST(AddressResolution, ConvertibleCheckP2WSH)
{
    // P2WSH is NOT convertible
    std::string atype;
    auto h160 = address_to_hash160(LTC_P2WSH, atype);
    EXPECT_EQ(atype, "p2wsh");
    bool convertible = (atype == "p2pkh" || atype == "p2wpkh" || atype == "p2sh");
    EXPECT_FALSE(convertible);
}

TEST(AddressResolution, ConvertibleCheckP2TR)
{
    // P2TR is NOT convertible
    std::string atype;
    auto h160 = address_to_hash160(LTC_P2TR, atype);
    EXPECT_EQ(atype, "p2tr");
    bool convertible = (atype == "p2pkh" || atype == "p2wpkh" || atype == "p2sh");
    EXPECT_FALSE(convertible);
}
