// DGB Scrypt-only coin module — share / consensus-identity fixtures (M3).
// Mirrors src/impl/btc/test + src/impl/ltc/test. Locks the oracle-conformed
// consensus + sharechain-identity params against frstrtr/p2pool-dgb-scrypt
// (IDENTIFIER 4B62545B1A631AFE, PREFIX 1c0553f23ebfcffe). These are the params
// adjudicated CONFORM at prescan-DGB (#131/#137/#141); this guards regressions.
//
// SCOPE (project_v36_dgb_scrypt_only): V36 validates SCRYPT shares only.
// Scrypt-family wire format mirrors LTC; DGB-net identity lives in the params
// asserted below, NOT in the share codec. Captured-block PoW fixtures + multi-
// algo accept-by-continuity vectors are a follow-up slice (see README.txt).

#include <gtest/gtest.h>

#include <impl/dgb/config_pool.hpp>
#include <impl/dgb/config_coin.hpp>
#include <impl/dgb/share.hpp>

// Sharechain-identity: the isolation primitives (PREFIX / IDENTIFIER) are the
// per-coin namespacing boundary — they MUST stay byte-exact to the DGB oracle.
TEST(DGB_share_test, OracleSharechainIdentity)
{
    EXPECT_EQ(dgb::PoolConfig::IDENTIFIER_HEX,     "4b62545b1a631afe");
    EXPECT_EQ(dgb::PoolConfig::DEFAULT_PREFIX_HEX, "1c0553f23ebfcffe");
    EXPECT_EQ(dgb::PoolConfig::TESTNET_IDENTIFIER_HEX, dgb::PoolConfig::IDENTIFIER_HEX);
    EXPECT_EQ(dgb::PoolConfig::TESTNET_PREFIX_HEX,     dgb::PoolConfig::DEFAULT_PREFIX_HEX);
}

// Consensus / protocol params conformed to the oracle (networks/digibyte.py).
TEST(DGB_share_test, OracleConsensusParams)
{
    EXPECT_EQ(dgb::PoolConfig::P2P_PORT,                   5024u);
    EXPECT_EQ(dgb::PoolConfig::SEGWIT_ACTIVATION_VERSION,  35u);
    EXPECT_EQ(dgb::PoolConfig::MINIMUM_PROTOCOL_VERSION,   1700u);
    EXPECT_EQ(dgb::PoolConfig::ADVERTISED_PROTOCOL_VERSION, 3301u);
    EXPECT_EQ(dgb::PoolConfig::SHARE_PERIOD,               15u);
    EXPECT_EQ(dgb::PoolConfig::CHAIN_LENGTH,               2880u);
}

// Pool/share layer timing + bound params — audited CONFORM to the DGB oracle
// this slice (networks/digibyte.py + bitcoin/networks/digibyte.py). These drive
// PPLNS weighting (SPREAD), retarget lookbehind, chain pruning (REAL_CHAIN_LENGTH),
// block-template caps, and the tracker score() denominator (PARENT.BLOCK_PERIOD).
TEST(DGB_share_test, OraclePoolShareLayer)
{
    EXPECT_EQ(dgb::PoolConfig::SPREAD,            24u);        // networks/digibyte.py SPREAD
    EXPECT_EQ(dgb::PoolConfig::TARGET_LOOKBEHIND, 100u);       // TARGET_LOOKBEHIND
    EXPECT_EQ(dgb::PoolConfig::REAL_CHAIN_LENGTH, 2880u);      // REAL_CHAIN_LENGTH = 12*60*60//15
    EXPECT_EQ(dgb::PoolConfig::BLOCK_MAX_SIZE,    32000000u);  // BLOCK_MAX_SIZE
    EXPECT_EQ(dgb::PoolConfig::BLOCK_MAX_WEIGHT,  128000000u); // BLOCK_MAX_WEIGHT

    // tracker score() denominator: work / ((1 - block_rel_height) * BLOCK_PERIOD).
    // PARENT.BLOCK_PERIOD = 75 (Scrypt-algo period), bitcoin/networks/digibyte.py.
    EXPECT_EQ(dgb::CoinParams::BLOCK_PERIOD,      75u);

    // MAX_TARGET = 2**256//2**20 - 1 = 2^236 - 1 (top 20 bits zero, rest ones).
    EXPECT_EQ(dgb::PoolConfig::max_target().GetHex(),
              "00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
}

// v35 donation = forrestv P2PK (4104ffd0…ac, 65-byte pubkey push + CHECKSIG).
// v36 donation = combined P2SH (23-byte). get_donation_script() switches on
// share_version at the SEGWIT/merged boundary.
TEST(DGB_share_test, OracleDonationScript)
{
    ASSERT_EQ(dgb::PoolConfig::DONATION_SCRIPT.size(), 67u);
    EXPECT_EQ(dgb::PoolConfig::DONATION_SCRIPT.front(), 0x41);  // OP_PUSHBYTES_65
    EXPECT_EQ(dgb::PoolConfig::DONATION_SCRIPT[1],      0x04);  // uncompressed pubkey tag
    EXPECT_EQ(dgb::PoolConfig::DONATION_SCRIPT[2],      0xff);
    EXPECT_EQ(dgb::PoolConfig::DONATION_SCRIPT[3],      0xd0);
    EXPECT_EQ(dgb::PoolConfig::DONATION_SCRIPT.back(),  0xac);  // OP_CHECKSIG

    EXPECT_EQ(dgb::PoolConfig::get_donation_script(35).size(), 67u);  // v35 P2PK
    EXPECT_EQ(dgb::PoolConfig::get_donation_script(36).size(), 23u);  // v36 combined P2SH
}

// Address byte versions (D… P2PKH / S… P2SH) — DigiByte mainnet.
TEST(DGB_share_test, AddressVersions)
{
    EXPECT_EQ(dgb::CoinParams::ADDRESS_VERSION,      0x1e);  // 30 — D prefix
    EXPECT_EQ(dgb::CoinParams::ADDRESS_P2SH_VERSION, 0x3f);  // 63 — S prefix
}

// Share-codec link smoke: dgb::load_share is the Scrypt-family wire entrypoint.
// Referencing it forces the dgb OBJECT-lib share TU to link into this test exe,
// build-verifying the pool/share stack (#132→#142) end-to-end.
TEST(DGB_share_test, LoadShareSymbolLinks)
{
    auto fn = static_cast<dgb::ShareType (*)(chain::RawShare&, NetService)>(&dgb::load_share);
    EXPECT_NE(fn, nullptr);
}
