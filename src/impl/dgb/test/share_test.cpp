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
#include <impl/dgb/share_tracker.hpp>   // DensePPLNSWindow — V36 decayed-PPLNS SSOT

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

// ── V36 decayed-PPLNS bit-exact KAT ───────────────────────────────────────
// Pins DensePPLNSWindow's decay constants + weight recurrence to the V36 MASTER
// (frstrtr/p2pool-merged-v36 data.py get_decayed_cumulative_weights) — NOT the
// legacy flat-weight oracle (that path is pre-v36 compat, replaced in the
// transition). 3-bucket: decayed-PPLNS = BUCKET 2 v36-native shared structure
// (DGB == ltc == merged-v36 ref). Ground truth re-derived independently with
// bigint integer math mirroring the exact fixed-point ops (DECAY_PRECISION=40,
// LN2_MICRO=693147, half_life=max(chain_len/4,1), iterative mul128_shift). This
// guard fails loudly if any decay constant or the weight math drifts.
TEST(DGB_share_test, DecayedPPLNSWeightsKAT)
{
    using W = dgb::DensePPLNSWindow;

    // chain_len = 8 -> half_life = max(8/4,1) = 2. Pin the per-step factor and
    // the full depth-0..7 decay table against the independent bigint oracle.
    W::init_decay_table(8);
    EXPECT_EQ(W::s_decay_per, 718450034647ull);
    ASSERT_EQ(W::s_decay_table.size(), 8u);
    EXPECT_EQ(W::s_decay_table[0], 1099511627776ull);  // == DECAY_SCALE = 2^40
    EXPECT_EQ(W::s_decay_table[1], 718450034647ull);
    EXPECT_EQ(W::s_decay_table[2], 469454291564ull);
    EXPECT_EQ(W::s_decay_table[3], 306753874646ull);
    EXPECT_EQ(W::s_decay_table[4], 200441110671ull);
    EXPECT_EQ(W::s_decay_table[5], 130973533401ull);
    EXPECT_EQ(W::s_decay_table[6], 85581577522ull);
    EXPECT_EQ(W::s_decay_table[7], 55921270664ull);

    // Hand-built window (depth 0 = newest). att kept small so every product
    // stays < 2^64 and the expected weights are exact uint64 literals.
    std::vector<unsigned char> A{0xAA}, B{0xBB}, C{0xCC};
    dgb::DensePPLNSWindow win;
    win.m_entries.push_back({uint288(1000000ull), 0u,     A});  // depth 0
    win.m_entries.push_back({uint288(1000000ull), 6553u,  B});  // depth 1
    win.m_entries.push_back({uint288(2000000ull), 0u,     A});  // depth 2
    win.m_entries.push_back({uint288(500000ull),  65535u, C});  // depth 3 (full donation)

    auto w = win.compute_v36_weights();

    // Per-script address weight: A = depth0 + depth2, B = depth1, C = 0 (full
    // donation consumed the weight). Totals from the same re-derivation.
    EXPECT_EQ(w.weights.at(A),           121497433620ull);
    EXPECT_EQ(w.weights.at(B),           38540372332ull);
    EXPECT_EQ(w.weights.at(C),           0ull);
    EXPECT_EQ(w.total_weight,            173461511355ull);
    EXPECT_EQ(w.total_donation_weight,   13423705403ull);
}
