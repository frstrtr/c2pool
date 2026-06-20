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
#include <impl/dgb/params.hpp>          // make_coin_params — assembled CoinParams SSOT
#include <impl/dgb/coin/rpc_conf.hpp>   // #82 external-daemon RPC creds (digibyte.conf)

#include <cstdio>
#include <fstream>

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

// ── get_desired_version_weights: attempts-weighted, NOT a flat count ─────────
// The check()-phase version-switch gate (share_check step 2) tallies each
// share's desired_version vote weighted by target_to_average_attempts(target)
// (= ShareIndex::work), per canonical p2pool get_desired_version_counts
// (data.py:2651) — NOT one-share-one-vote. Bucket-2 v36-native shared structure
// (must stay byte-identical with p2pool-merged-v36 across all coins). Guard: a
// SINGLE high-difficulty share out-votes TWO low-difficulty shares — exactly the
// property a flat tally (2 vs 1) inverts. test-only, no prod change.
TEST(DGB_share_test, DesiredVersionWeightsByAttempts)
{
    dgb::ShareTracker tracker;

    auto mk = [&](const char* hh, const char* ph, uint64_t dv, uint32_t bits) {
        auto* s = new dgb::MergedMiningShare();
        s->m_hash.SetHex(hh);
        if (ph) s->m_prev_hash.SetHex(ph); else s->m_prev_hash.SetNull();
        s->m_desired_version = dv;
        s->m_bits = bits;
        s->m_max_bits = bits;
        dgb::ShareType st; st = s;
        tracker.add(st);
    };

    // chain: h0 <- h1 (dv=36, easy target => low work) <- h2 (dv=35, hard target
    // => high work). flat count would read dv36=2, dv35=1; attempts read dv35 >>.
    const char* h0 = "00000000000000000000000000000000000000000000000000000000000000a0";
    const char* h1 = "00000000000000000000000000000000000000000000000000000000000000a1";
    const char* h2 = "00000000000000000000000000000000000000000000000000000000000000a2";
    mk(h0, nullptr, 36, 0x1e0fffff);
    mk(h1, h0,      36, 0x1e0fffff);
    mk(h2, h1,      35, 0x1d00ffff);

    uint256 tip; tip.SetHex(h2);
    auto w = tracker.get_desired_version_weights(tip, 100);

    ASSERT_EQ(w.count(35u), 1u);
    ASSERT_EQ(w.count(36u), 1u);

    // Weight per desired_version == sum of ShareIndex::work over its shares,
    // tied directly to the SSOT work fn (no magic literals).
    const uint288 easy_work = chain::target_to_average_attempts(chain::bits_to_target(0x1e0fffff));
    const uint288 hard_work = chain::target_to_average_attempts(chain::bits_to_target(0x1d00ffff));
    EXPECT_EQ(w.at(36u), easy_work + easy_work);  // two equal dv=36 shares
    EXPECT_EQ(w.at(35u), hard_work);              // one dv=35 share

    // Attempts-weighting: the lone high-difficulty dv=35 share outweighs the two
    // low-difficulty dv=36 shares — the exact property a flat count inverts.
    EXPECT_GT(w.at(35u), w.at(36u));
}


// ── Address-encoding + relay-policy SSOT KAT (assembled CoinParams) ─────────
// Pins the values make_coin_params() actually hands the pool, on BOTH nets,
// against the DGB oracle frstrtr/p2pool-dgb-scrypt (switch-oracle Option B).
// Otherwise-unguarded: the mainnet/testnet address bytes + BECH32 HRPs
// (config_coin SSOT) and three values that live ONLY in the params.hpp
// assembly — address_p2sh_version2 (the disabled secondary P2SH prefix),
// worker_port, and dust_threshold. 3-bucket: the address bytes + ports are
// BUCKET-1 isolation/identity primitives (KEEP per-coin, v36 AND v37);
// dust_threshold is local relay policy. test-only, no prod change.
//
// REGRESSION GUARD of note: address_p2sh_version2 MUST stay 0 (disabled). The
// oracle (bitcoin/data.py) accepts exactly {30, 63} and defines no secondary
// P2SH prefix; the prior =5 was an LTC-borrowed artifact. A silent revert to a
// non-zero secondary prefix would re-introduce that artifact — this fails loud.
TEST(DGB_share_test, OracleAddressAndRelayParams)
{
    const core::CoinParams main = dgb::make_coin_params(/*testnet=*/false);
    EXPECT_EQ(main.address_version,       0x1e);      // 30 - D... (P2PKH)
    EXPECT_EQ(main.address_p2sh_version,  0x3f);      // 63 - S... (P2SH)
    EXPECT_EQ(main.address_p2sh_version2, 0x00);      // disabled - oracle has no 2nd P2SH prefix
    EXPECT_EQ(main.bech32_hrp,            "dgb");
    EXPECT_EQ(main.p2p_port,              5024u);     // oracle P2P_PORT (assembled)
    EXPECT_EQ(main.worker_port,           5025u);     // oracle WORKER_PORT
    EXPECT_EQ(main.dust_threshold,        100000u);   // DUST_THRESHOLD = 0.001e8

    const core::CoinParams test = dgb::make_coin_params(/*testnet=*/true);
    EXPECT_EQ(test.address_version,       0x7e);      // 126 (testnet)
    EXPECT_EQ(test.address_p2sh_version,  0x8c);      // 140 (testnet P2SH)
    EXPECT_EQ(test.address_p2sh_version2, 0x00);      // disabled on testnet too
    EXPECT_EQ(test.bech32_hrp,            "dgbt");
}


// ---------------------------------------------------------------------------
// #82 external-daemon submit arm — digibyte.conf credential resolution.
// Guards dgb::coin::load_rpc_conf / apply_endpoint_override / RpcConf::armed():
// the RPC leg of the dual-path broadcaster is armed ONLY when both creds AND a
// port resolve, and the rpcpassword is sourced from-file (never argv). The
// endpoint override carries no secret. Header-only helper, so this lives in the
// already-allowlisted dgb_share_test target (no new gtest binary; avoids #143).
namespace {
std::string write_tmp_conf(const char* tag, const std::string& body)
{
    const std::string path = std::string(::testing::TempDir()) + "/dgb_rpc_conf_" + tag + ".conf";
    std::ofstream(path) << body;
    return path;
}
}

TEST(DGB_rpc_conf, ParsesUserPassPortAndConnect)
{
    const std::string path = write_tmp_conf("full",
        "# digibyte.conf\n"
        "rpcuser=dgbuser\n"
        "rpcpassword=s3cr3t=with=eq\n"   // value may contain '=' after the first
        "rpcport=14024\n"
        "rpcconnect=10.0.0.7\n");
    dgb::coin::RpcConf c;
    EXPECT_TRUE(dgb::coin::load_rpc_conf(path, c));
    EXPECT_EQ(c.user, "dgbuser");
    EXPECT_EQ(c.pass, "s3cr3t=with=eq");
    EXPECT_EQ(c.port, 14024u);
    EXPECT_EQ(c.host, "10.0.0.7");
    EXPECT_TRUE(c.armed());
    EXPECT_EQ(c.userpass(), "dgbuser:s3cr3t=with=eq");
    std::remove(path.c_str());
}

TEST(DGB_rpc_conf, AcceptsC2poolAliasesAndComments)
{
    const std::string path = write_tmp_conf("alias",
        "dgb_rpc_user = aliasuser   # inline comment stripped\n"
        "dgb_rpc_password = aliaspass\n");
    dgb::coin::RpcConf c;
    EXPECT_TRUE(dgb::coin::load_rpc_conf(path, c));
    EXPECT_EQ(c.user, "aliasuser");
    EXPECT_EQ(c.pass, "aliaspass");
    EXPECT_EQ(c.port, 0u);              // no rpcport -> caller fills net default
    EXPECT_FALSE(c.armed());           // armed() requires a non-zero port
    std::remove(path.c_str());
}

TEST(DGB_rpc_conf, MissingPasswordIsNotArmedAndLoadFails)
{
    const std::string path = write_tmp_conf("nopass", "rpcuser=lonely\n");
    dgb::coin::RpcConf c;
    EXPECT_FALSE(dgb::coin::load_rpc_conf(path, c));  // both user+pass required
    EXPECT_FALSE(c.armed());
    std::remove(path.c_str());
}

TEST(DGB_rpc_conf, MissingFileReturnsFalse)
{
    dgb::coin::RpcConf c;
    EXPECT_FALSE(dgb::coin::load_rpc_conf("/nonexistent/dgb/digibyte.conf", c));
    EXPECT_FALSE(c.armed());
}

TEST(DGB_rpc_conf, EndpointOverrideCarriesNoSecret)
{
    dgb::coin::RpcConf c;
    c.user = "u"; c.pass = "p"; c.port = 14024; c.host = "127.0.0.1";
    dgb::coin::apply_endpoint_override("192.168.1.50:15001", c);
    EXPECT_EQ(c.host, "192.168.1.50");
    EXPECT_EQ(c.port, 15001u);
    // host-only override keeps the resolved port
    dgb::coin::apply_endpoint_override("example.host", c);
    EXPECT_EQ(c.host, "example.host");
    EXPECT_EQ(c.port, 15001u);
    // empty override is a no-op; creds untouched (still off the process table)
    dgb::coin::apply_endpoint_override("", c);
    EXPECT_EQ(c.host, "example.host");
    EXPECT_EQ(c.userpass(), "u:p");
}
