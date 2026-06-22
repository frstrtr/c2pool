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

#include <algorithm>
#include <array>

#include <impl/dgb/config_pool.hpp>
#include <impl/dgb/config_coin.hpp>
#include <impl/dgb/share.hpp>
#include <impl/dgb/share_tracker.hpp>   // DensePPLNSWindow — V36 decayed-PPLNS SSOT
#include <impl/dgb/coin/pplns_weight_walk.hpp> // SSOT: PPLNS step-1 tracker walk (shared emission/verify)
#include <impl/dgb/params.hpp>          // make_coin_params — assembled CoinParams SSOT
#include <impl/dgb/coin/rpc_conf.hpp>   // #82 external-daemon RPC creds (digibyte.conf)
#include <impl/dgb/auto_ratchet.hpp> // Phase B: mint-side share-version ratchet
#include <impl/dgb/auto_ratchet_wire.hpp> // Phase B: production wire-in (base_version=35)
#include <impl/dgb/run_loop_mint.hpp>     // Phase B: worker->mint adapter (re-landed #294)
#include <unistd.h>                  // getpid (AutoRatchet KAT temp state file)

#include <cstdio>
#include <set>
#include <string>
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

// SOFTFORKS_REQUIRED — DGB-distinctive softfork-signalling set. reservealgo
// and odo are DigiByte-unique (absent from BTC/LTC); a silent drop here makes
// the embedded daemon mis-signal softfork requirements vs the oracle network.
// Oracle SSOT: frstrtr/p2pool-dgb-scrypt networks/digibyte.py:25
//   set([nversionbips,csv,segwit,reservealgo,odo,taproot])
TEST(DGB_share_test, OracleSoftforksRequired)
{
    const std::set<std::string> kExpected = {
        "nversionbips", "csv", "segwit", "reservealgo", "odo", "taproot"
    };
    EXPECT_EQ(dgb::PoolConfig::SOFTFORKS_REQUIRED, kExpected);
    // Loud guard on the DGB-unique members + cardinality (catches add OR drop).
    EXPECT_EQ(dgb::PoolConfig::SOFTFORKS_REQUIRED.count("reservealgo"), 1u);
    EXPECT_EQ(dgb::PoolConfig::SOFTFORKS_REQUIRED.count("odo"),         1u);
    EXPECT_EQ(dgb::PoolConfig::SOFTFORKS_REQUIRED.size(),               6u);
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

// v36 combined-donation P2SH — FULL 23-byte pin (bucket-2 standardization).
// OracleDonationScript above pins only the SIZE of the v36 path; a drift in the
// 20-byte hash160 would slip past it. This locks the exact bytes get_donation_
// script(36) emits: OP_HASH160 PUSH20 <hash160> OP_EQUAL, where the hash160 is
// the canonical FLAG6 unified cross-coin v36 donation (1-of-2 forrestv+c2pool
// dev key). 3-bucket rule: the v36 donation target is BUCKET 2 (v36-native
// shared structure), so this hash is byte-identical across ALL v36 coins — the
// same 8c627262… as src/impl/ltc/config_pool.hpp COMBINED_DONATION_SCRIPT.
// Guards against a coin-local fork of the donation target during the transition.
TEST(DGB_share_test, V36CombinedDonationScriptBytes)
{
    // hash160 of the FLAG6 1-of-2 P2MS redeem script (forrestv + c2pool dev).
    static constexpr std::array<uint8_t, 23> kExpected = {
        0xa9, 0x14,                                       // OP_HASH160 PUSH20
        0x8c, 0x62, 0x72, 0x62, 0x1d, 0x89, 0xe8, 0xfa,
        0x52, 0x6d, 0xd8, 0x6a, 0xcf, 0xf6, 0x0c, 0x71,
        0x36, 0xbe, 0x8e, 0x85,
        0x87                                              // OP_EQUAL
    };

    const auto got = dgb::PoolConfig::get_donation_script(36);
    ASSERT_EQ(got.size(), kExpected.size());
    for (size_t i = 0; i < kExpected.size(); ++i)
        EXPECT_EQ(got[i], kExpected[i]) << "donation byte " << i << " drifted";

    // The raw constant the switch returns must match too (no copy divergence).
    EXPECT_TRUE(std::equal(kExpected.begin(), kExpected.end(),
                           dgb::PoolConfig::COMBINED_DONATION_SCRIPT.begin()));
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

// ── compute_pplns_weight_walk() SSOT contract KAT ───────────────────────────
// The PPLNS step-1 tracker walk is now ONE helper shared by the share-
// VERIFICATION path (generate_share_transaction) and the per-connection Stratum
// coinbase EMISSION path (build_connection_coinbase producer seam). Value-level
// faithfulness of the lift is proven by the unchanged generate_share_transaction
// fixtures (they route through the helper now); this KAT independently locks the
// helper's CONTRACT so a later edit that breaks the emission path is caught even
// where no verifier test covers it:
//   (1) it forwards verbatim to get_v36_decayed_cumulative_weights on the V36
//       path (byte-identical weights/totals), and
//   (2) it returns an empty, safe result (no throw) when the parent is null or
//       absent from the chain — the "safe coinbase-only / empty job" the seam
//       relies on while the tip is unknown.
TEST(DGB_share_test, WeightWalkSSOTContract)
{
    const core::CoinParams params = dgb::make_coin_params(/*testnet=*/false);

    dgb::ShareTracker tracker;
    auto mk = [&](const char* hh, const char* ph, uint32_t bits) {
        auto* s = new dgb::MergedMiningShare();
        s->m_hash.SetHex(hh);
        if (ph) s->m_prev_hash.SetHex(ph); else s->m_prev_hash.SetNull();
        s->m_bits = bits;
        s->m_max_bits = bits;
        dgb::ShareType st; st = s;
        tracker.add(st);
    };
    const char* h0 = "00000000000000000000000000000000000000000000000000000000000000b0";
    const char* h1 = "00000000000000000000000000000000000000000000000000000000000000b1";
    const char* h2 = "00000000000000000000000000000000000000000000000000000000000000b2";
    mk(h0, nullptr,    0x1e0fffff);
    mk(h1, h0,         0x1e0fffff);
    mk(h2, h1,         0x1e0fffff);

    uint256 tip; tip.SetHex(h2);
    const auto chain_len = static_cast<int32_t>(params.real_chain_length);

    // (1) V36 path forwards verbatim to the tracker's decayed-weights SSOT.
    uint288 unlimited_weight;
    unlimited_weight.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    const auto direct = tracker.get_v36_decayed_cumulative_weights(tip, chain_len, unlimited_weight);
    const auto via_helper = dgb::coin::compute_pplns_weight_walk(
        tracker, tip, /*block_bits=*/0x1e0fffff, params, /*use_v36_pplns=*/true);
    EXPECT_EQ(via_helper.weights,               direct.weights);
    EXPECT_EQ(via_helper.total_weight,          direct.total_weight);
    EXPECT_EQ(via_helper.total_donation_weight, direct.total_donation_weight);

    // (2a) null parent -> empty, safe (no throw).
    const auto null_walk = dgb::coin::compute_pplns_weight_walk(
        tracker, uint256::ZERO, 0x1e0fffff, params, /*use_v36_pplns=*/true);
    EXPECT_TRUE(null_walk.weights.empty());
    EXPECT_TRUE(null_walk.total_weight.IsNull());
    EXPECT_TRUE(null_walk.total_donation_weight.IsNull());

    // (2b) parent absent from the chain -> empty, safe (no throw).
    uint256 absent; absent.SetHex(
        "00000000000000000000000000000000000000000000000000000000deadbeef");
    const auto absent_walk = dgb::coin::compute_pplns_weight_walk(
        tracker, absent, 0x1e0fffff, params, /*use_v36_pplns=*/true);
    EXPECT_TRUE(absent_walk.weights.empty());
    EXPECT_TRUE(absent_walk.total_weight.IsNull());
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

// -- Sharechain isolation-primitive SSOT KAT (assembled CoinParams) ----------
// Pins the two network-namespacing values make_coin_params() hands the pool --
// identifier_hex (sharechain IDENTIFIER) and prefix_hex (P2P message PREFIX) --
// against the DGB oracle frstrtr/p2pool-dgb-scrypt, on BOTH nets. These are the
// peer/sharechain namespacing + multi-instance isolation boundary.
//
// 3-bucket rule (v36 standardization): identifier_hex / prefix_hex are
// BUCKET-1 ISOLATION PRIMITIVES. KEEP per-coin AND per-pool-instance, in v36
// AND v37 -- the v37 unified multichain datastructure unifies the CODE, NOT
// these namespaces (each ParentChainInstance keeps its own PREFIX/IDENTIFIER).
// TRAP: never "standardize"/unify these toward a cross-coin value. A silent
// drift to the LTC prefix/identifier (the LTC-borrowed-artifact failure mode)
// would collapse DGB onto the LTC sharechain namespace -- this fails loud.
// test-only, no prod change.
TEST(DGB_share_test, OracleSharechainIsolationPrimitives)
{
    const core::CoinParams p = dgb::make_coin_params(/*testnet=*/false);
    // mainnet + testnet carriers are assembled unconditionally (params.hpp)
    EXPECT_EQ(p.identifier_hex,         "4b62545b1a631afe");  // oracle IDENTIFIER
    EXPECT_EQ(p.prefix_hex,             "1c0553f23ebfcffe");  // oracle PREFIX
    EXPECT_EQ(p.testnet_identifier_hex, "4b62545b1a631afe");  // oracle (same on testnet)
    EXPECT_EQ(p.testnet_prefix_hex,     "1c0553f23ebfcffe");  // oracle (same on testnet)

    // active_*() selectors must resolve to the same isolation namespace.
    core::CoinParams m = p; m.is_testnet = false;
    EXPECT_EQ(m.active_identifier_hex(), "4b62545b1a631afe");
    EXPECT_EQ(m.active_prefix_hex(),     "1c0553f23ebfcffe");
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

// ----------------------------------------------------------------------------
// AutoRatchet (mint-side share-version ratchet) — Phase B pool/share.
// Bucket-2 v36-native shared structure (standardized cross-coin toward v37).
// These cases pin the threshold constants + bootstrap/persistence semantics
// and, critically, prove the DGB VOTING-output version is the oracle baseline
// parameter (base_version_), NOT the ltc hardcode target-1. The live baseline
// value itself is a [decision-needed] vs frstrtr/p2pool-dgb-scrypt; the module
// stays unwired (surface-for-tap) until that lands.
// ----------------------------------------------------------------------------

TEST(DGB_share_test, AutoRatchetThresholdsMatchCanonical)
{
    EXPECT_EQ(dgb::AutoRatchet::ACTIVATION_THRESHOLD,    95);
    EXPECT_EQ(dgb::AutoRatchet::DEACTIVATION_THRESHOLD,  50);
    EXPECT_EQ(dgb::AutoRatchet::CONFIRMATION_MULTIPLIER,  2);
    EXPECT_EQ(dgb::AutoRatchet::SWITCH_THRESHOLD,        60);
}

// The DGB divergence: base_version must be honored as a parameter, never the
// ltc target-1 hardcode. Compile default keeps the module buildable.
TEST(DGB_share_test, AutoRatchetBaseVersionParameterized)
{
    dgb::AutoRatchet def("", 36);          // default: target-1
    EXPECT_EQ(def.target_version(), 36);
    EXPECT_EQ(def.base_version(),   35);

    dgb::AutoRatchet older("", 36, 33);    // DGB oracle baseline override
    EXPECT_EQ(older.target_version(), 36);
    EXPECT_EQ(older.base_version(),   33);
    EXPECT_EQ(older.state(), dgb::RatchetState::VOTING);
}

// Bootstrap with no chain: VOTING node votes target but still MINTS the
// baseline version (an empty/just-started tracker must not skip ahead).
TEST(DGB_share_test, AutoRatchetBootstrapMintsBaselineWhileVoting)
{
    dgb::AutoRatchet ar("", 36, 33);
    dgb::ShareTracker tracker;
    auto [mint, vote] = ar.get_share_version(tracker, uint256{}); // null best hash
    EXPECT_EQ(mint, 33);   // baseline, NOT 35, NOT 36
    EXPECT_EQ(vote, 36);   // always vote for target
    EXPECT_EQ(ar.state(), dgb::RatchetState::VOTING);
}

// State persists across restart via the JSON state file.
TEST(DGB_share_test, AutoRatchetStatePersistsAcrossRestart)
{
    std::string path = std::string("/tmp/dgb_autoratchet_kat_") +
                       std::to_string(::getpid()) + ".json";
    std::remove(path.c_str());
    {
        // Seed a CONFIRMED state file.
        nlohmann::json j;
        j["state"] = "confirmed";
        j["activated_at"] = 1;
        j["activated_height"] = 2;
        j["confirmed_at"] = 3;
        j["confirm_count"] = 4;
        j["target_version"] = 36;
        j["base_version"] = 33;
        std::ofstream f(path);
        f << j.dump(2);
    }
    dgb::AutoRatchet ar(path, 36, 33);
    EXPECT_EQ(ar.state(), dgb::RatchetState::CONFIRMED);
    // CONFIRMED bootstrap (no chain) mints the target version.
    dgb::ShareTracker tracker;
    auto [mint, vote] = ar.get_share_version(tracker, uint256{});
    EXPECT_EQ(mint, 36);
    EXPECT_EQ(vote, 36);
    std::remove(path.c_str());
}

// ----------------------------------------------------------------------------
// Production wire-in (auto_ratchet_wire.hpp). The DGB baseline [decision-needed]
// is RESOLVED: oracle frstrtr/p2pool-dgb-scrypt @22761e7 mints share VERSION=35
// (SUCCESSOR=None), so base_version=35. These KATs pin that constant where it
// enters production code, so a future edit that regresses it to the ltc
// hardcode fails loudly.
// ----------------------------------------------------------------------------
TEST(DGB_share_test, AutoRatchetWireBaselineConstantsFromOracle)
{
    EXPECT_EQ(dgb::DGB_BASE_VERSION,   35);
    EXPECT_EQ(dgb::DGB_TARGET_VERSION, 36);

    auto ar = dgb::make_dgb_ratchet();
    EXPECT_EQ(ar.base_version(),   35);   // oracle 22761e7, NOT a hardcode coincidence
    EXPECT_EQ(ar.target_version(), 36);
    EXPECT_EQ(ar.state(), dgb::RatchetState::VOTING);
}

// A freshly-started production node votes V36 but MINTS the V35 baseline — it
// must not skip ahead of the network on an empty tracker.
TEST(DGB_share_test, AutoRatchetWireBootstrapMints35Votes36)
{
    auto ar = dgb::make_dgb_ratchet();
    dgb::ShareTracker tracker;
    auto [mint, vote] = dgb::dgb_select_mint_versions(ar, tracker, uint256{});
    EXPECT_EQ(mint, 35);   // baseline share version (oracle)
    EXPECT_EQ(vote, 36);   // always vote target
    EXPECT_EQ(ar.state(), dgb::RatchetState::VOTING);
}

// ----------------------------------------------------------------------------
// run_loop_mint.hpp — Phase B worker->mint adapter (re-landed #294 helper).
// The adapter maps a ShareAccept submission's raw header/coinbase bytes into
// create_local_share()'s arguments, stamping the ratchet-selected {mint, vote}
// version pair. These KATs pin the novel logic: the 80-byte header parse and the
// fail-closed guard. The version-selection delegation is pinned by the
// AutoRatchetWire* tests above; create_local_share's own insertion path is
// covered by its existing fixtures.
// ----------------------------------------------------------------------------

// Local stand-in for DGBWorkSource::MintShareInputs — the adapter is duck-typed
// on the inputs so this TU need not pull the stratum work_source in.
struct MintInputsKAT {
    std::vector<unsigned char> header_bytes;
    std::vector<unsigned char> coinbase_bytes;
    uint64_t                   subsidy = 0;
    uint256                    prev_share;
    std::vector<uint256>       merkle_branches;
    std::vector<unsigned char> payout_script;
    bool                       segwit_active = false;
};

TEST(DGB_run_loop_mint, ParseMinHeader80RoundTrip)
{
    dgb::coin::BlockHeaderType hdr;
    hdr.m_version        = 0x20000000u;        // version bits | SCRYPT marker shape
    hdr.m_previous_block = uint256S(
        "00000000000000000000000000000000000000000000000000000000deadbeef");
    hdr.m_merkle_root    = uint256S(
        "00000000000000000000000000000000000000000000000000000000cafef00d");
    hdr.m_timestamp      = 0x5f5e1000u;
    hdr.m_bits           = 0x1e0ffff0u;
    hdr.m_nonce          = 0x12345678u;

    PackStream packed = pack<dgb::coin::BlockHeaderType>(hdr);
    std::vector<unsigned char> bytes(
        reinterpret_cast<unsigned char*>(packed.data()),
        reinterpret_cast<unsigned char*>(packed.data()) + packed.size());
    ASSERT_EQ(bytes.size(), 80u);  // 4+32+32+4+4+4

    auto small = dgb::parse_min_header_80(bytes);
    ASSERT_TRUE(small.has_value());
    EXPECT_EQ(small->m_version,        0x20000000u);
    EXPECT_EQ(small->m_previous_block, hdr.m_previous_block);
    EXPECT_EQ(small->m_timestamp,      0x5f5e1000u);
    EXPECT_EQ(small->m_bits,           0x1e0ffff0u);
    EXPECT_EQ(small->m_nonce,          0x12345678u);
}

TEST(DGB_run_loop_mint, ParseMinHeaderShortFailsClosed)
{
    EXPECT_FALSE(dgb::parse_min_header_80({}).has_value());
    EXPECT_FALSE(dgb::parse_min_header_80(std::vector<unsigned char>(79, 0)).has_value());
}

// A malformed (short) header returns NULL uint256 WITHOUT touching the tracker —
// and exercises the template instantiation of mint_local_share_with_ratchet
// against master's create_local_share signature (compile+link drift guard).
TEST(DGB_run_loop_mint, AdapterFailsClosedOnShortHeader)
{
    dgb::ShareTracker tracker;
    auto params  = dgb::make_coin_params(/*testnet=*/false);
    auto ratchet = dgb::make_dgb_ratchet();

    MintInputsKAT in;
    in.header_bytes = std::vector<unsigned char>(40, 0);  // too short -> fail-closed

    uint256 h = dgb::mint_local_share_with_ratchet(in, tracker, params, ratchet);
    EXPECT_TRUE(h.IsNull());
}
