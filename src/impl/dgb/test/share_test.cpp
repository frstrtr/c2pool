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
#include <impl/dgb/coin/pplns_payout_split.hpp> // #328 SSOT: weights -> payout outputs (invariance tie-in)
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
    EXPECT_EQ(dgb::PoolConfig::MINIMUM_PROTOCOL_VERSION,   1400u);
    EXPECT_EQ(dgb::PoolConfig::ADVERTISED_PROTOCOL_VERSION, 3501u);  // oracle p2p.py:28 Protocol.VERSION (was wrongly 3301)
    EXPECT_EQ(dgb::PoolConfig::SHARE_PERIOD,               15u);
    EXPECT_EQ(dgb::PoolConfig::CHAIN_LENGTH,               2880u);
}

// G1 version-semantics guard: the OUTBOUND version handshake must ADVERTISE our
// capability (oracle frstrtr/p2pool-dgb-scrypt p2p.py:28 Protocol.VERSION = 3501),
// NOT the accept-floor. The cold accept-floor (oracle p2p.py:153 getattr fallback = 1400) stays the
// inbound reject threshold (node.cpp handle_version). These are two distinct
// fields per p2pool: send_version(version=self.VERSION); reject if version<NEW_MIN.
// Regression caught: send_version previously fed minimum_protocol_version (accept-floor)
// into the version field, so a mature oracle network (MINIMUM_PROTOCOL_VERSION
// ratcheted to 3500) would reject us as "peer too old".
TEST(DGB_share_test, OracleAdvertisedVsAcceptFloorProtocolVersion)
{
    const core::CoinParams main = dgb::make_coin_params(/*testnet=*/false);
    EXPECT_EQ(main.advertised_protocol_version, 3501u);  // oracle p2p.py VERSION (what we SEND)
    EXPECT_EQ(main.minimum_protocol_version,    1400u);  // oracle cold floor 1400 (p2p.py:153 getattr fallback)
    // We must advertise ABOVE the floor so a mature oracle net (floor->3500) accepts us.
    EXPECT_GT(main.advertised_protocol_version, main.minimum_protocol_version);
    EXPECT_GE(main.advertised_protocol_version, 3500u);

    // NOTE: testnet coverage is asserted via the net-independent PoolConfig
    // constant below rather than make_coin_params(true) -- the testnet builder
    // leaks a global max_target that corrupts later mainnet-expecting tests if
    // it runs mid-suite (harmless in prod: one net is built per process).
    EXPECT_EQ(dgb::PoolConfig::ADVERTISED_PROTOCOL_VERSION, 3501u);
    EXPECT_EQ(dgb::PoolConfig::MINIMUM_PROTOCOL_VERSION,    1400u);
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

// ── PPLNS weight-walk VALUE-INVARIANCE (before-vs-after) differential KAT ────
// SAME BAR as the #328 payout-split invariance KAT: prove the #333 lift of
// generate_share_transaction() step-1 into dgb::coin::compute_pplns_weight_walk()
// moves ZERO weight. We embed the PRE-REFACTOR inline walk here VERBATIM
// (transcribed line-for-line from the share_check.hpp generate_share_transaction()
// body that commit a5c23b7fb removed) as legacy_inline_weight_walk(), and assert
// the helper reproduces it weight-for-weight — per-script weights, total_weight
// AND total_donation_weight — across a battery exercising BOTH PPLNS branches
// (V36 decay / pre-V36 grandparent-start + max_weight cap), the donation split,
// zero-addr-weight shares (full-donation), the insufficient-depth guard (throw),
// null/absent parents, and a chain that EXCEEDS the real_chain_length window.
// Then BOTH weight maps are fed through the #328 payout-split SSOT and the
// resulting outputs + donation asserted byte-identical — closing the end-to-end
// "no payout satoshi drifts between emission and verification" proof.
//
// COVERAGE NOTE (no silent cap): the >4000-distinct-OUTPUT truncation
// (PPLNS_MAX_OUTPUTS) is proven on the payout-split side by the #328 KAT
// (PplnsPayoutSplitInvariance, case n=4096). Here the weight-walk "window" is
// the real_chain_length share cap; the window case below drives the walk past it
// on testnet params (window=400) to prove the cap truncates the walk identically
// before vs after the lift.

// Verbatim transcription of share_check.hpp generate_share_transaction() step 1
// as it stood BEFORE commit a5c23b7fb (the #333 weight-walk lift). The only
// adaptation: block_bits is taken as a parameter (the helper extracted exactly
// share.m_min_header.m_bits into this same parameter) and the three result
// fields are returned in the deduced CumulativeWeights instead of assigned to
// generate_share_transaction()'s locals.
template <typename TrackerT>
static auto legacy_inline_weight_walk(
    TrackerT& tracker, const uint256& prev_hash, uint32_t block_bits,
    const core::CoinParams& params, bool use_v36_pplns)
    -> decltype(tracker.get_v36_decayed_cumulative_weights(
           prev_hash, std::int32_t{0}, std::declval<const uint288&>()))
{
    using Result = decltype(tracker.get_v36_decayed_cumulative_weights(
        prev_hash, std::int32_t{0}, std::declval<const uint288&>()));
    Result out{};

    if (!prev_hash.IsNull() && tracker.chain.contains(prev_hash))
    {
        auto chain_len = static_cast<int32_t>(params.real_chain_length);
        {
            auto pplns_height = tracker.chain.get_height(prev_hash);
            auto pplns_last = tracker.chain.get_last(prev_hash);
            if (!(pplns_height >= chain_len || pplns_last.IsNull()))
                throw std::invalid_argument(
                    "share chain not long enough for PPLNS verification (height="
                    + std::to_string(pplns_height) + " need="
                    + std::to_string(chain_len) + ")");
        }

        auto block_target = chain::bits_to_target(block_bits);
        auto max_weight = chain::target_to_average_attempts(block_target)
                          * params.spread * 65535;

        if (use_v36_pplns) {
            uint288 unlimited_weight;
            unlimited_weight.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            auto result = tracker.get_v36_decayed_cumulative_weights(prev_hash, chain_len, unlimited_weight);
            out.weights = std::move(result.weights);
            out.total_weight = result.total_weight;
            out.total_donation_weight = result.total_donation_weight;
        } else {
            uint256 pplns_start;
            tracker.chain.get(prev_hash).share.invoke([&](auto* s) {
                pplns_start = s->m_prev_hash;  // grandparent
            });
            auto available = tracker.chain.get_height(prev_hash);
            auto walk_count = static_cast<int32_t>(
                std::max(0, std::min(chain_len, available) - 1));

            if (!pplns_start.IsNull() && tracker.chain.contains(pplns_start) && walk_count > 0) {
                auto result = tracker.get_cumulative_weights(pplns_start, walk_count, max_weight);
                out.weights = std::move(result.weights);
                out.total_weight = result.total_weight;
                out.total_donation_weight = result.total_donation_weight;
            }
        }
    }
    return out;
}

namespace {
// Build a share into the tracker. prev==nullptr => null parent (resolved chain
// genesis). bits drives per-share work (target_to_average_attempts); donation in
// [0,65535] drives the addr/donation weight split (65535 => zero addr weight).
inline void add_walk_share(dgb::ShareTracker& tracker, const uint256& hh,
                           const uint256* ph, uint32_t bits, uint16_t donation)
{
    auto* s = new dgb::MergedMiningShare();
    s->m_hash = hh;
    if (ph) s->m_prev_hash = *ph; else s->m_prev_hash.SetNull();
    s->m_bits = bits;
    s->m_max_bits = bits;
    s->m_min_header.m_bits = bits;
    s->m_donation = donation;
    dgb::ShareType st; st = s;
    tracker.add(st);
}
inline uint256 hx(const std::string& tail) {
    uint256 v; v.SetHex(std::string(64 - tail.size(), '0') + tail); return v;
}
} // namespace

TEST(DGB_share_test, WeightWalkValueInvarianceBattery)
{
    const core::CoinParams params = dgb::make_coin_params(/*testnet=*/false);
    const uint32_t bb = 0x1e0fffff;  // block-header bits feeding the pre-V36 cap

    auto assert_walk_identical =
        [&](dgb::ShareTracker& tk, const uint256& prev, bool v36, const char* tag) {
            const auto legacy = legacy_inline_weight_walk(tk, prev, bb, params, v36);
            const auto helper = dgb::coin::compute_pplns_weight_walk(tk, prev, bb, params, v36);
            EXPECT_EQ(helper.weights,               legacy.weights)               << tag << " weights";
            EXPECT_EQ(helper.total_weight,          legacy.total_weight)          << tag << " total_weight";
            EXPECT_EQ(helper.total_donation_weight, legacy.total_donation_weight) << tag << " donation_weight";

            // End-to-end: identical weights => identical payout split (the #328
            // SSOT), proven on the SAME inputs both paths feed.
            std::vector<unsigned char> finder = helper.weights.empty() ? std::vector<unsigned char>{} : helper.weights.begin()->first;
            for (uint64_t subsidy : {uint64_t(0), uint64_t(625000000)}) {
                auto sp_h = dgb::coin::compute_pplns_payout_split(
                    helper.weights, helper.total_weight, subsidy, v36, finder);
                auto sp_l = dgb::coin::compute_pplns_payout_split(
                    legacy.weights, legacy.total_weight, subsidy, v36, finder);
                EXPECT_EQ(sp_h.payout_outputs,  sp_l.payout_outputs)  << tag << " payout_outputs s=" << subsidy;
                EXPECT_EQ(sp_h.donation_amount, sp_l.donation_amount) << tag << " donation s=" << subsidy;
            }
        };

    // Resolved chain g <- a <- b <- c (g.prev null). Mixed donation incl. 0 and
    // full-donation (65535 => that share contributes ZERO addr weight) and
    // varied bits (varied per-share work).
    {
        dgb::ShareTracker tk;
        uint256 g = hx("c0"), a = hx("c1"), b = hx("c2"), c = hx("c3");
        add_walk_share(tk, g, nullptr, 0x1e0fffff, 0);
        add_walk_share(tk, a, &g,      0x1e07ffff, 32767);
        add_walk_share(tk, b, &a,      0x1e0fffff, 65535);   // zero addr-weight share
        add_walk_share(tk, c, &b,      0x1d00ffff, 100);
        assert_walk_identical(tk, c, /*v36=*/true,  "v36-basic");
        assert_walk_identical(tk, c, /*v36=*/false, "preV36-basic(grandparent+cap)");

        // Donation weight is genuinely exercised (>0) so the donation field is
        // not a trivial zero on both sides.
        const auto w = dgb::coin::compute_pplns_weight_walk(tk, c, bb, params, true);
        EXPECT_FALSE(w.total_donation_weight.IsNull()) << "battery must exercise non-zero donation weight";
        EXPECT_FALSE(w.total_weight.IsNull())          << "battery must exercise non-zero total weight";
    }

    // prev points at genesis directly => pre-V36 grandparent is null => empty
    // (both), even though prev IS in the chain.
    {
        dgb::ShareTracker tk;
        uint256 g = hx("d0"), a = hx("d1");
        add_walk_share(tk, g, nullptr, 0x1e0fffff, 0);
        add_walk_share(tk, a, &g,      0x1e0fffff, 0);
        assert_walk_identical(tk, g, /*v36=*/false, "preV36-grandparent-null");
    }

    // null parent / absent parent => empty, no throw (both).
    {
        dgb::ShareTracker tk;
        uint256 g = hx("e0");
        add_walk_share(tk, g, nullptr, 0x1e0fffff, 0);
        assert_walk_identical(tk, uint256::ZERO, true, "null-parent");
        assert_walk_identical(tk, hx("deadbeef"), true, "absent-parent");
    }

    // Insufficient-depth guard: a chain whose oldest share points at a NON-null
    // hash absent from the tracker (so chain.get_last(prev) is non-null) and
    // whose height < real_chain_length MUST throw — identically, both paths.
    {
        dgb::ShareTracker tk;
        uint256 root_missing = hx("beef"), a = hx("f1"), b = hx("f2");
        add_walk_share(tk, a, &root_missing, 0x1e0fffff, 0);  // a.prev absent => get_last non-null
        add_walk_share(tk, b, &a,            0x1e0fffff, 0);
        EXPECT_THROW(legacy_inline_weight_walk(tk, b, bb, params, true), std::invalid_argument)
            << "legacy guard must throw on insufficient depth";
        EXPECT_THROW(dgb::coin::compute_pplns_weight_walk(tk, b, bb, params, true), std::invalid_argument)
            << "helper guard must throw identically";
    }

    // Exceeds the real_chain_length window: testnet params (window=400); build a
    // resolved chain LONGER than the window and prove the walk caps identically.
    {
        const core::CoinParams tn = dgb::make_coin_params(/*testnet=*/true);
        const int32_t window = static_cast<int32_t>(tn.real_chain_length);  // 400
        dgb::ShareTracker tk;
        uint256 prev; prev.SetNull();
        uint256 tip;
        for (int i = 0; i < window + 5; ++i) {
            char buf[16]; std::snprintf(buf, sizeof(buf), "%x", 0x9000 + i);
            uint256 h = hx(buf);
            add_walk_share(tk, h, (i == 0 ? nullptr : &prev),
                           0x1e0fffff, static_cast<uint16_t>((i * 7919) % 65535));
            prev = h; tip = h;
        }
        const auto legacy = legacy_inline_weight_walk(tk, tip, bb, tn, /*v36=*/true);
        const auto helper = dgb::coin::compute_pplns_weight_walk(tk, tip, bb, tn, /*v36=*/true);
        EXPECT_EQ(helper.weights,               legacy.weights)               << "window weights";
        EXPECT_EQ(helper.total_weight,          legacy.total_weight)          << "window total_weight";
        EXPECT_EQ(helper.total_donation_weight, legacy.total_donation_weight) << "window donation_weight";
    }
}

// ── #429 follow-on: ShareTracker delegation byte-identity over {2,4,8} ───────
// #429 lifted the per-version tally accumulation into the desired_version_tally
// SSOT (accumulate_version_weights / accumulate_version_counts) WITHOUT rewiring
// ShareTracker. This slice rewires get_desired_version_weights() (the CONSENSUS
// 60%-by-work switch gate input) and its flat-count diagnostic sibling
// get_desired_version_counts() to delegate into that SSOT, keeping the
// chain-walk + lookbehind clamp inline. This KAT proves the rewire is
// value-identical NON-CIRCULARLY: the expected maps are derived from first
// principles (production chain::target_to_average_attempts over the known input
// bits, and a hand counted flat tally) — NOT from the SSOT under test — over
// chains of exactly 2, 4 and 8 shares (the {2,4,8} anchors).
TEST(DGB_share_test, DesiredVersionTallyDelegationByteIdentity)
{
    struct In { uint64_t dv; uint32_t bits; };

    auto run = [](const std::vector<In>& shares, const char* tag) {
        dgb::ShareTracker tracker;
        std::vector<uint256> hashes;
        for (size_t i = 0; i < shares.size(); ++i) {
            char buf[16]; std::snprintf(buf, sizeof(buf), "%zx", 0x4290 + i);
            uint256 h = hx(buf);
            auto* sh = new dgb::MergedMiningShare();
            sh->m_hash = h;
            if (i == 0) sh->m_prev_hash.SetNull(); else sh->m_prev_hash = hashes.back();
            sh->m_desired_version = shares[i].dv;
            sh->m_bits = shares[i].bits;
            sh->m_max_bits = shares[i].bits;
            dgb::ShareType st; st = sh;
            tracker.add(st);
            hashes.push_back(h);
        }
        const uint256& tip = hashes.back();

        // Expected, hand-derived from first principles (not via the SSOT):
        //  counts  = flat occurrence per desired_version
        //  weights = sum of production work per desired_version
        std::map<uint64_t, int32_t> want_counts;
        std::map<uint64_t, uint288> want_weights;
        for (const auto& in : shares) {
            want_counts[in.dv] += 1;
            const uint288 w = chain::target_to_average_attempts(chain::bits_to_target(in.bits));
            want_weights[in.dv] = want_weights[in.dv] + w;
        }

        const auto got_counts  = tracker.get_desired_version_counts(tip, 1000);
        const auto got_weights = tracker.get_desired_version_weights(tip, 1000);
        EXPECT_EQ(got_counts,  want_counts)  << tag << " counts (flat, diag)";
        EXPECT_EQ(got_weights, want_weights) << tag << " weights (consensus gate)";
    };

    // 2 shares: split versions, equal work => flat-count and weight agree on keys
    run({{36, 0x1e0fffff}, {35, 0x1e0fffff}}, "anchor-2");

    // 4 shares: 3x dv=36 (easy) vs 1x dv=35 (hard) — the exact case where a flat
    // count (36 leads 3:1) inverts under work-weighting (35 outweighs).
    run({{36, 0x1e0fffff}, {36, 0x1e0fffff}, {35, 0x1d00ffff}, {36, 0x1e0fffff}}, "anchor-4");

    // 8 shares: three versions, mixed difficulty, repeated keys.
    run({{35, 0x1d00ffff}, {36, 0x1e0fffff}, {36, 0x1e07ffff}, {37, 0x1e0fffff},
         {35, 0x1e0fffff}, {36, 0x1d00ffff}, {37, 0x1e07ffff}, {36, 0x1e0fffff}},
        "anchor-8");

    // Lookbehind clamp stays inline & correct: a window shorter than the chain
    // tallies ONLY the clamped tail, and a height/<=0 guard yields an empty map.
    {
        dgb::ShareTracker tracker;
        uint256 g = hx("7a0"), a = hx("7a1"), b = hx("7a2");
        auto mk = [&](const uint256& h, const uint256* ph, uint64_t dv) {
            auto* sh = new dgb::MergedMiningShare();
            sh->m_hash = h;
            if (ph) sh->m_prev_hash = *ph; else sh->m_prev_hash.SetNull();
            sh->m_desired_version = dv; sh->m_bits = 0x1e0fffff; sh->m_max_bits = 0x1e0fffff;
            dgb::ShareType st; st = sh; tracker.add(st);
        };
        mk(g, nullptr, 35); mk(a, &g, 36); mk(b, &a, 36);
        EXPECT_TRUE(tracker.get_desired_version_counts(b, 0).empty()) << "clamp<=0 empty";
        EXPECT_TRUE(tracker.get_desired_version_weights(b, 0).empty()) << "clamp<=0 empty";
        auto c2 = tracker.get_desired_version_counts(b, 2);   // tail of 2 => both dv=36
        ASSERT_EQ(c2.size(), 1u); EXPECT_EQ(c2.at(36u), 2);
    }
}

// ============================================================================
// WorkRefHashAssembler — prospective-work RefHashParams assembler KAT.
//
// Pins dgb::coin::make_work_ref_hash_params() (coin/work_ref_hash.hpp): the
// tracker-free SSOT that assembles the ~25-field RefHashParams a per-connection
// Stratum coinbase commits to, lifting the field-for-field mapping out of
// share_check.hpp create_local_share() / create_local_share_v35().
//
// EMISSION == VERIFICATION: for a fixed set of prospective-work inputs we build
// a RefHashParams TWO independent ways —
//   (E) via the new assembler make_work_ref_hash_params() (the EMISSION path), and
//   (V) a verbatim field-build mirroring how create_local_share() populates the
//       ref preimage (the VERIFICATION reference) —
// then run BOTH through the SAME verifier primitive compute_ref_hash_for_work()
// and assert the resulting ref_hash is byte-identical. A divergence on any of
// the ~25 fields (payout-identity classification, V35 address derivation, the
// V36/V35 conditionals, the no-segwit placeholder) would split the two
// ref_hashes — exactly the Stratum OP_RETURN mismatch the assembler exists to
// prevent. compute_ref_hash_for_work() is itself the byte-exact oracle the share
// verifier uses (share_init_verify / generate_share_transaction), so equality
// here is emission==verification by construction.
//
// Covers: V36 no-segwit (the #336 placeholder branch), V36 with-segwit, V35
// (the address-VarStr path), and all three payout-script identity classes.
// ============================================================================

#include <impl/dgb/coin/work_ref_hash.hpp>   // make_work_ref_hash_params, classify_payout_identity

namespace {

using WScript = std::vector<unsigned char>;

WScript wrh_unhex(const std::string& h) {
    WScript v; v.reserve(h.size() / 2);
    auto nyb = [](char c) -> int { return (c <= '9') ? c - '0' : (c | 0x20) - 'a' + 10; };
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        v.push_back(static_cast<unsigned char>((nyb(h[i]) << 4) | nyb(h[i + 1])));
    return v;
}

// A canonical P2PKH scriptPubKey: 76 a9 14 <20B hash160> 88 ac.
const WScript WRH_P2PKH = wrh_unhex(
    "76a914000102030405060708090a0b0c0d0e0f1011121388ac");
// P2SH: a9 14 <20B> 87.
const WScript WRH_P2SH = wrh_unhex(
    "a914202122232425262728292a2b2c2d2e2f3031323387");
// P2WPKH: 00 14 <20B>.
const WScript WRH_P2WPKH = wrh_unhex(
    "0014404142434445464748494a4b4c4d4e4f50515253");

const WScript WRH_CB = wrh_unhex("03a1b2c3041122334455667788");

// Build the prospective-work inputs for a non-trivial share. mirror_to_params()
// below builds the SAME fields the verification reference uses.
dgb::coin::WorkRefHashInputs make_inputs(int64_t version, const WScript& payout_script,
                                         bool has_segwit) {
    dgb::coin::WorkRefHashInputs in;
    in.share_version       = version;
    in.desired_version     = 36;
    in.prev_share          = uint256();      // genesis-ish; ref serialises it raw
    in.coinbase_scriptSig  = WRH_CB;
    in.share_nonce         = 0x12345678u;
    in.payout_script       = payout_script;
    in.subsidy             = 64000000u;
    in.donation            = 37u;
    in.stale_info          = 0u;
    in.has_segwit          = has_segwit;
    // SegwitData default-constructed (empty branch / zero root) — both paths see
    // the identical value, so when has_segwit is true the data still matches.
    in.merged_payout_hash.SetNull();
    in.far_share_hash.SetNull();
    in.max_bits            = 0x1e0fffffu;
    in.bits                = 0x1e0fffffu;
    in.timestamp           = 1718700000u;
    in.absheight           = 1000u;
    in.abswork             = uint128(123456789u);
    return in;
}

// VERIFICATION reference: populate RefHashParams the way create_local_share() /
// create_local_share_v35() feed the ref preimage, WITHOUT going through the new
// assembler. This is the independent oracle the assembler must reproduce.
dgb::RefHashParams mirror_to_params(const dgb::coin::WorkRefHashInputs& in,
                                    const core::CoinParams& params) {
    dgb::RefHashParams p;
    p.share_version      = in.share_version;
    p.desired_version    = in.desired_version;
    p.prev_share         = in.prev_share;
    p.coinbase_scriptSig = in.coinbase_scriptSig;
    p.share_nonce        = in.share_nonce;
    p.subsidy            = in.subsidy;
    p.donation           = in.donation;
    p.stale_info         = in.stale_info;

    // Payout identity — verbatim from create_local_share()'s scriptPubKey tests.
    const auto& ps = in.payout_script;
    if (ps.size() == 25 && ps[0] == 0x76 && ps[1] == 0xa9 && ps[2] == 0x14 &&
        ps[23] == 0x88 && ps[24] == 0xac) {
        std::memcpy(p.pubkey_hash.data(), ps.data() + 3, 20); p.pubkey_type = 0;
    } else if (ps.size() == 23 && ps[0] == 0xa9 && ps[1] == 0x14 && ps[22] == 0x87) {
        std::memcpy(p.pubkey_hash.data(), ps.data() + 2, 20); p.pubkey_type = 2;
    } else if (ps.size() == 22 && ps[0] == 0x00 && ps[1] == 0x14) {
        std::memcpy(p.pubkey_hash.data(), ps.data() + 2, 20); p.pubkey_type = 1;
    } else if (ps.size() >= 20) {
        std::memcpy(p.pubkey_hash.data(), ps.data(), 20); p.pubkey_type = 0;
    }
    {
        std::string addr = dgb::pubkey_hash_to_address(p.pubkey_hash, p.pubkey_type, params);
        p.address.assign(addr.begin(), addr.end());
    }

    p.has_segwit         = in.has_segwit;
    p.segwit_data        = in.segwit_data;
    p.merged_addresses   = in.merged_addresses;
    p.merged_coinbase_info = in.merged_coinbase_info;
    p.merged_payout_hash = in.merged_payout_hash;
    p.message_data       = in.message_data;
    p.far_share_hash     = in.far_share_hash;
    p.max_bits           = in.max_bits;
    p.bits               = in.bits;
    p.timestamp          = in.timestamp;
    p.absheight          = in.absheight;
    p.abswork            = in.abswork;
    return p;
}

// (1) V36, no segwit: the assembler ref_hash == the verification-reference
//     ref_hash. Exercises the #336 no-segwit placeholder branch.
TEST(WorkRefHashAssembler, V36NoSegwitEmissionEqualsVerification) {
    const auto params = dgb::make_coin_params(/*testnet=*/false);
    const auto in = make_inputs(/*version=*/36, WRH_P2PKH, /*has_segwit=*/false);

    const auto emit_params   = dgb::coin::make_work_ref_hash_params(in, params);
    const auto verify_params = mirror_to_params(in, params);

    const auto emit_ref   = dgb::compute_ref_hash_for_work(emit_params, params).first;
    const auto verify_ref = dgb::compute_ref_hash_for_work(verify_params, params).first;

    EXPECT_EQ(emit_ref, verify_ref);
    EXPECT_FALSE(emit_ref.IsNull());
    // Assembler classified the P2PKH script correctly.
    EXPECT_EQ(emit_params.pubkey_type, 0);
}

// (2) V36, with segwit: same delegation, segwit field carried verbatim.
TEST(WorkRefHashAssembler, V36WithSegwitEmissionEqualsVerification) {
    const auto params = dgb::make_coin_params(/*testnet=*/false);
    const auto in = make_inputs(/*version=*/36, WRH_P2WPKH, /*has_segwit=*/true);

    const auto emit_ref =
        dgb::compute_ref_hash_for_work(dgb::coin::make_work_ref_hash_params(in, params), params).first;
    const auto verify_ref =
        dgb::compute_ref_hash_for_work(mirror_to_params(in, params), params).first;

    EXPECT_EQ(emit_ref, verify_ref);
    // P2WPKH -> type 1.
    EXPECT_EQ(dgb::coin::make_work_ref_hash_params(in, params).pubkey_type, 1);
}

// (3) V35: the address-VarStr path. The assembler must derive the address the
//     same way create_local_share_v35() does, or the V35 ref_hash splits.
TEST(WorkRefHashAssembler, V35AddressPathEmissionEqualsVerification) {
    const auto params = dgb::make_coin_params(/*testnet=*/false);
    const auto in = make_inputs(/*version=*/35, WRH_P2SH, /*has_segwit=*/false);

    const auto emit_params   = dgb::coin::make_work_ref_hash_params(in, params);
    const auto verify_params = mirror_to_params(in, params);

    const auto emit_ref   = dgb::compute_ref_hash_for_work(emit_params, params).first;
    const auto verify_ref = dgb::compute_ref_hash_for_work(verify_params, params).first;

    EXPECT_EQ(emit_ref, verify_ref);
    EXPECT_FALSE(emit_ref.IsNull());
    // The V35 ref serialises the address string — confirm the assembler filled it
    // and that it round-trips the P2SH identity.
    EXPECT_FALSE(emit_params.address.empty());
    EXPECT_EQ(emit_params.address, verify_params.address);
    EXPECT_EQ(emit_params.pubkey_type, 2);
}

// (4) classify_payout_identity covers all three script classes byte-for-byte
//     (the one judgment call shared with both mint paths).
TEST(WorkRefHashAssembler, PayoutIdentityClassification) {
    auto p2pkh = dgb::coin::classify_payout_identity(WRH_P2PKH);
    EXPECT_EQ(p2pkh.pubkey_type, 0);
    EXPECT_EQ(std::memcmp(p2pkh.pubkey_hash.data(), WRH_P2PKH.data() + 3, 20), 0);

    auto p2sh = dgb::coin::classify_payout_identity(WRH_P2SH);
    EXPECT_EQ(p2sh.pubkey_type, 2);
    EXPECT_EQ(std::memcmp(p2sh.pubkey_hash.data(), WRH_P2SH.data() + 2, 20), 0);

    auto p2wpkh = dgb::coin::classify_payout_identity(WRH_P2WPKH);
    EXPECT_EQ(p2wpkh.pubkey_type, 1);
    EXPECT_EQ(std::memcmp(p2wpkh.pubkey_hash.data(), WRH_P2WPKH.data() + 2, 20), 0);
}

}  // namespace
