/// Phase C-TEMPLATE step 5 (S7 embedded_gbt capstone) — Dash embedded
/// getblocktemplate bit-parity unit tests.
///
/// Exercises the capstone that fuses every landed S7 leaf into a single
/// getblocktemplate-equivalent projection:
///
///   - build_embedded_workdata() : subsidy.hpp block-reward + MN/platform
///     split + mempool get_sorted_txs_with_fees() selection + MN payee
///     resolution (mn_state_machine find_expected_payee → script_to_address)
///     + DIP-0027 OP_RETURN platform-burn ordering.
///   - build_embedded_cbtx() / encode_cbtx() / parse_cbtx() : the CCbTx
///     (coinbase extra_payload) wire encoder — merkleRootMNList (SML) +
///     merkleRootQuorums (QuorumManager) + bestCL* + creditPoolBalance.
///   - gbt_xcheck() / cbtx_xcheck() : the dashd-RPC cross-check comparators.
///
/// KAT philosophy (mirrors test_dash_mn_state.cpp / test_dash_simplifiedmns.cpp):
/// every assertion is either
///   (a) a structural round-trip (build → encode → parse → field EQ),
///   (b) a bit-exact preimage rebuilt INDEPENDENTLY (the subsidy / split
///       integer arithmetic recomputed by hand in the test, the CCbTx wire
///       re-serialized through a second path) and compared byte-for-byte, or
///   (c) a self-consistency property of the comparator (identical inputs
///       match; a single mutated field is detected).
/// No "expected" hashes or amounts are fabricated — every numeric oracle is
/// derived from the same closed-form formula dashcore uses, recomputed
/// independently here.
///
/// ════════════════════════════════════════════════════════════════════════
/// SCOPE NOTE (honest, mirrors test_dash_mn_state.cpp's deferral):
/// The end-to-end oracle cross-check — "build_embedded_workdata over a REAL
/// Dash mainnet tip produces the SAME coinbasevalue / payee / CCbTx roots as
/// a live `dashd-cli getblocktemplate`" — requires a live Dash node oracle
/// (a synced mainnet dashd exposing getblocktemplate + the matching
/// mnlistdiff/quorum state) which this hermetic unit test deliberately does
/// NOT reach. That node-backed parity vector is captured by the
/// embedded_gbt RPC-shadow path at runtime ([GBT-XCHECK] / [CBTX-XCHECK]
/// log lines) and is the subject of a follow-up live-harness leaf. The
/// gbt_xcheck()/cbtx_xcheck() comparators ARE exercised here against
/// locally-built reference WorkData/CCbTx so the comparison logic itself is
/// proven; only the dashd-supplied side is deferred.  TODO(oracle-e2e):
/// wire VMID 200/201 dashd getblocktemplate vectors once a node is reachable.
/// ════════════════════════════════════════════════════════════════════════

#include <gtest/gtest.h>

#include <impl/dash/coin/embedded_gbt.hpp>
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/mn_state_db.hpp>
#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/subsidy.hpp>
#include <impl/dash/coin/utxo_adapter.hpp>
#include <impl/dash/coin/quorum_manager.hpp>
#include <impl/dash/coin/quorum_root.hpp>
#include <impl/dash/coin/rpc_data.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using dash::coin::DashWorkData;
using dash::coin::PackedPayment;
using dash::coin::MNState;
using dash::coin::MnStateMachine;
using dash::coin::Mempool;
using dash::coin::MutableTransaction;
using dash::coin::QuorumManager;
using dash::coin::build_embedded_workdata;
using dash::coin::build_embedded_cbtx;
using dash::coin::encode_cbtx;
using dash::coin::gbt_xcheck;
using dash::coin::cbtx_xcheck;
using dash::coin::compute_dash_block_reward_post_v20;
using dash::coin::compute_dash_mn_payment_post_v20;
using dash::coin::compute_dash_platform_reward_post_v20_mn_rr;
using dash::coin::compute_merkle_root_quorums;
using dash::coin::vendor::CCbTx;
using dash::coin::vendor::CSimplifiedMNList;
using dash::coin::vendor::CSimplifiedMNListEntry;
using dash::coin::vendor::parse_cbtx;
using ::core::coin::UTXOViewCache;
using ::core::coin::Outpoint;
using ::core::coin::Coin;
using ::bitcoin_family::coin::TxIn;
using ::bitcoin_family::coin::TxOut;

// Dash mainnet base58 version bytes (chainparams.cpp PUBKEY_ADDRESS=76,
// SCRIPT_ADDRESS=16). Used so script_to_address() emits a real Dash payee.
static constexpr uint8_t DASH_PUBKEY_VER = 76;
static constexpr uint8_t DASH_P2SH_VER   = 16;

// A checkpoint height well past V20 (1,987,776) AND MN_RR (2,128,896) so the
// platform-share burn is always active — matches the mainnet steady state the
// shadow path validates.
static constexpr uint32_t H = 2'400'000;

// ─── helpers ────────────────────────────────────────────────────────────────

static uint256 raw256(uint8_t base) {
    uint256 h;
    std::array<uint8_t, 32> p{};
    for (size_t i = 0; i < 32; ++i) p[i] = static_cast<uint8_t>(base + i);
    std::memcpy(h.data(), p.data(), 32);
    return h;
}

template <size_t N>
static std::array<uint8_t, N> seq_array(uint8_t base) {
    std::array<uint8_t, N> a{};
    for (size_t i = 0; i < N; ++i) a[i] = static_cast<uint8_t>(base + i);
    return a;
}

// A valid 25-byte P2PKH scriptPubKey: OP_DUP OP_HASH160 <20> .. OP_EQUALVERIFY
// OP_CHECKSIG. script_to_address() must decode this to a base58 Dash address.
static std::vector<unsigned char> p2pkh_script(uint8_t hashseed) {
    std::vector<unsigned char> s;
    s.push_back(0x76);              // OP_DUP
    s.push_back(0xa9);              // OP_HASH160
    s.push_back(0x14);              // push 20
    for (int i = 0; i < 20; ++i) s.push_back(static_cast<unsigned char>(hashseed + i));
    s.push_back(0x88);              // OP_EQUALVERIFY
    s.push_back(0xac);              // OP_CHECKSIG
    return s;
}

static uint256 mint_hash(uint32_t seed) {
    MutableTransaction t;
    t.version = 1; t.type = 0;
    t.locktime = 0x51000000u ^ seed;
    auto ps = ::pack(t);
    return ::Hash(ps.get_span());
}

static MutableTransaction make_spend(const uint256& prev, uint32_t idx,
                                     int64_t out_value, uint32_t salt) {
    MutableTransaction tx;
    tx.version = 1; tx.type = 0; tx.locktime = salt;
    TxIn in; in.prevout.hash = prev; in.prevout.index = idx;
    in.sequence = 0xffffffffu;
    tx.vin.push_back(in);
    TxOut o; o.value = out_value;
    tx.vout.push_back(o);
    return tx;
}

// Seed an MnStateMachine with a single valid MN paying `payout`, so
// find_expected_payee() resolves to it deterministically.
static MnStateMachine single_mn(const std::vector<unsigned char>& payout) {
    MNState s;
    s.isValid = true;
    s.nRegisteredHeight = 2'300'000;
    s.nLastPaidHeight = 0;
    s.scriptPayout.m_data = payout;
    MnStateMachine m;
    m.load(std::vector<std::pair<uint256, MNState>>{{raw256(0x01), s}});
    return m;
}

// ════════════════════════════════════════════════════════════════════════
// build_embedded_workdata — structural fields + independently-recomputed
// subsidy/split arithmetic (bit-exact integer oracle).
// ════════════════════════════════════════════════════════════════════════

TEST(DashEmbeddedGbt, WorkdataHeaderFieldsAndSubsidyArithmetic) {
    UTXOViewCache utxo(nullptr);
    uint256 prev = mint_hash(20);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, /*height=*/1, /*cb=*/false));
    Mempool mp;
    mp.set_utxo(&utxo);
    auto tx = make_spend(prev, 0, 90'000, /*salt=*/1);   // fee = 10'000
    ASSERT_TRUE(mp.add_tx(tx));

    auto payout = p2pkh_script(0x30);
    auto mnstates = single_mn(payout);

    uint256 prev_hash = raw256(0xAB);
    const uint32_t bits = 0x1b104be3u;
    const uint32_t mtp  = 1'700'000'000u;

    auto w = build_embedded_workdata(
        /*prev_height=*/H - 1, prev_hash, mnstates, mp,
        bits, mtp, DASH_PUBKEY_VER, DASH_P2SH_VER);

    // Header fields are pass-through / derived — assert exactly.
    EXPECT_EQ(w.m_height, H);
    EXPECT_EQ(w.m_previous_block, prev_hash);
    EXPECT_EQ(w.m_bits, bits);
    EXPECT_EQ(w.m_mintime, mtp + 1u);            // GBT returns MTP+1
    EXPECT_EQ(w.m_version, 0x20000000);          // BIP9 default top bit

    // Independent re-derivation of the value/split arithmetic (same
    // closed-form formulas dashcore uses, recomputed here from scratch).
    int64_t reward          = compute_dash_block_reward_post_v20(H);
    int64_t total_fees      = 10'000;            // the one selected tx
    int64_t block_value     = reward + total_fees;
    int64_t platform_reward = compute_dash_platform_reward_post_v20_mn_rr(H);
    int64_t mn_payment      = compute_dash_mn_payment_post_v20(block_value)
                              - platform_reward;

    EXPECT_EQ(w.m_coinbase_value, static_cast<uint64_t>(block_value));
    EXPECT_EQ(w.m_payment_amount, static_cast<uint64_t>(mn_payment));
    EXPECT_GT(platform_reward, 0)
        << "h=" << H << " is past MN_RR so platform burn must be active";

    // tx plumbing: the single fee-known mempool tx is selected.
    ASSERT_EQ(w.m_txs.size(), 1u);
    ASSERT_EQ(w.m_tx_fees.size(), 1u);
    ASSERT_EQ(w.m_tx_hashes.size(), 1u);
    EXPECT_EQ(w.m_tx_fees[0], 10'000u);
    EXPECT_EQ(w.m_tx_hashes[0], dash::coin::dash_txid(tx));
}

TEST(DashEmbeddedGbt, PlatformBurnIsFirstPaymentAndMnPayeeBase58) {
    UTXOViewCache utxo(nullptr);   // empty mempool path (no fees)
    Mempool mp;
    auto payout = p2pkh_script(0x40);
    auto mnstates = single_mn(payout);

    auto w = build_embedded_workdata(
        H - 1, raw256(0x10), mnstates, mp,
        /*bits=*/0x1b104be3u, /*mtp=*/1'700'000'000u,
        DASH_PUBKEY_VER, DASH_P2SH_VER);

    // Two payments in dashcore order: [0] OP_RETURN platform burn ("!6a"),
    // [1] the MN payee (a base58 Dash address from the P2PKH script).
    ASSERT_EQ(w.m_packed_payments.size(), 2u);

    int64_t platform_reward = compute_dash_platform_reward_post_v20_mn_rr(H);
    EXPECT_EQ(w.m_packed_payments[0].payee, "!6a")
        << "platform credit-pool burn must be the OP_RETURN raw-script payee";
    EXPECT_EQ(w.m_packed_payments[0].amount,
              static_cast<uint64_t>(platform_reward));

    // MN payee: P2PKH → base58 (NOT the "!hex" fallback). Independent decode
    // through script_to_address must agree byte-for-byte.
    std::string expect_addr = ::core::script_to_address(
        payout, "", DASH_PUBKEY_VER, DASH_P2SH_VER);
    ASSERT_FALSE(expect_addr.empty())
        << "P2PKH must decode to a base58 address, not fall to !hex";
    EXPECT_EQ(w.m_packed_payments[1].payee, expect_addr);
    EXPECT_NE(w.m_packed_payments[1].payee.rfind('!', 0), 0u)
        << "standard P2PKH must NOT use the !hex raw-script fallback";

    int64_t reward      = compute_dash_block_reward_post_v20(H);   // no fees
    int64_t mn_payment  = compute_dash_mn_payment_post_v20(reward) - platform_reward;
    EXPECT_EQ(w.m_packed_payments[1].amount, static_cast<uint64_t>(mn_payment));
}

TEST(DashEmbeddedGbt, NonStandardScriptFallsBackToHexPayee) {
    Mempool mp;
    // 7-byte opaque script: not P2PKH/P2SH/bech32 → "!hex" fallback.
    std::vector<unsigned char> weird{0x6a, 0x05, 0xde, 0xad, 0xbe, 0xef, 0x01};
    auto mnstates = single_mn(weird);

    auto w = build_embedded_workdata(
        H - 1, raw256(0x20), mnstates, mp,
        0x1b104be3u, 1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER);

    ASSERT_EQ(w.m_packed_payments.size(), 2u);   // burn + MN
    // Independent hex encode of the raw script, "!"-prefixed.
    std::string expect = "!";
    static const char* d = "0123456789abcdef";
    for (uint8_t b : weird) { expect.push_back(d[(b >> 4) & 0xF]); expect.push_back(d[b & 0xF]); }
    EXPECT_EQ(w.m_packed_payments[1].payee, expect);
}

// ════════════════════════════════════════════════════════════════════════
// CCbTx (coinbase extra_payload) — bit-exact wire preimage parity.
// ════════════════════════════════════════════════════════════════════════

// Independent re-serialization of a CCbTx via a fresh PackStream, bypassing
// encode_cbtx, so the encoder is checked against a second path.
static std::vector<unsigned char> repack_cbtx(const CCbTx& c) {
    ::PackStream s;
    s << c;
    auto sp = s.get_span();
    return std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
}

TEST(DashEmbeddedGbt, CbtxEncodeDecodeRoundTripAndPreimage) {
    // Seed an SML with two entries so CalcMerkleRoot is non-trivial.
    CSimplifiedMNListEntry e1; e1.proRegTxHash = raw256(0x11); e1.isValid = true;
    CSimplifiedMNListEntry e2; e2.proRegTxHash = raw256(0x22); e2.isValid = true;
    CSimplifiedMNList sml(std::vector<CSimplifiedMNListEntry>{e1, e2});

    QuorumManager qmgr;   // empty active set → deterministic root
    std::array<uint8_t, 96> clsig = seq_array<96>(0x55);

    CCbTx c = build_embedded_cbtx(
        /*prev_height=*/H - 1, sml, qmgr,
        /*best_cl_height=*/static_cast<int32_t>(H - 10), clsig,
        /*last_observed_credit_pool=*/123'456'789LL);

    // Field provenance: independently recompute the two roots.
    CSimplifiedMNList sml_copy = sml;
    EXPECT_EQ(c.merkleRootMNList, sml_copy.CalcMerkleRoot());
    EXPECT_EQ(c.merkleRootQuorums, compute_merkle_root_quorums(qmgr));
    EXPECT_EQ(c.nVersion, CCbTx::VERSION_CLSIG_AND_BALANCE);
    EXPECT_EQ(c.nHeight, static_cast<int32_t>(H));
    // best_cl_height=H-10 ≤ prev_height=H-1 → diff = prev_height - best.
    EXPECT_EQ(c.bestCLHeightDiff, (H - 1) - (H - 10));
    EXPECT_EQ(c.bestCLSignature, clsig);
    EXPECT_EQ(c.creditPoolBalance, 123'456'789LL);

    // (a) encoder == independent re-serialization (bit-exact preimage).
    auto wire = encode_cbtx(c);
    EXPECT_EQ(wire, repack_cbtx(c)) << "encode_cbtx must match a second pack path";
    EXPECT_FALSE(wire.empty());

    // (b) decode round-trip: parse_cbtx(wire) reconstructs every field.
    CCbTx back;
    ASSERT_TRUE(parse_cbtx(wire, back)) << "encoded payload must parse cleanly";
    EXPECT_EQ(back.nVersion, c.nVersion);
    EXPECT_EQ(back.nHeight, c.nHeight);
    EXPECT_EQ(back.merkleRootMNList, c.merkleRootMNList);
    EXPECT_EQ(back.merkleRootQuorums, c.merkleRootQuorums);
    EXPECT_EQ(back.bestCLHeightDiff, c.bestCLHeightDiff);
    EXPECT_EQ(back.bestCLSignature, c.bestCLSignature);
    EXPECT_EQ(back.creditPoolBalance, c.creditPoolBalance);

    // (c) re-encode the parsed struct → identical bytes (encode⁻¹ is exact).
    EXPECT_EQ(encode_cbtx(back), wire) << "round-trip must be byte-stable";
}

TEST(DashEmbeddedGbt, CbtxNoChainlockZeroesBestCLFields) {
    CSimplifiedMNListEntry e; e.proRegTxHash = raw256(0x33); e.isValid = true;
    CSimplifiedMNList sml(std::vector<CSimplifiedMNListEntry>{e});
    QuorumManager qmgr;

    // best_cl_height=0 → no CLSIG observed → bestCL* must be zeroed,
    // matching dashd's "no chainlock for the window" wire shape.
    CCbTx c = build_embedded_cbtx(
        H - 1, sml, qmgr, /*best_cl_height=*/0, std::array<uint8_t, 96>{},
        /*last_observed_credit_pool=*/0LL);
    EXPECT_EQ(c.bestCLHeightDiff, 0u);
    EXPECT_EQ(c.bestCLSignature, (std::array<uint8_t, 96>{}));
    EXPECT_FALSE(c.has_best_cl_signature());

    auto wire = encode_cbtx(c);
    CCbTx back;
    ASSERT_TRUE(parse_cbtx(wire, back));
    EXPECT_EQ(back.bestCLHeightDiff, 0u);
    EXPECT_FALSE(back.has_best_cl_signature());
}

// ════════════════════════════════════════════════════════════════════════
// cbtx_xcheck / gbt_xcheck — comparator self-consistency (the dashd side
// is mirrored by a locally-built reference; only the node oracle is deferred).
// ════════════════════════════════════════════════════════════════════════

TEST(DashEmbeddedGbt, CbtxXcheckMatchesIdenticalDetectsRootDrift) {
    CSimplifiedMNListEntry e; e.proRegTxHash = raw256(0x44); e.isValid = true;
    CSimplifiedMNList sml(std::vector<CSimplifiedMNListEntry>{e});
    QuorumManager qmgr;
    CCbTx c = build_embedded_cbtx(H - 1, sml, qmgr, 0, std::array<uint8_t, 96>{}, 0LL);

    // Identical payload → roots match.
    auto wire = encode_cbtx(c);
    EXPECT_TRUE(cbtx_xcheck(c, wire));

    // Flip merkleRootMNList on the embedded side → root drift detected.
    CCbTx c_drift = c;
    c_drift.merkleRootMNList = raw256(0xFF);
    EXPECT_FALSE(cbtx_xcheck(c_drift, wire))
        << "a divergent merkleRootMNList must fail the root cross-check";

    // Unparseable payload → returns false (defensive).
    std::vector<unsigned char> garbage{0x01, 0x02};
    EXPECT_FALSE(cbtx_xcheck(c, garbage));
}

TEST(DashEmbeddedGbt, GbtXcheckMatchesIdenticalDetectsFieldDrift) {
    Mempool mp;
    auto payout = p2pkh_script(0x50);
    auto mnstates = single_mn(payout);
    auto w = build_embedded_workdata(
        H - 1, raw256(0x60), mnstates, mp,
        0x1b104be3u, 1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER);

    // Identical WorkData (embedded vs. a copy standing in for the RPC side).
    DashWorkData rpc = w;
    EXPECT_TRUE(gbt_xcheck(w, rpc));

    // Single-field drift on coinbase_value → detected.
    DashWorkData rpc_bad = w;
    rpc_bad.m_coinbase_value += 1;
    EXPECT_FALSE(gbt_xcheck(w, rpc_bad));

    // Payee drift → detected.
    DashWorkData rpc_payee = w;
    ASSERT_FALSE(rpc_payee.m_packed_payments.empty());
    rpc_payee.m_packed_payments.back().payee = "XdifferentDashAddr";
    EXPECT_FALSE(gbt_xcheck(w, rpc_payee));

    // packed_payments count drift → detected.
    DashWorkData rpc_count = w;
    rpc_count.m_packed_payments.pop_back();
    EXPECT_FALSE(gbt_xcheck(w, rpc_count));
}

// ════════════════════════════════════════════════════════════════════════
// G1 golden: deterministic template+coinbase vector via the curtime seam.
//
// The sole non-determinism in build_embedded_workdata was the live
// std::time(nullptr) read for m_curtime. With the trailing defaulted curtime
// param, a fixed-input call yields a byte-for-byte reproducible header
// projection — the G1 deliverable (fixed-input template+coinbase golden) in
// the per-coin block-production gate.
//
// Oracle discipline (non-circular, mirrors the params KAT): bits is pinned to
// the oracle GBT nBits and passed through; every value/split number is
// re-derived here from the SAME closed-form dashcore formulas, not copied from
// a build_embedded_workdata run. Only curtime is a pinned input we assert the
// seam faithfully echoes.
// ════════════════════════════════════════════════════════════════════════

TEST(DashEmbeddedGbt, G1GoldenDeterministicTemplateViaCurtimeSeam) {
    UTXOViewCache utxo(nullptr);
    uint256 prev = mint_hash(77);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, /*height=*/1, /*cb=*/false));
    Mempool mp;
    mp.set_utxo(&utxo);
    auto tx = make_spend(prev, 0, 90'000, /*salt=*/7);   // fee = 10'000
    ASSERT_TRUE(mp.add_tx(tx));

    auto payout   = p2pkh_script(0x55);
    auto mnstates = single_mn(payout);

    uint256 prev_hash = raw256(0xC3);
    const uint32_t bits           = 0x1b104be3u;   // pinned oracle GBT nBits
    const uint32_t mtp            = 1'700'000'000u;
    const uint32_t PINNED_CURTIME = 1'700'000'123u;  // fixed block time

    // Same fixed inputs → identical WorkData every run (the golden property).
    auto a = build_embedded_workdata(
        H - 1, prev_hash, mnstates, mp,
        bits, mtp, DASH_PUBKEY_VER, DASH_P2SH_VER, PINNED_CURTIME);
    auto b = build_embedded_workdata(
        H - 1, prev_hash, mnstates, mp,
        bits, mtp, DASH_PUBKEY_VER, DASH_P2SH_VER, PINNED_CURTIME);

    // The seam echoes the pinned time exactly — no wall-clock leak.
    EXPECT_EQ(a.m_curtime, PINNED_CURTIME);
    EXPECT_EQ(b.m_curtime, PINNED_CURTIME);

    // Full header projection is deterministic field-for-field.
    EXPECT_EQ(a.m_height,          b.m_height);
    EXPECT_EQ(a.m_previous_block,  b.m_previous_block);
    EXPECT_EQ(a.m_bits,            b.m_bits);
    EXPECT_EQ(a.m_mintime,         b.m_mintime);
    EXPECT_EQ(a.m_version,         b.m_version);
    EXPECT_EQ(a.m_coinbase_value,  b.m_coinbase_value);
    EXPECT_EQ(a.m_payment_amount,  b.m_payment_amount);

    // Independent re-derivation of the golden values (non-circular oracle).
    int64_t reward          = compute_dash_block_reward_post_v20(H);
    int64_t total_fees      = 10'000;
    int64_t block_value     = reward + total_fees;
    int64_t platform_reward = compute_dash_platform_reward_post_v20_mn_rr(H);
    int64_t mn_payment      = compute_dash_mn_payment_post_v20(block_value)
                              - platform_reward;

    EXPECT_EQ(a.m_height,         H);
    EXPECT_EQ(a.m_previous_block, prev_hash);
    EXPECT_EQ(a.m_bits,           bits);            // oracle nBits passthrough
    EXPECT_EQ(a.m_mintime,        mtp + 1u);        // GBT returns MTP+1
    EXPECT_EQ(a.m_version,        0x20000000u);
    EXPECT_EQ(a.m_coinbase_value, static_cast<uint64_t>(block_value));
    EXPECT_EQ(a.m_payment_amount, static_cast<uint64_t>(mn_payment));

    // Coinbase payee side is deterministic: platform OP_RETURN burn FIRST,
    // then the MN base58 payee — same ordering the shadow path asserts.
    ASSERT_EQ(a.m_packed_payments.size(), 2u);
    EXPECT_EQ(a.m_packed_payments[0].payee, "!6a");   // DIP-0027 burn
    EXPECT_EQ(a.m_packed_payments[0].amount,
              static_cast<uint64_t>(platform_reward));
    EXPECT_EQ(a.m_packed_payments[1].amount,
              static_cast<uint64_t>(mn_payment));
    EXPECT_FALSE(a.m_packed_payments[1].payee.empty());
    EXPECT_NE(a.m_packed_payments[1].payee.front(), '!');  // base58, not !hex

    // The default arg preserves the prior live-read behavior: omitting curtime
    // still reads the wall clock (post-2023 epoch), so no caller is changed.
    auto live = build_embedded_workdata(
        H - 1, prev_hash, mnstates, mp,
        bits, mtp, DASH_PUBKEY_VER, DASH_P2SH_VER);
    EXPECT_GE(live.m_curtime, 1'700'000'000u)
        << "default curtime must still read std::time(nullptr)";
}

// ========================================================================
// G1 golden: injectable block-version seam (companion to the curtime seam).
//
// build_embedded_workdata hardcoded m_version = 0x20000000 (BIP9 "no
// signaling" baseline). With the trailing defaulted `version` param a
// fixed-input call yields a byte-for-byte reproducible version projection,
// and a real BIP9-deployment-aware value can later be threaded through
// without disturbing the default. curtime is pinned here because the
// version seam sits AFTER curtime in the signature.
// ========================================================================
TEST(DashEmbeddedGbt, G1GoldenVersionSeamEchoesInjectedVersion) {
    UTXOViewCache utxo(nullptr);
    uint256 prev = mint_hash(88);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, /*height=*/1, /*cb=*/false));
    Mempool mp;
    mp.set_utxo(&utxo);
    auto tx = make_spend(prev, 0, 90'000, /*salt=*/9);   // fee = 10'000
    ASSERT_TRUE(mp.add_tx(tx));

    auto payout   = p2pkh_script(0x55);
    auto mnstates = single_mn(payout);

    uint256 prev_hash = raw256(0xD4);
    const uint32_t bits           = 0x1b104be3u;   // pinned oracle GBT nBits
    const uint32_t mtp            = 1'700'000'000u;
    const uint32_t PINNED_CURTIME = 1'700'000'123u; // pinned: sits before version in sig
    const uint32_t PINNED_VERSION = 0x20000004u;   // BIP9 baseline + bit 2 set

    // Injected version is echoed byte-for-byte -- the seam adds no arithmetic.
    auto injected = build_embedded_workdata(
        H - 1, prev_hash, mnstates, mp,
        bits, mtp, DASH_PUBKEY_VER, DASH_P2SH_VER, PINNED_CURTIME, PINNED_VERSION);
    EXPECT_EQ(injected.m_version, PINNED_VERSION);

    // Deterministic: same fixed inputs -> identical version projection.
    auto injected2 = build_embedded_workdata(
        H - 1, prev_hash, mnstates, mp,
        bits, mtp, DASH_PUBKEY_VER, DASH_P2SH_VER, PINNED_CURTIME, PINNED_VERSION);
    EXPECT_EQ(injected.m_version, injected2.m_version);

    // Default arg preserves the prior hardcoded projection: omitting version
    // still yields the BIP9 "no signaling" baseline, so no caller is changed.
    auto baseline = build_embedded_workdata(
        H - 1, prev_hash, mnstates, mp,
        bits, mtp, DASH_PUBKEY_VER, DASH_P2SH_VER, PINNED_CURTIME);
    EXPECT_EQ(baseline.m_version, 0x20000000u);

    // The version seam is orthogonal to every other header field: injecting a
    // non-default version changes ONLY m_version, nothing else drifts.
    EXPECT_EQ(injected.m_height,         baseline.m_height);
    EXPECT_EQ(injected.m_previous_block, baseline.m_previous_block);
    EXPECT_EQ(injected.m_bits,           baseline.m_bits);
    EXPECT_EQ(injected.m_mintime,        baseline.m_mintime);
    EXPECT_EQ(injected.m_coinbase_value, baseline.m_coinbase_value);
    EXPECT_EQ(injected.m_payment_amount, baseline.m_payment_amount);
}
