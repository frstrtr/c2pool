// SPDX-License-Identifier: AGPL-3.0-or-later
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
#include <impl/dash/coin/vendor/smldiff.hpp>           // E2: CSimplifiedMNListDiff (restart-seed KAT)
#include <impl/dash/coin/node_coin_state.hpp>          // E2: NodeCoinState freshness gate
#include <impl/dash/coin/coin_state_maintainer.hpp>    // E2: CoinStateMaintainer (independent advance)
#include <impl/dash/coin/credit_pool.hpp>              // E2: CreditPool (running accrual)
#include <impl/dash/coin/block.hpp>                    // E2: BlockType (ingested block)
#include <impl/dash/coin/block_producer.hpp>           // E2 finding A: compute_merkle_root / block_body_binds_to_header

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
using dash::coin::vendor::CSimplifiedMNListDiff;
using dash::coin::vendor::parse_cbtx;
using dash::coin::NodeCoinState;
using dash::coin::CoinStateMaintainer;
using dash::coin::BlockType;
using dash::coin::compute_dash_block_reward_post_v20;
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

// C-3 (consensus): the embedded block MUST exclude every DIP special-tx type
// (1-4 ProTx, 6 quorum-commitment, 8/9 asset-lock/unlock). build_embedded_cbtx
// commits merkle roots + creditPool computed from the SML/quorum/seed state
// WITHOUT applying the block's own txs' state effects, so a selected special tx
// (which changes the MN list / quorums / creditPool) would make the committed
// CbTx inconsistent -> consensus-invalid (bad-cbtx / bad merkle). End-to-end via
// build_embedded_workdata (the serving path). Each special tx is UTXO-priced
// (fee-known) so it WOULD be selected but for the type filter.
TEST(DashEmbeddedGbt, EmbeddedBlockExcludesAllDipSpecialTxs) {
    UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);

    // A standard (type-0) fee-paying tx — MUST be selected.
    uint256 p0 = mint_hash(0x50);
    utxo.add_coin(Outpoint(p0, 0), Coin(100'000, {}, /*height=*/1, /*cb=*/false));
    auto std_tx = make_spend(p0, 0, 90'000, /*salt=*/1);   // type 0, fee 10'000
    ASSERT_TRUE(mp.add_tx(std_tx));

    // DIP special txs (1,2,3,4,6,8,9), each UTXO-priced (fee-known) — MUST be
    // excluded. (Type 5 is the coinbase itself, never a mempool tx.)
    const uint16_t special_types[] = {1, 2, 3, 4, 6, 8, 9};
    std::vector<uint256> special_ids;
    uint32_t seed = 0x60;
    for (uint16_t t : special_types) {
        uint256 pv = mint_hash(seed++);
        utxo.add_coin(Outpoint(pv, 0), Coin(100'000, {}, 1, false));
        auto sp = make_spend(pv, 0, 90'000, /*salt=*/100u + t);
        sp.type = t;                     // DIP special type
        ASSERT_TRUE(mp.add_tx(sp));
        special_ids.push_back(dash::coin::dash_txid(sp));
    }

    auto mnstates = single_mn(p2pkh_script(0x30));
    auto w = build_embedded_workdata(
        H - 1, raw256(0xAB), mnstates, mp,
        0x1b104be3u, 1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER);

    // Only the standard tx is in the embedded block; no special tx leaked in.
    ASSERT_EQ(w.m_txs.size(), 1u)
        << "embedded block must contain only the standard tx (all special txs excluded)";
    EXPECT_EQ(w.m_txs[0].type, 0);
    EXPECT_EQ(w.m_tx_hashes[0], dash::coin::dash_txid(std_tx));
    for (const auto& id : special_ids)
        for (const auto& h : w.m_tx_hashes)
            EXPECT_NE(h, id) << "a DIP special tx must never reach the embedded block";
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

// ════════════════════════════════════════════════════════════════════════
// E2 — independent credit-pool advance on ingestion, POST-RESTART.
//
// The gap: m_credit_pool is seeded only by the periodic mnlistdiff cbTx, and is
// NOT persisted. After a warm restart the SML resumes from its persisted tip
// (#800), but the credit pool re-seeds to nothing until the NEXT mnlistdiff —
// so for the tip that existed AT restart the credit-pool freshness gate fails
// closed and the daemonless arm falls back to dashd.
//
// The fix (verified here):
//   (1) persist the credit-pool tip alongside the SML (same blockHash/height)
//       and RESTORE it on warm restart, so the gate is live at the restart tip;
//   (2) ADVANCE the pool INDEPENDENTLY on every ingested block, verified against
//       that block's OWN from-wire cbTx creditPoolBalance at nHeight == height —
//       NOT against a template we built from the seed (the self-consistent-but-
//       stale trap that refuted 3 prior soaks).
//
// Oracle discipline: the block's committed creditPoolBalance is built from the
// raw dashcore platform-share formula (subsidy*3/4*375/1000, recomputed here),
// and we assert the maintainer's independent accrual reproduces exactly that
// from-wire value — two independent derivations meeting, never a self-check.
// ════════════════════════════════════════════════════════════════════════

// v3 CCbTx extra_payload at a given height carrying a given creditPoolBalance.
static std::vector<unsigned char> e2_cbtx_payload(int32_t cb_height,
                                                  int64_t credit_pool) {
    CCbTx cb;
    cb.nVersion          = CCbTx::VERSION_CLSIG_AND_BALANCE;
    cb.nHeight           = cb_height;
    cb.creditPoolBalance = credit_pool;
    return dash::coin::encode_cbtx(cb);
}

// A block whose coinbase (tx 0) is a type-5 CbTx committing creditPoolBalance at
// cb_height. No special asset-lock/unlock txs, so the per-block accrual reduces
// to the platform-reward term (the mainnet steady state at H).
static BlockType e2_block_with_cbtx(int32_t cb_height, int64_t credit_pool) {
    BlockType blk;
    blk.m_bits = 0x1b104be3u;                 // non-null header (identity hashable)
    MutableTransaction coinbase;
    coinbase.version       = 3;
    coinbase.type          = 5;               // CbTx
    coinbase.extra_payload = e2_cbtx_payload(cb_height, credit_pool);
    // A coinbase input (prevout null) — not inspected by the credit-pool walk
    // (it skips tx 0), present only so the block looks well-formed.
    TxIn cin; cin.prevout.hash = uint256::ZERO; cin.prevout.index = 0xffffffffu;
    coinbase.vin.push_back(cin);
    blk.m_txs.push_back(std::move(coinbase));
    // Bind the body to the header: commit the merkle root over the actual tx set,
    // so the E2 finding-A guard (block_body_binds_to_header) accepts this block.
    std::vector<uint256> txids;
    for (const auto& tx : blk.m_txs) txids.push_back(dash::coin::dash_txid(tx));
    blk.m_merkle_root = dash::coin::compute_merkle_root(txids);
    return blk;
}

// A FORGED body: the header commits the real coinbase's merkle root, but the
// delivered body swaps in a coinbase with a WRONG creditPoolBalance (same
// nHeight). The merkle root is left committing the real coinbase, so the body no
// longer binds to the header — a real-PoW-header + forged-body attack.
static BlockType e2_forged_block(int32_t cb_height, int64_t real_cp,
                                 int64_t forged_cp) {
    BlockType blk = e2_block_with_cbtx(cb_height, real_cp);   // root commits real cbTx
    blk.m_txs[0].extra_payload = e2_cbtx_payload(cb_height, forged_cp);  // swap in forgery
    return blk;                                              // m_merkle_root NOT updated
}

static CSimplifiedMNListEntry e2_sml_entry(uint8_t seed) {
    CSimplifiedMNListEntry e;
    e.proRegTxHash  = raw256(seed);
    e.confirmedHash = raw256(seed + 1);
    e.isValid = true;
    return e;
}

// mnlistdiff carrying a type-5 cbTx seed (credit pool @ cb_height).
static CSimplifiedMNListDiff e2_diff_with_seed(const uint256& base,
                                               const uint256& block,
                                               int32_t cb_height,
                                               int64_t credit_pool) {
    CSimplifiedMNListDiff d;
    d.baseBlockHash = base;
    d.blockHash     = block;
    d.mnList = {e2_sml_entry(0x40)};
    d.cbTx.version       = 3;
    d.cbTx.type          = 5;
    d.cbTx.extra_payload = e2_cbtx_payload(cb_height, credit_pool);
    return d;
}

static std::vector<std::pair<uint256, MNState>>
e2_mn_pairs(const std::vector<unsigned char>& payout) {
    MNState s;
    s.isValid = true;
    s.nRegisteredHeight = 2'300'000;
    s.nLastPaidHeight = 0;
    s.scriptPayout.m_data = payout;
    return std::vector<std::pair<uint256, MNState>>{{raw256(0x01), s}};
}

// The independent platform-reward oracle at a height (raw dashcore formula,
// truncation order preserved), NOT compute_dash_platform_reward_post_v20_mn_rr.
static int64_t e2_platform_reward_oracle(uint32_t height) {
    int64_t mn_share = compute_dash_block_reward_post_v20(height) * 3 / 4;
    return mn_share * 375 / 1000;
}

TEST(DashEmbeddedGbt, E2CreditPoolIndependentAdvancePostRestart) {
    // Snapshot tip at P = H-1; the first post-restart block is at H.
    const uint32_t P       = H - 1;
    const uint256  HASH_P  = raw256(0x54);
    const int64_t  CP0     = 111'000'000'000LL;             // snapshot balance @ P
    const int64_t  reward  = e2_platform_reward_oracle(H);  // locked at block H
    ASSERT_GT(reward, 0) << "H must be past MN_RR so the platform burn is active";
    const int64_t  CP1     = CP0 + reward;                  // committed balance @ H

    // ── Pre-restart: a cold snapshot seeds + PERSISTS the credit pool @ P. ──
    uint256 persist_hash; uint32_t persist_h = 0; int64_t persist_bal = 0; bool persisted = false;
    {
        NodeCoinState st;
        CoinStateMaintainer m(st);
        m.set_on_credit_pool_persist(
            [&](const uint256& h, uint32_t ht, int64_t bal) {
                persist_hash = h; persist_h = ht; persist_bal = bal; persisted = true;
            });
        m.on_mnlistdiff(e2_diff_with_seed(uint256::ZERO, HASH_P,
                                          static_cast<int32_t>(P), CP0));
        ASSERT_EQ(st.credit_pool(), CP0);
        ASSERT_EQ(st.credit_pool_height(), static_cast<int32_t>(P));
        ASSERT_TRUE(persisted) << "an accepted diff with a v3 cbTx must persist the pool tip";
        EXPECT_EQ(persist_hash, HASH_P);
        EXPECT_EQ(persist_h, P);
        EXPECT_EQ(persist_bal, CP0);
    }

    // Helper: simulate a warm SML restore (loaded from SMLDb directly, NOT via a
    // diff), so the credit pool is the ONLY axis under test.
    auto warm_restore_sml = [&](NodeCoinState& st) {
        st.sml() = CSimplifiedMNList(std::vector<CSimplifiedMNListEntry>{e2_sml_entry(0x40)});
        st.set_have_sml(true);
        st.set_sml_current_hash(HASH_P);
    };
    auto arm_full_bundle = [&](NodeCoinState& st, CoinStateMaintainer& m) {
        st.set_require_sml(true);
        st.set_require_fresh_credit_pool(true);
        m.on_mn_list_update(e2_mn_pairs(p2pkh_script(0x30)));
        m.on_new_tip(P, HASH_P, 0x1b104be3u, 1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER);
    };

    // ── Restart WITHOUT the credit-pool restore (the bug): SML resumes @ P but
    //    the pool is unseeded (height -1) → the freshness gate fails closed. ──
    {
        NodeCoinState st;
        CoinStateMaintainer m(st);
        warm_restore_sml(st);
        arm_full_bundle(st, m);
        EXPECT_EQ(st.credit_pool_height(), -1)
            << "without persistence the pool is unseeded at the restart tip";
        EXPECT_FALSE(st.make_embedded_work_inputs().viable())
            << "unseeded credit pool at the restart tip must fail closed to dashd fallback";
    }

    // ── Restart WITH the credit-pool restore (the fix): pool resumes @ P, the
    //    gate is live at the restart tip, and the first ingested block advances
    //    the pool INDEPENDENTLY, VERIFIED against its own from-wire cbTx. ──
    NodeCoinState st;
    CoinStateMaintainer m(st);
    warm_restore_sml(st);
    // Restore both the freshness seed (NodeCoinState) and the running accrual.
    st.set_credit_pool(persist_bal, persist_hash, static_cast<int32_t>(persist_h));
    m.restore_credit_pool(persist_bal, persist_h);
    arm_full_bundle(st, m);
    EXPECT_EQ(st.credit_pool_height(), static_cast<int32_t>(P));
    EXPECT_EQ(st.credit_pool(), CP0);
    EXPECT_TRUE(st.make_embedded_work_inputs().viable())
        << "restored credit pool current at the restart tip must serve daemonlessly";

    // First incremental block @ H carrying the from-wire committed balance CP1.
    BlockType blk = e2_block_with_cbtx(static_cast<int32_t>(H), CP1);
    // Sanity: the block's OWN coinbase commits CP1 at nHeight H (the independent
    // source of truth the advance is verified against — re-parsed here).
    {
        CCbTx from_wire;
        ASSERT_TRUE(parse_cbtx(blk.m_txs[0].extra_payload, from_wire));
        ASSERT_EQ(from_wire.nHeight, static_cast<int32_t>(H));
        ASSERT_EQ(from_wire.creditPoolBalance, CP1);
    }
    m.on_block_connected(blk, H);
    // The pool advanced to the tip, matching the block's OWN committed value.
    EXPECT_EQ(st.credit_pool_height(), static_cast<int32_t>(H))
        << "the pool must advance to the ingested block's height independently";
    EXPECT_EQ(st.credit_pool(), CP1)
        << "advance must equal the block's from-wire committed creditPoolBalance";
    // Non-self-referential: the advanced value equals CP0 + the INDEPENDENTLY
    // derived platform reward, i.e. the seed plus this block's own accrual —
    // reproduced from the raw formula, not read back off a template we built.
    EXPECT_EQ(st.credit_pool(), CP0 + e2_platform_reward_oracle(H));

    // The advanced pool is fresh at the new tip → still serves at H.
    m.on_new_tip(H, raw256(0x55), 0x1b104be3u, 1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER);
    // (sml_current_hash must also be at the new tip for full viability; the
    // credit-pool axis specifically is proven fresh below regardless.)
    EXPECT_EQ(st.credit_pool_height(), static_cast<int32_t>(H));
}

// E2 — the independent verify is REAL: a block whose coinbase commits a WRONG
// creditPoolBalance (inconsistent with the accrual) is REJECTED — the freshness
// seed is NOT advanced, so the arm fails closed rather than serving a bad-cbtx
// balance. A self-referential built==seed+reward check could not catch this
// (it would happily rebuild the wrong value); comparing our independent accrual
// to the block's own committed value does.
TEST(DashEmbeddedGbt, E2CreditPoolDriftFailsClosedNotSelfReferential) {
    const uint32_t P      = H - 1;
    const uint256  HASH_P = raw256(0x54);
    const int64_t  CP0    = 111'000'000'000LL;
    const int64_t  reward = e2_platform_reward_oracle(H);
    const int64_t  CP1_correct = CP0 + reward;
    const int64_t  CP1_wrong   = CP1_correct + 1;   // off-by-one bad-cbtx

    NodeCoinState st;
    CoinStateMaintainer m(st);
    // Warm-restore the pool @ P (contiguous predecessor of block H).
    st.sml() = CSimplifiedMNList(std::vector<CSimplifiedMNListEntry>{e2_sml_entry(0x40)});
    st.set_have_sml(true);
    st.set_sml_current_hash(HASH_P);
    st.set_credit_pool(CP0, HASH_P, static_cast<int32_t>(P));
    m.restore_credit_pool(CP0, P);

    // A block @ H whose committed balance disagrees with the accrual by 1 duff.
    BlockType bad = e2_block_with_cbtx(static_cast<int32_t>(H), CP1_wrong);
    m.on_block_connected(bad, H);

    // Fail closed: the freshness seed stayed at P (did NOT advance to H), so with
    // the tip at H the credit-pool gate refuses the arm — the invariant "never
    // serve a wrong creditPoolBalance" holds by failing to fallback, not by
    // adopting the bad value.
    EXPECT_EQ(st.credit_pool_height(), static_cast<int32_t>(P))
        << "a drifted (bad-cbtx) balance must NOT advance the freshness seed";
    EXPECT_NE(st.credit_pool(), CP1_wrong)
        << "the wrong committed balance must never be adopted as the seed";
    EXPECT_EQ(st.credit_pool(), CP0)
        << "the seed must remain the last independently-confirmed value";

    // Contrast — the SAME block with the CORRECT committed balance DOES verify
    // (contiguous advance from the restored P) and advances the seed to H. This
    // is what proves the check is discriminating, not merely always-refusing.
    NodeCoinState st_ok;
    CoinStateMaintainer m_ok(st_ok);
    st_ok.set_credit_pool(CP0, HASH_P, static_cast<int32_t>(P));
    m_ok.restore_credit_pool(CP0, P);
    BlockType good = e2_block_with_cbtx(static_cast<int32_t>(H), CP1_correct);
    m_ok.on_block_connected(good, H);
    EXPECT_EQ(st_ok.credit_pool_height(), static_cast<int32_t>(H));
    EXPECT_EQ(st_ok.credit_pool(), CP1_correct);
}

// E2 finding A — a FORGED block body (real PoW header, fake type-5 coinbase with
// the CORRECT nHeight but a WRONG creditPoolBalance and an unbound merkle root)
// must be REFUSED at ingestion and must NOT advance the freshness seed. Without
// the body↔header binding this forgery would ride the non-contiguous bootstrap,
// advance the gate, and be SERVED as a bad-cbtx — E2 widened this trust surface,
// so the binding closes it. The verify is discriminating: a well-BOUND block
// (correct root committing its own coinbase) still advances.
TEST(DashEmbeddedGbt, E2ForgedBlockBodyRefusedDoesNotAdvanceSeed) {
    const uint32_t P      = H - 1;
    const uint256  HASH_P = raw256(0x54);
    const int64_t  CP0    = 111'000'000'000LL;
    const int64_t  reward = e2_platform_reward_oracle(H);
    const int64_t  CP1_real   = CP0 + reward;
    const int64_t  CP1_forged = CP1_real + 777;   // attacker's fabricated balance

    NodeCoinState st;
    CoinStateMaintainer m(st);
    st.set_credit_pool(CP0, HASH_P, static_cast<int32_t>(P));
    m.restore_credit_pool(CP0, P);

    // Forged body: right nHeight (H), wrong creditPoolBalance, header still commits
    // the REAL coinbase → the delivered body does not fold to the committed root.
    BlockType forged = e2_forged_block(static_cast<int32_t>(H), CP1_real, CP1_forged);
    ASSERT_FALSE(dash::coin::block_body_binds_to_header(forged))
        << "the forged body must fail the merkle body↔header binding";
    // Re-parse confirms the forgery carries the right height but the fake balance.
    {
        CCbTx fake;
        ASSERT_TRUE(parse_cbtx(forged.m_txs[0].extra_payload, fake));
        ASSERT_EQ(fake.nHeight, static_cast<int32_t>(H));
        ASSERT_EQ(fake.creditPoolBalance, CP1_forged);
    }
    m.on_block_connected(forged, H);

    // Refused: the seed stayed at P — the fabricated balance was never adopted.
    EXPECT_EQ(st.credit_pool_height(), static_cast<int32_t>(P))
        << "a forged/unbound body must NOT advance the freshness seed";
    EXPECT_EQ(st.credit_pool(), CP0);
    EXPECT_NE(st.credit_pool(), CP1_forged);

    // Discriminating: a well-bound block at H (root commits its own coinbase) IS
    // accepted and advances — the guard rejects only unbound bodies, not valid ones.
    BlockType good = e2_block_with_cbtx(static_cast<int32_t>(H), CP1_real);
    ASSERT_TRUE(dash::coin::block_body_binds_to_header(good));
    m.on_block_connected(good, H);
    EXPECT_EQ(st.credit_pool_height(), static_cast<int32_t>(H));
    EXPECT_EQ(st.credit_pool(), CP1_real);
}
