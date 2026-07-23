// SPDX-License-Identifier: AGPL-3.0-or-later
/// Phase C-TEMPLATE step 6 -- NodeCoinState live-wire KAT.
///
/// #672 proved select_dash_work()'s COLD arm (has_state=false -> dashd
/// fallback = retained safety path, verify point 3). This suite proves the
/// HOT arm the node-held coin-state slice unlocks:
///
///   populated NodeCoinState -> select_work() routes WorkSource::Embedded and
///   returns EXACTLY the DashWorkData that a direct build_embedded_workdata()
///   over the same MN list + mempool + tip params produces -- i.e. wiring the
///   bundle in changes nothing about the oracle-parity template, it only
///   flips which arm runs. The dashd fallback closure is NOT invoked on the
///   hot path; it IS invoked (and only it) when the bundle is unpopulated or
///   has been invalidate()d.
///
/// Construction mirrors test_dash_embedded_gbt.cpp exactly (same single_mn /
/// mempool seeding) so the two suites pin the SAME projection from the two
/// call shapes. No fabricated oracle values -- the "expected" work IS an
/// independent build_embedded_workdata() call, compared field-for-field.

#include <gtest/gtest.h>

#include <impl/dash/coin/node_coin_state.hpp>
#include <impl/dash/coin/embedded_gbt.hpp>
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/utxo_adapter.hpp>
#include <impl/dash/coin/rpc_data.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/coin_state_maintainer.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>
#include <impl/dash/coin/vendor/smldiff.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/quorum_manager.hpp>
#include <impl/dash/coin/quorum_root.hpp>
#include <impl/dash/coin/dkg_window.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

using dash::coin::NodeCoinState;
using dash::coin::DashWorkData;
using dash::coin::WorkSource;
using dash::coin::WorkSelection;
using dash::coin::MNState;
using dash::coin::MnStateMachine;
using dash::coin::Mempool;
using dash::coin::MutableTransaction;
using dash::coin::build_embedded_workdata;
using dash::coin::CoinStateMaintainer;
using dash::coin::QuorumManager;
using dash::coin::vendor::CSimplifiedMNList;
using dash::coin::vendor::CSimplifiedMNListEntry;
using dash::coin::vendor::CSimplifiedMNListDiff;
using dash::coin::vendor::CCbTx;
using ::core::coin::UTXOViewCache;
using ::core::coin::Outpoint;
using ::core::coin::Coin;
using ::bitcoin_family::coin::TxIn;
using ::bitcoin_family::coin::TxOut;

static constexpr uint8_t  DASH_PUBKEY_VER = 76;
static constexpr uint8_t  DASH_P2SH_VER   = 16;
static constexpr uint32_t H = 2'400'000;   // past MN_RR: platform burn active

static uint256 raw256(uint8_t base) {
    uint256 h;
    std::array<uint8_t, 32> p{};
    for (size_t i = 0; i < 32; ++i) p[i] = static_cast<uint8_t>(base + i);
    std::memcpy(h.data(), p.data(), 32);
    return h;
}

static std::vector<unsigned char> p2pkh_script(uint8_t hashseed) {
    std::vector<unsigned char> s{0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(static_cast<unsigned char>(hashseed + i));
    s.push_back(0x88); s.push_back(0xac);
    return s;
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

// Seed `st.mnstates()` with a single valid MN paying `payout`.
static void seed_single_mn(NodeCoinState& st, const std::vector<unsigned char>& payout) {
    MNState s;
    s.isValid = true;
    s.nRegisteredHeight = 2'300'000;
    s.nLastPaidHeight = 0;
    s.scriptPayout.m_data = payout;
    st.mnstates().load(std::vector<std::pair<uint256, MNState>>{{raw256(0x01), s}});
}

static void expect_workdata_eq(const DashWorkData& a, const DashWorkData& b) {
    EXPECT_EQ(a.m_version, b.m_version);
    EXPECT_EQ(a.m_previous_block, b.m_previous_block);
    EXPECT_EQ(a.m_height, b.m_height);
    EXPECT_EQ(a.m_coinbase_value, b.m_coinbase_value);
    EXPECT_EQ(a.m_bits, b.m_bits);
    EXPECT_EQ(a.m_curtime, b.m_curtime);
    EXPECT_EQ(a.m_mintime, b.m_mintime);
    EXPECT_EQ(a.m_payment_amount, b.m_payment_amount);
    EXPECT_EQ(a.m_tx_hashes, b.m_tx_hashes);
    EXPECT_EQ(a.m_tx_fees, b.m_tx_fees);
    EXPECT_EQ(a.m_txs.size(), b.m_txs.size());
}

// ════════════════════════════════════════════════════════════════════════
// HOT arm: populated bundle -> Embedded, byte-equal to direct build.
// ════════════════════════════════════════════════════════════════════════
TEST(DashNodeCoinState, PopulatedRoutesEmbeddedByteEqualToDirectBuild) {
    UTXOViewCache utxo(nullptr);
    uint256 prev = raw256(0x77);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, /*height=*/1, /*cb=*/false));

    auto payout = p2pkh_script(0x30);
    const uint256 prev_hash = raw256(0xAB);
    const uint32_t bits = 0x1b104be3u;
    const uint32_t mtp  = 1'700'000'000u;
    const uint32_t curtime = 1'700'000'123u;   // pin the injectable seams so
    const uint32_t version = 0x20000000u;      // both build paths are identical

    NodeCoinState st;
    seed_single_mn(st, payout);
    st.mempool().set_utxo(&utxo);
    ASSERT_TRUE(st.mempool().add_tx(make_spend(prev, 0, 90'000, /*salt=*/1)));  // fee 10'000
    st.set_tip(H - 1, prev_hash, bits, mtp, DASH_PUBKEY_VER, DASH_P2SH_VER, curtime, version);

    ASSERT_TRUE(st.populated());
    ASSERT_TRUE(st.make_embedded_work_inputs().viable());

    // Independent reference: the SAME projection built directly. The node
    // bundle must reproduce it exactly, only choosing the Embedded arm.
    DashWorkData reference = build_embedded_workdata(
        H - 1, prev_hash, st.mnstates(), st.mempool(),
        bits, mtp, DASH_PUBKEY_VER, DASH_P2SH_VER, curtime, version);

    bool fallback_called = false;
    WorkSelection sel = st.select_work([&]() {
        fallback_called = true;
        return DashWorkData{};   // sentinel: must NOT be returned on hot path
    });

    EXPECT_EQ(sel.source, WorkSource::Embedded);
    EXPECT_FALSE(fallback_called) << "dashd fallback must not run when embedded is viable";
    EXPECT_EQ(sel.work.m_height, H);
    expect_workdata_eq(sel.work, reference);
}

// ════════════════════════════════════════════════════════════════════════
// COLD arm (retained fallback): unpopulated / invalidated -> DashdFallback.
// ════════════════════════════════════════════════════════════════════════
TEST(DashNodeCoinState, UnpopulatedRoutesRetainedDashdFallback) {
    NodeCoinState st;   // default: not populated
    ASSERT_FALSE(st.populated());
    ASSERT_FALSE(st.make_embedded_work_inputs().viable());

    DashWorkData sentinel;
    sentinel.m_height = 4'242'424u;   // a value the embedded path would never emit here

    bool fallback_called = false;
    WorkSelection sel = st.select_work([&]() {
        fallback_called = true;
        return sentinel;
    });

    EXPECT_EQ(sel.source, WorkSource::DashdFallback);
    EXPECT_TRUE(fallback_called) << "the always-reachable dashd arm must run when no coin-state";
    EXPECT_EQ(sel.work.m_height, sentinel.m_height);
}

TEST(DashNodeCoinState, InvalidateRevertsToFallback) {
    UTXOViewCache utxo(nullptr);
    uint256 prev = raw256(0x77);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));

    NodeCoinState st;
    seed_single_mn(st, p2pkh_script(0x30));
    st.mempool().set_utxo(&utxo);
    ASSERT_TRUE(st.mempool().add_tx(make_spend(prev, 0, 90'000, 1)));
    st.set_tip(H - 1, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);
    ASSERT_TRUE(st.make_embedded_work_inputs().viable());

    st.invalidate();   // reorg / mempool flush
    EXPECT_FALSE(st.populated());
    EXPECT_FALSE(st.make_embedded_work_inputs().viable());

    bool fallback_called = false;
    WorkSelection sel = st.select_work([&]() { fallback_called = true; return DashWorkData{}; });
    EXPECT_EQ(sel.source, WorkSource::DashdFallback);
    EXPECT_TRUE(fallback_called);
}

// ════════════════════════════════════════════════════════════════════════
// CCbTx WIRING (v0.2.4 daemonless critical path).
//
// Proves the end-to-end seam: a NodeCoinState carrying an applied SML +
// QuorumManager routes the Embedded arm AND emits the real DIP-0004 type-5
// CCbTx extra_payload (non-empty m_coinbase_payload), byte-identical to a
// direct build_embedded_workdata() call passing the same SML/quorum seams.
// The pre-wiring bundle (no SML) emits an EMPTY payload — the C1 gap.
// ════════════════════════════════════════════════════════════════════════

static CSimplifiedMNListEntry sml_entry(uint8_t seed) {
    CSimplifiedMNListEntry e;
    e.proRegTxHash = raw256(seed);
    e.confirmedHash = raw256(seed + 1);
    e.isValid = true;
    return e;
}

// Seed the NodeCoinState SML/quorum stores directly (as the maintainer would
// after an accepted mnlistdiff) and mark have_sml.
static void seed_sml(NodeCoinState& st) {
    st.sml().mnList = {sml_entry(0x40), sml_entry(0x60)};
    st.sml().sort();
    st.set_have_sml(true);
}

TEST(DashNodeCoinState, SmlPresentEmitsRealCcbtxPayloadByteEqualToDirectBuild) {
    UTXOViewCache utxo(nullptr);
    uint256 prev = raw256(0x77);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));

    auto payout = p2pkh_script(0x30);
    const uint256 prev_hash = raw256(0xAB);
    const uint32_t bits = 0x1b104be3u, mtp = 1'700'000'000u;
    const uint32_t curtime = 1'700'000'123u, version = 0x20000000u;

    NodeCoinState st;
    seed_single_mn(st, payout);
    seed_sml(st);
    st.mempool().set_utxo(&utxo);
    ASSERT_TRUE(st.mempool().add_tx(make_spend(prev, 0, 90'000, 1)));
    st.set_tip(H - 1, prev_hash, bits, mtp, DASH_PUBKEY_VER, DASH_P2SH_VER, curtime, version);

    ASSERT_TRUE(st.make_embedded_work_inputs().viable());

    // Independent reference: direct build with the SAME SML/quorum seams.
    CSimplifiedMNList ref_sml = st.sml();
    QuorumManager ref_qmgr;   // empty active set == st.qmgr() here
    DashWorkData reference = build_embedded_workdata(
        H - 1, prev_hash, st.mnstates(), st.mempool(),
        bits, mtp, DASH_PUBKEY_VER, DASH_P2SH_VER, curtime, version,
        /*underfill=*/nullptr, &ref_sml, &ref_qmgr,
        /*best_cl_height=*/0, dash::coin::k_zero_cl_sig, /*credit_pool=*/0);

    bool fallback_called = false;
    WorkSelection sel = st.select_work([&]() { fallback_called = true; return DashWorkData{}; });

    EXPECT_EQ(sel.source, WorkSource::Embedded);
    EXPECT_FALSE(fallback_called);
    // THE CORE ASSERTION: a real, non-empty type-5 payload, byte-equal to ref.
    EXPECT_FALSE(sel.work.m_coinbase_payload.empty())
        << "SML-backed bundle must emit a non-empty CCbTx extra_payload";
    EXPECT_EQ(sel.work.m_coinbase_payload, reference.m_coinbase_payload);

    // And it decodes as a v3 CCbTx whose merkleRootMNList is our SML root.
    CCbTx decoded;
    ASSERT_TRUE(dash::coin::vendor::parse_cbtx(sel.work.m_coinbase_payload, decoded));
    EXPECT_EQ(decoded.nVersion, CCbTx::VERSION_CLSIG_AND_BALANCE);
    EXPECT_EQ(decoded.nHeight, static_cast<int32_t>(H));
    EXPECT_EQ(decoded.merkleRootMNList, ref_sml.CalcMerkleRoot());
    EXPECT_EQ(decoded.merkleRootQuorums,
              dash::coin::compute_merkle_root_quorums(ref_qmgr));
}

// Without an SML the bundle still routes Embedded but emits an EMPTY payload —
// the exact C1 gap (invalid on mainnet). This pins the pre/post contrast.
TEST(DashNodeCoinState, NoSmlEmitsEmptyPayloadC1Gap) {
    UTXOViewCache utxo(nullptr);
    uint256 prev = raw256(0x77);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));
    NodeCoinState st;
    seed_single_mn(st, p2pkh_script(0x30));
    st.mempool().set_utxo(&utxo);
    ASSERT_TRUE(st.mempool().add_tx(make_spend(prev, 0, 90'000, 1)));
    st.set_tip(H - 1, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);
    WorkSelection sel = st.select_work([&]() { return DashWorkData{}; });
    EXPECT_EQ(sel.source, WorkSource::Embedded);
    EXPECT_TRUE(sel.work.m_coinbase_payload.empty());
}

// require_sml gate (review finding H3): the embedded arm must NOT serve a template with
// no CCbTx. With the gate on, a bundle lacking an SML falls back to dashd;
// applying an SML flips it to Embedded.
TEST(DashNodeCoinState, RequireSmlGateFallsBackUntilSmlApplied) {
    UTXOViewCache utxo(nullptr);
    uint256 prev = raw256(0x77);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));
    NodeCoinState st;
    st.set_require_sml(true);
    seed_single_mn(st, p2pkh_script(0x30));
    st.mempool().set_utxo(&utxo);
    ASSERT_TRUE(st.mempool().add_tx(make_spend(prev, 0, 90'000, 1)));
    st.set_tip(H - 1, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);

    EXPECT_FALSE(st.make_embedded_work_inputs().viable())
        << "require_sml + no SML must gate the embedded arm off";
    bool fb = false;
    EXPECT_EQ(st.select_work([&]{ fb = true; return DashWorkData{}; }).source,
              WorkSource::DashdFallback);
    EXPECT_TRUE(fb);

    seed_sml(st);
    // Freshness gate (H-6): require_sml also requires the SML to be current AT
    // the tip we build on. seed_sml() bypasses the maintainer, so set the
    // current-at hash to the tip prev_hash explicitly (the maintainer does this
    // from diff.blockHash on the live path).
    st.set_sml_current_hash(raw256(0xAB));
    EXPECT_TRUE(st.make_embedded_work_inputs().viable());
    EXPECT_EQ(st.select_work([&]{ return DashWorkData{}; }).source,
              WorkSource::Embedded);
}

// Freshness gate (H-6): with require_sml + an applied SML, a tip that moves
// AHEAD of the SML (sml_current_hash != prev_hash) must gate the embedded arm
// OFF until a fresh mnlistdiff re-aligns the SML to the new tip — no stale-SML
// template served at a moved tip.
TEST(DashNodeCoinState, RequireSmlFreshnessGateHoldsWhenSmlStaleAtTip) {
    NodeCoinState st;
    st.set_require_sml(true);
    seed_single_mn(st, p2pkh_script(0x30));
    seed_sml(st);
    // SML is current at block A, but the tip advanced to build on block B.
    st.set_sml_current_hash(raw256(0xAB));
    st.set_tip(H - 1, raw256(0xCD), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);
    EXPECT_FALSE(st.make_embedded_work_inputs().viable())
        << "stale SML at a moved tip must gate the embedded arm off";

    // The fresh diff for block B lands: SML now current at the tip -> viable.
    st.set_sml_current_hash(raw256(0xCD));
    EXPECT_TRUE(st.make_embedded_work_inputs().viable());
}

// Superblock guard: on a superblock-height NEXT block, the embedded arm must
// refuse (route to the reward-safe dashd fallback that carries the governance
// outputs) rather than emit an invalid non-superblock coinbase.
TEST(DashNodeCoinState, SuperblockHeightRefusesEmbedded) {
    NodeCoinState st;
    seed_single_mn(st, p2pkh_script(0x30));
    seed_sml(st);
    st.set_sml_current_hash(raw256(0xAB));
    // Predicate flags exactly height H (the next block) as a superblock.
    st.set_is_superblock_fn([](uint32_t next_h) { return next_h == H; });

    // Tip at H-1 => next block is H => superblock => embedded refused.
    st.set_tip(H - 1, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);
    EXPECT_FALSE(st.make_embedded_work_inputs().viable())
        << "superblock height must refuse the embedded arm";
    bool fb = false;
    EXPECT_EQ(st.select_work([&]{ fb = true; return DashWorkData{}; }).source,
              WorkSource::DashdFallback);
    EXPECT_TRUE(fb);

    // Tip at H => next block is H+1 => not a superblock => embedded serves.
    st.set_tip(H, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);
    EXPECT_TRUE(st.make_embedded_work_inputs().viable());
}

// BLOCKER-1 (PR #780): is_dkg_commitment_window over REAL live-testnet heights —
// the DKG mining windows the review pulled must be flagged, the fixture height
// (a non-qc coinbase-only block) must not.
TEST(DashDkgWindow, RealTestnetCommitmentHeightsFlagged) {
    // Live testnet blocks 1518418/19/42 each carry 3 mandatory type-6 commitments.
    EXPECT_TRUE(dash::coin::is_dkg_commitment_window(1518418));  // h%24=10
    EXPECT_TRUE(dash::coin::is_dkg_commitment_window(1518419));  // h%24=11
    EXPECT_TRUE(dash::coin::is_dkg_commitment_window(1518442));  // h%24=10
    // The byte-parity fixture height 1518413 is a non-qc block (h%24=5).
    EXPECT_FALSE(dash::coin::is_dkg_commitment_window(1518413));
    // Whole [10,18] window of the 24-interval types must be refused.
    for (uint32_t p = 10; p <= 18; ++p)
        EXPECT_TRUE(dash::coin::is_dkg_commitment_window(1518408 + p));
    // Phases just outside the window proceed.
    EXPECT_FALSE(dash::coin::is_dkg_commitment_window(1518408 + 9));
    EXPECT_FALSE(dash::coin::is_dkg_commitment_window(1518408 + 19));
}

// BLOCKER-1 viability: the embedded arm fails closed on a DKG commitment height
// and serves on a clear height.
TEST(DashNodeCoinState, DkgCommitmentHeightRefusesEmbedded) {
    NodeCoinState st;
    seed_single_mn(st, p2pkh_script(0x30));
    seed_sml(st);
    st.set_commitment_window_fn(
        [](uint32_t next_h) { return dash::coin::is_dkg_commitment_window(next_h); });

    // Tip at 1518417 => next block 1518418 (commitment window) => refuse.
    st.set_sml_current_hash(raw256(0xAB));
    st.set_tip(1518417, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);
    EXPECT_FALSE(st.make_embedded_work_inputs().viable())
        << "DKG commitment height must fail closed to the dashd fallback";

    // Tip at 1518412 => next block 1518413 (clear) => serve.
    st.set_tip(1518412, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);
    EXPECT_TRUE(st.make_embedded_work_inputs().viable());
}

// E1 — daemonless DKG-window serving: with a qc plan installed the SAME
// window height that BLOCKER-1 refused is SERVED, the template carries the
// mandatory type-6 txs (dkg_commitments.hpp plan, testnet types 1/4/6 at an
// interval-24 window height), and the pre-emit gate both accepts the honest
// template and discards a tampered one (missing commitment => the block
// dashd would reject as bad-qc-missing never leaves the node).
TEST(DashNodeCoinState, QcPlanServesDkgWindowHeightAndEmitGateEnforcesIt) {
    NodeCoinState st;
    seed_single_mn(st, p2pkh_script(0x30));
    seed_sml(st);
    st.set_require_sml(true);
    st.set_commitment_window_fn(
        [](uint32_t next_h) { return dash::coin::is_dkg_commitment_window(next_h); });
    // The same closure shape main_dash installs: the daemonless plan over
    // the node's own QuorumManager + a header-chain hash-at-height lookup.
    // Attested failed-DKG evidence for every slot keeps the all-null plan
    // servable under the height-completeness gate (block-1520106 fix); the
    // no-evidence fail-closed leg is asserted further down.
    auto make_plan_fn = [&st](dash::coin::DkgNullEvidenceFn evidence) {
        return [&st, evidence](uint32_t next_h) {
            return dash::coin::build_daemonless_qc_plan(
                dash::coin::LlmqNetwork::Testnet, next_h, st.qmgr(),
                [](uint32_t h) -> std::optional<uint256> {
                    uint256 u;
                    std::memset(u.data(), 0xCD, 32);
                    std::memcpy(u.data(), &h, 4);
                    return u;
                },
                [](const uint256&) -> std::optional<uint32_t> {
                    return std::nullopt;   // never needed for an all-null plan
                },
                /*cache=*/nullptr, evidence);
        };
    };
    st.set_qc_plan_fn(make_plan_fn(
        [](uint8_t, const uint256&) { return true; }));

    // Tip 1518417 => next block 1518418 (phase 10: the exact height the
    // BLOCKER-1 test above proves REFUSED without a plan).
    st.set_sml_current_hash(raw256(0xAB));
    st.set_tip(1518417, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER, 1'700'000'123u, 0x20000000u);

    auto e = st.make_embedded_work_inputs();
    ASSERT_TRUE(e.viable())
        << "E1: a DKG window height must now be SERVED daemonlessly";
    // Testnet interval-24 types LLMQ_50_60 / LLMQ_100_67 / LLMQ_25_67, all
    // unmined in the (empty) quorum set => 3 mandatory null commitments.
    ASSERT_EQ(e.qc_commitments.size(), 3u);
    ASSERT_TRUE(e.has_quorum_root_override);

    bool fallback_called = false;
    WorkSelection sel = st.select_work([&]() {
        fallback_called = true;
        return DashWorkData{};
    });
    EXPECT_EQ(sel.source, WorkSource::Embedded);
    EXPECT_FALSE(fallback_called);
    ASSERT_EQ(sel.work.m_txs.size(), 3u);
    for (size_t i = 0; i < 3; ++i)
        EXPECT_EQ(sel.work.m_txs[i].type, 6) << "qc txs must lead the tx set";
    EXPECT_TRUE(st.embedded_template_emit_ok(sel.work))
        << "the honest daemonless qc template must pass the pre-emit gate";

    // Tampered: drop one mandatory commitment => the emit gate must discard
    // (that block is dashd bad-qc-missing).
    DashWorkData tampered = sel.work;
    tampered.m_txs.pop_back();
    EXPECT_FALSE(st.embedded_template_emit_ok(tampered));

    // Tampered: wrong committed quorum root => discard (wrong-root block).
    DashWorkData wrong_root = sel.work;
    {
        dash::coin::vendor::CCbTx cb;
        ASSERT_TRUE(dash::coin::vendor::parse_cbtx(wrong_root.m_coinbase_payload, cb));
        cb.merkleRootQuorums = raw256(0x5A);
        wrong_root.m_coinbase_payload = dash::coin::encode_cbtx(cb);
    }
    EXPECT_FALSE(st.embedded_template_emit_ok(wrong_root));

    // COMPLETENESS GATE (block-1520106 fix): the SAME closure without
    // failed-DKG evidence must fail the whole height closed — mandatory
    // slots with neither a verified real commitment nor attested-null
    // evidence are unservable (null-where-unsourced is the bad-cbtx).
    st.set_qc_plan_fn(make_plan_fn(nullptr));
    EXPECT_FALSE(st.make_embedded_work_inputs().viable())
        << "unattested mandatory slots must fail closed to the dashd arm";

    // And a plan fn that cannot derive the set (header gap) fails closed —
    // the PHASE-1 reward-safe routing, not a wrong block.
    st.set_qc_plan_fn([](uint32_t) { return std::nullopt; });
    EXPECT_FALSE(st.make_embedded_work_inputs().viable());
}

// BLOCKER-2 viability: a stale/absent bestCL fails closed; a fresh one serves.
TEST(DashNodeCoinState, StaleBestClRefusesEmbedded) {
    NodeCoinState st;
    seed_single_mn(st, p2pkh_script(0x30));
    seed_sml(st);
    st.set_sml_current_hash(raw256(0xAB));
    st.set_require_fresh_bestcl(true);

    // No ChainLock observed (best_cl_height == 0) at a high tip => refuse.
    st.set_tip(1518412, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);
    EXPECT_FALSE(st.make_embedded_work_inputs().viable())
        << "absent bestCL must fail closed";

    // A ChainLock two blocks back (prev_height-2) is still too stale => refuse.
    std::array<uint8_t, 96> sig{}; sig[0] = 0x11;
    st.set_best_cl(1518410, sig);   // prev_height-2
    EXPECT_FALSE(st.make_embedded_work_inputs().viable())
        << "bestCL older than prev_height-1 must fail closed";

    // A ChainLock at prev_height-1 is fresh enough => serve (matches the
    // real fixture: block 1518412 committed bestCL height 1518411 = prev-1).
    st.set_best_cl(1518411, sig);
    EXPECT_TRUE(st.make_embedded_work_inputs().viable());

    // A ChainLock at the tip itself is also fine.
    st.set_best_cl(1518412, sig);
    EXPECT_TRUE(st.make_embedded_work_inputs().viable());
}

// SOAK FIX v3 (INDEPENDENT height check): the credit-pool seed can lag one block
// behind the tip while its VALUE and hash-tag look fresh (built = stale_seed +
// reward is self-consistent but wrong — 3 soaks refuted the hash- and value-self-
// checks). The independent gate compares the seed cbTx's OWN height to the tip:
// a seed for block N-1 while building on tip N-1 (to make block N) must have
// seed height == N-1. A seed at N-2 fails closed. Real re-soak #2 values.
TEST(DashNodeCoinState, CreditPoolSeedHeightBehindTipRefusesEmbedded) {
    NodeCoinState st;
    seed_single_mn(st, p2pkh_script(0x30));
    seed_sml(st);
    st.set_require_sml(true);
    st.set_sml_current_hash(raw256(0xAB));   // SML fresh at the tip
    st.set_require_fresh_credit_pool(true);
    // Building block 1518657 (tip = 1518656 = prev) — the re-soak #2 failure.
    st.set_tip(1518656, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);

    // Seed is creditPool(1518655) at HEIGHT 1518655 — one block behind the tip
    // (exactly what the soak committed). Its value/hash look plausibly fresh, but
    // the height (1518655) != tip height (1518656) => FAIL CLOSED.
    st.set_credit_pool(33974827375826LL, raw256(0xAB), 1518655);
    EXPECT_FALSE(st.make_embedded_work_inputs().viable())
        << "a seed one block behind the tip must fail closed (independent height check)";
    {
        bool fb = false;
        EXPECT_EQ(st.select_work([&]{ fb = true; return DashWorkData{}; }).source,
                  WorkSource::DashdFallback);
        EXPECT_TRUE(fb);
    }

    // Seed advances to creditPool(1518656) at HEIGHT 1518656 == tip => serves.
    st.set_credit_pool(33974894342656LL, raw256(0xAB), 1518656);
    ASSERT_TRUE(st.make_embedded_work_inputs().viable());
    WorkSelection sel = st.select_work([]{ return DashWorkData{}; });
    ASSERT_EQ(sel.source, WorkSource::Embedded);
    EXPECT_TRUE(st.embedded_template_emit_ok(sel.work));
}

// Defence-in-depth: the pre-emit VALUE re-check still rejects a built template
// whose committed creditPool != current_seed + reward (a seed with a matching
// height but a value that changed between build and emit).
TEST(DashNodeCoinState, StaleBuiltCreditPoolFailsPreEmitValueCheck) {
    NodeCoinState st;
    seed_single_mn(st, p2pkh_script(0x30));
    seed_sml(st);
    st.set_require_sml(true);
    st.set_sml_current_hash(raw256(0xAB));
    st.set_require_fresh_credit_pool(true);
    st.set_tip(1518608, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);

    const int64_t v1 = 33971612967986LL;
    const int64_t v2 = v1 + 66966830LL;
    // Seed height == tip (1518608) so viability/height pass; build a template.
    st.set_credit_pool(v1, raw256(0xAB), 1518608);
    ASSERT_TRUE(st.make_embedded_work_inputs().viable());
    WorkSelection sel = st.select_work([]{ return DashWorkData{}; });
    ASSERT_EQ(sel.source, WorkSource::Embedded);
    EXPECT_TRUE(st.embedded_template_emit_ok(sel.work));

    // The seed VALUE changes (height still 1518608): the built template's baked
    // creditPool now mismatches current_seed + reward => VALUE re-check rejects.
    st.set_credit_pool(v2, raw256(0xAB), 1518608);
    EXPECT_FALSE(st.embedded_template_emit_ok(sel.work))
        << "a built creditPool != current seed + reward must fail the value re-check";
}

// BLOCKER-3 (PR #780): the pre-emit hard gate accepts a valid built CbTx and
// fails closed on a tampered/empty payload, a re-asserted height-class guard,
// or an unhealthy quorum set.
TEST(DashNodeCoinState, PreEmitGateAcceptsValidRejectsTampered) {
    NodeCoinState st;
    seed_single_mn(st, p2pkh_script(0x30));
    seed_sml(st);
    st.set_require_sml(true);
    st.set_sml_current_hash(raw256(0xAB));
    st.set_tip(1518412, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);

    ASSERT_TRUE(st.make_embedded_work_inputs().viable());
    WorkSelection sel = st.select_work([]{ return DashWorkData{}; });
    ASSERT_EQ(sel.source, WorkSource::Embedded);
    ASSERT_FALSE(sel.work.m_coinbase_payload.empty());

    // Valid built template passes the pre-emit gate.
    EXPECT_TRUE(st.embedded_template_emit_ok(sel.work));

    // Tamper a byte inside merkleRootMNList => root mismatch => fail closed.
    DashWorkData bad = sel.work;
    bad.m_coinbase_payload[10] ^= 0xFF;
    EXPECT_FALSE(st.embedded_template_emit_ok(bad));

    // Empty payload (the C1 gap) under require_sml => fail closed.
    DashWorkData empty = sel.work;
    empty.m_coinbase_payload.clear();
    EXPECT_FALSE(st.embedded_template_emit_ok(empty));

    // Height-class guard re-asserted at emit: a commitment window fails closed
    // even though the payload itself is well-formed.
    st.set_commitment_window_fn([](uint32_t){ return true; });
    EXPECT_FALSE(st.embedded_template_emit_ok(sel.work));
    st.set_commitment_window_fn(nullptr);
    EXPECT_TRUE(st.embedded_template_emit_ok(sel.work));

    // Quorum-tail health: an unhealthy quorum set fails viability closed (the
    // review nit — a silently-skipped quorum tail leaves a stale set).
    st.set_quorum_healthy(false);
    EXPECT_FALSE(st.make_embedded_work_inputs().viable());
    st.set_quorum_healthy(true);
    EXPECT_TRUE(st.make_embedded_work_inputs().viable());
}

// Maintainer wiring: on_mnlistdiff applies the vendored apply_diff into the
// node-held SML and flips have_sml, so a subsequent select_work emits the
// real payload — the full reception path minus the socket.
TEST(DashNodeCoinState, MaintainerOnMnlistdiffPopulatesSmlAndEmitsPayload) {
    UTXOViewCache utxo(nullptr);
    uint256 prev = raw256(0x77);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));

    NodeCoinState st;
    st.set_require_sml(true);
    CoinStateMaintainer maint(st);

    // Reception order mirrors the live node: MN payee set THROUGH the
    // maintainer (leg 4 — arms the maintainer's own have_mn gate), mempool
    // (leg 1), then the SML diff (new leg), then the tip (leg 2).
    MNState pm; pm.isValid = true; pm.nRegisteredHeight = 2'300'000;
    pm.nLastPaidHeight = 0; pm.scriptPayout.m_data = p2pkh_script(0x30);
    maint.on_mn_list_update(
        std::vector<std::pair<uint256, MNState>>{{raw256(0x01), pm}}, 0);
    st.mempool().set_utxo(&utxo);
    ASSERT_TRUE(st.mempool().add_tx(make_spend(prev, 0, 90'000, 1)));

    // Build a minimal mnlistdiff: two fresh MNs, no deletes, empty quorum tail,
    // default (type-0) cbTx so the credit-pool seed is skipped.
    CSimplifiedMNListDiff diff;
    diff.baseBlockHash = uint256::ZERO;
    diff.blockHash = raw256(0xAB);
    diff.mnList = {sml_entry(0x40), sml_entry(0x60)};

    EXPECT_FALSE(st.have_sml());
    maint.on_mnlistdiff(diff);
    EXPECT_TRUE(st.have_sml());
    EXPECT_EQ(st.sml().size(), 2u);

    // Arm the tip AFTER the SML so republish sees both halves.
    maint.on_new_tip(H - 1, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
                     DASH_PUBKEY_VER, DASH_P2SH_VER, 1'700'000'123u, 0x20000000u);
    ASSERT_TRUE(st.populated());
    ASSERT_TRUE(st.make_embedded_work_inputs().viable());

    WorkSelection sel = st.select_work([&]() { return DashWorkData{}; });
    EXPECT_EQ(sel.source, WorkSource::Embedded);
    EXPECT_FALSE(sel.work.m_coinbase_payload.empty());

    // A reorg wipe drops the SML and gates the arm back to fallback.
    maint.on_sml_reorg();
    EXPECT_FALSE(st.have_sml());
    EXPECT_EQ(st.sml().size(), 0u);
    EXPECT_FALSE(st.make_embedded_work_inputs().viable());
}
