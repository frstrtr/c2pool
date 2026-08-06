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
    s.payoutSplitProvenance = MNState::SPLIT_KNOWN;   // fixture: proven zero split (h=2516595 gate)
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
    // This KAT pins the FEE-CARRYING flow; tx-carrying templates are the
    // --embedded-serve-mempool-txs OPT-IN (default OFF = coinbase-only; the
    // default posture is pinned by the DashMempoolTxServing suite below).
    st.set_serve_mempool_txs(true);

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

// ════════════════════════════════════════════════════════════════════════
// #996: payee fail-closed gate. A populated, tip-fresh bundle whose MN set
// resolves NO payee (every entry isValid=false — e.g. a PoSe ban the tx-walk
// never observed) while a MN payment is due must REFUSE the embedded arm: the
// builder (build_embedded_workdata) would emit a coinbase claiming
// m_payment_amount with no MN output — fail-OPEN on a money path (bad-cb-payee).
// NEGATIVE PASS: with the guard OFF (pre-#996 behaviour) the SAME bundle is
// (wrongly) viable and would serve the defective template; with the guard ON it
// falls back to the reward-safe dashd arm. A CONTROL with a resolvable payee at
// the same tip stays viable, proving the gate is payee-specific, not a blanket
// refuse.
// ════════════════════════════════════════════════════════════════════════
TEST(DashNodeCoinState, UnresolvablePayeeFailsClosedToDashd) {
    NodeCoinState st;
    // One MN, marked INVALID — find_expected_payee() skips it => nullopt.
    MNState banned;
    banned.isValid          = false;
    banned.nRegisteredHeight = 2'300'000;
    banned.scriptPayout.m_data = p2pkh_script(0x30);
    banned.payoutSplitProvenance = MNState::SPLIT_KNOWN;   // fixture: proven zero split (h=2516595 gate)
    st.mnstates().load(std::vector<std::pair<uint256, MNState>>{
        {raw256(0x01), banned}});
    st.set_tip(H - 1, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);

    ASSERT_TRUE(st.populated()) << "bundle is populated (MN set loaded + tip set)";
    ASSERT_FALSE(st.mnstates().find_expected_payee().has_value())
        << "precondition: no payee resolves from an all-invalid MN set";

    // NEGATIVE PASS — reproduce the pre-#996 fail-open: guard OFF => the
    // defective bundle is viable and would serve the MN-less embedded template.
    st.set_require_resolvable_payee(false);
    EXPECT_TRUE(st.make_embedded_work_inputs().viable())
        << "pre-#996: an unresolvable payee was served (fail-open) — the defect";

    // GUARD ON (default posture) => the gate fires: refuse embedded, route dashd.
    st.set_require_resolvable_payee(true);
    EXPECT_FALSE(st.make_embedded_work_inputs().viable())
        << "#996: due MN payment + unresolvable payee must refuse the embedded arm";
    bool fb = false;
    EXPECT_EQ(st.select_work([&]{ fb = true; return DashWorkData{}; }).source,
              WorkSource::DashdFallback);
    EXPECT_TRUE(fb) << "refused embedded must reach the always-on dashd fallback";

    // CONTROL — a resolvable payee (valid MN) at the SAME tip stays viable with
    // the guard ON: the gate is payee-specific, not a blanket refuse.
    seed_single_mn(st, p2pkh_script(0x30));
    ASSERT_TRUE(st.mnstates().find_expected_payee().has_value());
    EXPECT_TRUE(st.make_embedded_work_inputs().viable())
        << "#996 guard must NOT refuse when the due payee resolves";
}

// #996 rescope: an EMPTY payee queue must NOT trip the guard (default ON).
// No-masternode-set is not a resolution failure: a network that genuinely
// has none serves normally (the builder emits no MN output and dashd expects
// none), and a mid-sync empty queue is already fail-closed on the armed
// posture by require_sml + require_fresh_mn_payee. Distinguishes the
// no-MN-set case from UnresolvablePayeeFailsClosedToDashd above, where
// entries EXIST but none resolves -- that one must keep refusing.
TEST(DashNodeCoinState, EmptyMnSetDoesNotTripPayeeGuard) {
    NodeCoinState st;
    st.set_tip(H - 1, raw256(0xAB), 0x1b104be3u, 1700000000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);
    ASSERT_TRUE(st.populated());
    ASSERT_TRUE(st.mnstates().entries().empty());
    ASSERT_FALSE(st.mnstates().find_expected_payee().has_value());
    // Guard at its DEFAULT (ON): the empty set stays viable at a height where
    // a MN payment WOULD be due if a masternode set existed.
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
    pm.payoutSplitProvenance = MNState::SPLIT_KNOWN;   // fixture: proven zero split (h=2516595 gate)
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

// ════════════════════════════════════════════════════════════════════════
// DEFECT-3 (daemonless soak 2026-08-03): the serve gate must NAME its refusal.
//
// Measured: the embedded arm served three templates whose MN payee was
// byte-identical to a real dashd getblocktemplate, then flipped to
// "arm=dashd-fallback h=0 mn_payee=(none)" and stayed there with the tip
// advancing normally and NO reason line of any kind.
//
// The design property these KATs pin is the one the prior art has and we had
// dropped (dashcore src/consensus/validation.h:69 ValidationState — the call
// that returns false is the call that records why): the reason RIDES THE
// DECISION. `make_embedded_work_inputs()` sets has_state from
// `decline.viable`, so a bundle that is not viable ALWAYS carries a non-viable
// report and vice versa. That equivalence is not a convention a future
// refactor can quietly break; it is the code.
//
// Each positive has its negative twin: every "names cause X" test is paired
// with the same state minus the fault, asserting the arm is viable and the
// report says so.
// ════════════════════════════════════════════════════════════════════════

using dash::coin::DeclineReport;

// A fully HEALTHY armed bundle: every optional gate enabled and satisfied.
// Every decline test below starts here and breaks exactly ONE thing, so the
// cause it names is unambiguous.
static void seed_healthy_armed(NodeCoinState& st) {
    seed_single_mn(st, p2pkh_script(0x30));
    seed_sml(st);
    st.set_require_sml(true);
    st.set_sml_current_hash(raw256(0xAB));
    st.set_require_fresh_bestcl(true);
    st.set_best_cl(static_cast<int32_t>(H - 1), {});
    st.set_require_fresh_credit_pool(true);
    st.set_credit_pool(0, raw256(0xAB), static_cast<int32_t>(H - 1));
    st.set_require_fresh_mn_payee(true);
    st.mnstates().load(
        std::vector<std::pair<uint256, MNState>>{}, H - 1);
    // Re-seed the single MN AT the tip so last_applied_height == prev_height.
    {
        MNState s;
        s.isValid = true;
        s.nRegisteredHeight = 2'300'000;
        s.nLastPaidHeight = 0;
        s.scriptPayout.m_data = p2pkh_script(0x30);
        s.payoutSplitProvenance = MNState::SPLIT_KNOWN;   // fixture: proven zero split (h=2516595 gate)
        st.mnstates().load(
            std::vector<std::pair<uint256, MNState>>{{raw256(0x01), s}}, H - 1);
    }
    st.set_tip(H - 1, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER, 1'700'000'123u, 0x20000000u);
}

// ── The baseline (NEGATIVE TWIN for every decline case below) ───────────
TEST(DashServeGateNamesRefusal, HealthyArmedBundleIsViableAndReportsSo) {
    NodeCoinState st;
    seed_healthy_armed(st);
    const auto e = st.make_embedded_work_inputs();
    ASSERT_TRUE(e.has_state)
        << "the shared baseline must be VIABLE, else every decline test below "
           "could pass for the wrong reason";
    EXPECT_TRUE(e.decline.viable);
    EXPECT_EQ(st.classify_decline(), "viable-race");
}

// ── THE INVARIANT: reason rides the decision, never beside it ────────────
// This is the property a returned reason buys over a parallel log statement.
// If a future edit adds a clause to has_state and forgets the report (the
// failure that let a #996 payee-unresolvable refusal masquerade as
// "viable-race"), this goes red.
TEST(DashServeGateNamesRefusal, HasStateAndDeclineViableAreTheSameBit) {
    NodeCoinState st;
    seed_healthy_armed(st);
    EXPECT_EQ(st.make_embedded_work_inputs().has_state,
              st.make_embedded_work_inputs().decline.viable);

    // …and stays the same bit across every single-fault mutation.
    st.set_credit_pool(0, raw256(0xAB), static_cast<int32_t>(H - 5));
    const auto stale = st.make_embedded_work_inputs();
    EXPECT_EQ(stale.has_state, stale.decline.viable);
    EXPECT_FALSE(stale.has_state);
}

// ── One case per condition, each naming its FIRST unmet clause ──────────
TEST(DashServeGateNamesRefusal, CreditPoolStaleNamesValueAndThreshold) {
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_credit_pool(0, raw256(0xAB), static_cast<int32_t>(H - 4));
    const DeclineReport d = st.describe_decline();
    EXPECT_FALSE(d.viable);
    EXPECT_EQ(d.cause, "creditpool-stale");
    EXPECT_EQ(d.value, std::to_string(H - 4))     << "the MEASURED seed height";
    EXPECT_EQ(d.threshold, std::to_string(H - 1)) << "the tip it had to equal";
}

TEST(DashServeGateNamesRefusal, CreditPoolFreshIsViable) {   // negative twin
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_credit_pool(0, raw256(0xAB), static_cast<int32_t>(H - 1));
    EXPECT_TRUE(st.describe_decline().viable);
}

TEST(DashServeGateNamesRefusal, PayeeStaleNamesValueAndThreshold) {
    NodeCoinState st;
    seed_healthy_armed(st);
    MNState s;
    s.isValid = true;
    s.nRegisteredHeight = 2'300'000;
    s.scriptPayout.m_data = p2pkh_script(0x30);
    s.payoutSplitProvenance = MNState::SPLIT_KNOWN;   // fixture: proven zero split (h=2516595 gate)
    st.mnstates().load(
        std::vector<std::pair<uint256, MNState>>{{raw256(0x01), s}}, H - 3);
    const DeclineReport d = st.describe_decline();
    EXPECT_EQ(d.cause, "payee-stale");
    EXPECT_EQ(d.value, std::to_string(H - 3));
    EXPECT_EQ(d.threshold, std::to_string(H - 1));
}

TEST(DashServeGateNamesRefusal, PayeeFreshIsViable) {        // negative twin
    NodeCoinState st;
    seed_healthy_armed(st);
    EXPECT_TRUE(st.describe_decline().viable);
}

// A REALISTIC DASH mainnet block hash. raw256() above is NOT one: its bytes are
// base+i, so its display hex has no leading zeros and any rendering of it looks
// discriminating. A real block hash carries the DIFFICULTY PADDING — at mainnet
// difficulty the display hex opens with ~14 zero nibbles (measured on the hotel
// node 2026-08-06: 000000000000000e, 000000000000001c, 0000000000000018).
// Zeroing the top 7 bytes reproduces exactly that shape.
//
// This helper exists because THE FIXTURE IS WHAT HID THE DEFECT: the old
// DmnStaleNamesSmlHashAndTipHash asserted GetHex().substr(0, 12) and passed,
// while in production both sides of that comparison rendered as twelve zeros
// on 114 of 114 refusals.
static uint256 pow256(uint8_t entropy) {
    uint256 h;
    std::array<uint8_t, 32> p{};
    for (size_t i = 0; i < 25; ++i) p[i] = static_cast<uint8_t>(entropy + i);
    // p[25..31] left ZERO -> 14 leading zero nibbles in GetHex().
    std::memcpy(h.data(), p.data(), 32);
    return h;
}

// Guard the helper itself: if it ever stops producing a padded hash, the tests
// below would silently stop testing anything.
TEST(DashServeGateNamesRefusal, PowFixtureActuallyCarriesDifficultyPadding) {
    EXPECT_EQ(pow256(0x11).GetHex().substr(0, 12), std::string(12, '0'));
    EXPECT_EQ(pow256(0x22).GetHex().substr(0, 12), std::string(12, '0'))
        << "two DIFFERENT mainnet-shaped hashes must share their leading "
           "nibbles — that is the whole reason the old rendering was blind";
}

TEST(DashServeGateNamesRefusal, DmnStaleNamesSmlHeightAndTipHeight) {
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_sml_current_hash(raw256(0xCD));   // SML current at a DIFFERENT block
    st.set_sml_current_height(static_cast<int64_t>(H - 4));
    const DeclineReport d = st.describe_decline();
    EXPECT_EQ(d.cause, "dmn-stale");
    // HEIGHT first (how far behind), discriminating hash TAIL second (which
    // block — and same-height forks, which the height alone cannot express).
    EXPECT_EQ(d.value, "h=" + std::to_string(H - 4) + ",..."
                           + dash::coin::discriminating_hash_tail(raw256(0xCD)));
    EXPECT_EQ(d.threshold, "h=" + std::to_string(H - 1) + ",..."
                               + dash::coin::discriminating_hash_tail(raw256(0xAB)));
}

// THE DEFECT, as production actually presents it. Both hashes are mainnet-
// shaped, so the pre-fix rendering collapses them onto the same twelve zeros
// and the refusal reports value == threshold — on a refusal whose entire
// meaning is that the two DIFFER.
TEST(DashServeGateNamesRefusal, DmnStaleDistinguishesTwoMainnetPowHashes) {
    NodeCoinState st;
    seed_healthy_armed(st);
    // Re-stamp the tip with a mainnet-SHAPED hash. set_tip is the last thing
    // seed_healthy_armed does, so this simply replaces it; the height is
    // unchanged, so every height-keyed clause above dmn-stale stays satisfied.
    st.set_tip(H - 1, pow256(0x11), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER, 1'700'000'123u, 0x20000000u);
    st.set_sml_current_hash(pow256(0x22));

    const DeclineReport d = st.describe_decline();
    ASSERT_EQ(d.cause, "dmn-stale");
    EXPECT_NE(d.value, d.threshold)
        << "dmn-stale refuses BECAUSE the SML hash differs from the tip hash, "
           "so a report whose value EQUALS its threshold cannot be read at all. "
           "Measured on the hotel node 2026-08-06: 114 of 114 refusals printed "
           "value=000000000000 threshold=000000000000, because both sides were "
           "GetHex().substr(0, 12) of a PROOF-OF-WORK hash and those nibbles "
           "are the difficulty padding. Report the discriminating TAIL.";
    EXPECT_EQ(d.value.find(std::string(12, '0')), std::string::npos)
        << "the reported value is still (or contains) the all-zero difficulty "
           "padding — it carries no information about which block the SML is at";
}

// The height half, which is what turns "different" into "how far behind".
// Uses the diagnostic height seam the maintainer publishes beside the hash.
TEST(DashServeGateNamesRefusal, DmnStaleNamesHowFarBehindTheDmlIs) {
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_tip(H - 1, pow256(0x11), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER, 1'700'000'123u, 0x20000000u);
    st.set_sml_current_hash(pow256(0x22));
    st.set_sml_current_height(static_cast<int64_t>(H - 3));

    const DeclineReport d = st.describe_decline();
    ASSERT_EQ(d.cause, "dmn-stale");
    EXPECT_NE(d.value.find("h=" + std::to_string(H - 3)), std::string::npos)
        << "the report must say HOW FAR BEHIND the DML is — the only quantity "
           "an operator can act on. A hash says THAT it differs, never by how "
           "much, and every long dmn-stale episode measured in production was "
           "closed by the next block arriving rather than by the SML catching "
           "up at the same tip.";
    EXPECT_NE(d.threshold.find("h=" + std::to_string(H - 1)), std::string::npos);
}

// Never reported (cold maintainer) must read as n/a, not as height 0 — the
// #1039 discipline: do not print a measurement that was never taken.
TEST(DashServeGateNamesRefusal, DmnStaleUnreportedHeightIsNotZero) {
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_sml_current_hash(raw256(0xCD));   // height never published
    const DeclineReport d = st.describe_decline();
    ASSERT_EQ(d.cause, "dmn-stale");
    EXPECT_NE(d.value.find("h=n/a"), std::string::npos);
    EXPECT_EQ(d.value.find("h=0,"), std::string::npos)
        << "0 would read as 'we measured the SML height and it was genesis'";
}

// A cold / reorg-wiped SML is a DIFFERENT operator situation from a lagging
// one, and "000000000000" could express neither.
TEST(DashServeGateNamesRefusal, DmnStaleColdSmlSaysColdNotZeros) {
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_sml_current_hash(uint256::ZERO);
    const DeclineReport d = st.describe_decline();
    ASSERT_EQ(d.cause, "dmn-stale");
    EXPECT_EQ(d.value, "cold/wiped");
}

TEST(DashServeGateNamesRefusal, DmnCurrentAtTipIsViable) {   // negative twin
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_sml_current_hash(raw256(0xAB));
    EXPECT_TRUE(st.describe_decline().viable);
}

TEST(DashServeGateNamesRefusal, BestClStaleNamesHeightAndFloor) {
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_best_cl(static_cast<int32_t>(H - 50), {});
    const DeclineReport d = st.describe_decline();
    EXPECT_EQ(d.cause, "bestcl-stale");
    EXPECT_EQ(d.value, std::to_string(H - 50));
    EXPECT_EQ(d.threshold, ">=" + std::to_string(H - 2));
}

TEST(DashServeGateNamesRefusal, BestClFreshIsViable) {       // negative twin
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_best_cl(static_cast<int32_t>(H - 2), {});   // exactly at the floor
    EXPECT_TRUE(st.describe_decline().viable);
}

TEST(DashServeGateNamesRefusal, QuorumUnhealthyIsNamed) {
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_quorum_healthy(false);
    EXPECT_EQ(st.describe_decline().cause, "quorum-unhealthy");
}

TEST(DashServeGateNamesRefusal, QuorumHealthyIsViable) {     // negative twin
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_quorum_healthy(true);
    EXPECT_TRUE(st.describe_decline().viable);
}

TEST(DashServeGateNamesRefusal, SuperblockRefusalIsNamed) {
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_is_superblock_fn([](uint32_t) { return true; });
    EXPECT_EQ(st.describe_decline().cause, "superblock-refused");
}

TEST(DashServeGateNamesRefusal, NonSuperblockHeightIsViable) {  // negative twin
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_is_superblock_fn([](uint32_t) { return false; });
    EXPECT_TRUE(st.describe_decline().viable);
}

TEST(DashServeGateNamesRefusal, DkgCommitmentWindowIsNamed) {
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_commitment_window_fn([](uint32_t) { return true; });
    const DeclineReport d = st.describe_decline();
    EXPECT_EQ(d.cause, "dkg-commitment-window");
    EXPECT_EQ(d.value, "in-window@h=" + std::to_string(H));
}

TEST(DashServeGateNamesRefusal, OffCommitmentWindowIsViable) {  // negative twin
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_commitment_window_fn([](uint32_t) { return false; });
    EXPECT_TRUE(st.describe_decline().viable);
}

TEST(DashServeGateNamesRefusal, UtxoImmatureIsNamed) {
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_utxo_ready_fn([] { return false; });
    // No policy call: refusing IS the default (p2pool semantics — an unsynced
    // node does not serve templates), byte-identical to the pre-policy gate.
    EXPECT_EQ(st.describe_decline().cause, "utxo-immature");
}

TEST(DashServeGateNamesRefusal, UtxoMatureIsViable) {          // negative twin
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_utxo_ready_fn([] { return true; });
    EXPECT_TRUE(st.describe_decline().viable);
}

// ════════════════════════════════════════════════════════════════════════
// UTXO-IMMATURE SERVING (pure-daemonless OPT-IN)
//
// The DEFAULT during the blocks_connected < 106 window is to REFUSE — p2pool
// semantics, the operator's design law: an unsynced node has unverified state
// and does not serve block templates; miners idling is correct, and the dashd
// fallback serves FULL templates where armed. The first test pins that default
// exactly.
//
// ServeEmptyTxSet is the explicit opt-in for pure-daemonless nodes with no
// fallback to route to: serve a coinbase-only template rather than nothing.
// Consensus never requires a mempool transaction, and with zero txs the fee
// term is exactly 0 — no fee to overstate, so the bad-cb-amount risk the gate
// guards is structurally absent in that mode. The remaining tests pin the
// opt-in contract: it serves, it suppresses the tx set, it SAYS so, and every
// other gate still refuses.
// ════════════════════════════════════════════════════════════════════════

TEST(DashUtxoImmatureServing, DefaultRefusesTheImmatureWindowExactlyAsBefore) {
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_utxo_ready_fn([] { return false; });
    // No policy call at all — this is the shipped default.
    EXPECT_EQ(st.utxo_immature_policy(),
              dash::coin::UtxoImmaturePolicy::Refuse)
        << "the default posture is REFUSE (p2pool semantics: an unsynced node "
           "does not serve templates)";
    const auto e = st.make_embedded_work_inputs();
    EXPECT_FALSE(e.has_state);
    EXPECT_EQ(e.decline.cause, "utxo-immature");
    EXPECT_EQ(e.decline.value, "utxo_ready=false");
    EXPECT_EQ(e.decline.threshold, "utxo_ready=true");
    EXPECT_EQ(st.classify_decline(), "utxo-immature");
    // (With mempool-tx serving armed, the refusing arm suppresses nothing —
    // the suppress bit belongs to WHAT is served, and nothing is.)
    st.set_serve_mempool_txs(true);
    EXPECT_FALSE(st.make_embedded_work_inputs().suppress_mempool_txs)
        << "a refusing arm serves nothing, so it suppresses nothing";
}

TEST(DashUtxoImmatureServing, OptInServesTheImmatureWindow) {
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_utxo_ready_fn([] { return false; });
    st.set_utxo_immature_policy(
        dash::coin::UtxoImmaturePolicy::ServeEmptyTxSet);
    const auto e = st.make_embedded_work_inputs();
    EXPECT_TRUE(e.has_state)
        << "under the opt-in, an immature UTXO lane must not cost the whole "
           "template";
    EXPECT_TRUE(e.decline.viable);
    EXPECT_NE(st.describe_decline().cause, "utxo-immature");
}

TEST(DashUtxoImmatureServing, OptInSuppressesTheMempoolTxSet) {
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_utxo_ready_fn([] { return false; });
    st.set_utxo_immature_policy(
        dash::coin::UtxoImmaturePolicy::ServeEmptyTxSet);
    const auto e = st.make_embedded_work_inputs();
    // THE safety property: we serve, but we serve coinbase-only. Without this
    // bit the arm would build a normal template off an immature UTXO view.
    EXPECT_TRUE(e.suppress_mempool_txs)
        << "serving an immature window WITHOUT suppressing the tx set is the "
           "one variant that could overstate a fee";
}

TEST(DashUtxoImmatureServing, MatureLaneNeverSuppresses) {     // negative twin
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_utxo_ready_fn([] { return true; });
    // Mempool-tx serving armed (--embedded-serve-mempool-txs; without it the
    // default-OFF posture suppresses regardless — DashMempoolTxServing suite).
    st.set_serve_mempool_txs(true);
    // Even WITH the opt-in policy, a mature lane builds normal templates.
    st.set_utxo_immature_policy(
        dash::coin::UtxoImmaturePolicy::ServeEmptyTxSet);
    const auto e = st.make_embedded_work_inputs();
    EXPECT_TRUE(e.has_state);
    EXPECT_FALSE(e.suppress_mempool_txs)
        << "a mature lane must build normal, fee-paying templates";
    // …and neither does a bundle with no UTXO lane armed at all.
    NodeCoinState unarmed;
    seed_healthy_armed(unarmed);
    unarmed.set_serve_mempool_txs(true);
    EXPECT_FALSE(unarmed.make_embedded_work_inputs().suppress_mempool_txs);
}

// ════════════════════════════════════════════════════════════════════════
// --embedded-serve-mempool-txs (default OFF): fee-carrying templates are an
// explicit operator opt-in; the shipped default serves coinbase-only bodies
// with the cause named on the template. Audit:
// DASH_CONNECTBLOCK_REJECT_SURFACE_AUDIT.md (mempool-tx body path G1-G4).
// ════════════════════════════════════════════════════════════════════════
TEST(DashMempoolTxServing, DefaultOffSuppressesBodyWithNamedCause) {
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_utxo_ready_fn([] { return true; });   // even a MATURE lane
    EXPECT_FALSE(st.serve_mempool_txs()) << "the shipped default is OFF";
    const auto e = st.make_embedded_work_inputs();
    EXPECT_TRUE(e.has_state) << "coinbase-only serving is not a refusal";
    EXPECT_TRUE(e.suppress_mempool_txs)
        << "default OFF: the body must be coinbase-only";
    EXPECT_STREQ(e.suppress_cause, "mempool-txs-disabled")
        << "the state must say its own name";
}

TEST(DashMempoolTxServing, OptInCarriesMempoolTxs) {           // negative twin
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_utxo_ready_fn([] { return true; });
    st.set_serve_mempool_txs(true);
    const auto e = st.make_embedded_work_inputs();
    EXPECT_TRUE(e.has_state);
    EXPECT_FALSE(e.suppress_mempool_txs)
        << "the opt-in with a mature lane serves fee-carrying templates";
}

TEST(DashMempoolTxServing, UtxoImmatureCauseWinsOverDisabled) {
    // Both suppressed-body producers active: the more specific state name
    // (utxo-immature-serving) must win so soak greps attribute the window
    // correctly.
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_utxo_ready_fn([] { return false; });
    st.set_utxo_immature_policy(
        dash::coin::UtxoImmaturePolicy::ServeEmptyTxSet);
    const auto e = st.make_embedded_work_inputs();
    EXPECT_TRUE(e.suppress_mempool_txs);
    EXPECT_STREQ(e.suppress_cause, "utxo-immature-serving");
}

// The opt-in relaxes ONLY this clause. Every other gate must still refuse —
// otherwise "serve during immaturity" would have quietly become "serve
// regardless", which is how a lost block gets shipped as a feature.
TEST(DashUtxoImmatureServing, OtherGatesStillRefuseUnderTheOptIn) {
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_utxo_ready_fn([] { return false; });
    st.set_utxo_immature_policy(
        dash::coin::UtxoImmaturePolicy::ServeEmptyTxSet);
    st.set_credit_pool(0, raw256(0xAB), static_cast<int32_t>(H - 4));
    const DeclineReport d = st.describe_decline();
    EXPECT_FALSE(d.viable);
    EXPECT_EQ(d.cause, "creditpool-stale");
}

TEST(DashServeGateNamesRefusal, QcPlanUnderivableIsNamed) {
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_qc_plan_fn([](uint32_t) { return std::optional<dash::coin::QcBlockPlan>{}; });
    EXPECT_EQ(st.describe_decline().cause, "qc-plan-underivable");
}

TEST(DashServeGateNamesRefusal, QcPlanDerivableIsViable) {     // negative twin
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_qc_plan_fn([](uint32_t) {
        dash::coin::QcBlockPlan p;
        p.merkle_root_quorums = uint256::ZERO;
        return std::optional<dash::coin::QcBlockPlan>{p};
    });
    EXPECT_TRUE(st.describe_decline().viable);
}

TEST(DashServeGateNamesRefusal, NotPopulatedIsNamed) {
    NodeCoinState st;
    seed_healthy_armed(st);
    st.invalidate();
    EXPECT_EQ(st.describe_decline().cause, "not-populated");
}

TEST(DashServeGateNamesRefusal, MnNeedsReseedOutranksNotPopulated) {
    NodeCoinState st;
    seed_healthy_armed(st);
    st.invalidate();
    st.set_mn_needs_reseed(true);
    const DeclineReport d = st.describe_decline();
    EXPECT_EQ(d.cause, "mn-needs-reseed")
        << "the latch is strictly more informative than the not-populated "
           "state it causes (the smoke rig logged 639 'not-populated' declines "
           "while the real cause was a payee desync)";
    EXPECT_EQ(st.classify_decline(), "mn-needs-reseed")
        << "legacy wire text must not change -- the shadow ledger keys on it";
}

TEST(DashServeGateNamesRefusal, MnReseedLatchClearIsViable) {   // negative twin
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_mn_needs_reseed(false);
    EXPECT_TRUE(st.describe_decline().viable);
}

// A DIAGNOSTIC refinement must never CREATE a refusal. Before the single-list
// rewrite, classify_decline() tested prev_hash.IsNull() unconditionally and so
// could report "no-tip" for an arm that was in fact serving.
TEST(DashServeGateNamesRefusal, DiagnosticRefinementNeverContradictsHasState) {
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_mn_needs_reseed(true);   // latch ON while the bundle is healthy
    const auto e = st.make_embedded_work_inputs();
    EXPECT_TRUE(e.has_state)
        << "the reseed latch is diagnostic-only: it must not gate serving";
    EXPECT_TRUE(e.decline.viable)
        << "and it must not manufacture a decline report either";
    EXPECT_EQ(e.decline.cause, "viable")
        << "nor RENAME a viable report: the refinement block must be "
           "unreachable while the arm is serving, or an operator reads a cause "
           "for a refusal that never happened";
    EXPECT_EQ(st.classify_decline(), "viable-race");
}

// ── THE n/a RULE: an unevaluated field must NEVER print as 0 ─────────────
// A zero standing in for "not measured" is the same silent-refusal defect in
// new clothes. Each of these three members uses a zero/negative as its own
// "never measured" sentinel.
TEST(DashServeGateNamesRefusal, NeverSeededCreditPoolPrintsNaNotZero) {
    NodeCoinState st;
    seed_healthy_armed(st);
    NodeCoinState fresh;                    // credit_pool_height == -1 sentinel
    seed_single_mn(fresh, p2pkh_script(0x30));
    fresh.set_require_fresh_credit_pool(true);
    fresh.set_tip(H - 1, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
                  DASH_PUBKEY_VER, DASH_P2SH_VER, 1'700'000'123u, 0x20000000u);
    const DeclineReport d = fresh.describe_decline();
    ASSERT_EQ(d.cause, "creditpool-stale");
    EXPECT_EQ(d.value, "n/a")
        << "credit_pool_height==-1 means NEVER SEEDED; printing it as a height "
           "reads like a measurement that was never taken";
    EXPECT_NE(d.value, "-1");
    EXPECT_NE(d.value, "0");
}

TEST(DashServeGateNamesRefusal, NeverObservedChainLockPrintsNaNotZero) {
    NodeCoinState st;
    seed_single_mn(st, p2pkh_script(0x30));
    st.set_require_fresh_bestcl(true);       // best_cl_height stays 0 = never seen
    st.set_tip(H - 1, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER, 1'700'000'123u, 0x20000000u);
    const DeclineReport d = st.describe_decline();
    ASSERT_EQ(d.cause, "bestcl-stale");
    EXPECT_EQ(d.value, "n/a")
        << "best_cl_height==0 means no clsig EVER observed, not 'ChainLock at "
           "height 0'";
    EXPECT_NE(d.value, "0");
}

TEST(DashServeGateNamesRefusal, NeverFoldedPayeeQueuePrintsNaNotZero) {
    NodeCoinState st;
    seed_single_mn(st, p2pkh_script(0x30));  // load() with no as_of => cursor 0
    st.set_require_fresh_mn_payee(true);
    st.set_tip(H - 1, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER, 1'700'000'123u, 0x20000000u);
    const DeclineReport d = st.describe_decline();
    ASSERT_EQ(d.cause, "payee-stale");
    EXPECT_EQ(d.value, "n/a")
        << "last_applied_height()==0 means the queue has never folded a block";
    EXPECT_NE(d.value, "0");
}

// A MEASURED zero, by contrast, must still print as 0 -- the n/a rule must not
// swallow real data. (Fails-without-fix guard on the rule itself.)
TEST(DashServeGateNamesRefusal, MeasuredHeightsStillPrintNumerically) {
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_credit_pool(0, raw256(0xAB), 7);
    const DeclineReport d = st.describe_decline();
    ASSERT_EQ(d.cause, "creditpool-stale");
    EXPECT_EQ(d.value, "7") << "7 was measured; it must not be blanked to n/a";
}

// ── one_line() is the greppable contract ────────────────────────────────
TEST(DashServeGateNamesRefusal, OneLineCarriesCauseValueAndThreshold) {
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_credit_pool(0, raw256(0xAB), static_cast<int32_t>(H - 4));
    const std::string line = st.describe_decline().one_line();
    EXPECT_EQ(line, "cause=creditpool-stale value=" + std::to_string(H - 4)
                        + " threshold=" + std::to_string(H - 1));
    EXPECT_EQ(line.find(' '), line.find(" value="))
        << "the cause token must contain no spaces -- it is grepped";
}

// ── HEADER-SYNC gate: the ONE absolute check (cross-lane asymmetry) ─────
// HeaderChain::is_synced() existed and had ZERO callers on the DASH template
// path (bch 13, ltc 12, nmc 12, btc 6, dgb 6, dash 0). These KATs pin why that
// mattered: every other gate is relative to our own tip, so a node that is
// self-consistently STALE passes all of them.
TEST(DashServeGateNamesRefusal, UnsyncedChainIsNamedAndRefused) {
    NodeCoinState st;
    seed_healthy_armed(st);
    ASSERT_TRUE(st.make_embedded_work_inputs().has_state)
        << "baseline must be viable before the sync gate is applied";
    st.set_chain_synced_fn([] { return false; });
    const auto e = st.make_embedded_work_inputs();
    EXPECT_FALSE(e.has_state);
    EXPECT_EQ(e.decline.cause, "chain-not-synced");
    EXPECT_EQ(e.decline.threshold, "header-tip-current");
}

TEST(DashServeGateNamesRefusal, SyncedChainIsViable) {          // negative twin
    NodeCoinState st;
    seed_healthy_armed(st);
    st.set_chain_synced_fn([] { return true; });
    EXPECT_TRUE(st.make_embedded_work_inputs().has_state);
}

TEST(DashServeGateNamesRefusal, UnsetSyncFnLeavesEveryPriorKatUnchanged) {
    NodeCoinState st;
    seed_healthy_armed(st);   // no set_chain_synced_fn call at all
    EXPECT_TRUE(st.make_embedded_work_inputs().has_state)
        << "an unwired sync predicate must not silently close the arm -- that "
           "would break every pre-existing KAT and every testnet harness";
}

// THE POINT of the gate: a stale-but-self-consistent node passes every
// RELATIVE freshness check. Without the absolute one it would serve.
TEST(DashServeGateNamesRefusal, SelfConsistentStaleTipPassesEveryRelativeGate) {
    NodeCoinState st;
    // Same construction as the healthy baseline, but "the tip" is an ancient
    // height. Credit pool, payee cursor and SML hash are all current AT it.
    const uint32_t ancient = H - 500'000;
    seed_sml(st);
    st.set_require_sml(true);
    st.set_sml_current_hash(raw256(0xAB));
    st.set_require_fresh_bestcl(true);
    st.set_best_cl(static_cast<int32_t>(ancient), {});
    st.set_require_fresh_credit_pool(true);
    st.set_credit_pool(0, raw256(0xAB), static_cast<int32_t>(ancient));
    st.set_require_fresh_mn_payee(true);
    {
        MNState s;
        s.isValid = true;
        s.nRegisteredHeight = 1'000'000;
        s.scriptPayout.m_data = p2pkh_script(0x30);
        s.payoutSplitProvenance = MNState::SPLIT_KNOWN;   // fixture: proven zero split (h=2516595 gate)
        st.mnstates().load(
            std::vector<std::pair<uint256, MNState>>{{raw256(0x01), s}}, ancient);
    }
    st.set_tip(ancient, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER, 1'700'000'123u, 0x20000000u);

    EXPECT_TRUE(st.make_embedded_work_inputs().has_state)
        << "THIS IS THE HAZARD: every relative gate is satisfied on a tip half "
           "a million blocks behind, because none of them compares against "
           "anything outside our own view";

    st.set_chain_synced_fn([] { return false; });
    const auto gated = st.make_embedded_work_inputs();
    EXPECT_FALSE(gated.has_state)
        << "the absolute gate is the only thing that can refuse this";
    EXPECT_EQ(gated.decline.cause, "chain-not-synced");
}

// "not-populated" collapsed two operator situations needing opposite responses
// (headers still syncing vs the MN set never seeded) into one word. It now
// carries which half the maintainer is missing — and prints n/a, not 0, when
// the maintainer has never reported.
TEST(DashServeGateNamesRefusal, NotPopulatedNamesWhichHalfIsMissing) {
    NodeCoinState st;
    // A real tip is required first: with a NULL prev_hash the diagnostic
    // refinement (correctly) relabels this to the more informative "no-tip".
    st.set_tip(H - 1, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER, 1'700'000'123u, 0x20000000u);
    st.invalidate();
    st.set_populate_inputs(/*have_tip=*/true, /*have_mn=*/false);
    const DeclineReport d = st.describe_decline();
    ASSERT_EQ(d.cause, "not-populated");
    EXPECT_EQ(d.value, "have_tip=1,have_mn=0")
        << "'MN set never seeded' and 'headers still syncing' need opposite "
           "operator responses; one word cannot carry both";
    EXPECT_EQ(d.threshold, "have_tip=1,have_mn=1");
}

TEST(DashServeGateNamesRefusal, NotPopulatedOtherHalf) {          // twin
    NodeCoinState st;
    st.set_tip(H - 1, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER, 1'700'000'123u, 0x20000000u);
    st.invalidate();
    st.set_populate_inputs(/*have_tip=*/false, /*have_mn=*/true);
    EXPECT_EQ(st.describe_decline().value, "have_tip=0,have_mn=1");
}

TEST(DashServeGateNamesRefusal, UnreportedPopulateInputsPrintNaNotZero) {
    NodeCoinState st;   // maintainer has never called set_populate_inputs
    st.set_tip(H - 1, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER, 1'700'000'123u, 0x20000000u);
    st.invalidate();
    const DeclineReport d = st.describe_decline();
    ASSERT_EQ(d.cause, "not-populated");
    EXPECT_EQ(d.value, "n/a")
        << "never reported is NOT reported-false; printing have_tip=0 here "
           "would be a measurement we never took";
    EXPECT_EQ(d.value.find('0'), std::string::npos);
}

// The no-tip refinement, pinned so the ordering cannot silently flip.
//
// CAUGHT LIVE on the daemonless rig 2026-08-03: the header chain was at
// h=2515420 and advancing every ~60 s while this refinement reported "no-tip".
// NodeCoinState::m_prev_hash is only written by set_tip(), which the maintainer
// calls only once it holds BOTH a tip and an MN set — so while the MN set is
// unseeded, prev_hash stays null no matter how current the headers are. Reading
// that null as "no tip" told the operator to chase a header-sync fault that did
// not exist while the real blocker went unnamed: the same silent-refusal defect
// this whole change exists to kill, reintroduced by the diagnostic meant to fix
// it. The maintainer's report wins whenever it exists.
TEST(DashServeGateNamesRefusal, MaintainerReportOutranksOurOwnNullPrevHash) {
    NodeCoinState st;
    st.set_populate_inputs(/*have_tip=*/true, /*have_mn=*/false);
    const DeclineReport d = st.describe_decline();
    EXPECT_EQ(d.cause, "not-populated")
        << "have_tip=1 explains the null prev_hash; calling it 'no-tip' would "
           "point the operator at headers when the MN set is the blocker";
    EXPECT_EQ(d.value, "have_tip=1,have_mn=0");
}

TEST(DashServeGateNamesRefusal, MaintainerReportWinsInTheOtherDirectionToo) {
    NodeCoinState st;
    st.set_populate_inputs(/*have_tip=*/false, /*have_mn=*/true);
    const DeclineReport d = st.describe_decline();
    EXPECT_EQ(d.cause, "not-populated");
    EXPECT_EQ(d.value, "have_tip=0,have_mn=1")
        << "even when the maintainer agrees there is no tip, its report is the "
           "measurement -- our null pointer is only a consequence of it";
}

TEST(DashServeGateNamesRefusal, NoTipOnlyWhenTheMaintainerNeverReported) {
    NodeCoinState st;   // set_populate_inputs never called
    const DeclineReport d = st.describe_decline();
    EXPECT_EQ(d.cause, "no-tip")
        << "with NO maintainer report, our own null prev_hash is the only "
           "evidence there is, and it is worth naming";
    EXPECT_EQ(d.value, "prev_hash=null,maintainer-never-reported")
        << "and it must say that it is inferring, not measuring";
}

// ════════════════════════════════════════════════════════════════════════
// The #1083 PoSe landmine, ENFORCED (emit-qc-real-pose-unfolded).
//
// dashd's verifier PoSe-punishes every quorum member a NON-NULL in-block
// commitment marks invalid (specialtxman.cpp:159-174 HandleQuorumCommitment
// -> PoSePunish(CalcPenalty(66))), and a punishment crossing the ban
// threshold flips that MN's validity IN THE SAME BLOCK's MN list — changing
// the merkleRootMNList the same coinbase commits. Null commitments are
// exempt (specialtxman.cpp:427-432, IsNull() guard). c2pool folds no PoSe
// pass into its committed root; since #1077 wired rotated member sourcing
// the real-commitment lane is LIVE, so a verified real commitment carrying
// !validMembers[i] for a listed member is a servable bad-cbtx-mnmerkleroot —
// a silently losable block. The pre-emit gate must refuse it; the ONLY thing
// standing there before this gate was a comment (embedded_gbt.hpp), and a
// comment refuses nothing.
//
// Shared fixture: the QcPlanServesDkgWindowHeightAndEmitGateEnforcesIt
// posture (tip 1518417 => next 1518418), with the plan fn returning ONE
// commitment — the same closure shape production installs, minus sourcing.
// ════════════════════════════════════════════════════════════════════════

namespace {

dash::coin::vendor::CFinalCommitment make_real_qc(bool punish_listed_member)
{
    // A structurally real (non-null) testnet LLMQ_50_60 commitment: full
    // 50-member quorum, non-zero crypto fields. punish_listed_member marks
    // ONE listed member invalid — the exact landmine input.
    dash::coin::vendor::CFinalCommitment c;
    c.nVersion = dash::coin::vendor::CFinalCommitment
                     ::BASIC_BLS_NON_INDEXED_QUORUM_VERSION;
    c.llmqType    = 1;                    // LLMQ_50_60 (testnet-enabled)
    c.quorumHash  = raw256(0x50);
    c.quorumIndex = 0;
    c.signers.assign(50, true);
    c.validMembers.assign(50, true);
    if (punish_listed_member) c.validMembers[7] = false;
    c.quorumPublicKey.fill(0x11);
    c.quorumVvecHash = raw256(0x22);
    c.quorumSig.fill(0x33);
    c.membersSig.fill(0x44);
    return c;
}

// Seed the same healthy DKG-window serving posture the E1 qc-plan test uses,
// with a plan fn returning exactly `qc` + a fixed with-block root override.
void seed_real_qc_serving(NodeCoinState& st,
                          const dash::coin::vendor::CFinalCommitment& qc)
{
    seed_single_mn(st, p2pkh_script(0x30));
    seed_sml(st);
    st.set_require_sml(true);
    st.set_sml_current_hash(raw256(0xAB));
    dash::coin::QcBlockPlan plan;
    plan.commitments = {qc};
    plan.merkle_root_quorums = raw256(0x77);
    st.set_qc_plan_fn([plan](uint32_t) {
        return std::optional<dash::coin::QcBlockPlan>{plan};
    });
    st.set_tip(1518417, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER, 1'700'000'123u, 0x20000000u);
}

} // namespace

// THE MASTER DEFECT, pinned. On pre-gate master this test FAILS at the
// EXPECT_FALSE: the punishing real commitment sails through the pre-emit
// gate (count/payload/root all self-consistent) and the template SERVES —
// the silently losable block. No PoSe-noop capability is wired here, which
// is exactly the state production shipped in: the gate must fail CLOSED on
// capability absence, not only on a proven punishment.
TEST(DashQcPoseGate, RealCommitmentPunishingListedMemberIsRefusedAtEmit) {
    NodeCoinState st;
    seed_real_qc_serving(st, make_real_qc(/*punish_listed_member=*/true));

    // The template BUILDS and carries the real qc tx — viability alone does
    // not (and cannot cheaply) prove the PoSe no-op; the emit gate is the
    // enforcement point, exactly like the other emit re-derivations.
    WorkSelection sel = st.select_work([] { return DashWorkData{}; });
    ASSERT_EQ(sel.source, WorkSource::Embedded);
    ASSERT_EQ(sel.work.m_txs.size(), 1u);
    ASSERT_EQ(sel.work.m_txs[0].type, 6);

    DeclineReport why;
    EXPECT_FALSE(st.embedded_template_emit_ok(sel.work, &why))
        << "a REAL commitment that PoSe-punishes a listed member reached the "
           "miner: dashd's verifier flips that MN in THIS block's list and "
           "the committed merkleRootMNList is wrong (bad-cbtx-mnmerkleroot = "
           "a silently lost block)";
    EXPECT_EQ(why.cause, "emit-qc-real-pose-unfolded");
    EXPECT_EQ(why.threshold, "pose-pass-provably-noop(all-listed-members-valid)");
    EXPECT_NE(why.value.find("pose_noop=n/a"), std::string::npos)
        << "capability ABSENT must print n/a, not a fabricated verdict: "
        << why.value;
}

// Negative twin: with the PoSe-noop capability wired and every listed member
// valid (the common case), the SAME posture serves exactly as before — the
// gate is punishment-specific, not a blanket real-commitment refuse.
TEST(DashQcPoseGate, AllListedMembersValidServesExactlyAsBefore) {
    NodeCoinState st;
    seed_real_qc_serving(st, make_real_qc(/*punish_listed_member=*/false));
    st.set_qc_pose_noop_fn(
        [](const dash::coin::vendor::CFinalCommitment& c)
            -> std::optional<bool> {
            // The production shape: judge against the deterministic member
            // list's size (full 50-member quorum here).
            return dash::coin::qc_pose_pass_provably_noop(c, 50);
        });

    WorkSelection sel = st.select_work([] { return DashWorkData{}; });
    ASSERT_EQ(sel.source, WorkSource::Embedded);
    DeclineReport why;
    EXPECT_TRUE(st.embedded_template_emit_ok(sel.work, &why))
        << "cause=" << why.cause << " value=" << why.value;

    // And the pre-existing drift enforcement is untouched: dropping the
    // mandatory commitment still discards the template (bad-qc-missing).
    DashWorkData tampered = sel.work;
    tampered.m_txs.clear();
    EXPECT_FALSE(st.embedded_template_emit_ok(tampered));
}

// With the capability WIRED, a proven punishment refuses with the measured
// value naming the offending commitment — cause/value/threshold discipline.
TEST(DashQcPoseGate, PunishingCommitmentRefusedEvenWithCapabilityWired) {
    NodeCoinState st;
    seed_real_qc_serving(st, make_real_qc(/*punish_listed_member=*/true));
    st.set_qc_pose_noop_fn(
        [](const dash::coin::vendor::CFinalCommitment& c)
            -> std::optional<bool> {
            return dash::coin::qc_pose_pass_provably_noop(c, 50);
        });

    WorkSelection sel = st.select_work([] { return DashWorkData{}; });
    ASSERT_EQ(sel.source, WorkSource::Embedded);
    DeclineReport why;
    EXPECT_FALSE(st.embedded_template_emit_ok(sel.work, &why));
    EXPECT_EQ(why.cause, "emit-qc-real-pose-unfolded");
    EXPECT_NE(why.value.find("pose_noop=unproven"), std::string::npos)
        << "a MEASURED failed proof must say 'unproven', not 'n/a': "
        << why.value;
    EXPECT_NE(why.value.find("type=1"), std::string::npos) << why.value;
}

// A wired capability that CANNOT answer (member set no longer cached) must
// refuse — nullopt is "cannot prove", and unprovable serves nothing.
TEST(DashQcPoseGate, UnprovableMemberSetFailsClosed) {
    NodeCoinState st;
    seed_real_qc_serving(st, make_real_qc(/*punish_listed_member=*/false));
    st.set_qc_pose_noop_fn(
        [](const dash::coin::vendor::CFinalCommitment&)
            -> std::optional<bool> { return std::nullopt; });

    WorkSelection sel = st.select_work([] { return DashWorkData{}; });
    ASSERT_EQ(sel.source, WorkSource::Embedded);
    DeclineReport why;
    EXPECT_FALSE(st.embedded_template_emit_ok(sel.work, &why));
    EXPECT_EQ(why.cause, "emit-qc-real-pose-unfolded");
    EXPECT_NE(why.value.find("pose_noop=n/a"), std::string::npos) << why.value;
}

// Null commitments are exempt by dashd's own IsNull() guard — an all-null
// plan serves with NO capability wired, byte-unchanged. (The E1 qc-plan test
// above already proves this through the full daemonless plan; this twin pins
// it against the gate directly so the exemption cannot silently narrow.)
TEST(DashQcPoseGate, NullCommitmentPlanIsExemptWithoutCapability) {
    NodeCoinState st;
    const auto null_qc = dash::coin::build_null_commitment(
        dash::coin::kLlmq50_60, raw256(0x50), 0);
    seed_real_qc_serving(st, null_qc);
    // No set_qc_pose_noop_fn on purpose.
    WorkSelection sel = st.select_work([] { return DashWorkData{}; });
    ASSERT_EQ(sel.source, WorkSource::Embedded);
    DeclineReport why;
    EXPECT_TRUE(st.embedded_template_emit_ok(sel.work, &why))
        << "cause=" << why.cause << " value=" << why.value;
}
