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
