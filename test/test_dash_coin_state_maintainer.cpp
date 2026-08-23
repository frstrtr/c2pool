// SPDX-License-Identifier: AGPL-3.0-or-later
/// Phase C-TEMPLATE step 7 -- CoinStateMaintainer live-update KAT.
///
/// #673 proved a directly-poked NodeCoinState routes the hot arm. This suite
/// proves the MAINTAINER that populates it off async update events:
///
///   * the bundle flips has_state=true ONLY once BOTH a tip AND a non-empty
///     MN list have arrived -- in EITHER order (tip-then-MN and MN-then-tip
///     both converge to the same live template);
///   * once live, select_work() returns EXACTLY the DashWorkData a direct
///     build_embedded_workdata() over the same inputs produces (maintainer
///     changes nothing about oracle parity, only WHEN the arm goes live);
///   * an empty MN list (mnlistdiff gap) and a reorg invalidate demote the
///     bundle back to the retained dashd fallback; a reorg drops the tip so
///     a fresh tip is required to re-arm (no auto-republish of a stale prev).
///
/// Seeding mirrors test_dash_node_coin_state.cpp exactly so the two suites pin
/// the SAME projection. No fabricated oracle values -- "expected" IS an
/// independent build_embedded_workdata() call, compared field-for-field.

#include <gtest/gtest.h>

#include <impl/dash/coin/coin_state_maintainer.hpp>
#include <impl/dash/coin/node_coin_state.hpp>
#include <impl/dash/coin/embedded_gbt.hpp>
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/block_producer.hpp>   // compute_merkle_root (E2 finding A body↔header bind)
#include <impl/dash/coin/utxo_adapter.hpp>
#include <impl/dash/coin/rpc_data.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/vendor/smldiff.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>

#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

using dash::coin::CoinStateMaintainer;
using dash::coin::NodeCoinState;
using dash::coin::DashWorkData;
using dash::coin::WorkSource;
using dash::coin::WorkSelection;
using dash::coin::MNState;
using dash::coin::Mempool;
using dash::coin::MutableTransaction;
using dash::coin::BlockType;
using dash::coin::build_embedded_workdata;
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

// Bind a hand-built block body to its header: commit the merkle root over the
// tx set so on_block_connected's E2 finding-A guard (block_body_binds_to_header)
// accepts it. Every block fed to the connect path must be bound (as a real
// P2P-delivered, PoW-headed block is).
static void bind_block(BlockType& b) {
    std::vector<uint256> ids;
    for (const auto& tx : b.m_txs) ids.push_back(dash::coin::dash_txid(tx));
    b.m_merkle_root = dash::coin::compute_merkle_root(ids);
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

static std::vector<std::pair<uint256, MNState>> single_mn(const std::vector<unsigned char>& payout) {
    MNState s;
    s.isValid = true;
    s.nRegisteredHeight = 2'300'000;
    s.nLastPaidHeight = 0;
    s.scriptPayout.m_data = payout;
    s.payoutSplitProvenance = MNState::SPLIT_KNOWN;   // fixture: proven zero split (h=2516595 gate)
    return std::vector<std::pair<uint256, MNState>>{{raw256(0x01), s}};
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

static const uint256  PREV_HASH = raw256(0xAB);
static const uint32_t BITS      = 0x1b104be3u;
static const uint32_t MTP       = 1'700'000'000u;
static const uint32_t CURTIME   = 1'700'000'123u;
static const uint32_t VERSION   = 0x20000000u;

// ════════════════════════════════════════════════════════════════════════
// tip-first: bundle stays fallback until the MN list also arrives, then flips.
// ════════════════════════════════════════════════════════════════════════
TEST(DashCoinStateMaintainer, TipBeforeMnStaysFallbackThenMnPublishes) {
    NodeCoinState st;
    CoinStateMaintainer m(st);

    // Tip arrives first; no MN list yet -> NOT live, routes fallback.
    m.on_new_tip(H - 1, PREV_HASH, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER, CURTIME, VERSION);
    EXPECT_FALSE(m.live());
    EXPECT_FALSE(st.make_embedded_work_inputs().viable());
    {
        bool fb = false;
        WorkSelection sel = st.select_work([&]() { fb = true; return DashWorkData{}; });
        EXPECT_EQ(sel.source, WorkSource::DashdFallback);
        EXPECT_TRUE(fb);
    }

    // mnlistdiff lands -> prerequisites complete -> bundle flips live.
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    EXPECT_TRUE(m.live());
    EXPECT_TRUE(st.make_embedded_work_inputs().viable());
    {
        bool fb = false;
        WorkSelection sel = st.select_work([&]() { fb = true; return DashWorkData{}; });
        EXPECT_EQ(sel.source, WorkSource::Embedded);
        EXPECT_FALSE(fb);
        EXPECT_EQ(sel.work.m_height, H);
    }
}

// ════════════════════════════════════════════════════════════════════════
// MN-first then tip: converges to the SAME live template, byte-equal to a
// direct build over the identical inputs (incl. a mempool tx routed through
// the maintainer's on_mempool_tx path).
// ════════════════════════════════════════════════════════════════════════
TEST(DashCoinStateMaintainer, MnThenTipPublishesByteEqualToDirectBuild) {
    UTXOViewCache utxo(nullptr);
    uint256 prev = raw256(0x77);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));

    NodeCoinState st;
    st.mempool().set_utxo(&utxo);
    // This KAT pins the FEE-CARRYING flow — the --embedded-serve-mempool-txs
    // OPT-IN (default OFF = coinbase-only; pinned in test_dash_node_coin_state
    // DashMempoolTxServing).
    st.set_serve_mempool_txs(true);
    CoinStateMaintainer m(st);

    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    EXPECT_FALSE(m.live()) << "MN alone (no tip) must not publish";
    ASSERT_TRUE(m.on_mempool_tx(make_spend(prev, 0, 90'000, /*salt=*/1)));  // fee 10'000
    m.on_new_tip(H - 1, PREV_HASH, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER, CURTIME, VERSION);
    ASSERT_TRUE(m.live());

    DashWorkData reference = build_embedded_workdata(
        H - 1, PREV_HASH, st.mnstates(), st.mempool(),
        BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER, CURTIME, VERSION);

    bool fb = false;
    WorkSelection sel = st.select_work([&]() { fb = true; return DashWorkData{}; });
    EXPECT_EQ(sel.source, WorkSource::Embedded);
    EXPECT_FALSE(fb);
    EXPECT_EQ(sel.work.m_height, H);
    expect_workdata_eq(sel.work, reference);
    // mempool tx actually reached the template (coinbase-only would have 0 fees).
    EXPECT_FALSE(reference.m_tx_hashes.empty());
    EXPECT_EQ(sel.work.m_tx_hashes.size(), reference.m_tx_hashes.size());
}

// ════════════════════════════════════════════════════════════════════════
// empty mnlistdiff = gap: demotes a live bundle back to the dashd fallback.
// ════════════════════════════════════════════════════════════════════════
TEST(DashCoinStateMaintainer, EmptyMnListIsGapDemotesToFallback) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.on_new_tip(H - 1, PREV_HASH, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER, CURTIME, VERSION);
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    ASSERT_TRUE(m.live());

    m.on_mn_list_update({});   // gap: cannot back a payee
    EXPECT_FALSE(m.live());
    bool fb = false;
    WorkSelection sel = st.select_work([&]() { fb = true; return DashWorkData{}; });
    EXPECT_EQ(sel.source, WorkSource::DashdFallback);
    EXPECT_TRUE(fb);
}

// ════════════════════════════════════════════════════════════════════════
// reorg: invalidate drops the tip -> fallback; a stale MN refresh must NOT
// auto-republish the old prev; only a fresh tip re-arms the live bundle.
// ════════════════════════════════════════════════════════════════════════
TEST(DashCoinStateMaintainer, InvalidateReorgRequiresFreshTipToReArm) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    m.on_new_tip(H - 1, PREV_HASH, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER, CURTIME, VERSION);
    ASSERT_TRUE(m.live());

    m.on_invalidate();   // reorg
    EXPECT_FALSE(m.live());

    // An MN refresh alone must not resurrect the invalidated tip.
    m.on_mn_list_update(single_mn(p2pkh_script(0x31)));
    EXPECT_FALSE(m.live()) << "reorg dropped the tip; MN refresh alone must not republish a stale prev";

    // A fresh tip re-arms the bundle.
    m.on_new_tip(H, raw256(0xCD), BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER, CURTIME, VERSION);
    EXPECT_TRUE(m.live());
    bool fb = false;
    WorkSelection sel = st.select_work([&]() { fb = true; return DashWorkData{}; });
    EXPECT_EQ(sel.source, WorkSource::Embedded);
    EXPECT_FALSE(fb);
    EXPECT_EQ(sel.work.m_height, H + 1);
}

// ========================================================================
// on_block_connected() -- incremental MnStateMachine::apply_block live-wire.
// #674 populated the DMN set only via the bulk mnlistdiff snapshot
// (on_mn_list_update). This slice drives apply_block per connected block so
// the set the embedded coinbase pays auto-maintains between snapshots, while
// the dashd RPC arm stays the fallback when the set can no longer back a payee.
// ========================================================================
static std::vector<std::pair<uint256, MNState>>
single_mn_coll(const std::vector<unsigned char>& payout,
               const uint256& coll_hash, uint32_t coll_idx) {
    MNState s;
    s.isValid = true;
    s.nRegisteredHeight = 2300000;
    s.nLastPaidHeight = 0;
    s.scriptPayout.m_data = payout;
    s.payoutSplitProvenance = MNState::SPLIT_KNOWN;   // fixture: proven zero split (h=2516595 gate)
    s.collateralOutpoint.hash  = coll_hash;
    s.collateralOutpoint.index = coll_idx;
    return std::vector<std::pair<uint256, MNState>>{{raw256(0x01), s}};
}

// A block with no special txs touches no DMN records: apply_block registers
// nothing, the set is unchanged, and the embedded bundle stays live.
TEST(DashCoinStateMaintainer, BlockConnectNoSpecialTxPreservesReadiness) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    m.on_new_tip(H - 1, PREV_HASH, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER, CURTIME, VERSION);
    ASSERT_TRUE(m.live());

    // Post projection-attribution: a connected block's coinbase pays the
    // PROJECTED payee (every dashd-accepted block does) — that is the
    // readiness-preserving "normal" block. A coinbase that does NOT pay the
    // projected MN is a payee DESYNC (own KAT below), not a no-op.
    BlockType blk;
    blk.m_txs.push_back(make_spend(raw256(0x90), 0, 500000000, 1));  // cb (idx 0)
    blk.m_txs[0].vout[0].scriptPubKey.m_data = p2pkh_script(0x30);   // pays projected MN
    blk.m_txs.push_back(make_spend(raw256(0x91), 0, 400000000, 2));  // plain spend, no collateral match
    bind_block(blk);
    auto r = m.on_block_connected(blk, H);

    EXPECT_EQ(r.registered, 0u);
    EXPECT_EQ(r.paid, 1u) << "projected payee must be marked paid";
    EXPECT_FALSE(r.payee_desync);
    EXPECT_EQ(st.mnstates().size(), 1u);
    EXPECT_TRUE(m.live()) << "no-op block must not drop the live bundle";
}

// ════════════════════════════════════════════════════════════════════════
// Soak-found 2026-07-22 (E4 re-soak, 13x bad-cb-payee): the payee queue can
// desync from the network's DIP-3 payment schedule (duplicated attribution,
// missed block, corrupted seed). A connected block whose coinbase does NOT
// pay the MN we project is that desync made visible. The maintainer must
// fail CLOSED: wipe the untrustworthy payee set, demote to the dashd
// fallback, and fire the authoritative re-seed hook — never keep serving a
// guessed payee (dashd rejects it with bad-cb-payee).
// ════════════════════════════════════════════════════════════════════════
TEST(DashCoinStateMaintainer, PayeeDesyncWipesDemotesAndFiresReseed) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    bool reseed_fired = false;
    m.set_on_mn_reseed([&]() { reseed_fired = true; });
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    m.on_new_tip(H - 1, PREV_HASH, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER, CURTIME, VERSION);
    ASSERT_TRUE(m.live());

    // Coinbase pays a DIFFERENT script than the projected MN's payout.
    // (bind_block: the E2 finding-A body-header bind guard landed after this
    // KAT was written; an unbound block was silently REFUSED before ever
    // reaching apply_block, so the desync path was never exercised here —
    // repaired as part of the E4 contiguity fix.)
    BlockType blk;
    blk.m_txs.push_back(make_spend(raw256(0x90), 0, 500000000, 1));
    blk.m_txs[0].vout[0].scriptPubKey.m_data = p2pkh_script(0x77);  // NOT the MN
    bind_block(blk);  // #802 body<->header bind guard: unbound blocks are REFUSED before the desync path
    auto r = m.on_block_connected(blk, H);

    EXPECT_TRUE(r.payee_desync);
    EXPECT_EQ(r.paid, 0u) << "a desynced payment must NOT be guessed onto some MN";
    EXPECT_EQ(st.mnstates().size(), 0u) << "desynced payee set must be wiped";
    EXPECT_FALSE(m.live()) << "desync must demote the bundle to the dashd fallback";
    EXPECT_TRUE(reseed_fired) << "desync must request an authoritative re-seed";

    bool fb = false;
    WorkSelection sel = st.select_work([&]() { fb = true; return DashWorkData{}; });
    EXPECT_EQ(sel.source, WorkSource::DashdFallback);
    EXPECT_TRUE(fb) << "after a payee desync, get_work must serve the dashd fallback";
}


// ════════════════════════════════════════════════════════════════════════
// Soak-found 2026-07-23 (E4 re-soak, bad-cb-payee at 1519827): a NON-
// CONTIGUOUS fold — the connected block is more than one past the payee
// queue's cursor (seed as-of height or last applied block) — means dashd
// advanced its DIP-3 payment queue at blocks we never folded. Within a
// shared-payoutAddress group the resulting cursor lag is invisible to the
// coinbase cross-check (same script) and surfaces as a served bad-cb-payee
// at the next address-group boundary. The maintainer must treat a gap
// exactly like a desync: fail CLOSED (wipe + demote + authoritative
// re-seed), never fold on a stale cursor. PRE-FIX this folded silently and
// stayed live serving the lagged projection.
// ════════════════════════════════════════════════════════════════════════
TEST(DashCoinStateMaintainer, SeedGapFailsClosedWipesDemotesAndReseeds) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    bool reseed_fired = false;
    m.set_on_mn_reseed([&]() { reseed_fired = true; });
    // Seed current as-of H-3: blocks H-2 and H-1 are never folded (the E4
    // incident's 1519821/1519822, mined during header sync).
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)), H - 3);
    m.on_new_tip(H - 1, PREV_HASH, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER, CURTIME, VERSION);
    ASSERT_TRUE(m.live());

    // The connected block's coinbase DOES pay the projected MN's script —
    // exactly the incident shape (same shared address), so pre-fix nothing
    // looked wrong and the wrong cursor slot was advanced.
    BlockType blk;
    blk.m_txs.push_back(make_spend(raw256(0x90), 0, 500000000, 1));
    blk.m_txs[0].vout[0].scriptPubKey.m_data = p2pkh_script(0x30);
    bind_block(blk);
    auto r = m.on_block_connected(blk, H);

    EXPECT_TRUE(r.gap_detected);
    EXPECT_EQ(r.paid, 0u) << "a gapped fold must not attribute the payment";
    EXPECT_EQ(st.mnstates().size(), 0u) << "stale-cursor payee set must be wiped";
    EXPECT_FALSE(m.live()) << "a gap must demote the bundle to the dashd fallback";
    EXPECT_TRUE(reseed_fired) << "a gap must request an authoritative re-seed";

    bool fb = false;
    WorkSelection sel = st.select_work([&]() { fb = true; return DashWorkData{}; });
    EXPECT_EQ(sel.source, WorkSource::DashdFallback);
    EXPECT_TRUE(fb) << "after a payee-queue gap, get_work must serve the dashd fallback";
}

// ════════════════════════════════════════════════════════════════════════
// Serve-time MN-payee freshness gate (E4 re-soak fix): under
// require_fresh_mn_payee the embedded arm must NOT serve while the payee
// queue has not folded every block through the tip it builds on — the
// projected payee would be a stale queue slot (the incident served
// templates for 1519823..1519827 off a queue current at 1519820). Once the
// queue catches up contiguously, the arm serves again. PRE-FIX no such gate
// existed: viability ignored the payee queue's currency entirely.
// ════════════════════════════════════════════════════════════════════════
TEST(DashCoinStateMaintainer, FreshMnPayeeGateRefusesLaggedQueueThenServes) {
    NodeCoinState st;
    st.set_require_fresh_mn_payee(true);
    CoinStateMaintainer m(st);
    // Queue current as-of H-2, but the tip we build on is H-1: the queue
    // has not folded block H-1 yet — its projection is pre-H-1 stale.
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)), H - 2);
    m.on_new_tip(H - 1, PREV_HASH, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER, CURTIME, VERSION);
    ASSERT_TRUE(m.live()) << "bundle is populated; the gate acts at viability";

    bool fb1 = false;
    WorkSelection s1 = st.select_work([&]() { fb1 = true; return DashWorkData{}; });
    EXPECT_EQ(s1.source, WorkSource::DashdFallback)
        << "a payee queue lagging the tip must not back an embedded template";
    EXPECT_TRUE(fb1);

    // Fold the missing block H-1 (contiguous with the H-2 seed; its
    // coinbase pays the projected MN). The queue is now current AT the tip.
    BlockType blk;
    blk.m_txs.push_back(make_spend(raw256(0x90), 0, 500000000, 1));
    blk.m_txs[0].vout[0].scriptPubKey.m_data = p2pkh_script(0x30);
    bind_block(blk);
    auto r = m.on_block_connected(blk, H - 1);
    EXPECT_FALSE(r.gap_detected);
    EXPECT_FALSE(r.payee_desync);
    EXPECT_EQ(r.paid, 1u);
    ASSERT_TRUE(m.live());

    bool fb2 = false;
    WorkSelection s2 = st.select_work([&]() { fb2 = true; return DashWorkData{}; });
    EXPECT_EQ(s2.source, WorkSource::Embedded)
        << "queue current at the tip: the embedded arm serves again";
    EXPECT_FALSE(fb2);
}

// A block whose non-coinbase tx spends the sole MN's collateral removes it
// (apply_block pass 2). The now-empty set cannot back a masternode payee, so
// the maintainer drops the embedded bundle and get_work falls back to dashd.
TEST(DashCoinStateMaintainer, BlockConnectCollateralSpendDropsToFallback) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    const uint256 coll = raw256(0x55);
    m.on_mn_list_update(single_mn_coll(p2pkh_script(0x30), coll, 3));
    m.on_new_tip(H - 1, PREV_HASH, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER, CURTIME, VERSION);
    ASSERT_TRUE(m.live());
    ASSERT_EQ(st.mnstates().size(), 1u);

    BlockType blk;
    blk.m_txs.push_back(make_spend(raw256(0x90), 0, 500000000, 1));  // cb (idx 0, skipped)
    blk.m_txs.push_back(make_spend(coll, 3, 400000000, 2));          // spends the MN collateral
    bind_block(blk);
    m.on_block_connected(blk, H);

    EXPECT_EQ(st.mnstates().size(), 0u);
    EXPECT_FALSE(m.live()) << "collateral spend emptied the DMN set; bundle must drop to fallback";

    bool fb = false;
    WorkSelection sel = st.select_work([&]() { fb = true; return DashWorkData{}; });
    EXPECT_EQ(sel.source, WorkSource::DashdFallback);
    EXPECT_TRUE(fb) << "empty DMN set must route get_work to the dashd RPC fallback";
}

// ========================================================================
// SML-axis reception behaviours (C-2 / H-6 / H-7).
// ========================================================================
using dash::coin::vendor::CSimplifiedMNListDiff;
using dash::coin::vendor::CSimplifiedMNListEntry;

static CSimplifiedMNListEntry sml_entry(uint8_t seed) {
    CSimplifiedMNListEntry e;
    e.proRegTxHash  = raw256(seed);
    e.confirmedHash = raw256(seed + 1);
    e.isValid = true;
    return e;
}

// A cold/incremental mnlistdiff carrying a type-5 cbTx seed (creditPool +
// nHeight @ cb_height), so on_mnlistdiff advances BOTH the currency hash and
// the paired height. Defined here (moved up from below) because the step-1
// wipe-audit KATs need it.
static CSimplifiedMNListDiff diff_with_seed(const uint256& base, const uint256& block,
                                            int32_t cb_height, int64_t credit_pool,
                                            CSimplifiedMNListEntry mn) {
    CSimplifiedMNListDiff d;
    d.baseBlockHash = base;
    d.blockHash     = block;
    d.mnList = {mn};
    dash::coin::vendor::CCbTx cb;
    cb.nVersion = dash::coin::vendor::CCbTx::VERSION_CLSIG_AND_BALANCE;
    cb.nHeight  = cb_height;
    cb.creditPoolBalance = credit_pool;
    d.cbTx.version = 3;
    d.cbTx.type    = 5;
    d.cbTx.extra_payload = dash::coin::encode_cbtx(cb);
    return d;
}

// ════════════════════════════════════════════════════════════════════════
// STEP-1 SML-CURRENCY WIPE AUDIT (gate for the "fourth-axis conjunct" that
// makes dmn-stale structurally unsatisfiable in steady state). The conjunct
// blocks tip promotion until sml_current_hash() == the header prev-hash and
// advances it back to a real value only via on_mnlistdiff. If ANY wipe path
// could leave m_sml_current_hash STALE-NONZERO, the base-continuity guard
// (on_mnlistdiff) would then reject every incremental whose base != that
// stale value, sml_current_hash could never re-reach the tip, and the
// conjunct would deadlock into an indefinite QUIET stall (no loud refusal,
// just work that never promotes). So the invariant the conjunct depends on
// is: every SML wipe leaves the currency hash EXACTLY ZERO, and ZERO is the
// cold sentinel on_mnlistdiff treats as "accept a full snapshot".
//
// The four (and only four) writers of m_sml_current_hash are:
//   1. on_mnlistdiff        -> diff.blockHash  (advance; paired with the list)
//   2. on_sml_reorg         -> uint256::ZERO   (wipe)
//   3. warm restart restore -> get_best_hash() (only inside the root-verified
//                              `warm` guard, main_dash.cpp; cold leaves ZERO)
//   4. the setter itself     (plumbing)
// The SML-LIST wipes are exactly two: the full-snapshot clear inside
// on_mnlistdiff (:595, which always falls through to writer #1 and lands a
// REAL hash) and on_sml_reorg (:829, which lands writer #2 = ZERO).
//
// FINDING (premise correction): the payee-desync / apply-gap wipe the design
// note flagged as a suspect (coin_state_maintainer.hpp ~:1224) is NOT an SML
// wipe at all — it wipes mnstates() (the PAYEE axis) and never touches the
// SML or its currency hash. So it correctly leaves sml_current_hash intact,
// and the two KATs below pin BOTH facts: the reorg wipe zeroes it, the payee
// desync leaves it untouched. No path can leave it stale-nonzero.
// ════════════════════════════════════════════════════════════════════════

// on_sml_reorg is the header-chain reorg entry (main_dash's reorg hook calls
// it directly; the malformed-quorum-tail heal reaches the SAME function via
// on_mnlistdiff, already covered above). It must land the currency hash at
// EXACTLY ZERO and the paired height at 0 — never a stale block hash.
TEST(DashCoinStateMaintainer, ReorgWipeZerosSmlCurrencyHashAndHeight) {
    NodeCoinState st;
    CoinStateMaintainer m(st);

    // Sync the SML to a real, NON-ZERO currency hash (cold full snapshot
    // carrying a type-5 cbTx so the paired height advances too).
    m.on_mnlistdiff(diff_with_seed(uint256::ZERO, raw256(0x54), 1518654,
                                   111'000'000LL, sml_entry(0x40)));
    ASSERT_TRUE(st.have_sml());
    ASSERT_EQ(st.sml_current_hash(), raw256(0x54));
    ASSERT_NE(st.sml_current_hash(), uint256::ZERO);
    ASSERT_EQ(m.sml_current_height(), 1518654u);
    ASSERT_TRUE(m.sml_height_paired());

    m.on_sml_reorg();

    EXPECT_EQ(st.sml_current_hash(), uint256::ZERO)
        << "an SML wipe MUST leave the currency hash EXACTLY ZERO, never a "
           "stale block hash — a stale-nonzero value would make on_mnlistdiff "
           "reject every incremental off it (base != stale), so the currency "
           "hash could never re-reach the tip and the fourth-axis conjunct "
           "would deadlock into an indefinite quiet stall";
    EXPECT_FALSE(st.have_sml());
    EXPECT_EQ(m.sml_current_height(), 0u)
        << "the paired height must reset with the hash (R1 freshness tracker)";
    EXPECT_FALSE(m.sml_height_paired());

    // And ZERO must actually behave as the cold sentinel: only a FULL
    // snapshot (base=ZERO) is accepted; a clean incremental off the old tip
    // is refused. This is the property that lets the conjunct recover rather
    // than wedge — a fresh full diff re-establishes currency.
    m.on_mnlistdiff(diff_with_seed(raw256(0x54), raw256(0x55), 1518655,
                                   111'066'966'830LL, sml_entry(0x41)));
    EXPECT_FALSE(st.have_sml())
        << "post-wipe, an incremental off the old tip must STILL refuse";
    EXPECT_EQ(st.sml_current_hash(), uint256::ZERO);
}

// The payee-desync / apply-gap path (on_block_connected -> wipe) is a PAYEE
// wipe, not an SML wipe. It must leave the SML currency hash UNTOUCHED — the
// SML axis stays valid and its hash keeps describing it accurately, so the
// conjunct is neither falsely satisfied (the SML really is at that block) nor
// deadlocked (the hash is not corrupted). This KAT pins the premise
// correction: the path the design note suspected does not move the hash.
TEST(DashCoinStateMaintainer, PayeeDesyncLeavesSmlCurrencyHashIntact) {
    NodeCoinState st;
    CoinStateMaintainer m(st);

    // SML current at a real block; payee queue armed and live at the tip.
    m.on_mnlistdiff(diff_with_seed(uint256::ZERO, PREV_HASH, H - 1,
                                   111'000'000LL, sml_entry(0x40)));
    ASSERT_EQ(st.sml_current_hash(), PREV_HASH);
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    m.on_new_tip(H - 1, PREV_HASH, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER,
                 CURTIME, VERSION);

    // Force a payee desync: the connected block's coinbase pays a script the
    // projected MN does not.
    BlockType blk;
    blk.m_txs.push_back(make_spend(raw256(0x90), 0, 500000000, 1));
    blk.m_txs[0].vout[0].scriptPubKey.m_data = p2pkh_script(0x77);  // NOT the MN
    bind_block(blk);
    auto r = m.on_block_connected(blk, H);

    ASSERT_TRUE(r.payee_desync) << "precondition: the desync path must fire";
    EXPECT_EQ(st.mnstates().size(), 0u) << "the PAYEE set is wiped...";
    EXPECT_EQ(st.sml_current_hash(), PREV_HASH)
        << "...but the SML currency hash is UNTOUCHED — a payee-axis wipe is "
           "not an SML wipe. Zeroing it here would needlessly force a full "
           "SML re-sync on every payee desync; leaving it stale-WRONG would "
           "deadlock the conjunct. It must stay EXACTLY what the SML is at.";
    EXPECT_TRUE(st.have_sml()) << "the SML list itself survives a payee wipe";
}

// ════════════════════════════════════════════════════════════════════════
// STEP 2 — THE FOURTH-AXIS CONJUNCT (SML currency) in maybe_promote_pending_tip.
//
// Publish-last: the body-first serve tip is promoted only once ALL FOUR
// derived axes agree on the block — credit-pool, payee cursor, AND now the SML
// currency hash. This makes node_coin_state.hpp clause 12 (dmn-stale)
// structurally unsatisfiable in steady state WITHOUT relaxing the gate: the
// serve tip m_prev_hash is never advanced to a block the SML is not at.
//
// Helper: arm credit-pool + payee current AT `tip`/`height` directly on the
// NodeCoinState (each axis has its own public setter), leaving SML to the
// individual test. Promotion reads these axes plus the maintainer's stashed
// header tip; the require_* serve flags gate SERVING, not promotion.
static void arm_cp_and_payee_at(NodeCoinState& st, const uint256& tip,
                                uint32_t height) {
    st.set_credit_pool(111'000'000LL, tip, static_cast<int32_t>(height));
    MNState s;
    s.isValid = true;
    s.nRegisteredHeight = 2'300'000;
    s.scriptPayout.m_data = p2pkh_script(0x30);
    s.payoutSplitProvenance = MNState::SPLIT_KNOWN;
    st.mnstates().load(
        std::vector<std::pair<uint256, MNState>>{{raw256(0x01), s}}, height);
}

// SML behind the tip (nonzero, mismatched) MUST block promotion — the tip
// stays body-pending rather than advancing into a dmn-stale refusal.
TEST(DashCoinStateMaintainer, FourthAxisSmlBehindTipBlocksPromotion) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.set_body_first_serve_tip(true);

    arm_cp_and_payee_at(st, PREV_HASH, H - 1);
    st.set_have_sml(true);
    st.set_sml_current_hash(raw256(0xCD));   // SML at a DIFFERENT nonzero block

    m.on_new_tip(H - 1, PREV_HASH, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER,
                 CURTIME, VERSION);

    EXPECT_TRUE(m.tip_body_pending())
        << "credit-pool and payee are current at the tip but the SML is not — "
           "promoting here would advance the serve tip straight into a "
           "dmn-stale refusal (clause 12). The fourth-axis conjunct must hold "
           "the tip body-pending until the SML currency reaches it.";
}

// SML current at the tip (all four axes agree) MUST promote.
TEST(DashCoinStateMaintainer, FourthAxisSmlCurrentAtTipPromotes) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.set_body_first_serve_tip(true);

    arm_cp_and_payee_at(st, PREV_HASH, H - 1);
    st.set_have_sml(true);
    st.set_sml_current_hash(PREV_HASH);      // SML current AT the tip

    m.on_new_tip(H - 1, PREV_HASH, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER,
                 CURTIME, VERSION);

    // tip_body_pending() flipping to false IS the promotion (the conjunct
    // released). m.live()/populated() additionally needs the MN-readiness
    // snapshot plumbing, which this unit does not arm — the promotion axis is
    // exactly tip_body_pending here.
    EXPECT_FALSE(m.tip_body_pending())
        << "all four axes current at the tip — promotion must proceed";
}

// THE CARVE-OUT (coordinator-mandated, test-visible so a future reader cannot
// "tighten" it into a cold-start deadlock). A ZERO SML currency hash is
// cold-start OR post-reorg-wipe (step-1 audit: both land the identical ZERO
// sentinel). It must NOT block promotion — serving is still gated by the
// require_sml half of populated(), which surfaces as clause 10 (no-dmn-set),
// evaluated before clause 12. If the ZERO case blocked promotion, a cold node
// would deadlock: the currency hash can only reach the tip once a full
// snapshot lands, and nothing drives that if the whole arm waited on it first.
TEST(DashCoinStateMaintainer, FourthAxisColdSmlDoesNotBlockPromotion) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.set_body_first_serve_tip(true);

    arm_cp_and_payee_at(st, PREV_HASH, H - 1);
    st.set_sml_current_hash(uint256::ZERO);  // cold / post-wipe sentinel

    m.on_new_tip(H - 1, PREV_HASH, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER,
                 CURTIME, VERSION);

    EXPECT_FALSE(m.tip_body_pending())
        << "a ZERO (cold/wiped) SML currency must NOT hold promotion back — "
           "that is the carve-out; blocking here would deadlock cold start. "
           "Serving is still gated by require_sml/no-dmn-set downstream.";
}

// ════════════════════════════════════════════════════════════════════════
// STEP 3 — the LOAD-BEARING companion: the diff-phase sub-threshold re-request.
// Without it the conjunct turns a dropped/lost getmnlistd into up to 30 s of
// silent H-1 serving (which orphans past propagation). check_tip_body_overdue,
// driven opportunistically (on_mempool_tx is the clock), fires the first
// getmnlistd(base=sml, target=hdr-tip) after ~min_quiet, then re-asks on a
// GEOMETRIC backoff for max_attempts tries and, past the cap, at a CLAMPED
// perpetual cadence (min_quiet * backoff^max_attempts) — never a burst, but
// never silent either (#1315: an unchanging stuck (tip, sml) pair used to go
// silent at the cap and strand the arm on the dashd fallback for the whole
// 18-min block gap). The 30 s hard doomed-tip demote is unchanged and still
// governs; the re-ask only makes the promotion state arrive sooner, it never
// widens what is served.
// ════════════════════════════════════════════════════════════════════════
TEST(DashCoinStateMaintainer, DiffPhaseReRequestFiresBoundedThenDefersToDemote) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.set_body_first_serve_tip(true);
    m.set_tip_body_overdue_secs(30);

    int64_t now = 1000;
    m.set_now_fn([&now]() { return now; });

    std::vector<std::pair<uint256, uint256>> reqs;
    std::vector<int64_t> req_times;  // wall-clock of each re-ask, to pin the cadence
    m.set_on_sml_rerequest(
        [&reqs, &req_times, &now](const uint256& base, const uint256& target) {
            reqs.emplace_back(base, target);
            req_times.push_back(now);
        });

    // Tip body-pending with the SML stuck one behind the tip.
    arm_cp_and_payee_at(st, PREV_HASH, H - 1);
    st.set_have_sml(true);
    st.set_sml_current_hash(raw256(0xCD));
    m.on_new_tip(H - 1, PREV_HASH, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER,
                 CURTIME, VERSION);
    ASSERT_TRUE(m.tip_body_pending()) << "conjunct holds it pending";

    auto tick = [&](int64_t at) {
        now = at;
        m.on_mempool_tx(make_spend(raw256(0x90), 0, 90'000, /*salt=*/int(at)));
    };

    // First sighting of the stuck (tip, sml) pair starts the quiet clock and
    // NEVER retries — this is what keeps the ordinary sub-second per-tip window
    // (104 of 109 measured episodes) from ever generating traffic.
    tick(1001);
    EXPECT_TRUE(reqs.empty()) << "first sighting must not re-request";

    // Still inside the quiet period (2 s < 4 s).
    tick(1003);
    EXPECT_TRUE(reqs.empty()) << "must not re-request inside the quiet period";

    // Past min_quiet (5 s ≥ 4 s): exactly ONE re-request, byte-identical to the
    // tip-change getmnlistd (base = where the SML is, target = the header tip).
    tick(1006);
    ASSERT_EQ(reqs.size(), 1u) << "one bounded re-request after ~min_quiet";
    EXPECT_EQ(reqs[0].first,  raw256(0xCD)) << "base = where the SML is";
    EXPECT_EQ(reqs[0].second, PREV_HASH)    << "target = the header tip";

    // Geometric backoff, then a CLAMPED perpetual cadence: keep ticking on a 5 s
    // clock across a long stall on the SAME stuck (tip, sml) pair. The re-ask
    // must (a) keep going PAST the old max_attempts=3 cap — going silent here is
    // the measured 18-min wedge (#1315) — while (b) never collapsing to a burst:
    // past the cap the spacing is pinned at the clamp interval
    //   min_quiet(4) * backoff(2)^max_attempts(3) = 32 s.
    const int64_t kClampSec = 32;   // = 4 * 2^3
    const int64_t kTickStep = 5;
    int loop_ticks = 0;
    for (int64_t t = 1010; t <= 1200; t += kTickStep) { tick(t); ++loop_ticks; }

    // (a) It did NOT stop at the old cap of 3 — the whole point of the fix.
    EXPECT_GT(reqs.size(), 3u)
        << "past max_attempts the re-ask must CONTINUE at the clamped cadence; "
           "the pre-fix code went silent at 3 and stranded the 18-min wedge";

    // Deterministic and bounded: over this exact window the clamped cadence
    // yields precisely these re-asks — never one-per-tick.
    EXPECT_EQ(reqs.size(), 7u)
        << "first re-ask at ~min_quiet, geometric (8 s, 16 s), then clamped at "
           "32 s for the rest of the window — a fixed, bounded schedule";
    EXPECT_LT(static_cast<int>(reqs.size()), loop_ticks / 4)
        << "the clamped cadence must stay far below one request per tick — "
           "never a burst against a struggling peer";
    ASSERT_EQ(reqs.size(), req_times.size());

    // (b) Cadence proof: every gap AFTER the geometric ramp (attempts >= 4, i.e.
    // from req index 3 on) sits at the clamp — at least kClampSec (never faster)
    // and at most one tick past it (re-asks the instant the clamp elapses, so it
    // is a steady clamped cadence, not a one-shot that then goes quiet).
    for (size_t i = 4; i < req_times.size(); ++i) {
        const int64_t gap = req_times[i] - req_times[i - 1];
        EXPECT_GE(gap, kClampSec)
            << "clamped interval must never collapse below the cap (i=" << i << ")";
        EXPECT_LE(gap, kClampSec + kTickStep)
            << "but it must re-ask as soon as the clamp elapses (i=" << i << ")";
    }

    // The re-ask stays byte-identical to the tip-change getmnlistd for the whole
    // clamped run: base = where the SML is, target = the header tip.
    EXPECT_EQ(reqs.back().first,  raw256(0xCD)) << "base = where the SML is";
    EXPECT_EQ(reqs.back().second, PREV_HASH)    << "target = the header tip";

    // STILL DEFERS TO DEMOTE: the perpetual re-ask does not change what is
    // served. The SML never reached the tip, so the conjunct kept the tip
    // body-pending the entire time (well past the 30 s doomed-tip demote
    // boundary) — it never promoted into a dmn-stale serve. The clamped re-ask
    // only tries to heal the stall sooner; the demote gate is untouched.
    EXPECT_TRUE(m.tip_body_pending());
}

// H-7 base-continuity: once the SML is current at block A, an INCREMENTAL diff
// whose base is NOT A is rejected — the SML and its current-at marker are left
// untouched (no ghost-MN corruption from applying a diff off the wrong base).
TEST(DashCoinStateMaintainer, MnlistdiffBaseContinuityRejectsMismatchedBase) {
    NodeCoinState st;
    CoinStateMaintainer m(st);

    // Cold-start full snapshot (base ZERO) -> SML current at A.
    CSimplifiedMNListDiff d1;
    d1.baseBlockHash = uint256::ZERO;
    d1.blockHash     = raw256(0xA0);
    d1.mnList = {sml_entry(0x40), sml_entry(0x60)};
    m.on_mnlistdiff(d1);
    ASSERT_TRUE(st.have_sml());
    ASSERT_EQ(st.sml().size(), 2u);
    ASSERT_EQ(st.sml_current_hash(), raw256(0xA0));

    // A diff based on some OTHER block B (!= A) must be rejected.
    CSimplifiedMNListDiff bad;
    bad.baseBlockHash = raw256(0xB0);
    bad.blockHash     = raw256(0xC0);
    bad.mnList = {sml_entry(0x80)};
    m.on_mnlistdiff(bad);
    EXPECT_EQ(st.sml().size(), 2u) << "mismatched-base diff must not mutate the SML";
    EXPECT_EQ(st.sml_current_hash(), raw256(0xA0)) << "current-at marker must not advance";

    // A correctly-based incremental diff (base == A) IS accepted.
    CSimplifiedMNListDiff d2;
    d2.baseBlockHash = raw256(0xA0);
    d2.blockHash     = raw256(0xD0);
    d2.mnList = {sml_entry(0x80)};
    m.on_mnlistdiff(d2);
    EXPECT_EQ(st.sml_current_hash(), raw256(0xD0));
    EXPECT_EQ(st.sml().size(), 3u);
}

// ════════════════════════════════════════════════════════════════════════
// RESEED-WEDGE KAT (daemonless soak wedge): a getmnlistd(base=B, target=T)
// reply that lands AFTER the SML already advanced to T is REDUNDANT (target
// already held), NOT out-of-sequence — have_at == T == diff.blockHash while
// baseBlockHash == B != have_at. PRE-FIX the H-7 base-continuity guard
// rejected it, and the payee-desync reseed latch (m_mn_needs_reseed), which
// was waiting on exactly that advance, stayed latched forever: the node
// served nothing (wedge log: have_mn=0 mn_entries=0, sml advanced).
//
// The fix must (a) NOT apply the redundant diff (we are already at its
// target), (b) clear the latch, and (c) RE-DRIVE the existing authoritative
// payee re-seed ask (m_on_mn_reseed): clearing the flag alone cannot restore
// serving because the desync wipe emptied the payee queue and m_have_mn only
// re-arms off a NON-EMPTY authoritative snapshot. Serving is then proven to
// actually recover once that snapshot lands.
// ════════════════════════════════════════════════════════════════════════
TEST(DashCoinStateMaintainer, TargetAlreadyHeldDiffIsNoOpAndClearsReseedLatch) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    int reseed_asks = 0;
    m.set_on_mn_reseed([&]() { ++reseed_asks; });

    // SML current at A (cold full snapshot, height-paired via the cbTx seed).
    m.on_mnlistdiff(diff_with_seed(uint256::ZERO, raw256(0xA0), H - 1,
                                   1'000'000, sml_entry(0x40)));
    ASSERT_TRUE(st.have_sml());
    ASSERT_EQ(st.sml_current_hash(), raw256(0xA0));
    const size_t sml_before = st.sml().size();

    // Payee queue + tip -> the embedded arm serves.
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)), H - 1);
    m.on_new_tip(H - 1, PREV_HASH, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER,
                 CURTIME, VERSION);
    ASSERT_TRUE(m.live());

    // Payee DESYNC at H: coinbase pays a script that is NOT the projected
    // MN's — the maintainer wipes the queue, latches, demotes, asks reseed.
    BlockType blk;
    blk.m_txs.push_back(make_spend(raw256(0x90), 0, 500000000, 1));
    blk.m_txs[0].vout[0].scriptPubKey.m_data = p2pkh_script(0x77);
    bind_block(blk);
    auto r = m.on_block_connected(blk, H);
    ASSERT_TRUE(r.payee_desync);
    ASSERT_TRUE(m.mn_needs_reseed_latched());
    ASSERT_TRUE(st.mn_needs_reseed());
    ASSERT_EQ(st.mnstates().size(), 0u) << "the wipe empties the payee queue";
    ASSERT_EQ(reseed_asks, 1);

    // The raced reply: getmnlistd(base=B, target=A) landing after the SML
    // already advanced to A. Target already held => redundant no-op.
    m.on_mnlistdiff(diff_with_seed(raw256(0x90), raw256(0xA0), H - 1,
                                   1'000'000, sml_entry(0x40)));

    // RED ON MASTER: the base-continuity guard rejected the redundant diff
    // and the latch stayed latched forever.
    EXPECT_FALSE(m.mn_needs_reseed_latched())
        << "a target-already-held diff is redundant, not out-of-sequence — "
           "it must clear the reseed latch that was waiting on this advance";
    EXPECT_FALSE(st.mn_needs_reseed());
    EXPECT_EQ(reseed_asks, 2)
        << "latch-clear alone cannot restore serving (the queue is EMPTY): "
           "the redundant diff must re-drive the authoritative re-seed ask";

    // No-op pins: the redundant diff must not have been APPLIED.
    EXPECT_EQ(st.sml_current_hash(), raw256(0xA0));
    EXPECT_EQ(st.sml().size(), sml_before);
    EXPECT_EQ(st.mnstates().size(), 0u)
        << "the SML diff itself must not repopulate the payee queue";

    // SERVE-RESTORE, not just the flag: answer the re-driven ask with the
    // authoritative snapshot — the arm must serve again.
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)), H);
    ASSERT_TRUE(m.live())
        << "after the authoritative re-seed lands, the embedded arm re-arms";
    bool fb = false;
    WorkSelection sel = st.select_work([&]() { fb = true; return DashWorkData{}; });
    EXPECT_EQ(sel.source, WorkSource::Embedded);
    EXPECT_FALSE(fb);
}

// ════════════════════════════════════════════════════════════════════════
// CANNOT-WEAKEN PIN for the carve-out above: a genuinely OUT-OF-SEQUENCE
// diff — base != have_at AND target != have_at — must still take the H-7
// base-continuity reject UNCHANGED: no SML mutation, no currency advance,
// the reseed latch STAYS latched and no re-seed ask is re-driven. The
// carve-out condition (diff.blockHash == have_at) is disjoint from this
// case by construction; this test keeps it that way.
// ════════════════════════════════════════════════════════════════════════
TEST(DashCoinStateMaintainer, OutOfSequenceDiffStillRejectedAndKeepsLatch) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    int reseed_asks = 0;
    m.set_on_mn_reseed([&]() { ++reseed_asks; });

    m.on_mnlistdiff(diff_with_seed(uint256::ZERO, raw256(0xA0), H - 1,
                                   1'000'000, sml_entry(0x40)));
    ASSERT_EQ(st.sml_current_hash(), raw256(0xA0));
    const size_t sml_before = st.sml().size();

    m.on_mn_list_update(single_mn(p2pkh_script(0x30)), H - 1);
    m.on_new_tip(H - 1, PREV_HASH, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER,
                 CURTIME, VERSION);
    ASSERT_TRUE(m.live());

    BlockType blk;
    blk.m_txs.push_back(make_spend(raw256(0x90), 0, 500000000, 1));
    blk.m_txs[0].vout[0].scriptPubKey.m_data = p2pkh_script(0x77);
    bind_block(blk);
    auto r = m.on_block_connected(blk, H);
    ASSERT_TRUE(r.payee_desync);
    ASSERT_TRUE(m.mn_needs_reseed_latched());
    ASSERT_EQ(reseed_asks, 1);

    // Genuinely out-of-sequence: base 0x90 != have_at 0xA0 AND target
    // 0xC0 != have_at. The reject must fire exactly as before the carve-out.
    m.on_mnlistdiff(diff_with_seed(raw256(0x90), raw256(0xC0), H,
                                   1'000'000, sml_entry(0x80)));

    EXPECT_EQ(st.sml().size(), sml_before)
        << "an out-of-sequence diff must not mutate the SML";
    EXPECT_EQ(st.sml_current_hash(), raw256(0xA0))
        << "the currency marker must not advance off an out-of-sequence diff";
    EXPECT_TRUE(m.mn_needs_reseed_latched())
        << "an out-of-sequence diff proves NOTHING about the awaited advance "
           "— the reseed latch must stay latched";
    EXPECT_TRUE(st.mn_needs_reseed());
    EXPECT_EQ(reseed_asks, 1)
        << "no re-seed re-drive off a rejected out-of-sequence diff";

    bool fb = false;
    WorkSelection sel = st.select_work([&]() { fb = true; return DashWorkData{}; });
    EXPECT_EQ(sel.source, WorkSource::DashdFallback);
    EXPECT_TRUE(fb) << "the arm stays demoted until an authoritative re-seed";
}

// A1 cursor-derived getmnlistd base: the tip-advance / handshake send paths
// (main_dash.cpp:5107 / :5226) now derive the getmnlistd request base from
// CoinStateMaintainer::sml_current_hash() — the block the SML is ACTUALLY
// current at — instead of the reception-time `sml_base` tracker that advanced
// on EVERY received diff (accepted or not). This regression-pins the
// in-flight-overlap latch closed.
//
// Scenario (the design's root divergence, no demux leak needed): two tip
// advances overlap in flight and both request base = cursor0 (ZERO, cold).
// reply1 (base ZERO -> tip1) is accepted (cursor -> tip1). reply2 (base ZERO
// -> tip2) BASE-REJECTS at the maintainer because have_at is now tip1 — but a
// reception-time tracker would still write tip2, stranding the request base
// AHEAD of the applied cursor. Every later request off that stranded base then
// re-trips base-continuity and the cursor never moves again (latch).
//
// With the base derived from sml_current_hash(): after the rejected reply2 the
// base source is still tip1 (the applied cursor), so the next advance requests
// base == tip1 -> a contiguous span that is accepted and advances the cursor.
TEST(DashCoinStateMaintainer, CursorDerivedBaseSurvivesInFlightOverlapLatch) {
    NodeCoinState st;
    CoinStateMaintainer m(st);

    const uint256 TIP1 = raw256(0xA0);
    const uint256 TIP2 = raw256(0xB0);
    const uint256 TIP3 = raw256(0xC0);

    // A fake coin_p2p capturing send_getmnlistd(base, target). The captured
    // base mirrors the FIXED send site exactly: base = m.sml_current_hash().
    std::vector<std::pair<uint256, uint256>> reqs;
    auto request = [&](const uint256& target) {
        const uint256 base = m.sml_current_hash();   // A1 send-site derivation
        reqs.emplace_back(base, target);
        return base;
    };
    // A model of the RETIRED reception-time tracker: advances on every received
    // diff regardless of acceptance. Kept only to demonstrate it would strand.
    uint256 reception_base = uint256::ZERO;
    auto on_reply = [&](const uint256& base, const uint256& block) {
        CSimplifiedMNListDiff d;
        d.baseBlockHash = base;
        d.blockHash     = block;
        d.mnList = {sml_entry(0x40)};
        m.on_mnlistdiff(d);
        reception_base = block;   // reception-time tracker: writes unconditionally
    };

    // Two advances overlap in flight: both derive base from the cold cursor
    // (ZERO) BEFORE either reply lands.
    ASSERT_EQ(request(TIP1), uint256::ZERO);
    ASSERT_EQ(request(TIP2), uint256::ZERO);

    // reply1: base ZERO -> tip1, accepted; cursor advances to tip1.
    on_reply(uint256::ZERO, TIP1);
    ASSERT_EQ(m.sml_current_hash(), TIP1);

    // reply2: base ZERO -> tip2, BASE-REJECTS (have_at is tip1 now). The cursor
    // must NOT advance to the stranded reception hash.
    on_reply(uint256::ZERO, TIP2);
    EXPECT_EQ(m.sml_current_hash(), TIP1)
        << "a base-rejected overlapping reply must not advance the applied cursor";
    // The retired reception-time tracker WOULD have stranded ahead of the
    // cursor — this is exactly the latch the fix removes.
    EXPECT_EQ(reception_base, TIP2);
    EXPECT_NE(reception_base, m.sml_current_hash());

    // Next advance: the FIXED send site derives base from the applied cursor
    // (tip1), NOT the stranded reception hash (tip2).
    const uint256 next_base = request(TIP3);
    EXPECT_EQ(next_base, m.sml_current_hash());
    EXPECT_EQ(next_base, TIP1) << "base must be the applied cursor, not the stranded reception hash";
    EXPECT_NE(next_base, reception_base);

    // A diff off that cursor-derived base (tip1 -> tip3) is contiguous and
    // accepted: the cursor advances, the latch is broken.
    on_reply(next_base, TIP3);
    EXPECT_EQ(m.sml_current_hash(), TIP3)
        << "cursor-derived base yields a contiguous span the maintainer accepts";

    // Counter-model: had the send site used the stranded reception base (tip2),
    // the same reply would base-reject and the cursor would stay wedged.
    {
        NodeCoinState st2;
        CoinStateMaintainer m2(st2);
        CSimplifiedMNListDiff cold;
        cold.baseBlockHash = uint256::ZERO;
        cold.blockHash     = TIP1;
        cold.mnList = {sml_entry(0x40)};
        m2.on_mnlistdiff(cold);
        ASSERT_EQ(m2.sml_current_hash(), TIP1);
        CSimplifiedMNListDiff stranded;
        stranded.baseBlockHash = TIP2;   // the reception-time tracker's stranded base
        stranded.blockHash     = TIP3;
        stranded.mnList = {sml_entry(0x41)};
        m2.on_mnlistdiff(stranded);
        EXPECT_EQ(m2.sml_current_hash(), TIP1)
            << "reception-time base (tip2) base-rejects at the maintainer -> the "
               "cursor stays wedged: this is the latch the A1 fix removes";
    }
}

// C-2 chainlock: on_new_chainlock adopts a fresher ChainLock as the CCbTx
// bestCL* and fires the state-dirty sink; a non-advancing height is ignored.
TEST(DashCoinStateMaintainer, OnNewChainlockAdoptsForwardOnlyAndFiresDirty) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    int dirty = 0;
    m.set_on_state_dirty([&] { ++dirty; });
    // Accepting verifier: this test covers the forward-only/dirty axis only.
    m.set_chainlock_verify_fn(
        [](int32_t, const uint256&, const std::array<uint8_t, 96>&) { return true; });

    const uint256 bh = uint256::ZERO;
    std::array<uint8_t, 96> sig{}; sig[0] = 0x11;
    m.on_new_chainlock(1500000, bh, sig);
    EXPECT_EQ(st.best_cl_height(), 1500000);
    EXPECT_EQ(dirty, 1) << "a fresher ChainLock must re-issue work";

    // A stale (<=) height is ignored — no adoption, no re-issue.
    std::array<uint8_t, 96> older{}; older[0] = 0x22;
    m.on_new_chainlock(1499999, bh, older);
    EXPECT_EQ(st.best_cl_height(), 1500000);
    EXPECT_EQ(dirty, 1);

    // A forward ChainLock advances + re-issues again.
    m.on_new_chainlock(1500005, bh, sig);
    EXPECT_EQ(st.best_cl_height(), 1500005);
    EXPECT_EQ(dirty, 2);
}

// C-2b chainlock adoption is GATED ON VERIFICATION. These are the reward-
// critical negatives: an unverified clsig from a hostile peer must never reach
// the CCbTx bestCL* fields we commit into a served template.
TEST(DashCoinStateMaintainer, OnNewChainlockFailsClosedWithoutVerifier) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    int dirty = 0;
    m.set_on_state_dirty([&] { ++dirty; });

    // NO verifier installed -> adopt nothing (the pre-existing lagging
    // chain-committed derivation stays authoritative).
    std::array<uint8_t, 96> sig{}; sig[0] = 0x11;
    m.on_new_chainlock(1500000, uint256::ZERO, sig);
    EXPECT_EQ(st.best_cl_height(), 0)
        << "no verifier must mean no adoption, not blind adoption";
    EXPECT_EQ(dirty, 0);
}

TEST(DashCoinStateMaintainer, OnNewChainlockRejectedWhenVerifierSaysNo) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    int dirty = 0, calls = 0;
    m.set_on_state_dirty([&] { ++dirty; });
    m.set_chainlock_verify_fn(
        [&](int32_t, const uint256&, const std::array<uint8_t, 96>&) {
            ++calls;
            return false;                 // verification FAILS
        });

    std::array<uint8_t, 96> sig{}; sig[0] = 0x11;
    m.on_new_chainlock(1500000, uint256::ZERO, sig);
    EXPECT_EQ(calls, 1) << "the verifier must actually be consulted";
    EXPECT_EQ(st.best_cl_height(), 0) << "a failing verify must not adopt";
    EXPECT_EQ(dirty, 0);

    // And the identical ChainLock IS adopted once the verifier accepts it —
    // proving the refusal above came from the gate, not from some other guard.
    m.set_chainlock_verify_fn(
        [](int32_t, const uint256&, const std::array<uint8_t, 96>&) { return true; });
    m.on_new_chainlock(1500000, uint256::ZERO, sig);
    EXPECT_EQ(st.best_cl_height(), 1500000);
    EXPECT_EQ(dirty, 1);
}

// H-1 (PR #780): a malformed quorum tail must NOT be papered over. It heals like
// a quorum-axis reorg (wipe + force full re-sync); a later clean INCREMENTAL diff
// is REJECTED by base-continuity (state stays wiped) — only a full snapshot
// recovers. This closes the un-latch where quorum_healthy flipped back true on
// the next incremental while the QuorumManager stayed permanently wrong.
TEST(DashCoinStateMaintainer, MalformedQuorumTailHealsViaFullResyncNotIncremental) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    int resync_calls = 0;
    m.set_on_full_resync([&] { ++resync_calls; });

    // 1) Cold full snapshot with a valid (empty) quorum tail -> applied.
    CSimplifiedMNListDiff d_full1;
    d_full1.baseBlockHash = uint256::ZERO;
    d_full1.blockHash     = raw256(0xA0);
    d_full1.mnList = {sml_entry(0x40), sml_entry(0x60)};
    // quorum_tail empty => parse_quorum_tail returns true.
    m.on_mnlistdiff(d_full1);
    ASSERT_TRUE(st.have_sml());
    ASSERT_EQ(st.sml().size(), 2u);
    ASSERT_EQ(st.sml_current_hash(), raw256(0xA0));
    ASSERT_TRUE(st.quorum_healthy());

    // 2) Incremental off A with a MALFORMED quorum tail -> HEAL: wipe + resync.
    CSimplifiedMNListDiff d_bad;
    d_bad.baseBlockHash = raw256(0xA0);
    d_bad.blockHash     = raw256(0xB0);
    d_bad.mnList = {sml_entry(0x80)};
    d_bad.quorum_tail = {0x01};   // deletedQuorums count=1 with no body => parse fails
    m.on_mnlistdiff(d_bad);
    EXPECT_FALSE(st.have_sml())      << "malformed tail must wipe (fail closed)";
    EXPECT_EQ(st.sml().size(), 0u);
    EXPECT_EQ(st.sml_current_hash(), uint256::ZERO);
    EXPECT_FALSE(st.quorum_healthy());
    EXPECT_EQ(resync_calls, 1)       << "must force a full re-sync from zero";

    // 3) A clean INCREMENTAL diff must NOT recover — base-continuity rejects it
    //    (base=B != current=ZERO), so the skipped delta can't be ridden over.
    CSimplifiedMNListDiff d_incr;
    d_incr.baseBlockHash = raw256(0xB0);
    d_incr.blockHash     = raw256(0xC0);
    d_incr.mnList = {sml_entry(0x90)};
    m.on_mnlistdiff(d_incr);
    EXPECT_FALSE(st.have_sml()) << "a clean incremental after a wipe must STILL refuse";
    EXPECT_EQ(st.sml().size(), 0u);
    EXPECT_EQ(st.sml_current_hash(), uint256::ZERO);
    EXPECT_FALSE(st.quorum_healthy());

    // 4) Only a FULL snapshot (base=ZERO) heals the state.
    CSimplifiedMNListDiff d_full2;
    d_full2.baseBlockHash = uint256::ZERO;
    d_full2.blockHash     = raw256(0xC0);
    d_full2.mnList = {sml_entry(0x40), sml_entry(0x60), sml_entry(0x90)};
    m.on_mnlistdiff(d_full2);
    EXPECT_TRUE(st.have_sml());
    EXPECT_EQ(st.sml().size(), 3u);
    EXPECT_EQ(st.sml_current_hash(), raw256(0xC0));
    EXPECT_TRUE(st.quorum_healthy());
}

// Build a diff carrying a type-5 cbTx seed (creditPool @ cb_height).
// SOAK FIX v3 — POST-RESTART: after a cold snapshot the credit-pool seed MUST
// advance off the snapshot on the first incremental (the re-soak #2 defect was
// it staying put). And a non-advancing seed (a diff whose cbTx does not carry a
// newer height) leaves the seed height behind → the freshness gate fails closed.
TEST(DashCoinStateMaintainer, PostRestartColdSnapshotThenIncrementalAdvancesSeed) {
    NodeCoinState st;
    CoinStateMaintainer m(st);

    // Cold snapshot at tip height 1518654 (base=ZERO).
    m.on_mnlistdiff(diff_with_seed(uint256::ZERO, raw256(0x54), 1518654,
                                   111'000'000LL, sml_entry(0x40)));
    ASSERT_EQ(st.credit_pool_height(), 1518654);
    ASSERT_EQ(st.credit_pool(), 111'000'000LL);

    // First incremental to 1518655 (base=0x54) — the seed MUST advance.
    m.on_mnlistdiff(diff_with_seed(raw256(0x54), raw256(0x55), 1518655,
                                   111'066'966'830LL, sml_entry(0x41)));
    EXPECT_EQ(st.credit_pool_height(), 1518655)
        << "credit-pool seed must advance off the cold snapshot on the first incremental";
    EXPECT_EQ(st.credit_pool(), 111'066'966'830LL);
    EXPECT_EQ(st.sml_current_hash(), raw256(0x55));

    // Full bundle so viability can be judged: MN payee + tip at 1518655.
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    st.set_require_sml(true);
    st.set_require_fresh_credit_pool(true);
    m.on_new_tip(1518655, raw256(0x55), 0x1b104be3u, 1'700'000'000u,
                 DASH_PUBKEY_VER, DASH_P2SH_VER);
    // Seed height (1518655) == tip (1518655) => credit-pool axis is fresh.
    EXPECT_TRUE(st.make_embedded_work_inputs().viable())
        << "an advanced seed current at the tip must serve";

    // Now the tip moves to 1518656 but a NON-ADVANCING diff arrives (its cbTx is
    // type-0 / carries no newer seed): the seed height stays at 1518655 while the
    // tip is 1518656 => the credit-pool freshness gate fails closed.
    CSimplifiedMNListDiff stale;
    stale.baseBlockHash = raw256(0x55);
    stale.blockHash     = raw256(0x56);
    stale.mnList = {sml_entry(0x42)};
    // cbTx.type == 0 => the seed step is skipped; credit_pool_height stays 1518655.
    m.on_mnlistdiff(stale);
    EXPECT_EQ(st.credit_pool_height(), 1518655) << "a diff without a newer seed must not advance it";
    m.on_new_tip(1518656, raw256(0x56), 0x1b104be3u, 1'700'000'000u,
                 DASH_PUBKEY_VER, DASH_P2SH_VER);
    EXPECT_FALSE(st.make_embedded_work_inputs().viable())
        << "seed height 1518655 behind tip 1518656 must fail closed (independent height check)";
}

// H-6 state-dirty: applying an mnlistdiff (SML advance) fires the re-issue sink,
// and a reorg wipe fires it too (miners move off the orphaned-branch template).
TEST(DashCoinStateMaintainer, SmlApplyAndReorgFireStateDirty) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    int dirty = 0;
    m.set_on_state_dirty([&] { ++dirty; });

    CSimplifiedMNListDiff d1;
    d1.baseBlockHash = uint256::ZERO;
    d1.blockHash     = raw256(0xA0);
    d1.mnList = {sml_entry(0x40)};
    m.on_mnlistdiff(d1);
    EXPECT_EQ(dirty, 1) << "SML advance must re-issue work (freshness gate can now pass)";

    m.on_sml_reorg();
    EXPECT_FALSE(st.have_sml());
    EXPECT_EQ(st.sml_current_hash(), uint256::ZERO);
    EXPECT_EQ(dirty, 2) << "reorg wipe must re-issue work (drop orphaned-branch template)";
}

// ════════════════════════════════════════════════════════════════════════
// soak0804e (creditpool-stale ~3.3% of wall-clock, every decline exactly
// value = threshold-1): between the header tip-advance and the tip BODY parse
// the credit-pool seed is one block behind and the serve gate correctly
// refuses. Ingest was already event-driven end-to-end (inv -> getdata ->
// full_block -> block_connected -> advance_credit_pool_on_block), but the
// RESUME was not: the successful tip-body fold ended in republish() without
// firing the state-dirty sink, so no work re-issue happened until the next
// UNRELATED signal (template request / mnlistdiff / next tip). This KAT pins
// the event-driven resume: the tip body arriving must (a) advance the
// credit-pool seed to the tip, (b) turn the gate viable, and (c) fire
// set_on_state_dirty — with NO template request in between. It also pins that
// the gate still refuses BETWEEN tip-advance and body-parse: the consensus
// gate is untouched (dashd demands exact creditPoolBalance equality,
// bad-cbtx-assetlocked-amount); this is latency work, not gate work.
// ════════════════════════════════════════════════════════════════════════
static BlockType make_cbtx_block(uint32_t height, int64_t credit_pool,
                                 const std::vector<unsigned char>& payee_script) {
    dash::coin::vendor::CCbTx cb;
    cb.nVersion = dash::coin::vendor::CCbTx::VERSION_CLSIG_AND_BALANCE;
    cb.nHeight  = static_cast<int32_t>(height);
    cb.creditPoolBalance = credit_pool;
    BlockType blk;
    blk.m_txs.push_back(make_spend(raw256(0x90), 0, 500000000, height));
    blk.m_txs[0].type = 5;                                    // CbTx
    blk.m_txs[0].extra_payload = dash::coin::encode_cbtx(cb);
    blk.m_txs[0].vout[0].scriptPubKey.m_data = payee_script;  // pays projected MN
    bind_block(blk);
    return blk;
}

TEST(DashCoinStateMaintainer, TipBodyArrivalFiresStateDirtyWithoutTemplateRequest) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    int dirty = 0;
    m.set_on_state_dirty([&] { ++dirty; });

    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    st.set_require_fresh_credit_pool(true);

    // Header tip advance to H: the credit-pool seed (never seeded, -1) is now
    // behind the tip — the gate MUST refuse, and with the creditpool cause.
    // This is the correct refusal that MUST be preserved.
    m.on_new_tip(H, raw256(0xCD), BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER,
                 CURTIME, VERSION);
    auto before = st.describe_decline();
    EXPECT_FALSE(before.viable);
    EXPECT_EQ(before.cause, "creditpool-stale")
        << "between tip-advance and body-parse the gate must refuse on the "
           "credit-pool axis";

    const int dirty_before = dirty;

    // The tip BODY arrives (event-driven ingest): type-5 CbTx coinbase
    // carrying the committed creditPoolBalance at its own nHeight == tip.
    // This is the moment the decline condition ends.
    m.on_block_connected(make_cbtx_block(H, 123'456'789LL, p2pkh_script(0x30)), H);

    // (a) the seed advanced to the tip off the block's OWN committed value...
    EXPECT_EQ(st.credit_pool_height(), static_cast<int32_t>(H));
    EXPECT_EQ(st.credit_pool(), 123'456'789LL);
    // ...(b) the gate now evaluates viable...
    EXPECT_TRUE(st.describe_decline().viable)
        << "credit-pool seed current at the tip must clear the refusal";
    // ...(c) and the state-dirty sink fired — the event-driven resume. No
    // select_work()/template request happened between tip-advance and here.
    EXPECT_GT(dirty, dirty_before)
        << "tip-body fold must re-issue work (bump + notify) instead of "
           "waiting for the next template request / unrelated signal";
}

// Guard against a notify storm during the E2b historical window fill: a body
// fold BELOW the tip advances the seed to a non-tip height — still stale at
// the tip — and must NOT fire the re-issue sink.
TEST(DashCoinStateMaintainer, HistoricalBodyFoldBelowTipDoesNotFireStateDirty) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    int dirty = 0;
    m.set_on_state_dirty([&] { ++dirty; });

    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    st.set_require_fresh_credit_pool(true);
    m.on_new_tip(H, raw256(0xCD), BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER,
                 CURTIME, VERSION);
    const int dirty_before = dirty;

    // A HISTORICAL body (H-3 < tip H) folds in during window fill.
    m.on_block_connected(make_cbtx_block(H - 3, 111'000'000LL, p2pkh_script(0x30)),
                         H - 3);

    EXPECT_EQ(st.credit_pool_height(), static_cast<int32_t>(H - 3));
    EXPECT_FALSE(st.describe_decline().viable)
        << "a seed below the tip must still refuse (the correct refusal is "
           "preserved)";
    EXPECT_EQ(st.describe_decline().cause, "creditpool-stale");
    EXPECT_EQ(dirty, dirty_before)
        << "a historical fold must not fire the re-issue sink (no notify "
           "storm during the bootstrap window fill)";
}

// ── #814 review R1 hardening: stale ZERO-base snapshots must not corrupt the
// tip SML ─────────────────────────────────────────────────────────────────────
//
// A ZERO-base diff REPLACES the whole SML/quorum/credit-pool state. While the
// maintainer HOLDS state, only a genuine FORWARD tip-resync may do that: a
// stale historical full snapshot (a duplicate Phase-L member-sourcing reply
// leaking past the demux, or an unsolicited push from a malicious peer) whose
// cbTx height is at/below the current height — or whose freshness cannot be
// proven at all (no parseable cbTx) — is REJECTED. Cold / post-reorg states
// stay permissive (that IS the resync). This is the second fence behind the
// QuorumMemberSource send-once dedup; either alone stops the 07-xx class of
// tip-SML corruption, together they are defense in depth.
TEST(DashCoinStateMaintainer, StaleZeroBaseSnapshotDoesNotCorruptTipSml) {
    NodeCoinState st;
    CoinStateMaintainer m(st);

    // Tip-current state via a cold snapshot at height 1518700.
    m.on_mnlistdiff(diff_with_seed(uint256::ZERO, raw256(0x54), 1518700,
                                   111'000'000LL, sml_entry(0x40)));
    ASSERT_TRUE(st.have_sml());
    ASSERT_EQ(st.sml_current_hash(), raw256(0x54));
    ASSERT_EQ(st.sml().size(), 1u);

    // THE R1 KAT: a STALE ZERO-base snapshot (height 1518680 < 1518700 — the
    // shape of a historical member-sourcing reply for a quorum work block)
    // arrives while the tip state is ahead. It must NOT replace the tip SML.
    m.on_mnlistdiff(diff_with_seed(uint256::ZERO, raw256(0x99), 1518680,
                                   55'000'000LL, sml_entry(0x77)));
    EXPECT_EQ(st.sml_current_hash(), raw256(0x54))
        << "stale ZERO-base snapshot REPLACED tip state (block-losing R1)";
    ASSERT_EQ(st.sml().size(), 1u);
    EXPECT_EQ(st.sml().mnList[0].proRegTxHash, raw256(0x40))
        << "tip SML content corrupted by the stale snapshot";
    EXPECT_EQ(st.credit_pool_height(), 1518700)
        << "credit-pool seed rolled back by the stale snapshot";

    // Same height (== current) is equally stale — rejected.
    m.on_mnlistdiff(diff_with_seed(uint256::ZERO, raw256(0x9A), 1518700,
                                   66'000'000LL, sml_entry(0x78)));
    EXPECT_EQ(st.sml_current_hash(), raw256(0x54));

    // A ZERO-base snapshot whose freshness CANNOT be proven (no parseable
    // type-5 cbTx) while we hold state: fail closed, reject.
    {
        CSimplifiedMNListDiff unproven;
        unproven.baseBlockHash = uint256::ZERO;
        unproven.blockHash     = raw256(0x9B);
        unproven.mnList = {sml_entry(0x79)};
        m.on_mnlistdiff(unproven);
        EXPECT_EQ(st.sml_current_hash(), raw256(0x54))
            << "unproven ZERO-base snapshot must not replace held state";
    }

    // A genuine FORWARD tip-resync (height 1518701 > 1518700) IS accepted.
    m.on_mnlistdiff(diff_with_seed(uint256::ZERO, raw256(0x55), 1518701,
                                   112'000'000LL, sml_entry(0x41)));
    EXPECT_EQ(st.sml_current_hash(), raw256(0x55))
        << "forward full resync must still be accepted";
    EXPECT_EQ(st.sml().mnList[0].proRegTxHash, raw256(0x41));

    // Post-reorg wipe: the guard resets — a cold resync at ANY height (the new
    // branch may be shorter) is accepted again.
    m.on_sml_reorg();
    ASSERT_EQ(st.sml_current_hash(), uint256::ZERO);
    m.on_mnlistdiff(diff_with_seed(uint256::ZERO, raw256(0x60), 1518650,
                                   90'000'000LL, sml_entry(0x50)));
    EXPECT_EQ(st.sml_current_hash(), raw256(0x60))
        << "post-reorg cold resync must not be blocked by the stale-guard";
}

// ════════════════════════════════════════════════════════════════════════
// SML -> PAYEE validity reconcile wiring (2026-07-30, daemonless payee-desync).
//
// A PoSe ban is CONSENSUS-driven, never a special tx, so apply_block() can
// never observe it. The ONLY authoritative signal is the SML axis's per-entry
// isValid, which advances on every mnlistdiff. Before this wiring the reconciler
// MnStateMachine::sync_validity_from_sml() was DEAD CODE (zero production
// callers), so a banned MN stayed isValid=true on the PAYEE axis forever and
// find_expected_payee() kept projecting the phantom-eligible node -> the
// embedded template's payee disagreed with dashd -> bridge fail-closed. These
// two tests pin that the maintainer now actually CALLS the reconciler on both
// the live-diff path and the seed-join path.
// ════════════════════════════════════════════════════════════════════════

// Call site 1 (on_mnlistdiff): a ban that lands AFTER the payee axis was seeded
// valid must flip the payee entry — the exact live-observed ~h2513489 defect.
TEST(DashCoinStateMaintainer, MnlistdiffBanReconcilesOntoPayeeAxis) {
    NodeCoinState st;
    CoinStateMaintainer m(st);

    // Seed the payee axis valid (mirrors a `protx list valid true` checkpoint,
    // which pre-filters banned nodes — so the ban can only appear post-seed).
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)), H - 2);
    ASSERT_EQ(st.mnstates().size(), 1u);
    ASSERT_TRUE(st.mnstates().entries().at(raw256(0x01)).isValid);
    ASSERT_TRUE(st.mnstates().find_expected_payee().has_value());

    // SML full snapshot @ H-1: same MN (proRegTxHash raw256(0x01)), still valid.
    {
        CSimplifiedMNListEntry e = sml_entry(0x01);   // proRegTxHash = raw256(0x01)
        e.isValid = true;
        m.on_mnlistdiff(diff_with_seed(uint256::ZERO, raw256(0x54), H - 1,
                                       100'000'000LL, e));
    }
    EXPECT_TRUE(st.mnstates().entries().at(raw256(0x01)).isValid)
        << "no flip while the SML agrees the MN is valid";

    // Consensus PoSe ban lands as the NEXT incremental mnlistdiff: isValid=false.
    // No special tx exists for it; the SML axis is the only place it surfaces.
    {
        CSimplifiedMNListEntry e = sml_entry(0x01);
        e.isValid = false;
        m.on_mnlistdiff(diff_with_seed(raw256(0x54), raw256(0x55), H,
                                       100'000'001LL, e));
    }

    // The formerly-dead reconciler must have flipped the payee entry, so the
    // banned MN is no longer projected as the expected payee.
    EXPECT_FALSE(st.mnstates().entries().at(raw256(0x01)).isValid)
        << "SML ban must reconcile onto the payee axis (dead-code wiring)";
    EXPECT_FALSE(st.mnstates().find_expected_payee().has_value())
        << "a banned MN must never be projected as expected payee";
    // Position invariant (trap #2): the reconcile only touched the flipped
    // entry; it never added or removed entries.
    EXPECT_EQ(st.mnstates().size(), 1u);
}

// Call site 2 (on_mn_list_update): an SML ban already applied BEFORE the payee
// axis is (re)seeded must be applied at seed time — the startup/reseed join,
// robust to the seed-arrives-after-SML ordering.
TEST(DashCoinStateMaintainer, SeedReconcileAppliesAlreadyPresentSmlBan) {
    NodeCoinState st;
    CoinStateMaintainer m(st);

    // SML already carries the MN as BANNED, applied while the payee axis is
    // still empty (so on_mnlistdiff's reconcile has nothing to flip yet).
    {
        CSimplifiedMNListEntry e = sml_entry(0x01);
        e.isValid = false;
        m.on_mnlistdiff(diff_with_seed(uint256::ZERO, raw256(0x54), H - 1,
                                       100'000'000LL, e));
    }
    ASSERT_EQ(st.mnstates().size(), 0u);

    // Now the payee axis is seeded valid (a checkpoint taken a moment before the
    // ban still listed the MN valid). The seed-join reconcile must apply the
    // SML's authoritative ban immediately, not wait for the next diff.
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)), H - 1);
    EXPECT_FALSE(st.mnstates().entries().at(raw256(0x01)).isValid)
        << "seed reconcile must apply the already-present SML ban at seed time";
    EXPECT_FALSE(st.mnstates().find_expected_payee().has_value())
        << "a banned MN must never be projected as expected payee";
}

// ════════════════════════════════════════════════════════════════════════
// qc-plan-underivable fix: the mnlistdiff → MineableCommitmentCache tee.
//
// Pre-fix, the cache was fed from EXACTLY one source — the coin-P2P qfcommit
// push subscription — which requires being connected at the instant of the
// inv (measured: a 14 s – 5 m 35 s arrival race after window-open, 7.5% of
// wall-clock declined qc-plan-underivable on a healthy-peer host, total
// cold-start starvation on a churning host). mnlistdiff replies carry the
// COMPLETE CFinalCommitments in tail.newQuorums and the maintainer recorded
// only (llmqType, quorumHash) existence, dropping the crypto payload. These
// tests pin the tee: set_on_new_quorum_commitments hands every ACCEPTED
// diff's newQuorums to the wired consumer, which (as main_dash wires it)
// funnels them through the SAME ingest_ex admission path the push uses.
// ════════════════════════════════════════════════════════════════════════

using dash::coin::MineableCommitmentCache;
using dash::coin::LlmqNetwork;
using dash::coin::LlmqParamsView;
using dash::coin::vendor::CFinalCommitment;

namespace {

// Deterministic per-height pseudo hash (mirrors the dkg_commitments KATs).
std::optional<uint256> qc_fake_hash_at(uint32_t h)
{
    uint256 u;
    std::memset(u.data(), 0xAB, 32);
    std::memcpy(u.data(), &h, 4);
    return u;
}

bool qc_never_mined(uint8_t, const uint256&) { return false; }

// A structurally-admissible REAL commitment for params `p` (all signers set,
// non-null crypto fields) — same shape the dkg_commitments KATs use.
CFinalCommitment qc_real_commitment(const LlmqParamsView& p, const uint256& qh,
                                    int16_t qi, uint8_t seed)
{
    CFinalCommitment c;
    c.nVersion = p.use_rotation
        ? CFinalCommitment::BASIC_BLS_INDEXED_QUORUM_VERSION
        : CFinalCommitment::BASIC_BLS_NON_INDEXED_QUORUM_VERSION;
    c.llmqType    = p.type;
    c.quorumHash  = qh;
    c.quorumIndex = qi;
    c.signers.assign(p.size, true);
    c.validMembers.assign(p.size, true);
    c.quorumPublicKey.fill(seed);
    uint256 vv; std::memset(vv.data(), seed, 32); c.quorumVvecHash = vv;
    c.quorumSig.fill(seed);
    c.membersSig.fill(seed);
    return c;
}

// Serialize a quorum tail carrying only newQuorums (no deletions, no CL sigs)
// in the exact wire shape parse_quorum_tail expects.
std::vector<unsigned char> qc_tail_bytes(const std::vector<CFinalCommitment>& qcs)
{
    ::PackStream s;
    WriteCompactSize(s, 0);                      // deletedQuorums
    WriteCompactSize(s, qcs.size());             // newQuorums
    for (const auto& c : qcs) s << c;
    WriteCompactSize(s, 0);                      // quorumsCLSigs
    auto sp = s.get_span();
    return std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
}

} // namespace

// THE headline: a commitment that arrives ONLY via mnlistdiff — ZERO qfcommit
// push messages — must make verified_for serve it, i.e. the daemonless qc plan
// becomes derivable over request/response alone. Verified to FAIL on pre-fix
// master: set_on_new_quorum_commitments does not exist there (this TU does not
// compile), and the behavioural core is impossible by construction — the only
// production feed into MineableCommitmentCache was the push subscription
// (main_dash.cpp new_qfcommit), so after on_mnlistdiff the cache is empty and
// daemonless_qc_commitments returns nullopt = the qc-plan-underivable decline.
TEST(DashCoinStateMaintainer, CommitmentOnlyViaMnlistdiffMakesQcPlanDerivable) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    MineableCommitmentCache cache;

    // Wire the tee exactly as main_dash does: the SAME admission path
    // (ingest_ex, testnet enabled-set) the qfcommit push subscription uses.
    m.set_on_new_quorum_commitments(
        [&cache](const std::vector<CFinalCommitment>& qcs) {
            for (const auto& c : qcs)
                cache.ingest_ex(LlmqNetwork::Testnet, c);
        });

    // 1900812 is phase 12 of the 24-cycle, above the testnet serve floor:
    // the mandatory set is one slot each for types 1 / 4 / 6, all at the
    // cycle base 1900800.
    const uint32_t next_h = 1'900'812u;
    const uint256  qh     = *qc_fake_hash_at(1'900'800u);
    const std::vector<CFinalCommitment> qcs{
        qc_real_commitment(dash::coin::kLlmq50_60,  qh, 0, 0x11),
        qc_real_commitment(dash::coin::kLlmq100_67, qh, 0, 0x22),
        qc_real_commitment(dash::coin::kLlmq25_67,  qh, 0, 0x33)};

    CSimplifiedMNListDiff d = diff_with_seed(uint256::ZERO, raw256(0xA0),
                                             1'900'811, 100'000'000LL,
                                             sml_entry(0x40));
    d.quorum_tail = qc_tail_bytes(qcs);
    m.on_mnlistdiff(d);

    // The cache holds all three commitments off the diff alone.
    EXPECT_EQ(cache.size(), 3u);
    EXPECT_TRUE(cache.has_commitment(1, qh));
    EXPECT_TRUE(cache.has_commitment(4, qh));
    EXPECT_TRUE(cache.has_commitment(6, qh));

    // With the BLS hook passing (stub — the hook is the SAME seam the push
    // path serves through), verified_for yields them and the plan for the
    // window height is derivable. has_mined is deliberately `never`: this is
    // the posture where the slots are still REQUIRED (pre-mine race /
    // reorg-wiped QuorumManager), i.e. exactly when the cache must serve.
    cache.set_bls_verify_fn([](const CFinalCommitment&) { return true; });
    auto plan = dash::coin::daemonless_qc_commitments(
        LlmqNetwork::Testnet, next_h, qc_fake_hash_at, qc_never_mined, &cache);
    ASSERT_TRUE(plan.has_value())
        << "commitments sourced ONLY via mnlistdiff must derive the qc plan";
    ASSERT_EQ(plan->size(), 3u);
    for (const auto& c : *plan)
        EXPECT_GT(c.CountSigners(), 0) << "a REAL commitment must be served, not null";
}

// The tee fires ONLY for an ACCEPTED diff: every reject/heal path
// (base-continuity, stale-ZERO-base R1, malformed-tail H-1) must not hand
// commitments to the consumer — a refused diff's payload is untrusted.
TEST(DashCoinStateMaintainer, QuorumCommitmentTeeFiresOnlyForAcceptedDiffs) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    size_t batches = 0, commitments = 0;
    m.set_on_new_quorum_commitments(
        [&](const std::vector<CFinalCommitment>& qcs) {
            ++batches;
            commitments += qcs.size();
        });

    const uint256 qh = *qc_fake_hash_at(1'900'800u);

    // 1) Accepted cold full snapshot → tee fires once with one commitment.
    CSimplifiedMNListDiff d1 = diff_with_seed(uint256::ZERO, raw256(0xA0),
                                              1'900'811, 100'000'000LL,
                                              sml_entry(0x40));
    d1.quorum_tail = qc_tail_bytes({qc_real_commitment(dash::coin::kLlmq50_60,
                                                       qh, 0, 0x11)});
    m.on_mnlistdiff(d1);
    EXPECT_EQ(batches, 1u);
    EXPECT_EQ(commitments, 1u);

    // 2) Base-continuity reject (base != SML-current) → NO tee.
    CSimplifiedMNListDiff bad = diff_with_seed(raw256(0xB0), raw256(0xC0),
                                               1'900'812, 100'000'001LL,
                                               sml_entry(0x41));
    bad.quorum_tail = qc_tail_bytes({qc_real_commitment(dash::coin::kLlmq100_67,
                                                        qh, 0, 0x22)});
    m.on_mnlistdiff(bad);
    EXPECT_EQ(batches, 1u) << "a base-continuity-rejected diff must not tee";

    // 3) Stale ZERO-base snapshot (R1: cb height <= current) → NO tee.
    CSimplifiedMNListDiff stale = diff_with_seed(uint256::ZERO, raw256(0xD0),
                                                 1'900'810, 100'000'002LL,
                                                 sml_entry(0x42));
    stale.quorum_tail = qc_tail_bytes({qc_real_commitment(dash::coin::kLlmq25_67,
                                                          qh, 0, 0x33)});
    m.on_mnlistdiff(stale);
    EXPECT_EQ(batches, 1u) << "a stale-snapshot-rejected diff must not tee";

    // 4) Malformed tail (H-1 heal path) → NO tee.
    CSimplifiedMNListDiff mal = diff_with_seed(raw256(0xA0), raw256(0xE0),
                                               1'900'812, 100'000'003LL,
                                               sml_entry(0x43));
    mal.quorum_tail = {0x01};   // deletedQuorums count=1 with no body
    m.on_mnlistdiff(mal);
    EXPECT_EQ(batches, 1u) << "a malformed-tail diff must not tee";
    EXPECT_EQ(commitments, 1u);
}

// A tampered commitment arriving via mnlistdiff must be rejected EXACTLY as
// the same commitment arriving as a qfcommit push — same admission verdicts,
// nothing cached; and a structurally-admissible copy whose BLS signature the
// verifier refuses is withheld by verified_for regardless of transport.
TEST(DashCoinStateMaintainer, TamperedCommitmentViaMnlistdiffRejectedAsPush) {
    using Adm = MineableCommitmentCache::Admission;
    const uint256 qh = *qc_fake_hash_at(1'900'800u);

    // Tampered shapes: >=threshold-but-<minSize signers (the block-losing
    // colluding shape) and null crypto fields.
    auto below_min = qc_real_commitment(dash::coin::kLlmq50_60, qh, 0, 0x11);
    below_min.signers.assign(50, false);
    for (int i = 0; i < 35; ++i) below_min.signers[static_cast<size_t>(i)] = true;
    auto null_crypto = qc_real_commitment(dash::coin::kLlmq50_60, qh, 0, 0x11);
    null_crypto.quorumSig.fill(0);
    auto good = qc_real_commitment(dash::coin::kLlmq50_60, qh, 0, 0x11);

    // Push-path verdicts (the reference: direct ingest_ex, as the qfcommit
    // subscription calls it).
    MineableCommitmentCache push_cache;
    const auto push_v1 = push_cache.ingest_ex(LlmqNetwork::Testnet, below_min);
    const auto push_v2 = push_cache.ingest_ex(LlmqNetwork::Testnet, null_crypto);
    EXPECT_EQ(push_v1, Adm::SignersBelowMin);
    EXPECT_EQ(push_v2, Adm::NullCryptoFields);
    EXPECT_EQ(push_cache.size(), 0u);

    // mnlistdiff-path verdicts through the tee: MUST be identical.
    NodeCoinState st;
    CoinStateMaintainer m(st);
    MineableCommitmentCache cache;
    std::vector<Adm> seen;
    m.set_on_new_quorum_commitments(
        [&](const std::vector<CFinalCommitment>& qcs) {
            for (const auto& c : qcs)
                seen.push_back(cache.ingest_ex(LlmqNetwork::Testnet, c));
        });
    CSimplifiedMNListDiff d = diff_with_seed(uint256::ZERO, raw256(0xA0),
                                             1'900'811, 100'000'000LL,
                                             sml_entry(0x40));
    d.quorum_tail = qc_tail_bytes({below_min, null_crypto, good});
    m.on_mnlistdiff(d);

    ASSERT_EQ(seen.size(), 3u);
    EXPECT_EQ(seen[0], push_v1) << "mnlistdiff admission must equal push admission";
    EXPECT_EQ(seen[1], push_v2) << "mnlistdiff admission must equal push admission";
    EXPECT_EQ(seen[2], Adm::Accepted);
    EXPECT_EQ(cache.size(), 1u) << "only the untampered commitment may be cached";

    // BLS-invalid (structurally fine, wrong signature): the SAME verifier
    // hook gates both transports — verified_for withholds it.
    cache.set_bls_verify_fn(
        [](const CFinalCommitment& c) { return c.quorumSig[0] == 0x11; });
    ASSERT_TRUE(cache.verified_for(1, qh).has_value());
    const uint256 qh2 = *qc_fake_hash_at(1'900'776u);   // previous cycle base
    auto sig_bad = qc_real_commitment(dash::coin::kLlmq50_60, qh2, 0, 0x99);
    CSimplifiedMNListDiff d2 = diff_with_seed(raw256(0xA0), raw256(0xB0),
                                              1'900'812, 100'000'001LL,
                                              sml_entry(0x41));
    d2.quorum_tail = qc_tail_bytes({sig_bad});
    m.on_mnlistdiff(d2);
    EXPECT_TRUE(cache.has_commitment(1, qh2))
        << "structural admission cannot detect a bad signature";
    EXPECT_FALSE(cache.verified_for(1, qh2).has_value())
        << "a BLS-refused commitment must be withheld whatever its transport";
}

// Duplicate arrival across transports — push then mnlistdiff AND mnlistdiff
// then push — is a no-op: keep-best-by-CountSigners holds the first copy, the
// cache never grows, and a weaker (fewer-signers) later copy NEVER downgrades
// a served entry.
TEST(DashCoinStateMaintainer, DuplicateAcrossTransportsIsNoOpNeverDowngrades) {
    using Adm = MineableCommitmentCache::Admission;
    const uint256 qh = *qc_fake_hash_at(1'900'800u);
    auto good = qc_real_commitment(dash::coin::kLlmq50_60, qh, 0, 0x11);

    // ── push first, mnlistdiff second ────────────────────────────────────
    {
        NodeCoinState st;
        CoinStateMaintainer m(st);
        MineableCommitmentCache cache;
        std::vector<Adm> seen;
        m.set_on_new_quorum_commitments(
            [&](const std::vector<CFinalCommitment>& qcs) {
                for (const auto& c : qcs)
                    seen.push_back(cache.ingest_ex(LlmqNetwork::Testnet, c));
            });
        ASSERT_EQ(cache.ingest_ex(LlmqNetwork::Testnet, good), Adm::Accepted);

        CSimplifiedMNListDiff d = diff_with_seed(uint256::ZERO, raw256(0xA0),
                                                 1'900'811, 100'000'000LL,
                                                 sml_entry(0x40));
        d.quorum_tail = qc_tail_bytes({good});
        m.on_mnlistdiff(d);
        ASSERT_EQ(seen.size(), 1u);
        EXPECT_EQ(seen[0], Adm::NotBetterThanCached) << "duplicate must be a no-op";
        EXPECT_EQ(cache.size(), 1u);

        cache.set_bls_verify_fn([](const CFinalCommitment&) { return true; });
        auto served = cache.verified_for(1, qh);
        ASSERT_TRUE(served.has_value());
        EXPECT_EQ(served->CountSigners(), 50);

        // A WEAKER copy (45 of 50 signers, still >= minSize 40) arriving on a
        // later incremental must not replace the held 50-signer copy.
        auto weaker = good;
        weaker.signers.assign(50, false);
        for (int i = 0; i < 45; ++i) weaker.signers[static_cast<size_t>(i)] = true;
        CSimplifiedMNListDiff d2 = diff_with_seed(raw256(0xA0), raw256(0xB0),
                                                  1'900'812, 100'000'001LL,
                                                  sml_entry(0x41));
        d2.quorum_tail = qc_tail_bytes({weaker});
        m.on_mnlistdiff(d2);
        ASSERT_EQ(seen.size(), 2u);
        EXPECT_EQ(seen[1], Adm::NotBetterThanCached);
        auto still = cache.verified_for(1, qh);
        ASSERT_TRUE(still.has_value());
        EXPECT_EQ(still->CountSigners(), 50) << "a verified entry must never downgrade";
    }

    // ── mnlistdiff first, push second ────────────────────────────────────
    {
        NodeCoinState st;
        CoinStateMaintainer m(st);
        MineableCommitmentCache cache;
        std::vector<Adm> seen;
        m.set_on_new_quorum_commitments(
            [&](const std::vector<CFinalCommitment>& qcs) {
                for (const auto& c : qcs)
                    seen.push_back(cache.ingest_ex(LlmqNetwork::Testnet, c));
            });
        CSimplifiedMNListDiff d = diff_with_seed(uint256::ZERO, raw256(0xA0),
                                                 1'900'811, 100'000'000LL,
                                                 sml_entry(0x40));
        d.quorum_tail = qc_tail_bytes({good});
        m.on_mnlistdiff(d);
        ASSERT_EQ(seen.size(), 1u);
        EXPECT_EQ(seen[0], Adm::Accepted);

        // The SAME commitment now arrives as a push: no-op, no growth.
        EXPECT_EQ(cache.ingest_ex(LlmqNetwork::Testnet, good),
                  Adm::NotBetterThanCached);
        EXPECT_EQ(cache.size(), 1u);
        cache.set_bls_verify_fn([](const CFinalCommitment&) { return true; });
        auto served = cache.verified_for(1, qh);
        ASSERT_TRUE(served.has_value());
        EXPECT_EQ(served->CountSigners(), 50);
    }
}

// ════════════════════════════════════════════════════════════════════════
// BODY-FIRST SERVE TIP (operator direction off soak0804e; the follow-up the
// #1089 thread scoped). The serve tip — m_prev_height, the template height
// and the threshold of every freshness gate — advances ONLY when the tip
// block's inputs have been parsed (tip body fold, or the tip-targeted
// mnlistdiff cbTx), atomically with the credit-pool advance. The header tip
// keeps advancing on headers exactly as before and stays visible to its
// consumers (stale-work invalidation / job rebuild / won-block detection are
// wired off the header chain in main_dash and are untouched).
//
// FAILS-ON-MASTER: on header-first master m_prev_height is written directly
// in on_new_tip — the serve height exceeds the parsed-body height by design
// for the whole body window, so the invariant assertions below cannot hold
// there. (Default-off legacy mode is pinned separately below.)
// ════════════════════════════════════════════════════════════════════════

#include <impl/dash/crypto/hash_x11.hpp>


// Accrual-consistent balance for a CONTIGUOUS next block: the independent
// credit-pool advance verifies computed == from-wire (prev + platform reward,
// no asset locks/unlocks in these fabricated blocks); an inconsistent value
// trips the ACCRUAL DRIFT fail-closed path and blocks the seed advance.
static int64_t next_balance(const NodeCoinState& st, int64_t prev_balance,
                            uint32_t height) {
    return prev_balance
           + dash::coin::compute_dash_platform_reward_post_v20_mn_rr(
                 height, st.mn_rr_height());
}

static uint256 block_hash_of(const BlockType& b) {
    auto packed = ::pack(static_cast<const dash::coin::BlockHeaderType&>(b));
    return dash::crypto::hash_x11(packed.get_span());
}

// THE CENTREPIECE: "serve height never exceeds the height whose body has
// been parsed." Header arrival must not advance the serve tip; the body fold
// must — atomically with the credit-pool advance.
TEST(DashCoinStateMaintainer, BodyFirstServeTipNeverExceedsParsedBodyHeight) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.set_body_first_serve_tip(true);
    st.set_require_fresh_credit_pool(true);
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));

    // ── Establish the serve tip at H-1: header first, then its body. ──
    auto b1 = make_cbtx_block(H - 1, 111'000'000LL, p2pkh_script(0x30));
    m.on_new_tip(H - 1, block_hash_of(b1), BITS, MTP,
                 DASH_PUBKEY_VER, DASH_P2SH_VER, CURTIME, VERSION);
    // Header alone: the serve tip must NOT exist yet (cold start).
    EXPECT_TRUE(m.tip_body_pending());
    EXPECT_EQ(m.header_tip_height(), H - 1);
    EXPECT_EQ(m.serve_tip_height(), 0u)
        << "INVARIANT: no body parsed yet, no serve tip may exist";
    EXPECT_FALSE(m.live());
    // The refusal names itself: tip-body-pending, not a header-sync fault.
    EXPECT_EQ(st.describe_decline().cause, "tip-body-pending");

    m.on_block_connected(b1, H - 1);
    EXPECT_FALSE(m.tip_body_pending());
    EXPECT_EQ(m.serve_tip_height(), H - 1) << "body parsed => serve tip promoted";
    ASSERT_TRUE(m.live());
    {
        WorkSelection sel = st.select_work([]() { return DashWorkData{}; });
        EXPECT_EQ(sel.source, WorkSource::Embedded);
        EXPECT_EQ(sel.work.m_height, H) << "serving next-height H over parsed H-1";
    }

    // ── Header H arrives, body DELAYED. ──
    const int64_t bal2 = next_balance(st, 111'000'000LL, H);
    auto b2 = make_cbtx_block(H, bal2, p2pkh_script(0x30));
    m.on_new_tip(H, block_hash_of(b2), BITS, MTP,
                 DASH_PUBKEY_VER, DASH_P2SH_VER, CURTIME, VERSION);
    // Header-tip consumers see the new header immediately...
    EXPECT_EQ(m.header_tip_height(), H);
    EXPECT_TRUE(m.tip_body_pending());
    // ...but the INVARIANT holds: serve height stays at the parsed height.
    EXPECT_EQ(m.serve_tip_height(), H - 1)
        << "INVARIANT VIOLATED: serve height exceeds the height whose body "
           "has been parsed (this is exactly header-first master's behaviour)";
    // The serve gates hold VIABLE at the old height — the body window is a
    // normal transient (every pool serves prev-tip work during propagation),
    // NOT an error/decline state.
    EXPECT_TRUE(st.describe_decline().viable)
        << "tip-body-pending must not be treated as an error state";
    {
        WorkSelection sel = st.select_work([]() { return DashWorkData{}; });
        EXPECT_EQ(sel.source, WorkSource::Embedded);
        EXPECT_EQ(sel.work.m_height, H) << "still building on parsed H-1";
    }

    // ── Body H arrives: serve tip + credit pool advance ATOMICALLY. ──
    m.on_block_connected(b2, H);
    EXPECT_EQ(m.serve_tip_height(), H);
    EXPECT_EQ(st.credit_pool_height(), static_cast<int32_t>(H));
    EXPECT_EQ(st.credit_pool(), bal2);
    EXPECT_TRUE(st.describe_decline().viable)
        << "no creditpool-stale window may exist after the atomic advance";
    {
        WorkSelection sel = st.select_work([]() { return DashWorkData{}; });
        EXPECT_EQ(sel.work.m_height, H + 1);
    }
}

// ════════════════════════════════════════════════════════════════════════
// PR-5: CREDIT-POOL PUBLICATION HEIGHT
//
// The test above asserts "no creditpool-stale window may exist after the
// atomic advance" and passes only because it never exercises the SML axis:
// its sml_current_hash is the cold ZERO sentinel, which the fourth-axis
// carve-out (coin_state_maintainer.hpp:1820-1822) deliberately lets through,
// so the body fold always promotes and the pool write always lands AT the
// serve tip.
//
// The steady state is different: the SML is current at the serve tip H-1, and
// it advances only on its own getmnlistd round trip. Between the tip body
// fold and that round trip, promotion is HELD (by design — promoting first
// would trade a creditpool-stale window for a dmn-stale one) while
// advance_credit_pool_on_block writes the pool at the BODY height H. The pool
// is then ONE BLOCK AHEAD of the serve tip — which is precisely what the soak
// measured: all 48 creditpool-stale episodes carried value = threshold + 1,
// exactly, never behind.
//
// The scenario below is the one the maintainer actually runs; the two tests
// differ ONLY in the publication-height flag.
// ════════════════════════════════════════════════════════════════════════
namespace {
// Drives: serve tip established at H-1 (header+body), SML current AT H-1,
// then header H + body H with the SML still at H-1 (promotion held).
// Returns the H-block so the caller can address it.
struct HeldPromotionScenario {
    BlockType b1;
    BlockType b2;
    uint256   h1;
    uint256   h2;
    int64_t   bal1{111'000'000LL};
    int64_t   bal2{0};
};
HeldPromotionScenario drive_held_promotion(NodeCoinState& st,
                                           CoinStateMaintainer& m) {
    HeldPromotionScenario s;
    m.set_body_first_serve_tip(true);
    st.set_require_fresh_credit_pool(true);
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));

    s.b1 = make_cbtx_block(H - 1, s.bal1, p2pkh_script(0x30));
    s.h1 = block_hash_of(s.b1);
    m.on_new_tip(H - 1, s.h1, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER,
                 CURTIME, VERSION);
    m.on_block_connected(s.b1, H - 1);
    EXPECT_EQ(m.serve_tip_height(), H - 1);

    // STEADY STATE (what the test above never sets): the SML is current AT
    // the serve tip. A live node is here between every pair of blocks.
    st.set_sml_current_hash(s.h1);

    s.bal2 = next_balance(st, s.bal1, H);
    s.b2 = make_cbtx_block(H, s.bal2, p2pkh_script(0x30));
    s.h2 = block_hash_of(s.b2);
    m.on_new_tip(H, s.h2, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER,
                 CURTIME, VERSION);
    // The tip BODY lands before the tip-targeted mnlistdiff (the ordinary
    // order: the body is pushed, the SML must be asked for).
    m.on_block_connected(s.b2, H);
    return s;
}
}  // namespace

// CHARACTERIZATION of the DEFAULT (flag off) — this is master's behaviour and
// must stay master's behaviour until an operator arms the flag. It documents
// the defect rather than asserting it is desirable.
TEST(DashCoinStateMaintainer, CreditPoolPublishesAtBodyHeightByDefault) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    ASSERT_FALSE(m.credit_pool_publish_at_serve_tip()) << "money path: OFF by default";
    auto s = drive_held_promotion(st, m);

    // Promotion is held on the SML axis — correct, and unchanged by PR-5.
    EXPECT_EQ(m.serve_tip_height(), H - 1);
    EXPECT_TRUE(m.tip_body_pending());
    // ...but the pool was published at the BODY height: ONE BLOCK AHEAD.
    EXPECT_EQ(st.credit_pool_height(), static_cast<int32_t>(H));
    EXPECT_EQ(st.credit_pool(), s.bal2);
    auto d = st.describe_decline();
    EXPECT_FALSE(d.viable);
    EXPECT_EQ(d.cause, "creditpool-stale");
    EXPECT_EQ(d.value, std::to_string(H)) << "value = threshold + 1, always";
    EXPECT_EQ(m.held_credit_pool_height(), -1) << "nothing is held when the flag is off";
}

// THE FIX. Same scenario, publication height armed: the pool is published AT
// THE SERVE TIP, so no creditpool-stale window can exist while promotion is
// held — and, the reason this is a correctness fix and not a gate relaxation,
// the value the template would build from is the pool at the block it is
// building ON (dashd: GetCreditPool(pindexPrev), creditpool.cpp:224 / :325-333
// / specialtxman.cpp:565). Publishing H while building on H-1 would commit the
// wrong creditPoolBalance; today only the refusal prevents that.
TEST(DashCoinStateMaintainer, CreditPoolPublishesAtServeTipWhilePromotionHeld) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.set_credit_pool_publish_at_serve_tip(true);
    auto s = drive_held_promotion(st, m);

    // Promotion still held on the SML axis — PR-5 does NOT relax the conjunct.
    EXPECT_EQ(m.serve_tip_height(), H - 1);
    EXPECT_TRUE(m.tip_body_pending());

    // The published pool is the pool AT THE SERVE TIP.
    EXPECT_EQ(st.credit_pool_height(), static_cast<int32_t>(H - 1))
        << "publication height must follow the SERVE tip, not the body height";
    EXPECT_EQ(st.credit_pool(), s.bal1)
        << "the VALUE too: a template building on H-1 must commit the pool at H-1";
    // The derived-but-unpublished pool says its own name.
    EXPECT_EQ(m.held_credit_pool_height(), static_cast<int32_t>(H));

    // No creditpool-stale window exists — the state it needs is unreachable.
    auto d = st.describe_decline();
    EXPECT_TRUE(d.viable)
        << "creditpool-stale while promotion is held (cause=" << d.cause
        << " value=" << d.value << " threshold=" << d.threshold << ")";
    EXPECT_NE(d.cause, "creditpool-stale");
    {
        WorkSelection sel = st.select_work([]() { return DashWorkData{}; });
        EXPECT_EQ(sel.source, WorkSource::Embedded);
        EXPECT_EQ(sel.work.m_height, H) << "keeps serving H-1-based work, as designed";
    }

    // ── The SML catches up: promotion + publication are ONE step. ──
    // In production the SML advances inside on_mnlistdiff, which calls
    // maybe_promote_pending_tip itself (coin_state_maintainer.hpp:793); here
    // the currency is set directly and the next maintainer event drives the
    // promotion, which is the same code path.
    st.set_sml_current_hash(s.h2);
    m.on_new_tip(H, s.h2, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER,
                 CURTIME, VERSION);
    EXPECT_EQ(m.serve_tip_height(), H);
    EXPECT_EQ(st.credit_pool_height(), static_cast<int32_t>(H));
    EXPECT_EQ(st.credit_pool(), s.bal2);
    EXPECT_EQ(m.held_credit_pool_height(), -1) << "nothing left held after publication";
    EXPECT_TRUE(st.describe_decline().viable);
    {
        WorkSelection sel = st.select_work([]() { return DashWorkData{}; });
        EXPECT_EQ(sel.work.m_height, H + 1);
    }
}

// ── The no-serve-tip carve-out (`&& m_have_tip`, publish_credit_pool_at) ──
// The carve-out has ONE observable effect, and it is an INTERMEDIATE state:
// with no serve tip the derived pool goes to the PUBLISHED slot instead of the
// pending slot. Assert exactly that, and nothing more.
//
// The earlier version of this test asserted only the settled state after a
// cold fold that promotes in the same step — and could not fail, because a
// pending slot is drained by that very promotion (credit_pool_derived_at
// matches it, publish_held_credit_pool_at publishes it) so the settled state
// is byte-identical with or without the carve-out. Deleting `&& m_have_tip`
// left the whole suite green. The scenario below fixes that by holding
// promotion on the SML axis, so no promotion can launder the difference away:
// the SML currency is set to a NON-cold hash that does not name the incoming
// tip, which the fourth-axis ZERO carve-out therefore does not wave through.
//
// NOTE what is NOT claimed: this pins the carve-out's BEHAVIOUR, not a
// deadlock. No deadlock was demonstrated for the cold-start path — every
// pending slot reachable there is drained by the next promotion — so the
// former "pins the carve-out against a future tightening into a deadlock"
// claim is retracted.
TEST(DashCoinStateMaintainer, ColdStartPublishesImmediatelyWithPublicationHeightOn) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.set_body_first_serve_tip(true);
    m.set_credit_pool_publish_at_serve_tip(true);
    st.set_require_fresh_credit_pool(true);
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    // Non-cold SML currency naming SOME OTHER block => the fourth axis holds
    // promotion through the fold below.
    st.set_sml_current_hash(raw256(0xA7));

    auto b1 = make_cbtx_block(H - 1, 111'000'000LL, p2pkh_script(0x30));
    const uint256 h1 = block_hash_of(b1);
    m.on_new_tip(H - 1, h1, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER,
                 CURTIME, VERSION);
    ASSERT_EQ(m.serve_tip_height(), 0u) << "no serve tip yet";
    ASSERT_FALSE(m.have_tip()) << "the carve-out's precondition";
    m.on_block_connected(b1, H - 1);

    // Promotion is genuinely held, so nothing here can drain a pending slot.
    ASSERT_EQ(m.serve_tip_height(), 0u) << "SML axis holds promotion";
    ASSERT_TRUE(m.tip_body_pending());

    // THE CARVE-OUT, and the only thing it does: with no serve tip the pool is
    // PUBLISHED, not parked in a slot only a promotion can drain.
    EXPECT_EQ(st.credit_pool_height(), static_cast<int32_t>(H - 1))
        << "no serve tip => publish immediately, do not hold";
    EXPECT_EQ(st.credit_pool(), 111'000'000LL);
    EXPECT_EQ(m.held_credit_pool_height(), -1) << "nothing may be held here";

    // Settled state (identical either way — asserted for completeness, NOT as
    // the discriminating assertion): the SML lands and the tip promotes.
    st.set_sml_current_hash(h1);
    m.on_new_tip(H - 1, h1, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER,
                 CURTIME, VERSION);
    EXPECT_EQ(m.serve_tip_height(), H - 1) << "cold start must still promote";
    EXPECT_EQ(st.credit_pool_height(), static_cast<int32_t>(H - 1));
    EXPECT_TRUE(m.live());
}

// ════════════════════════════════════════════════════════════════════════
// ROLLBACK: discard_held_credit_pool() on both call sites.
//
// The pending slot answers credit_pool_derived_at() — the promotion
// precondition — so a slot that SURVIVES a rollback is not inert: the next
// promotion attempt at that same block hash/height finds the pool "derived",
// promotes, and publish_held_credit_pool_at writes the ORPHANED branch's
// balance into the published slot. On the cold-wipe path that silently
// defeats the deliberate fail-closed write of (0, ZERO, -1).
// ════════════════════════════════════════════════════════════════════════

// COLD WIPE (on_sml_reorg, no retained body on the new branch).
TEST(DashCoinStateMaintainer, ColdWipeDiscardsHeldPoolSoTheOrphanCannotBeRepublished) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.set_credit_pool_publish_at_serve_tip(true);
    auto s = drive_held_promotion(st, m);
    ASSERT_EQ(m.held_credit_pool_height(), static_cast<int32_t>(H))
        << "precondition: a pool derived at H is HELD above the serve tip";
    ASSERT_EQ(st.credit_pool_height(), static_cast<int32_t>(H - 1));

    // Reorg with the block buffer unwired => the cold wipe path, which
    // deliberately writes (0, ZERO, -1) to fail closed on this axis.
    m.on_sml_reorg();
    EXPECT_EQ(st.credit_pool_height(), -1) << "cold wipe must fail closed";
    EXPECT_EQ(m.held_credit_pool_height(), -1)
        << "a pool derived on the orphaned branch must be dropped with the seed";

    // THE MONEY PATH. The orphaned block is re-announced as the header tip
    // (reorg-back, or a competing announcement). If the slot survived, it
    // satisfies credit_pool_derived_at(h2, H) and promotion republishes the
    // orphan's balance over the fail-closed -1 — and serves off it.
    m.on_new_tip(H, s.h2, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER,
                 CURTIME, VERSION);
    EXPECT_EQ(st.credit_pool_height(), -1)
        << "promotion must not resurrect the orphaned branch's credit pool";
    EXPECT_NE(st.credit_pool(), s.bal2)
        << "the orphaned balance must never reach the published slot";
    EXPECT_EQ(m.serve_tip_height(), H - 1)
        << "no serve tip may be promoted off an orphan-derived pool";
}

// REORG UNDO from the retained fork-point body (the other call site): the pool
// is rolled back to the fork point, and the held pool — derived ABOVE it, on
// the branch that just went away — must go with it.
TEST(DashCoinStateMaintainer, ReorgUndoDiscardsHeldPoolDerivedAboveTheForkPoint) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.set_full_block_buffer(true);
    m.set_credit_pool_publish_at_serve_tip(true);
    auto s = drive_held_promotion(st, m);
    ASSERT_EQ(m.held_credit_pool_height(), static_cast<int32_t>(H));
    ASSERT_EQ(m.block_buffer_depth(), 2u);

    // New branch: H-1 is still ours (fork point), H is a different block.
    m.set_chain_hash_at_height_fn(
        [&](uint32_t h) -> std::optional<uint256> {
            if (h == H - 1) return s.h1;
            if (h == H) return raw256(0xEE);
            return std::nullopt;
        });
    m.on_sml_reorg();
    EXPECT_EQ(st.credit_pool_height(), static_cast<int32_t>(H - 1))
        << "rolled back to the fork point from the retained body";
    EXPECT_EQ(st.credit_pool(), s.bal1);
    EXPECT_EQ(m.held_credit_pool_height(), -1)
        << "the held pool was derived above the fork point, on the dead branch";

    m.on_new_tip(H, s.h2, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER,
                 CURTIME, VERSION);
    EXPECT_EQ(st.credit_pool_height(), static_cast<int32_t>(H - 1))
        << "promotion must not resurrect the orphaned branch's credit pool";
    EXPECT_EQ(st.credit_pool(), s.bal1);
    EXPECT_EQ(m.serve_tip_height(), H - 1);
}

// Legacy default pinned: with body-first NOT enabled, on_new_tip promotes the
// serve tip immediately (header-first) — byte-identical pre-split behaviour
// for every existing posture (KATs, dashd-RPC/ZMQ tip feed with no body feed).
TEST(DashCoinStateMaintainer, HeaderFirstDefaultPromotesServeTipOnHeader) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    m.on_new_tip(H, raw256(0xCD), BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER,
                 CURTIME, VERSION);
    EXPECT_EQ(m.serve_tip_height(), H);
    EXPECT_FALSE(m.tip_body_pending());
    EXPECT_TRUE(m.live());
}

// The body fold's promotion must fire the state-dirty re-issue sink (builds
// on #1089's event-driven resume) — serve tip + credit pool advance, gate
// resumes, with NO template request in between.
TEST(DashCoinStateMaintainer, BodyFirstPromotionFiresStateDirtyWithoutTemplateRequest) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.set_body_first_serve_tip(true);
    st.set_require_fresh_credit_pool(true);
    int dirty = 0;
    m.set_on_state_dirty([&] { ++dirty; });
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));

    auto b1 = make_cbtx_block(H - 1, 111'000'000LL, p2pkh_script(0x30));
    m.on_new_tip(H - 1, block_hash_of(b1), BITS, MTP,
                 DASH_PUBKEY_VER, DASH_P2SH_VER, CURTIME, VERSION);
    m.on_block_connected(b1, H - 1);
    ASSERT_TRUE(m.live());

    auto b2 = make_cbtx_block(H, next_balance(st, 111'000'000LL, H),
                              p2pkh_script(0x30));
    m.on_new_tip(H, block_hash_of(b2), BITS, MTP,
                 DASH_PUBKEY_VER, DASH_P2SH_VER, CURTIME, VERSION);
    const int dirty_before = dirty;
    // No select_work()/template request happens between here and the fold.
    m.on_block_connected(b2, H);
    EXPECT_EQ(m.serve_tip_height(), H);
    EXPECT_GT(dirty, dirty_before)
        << "promotion must re-issue work (bump + notify) event-driven";
}

// Cold-start path: the initial header sync ends at a tip whose body is never
// inv'd — the tip-targeted mnlistdiff's authoritative cbTx carries the same
// block inputs and must promote the pending serve tip.
TEST(DashCoinStateMaintainer, BodyFirstMnlistdiffAtTipPromotesPendingServeTip) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.set_body_first_serve_tip(true);
    st.set_require_fresh_credit_pool(true);
    // Payee axis current at the tip via the snapshot's as_of height.
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)), /*as_of_height=*/H);

    const uint256 tip_hash = raw256(0x54);
    m.on_new_tip(H, tip_hash, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER,
                 CURTIME, VERSION);
    EXPECT_TRUE(m.tip_body_pending());
    EXPECT_EQ(m.serve_tip_height(), 0u);

    m.on_mnlistdiff(diff_with_seed(uint256::ZERO, tip_hash, H,
                                   111'000'000LL, sml_entry(0x40)));
    EXPECT_FALSE(m.tip_body_pending());
    EXPECT_EQ(m.serve_tip_height(), H)
        << "a tip-targeted diff cbTx is a body-equivalent input advance";
    EXPECT_TRUE(m.live());
}

// A diff at the tip must NOT promote while the payee cursor lags the tip —
// that would trade the removed creditpool-stale window for an identical
// payee-stale one.
TEST(DashCoinStateMaintainer, BodyFirstDiffDoesNotPromoteOverLaggingPayeeCursor) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.set_body_first_serve_tip(true);
    st.set_require_fresh_credit_pool(true);
    // Snapshot as-of H-1: payee cursor is one behind the pending tip H.
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)), /*as_of_height=*/H - 1);

    const uint256 tip_hash = raw256(0x54);
    m.on_new_tip(H, tip_hash, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER,
                 CURTIME, VERSION);
    m.on_mnlistdiff(diff_with_seed(uint256::ZERO, tip_hash, H,
                                   111'000'000LL, sml_entry(0x40)));
    EXPECT_TRUE(m.tip_body_pending())
        << "promotion must wait for the payee axis to reach the tip";
    EXPECT_EQ(m.serve_tip_height(), 0u);
}

// Doomed-tip bound: a pending window that outlives the overdue budget (lost
// body the p2p watchdog could not recover / credit-pool drift) demotes the
// serve tip instead of serving knowingly-doomed old-tip work; the eventual
// body re-arms it.
TEST(DashCoinStateMaintainer, BodyFirstOverduePendingDemotesThenBodyReArms) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.set_body_first_serve_tip(true);
    st.set_require_fresh_credit_pool(true);
    int64_t now = 1'000'000;
    m.set_now_fn([&] { return now; });
    m.set_tip_body_overdue_secs(30);
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));

    auto b1 = make_cbtx_block(H - 1, 111'000'000LL, p2pkh_script(0x30));
    m.on_new_tip(H - 1, block_hash_of(b1), BITS, MTP,
                 DASH_PUBKEY_VER, DASH_P2SH_VER, CURTIME, VERSION);
    m.on_block_connected(b1, H - 1);
    ASSERT_TRUE(m.live());

    auto b2 = make_cbtx_block(H, next_balance(st, 111'000'000LL, H),
                              p2pkh_script(0x30));
    m.on_new_tip(H, block_hash_of(b2), BITS, MTP,
                 DASH_PUBKEY_VER, DASH_P2SH_VER, CURTIME, VERSION);
    // Inside the budget: still serving old-height work.
    now += 29;
    m.on_mempool_tx(make_spend(raw256(0x91), 0, 1'000, 7));
    EXPECT_TRUE(m.live());

    // Budget exceeded: demote — refusing beats serving doomed-tip work.
    now += 2;
    m.on_mempool_tx(make_spend(raw256(0x92), 0, 1'000, 8));
    EXPECT_FALSE(m.live())
        << "overdue pending window must stop serving old-tip work";
    EXPECT_EQ(st.describe_decline().cause, "tip-body-pending")
        << "the overdue refusal must carry the named transient";

    // The body finally lands: promotion re-arms the serve tip.
    m.on_block_connected(b2, H);
    EXPECT_TRUE(m.live());
    EXPECT_EQ(m.serve_tip_height(), H);
}

// ════════════════════════════════════════════════════════════════════════
// `tip-body-pending` must name a WAIT WE ARE ACTUALLY IN, and name what it
// is waiting FOR. Both pinned against the instrumented daemonless soak
// (86406d07, 2026-08-09 14:39–15:53).
// ════════════════════════════════════════════════════════════════════════

// MEASURED MISATTRIBUTION. Soak line 14:40:55 read
//   cause=tip-body-pending value=have_tip=0,have_mn=0 threshold=tip-body-folded
// — the body-pending flag was set, but BOTH populate halves were unmet and
// the MN half was the LONGER pole: the body folded at 14:41:15 (have_tip 0→1)
// and the arm still stayed down 5 s more waiting on have_mn. 19 s of the
// 126 s cold-start episode were charged to the block body; the MN seed owned
// them. The threshold made it worse by dropping `have_mn=1` from the
// requirement it printed.
//
// FAILS ON MASTER: the rename there is guarded only by the pending flag.
TEST(DashCoinStateMaintainer, TipBodyPendingIsNotNamedWhileTheMnHalfIsAlsoMissing) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.set_body_first_serve_tip(true);
    st.set_require_fresh_credit_pool(true);

    // Make the maintainer REPORT both halves as unmet without seeding the MN
    // set — the cold-start shape (have_tip=0, have_mn=0), and the reason the
    // "no-tip" refinement below must not fire either (the halves were
    // measured, not merely never reported).
    m.on_invalidate();
    ASSERT_EQ(st.have_tip_dbg(), 0);
    ASSERT_EQ(st.have_mn_dbg(), 0);

    auto b1 = make_cbtx_block(H - 1, 111'000'000LL, p2pkh_script(0x30));
    m.on_new_tip(H - 1, block_hash_of(b1), BITS, MTP,
                 DASH_PUBKEY_VER, DASH_P2SH_VER, CURTIME, VERSION);
    ASSERT_TRUE(m.tip_body_pending()) << "the pending flag IS set here";

    const auto d = st.describe_decline();
    EXPECT_EQ(d.cause, "not-populated")
        << "with the MN seed also missing, the block body is not the binding "
           "constraint — naming it sends the operator at the wrong lane";
    EXPECT_EQ(d.value, "have_tip=0,have_mn=0");
    EXPECT_EQ(d.threshold, "have_tip=1,have_mn=1")
        << "the threshold must keep requiring BOTH halves";
}

// The rename SURVIVES exactly where it is true: MN set ready, no serve tip,
// the tip block's own inputs the only thing missing — and it now says WHICH
// input. `awaiting=` is appended, never substituted, so the populate halves
// stay readable on the same line.
//
// FAILS ON MASTER: no axis exists there, so the value is the bare pair.
TEST(DashCoinStateMaintainer, TipBodyPendingNamesTheUnmetPromotionAxis) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.set_body_first_serve_tip(true);
    st.set_require_fresh_credit_pool(true);
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    ASSERT_EQ(st.have_mn_dbg(), 1);

    auto b1 = make_cbtx_block(H - 1, 111'000'000LL, p2pkh_script(0x30));
    m.on_new_tip(H - 1, block_hash_of(b1), BITS, MTP,
                 DASH_PUBKEY_VER, DASH_P2SH_VER, CURTIME, VERSION);
    ASSERT_TRUE(m.tip_body_pending());

    const auto d = st.describe_decline();
    EXPECT_EQ(d.cause, "tip-body-pending");
    EXPECT_EQ(d.threshold, "tip-body-folded");
    // The credit-pool seed is the first unmet conjunct: it is derived from the
    // tip block's BODY, which is exactly what has not arrived.
    EXPECT_EQ(d.value, "have_tip=0,have_mn=1,awaiting=credit-pool-seed")
        << "a wait must say what it is waiting FOR — the body and the "
           "getmnlistd reply are different fetches with different repair paths";

    // The body lands: promotion clears both the flag and the axis.
    m.on_block_connected(b1, H - 1);
    EXPECT_FALSE(m.tip_body_pending());
    EXPECT_STREQ(st.tip_body_pending_axis(), "");
}

// ════════════════════════════════════════════════════════════════════════
// Bounded full-block buffer (LTC-style retention): eviction proven at the
// bound — cap 24 with no ChainLock, shrink-to-floor 6 with a fresh one.
// FAILS-ON-MASTER: no retention exists there at all.
// ════════════════════════════════════════════════════════════════════════
TEST(DashCoinStateMaintainer, FullBlockBufferEvictsAtBound) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.set_full_block_buffer(true);

    const uint32_t H0 = H;
    for (uint32_t i = 0; i < 30; ++i)
        m.on_block_connected(
            make_cbtx_block(H0 + i, 1'000LL + i, p2pkh_script(0x30)), H0 + i);
    // No ChainLock observed => the cap alone bounds retention.
    EXPECT_EQ(m.block_buffer_depth(), 24u) << "cap must bound the buffer";
    EXPECT_EQ(m.block_buffer_lowest_height(), H0 + 6);
    EXPECT_EQ(m.block_buffer_highest_height(), H0 + 29);
    EXPECT_GE(m.block_buffer_evictions(), 6u) << "eviction must be OBSERVED";

    // A fresh ChainLock near the tip shrinks retention to the floor: nothing
    // at or below a ChainLocked height can reorg.
    std::array<uint8_t, 96> sig{};
    sig[0] = 1;
    st.set_best_cl(static_cast<int32_t>(H0 + 29),
                   sig, dash::coin::ClProvenance::ChainCommitted);
    m.on_block_connected(
        make_cbtx_block(H0 + 30, 2'000LL, p2pkh_script(0x30)), H0 + 30);
    EXPECT_EQ(m.block_buffer_depth(), 6u)
        << "with a tip-fresh ChainLock the floor governs";
    EXPECT_EQ(m.block_buffer_highest_height(), H0 + 30);
}

// Reorg WITHIN the buffer depth: the credit pool is rolled back to the fork
// point from the RETAINED fork-point body's own committed CCbTx balance — no
// cold wipe on the credit-pool axis. Beyond the buffer (no retained body
// still on the new branch) the existing wipe path is unchanged.
// FAILS-ON-MASTER: on_sml_reorg unconditionally wipes the seed to -1.
TEST(DashCoinStateMaintainer, ReorgWithinBufferReplaysCreditPoolUndoFromRetainedBodies) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.set_full_block_buffer(true);

    const uint32_t H0 = H;
    const int64_t bal_a = 1'000LL;
    const int64_t bal_b = next_balance(st, bal_a, H0 + 1);
    const int64_t bal_c = next_balance(st, bal_b, H0 + 2);
    auto a = make_cbtx_block(H0,     bal_a, p2pkh_script(0x30));
    auto b = make_cbtx_block(H0 + 1, bal_b, p2pkh_script(0x30));
    auto c = make_cbtx_block(H0 + 2, bal_c, p2pkh_script(0x30));
    m.on_block_connected(a, H0);
    m.on_block_connected(b, H0 + 1);
    m.on_block_connected(c, H0 + 2);
    ASSERT_EQ(st.credit_pool_height(), static_cast<int32_t>(H0 + 2));
    ASSERT_EQ(m.block_buffer_depth(), 3u);

    // New branch after the reorg: H0 is still ours (fork point), H0+1 is a
    // DIFFERENT block, H0+2 not present.
    const uint256 a_hash = block_hash_of(a);
    m.set_chain_hash_at_height_fn(
        [&](uint32_t h) -> std::optional<uint256> {
            if (h == H0) return a_hash;
            if (h == H0 + 1) return raw256(0xEE);   // new-branch block != b
            return std::nullopt;
        });
    m.on_sml_reorg();
    EXPECT_EQ(st.credit_pool_height(), static_cast<int32_t>(H0))
        << "credit pool must roll back to the fork point, not wipe to -1";
    EXPECT_EQ(st.credit_pool(), bal_a)
        << "the rolled-back balance is the retained body's own committed value";
    EXPECT_EQ(m.block_buffer_highest_height(), H0)
        << "orphan-branch bodies above the fork point must be dropped";

    // ── Beyond the buffer: no retained body on the new branch => wipe. ──
    NodeCoinState st2;
    CoinStateMaintainer m2(st2);
    m2.set_full_block_buffer(true);
    m2.on_block_connected(make_cbtx_block(H0, 1'000LL, p2pkh_script(0x30)), H0);
    m2.set_chain_hash_at_height_fn(
        [](uint32_t) -> std::optional<uint256> { return std::nullopt; });
    m2.on_sml_reorg();
    EXPECT_EQ(st2.credit_pool_height(), -1)
        << "beyond the buffer the existing wipe + cold-resync path stays";
    EXPECT_EQ(st2.credit_pool(), 0);
}

// ════════════════════════════════════════════════════════════════════════
// Tip-transition fallback leak: EVERY serve-tip promotion site must fire the
// state-dirty re-issue sink (bump + notify), not only the body-fold one —
// otherwise the work source rides a fallback decision cached during the (now
// closed) pending window until the next unrelated signal, and fallback serves
// leak for seconds after the fold. Latency only: no gate is weakened.
// ════════════════════════════════════════════════════════════════════════

// Body raced AHEAD of the header event (block message processed before the
// header-chain tip callback): on_new_tip promotes immediately — and must
// re-issue work. FAILS-ON-MASTER: that branch republished and returned
// without firing the sink.
TEST(DashCoinStateMaintainer, BodyFirstRacedBodyPromotionOnHeaderFiresStateDirty) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.set_body_first_serve_tip(true);
    st.set_require_fresh_credit_pool(true);
    int dirty = 0;
    m.set_on_state_dirty([&] { ++dirty; });
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));

    auto b1 = make_cbtx_block(H - 1, 111'000'000LL, p2pkh_script(0x30));
    m.on_new_tip(H - 1, block_hash_of(b1), BITS, MTP,
                 DASH_PUBKEY_VER, DASH_P2SH_VER, CURTIME, VERSION);
    m.on_block_connected(b1, H - 1);
    ASSERT_TRUE(m.live());

    // The BODY of H arrives first: the seed advances to H, but no pending
    // window is open, so the serve tip holds at the parsed H-1.
    auto b2 = make_cbtx_block(H, next_balance(st, 111'000'000LL, H),
                              p2pkh_script(0x30));
    m.on_block_connected(b2, H);
    ASSERT_EQ(st.credit_pool_height(), static_cast<int32_t>(H));
    ASSERT_EQ(m.serve_tip_height(), H - 1);

    // The header event lands: promotion is immediate (inputs already parsed)
    // and MUST re-issue work event-driven.
    const int dirty_before = dirty;
    m.on_new_tip(H, block_hash_of(b2), BITS, MTP,
                 DASH_PUBKEY_VER, DASH_P2SH_VER, CURTIME, VERSION);
    EXPECT_EQ(m.serve_tip_height(), H)
        << "body raced ahead: the header event must promote immediately";
    EXPECT_FALSE(m.tip_body_pending());
    EXPECT_GT(dirty, dirty_before)
        << "immediate promotion must fire the re-issue sink (bump + notify)";
}

// Cold-start diff-before-seed order: the authoritative snapshot as-of the
// pending tip completes the payee axis — the LAST promotion precondition —
// and that promotion must re-issue work too. FAILS-ON-MASTER: the
// on_mn_list_update promotion ended in republish() with no sink fire.
TEST(DashCoinStateMaintainer, BodyFirstSnapshotPromotionFiresStateDirty) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.set_body_first_serve_tip(true);
    st.set_require_fresh_credit_pool(true);
    int dirty = 0;
    m.set_on_state_dirty([&] { ++dirty; });
    // Payee cursor one behind the pending tip: the tip-targeted diff may NOT
    // promote (payee-stale hold, pinned elsewhere)...
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)), /*as_of_height=*/H - 1);
    const uint256 tip_hash = raw256(0x54);
    m.on_new_tip(H, tip_hash, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER,
                 CURTIME, VERSION);
    m.on_mnlistdiff(diff_with_seed(uint256::ZERO, tip_hash, H,
                                   111'000'000LL, sml_entry(0x40)));
    ASSERT_TRUE(m.tip_body_pending());
    ASSERT_EQ(m.serve_tip_height(), 0u);

    // ...then the authoritative snapshot as-of the tip lands: promotion — and
    // the event-driven re-issue with it.
    const int dirty_before = dirty;
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)), /*as_of_height=*/H);
    EXPECT_EQ(m.serve_tip_height(), H)
        << "snapshot as-of the tip completes the payee axis and promotes";
    EXPECT_FALSE(m.tip_body_pending());
    EXPECT_GT(dirty, dirty_before)
        << "snapshot promotion must fire the re-issue sink (bump + notify)";
}

// ════════════════════════════════════════════════════════════════════════
// DIP-0027 asset-unlock FEE term — KAT from real mainnet block 2,166,498.
//
// dashd (evo/creditpool.cpp) removes the GROSS unlock amount from the credit
// pool for every type-9 tx: payload.fee + Σ(tx.vout.value). The fee reaches
// the miner through the coinbase, but it still LEAVES the pool. An accrual
// that subtracts only Σvout runs HIGH by Σfee at every unlock block, so the
// per-block cross-check against the committed cbTx creditPoolBalance trips
// ACCRUAL DRIFT (fail-closed: freshness seed not advanced) at each of the
// ~5k historical unlock blocks — and an embedded template built from the
// drifted balance commits a wrong cbTx creditPool field (bad-cbtx class).
//
// Known answers, re-verified against a mainnet dashd (dash-cli getblock ×2,
// 2026-08-05):
//   cbTx(2,166,497).creditPoolBalance = 1,366,727,881,775
//   block 2,166,498: 4 type-9 unlocks (indexes 156..159), each fee = 190;
//                    Σvout = 100e6 + 100e6 + 1000e6 + 100e6 = 1,300,000,000
//   platform reward at 2,166,498 (mainnet MN_RR active)   =    53,617,393
//   cbTx(2,166,498).creditPoolBalance = 1,365,481,498,408
//     = 1,366,727,881,775 + 53,617,393 − 1,300,000,000 − 760
// Omitting the fee computes 1,365,481,499,168 — exactly 760 high.
// ════════════════════════════════════════════════════════════════════════

static std::vector<unsigned char> encode_unlock_payload(
    const dash::coin::vendor::CAssetUnlockPayload& p)
{
    auto stream = ::pack(p);
    auto sp = stream.get_span();
    return std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
}

// A structurally-real type-9 asset-unlock tx: no vin (credit-pool mint),
// withdrawal vout, and a well-formed CAssetUnlockPayload carrying the fee.
static MutableTransaction make_asset_unlock(uint64_t index, uint32_t fee,
                                            uint32_t requested_height,
                                            int64_t out_value, uint8_t salt)
{
    MutableTransaction tx;
    tx.version  = 3;
    tx.type     = dash::coin::vendor::CAssetUnlockPayload::SPECIALTX_TYPE;
    tx.locktime = 0;
    TxOut o;
    o.value = out_value;
    o.scriptPubKey.m_data = p2pkh_script(salt);
    tx.vout.push_back(o);
    dash::coin::vendor::CAssetUnlockPayload p;
    p.nVersion        = dash::coin::vendor::CAssetUnlockPayload::CURRENT_VERSION;
    p.index           = index;
    p.fee             = fee;
    p.requestedHeight = requested_height;
    p.quorumHash      = raw256(salt);   // structural only — not verified here
    tx.extra_payload  = encode_unlock_payload(p);
    return tx;
}

// The four unlocks of mainnet 2,166,498, appended to a type-5 CbTx coinbase
// committing `committed_balance` at the block's own height.
static BlockType make_unlock_block_2166498(int64_t committed_balance)
{
    BlockType blk = make_cbtx_block(2'166'498u, committed_balance,
                                    p2pkh_script(0x30));
    blk.m_txs.push_back(make_asset_unlock(156, 190, 2'166'497u,
                                          1'000'000'000LL, 0x10));
    blk.m_txs.push_back(make_asset_unlock(157, 190, 2'166'497u,
                                          100'000'000LL, 0x20));
    blk.m_txs.push_back(make_asset_unlock(158, 190, 2'166'497u,
                                          100'000'000LL, 0x21));
    blk.m_txs.push_back(make_asset_unlock(159, 190, 2'166'497u,
                                          100'000'000LL, 0x22));
    bind_block(blk);   // re-bind: the tx set changed after make_cbtx_block
    return blk;
}

// Pure state-machine KAT. FAILS-ON-MASTER: apply_block subtracted only Σvout,
// yielding 1,365,481,499,168 (760 high) instead of the committed
// 1,365,481,498,408.
TEST(DashCreditPool, MainnetBlock2166498UnlockFeeKAT) {
    // Independent pin of the platform-reward term used below (mainnet MN_RR).
    const int64_t reward =
        dash::coin::compute_dash_platform_reward_post_v20_mn_rr(2'166'498u);
    ASSERT_EQ(reward, 53'617'393LL);

    dash::coin::CreditPool sm;
    sm.seed(1'366'727'881'775LL, 2'166'497u);

    auto blk = make_unlock_block_2166498(1'365'481'498'408LL);
    auto delta = sm.apply_block(blk, 2'166'498u, reward);
    ASSERT_TRUE(delta.has_value());
    EXPECT_EQ(*delta, 53'617'393LL - 1'300'000'000LL - 760LL)
        << "unlock delta must be −(Σvout + Σfee) + platform reward";
    EXPECT_EQ(sm.balance(), 1'365'481'498'408LL)
        << "credit-pool balance must match the committed cbTx value "
           "(off-by-Σfee = the omitted payload.fee term)";
    EXPECT_EQ(sm.height(), 2'166'498u);
}

// Maintainer wire-path KAT: a CONTIGUOUS advance through the real unlock
// block must verify against the committed balance and advance the freshness
// seed. FAILS-ON-MASTER: the fee-less accrual disagreed with the wire value,
// tripping ACCRUAL DRIFT — fail-closed, seed held at 2,166,497.
TEST(DashCoinStateMaintainer, UnlockBlockContiguousAdvanceNoAccrualDrift) {
    NodeCoinState st;
    CoinStateMaintainer m(st);

    // Cold bootstrap at 2,166,497 off the block's own committed balance.
    m.on_block_connected(make_cbtx_block(2'166'497u, 1'366'727'881'775LL,
                                         p2pkh_script(0x30)),
                         2'166'497u);
    ASSERT_EQ(st.credit_pool_height(), 2'166'497);
    ASSERT_EQ(st.credit_pool(), 1'366'727'881'775LL);

    // Contiguous next block: the independent accrual (platform reward
    // + Σlocks − Σunlocks-incl-fee) must equal the committed balance.
    m.on_block_connected(make_unlock_block_2166498(1'365'481'498'408LL),
                         2'166'498u);
    EXPECT_EQ(st.credit_pool_height(), 2'166'498)
        << "ACCRUAL DRIFT fired on a correct block: the unlock fee term is "
           "missing from the credit-pool delta";
    EXPECT_EQ(st.credit_pool(), 1'365'481'498'408LL);
}

// ═══════════════════════════════════════════════════════════════════════════
// THE STALE-SML SEED RECONCILE (contabo, 2026-08-05, h=2516956)
//
// on_mn_list_update reconciles a freshly seeded payee queue against whatever
// SML is already held, so a live-advanced SML's bans land immediately. That is
// right when the SML is CURRENT. It is destructive when the SML is older than
// the snapshot: the snapshot already reflects every ban and revive up to its
// own height, so an older attestation can only undo them.
//
// MEASURED. A replay-fold snapshot as-of h=2516955 — byte-exact with dashd's
// list at that height — was reconciled 13 ms after publication against an SML
// dated h=2478000:
//     [SML->PAYEE] seed reconcile: -6 banned +21 revived @ h=2478000
//     [MNS-SM] PAYEE DESYNC h=2516956: coinbase does not pay projected MN
//              8ef71d8296c6e516
// Twenty-one masternodes the chain had banned were revived in the queue.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashCoinStateMaintainer, StaleSmlMustNotReviveBansInAFreshSnapshot) {
    NodeCoinState st;
    CoinStateMaintainer m(st);

    // An OLD SML that still believes this masternode is valid.
    CSimplifiedMNListEntry e = sml_entry(0x40);
    e.isValid = true;
    m.on_mnlistdiff(diff_with_seed(uint256::ZERO, raw256(0xA0),
                                   /*cb_height=*/2478000, 0, e));
    ASSERT_TRUE(st.have_sml());
    ASSERT_EQ(m.sml_current_height(), 2478000u);
    ASSERT_TRUE(m.sml_height_paired());

    // A snapshot ~39k blocks NEWER in which the chain has banned it.
    std::vector<std::pair<uint256, MNState>> snap;
    {
        MNState mn;
        mn.scriptPayout.m_data = p2pkh_script(0x30);
        mn.nRegisteredHeight   = 2400000;
        mn.nLastPaidHeight     = 2516000;
        mn.nPoSeBanHeight      = 2485482;   // banned on-chain
        mn.isValid             = false;
        mn.payoutSplitProvenance = MNState::SPLIT_KNOWN;
        snap.emplace_back(raw256(0x40), mn);
    }
    m.on_mn_list_update(snap, 2516955, "replay-fold");

    const auto& held = st.mnstates().entries();
    auto it = held.find(raw256(0x40));
    ASSERT_NE(it, held.end());
    EXPECT_FALSE(it->second.isValid)
        << "a 39k-block-stale SML must not revive a masternode the snapshot "
           "says the chain banned";
    EXPECT_EQ(it->second.nPoSeBanHeight, 2485482u)
        << "the snapshot's own ban height must survive the reconcile";
}

// The mirror: an SML at or AHEAD of the snapshot is real evidence and the
// reconcile still runs, so the behaviour this guard protects is not lost.
TEST(DashCoinStateMaintainer, CurrentSmlStillReconcilesAFreshSnapshot) {
    NodeCoinState st;
    CoinStateMaintainer m(st);

    CSimplifiedMNListEntry e = sml_entry(0x40);
    e.isValid = false;                       // the SML says: banned
    m.on_mnlistdiff(diff_with_seed(uint256::ZERO, raw256(0xA0),
                                   /*cb_height=*/2516955, 0, e));
    ASSERT_EQ(m.sml_current_height(), 2516955u);

    std::vector<std::pair<uint256, MNState>> snap;
    {
        MNState mn;
        mn.scriptPayout.m_data = p2pkh_script(0x30);
        mn.nRegisteredHeight   = 2400000;
        mn.nLastPaidHeight     = 2516000;
        mn.isValid             = true;       // the snapshot says: fine
        mn.payoutSplitProvenance = MNState::SPLIT_KNOWN;
        snap.emplace_back(raw256(0x40), mn);
    }
    m.on_mn_list_update(snap, 2516955, "replay-fold");

    const auto& held = st.mnstates().entries();
    auto it = held.find(raw256(0x40));
    ASSERT_NE(it, held.end());
    EXPECT_FALSE(it->second.isValid)
        << "an SML current AT the snapshot height is authoritative and its "
           "ban must land";
}
