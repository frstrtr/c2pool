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
    bind_block(blk);
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

// C-2 chainlock: on_new_chainlock adopts a fresher ChainLock as the CCbTx
// bestCL* and fires the state-dirty sink; a non-advancing height is ignored.
TEST(DashCoinStateMaintainer, OnNewChainlockAdoptsForwardOnlyAndFiresDirty) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    int dirty = 0;
    m.set_on_state_dirty([&] { ++dirty; });

    std::array<uint8_t, 96> sig{}; sig[0] = 0x11;
    m.on_new_chainlock(1500000, sig);
    EXPECT_EQ(st.best_cl_height(), 1500000);
    EXPECT_EQ(dirty, 1) << "a fresher ChainLock must re-issue work";

    // A stale (<=) height is ignored — no adoption, no re-issue.
    std::array<uint8_t, 96> older{}; older[0] = 0x22;
    m.on_new_chainlock(1499999, older);
    EXPECT_EQ(st.best_cl_height(), 1500000);
    EXPECT_EQ(dirty, 1);

    // A forward ChainLock advances + re-issues again.
    m.on_new_chainlock(1500005, sig);
    EXPECT_EQ(st.best_cl_height(), 1500005);
    EXPECT_EQ(dirty, 2);
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
