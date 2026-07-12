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
#include <impl/dash/coin/utxo_adapter.hpp>
#include <impl/dash/coin/rpc_data.hpp>
#include <impl/dash/coin/transaction.hpp>

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

    BlockType blk;
    blk.m_txs.push_back(make_spend(raw256(0x90), 0, 500000000, 1));  // cb (idx 0, skipped)
    blk.m_txs.push_back(make_spend(raw256(0x91), 0, 400000000, 2));  // plain spend, no collateral match
    auto r = m.on_block_connected(blk, H);

    EXPECT_EQ(r.registered, 0u);
    EXPECT_EQ(st.mnstates().size(), 1u);
    EXPECT_TRUE(m.live()) << "no-op block must not drop the live bundle";
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
    m.on_block_connected(blk, H);

    EXPECT_EQ(st.mnstates().size(), 0u);
    EXPECT_FALSE(m.live()) << "collateral spend emptied the DMN set; bundle must drop to fallback";

    bool fb = false;
    WorkSelection sel = st.select_work([&]() { fb = true; return DashWorkData{}; });
    EXPECT_EQ(sel.source, WorkSource::DashdFallback);
    EXPECT_TRUE(fb) << "empty DMN set must route get_work to the dashd RPC fallback";
}
