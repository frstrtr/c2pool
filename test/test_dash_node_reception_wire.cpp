// SPDX-License-Identifier: AGPL-3.0-or-later
/// Phase C-TEMPLATE step 9 -- reception-wire KAT (leg 1: mempool relay).
///
/// #672..#685 landed the node-held embedded coin-state bundle + its async
/// CoinStateMaintainer, and test_dash_coin_state_maintainer / _node_embedded_wire
/// proved that DRIVING the maintainer's on_*() methods flips select_work() to
/// the embedded arm. But every one of those suites poked the maintainer DIRECTLY
/// -- nothing subscribed a live interfaces::Node's reception events to it, so in
/// a running node the arm could never flip on its own. wire_mempool_ingest()
/// (src/impl/dash/coin/mempool_ingest.hpp) closes the FIRST of the four legs:
/// interfaces::Node::new_tx -> CoinStateMaintainer::on_mempool_tx. This suite
/// proves that subscription end-to-end, off the real Event, with no direct poke:
///
///   * a new_tx relay fired on the interface FOLDS into the maintainer's mempool
///     (size 0 -> 1) -- the reception path, not a test poke, drives the state;
///   * disposing the returned handle tears the subscription down: a later relay
///     is NOT folded (size stays put) -- teardown is honoured;
///   * a relayed tx reaches the assembled embedded template once MN+tip arm the
///     bundle (select_work -> WorkSource::Embedded, tx present in m_tx_hashes),
///     and an on_invalidate() reorg demotes back to the retained dashd fallback.
///
/// Seeding mirrors test_dash_coin_state_maintainer.cpp exactly so the suites pin
/// the SAME projection. Scope-honest: only the new_tx leg is wired here; the
/// on_block_connected / on_new_tip / on_mn_list_update legs need payload the
/// interface does not yet carry (block height / tip params / a mnlistdiff event)
/// and land in their own slices -- their maintainer methods are still exercised
/// directly here only to arm the bundle for the template-reach assertion.

#include <gtest/gtest.h>

#include <impl/dash/coin/node_interface.hpp>       // dash::interfaces::Node
#include <impl/dash/coin/mempool_ingest.hpp>       // c2pool::dash::wire_mempool_ingest
#include <impl/dash/coin/tip_ingest.hpp>         // c2pool::dash::wire_tip_ingest
#include <impl/dash/coin/block_connect_ingest.hpp> // c2pool::dash::wire_block_connect_ingest
#include <impl/dash/coin/coin_state_maintainer.hpp>
#include <impl/dash/coin/node_coin_state.hpp>
#include <impl/dash/coin/embedded_gbt.hpp>
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/utxo_adapter.hpp>
#include <impl/dash/coin/rpc_data.hpp>
#include <impl/dash/coin/transaction.hpp>

#include <core/uint256.hpp>
#include <core/events.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <utility>
#include <vector>

using c2pool::dash::wire_mempool_ingest;
using c2pool::dash::wire_tip_ingest;
using c2pool::dash::wire_block_connect_ingest;
using dash::coin::CoinStateMaintainer;
using dash::coin::NodeCoinState;
using dash::coin::WorkSource;
using dash::coin::WorkSelection;
using dash::coin::MNState;
using dash::coin::BlockType;
using dash::coin::MutableTransaction;
using dash::coin::Transaction;
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

// Same as single_mn but records the MN's collateral outpoint, so a block that
// spends it via apply_block (pass 2) removes the record (leg-3 demote KAT).
static std::vector<std::pair<uint256, MNState>>
single_mn_coll(const std::vector<unsigned char>& payout,
               const uint256& coll_hash, uint32_t coll_idx) {
    MNState s;
    s.isValid = true;
    s.nRegisteredHeight = 2'300'000;
    s.nLastPaidHeight = 0;
    s.scriptPayout.m_data = payout;
    s.collateralOutpoint.hash  = coll_hash;
    s.collateralOutpoint.index = coll_idx;
    return std::vector<std::pair<uint256, MNState>>{{raw256(0x01), s}};
}

static const uint256  PREV_HASH = raw256(0xAB);
static const uint32_t BITS      = 0x1b104be3u;
static const uint32_t MTP       = 1'700'000'000u;
static const uint32_t CURTIME   = 1'700'000'123u;
static const uint32_t VERSION   = 0x20000000u;

// ════════════════════════════════════════════════════════════════════════
// Leg 1: a new_tx relay fired on the interface folds through the maintainer.
// No direct on_mempool_tx() poke -- the Event drives it.
// ════════════════════════════════════════════════════════════════════════
TEST(DashReceptionWire, NewTxRelayFoldsThroughMaintainer) {
    UTXOViewCache utxo(nullptr);
    const uint256 prev = raw256(0x77);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));

    dash::interfaces::Node node;
    NodeCoinState st;
    st.mempool().set_utxo(&utxo);
    CoinStateMaintainer m(st);

    auto sub = wire_mempool_ingest(node, m);
    ASSERT_TRUE(sub) << "wire must return a live subscription handle";
    ASSERT_EQ(st.mempool().size(), 0u);

    // Fire the reception event (NOT a direct maintainer poke).
    node.new_tx.happened(Transaction(make_spend(prev, 0, 90'000, /*salt=*/1)));

    EXPECT_EQ(st.mempool().size(), 1u) << "new_tx relay must fold into the mempool";
}

// ════════════════════════════════════════════════════════════════════════
// Disposing the handle tears the subscription down: later relays are dropped.
// ════════════════════════════════════════════════════════════════════════
TEST(DashReceptionWire, DisposeStopsIngest) {
    UTXOViewCache utxo(nullptr);
    const uint256 a = raw256(0x77);
    const uint256 b = raw256(0x66);
    utxo.add_coin(Outpoint(a, 0), Coin(100'000, {}, 1, false));
    utxo.add_coin(Outpoint(b, 0), Coin(100'000, {}, 1, false));

    dash::interfaces::Node node;
    NodeCoinState st;
    st.mempool().set_utxo(&utxo);
    CoinStateMaintainer m(st);

    auto sub = wire_mempool_ingest(node, m);
    node.new_tx.happened(Transaction(make_spend(a, 0, 90'000, /*salt=*/1)));
    ASSERT_EQ(st.mempool().size(), 1u);

    sub->dispose();
    node.new_tx.happened(Transaction(make_spend(b, 0, 90'000, /*salt=*/2)));
    EXPECT_EQ(st.mempool().size(), 1u) << "after dispose, no further relay may fold";
}

// ════════════════════════════════════════════════════════════════════════
// A relayed tx reaches the assembled embedded template once MN+tip arm the
// bundle; an on_invalidate() reorg demotes back to the retained dashd fallback.
// (MN/tip legs are still poked directly -- only new_tx is wired in this slice.)
// ════════════════════════════════════════════════════════════════════════
TEST(DashReceptionWire, RelayedTxReachesEmbeddedTemplateThenInvalidateDemotes) {
    UTXOViewCache utxo(nullptr);
    const uint256 prev = raw256(0x77);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));

    dash::interfaces::Node node;
    NodeCoinState st;
    st.mempool().set_utxo(&utxo);
    CoinStateMaintainer m(st);
    auto sub = wire_mempool_ingest(node, m);

    // Reception leg feeds the mempool; MN + tip arm the bundle.
    node.new_tx.happened(Transaction(make_spend(prev, 0, 90'000, /*salt=*/1)));  // fee 10'000
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    m.on_new_tip(H - 1, PREV_HASH, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER, CURTIME, VERSION);
    ASSERT_TRUE(m.live());

    bool fb = false;
    WorkSelection sel = st.select_work([&]() { fb = true; return dash::coin::DashWorkData{}; });
    EXPECT_EQ(sel.source, WorkSource::Embedded);
    EXPECT_FALSE(fb) << "embedded arm must not invoke the dashd fallback";
    EXPECT_EQ(sel.work.m_height, H);
    ASSERT_EQ(st.mempool().size(), 1u);
    EXPECT_EQ(sel.work.m_tx_hashes.size(), 1u)
        << "the RELAYED tx must reach the assembled embedded template";

    // Reorg: on_invalidate drops the tip -> next get_work falls back to dashd.
    m.on_invalidate();
    EXPECT_FALSE(m.live());
    bool fb2 = false;
    WorkSelection sel2 = st.select_work([&]() { fb2 = true; return dash::coin::DashWorkData{}; });
    EXPECT_EQ(sel2.source, WorkSource::DashdFallback);
    EXPECT_TRUE(fb2) << "after invalidate, the retained dashd fallback must run";
}

// ════════════════════════════════════════════════════════════════════════
// Leg 2: a new_tip advance fired on the interface arms the maintainer tip-
// readiness THROUGH THE WIRE -- no direct on_new_tip() poke. A tip arriving
// before the first mnlistdiff must NOT go live (MN list absent); once the MN
// list seeds the other prerequisite the bundle arms and select_work flips to
// the embedded arm, and the WIRED tip params reach the assembled template.
// ════════════════════════════════════════════════════════════════════════
TEST(DashReceptionWire, NewTipRelayArmsBundleOnceMnSeeded) {
    UTXOViewCache utxo(nullptr);
    dash::interfaces::Node node;
    NodeCoinState st;
    st.mempool().set_utxo(&utxo);
    CoinStateMaintainer m(st);

    auto sub = wire_tip_ingest(node, m);
    ASSERT_TRUE(sub) << "wire must return a live subscription handle";

    // Tip arrives first (reception is async): tip-readiness is set via the
    // wire, but the MN list is still empty, so the bundle stays on dashd.
    dash::interfaces::TipAdvance t;
    t.prev_height = H - 1; t.prev_hash = PREV_HASH; t.bits_for_next = BITS;
    t.mtp_at_tip = MTP; t.address_version = DASH_PUBKEY_VER;
    t.address_p2sh_version = DASH_P2SH_VER; t.curtime = CURTIME; t.version = VERSION;
    node.new_tip.happened(t);
    EXPECT_FALSE(m.live()) << "tip alone must not arm the bundle -- MN list absent";

    // MN list seeds the second prerequisite -> bundle arms, embedded arm wins.
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    ASSERT_TRUE(m.live()) << "tip (via wire) + MN must arm the embedded bundle";

    bool fb = false;
    WorkSelection sel = st.select_work([&]() { fb = true; return dash::coin::DashWorkData{}; });
    EXPECT_EQ(sel.source, WorkSource::Embedded);
    EXPECT_FALSE(fb) << "embedded arm must not invoke the dashd fallback";
    EXPECT_EQ(sel.work.m_height, H) << "the WIRED tip params must reach the template";
}

// ════════════════════════════════════════════════════════════════════════
// Disposing the tip handle tears the subscription down: a later tip advance is
// not applied, so a post-reorg bundle cannot silently re-arm off a stale feed.
// ════════════════════════════════════════════════════════════════════════
TEST(DashReceptionWire, DisposeStopsTipIngest) {
    UTXOViewCache utxo(nullptr);
    dash::interfaces::Node node;
    NodeCoinState st;
    st.mempool().set_utxo(&utxo);
    CoinStateMaintainer m(st);

    // MN present up front; the tip is the gating event under test.
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    auto sub = wire_tip_ingest(node, m);
    sub->dispose();

    dash::interfaces::TipAdvance t;
    t.prev_height = H - 1; t.prev_hash = PREV_HASH; t.bits_for_next = BITS;
    t.mtp_at_tip = MTP; t.address_version = DASH_PUBKEY_VER;
    t.address_p2sh_version = DASH_P2SH_VER; t.curtime = CURTIME; t.version = VERSION;
    node.new_tip.happened(t);
    EXPECT_FALSE(m.live()) << "after dispose, a tip advance must not arm the bundle";
}

// ════════════════════════════════════════════════════════════════════════
// Leg 3: a block_connected relay fired on the interface drives the maintainer's
// incremental MnStateMachine::apply_block THROUGH THE WIRE -- no direct
// on_block_connected() poke. A connected block whose non-coinbase tx spends the
// sole MN's collateral empties the DMN set; the now-unbacked payee demotes the
// live bundle to the retained dashd fallback, and select_work routes get_work
// there. Proves the block-connect leg mutates coin-state off the real Event.
// ════════════════════════════════════════════════════════════════════════
TEST(DashReceptionWire, BlockConnectRelayDrivesApplyBlockThenDemotes) {
    UTXOViewCache utxo(nullptr);
    dash::interfaces::Node node;
    NodeCoinState st;
    st.mempool().set_utxo(&utxo);
    CoinStateMaintainer m(st);

    auto sub = wire_block_connect_ingest(node, m);
    ASSERT_TRUE(sub) << "wire must return a live subscription handle";

    // Arm the bundle: MN (with a known collateral) + tip both present.
    const uint256 coll = raw256(0x55);
    m.on_mn_list_update(single_mn_coll(p2pkh_script(0x30), coll, 3));
    m.on_new_tip(H - 1, PREV_HASH, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER, CURTIME, VERSION);
    ASSERT_TRUE(m.live());
    ASSERT_EQ(st.mnstates().size(), 1u);

    // A connected block spends the sole MN's collateral -- fired on the wire,
    // NOT a direct maintainer poke.
    dash::interfaces::BlockConnected bc;
    bc.height = H;
    bc.block.m_txs.push_back(make_spend(raw256(0x90), 0, 500'000'000, 1));  // cb (idx 0, skipped)
    bc.block.m_txs.push_back(make_spend(coll, 3, 400'000'000, 2));          // spends MN collateral
    node.block_connected.happened(bc);

    EXPECT_EQ(st.mnstates().size(), 0u) << "apply_block (via wire) must remove the MN";
    EXPECT_FALSE(m.live()) << "emptied DMN set must drop the live bundle";

    bool fb = false;
    WorkSelection sel = st.select_work([&]() { fb = true; return dash::coin::DashWorkData{}; });
    EXPECT_EQ(sel.source, WorkSource::DashdFallback);
    EXPECT_TRUE(fb) << "after the collateral-spend block, get_work must fall back to dashd";
}

// ════════════════════════════════════════════════════════════════════════
// A block with no special txs touches no DMN record: apply_block registers
// nothing, the set is unchanged, and the armed bundle stays live -- the wire
// routes the event but a no-op block must not disturb readiness.
// ════════════════════════════════════════════════════════════════════════
TEST(DashReceptionWire, BlockConnectRelayNoSpecialTxPreservesReadiness) {
    UTXOViewCache utxo(nullptr);
    dash::interfaces::Node node;
    NodeCoinState st;
    st.mempool().set_utxo(&utxo);
    CoinStateMaintainer m(st);

    auto sub = wire_block_connect_ingest(node, m);
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    m.on_new_tip(H - 1, PREV_HASH, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER, CURTIME, VERSION);
    ASSERT_TRUE(m.live());

    dash::interfaces::BlockConnected bc;
    bc.height = H;
    bc.block.m_txs.push_back(make_spend(raw256(0x90), 0, 500'000'000, 1));  // cb (idx 0, skipped)
    bc.block.m_txs.push_back(make_spend(raw256(0x91), 0, 400'000'000, 2));  // plain spend, no collateral
    node.block_connected.happened(bc);

    EXPECT_EQ(st.mnstates().size(), 1u) << "no-special-tx block must not touch the DMN set";
    EXPECT_TRUE(m.live()) << "no-op block via wire must not drop the live bundle";
}

// ════════════════════════════════════════════════════════════════════════
// Disposing the block-connect handle tears the subscription down: a later
// connected block is not applied, so a collateral spend cannot silently demote
// an armed bundle off a stale feed.
// ════════════════════════════════════════════════════════════════════════
TEST(DashReceptionWire, DisposeStopsBlockConnectIngest) {
    UTXOViewCache utxo(nullptr);
    dash::interfaces::Node node;
    NodeCoinState st;
    st.mempool().set_utxo(&utxo);
    CoinStateMaintainer m(st);

    const uint256 coll = raw256(0x55);
    m.on_mn_list_update(single_mn_coll(p2pkh_script(0x30), coll, 3));
    m.on_new_tip(H - 1, PREV_HASH, BITS, MTP, DASH_PUBKEY_VER, DASH_P2SH_VER, CURTIME, VERSION);
    ASSERT_TRUE(m.live());

    auto sub = wire_block_connect_ingest(node, m);
    sub->dispose();

    dash::interfaces::BlockConnected bc;
    bc.height = H;
    bc.block.m_txs.push_back(make_spend(raw256(0x90), 0, 500'000'000, 1));  // cb (idx 0, skipped)
    bc.block.m_txs.push_back(make_spend(coll, 3, 400'000'000, 2));          // would spend MN collateral
    node.block_connected.happened(bc);

    EXPECT_EQ(st.mnstates().size(), 1u) << "after dispose, a connected block must not be applied";
    EXPECT_TRUE(m.live()) << "after dispose, the armed bundle must stay live";
}
