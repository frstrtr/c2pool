// SPDX-License-Identifier: AGPL-3.0-or-later
/// Phase C-TEMPLATE step 8 -- NodeImpl embedded coin-state HOLD KAT.
///
/// #672 landed select_dash_work() (the branch point); #673 landed NodeCoinState
/// (the holder); #674/#675 landed CoinStateMaintainer (the async driver). But
/// every one of those was header-only -- NOTHING in the live NodeImpl held a
/// NodeCoinState, so the embedded arm could never actually flip in a running
/// node. This slice makes NodeImpl OWN the bundle + maintainer and exposes
/// select_work(); this suite proves that node surface end-to-end:
///
///   * a fresh node holds an UNpopulated bundle -> node.select_work() routes the
///     dashd getblocktemplate fallback (retained safety path) and INVOKES the
///     fallback closure exactly once;
///   * driving node.coin_state_maintainer() through the reception/think events
///     (on_new_tip + on_mn_list_update) publishes the node-held bundle ->
///     node.select_work() routes WorkSource::Embedded, does NOT invoke the
///     fallback, and returns EXACTLY the DashWorkData a direct
///     build_embedded_workdata() over the node's OWN held mnstates + mempool +
///     tip params produces (holding it in the node changes which arm runs, not
///     the oracle-parity template);
///   * an on_invalidate() (reorg) demotes the node-held bundle back to the
///     retained dashd fallback.
///
/// Seeding mirrors test_dash_node_coin_state.cpp / test_dash_coin_state_maintainer.cpp
/// exactly so all three suites pin the SAME projection. No fabricated oracle
/// values -- the "expected" work IS an independent build_embedded_workdata()
/// call, compared field-for-field. Rig-free: default-constructed NodeImpl, no
/// io_context, no sockets (matches test_dash_node.cpp).

#include <gtest/gtest.h>

#include <impl/dash/node.hpp>
#include <impl/dash/coin/node_coin_state.hpp>
#include <impl/dash/coin/coin_state_maintainer.hpp>
#include <impl/dash/coin/embedded_gbt.hpp>
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/utxo_adapter.hpp>
#include <impl/dash/coin/rpc_data.hpp>
#include <impl/dash/coin/transaction.hpp>

#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

using dash::coin::DashWorkData;
using dash::coin::WorkSource;
using dash::coin::WorkSelection;
using dash::coin::MNState;
using dash::coin::MutableTransaction;
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
    return {{raw256(0x01), s}};
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

// A recognisable sentinel the fallback closure returns, so we can prove which
// arm select_work() actually ran without depending on the closure's fields.
static DashWorkData fallback_sentinel() {
    DashWorkData w;
    w.m_height = 0xDEADBEEFu;
    w.m_bits   = 0x1a2b3c4du;
    return w;
}

// ════════════════════════════════════════════════════════════════════════
// COLD arm: a fresh node holds an unpopulated bundle -> dashd fallback.
// ════════════════════════════════════════════════════════════════════════
TEST(DashNodeEmbeddedWire, FreshNodeRoutesFallbackAndInvokesClosure) {
    dash::NodeImpl node;
    EXPECT_FALSE(node.coin_state().populated());

    int calls = 0;
    WorkSelection sel = node.select_work([&]{ ++calls; return fallback_sentinel(); });

    EXPECT_EQ(sel.source, WorkSource::DashdFallback);
    EXPECT_EQ(calls, 1);                       // fallback closure ran exactly once
    EXPECT_EQ(sel.work.m_height, 0xDEADBEEFu);  // and its result was returned verbatim
}

// ════════════════════════════════════════════════════════════════════════
// HOT arm: drive the node-held maintainer -> Embedded, byte-equal direct build.
// ════════════════════════════════════════════════════════════════════════
TEST(DashNodeEmbeddedWire, MaintainerPublishesNodeBundleRoutesEmbeddedByteEqual) {
    UTXOViewCache utxo(nullptr);
    uint256 prev = raw256(0x77);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, /*height=*/1, /*cb=*/false));

    auto payout = p2pkh_script(0x30);
    const uint256 prev_hash = raw256(0xAB);
    const uint32_t bits = 0x1b104be3u;
    const uint32_t mtp  = 1'700'000'000u;
    const uint32_t curtime = 1'700'000'123u;   // pin the injectable seams so both
    const uint32_t version = 0x20000000u;       // build paths are byte-identical

    dash::NodeImpl node;
    node.coin_state().mempool().set_utxo(&utxo);

    // Drive the bundle purely through the node's maintainer accessor -- the exact
    // surface the reception/think slices call. MN then tip; readiness gate flips
    // populated() only after BOTH land.
    node.coin_state_maintainer().on_mn_list_update(single_mn(payout));
    EXPECT_FALSE(node.coin_state().populated());   // tip not yet seen -> still cold
    ASSERT_TRUE(node.coin_state_maintainer().on_mempool_tx(
        make_spend(prev, 0, 90'000, /*salt=*/1)));  // fee 10'000
    node.coin_state_maintainer().on_new_tip(
        H - 1, prev_hash, bits, mtp, DASH_PUBKEY_VER, DASH_P2SH_VER, curtime, version);

    ASSERT_TRUE(node.coin_state().populated());
    ASSERT_TRUE(node.coin_state().make_embedded_work_inputs().viable());

    // Independent reference: the SAME projection over the node's OWN held state.
    DashWorkData reference = build_embedded_workdata(
        H - 1, prev_hash, node.coin_state().mnstates(), node.coin_state().mempool(),
        bits, mtp, DASH_PUBKEY_VER, DASH_P2SH_VER, curtime, version);

    int calls = 0;
    WorkSelection sel = node.select_work([&]{ ++calls; return fallback_sentinel(); });

    EXPECT_EQ(sel.source, WorkSource::Embedded);
    EXPECT_EQ(calls, 0);                       // fallback NOT invoked on the hot arm
    expect_workdata_eq(sel.work, reference);   // node bundle reproduces it exactly
}

// ════════════════════════════════════════════════════════════════════════
// Demote: on_invalidate() (reorg) drops the node bundle back to fallback.
// ════════════════════════════════════════════════════════════════════════
TEST(DashNodeEmbeddedWire, InvalidateDemotesNodeBundleToFallback) {
    auto payout = p2pkh_script(0x30);
    dash::NodeImpl node;

    node.coin_state_maintainer().on_mn_list_update(single_mn(payout));
    node.coin_state_maintainer().on_new_tip(
        H - 1, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
        DASH_PUBKEY_VER, DASH_P2SH_VER);
    ASSERT_TRUE(node.coin_state().populated());

    node.coin_state_maintainer().on_invalidate();
    EXPECT_FALSE(node.coin_state().populated());

    int calls = 0;
    WorkSelection sel = node.select_work([&]{ ++calls; return fallback_sentinel(); });
    EXPECT_EQ(sel.source, WorkSource::DashdFallback);
    EXPECT_EQ(calls, 1);
}
