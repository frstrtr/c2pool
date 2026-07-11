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
