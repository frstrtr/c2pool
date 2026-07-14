// SPDX-License-Identifier: AGPL-3.0-or-later
/// Phase C-TEMPLATE step 9 -- fused dash get_work() consumer KAT.
///
/// get_work() (src/impl/dash/stratum/get_work.hpp) is the single miner-facing
/// entry that FUSES the two halves prior slices landed separately:
///   * template source  -- NodeCoinState::select_work() (#672/#673), populated
///     by the 4-leg reception wire (#693/#694);
///   * job-target math   -- assemble_work_job_targets() (work_job_targets.hpp).
///
/// This suite pins the fused contract end-to-end:
///   * a set-gap (unpopulated node bundle) routes the RETAINED dashd fallback
///     (invoked exactly once) AND still assembles the job targets;
///   * a populated bundle routes WorkSource::Embedded WITHOUT invoking the
///     dashd fallback (no direct daemon poll on the hot path), and reproduces
///     EXACTLY the DashWorkData a direct build_embedded_workdata() over the
///     node's OWN held state yields;
///   * the assembled job targets are IDENTICAL across both template sources --
///     the arithmetic is a pure transform that rides on top of either arm;
///   * an on_invalidate() (reorg) demotes back to the fallback.
///
/// Seeding mirrors test_dash_node_embedded_wire.cpp EXACTLY (same projection),
/// and every "expected" value is an independent recomputation -- no fabricated
/// oracle constants. Rig-free: default-constructed NodeImpl, no io_context.

#include <gtest/gtest.h>

#include <impl/dash/stratum/get_work.hpp>
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
using dash::coin::MNState;
using dash::coin::MutableTransaction;
using dash::coin::build_embedded_workdata;
using dash::stratum::GetWork;
using dash::stratum::get_work;
using dash::stratum::WorkJobTargetInputs;
using dash::stratum::WorkJobTargets;
using dash::stratum::assemble_work_job_targets;
using ::core::coin::UTXOViewCache;
using ::core::coin::Outpoint;
using ::core::coin::Coin;
using ::bitcoin_family::coin::TxIn;
using ::bitcoin_family::coin::TxOut;

static constexpr uint8_t  DASH_PUBKEY_VER = 76;
static constexpr uint8_t  DASH_P2SH_VER   = 16;
static constexpr uint32_t H = 2'400'000;

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

static DashWorkData fallback_sentinel() {
    DashWorkData w;
    w.m_height = 0xDEADBEEFu;
    w.m_bits   = 0x1a2b3c4du;
    return w;
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

// A fixed, non-degenerate per-miner job-target input. share_info_bits_target
// sits inside the sane band; a positive local_hash_rate exercises the
// None-path pseudoshare modulation. Reused verbatim across every case so the
// assembled targets are directly comparable.
static WorkJobTargetInputs sample_job_inputs() {
    WorkJobTargetInputs in;
    in.share_info_bits_target.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000");
    in.sane_target_min.SetHex     ("0000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    in.sane_target_max.SetHex     ("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    in.have_desired_pseudoshare = false;
    in.local_hash_rate = 1.0e6;   // 1 MH/s -> real None-path cap
    return in;
}

static void expect_targets_eq(const WorkJobTargets& a, const WorkJobTargets& b) {
    EXPECT_EQ(a.min_share_target, b.min_share_target);
    EXPECT_EQ(a.share_target,     b.share_target);
}

// ════════════════════════════════════════════════════════════════════════
// Set-gap: unpopulated node bundle -> dashd fallback, targets still assembled.
// ════════════════════════════════════════════════════════════════════════
TEST(DashGetWork, GapRoutesFallbackAndAssemblesTargets) {
    dash::NodeImpl node;
    ASSERT_FALSE(node.coin_state().populated());

    const auto job_in = sample_job_inputs();
    const WorkJobTargets reference_targets = assemble_work_job_targets(job_in);

    int calls = 0;
    GetWork gw = get_work(node.coin_state(),
                          [&]{ ++calls; return fallback_sentinel(); }, job_in);

    EXPECT_EQ(gw.source, WorkSource::DashdFallback);
    EXPECT_EQ(calls, 1);                        // fallback invoked exactly once
    EXPECT_EQ(gw.work.m_height, 0xDEADBEEFu);   // and its template returned verbatim
    expect_targets_eq(gw.targets, reference_targets);  // job assembled regardless
}

// ════════════════════════════════════════════════════════════════════════
// Populated: embedded arm, no dashd poll, byte-equal to a direct build.
// ════════════════════════════════════════════════════════════════════════
TEST(DashGetWork, PopulatedRoutesEmbeddedNoDashdPoll) {
    UTXOViewCache utxo(nullptr);
    uint256 prev = raw256(0x77);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, /*height=*/1, /*cb=*/false));

    auto payout = p2pkh_script(0x30);
    const uint256 prev_hash = raw256(0xAB);
    const uint32_t bits = 0x1b104be3u;
    const uint32_t mtp  = 1'700'000'000u;
    const uint32_t curtime = 1'700'000'123u;
    const uint32_t version = 0x20000000u;

    dash::NodeImpl node;
    node.coin_state().mempool().set_utxo(&utxo);

    node.coin_state_maintainer().on_mn_list_update(single_mn(payout));
    ASSERT_TRUE(node.coin_state_maintainer().on_mempool_tx(
        make_spend(prev, 0, 90'000, /*salt=*/1)));
    node.coin_state_maintainer().on_new_tip(
        H - 1, prev_hash, bits, mtp, DASH_PUBKEY_VER, DASH_P2SH_VER, curtime, version);
    ASSERT_TRUE(node.coin_state().populated());

    DashWorkData reference = build_embedded_workdata(
        H - 1, prev_hash, node.coin_state().mnstates(), node.coin_state().mempool(),
        bits, mtp, DASH_PUBKEY_VER, DASH_P2SH_VER, curtime, version);

    const auto job_in = sample_job_inputs();
    const WorkJobTargets reference_targets = assemble_work_job_targets(job_in);

    int calls = 0;
    GetWork gw = get_work(node.coin_state(),
                          [&]{ ++calls; return fallback_sentinel(); }, job_in);

    EXPECT_EQ(gw.source, WorkSource::Embedded);
    EXPECT_EQ(calls, 0);                          // NO dashd poll on the hot path
    expect_workdata_eq(gw.work, reference);       // oracle-parity template preserved
    expect_targets_eq(gw.targets, reference_targets);
}

// ════════════════════════════════════════════════════════════════════════
// The job-target arithmetic is identical across BOTH template sources.
// ════════════════════════════════════════════════════════════════════════
TEST(DashGetWork, JobTargetsRideEitherTemplateSource) {
    const auto job_in = sample_job_inputs();

    // Gap arm.
    dash::NodeImpl gap_node;
    GetWork gap = get_work(gap_node.coin_state(),
                           [&]{ return fallback_sentinel(); }, job_in);
    ASSERT_EQ(gap.source, WorkSource::DashdFallback);

    // Populated arm.
    UTXOViewCache utxo(nullptr);
    uint256 prev = raw256(0x77);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));
    dash::NodeImpl hot_node;
    hot_node.coin_state().mempool().set_utxo(&utxo);
    hot_node.coin_state_maintainer().on_mn_list_update(single_mn(p2pkh_script(0x30)));
    ASSERT_TRUE(hot_node.coin_state_maintainer().on_mempool_tx(make_spend(prev, 0, 90'000, 1)));
    hot_node.coin_state_maintainer().on_new_tip(
        H - 1, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
        DASH_PUBKEY_VER, DASH_P2SH_VER, 1'700'000'123u, 0x20000000u);
    ASSERT_TRUE(hot_node.coin_state().populated());
    GetWork hot = get_work(hot_node.coin_state(),
                           [&]{ return fallback_sentinel(); }, job_in);
    ASSERT_EQ(hot.source, WorkSource::Embedded);

    // Same inputs -> same job targets, independent of which arm sourced work.
    expect_targets_eq(gap.targets, hot.targets);
}

// ════════════════════════════════════════════════════════════════════════
// Demote: on_invalidate() (reorg) drops back to the dashd fallback.
// ════════════════════════════════════════════════════════════════════════
TEST(DashGetWork, InvalidateDemotesToFallback) {
    dash::NodeImpl node;
    node.coin_state_maintainer().on_mn_list_update(single_mn(p2pkh_script(0x30)));
    node.coin_state_maintainer().on_new_tip(
        H - 1, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
        DASH_PUBKEY_VER, DASH_P2SH_VER);
    ASSERT_TRUE(node.coin_state().populated());

    node.coin_state_maintainer().on_invalidate();
    ASSERT_FALSE(node.coin_state().populated());

    const auto job_in = sample_job_inputs();
    int calls = 0;
    GetWork gw = get_work(node.coin_state(),
                          [&]{ ++calls; return fallback_sentinel(); }, job_in);

    EXPECT_EQ(gw.source, WorkSource::DashdFallback);
    EXPECT_EQ(calls, 1);
    EXPECT_EQ(gw.work.m_height, 0xDEADBEEFu);
}
