// SPDX-License-Identifier: AGPL-3.0-or-later
//
// RED->GREEN KAT for the serve-time INTERNAL-CONSISTENCY referee
// (tx_serve_referee.hpp) that replaces the dashd-tx-merkle PARITY backstop on
// the --embedded-tx-serve-own-set path.
//
// The referee decides whether a divergent-from-dashd embedded template may be
// served as OUR OWN valid set. It must:
//   (serve) pass a template that is internally consistent -- coinbase fee-exact
//           (coinbase_value == subsidy + Sum(fees) + superblock), every served
//           mempool tx fee_fold_proven, no intra-set double-spend -- EVEN when
//           its tx set (and hence tx-merkle-root) differs from dashd's.
//   (fail)  fail-close to the dashd fallback when ANY of those does not hold:
//           an over/under-claiming coinbase, an unproven tx, a double-spend, or
//           an unstamped (unknown-provenance) template.
//
// Each fail-close case is load-bearing: flip the single field under test back
// to its consistent value and the same template SERVES, proving the referee
// reacts to that field and nothing else.

#include <impl/dash/coin/tx_serve_referee.hpp>
#include <impl/dash/coin/subsidy.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <core/uint256.hpp>

#include <gtest/gtest.h>

namespace {

using dash::coin::DashWorkData;
using dash::coin::MutableTransaction;
using dash::coin::Transaction;
using dash::coin::tx_serve_internal_referee;

// A one-output spend of outpoint (hash, idx). scriptPubKey/value are immaterial
// to the referee (it reads vins for the double-spend fold and fees from
// m_tx_fees), so keep it minimal and deterministic.
MutableTransaction spend(const uint256& h, uint32_t idx)
{
    MutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash  = h;
    tx.vin[0].prevout.index = idx;
    tx.vout.resize(1);
    tx.vout[0].value = 1000;
    return tx;
}

uint256 h_of(uint8_t b)
{
    uint256 u;
    u.begin()[0] = b;
    return u;
}

// A minimally internally-consistent ARMED embedded template that carries one
// mempool-sourced tx of fee `fee` spending outpoint (0x11:0). By construction
// coinbase_value == subsidy(height) + fee + superblock, so the referee SERVES
// it. Each negative test perturbs exactly ONE field.
DashWorkData make_consistent(uint32_t height, uint64_t fee)
{
    DashWorkData w;
    w.m_height = height;

    MutableTransaction tx = spend(h_of(0x11), 0);
    w.m_txs.push_back(Transaction(tx));
    w.m_tx_hashes.push_back(h_of(0xaa));   // referee ignores hashes; realism only
    w.m_tx_fees.push_back(fee);
    w.m_mempool_tx_first_index = 0;
    w.m_mempool_tx_count       = 1;

    w.m_tx_serve_stamp.armed                       = true;
    w.m_tx_serve_stamp.all_mempool_fee_fold_proven = true;
    w.m_tx_serve_stamp.superblock_total            = 0;

    const uint64_t subsidy = static_cast<uint64_t>(
        dash::coin::compute_dash_block_reward_post_v20(height));
    w.m_coinbase_value = subsidy + fee;   // consistent
    return w;
}

// A realistic post-checkpoint mainnet height (past V20 / MN_RR).
constexpr uint32_t kH = 2'525'000;

}  // namespace

// ── SERVE: internally consistent, divergent-from-dashd is irrelevant ────────
TEST(DashTxServeReferee, ServesOwnSetWhenInternallyConsistent)
{
    const DashWorkData w = make_consistent(kH, 10'000);
    const auto v = tx_serve_internal_referee(w);
    EXPECT_TRUE(v.serve_own_set) << v.detail;
    EXPECT_TRUE(v.fail_cause.empty());
}

// ── SERVE: a funded superblock slice is accounted, not mistaken for over-claim
TEST(DashTxServeReferee, ServesWithSuperblockSliceAccounted)
{
    DashWorkData w = make_consistent(kH, 7'500);
    // Coinbase carries an additional treasury slice; the stamp records it, so
    // coinbase_value == subsidy + fee + superblock still holds exactly.
    w.m_tx_serve_stamp.superblock_total = 4'200'000;
    w.m_coinbase_value += 4'200'000;
    const auto v = tx_serve_internal_referee(w);
    EXPECT_TRUE(v.serve_own_set) << v.detail;
}

// ── FAIL-CLOSE (a): coinbase over-claims fees (bad-cb-amount vector) ─────────
TEST(DashTxServeReferee, FailClosesOnCoinbaseFeeOverclaim)
{
    DashWorkData w = make_consistent(kH, 10'000);
    w.m_coinbase_value += 1;   // one duff more than subsidy + fees
    const auto v = tx_serve_internal_referee(w);
    EXPECT_FALSE(v.serve_own_set);
    EXPECT_EQ(v.fail_cause, "tx-serve-coinbase-inconsistent") << v.detail;

    // Load-bearing: restore consistency and the SAME template serves.
    w.m_coinbase_value -= 1;
    EXPECT_TRUE(tx_serve_internal_referee(w).serve_own_set);
}

// ── FAIL-CLOSE (a): coinbase under-claims (per-tx fee vector corrupted) ──────
TEST(DashTxServeReferee, FailClosesWhenFeeVectorDoesNotReconcileCoinbase)
{
    DashWorkData w = make_consistent(kH, 10'000);
    // The served body grew a tx-fee entry the coinbase never folded in.
    w.m_tx_fees.push_back(5'000);
    const auto v = tx_serve_internal_referee(w);
    EXPECT_FALSE(v.serve_own_set);
    EXPECT_EQ(v.fail_cause, "tx-serve-coinbase-inconsistent") << v.detail;
}

// ── FAIL-CLOSE (b): a served tx is not fee_fold_proven ──────────────────────
TEST(DashTxServeReferee, FailClosesOnUnprovenFeeFold)
{
    DashWorkData w = make_consistent(kH, 10'000);
    w.m_tx_serve_stamp.all_mempool_fee_fold_proven = false;
    const auto v = tx_serve_internal_referee(w);
    EXPECT_FALSE(v.serve_own_set);
    EXPECT_EQ(v.fail_cause, "tx-serve-fee-fold-unproven") << v.detail;

    // Load-bearing: re-prove and the SAME template serves.
    w.m_tx_serve_stamp.all_mempool_fee_fold_proven = true;
    EXPECT_TRUE(tx_serve_internal_referee(w).serve_own_set);
}

// ── FAIL-CLOSE (c): two served txs spend the same outpoint ──────────────────
TEST(DashTxServeReferee, FailClosesOnIntraSetDoubleSpend)
{
    DashWorkData w = make_consistent(kH, 10'000);
    // A SECOND served tx spends the SAME coin (0x11:0) as the first. Keep the
    // coinbase and stamp consistent so ONLY the double-spend axis can fail.
    MutableTransaction dup = spend(h_of(0x11), 0);
    dup.vout[0].value = 500;
    w.m_txs.push_back(Transaction(dup));
    w.m_tx_hashes.push_back(h_of(0xbb));
    w.m_tx_fees.push_back(500);
    w.m_mempool_tx_count = 2;
    const uint64_t subsidy = static_cast<uint64_t>(
        dash::coin::compute_dash_block_reward_post_v20(kH));
    w.m_coinbase_value = subsidy + 10'000 + 500;   // fee-consistent

    const auto v = tx_serve_internal_referee(w);
    EXPECT_FALSE(v.serve_own_set);
    EXPECT_EQ(v.fail_cause, "tx-serve-double-spend") << v.detail;

    // Load-bearing: point the duplicate at a DIFFERENT coin and it serves.
    w.m_txs.back() = Transaction(spend(h_of(0x22), 0));
    EXPECT_TRUE(tx_serve_internal_referee(w).serve_own_set);
}

// ── FAIL-CLOSE (pre): unstamped template (unknown provenance) ───────────────
TEST(DashTxServeReferee, FailClosesOnUnstampedTemplate)
{
    DashWorkData w = make_consistent(kH, 10'000);
    w.m_tx_serve_stamp.armed = false;   // not built by the serving path
    const auto v = tx_serve_internal_referee(w);
    EXPECT_FALSE(v.serve_own_set);
    EXPECT_EQ(v.fail_cause, "tx-serve-unstamped") << v.detail;
}
