// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// doge_template_underfill_test.cpp -- regression pin for the [EMB-DOGE]
// TemplateBuilder UNDERFILL (contabo v36 cutover CODE gate (a)).
//
// Root cause: Mempool::get_sorted_txs_with_fees selected ONLY fee_known txs and
// silently dropped every fee_known=false tx, so an embedded DOGE UTXO set that
// could not resolve a large multi-input tx's fee produced a near-empty block on
// a non-empty mempool (24/35 tx, 5298/105766 B in the live journal 2026-07-25).
// The fix adds an opt-in Pass 2 that fills the remaining weight with unknown-fee
// txs WITHOUT crediting their (unknown) fees, so total_fees / coinbasevalue /
// gentx stay byte-for-byte unchanged (consensus-neutral, pre-v36 rule).
//
// Fixture: >=35 tx (24 fee_known + 11 fee_unknown) so the regression cannot
// silently return. Exercises the shared ltc::coin::Mempool directly (the DOGE
// embedded TemplateBuilder reuses it).
// ---------------------------------------------------------------------------
#include <cstdint>

#include <gtest/gtest.h>

#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/transaction.hpp>
#include <core/uint256.hpp>

using ltc::coin::Mempool;
using ltc::coin::MutableTransaction;
using ltc::coin::TxIn;
using ltc::coin::TxOut;
using ltc::coin::compute_txid;

namespace {

MutableTransaction tagged_tx(int64_t value, uint32_t index)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = index;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = value;
    tx.vout.push_back(out);
    return tx;
}

constexpr int      KNOWN       = 24;
constexpr int      UNKNOWN     = 11;
constexpr int      TOTAL       = KNOWN + UNKNOWN;   // 35, matching the live journal
constexpr uint32_t BIG_WEIGHT  = 4000000u;

// Build TOTAL distinct txs; the first KNOWN carry a resolved fee, the remaining
// UNKNOWN are left fee_known=false. Returns the sum of the known fees.
uint64_t build_fixture(Mempool& pool)
{
    uint64_t known_fee_sum = 0;
    for (int i = 0; i < TOTAL; ++i) {
        MutableTransaction tx = tagged_tx(1000 + i, static_cast<uint32_t>(i));
        EXPECT_TRUE(pool.add_tx(tx));
        if (i < KNOWN) {
            const uint64_t fee = 100 + static_cast<uint64_t>(i);
            pool.set_tx_fee(compute_txid(tx), fee);
            known_fee_sum += fee;
        }
    }
    EXPECT_EQ(pool.size(), static_cast<size_t>(TOTAL));
    return known_fee_sum;
}

} // namespace

// Default (proven LTC parent path): unchanged -- only fee_known txs selected.
TEST(DogeTemplateUnderfill, DefaultSelectsOnlyKnownFeeTxs)
{
    Mempool pool;
    const uint64_t known_fee_sum = build_fixture(pool);

    auto [selected, total_fees] = pool.get_sorted_txs_with_fees(BIG_WEIGHT);
    EXPECT_EQ(selected.size(), static_cast<size_t>(KNOWN));
    EXPECT_EQ(total_fees, known_fee_sum);
    for (const auto& s : selected) EXPECT_TRUE(s.fee_known);
}

// Fix (embedded DOGE path): Pass 2 fills the template with the unknown-fee
// backlog, resolving the UNDERFILL -- WITHOUT moving total_fees (coinbasevalue /
// gentx byte-identical). This is the regression pin.
TEST(DogeTemplateUnderfill, FillIncludesUnknownFeeBacklogWithoutMovingFees)
{
    Mempool pool;
    const uint64_t known_fee_sum = build_fixture(pool);

    auto [selected, total_fees] =
        pool.get_sorted_txs_with_fees(BIG_WEIGHT, /*fill_unknown_fee=*/true);
    EXPECT_EQ(selected.size(), static_cast<size_t>(TOTAL));   // all 35 packed
    EXPECT_EQ(total_fees, known_fee_sum);                     // fees UNCHANGED

    int known = 0, unknown = 0;
    for (const auto& s : selected) (s.fee_known ? known : unknown)++;
    EXPECT_EQ(known, KNOWN);
    EXPECT_EQ(unknown, UNKNOWN);
}

// Pass 2 still honors the weight budget (never overfills the block).
TEST(DogeTemplateUnderfill, FillRespectsWeightBudget)
{
    Mempool pool;
    build_fixture(pool);

    auto [full, full_fees] =
        pool.get_sorted_txs_with_fees(BIG_WEIGHT, /*fill_unknown_fee=*/true);
    (void)full_fees;
    ASSERT_EQ(full.size(), static_cast<size_t>(TOTAL));

    // A 1-weight budget fits nothing; selection must not exceed it.
    auto [capped, capped_fees] =
        pool.get_sorted_txs_with_fees(1u, /*fill_unknown_fee=*/true);
    (void)capped_fees;
    EXPECT_LT(capped.size(), static_cast<size_t>(TOTAL));
}
