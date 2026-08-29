// SPDX-License-Identifier: AGPL-3.0-or-later
/// DGB template-path underfill guard — port of the LTC/DOGE guard
/// (src/impl/ltc/coin/template_builder.hpp / src/impl/doge/coin/
/// template_builder.hpp) to the DGB embedded template path, mirroring the
/// DASH KAT (test/test_dash_underfill_guard.cpp).
///
/// DGB placement: dgb::coin::build_work_template() is a pure SHAPING function
/// with no mempool access (transactions[] is a caller-supplied pass-through),
/// so the guard evaluates in make_mempool_tx_source()
/// (coin/embedded_tx_select.cpp) — the ONE mempool-visible point that feeds
/// BOTH build_work_template callers (stratum DGBWorkSource +
/// EmbeddedCoinNode). Predicate + thresholds live in coin/template_builder.hpp
/// (underfill_guard_trips), identical to LTC/DOGE/DASH.
///
/// What the guard defends against: the tx selector returning a near-empty
/// selection (< UNDERFILL_MIN_FILL_BYTES packed) while the local mempool
/// holds a substantial fee-paying backlog (> selected +
/// UNDERFILL_BACKLOG_SLACK bytes with known fees > 0) — the "false-empty
/// block on a non-empty mempool" template-fill regression. Like LTC/DOGE it
/// is LOG-ONLY (WARNING): it never mutates the selection, never blocks work.
///
/// Two axes, mirroring the LTC/DOGE guard semantics exactly:
///   (1) underfill_guard_trips() predicate KATs — the exact boolean the
///       LTC/DOGE guards evaluate, pinned at the thresholds/boundaries.
///   (2) make_mempool_tx_source() wiring — the guard evaluates over the REAL
///       Mempool queries (byte_size / total_fees) inside the production
///       selection shaper, observed via the SAFE-ADDITIVE trailing
///       `bool* underfill_tripped` seam (defaulted nullptr; no caller
///       changed). The trip scenario is produced through a genuine mempool
///       path: a fee-known bulk backlog whose inputs the selection-time
///       stale-input guard rejects — selection goes empty while the pool
///       still reports the fee-paying backlog. The GBT selection shape
///       ({data,txid,hash,fee} + total_fees) is asserted UNCHANGED
///       (additive-only).

#include <gtest/gtest.h>

#include <impl/dgb/coin/embedded_tx_select.hpp>
#include <impl/dgb/coin/template_builder.hpp>
#include <impl/dgb/coin/mempool.hpp>
#include <impl/dgb/coin/transaction.hpp>

#include <core/uint256.hpp>
#include <core/coin/utxo_view_cache.hpp>

#include <array>
#include <cstdint>
#include <cstring>

using dgb::coin::EmbeddedTxSelection;
using dgb::coin::Mempool;
using dgb::coin::MutableTransaction;
using dgb::coin::TxIn;
using dgb::coin::TxOut;
using dgb::coin::make_mempool_tx_source;
using dgb::coin::underfill_guard_trips;
using dgb::coin::UNDERFILL_MIN_FILL_BYTES;
using dgb::coin::UNDERFILL_BACKLOG_SLACK;
using ::core::coin::UTXOViewCache;
using ::core::coin::Outpoint;
using ::core::coin::Coin;

// Selection budget — same figure the production callers pass
// (dgb::PoolConfig::BLOCK_MAX_WEIGHT; see template_other_txs_test.cpp).
static constexpr uint32_t MAX_WEIGHT = 4'000'000u;

// ─── helpers (mirrored from test_dash_underfill_guard.cpp) ──────────────────

static uint256 raw256(uint8_t base) {
    uint256 h;
    std::array<uint8_t, 32> p{};
    for (size_t i = 0; i < 32; ++i) p[i] = static_cast<uint8_t>(base + i);
    std::memcpy(h.data(), p.data(), 32);
    return h;
}

static MutableTransaction make_spend(const uint256& prev, uint32_t idx,
                                     int64_t out_value, uint32_t salt) {
    MutableTransaction tx;
    tx.version = 2; tx.locktime = salt;
    TxIn in; in.prevout.hash = prev; in.prevout.index = idx;
    in.sequence = 0xffffffffu;
    tx.vin.push_back(in);
    TxOut o; o.value = out_value;
    tx.vout.push_back(o);
    return tx;
}

// A deliberately BULKY spend: one funded input, n_outputs zero-value
// empty-script outputs (~9 wire bytes each). Zero-value outputs make the
// whole input a KNOWN fee, and the output fan inflates the serialized size
// past the near-empty floor without needing thousands of separate txs.
static MutableTransaction make_bulk_spend(const uint256& prev, uint32_t idx,
                                          size_t n_outputs, uint32_t salt) {
    MutableTransaction tx;
    tx.version = 2; tx.locktime = salt;
    TxIn in; in.prevout.hash = prev; in.prevout.index = idx;
    in.sequence = 0xffffffffu;
    tx.vin.push_back(in);
    tx.vout.reserve(n_outputs);
    for (size_t i = 0; i < n_outputs; ++i) {
        TxOut o; o.value = 0;       // zero-value → entire input value is fee
        tx.vout.push_back(o);
    }
    return tx;
}

// ════════════════════════════════════════════════════════════════════════
// (1) Predicate KATs — the exact LTC/DOGE boolean, pinned at boundaries.
// ════════════════════════════════════════════════════════════════════════

TEST(DgbUnderfillGuard, ThresholdsMatchTheCrossCoinPins) {
    // The v36-native shared thresholds — same values LTC/DOGE/DASH pin (the
    // legacy p2pool near-empty floor, ~50 kB). A drift here breaks cross-coin
    // standardization and must be a conscious, reviewed change.
    EXPECT_EQ(UNDERFILL_MIN_FILL_BYTES, 50'000ull);
    EXPECT_EQ(UNDERFILL_BACKLOG_SLACK,  50'000ull);
}

TEST(DgbUnderfillGuard, TripsOnNearEmptyTemplateWithFeePayingBacklog) {
    // Nothing selected, 200 kB of fee-paying mempool → the regression shape.
    EXPECT_TRUE(underfill_guard_trips(/*selected=*/0,
                                      /*mempool=*/200'000,
                                      /*known_fees=*/1));
}

TEST(DgbUnderfillGuard, EmptyMempoolNeverTrips) {
    // A genuinely empty mempool → an empty template is legitimate.
    EXPECT_FALSE(underfill_guard_trips(0, 0, 0));
}

TEST(DgbUnderfillGuard, FeeUnknownBacklogNeverTrips) {
    // Bytes present but NO known fees (fee_known=false txs are excluded from
    // selection by design — they'd poison coinbasevalue). Not a regression.
    EXPECT_FALSE(underfill_guard_trips(0, 200'000, /*known_fees=*/0));
}

TEST(DgbUnderfillGuard, WellFilledTemplateNeverTrips) {
    // At/above the near-empty floor the template is healthy regardless of
    // how much backlog remains (a full block on a deep mempool is normal).
    EXPECT_FALSE(underfill_guard_trips(UNDERFILL_MIN_FILL_BYTES,
                                       10'000'000, 5'000));
    EXPECT_TRUE(underfill_guard_trips(UNDERFILL_MIN_FILL_BYTES - 1,
                                      10'000'000, 5'000));
}

TEST(DgbUnderfillGuard, SmallDrainedMempoolNeverTrips) {
    // Tiny mempool fully drained into the template: near-empty, but there is
    // no backlog beyond the slack — the guard must stay quiet.
    EXPECT_FALSE(underfill_guard_trips(/*selected=*/300,
                                       /*mempool=*/300,
                                       /*known_fees=*/100));
}

TEST(DgbUnderfillGuard, BacklogSlackBoundaryIsStrict) {
    // has_backlog requires mempool_bytes STRICTLY > selected + slack —
    // mirrors the LTC/DOGE comparison operator exactly.
    EXPECT_FALSE(underfill_guard_trips(0, UNDERFILL_BACKLOG_SLACK,     1));
    EXPECT_TRUE (underfill_guard_trips(0, UNDERFILL_BACKLOG_SLACK + 1, 1));
}

// ════════════════════════════════════════════════════════════════════════
// (2) make_mempool_tx_source wiring — real Mempool, real production shaper.
// ════════════════════════════════════════════════════════════════════════

TEST(DgbUnderfillGuard, SourceTripsWhenSelectionGoesEmptyOnFeePayingBacklog) {
    // Seed a funded UTXO so the bulk tx enters the pool with a KNOWN fee
    // (1'000'000 sat — all outputs zero-value) and lands in the feerate index.
    UTXOViewCache funded(nullptr);
    uint256 prev = raw256(0x66);
    funded.add_coin(Outpoint(prev, 0),
                    Coin(1'000'000, {}, /*height=*/1, /*cb=*/false));
    Mempool mp;
    // ~9 wire bytes per zero-value empty-script output → 12'000 outputs
    // (~108 kB) is comfortably past floor+slack. Assert instead of assuming.
    auto bulk = make_bulk_spend(prev, 0, /*n_outputs=*/12'000, /*salt=*/1);
    ASSERT_TRUE(mp.add_tx(bulk, &funded));
    ASSERT_GT(mp.byte_size(), UNDERFILL_MIN_FILL_BYTES + UNDERFILL_BACKLOG_SLACK);
    ASSERT_GT(mp.total_fees(), 0u);

    // Now wire an EMPTY UTXO view: get_sorted_txs_with_fees()'s stale-input
    // guard rejects the tx (input not in UTXO, no parent in pool) → selection
    // returns NOTHING while byte_size()/total_fees() still report the
    // fee-paying backlog. This reproduces the tip-change/stale-window shape
    // of the template-fill regression.
    UTXOViewCache empty(nullptr);
    mp.set_utxo(&empty);
    ASSERT_TRUE(mp.get_sorted_txs_with_fees(MAX_WEIGHT).first.empty())
        << "precondition: stale-input guard must empty the selection";

    bool tripped = false;
    EmbeddedTxSelection sel = make_mempool_tx_source(mp, MAX_WEIGHT, &tripped)();

    EXPECT_TRUE(tripped)
        << "near-empty selection on a fee-paying non-empty mempool must trip";

    // Guard is ADDITIVE (log-only): the selection shape is intact.
    EXPECT_TRUE(sel.transactions.empty());
    EXPECT_EQ(sel.total_fees, 0u);   // nothing selected → nothing folded
}

TEST(DgbUnderfillGuard, SourceDoesNotTripOnEmptyMempool) {
    // Empty mempool → empty selection is legitimate; guard stays quiet.
    Mempool mp;

    bool tripped = true;   // pre-set opposite to prove the seam writes false
    EmbeddedTxSelection sel = make_mempool_tx_source(mp, MAX_WEIGHT, &tripped)();

    EXPECT_FALSE(tripped) << "an empty mempool must never trip the guard";
    EXPECT_TRUE(sel.transactions.empty());
    EXPECT_EQ(sel.total_fees, 0u);
}

TEST(DgbUnderfillGuard, SourceDoesNotTripWhenSmallPoolIsFullyDrained) {
    // One small fee-known tx, selected as normal: selection is near-empty but
    // the pool is drained (no backlog beyond slack) → healthy, no trip.
    UTXOViewCache utxo(nullptr);
    uint256 prev = raw256(0x21);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));
    Mempool mp;
    ASSERT_TRUE(mp.add_tx(make_spend(prev, 0, 90'000, /*salt=*/2), &utxo));  // fee = 10'000

    bool tripped = true;
    EmbeddedTxSelection sel = make_mempool_tx_source(mp, MAX_WEIGHT, &tripped)();

    EXPECT_FALSE(tripped) << "a fully drained small mempool must not trip";
    ASSERT_EQ(sel.transactions.size(), 1u);      // the tx WAS selected
    EXPECT_EQ(sel.total_fees, 10'000u);
    // The GBT entry shape build_work_template passes through verbatim.
    EXPECT_TRUE(sel.transactions[0].contains("data"));
    EXPECT_TRUE(sel.transactions[0].contains("txid"));
    EXPECT_TRUE(sel.transactions[0].contains("hash"));
    EXPECT_EQ(sel.transactions[0]["fee"].get<int64_t>(), 10'000);
}

TEST(DgbUnderfillGuard, DefaultSeamLeavesExistingCallersUnchanged) {
    // Omitting the trailing seam (every existing caller: main_dgb.cpp +
    // stratum work_source.cpp) yields the exact same selection as passing
    // it — SAFE-ADDITIVE, field-for-field.
    UTXOViewCache utxo(nullptr);
    uint256 prev = raw256(0x31);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));
    Mempool mp;
    ASSERT_TRUE(mp.add_tx(make_spend(prev, 0, 90'000, /*salt=*/3), &utxo));

    EmbeddedTxSelection legacy = make_mempool_tx_source(mp, MAX_WEIGHT)();
    bool tripped = true;
    EmbeddedTxSelection seamed = make_mempool_tx_source(mp, MAX_WEIGHT, &tripped)();

    EXPECT_FALSE(tripped);
    EXPECT_EQ(legacy.total_fees,   seamed.total_fees);
    EXPECT_EQ(legacy.transactions, seamed.transactions);
}
