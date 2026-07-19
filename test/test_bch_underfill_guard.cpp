// SPDX-License-Identifier: AGPL-3.0-or-later
/// BCH template-builder underfill guard — port of the LTC/DOGE guard
/// (src/impl/ltc/coin/template_builder.hpp / src/impl/doge/coin/
/// template_builder.hpp) to the BCH embedded template path
/// (src/impl/bch/coin/template_builder.hpp), mirroring the DASH KAT
/// (test/test_dash_underfill_guard.cpp).
///
/// What the guard defends against: the tx selector returning a near-empty
/// template (< UNDERFILL_MIN_FILL_BYTES packed) while the local mempool holds
/// a substantial fee-paying backlog (> selected + UNDERFILL_BACKLOG_SLACK
/// bytes with known fees > 0) — the "false-empty block on a non-empty
/// mempool" template-fill regression. Like LTC/DOGE it is LOG-ONLY
/// (WARNING): it never mutates the template, never blocks work.
///
/// Two axes, mirroring the LTC/DOGE guard semantics exactly:
///   (1) underfill_guard_trips() predicate KATs — the exact boolean the
///       LTC/DOGE guards evaluate, pinned at the thresholds/boundaries.
///   (2) TemplateBuilder::build_template() wiring — the guard evaluates over
///       the REAL Mempool queries (byte_size / total_fees) inside the
///       template build, observed via the SAFE-ADDITIVE trailing
///       `bool* underfill_tripped` seam (defaulted nullptr; no caller
///       changed). The trip scenario is produced through a genuine mempool
///       path: a fee-known bulk backlog whose inputs the selection-time
///       stale-input guard rejects — selection goes empty while the pool
///       still reports the fee-paying backlog. BCH specifics (ABLA floor
///       sizelimit, CTOR body) are asserted UNCHANGED when the guard trips
///       (additive-only).
///
/// Chain fixture: an in-memory HeaderChain seeded from a synthetic fast-start
/// checkpoint at H — the exact shape src/impl/bch/test/embedded_getwork_test.cpp
/// uses. H is far below the mainnet ASERT anchor (661'647), so build_template
/// takes its documented bits-fallback branch (synthetic seed bits=0 →
/// pow_limit); no ASERT math, no PoW to mine. build_template() is called
/// directly (not through EmbeddedCoinNode::getwork()), so the is_synced()
/// gate does not apply.

#include <gtest/gtest.h>

#include <impl/bch/coin/template_builder.hpp>
#include <impl/bch/coin/header_chain.hpp>
#include <impl/bch/coin/mempool.hpp>
#include <impl/bch/coin/transaction.hpp>
#include <impl/bch/coin/abla.hpp>

#include <core/uint256.hpp>
#include <core/coin/utxo_view_cache.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>

using bch::coin::BCHChainParams;
using bch::coin::HeaderChain;
using bch::coin::Mempool;
using bch::coin::MutableTransaction;
using bch::coin::TemplateBuilder;
using bch::coin::TxIn;
using bch::coin::TxOut;
using bch::coin::get_block_subsidy;
using bch::coin::underfill_guard_trips;
using bch::coin::UNDERFILL_MIN_FILL_BYTES;
using bch::coin::UNDERFILL_BACKLOG_SLACK;
using ::core::coin::UTXOViewCache;
using ::core::coin::Outpoint;
using ::core::coin::Coin;

// Fast-start checkpoint height, far below the mainnet ASERT anchor (661'647)
// → build_template stays on the bits-fallback branch (no ASERT walk).
static constexpr uint32_t H = 100'000;

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
// (BCH: single canonical serialization — no witness form.)
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

/// In-memory chain seeded from a synthetic fast-start checkpoint at H
/// (the embedded_getwork_test fixture shape; HeaderChain is non-copyable).
static std::unique_ptr<HeaderChain> make_checkpoint_chain() {
    BCHChainParams p = BCHChainParams::mainnet();
    p.fast_start_checkpoint = BCHChainParams::Checkpoint{H, raw256(0xC0)};
    auto chain = std::make_unique<HeaderChain>(p);
    EXPECT_TRUE(chain->init());
    return chain;
}

// ════════════════════════════════════════════════════════════════════════
// (1) Predicate KATs — the exact LTC/DOGE boolean, pinned at boundaries.
// ════════════════════════════════════════════════════════════════════════

TEST(BchUnderfillGuard, ThresholdsMatchTheCrossCoinPins) {
    // The v36-native shared thresholds — same values LTC/DOGE/DASH pin (the
    // legacy p2pool near-empty floor, ~50 kB). A drift here breaks cross-coin
    // standardization and must be a conscious, reviewed change.
    EXPECT_EQ(UNDERFILL_MIN_FILL_BYTES, 50'000ull);
    EXPECT_EQ(UNDERFILL_BACKLOG_SLACK,  50'000ull);
}

TEST(BchUnderfillGuard, TripsOnNearEmptyTemplateWithFeePayingBacklog) {
    // Nothing selected, 200 kB of fee-paying mempool → the regression shape.
    EXPECT_TRUE(underfill_guard_trips(/*selected=*/0,
                                      /*mempool=*/200'000,
                                      /*known_fees=*/1));
}

TEST(BchUnderfillGuard, EmptyMempoolNeverTrips) {
    // A genuinely empty mempool → an empty template is legitimate.
    EXPECT_FALSE(underfill_guard_trips(0, 0, 0));
}

TEST(BchUnderfillGuard, FeeUnknownBacklogNeverTrips) {
    // Bytes present but NO known fees (fee_known=false txs are excluded from
    // selection by design — they'd poison coinbasevalue). Not a regression.
    EXPECT_FALSE(underfill_guard_trips(0, 200'000, /*known_fees=*/0));
}

TEST(BchUnderfillGuard, WellFilledTemplateNeverTrips) {
    // At/above the near-empty floor the template is healthy regardless of
    // how much backlog remains (a full block on a deep mempool is normal).
    EXPECT_FALSE(underfill_guard_trips(UNDERFILL_MIN_FILL_BYTES,
                                       10'000'000, 5'000));
    EXPECT_TRUE(underfill_guard_trips(UNDERFILL_MIN_FILL_BYTES - 1,
                                      10'000'000, 5'000));
}

TEST(BchUnderfillGuard, SmallDrainedMempoolNeverTrips) {
    // Tiny mempool fully drained into the template: near-empty, but there is
    // no backlog beyond the slack — the guard must stay quiet.
    EXPECT_FALSE(underfill_guard_trips(/*selected=*/300,
                                       /*mempool=*/300,
                                       /*known_fees=*/100));
}

TEST(BchUnderfillGuard, BacklogSlackBoundaryIsStrict) {
    // has_backlog requires mempool_bytes STRICTLY > selected + slack —
    // mirrors the LTC/DOGE comparison operator exactly.
    EXPECT_FALSE(underfill_guard_trips(0, UNDERFILL_BACKLOG_SLACK,     1));
    EXPECT_TRUE (underfill_guard_trips(0, UNDERFILL_BACKLOG_SLACK + 1, 1));
}

// ════════════════════════════════════════════════════════════════════════
// (2) build_template wiring — real HeaderChain + Mempool, real build.
// ════════════════════════════════════════════════════════════════════════

TEST(BchUnderfillGuard, BuildTripsWhenSelectionGoesEmptyOnFeePayingBacklog) {
    auto chain = make_checkpoint_chain();

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
    ASSERT_TRUE(mp.get_sorted_txs_with_fees(8'000'000).first.empty())
        << "precondition: stale-input guard must empty the selection";

    bool tripped = false;
    auto wd = TemplateBuilder::build_template(*chain, mp, /*is_testnet=*/false,
                                              /*tip_state=*/nullptr, &tripped);
    ASSERT_TRUE(wd.has_value());
    EXPECT_TRUE(tripped)
        << "near-empty template on a fee-paying non-empty mempool must trip";

    // Guard is ADDITIVE (log-only): the BCH-specific projection is intact.
    EXPECT_TRUE(wd->m_data["transactions"].empty());
    EXPECT_EQ(wd->m_data["height"].get<int>(), static_cast<int>(H + 1));
    EXPECT_EQ(wd->m_data["coinbasevalue"].get<int64_t>(),
              static_cast<int64_t>(get_block_subsidy(H + 1)));  // no fees selected
    // ABLA floor budget untouched (no tracker wired → 32 MB activation floor).
    EXPECT_EQ(wd->m_data["sizelimit"].get<int64_t>(),
              static_cast<int64_t>(
                  bch::coin::abla::floor_block_size_limit(/*is_testnet=*/false)));
}

TEST(BchUnderfillGuard, BuildDoesNotTripOnEmptyMempool) {
    // Empty mempool → empty template is legitimate; guard stays quiet.
    auto chain = make_checkpoint_chain();
    Mempool mp;

    bool tripped = true;   // pre-set opposite to prove the seam writes false
    auto wd = TemplateBuilder::build_template(*chain, mp, /*is_testnet=*/false,
                                              /*tip_state=*/nullptr, &tripped);
    ASSERT_TRUE(wd.has_value());
    EXPECT_FALSE(tripped) << "an empty mempool must never trip the guard";
    EXPECT_TRUE(wd->m_data["transactions"].empty());
}

TEST(BchUnderfillGuard, BuildDoesNotTripWhenSmallPoolIsFullyDrained) {
    // One small fee-known tx, selected as normal: template is near-empty but
    // the pool is drained (no backlog beyond slack) → healthy, no trip.
    auto chain = make_checkpoint_chain();
    UTXOViewCache utxo(nullptr);
    uint256 prev = raw256(0x21);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));
    Mempool mp;
    ASSERT_TRUE(mp.add_tx(make_spend(prev, 0, 90'000, /*salt=*/2), &utxo));  // fee = 10'000

    bool tripped = true;
    auto wd = TemplateBuilder::build_template(*chain, mp, /*is_testnet=*/false,
                                              /*tip_state=*/nullptr, &tripped);
    ASSERT_TRUE(wd.has_value());
    EXPECT_FALSE(tripped) << "a fully drained small mempool must not trip";
    ASSERT_EQ(wd->m_data["transactions"].size(), 1u);   // the tx WAS selected
    EXPECT_EQ(wd->m_data["transactions"][0]["fee"].get<int64_t>(), 10'000);
    // BCH: no wtxid — "hash" must equal "txid" (guard did not disturb the
    // CTOR/serialization path).
    EXPECT_EQ(wd->m_data["transactions"][0]["hash"],
              wd->m_data["transactions"][0]["txid"]);
}

TEST(BchUnderfillGuard, DefaultSeamLeavesExistingCallersUnchanged) {
    // Omitting the trailing seam (every existing caller) builds the same
    // template as passing it — SAFE-ADDITIVE. curtime is wall-clock (no
    // injection seam on the BCH builder), so only time-independent fields
    // compare.
    auto chain = make_checkpoint_chain();
    UTXOViewCache utxo(nullptr);
    uint256 prev = raw256(0x31);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));
    Mempool mp;
    ASSERT_TRUE(mp.add_tx(make_spend(prev, 0, 90'000, /*salt=*/3), &utxo));

    auto legacy = TemplateBuilder::build_template(*chain, mp);
    bool tripped = true;
    auto seamed = TemplateBuilder::build_template(*chain, mp, /*is_testnet=*/false,
                                                  /*tip_state=*/nullptr, &tripped);
    ASSERT_TRUE(legacy.has_value());
    ASSERT_TRUE(seamed.has_value());
    EXPECT_FALSE(tripped);
    EXPECT_EQ(legacy->m_data["height"],            seamed->m_data["height"]);
    EXPECT_EQ(legacy->m_data["previousblockhash"], seamed->m_data["previousblockhash"]);
    EXPECT_EQ(legacy->m_data["bits"],              seamed->m_data["bits"]);
    EXPECT_EQ(legacy->m_data["version"],           seamed->m_data["version"]);
    EXPECT_EQ(legacy->m_data["coinbasevalue"],     seamed->m_data["coinbasevalue"]);
    EXPECT_EQ(legacy->m_data["sizelimit"],         seamed->m_data["sizelimit"]);
    EXPECT_EQ(legacy->m_data["mintime"],           seamed->m_data["mintime"]);
    EXPECT_EQ(legacy->m_data["transactions"],      seamed->m_data["transactions"]);
}
