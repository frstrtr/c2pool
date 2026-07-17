// SPDX-License-Identifier: AGPL-3.0-or-later
/// NMC template-builder underfill guard — port of the LTC/DOGE guard
/// (src/impl/ltc/coin/template_builder.hpp / src/impl/doge/coin/
/// template_builder.hpp) to the NMC embedded template path
/// (src/impl/nmc/coin/template_builder.hpp), mirroring the BTC KAT
/// (test/test_btc_underfill_guard.cpp) and the DASH KAT
/// (test/test_dash_underfill_guard.cpp).
///
/// What the guard defends against: the tx selector returning a near-empty
/// template (< UNDERFILL_MIN_FILL_BYTES packed) while the local mempool holds
/// a substantial fee-paying backlog (> selected + UNDERFILL_BACKLOG_SLACK
/// bytes with known fees > 0) — the "false-empty block on a non-empty
/// mempool" template-fill regression. Like LTC/DOGE/BTC it is LOG-ONLY
/// (WARNING): it never mutates the template, never blocks work. NMC is BTC's
/// merge-mined aux child, so a near-empty aux block does not waste parent PoW
/// (severity LOW) — this KAT completes the all-coin underfill matrix.
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
///       still reports the fee-paying backlog. The NMC template projection
///       (height / coinbasevalue / GBT shape) is asserted UNCHANGED when the
///       guard trips (additive-only).
///
/// Chain fixture: the seeded in-memory HeaderChain the sibling
/// nmc_template_builder_test uses (genesis + one child header, tip height 1,
/// bits 0x1d00ffff → no retarget, no fallback). build_template() is called
/// directly (not through EmbeddedCoinNode::getwork()), so the is_synced()
/// gate does not apply.
///
/// Per-coin isolation: src/impl/nmc/ only; btc tree consumed READ-ONLY.
/// Compiled INTO the already-allowlisted nmc_template_builder_test target
/// (second source — gtest_add_tests AUTO scans all target sources), so the
/// build.yml --target allowlist needs no edit; a NEW target absent from that
/// allowlist would red master as a NOT_BUILT sentinel (the #724/#728 lesson).

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <memory>

#include <core/uint256.hpp>
#include <core/coin/utxo_view_cache.hpp>

#include "../coin/header_chain.hpp"
#include "../coin/mempool.hpp"
#include "../coin/template_builder.hpp"
#include "../coin/transaction.hpp"

namespace {

using nmc::coin::BlockHeaderType;
using nmc::coin::HeaderChain;
using nmc::coin::Mempool;
using nmc::coin::MutableTransaction;
using nmc::coin::NMCChainParams;
using nmc::coin::TemplateBuilder;
using nmc::coin::TxIn;
using nmc::coin::TxOut;
using nmc::coin::block_hash;
using nmc::coin::get_block_subsidy;
using nmc::coin::underfill_guard_trips;
using nmc::coin::UNDERFILL_MIN_FILL_BYTES;
using nmc::coin::UNDERFILL_BACKLOG_SLACK;
using ::core::coin::UTXOViewCache;
using ::core::coin::Outpoint;
using ::core::coin::Coin;

// ─── helpers (mirrored from test_btc_underfill_guard.cpp) ───────────────────

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

static BlockHeaderType plain_header(const uint256& prev, uint32_t bits,
                                    uint32_t nonce, uint32_t ts) {
    BlockHeaderType h{};
    h.m_version        = 1;
    h.m_previous_block = prev;
    h.m_bits           = bits;
    h.m_nonce          = nonce;
    h.m_timestamp      = ts;
    return h;
}

/// Seeded in-memory chain: genesis + one child header (tip height 1 → the
/// template builds for height 2). Same fixture shape as the sibling
/// nmc_template_builder_test SeededChainYieldsWorkData (HeaderChain is
/// non-copyable → unique_ptr, like the BTC KAT fixture).
static std::unique_ptr<HeaderChain> make_seeded_chain() {
    NMCChainParams p = NMCChainParams::mainnet();
    p.aux_chain_id = 1;
    p.auxpow_activation_height = 19200;  // TEST-only pin (plain headers admit)
    auto chain = std::make_unique<HeaderChain>(p);
    auto now = static_cast<uint32_t>(std::time(nullptr));
    uint256 z; z.SetNull();
    BlockHeaderType g = plain_header(z, 0x1d00ffffu, 1, now - 100);
    EXPECT_TRUE(chain->add_header(g));
    BlockHeaderType c = plain_header(block_hash(g), 0x1d00ffffu, 2, now - 50);
    EXPECT_TRUE(chain->add_header(c));
    EXPECT_EQ(chain->height(), 1u);
    return chain;
}

// ════════════════════════════════════════════════════════════════════════
// (1) Predicate KATs — the exact LTC/DOGE boolean, pinned at boundaries.
// ════════════════════════════════════════════════════════════════════════

TEST(NmcUnderfillGuard, ThresholdsMatchTheCrossCoinPins) {
    // The v36-native shared thresholds — same values LTC/DOGE/DASH/BTC pin
    // (the legacy p2pool near-empty floor, ~50 kB). A drift here breaks
    // cross-coin standardization and must be a conscious, reviewed change.
    EXPECT_EQ(UNDERFILL_MIN_FILL_BYTES, 50'000ull);
    EXPECT_EQ(UNDERFILL_BACKLOG_SLACK,  50'000ull);
}

TEST(NmcUnderfillGuard, TripsOnNearEmptyTemplateWithFeePayingBacklog) {
    // Nothing selected, 200 kB of fee-paying mempool → the regression shape.
    EXPECT_TRUE(underfill_guard_trips(/*selected=*/0,
                                      /*mempool=*/200'000,
                                      /*known_fees=*/1));
}

TEST(NmcUnderfillGuard, EmptyMempoolNeverTrips) {
    // A genuinely empty mempool → an empty template is legitimate.
    EXPECT_FALSE(underfill_guard_trips(0, 0, 0));
}

TEST(NmcUnderfillGuard, FeeUnknownBacklogNeverTrips) {
    // Bytes present but NO known fees (fee_known=false txs are excluded from
    // selection by design — they'd poison coinbasevalue). Not a regression.
    EXPECT_FALSE(underfill_guard_trips(0, 200'000, /*known_fees=*/0));
}

TEST(NmcUnderfillGuard, WellFilledTemplateNeverTrips) {
    // At/above the near-empty floor the template is healthy regardless of
    // how much backlog remains (a full block on a deep mempool is normal).
    EXPECT_FALSE(underfill_guard_trips(UNDERFILL_MIN_FILL_BYTES,
                                       10'000'000, 5'000));
    EXPECT_TRUE(underfill_guard_trips(UNDERFILL_MIN_FILL_BYTES - 1,
                                      10'000'000, 5'000));
}

TEST(NmcUnderfillGuard, SmallDrainedMempoolNeverTrips) {
    // Tiny mempool fully drained into the template: near-empty, but there is
    // no backlog beyond the slack — the guard must stay quiet.
    EXPECT_FALSE(underfill_guard_trips(/*selected=*/300,
                                       /*mempool=*/300,
                                       /*known_fees=*/100));
}

TEST(NmcUnderfillGuard, BacklogSlackBoundaryIsStrict) {
    // has_backlog requires mempool_bytes STRICTLY > selected + slack —
    // mirrors the LTC/DOGE comparison operator exactly.
    EXPECT_FALSE(underfill_guard_trips(0, UNDERFILL_BACKLOG_SLACK,     1));
    EXPECT_TRUE (underfill_guard_trips(0, UNDERFILL_BACKLOG_SLACK + 1, 1));
}

// ════════════════════════════════════════════════════════════════════════
// (2) build_template wiring — real HeaderChain + Mempool, real build.
// ════════════════════════════════════════════════════════════════════════

TEST(NmcUnderfillGuard, BuildTripsWhenSelectionGoesEmptyOnFeePayingBacklog) {
    auto chain = make_seeded_chain();

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
    ASSERT_TRUE(mp.get_sorted_txs_with_fees(4'000'000).first.empty())
        << "precondition: stale-input guard must empty the selection";

    bool tripped = false;
    auto wd = TemplateBuilder::build_template(*chain, mp,
                                              /*is_testnet=*/false, &tripped);
    ASSERT_TRUE(wd.has_value());
    EXPECT_TRUE(tripped)
        << "near-empty template on a fee-paying non-empty mempool must trip";

    // Guard is ADDITIVE (log-only): the GBT projection is intact.
    EXPECT_TRUE(wd->m_data["transactions"].empty());
    EXPECT_EQ(wd->m_data["height"].get<int>(), 2);
    EXPECT_EQ(wd->m_data["coinbasevalue"].get<int64_t>(),
              static_cast<int64_t>(get_block_subsidy(2u)));  // no fees selected
}

TEST(NmcUnderfillGuard, BuildDoesNotTripOnEmptyMempool) {
    // Empty mempool → empty template is legitimate; guard stays quiet.
    auto chain = make_seeded_chain();
    Mempool mp;

    bool tripped = true;   // pre-set opposite to prove the seam writes false
    auto wd = TemplateBuilder::build_template(*chain, mp,
                                              /*is_testnet=*/false, &tripped);
    ASSERT_TRUE(wd.has_value());
    EXPECT_FALSE(tripped) << "an empty mempool must never trip the guard";
    EXPECT_TRUE(wd->m_data["transactions"].empty());
}

TEST(NmcUnderfillGuard, BuildDoesNotTripWhenSmallPoolIsFullyDrained) {
    // One small fee-known tx, selected as normal: template is near-empty but
    // the pool is drained (no backlog beyond slack) → healthy, no trip.
    auto chain = make_seeded_chain();
    UTXOViewCache utxo(nullptr);
    uint256 prev = raw256(0x21);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));
    Mempool mp;
    ASSERT_TRUE(mp.add_tx(make_spend(prev, 0, 90'000, /*salt=*/2), &utxo));  // fee = 10'000
    mp.set_utxo(&utxo);

    bool tripped = true;
    auto wd = TemplateBuilder::build_template(*chain, mp,
                                              /*is_testnet=*/false, &tripped);
    ASSERT_TRUE(wd.has_value());
    EXPECT_FALSE(tripped) << "a fully drained small mempool must not trip";
    ASSERT_EQ(wd->m_data["transactions"].size(), 1u);   // the tx WAS selected
    EXPECT_EQ(wd->m_data["transactions"][0]["fee"].get<int64_t>(), 10'000);
}

TEST(NmcUnderfillGuard, DefaultSeamLeavesExistingCallersUnchanged) {
    // Omitting the trailing seam (every existing caller) builds the same
    // template as passing it — SAFE-ADDITIVE. curtime is wall-clock (no
    // injection seam on the NMC builder), so only time-independent fields
    // compare.
    auto chain = make_seeded_chain();
    UTXOViewCache utxo(nullptr);
    uint256 prev = raw256(0x31);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));
    Mempool mp;
    ASSERT_TRUE(mp.add_tx(make_spend(prev, 0, 90'000, /*salt=*/3), &utxo));
    mp.set_utxo(&utxo);

    auto legacy = TemplateBuilder::build_template(*chain, mp);
    bool tripped = true;
    auto seamed = TemplateBuilder::build_template(*chain, mp,
                                                  /*is_testnet=*/false, &tripped);
    ASSERT_TRUE(legacy.has_value());
    ASSERT_TRUE(seamed.has_value());
    EXPECT_FALSE(tripped);
    EXPECT_EQ(legacy->m_data["height"],            seamed->m_data["height"]);
    EXPECT_EQ(legacy->m_data["previousblockhash"], seamed->m_data["previousblockhash"]);
    EXPECT_EQ(legacy->m_data["bits"],              seamed->m_data["bits"]);
    EXPECT_EQ(legacy->m_data["version"],           seamed->m_data["version"]);
    EXPECT_EQ(legacy->m_data["coinbasevalue"],     seamed->m_data["coinbasevalue"]);
    EXPECT_EQ(legacy->m_data["mintime"],           seamed->m_data["mintime"]);
    EXPECT_EQ(legacy->m_data["transactions"],      seamed->m_data["transactions"]);
}

}  // namespace
