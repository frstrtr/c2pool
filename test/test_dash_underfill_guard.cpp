// SPDX-License-Identifier: AGPL-3.0-or-later
/// DASH template-builder underfill guard — port of the LTC/DOGE guard
/// (src/impl/ltc/coin/template_builder.hpp / src/impl/doge/coin/
/// template_builder.hpp) to the DASH embedded GBT path (embedded_gbt.hpp),
/// for the mining-hotel deployment.
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
///   (2) build_embedded_workdata() wiring — the guard evaluates over the
///       REAL Mempool queries (byte_size / total_known_fees) inside the
///       template build, observed via the SAFE-ADDITIVE trailing
///       `bool* underfill_tripped` seam (defaulted nullptr; no caller
///       changed). The trip scenario is produced through a genuine
///       mempool path: fee-known bulk backlog whose inputs the
///       stale-input guard rejects at selection time — selection goes
///       empty while the pool still reports the fee-paying backlog.
///       DASH specifics (platform burn / MN payee projection) are
///       asserted UNCHANGED when the guard trips (additive-only).
///
/// Setup helpers mirror test_dash_embedded_gbt.cpp so the fixture semantics
/// stay identical to the capstone KAT.

#include <gtest/gtest.h>

#include <impl/dash/coin/embedded_gbt.hpp>
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/subsidy.hpp>
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

using dash::coin::DashWorkData;
using dash::coin::MNState;
using dash::coin::MnStateMachine;
using dash::coin::Mempool;
using dash::coin::MutableTransaction;
using dash::coin::build_embedded_workdata;
using dash::coin::underfill_guard_trips;
using dash::coin::UNDERFILL_MIN_FILL_BYTES;
using dash::coin::UNDERFILL_BACKLOG_SLACK;
using dash::coin::compute_dash_block_reward_post_v20;
using dash::coin::compute_dash_mn_payment_post_v20;
using dash::coin::compute_dash_platform_reward_post_v20_mn_rr;
using ::core::coin::UTXOViewCache;
using ::core::coin::Outpoint;
using ::core::coin::Coin;
using ::bitcoin_family::coin::TxIn;
using ::bitcoin_family::coin::TxOut;

// Dash mainnet base58 version bytes (chainparams.cpp PUBKEY_ADDRESS=76,
// SCRIPT_ADDRESS=16) — same pins as test_dash_embedded_gbt.cpp.
static constexpr uint8_t DASH_PUBKEY_VER = 76;
static constexpr uint8_t DASH_P2SH_VER   = 16;

// Past V20 + MN_RR so the platform burn is active (mainnet steady state).
static constexpr uint32_t H = 2'400'000;

// ─── helpers (mirrored from test_dash_embedded_gbt.cpp) ─────────────────────

static uint256 raw256(uint8_t base) {
    uint256 h;
    std::array<uint8_t, 32> p{};
    for (size_t i = 0; i < 32; ++i) p[i] = static_cast<uint8_t>(base + i);
    std::memcpy(h.data(), p.data(), 32);
    return h;
}

static std::vector<unsigned char> p2pkh_script(uint8_t hashseed) {
    std::vector<unsigned char> s;
    s.push_back(0x76);              // OP_DUP
    s.push_back(0xa9);              // OP_HASH160
    s.push_back(0x14);              // push 20
    for (int i = 0; i < 20; ++i) s.push_back(static_cast<unsigned char>(hashseed + i));
    s.push_back(0x88);              // OP_EQUALVERIFY
    s.push_back(0xac);              // OP_CHECKSIG
    return s;
}

static uint256 mint_hash(uint32_t seed) {
    MutableTransaction t;
    t.version = 1; t.type = 0;
    t.locktime = 0x51000000u ^ seed;
    auto ps = ::pack(t);
    return ::Hash(ps.get_span());
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

// A deliberately BULKY spend: one funded input, n_outputs zero-value
// empty-script outputs (~9 wire bytes each). Zero-value outputs make the
// whole input a KNOWN fee, and the output fan inflates base_size past the
// near-empty floor without needing thousands of separate txs.
static MutableTransaction make_bulk_spend(const uint256& prev, uint32_t idx,
                                          size_t n_outputs, uint32_t salt) {
    MutableTransaction tx;
    tx.version = 1; tx.type = 0; tx.locktime = salt;
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

static MnStateMachine single_mn(const std::vector<unsigned char>& payout) {
    MNState s;
    s.isValid = true;
    s.nRegisteredHeight = 2'300'000;
    s.nLastPaidHeight = 0;
    s.scriptPayout.m_data = payout;
    MnStateMachine m;
    m.load(std::vector<std::pair<uint256, MNState>>{{raw256(0x01), s}});
    return m;
}

// ════════════════════════════════════════════════════════════════════════
// (1) Predicate KATs — the exact LTC/DOGE boolean, pinned at boundaries.
// ════════════════════════════════════════════════════════════════════════

TEST(DashUnderfillGuard, ThresholdsMatchTheCrossCoinPins) {
    // The v36-native shared thresholds — same values LTC/DOGE pin (the legacy
    // p2pool near-empty floor, ~50 kB). A drift here breaks cross-coin
    // standardization and must be a conscious, reviewed change.
    EXPECT_EQ(UNDERFILL_MIN_FILL_BYTES, 50'000ull);
    EXPECT_EQ(UNDERFILL_BACKLOG_SLACK,  50'000ull);
}

TEST(DashUnderfillGuard, TripsOnNearEmptyTemplateWithFeePayingBacklog) {
    // Nothing selected, 200 kB of fee-paying mempool → the regression shape.
    EXPECT_TRUE(underfill_guard_trips(/*selected=*/0,
                                      /*mempool=*/200'000,
                                      /*known_fees=*/1));
}

TEST(DashUnderfillGuard, EmptyMempoolNeverTrips) {
    // A genuinely empty mempool → an empty template is legitimate.
    EXPECT_FALSE(underfill_guard_trips(0, 0, 0));
}

TEST(DashUnderfillGuard, FeeUnknownBacklogNeverTrips) {
    // Bytes present but NO known fees (fee_known=false txs are excluded from
    // selection by design — they'd poison coinbasevalue). Not a regression.
    EXPECT_FALSE(underfill_guard_trips(0, 200'000, /*known_fees=*/0));
}

TEST(DashUnderfillGuard, WellFilledTemplateNeverTrips) {
    // At/above the near-empty floor the template is healthy regardless of
    // how much backlog remains (a full block on a deep mempool is normal).
    EXPECT_FALSE(underfill_guard_trips(UNDERFILL_MIN_FILL_BYTES,
                                       10'000'000, 5'000));
    EXPECT_TRUE(underfill_guard_trips(UNDERFILL_MIN_FILL_BYTES - 1,
                                      10'000'000, 5'000));
}

TEST(DashUnderfillGuard, SmallDrainedMempoolNeverTrips) {
    // Tiny mempool fully drained into the template: near-empty, but there is
    // no backlog beyond the slack — the guard must stay quiet.
    EXPECT_FALSE(underfill_guard_trips(/*selected=*/300,
                                       /*mempool=*/300,
                                       /*known_fees=*/100));
}

TEST(DashUnderfillGuard, BacklogSlackBoundaryIsStrict) {
    // has_backlog requires mempool_bytes STRICTLY > selected + slack —
    // mirrors the LTC/DOGE comparison operator exactly.
    EXPECT_FALSE(underfill_guard_trips(0, UNDERFILL_BACKLOG_SLACK,     1));
    EXPECT_TRUE (underfill_guard_trips(0, UNDERFILL_BACKLOG_SLACK + 1, 1));
}

// ════════════════════════════════════════════════════════════════════════
// (2) build_embedded_workdata wiring — real Mempool, real template build.
// ════════════════════════════════════════════════════════════════════════

TEST(DashUnderfillGuard, BuildTripsWhenSelectionGoesEmptyOnFeePayingBacklog) {
    // Seed a funded UTXO so the bulk tx enters the pool with a KNOWN fee
    // (1'000'000 sat — all outputs zero-value) and lands in the feerate index.
    UTXOViewCache funded(nullptr);
    uint256 prev = mint_hash(101);
    funded.add_coin(Outpoint(prev, 0),
                    Coin(1'000'000, {}, /*height=*/1, /*cb=*/false));
    Mempool mp;
    mp.set_utxo(&funded);
    // ~9 wire bytes per zero-value empty-script output → 12'000 outputs
    // (~108 kB) is comfortably past floor+slack. Assert instead of assuming.
    auto bulk = make_bulk_spend(prev, 0, /*n_outputs=*/12'000, /*salt=*/1);
    ASSERT_TRUE(mp.add_tx(bulk));
    ASSERT_GT(mp.byte_size(), UNDERFILL_MIN_FILL_BYTES + UNDERFILL_BACKLOG_SLACK);
    ASSERT_GT(mp.total_known_fees(), 0u);

    // Now swap in an EMPTY UTXO view: get_sorted_txs_with_fees()'s
    // stale-input guard rejects the tx (input not in UTXO, no parent in
    // pool) → selection returns NOTHING while byte_size()/total_known_fees()
    // still report the fee-paying backlog. This reproduces the
    // tip-change/stale-window shape of the template-fill regression.
    UTXOViewCache empty(nullptr);
    mp.set_utxo(&empty);
    ASSERT_TRUE(mp.get_sorted_txs_with_fees(1'990'000).first.empty())
        << "precondition: stale-input guard must empty the selection";

    auto payout   = p2pkh_script(0x30);
    auto mnstates = single_mn(payout);

    bool tripped = false;
    auto w = build_embedded_workdata(
        H - 1, raw256(0xAB), mnstates, mp,
        /*bits=*/0x1b104be3u, /*mtp=*/1'700'000'000u,
        DASH_PUBKEY_VER, DASH_P2SH_VER,
        /*curtime=*/1'700'000'123u, /*version=*/0x20000000u, &tripped);

    EXPECT_TRUE(tripped)
        << "near-empty template on a fee-paying non-empty mempool must trip";

    // Guard is ADDITIVE (log-only): the DASH-specific projection is intact.
    EXPECT_TRUE(w.m_txs.empty());
    int64_t reward          = compute_dash_block_reward_post_v20(H);
    int64_t platform_reward = compute_dash_platform_reward_post_v20_mn_rr(H);
    int64_t mn_payment      = compute_dash_mn_payment_post_v20(reward)
                              - platform_reward;
    EXPECT_EQ(w.m_coinbase_value, static_cast<uint64_t>(reward));  // no fees selected
    ASSERT_EQ(w.m_packed_payments.size(), 2u);                     // burn + MN payee
    EXPECT_EQ(w.m_packed_payments[0].payee, "!6a");                // DIP-0027 burn first
    EXPECT_EQ(w.m_packed_payments[0].amount,
              static_cast<uint64_t>(platform_reward));
    EXPECT_EQ(w.m_packed_payments[1].amount,
              static_cast<uint64_t>(mn_payment));
}

TEST(DashUnderfillGuard, BuildDoesNotTripOnEmptyMempool) {
    // Empty mempool → empty template is legitimate; guard stays quiet.
    Mempool mp;
    auto payout   = p2pkh_script(0x40);
    auto mnstates = single_mn(payout);

    bool tripped = true;   // pre-set opposite to prove the seam writes false
    auto w = build_embedded_workdata(
        H - 1, raw256(0x10), mnstates, mp,
        0x1b104be3u, 1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER,
        1'700'000'123u, 0x20000000u, &tripped);

    EXPECT_FALSE(tripped) << "an empty mempool must never trip the guard";
    EXPECT_TRUE(w.m_txs.empty());
    ASSERT_EQ(w.m_packed_payments.size(), 2u);   // projection unchanged
}

TEST(DashUnderfillGuard, BuildDoesNotTripWhenSmallPoolIsFullyDrained) {
    // One small fee-known tx, selected as normal: template is near-empty but
    // the pool is drained (no backlog beyond slack) → healthy, no trip.
    UTXOViewCache utxo(nullptr);
    uint256 prev = mint_hash(102);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));
    Mempool mp;
    mp.set_utxo(&utxo);
    auto tx = make_spend(prev, 0, 90'000, /*salt=*/2);   // fee = 10'000
    ASSERT_TRUE(mp.add_tx(tx));

    auto payout   = p2pkh_script(0x50);
    auto mnstates = single_mn(payout);

    bool tripped = true;
    auto w = build_embedded_workdata(
        H - 1, raw256(0x20), mnstates, mp,
        0x1b104be3u, 1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER,
        1'700'000'123u, 0x20000000u, &tripped);

    EXPECT_FALSE(tripped) << "a fully drained small mempool must not trip";
    ASSERT_EQ(w.m_txs.size(), 1u);               // the tx WAS selected
    EXPECT_EQ(w.m_tx_fees[0], 10'000u);
}

TEST(DashUnderfillGuard, DefaultSeamLeavesExistingCallersUnchanged) {
    // Omitting the trailing seam (every existing caller) builds the exact
    // same template as passing it — SAFE-ADDITIVE, field-for-field.
    UTXOViewCache utxo(nullptr);
    uint256 prev = mint_hash(103);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));
    Mempool mp;
    mp.set_utxo(&utxo);
    ASSERT_TRUE(mp.add_tx(make_spend(prev, 0, 90'000, /*salt=*/3)));

    auto payout   = p2pkh_script(0x55);
    auto mnstates = single_mn(payout);
    const uint32_t PINNED_CURTIME = 1'700'000'123u;

    auto legacy = build_embedded_workdata(
        H - 1, raw256(0x60), mnstates, mp,
        0x1b104be3u, 1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER,
        PINNED_CURTIME);
    bool tripped = true;
    auto seamed = build_embedded_workdata(
        H - 1, raw256(0x60), mnstates, mp,
        0x1b104be3u, 1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER,
        PINNED_CURTIME, 0x20000000u, &tripped);

    EXPECT_FALSE(tripped);
    EXPECT_EQ(legacy.m_height,          seamed.m_height);
    EXPECT_EQ(legacy.m_previous_block,  seamed.m_previous_block);
    EXPECT_EQ(legacy.m_bits,            seamed.m_bits);
    EXPECT_EQ(legacy.m_mintime,         seamed.m_mintime);
    EXPECT_EQ(legacy.m_version,         seamed.m_version);
    EXPECT_EQ(legacy.m_curtime,         seamed.m_curtime);
    EXPECT_EQ(legacy.m_coinbase_value,  seamed.m_coinbase_value);
    EXPECT_EQ(legacy.m_payment_amount,  seamed.m_payment_amount);
    EXPECT_EQ(legacy.m_txs.size(),      seamed.m_txs.size());
    EXPECT_EQ(legacy.m_packed_payments.size(), seamed.m_packed_payments.size());
}
