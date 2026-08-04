// SPDX-License-Identifier: AGPL-3.0-or-later
/// MN-collateral spend filter (sml_projection.hpp tx_spends_mn_collateral +
/// the embedded_gbt.hpp selection filter + the NodeCoinState pre-emit check).
///
/// THE DEFECT PINNED HERE (silent block loss while the tx is in the
/// mempool): dashcore's verifier runs its collateral pass over ALL block txs
/// with NO special-tx guard (v23.1.7 specialtxman.cpp:457-464) — a plain
/// type-0 transaction spending a masternode's collateral outpoint forces the
/// verifier to REMOVE that MN from the list for that block, changing the
/// merkleRootMNList the CbTx must commit. The C-3 special-tx cut
/// (mempool.hpp exclude_special, tx.type != 0) cannot catch it: the tx IS
/// type 0. Pre-fix, such a tx sailed into the template while the committed
/// root still contained the MN — bad-cbtx-mnmerkleroot on every template
/// built while the spend sat in the mempool, invisible to every gate (the
/// SML is current at tip; the removal only exists in the verifier's rebuild
/// of the block BEING templated).
///
/// The fix EXCLUDES the tx from selection (no tx is ever mandatory, so
/// exclusion is consensus-clean; dashd's own miner folds the removal into
/// the root instead — larger, deferred). Posture on coverage: the lookup is
/// the DMN view's UNFILTERED collateral index (banned MNs included, matching
/// dashd's GetMNByCollateral in this pass); an outpoint the index does not
/// hold is treated as NOT a collateral — dropping every type-0 tx with any
/// unknown input would gut template fill.

#include <gtest/gtest.h>

#include <impl/dash/coin/embedded_gbt.hpp>
#include <impl/dash/coin/sml_projection.hpp>
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/mn_state_db.hpp>
#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/node_coin_state.hpp>
#include <impl/dash/coin/subsidy.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/utxo_adapter.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

using dash::coin::DashWorkData;
using dash::coin::DeclineReport;
using dash::coin::MNState;
using dash::coin::MnStateMachine;
using dash::coin::Mempool;
using dash::coin::MutableTransaction;
using dash::coin::NodeCoinState;
using dash::coin::build_embedded_workdata;
using dash::coin::build_embedded_cbtx;
using dash::coin::encode_cbtx;
using dash::coin::compute_dash_block_reward_post_v20;
using dash::coin::tx_spends_mn_collateral;
using dash::coin::vendor::CSimplifiedMNList;
using dash::coin::vendor::CSimplifiedMNListEntry;
using ::core::coin::UTXOViewCache;
using ::core::coin::Outpoint;
using ::core::coin::Coin;
using ::bitcoin_family::coin::TxIn;
using ::bitcoin_family::coin::TxOut;

static constexpr uint8_t DASH_PUBKEY_VER = 76;
static constexpr uint8_t DASH_P2SH_VER   = 16;
static constexpr uint32_t H = 2'400'000;

static uint256 raw256(uint8_t base) {
    uint256 h;
    std::array<uint8_t, 32> p{};
    for (size_t i = 0; i < 32; ++i) p[i] = static_cast<uint8_t>(base + i);
    std::memcpy(h.data(), p.data(), 32);
    return h;
}

static std::vector<unsigned char> p2pkh_script(uint8_t hashseed) {
    std::vector<unsigned char> s;
    s.push_back(0x76); s.push_back(0xa9); s.push_back(0x14);
    for (int i = 0; i < 20; ++i) s.push_back(static_cast<unsigned char>(hashseed + i));
    s.push_back(0x88); s.push_back(0xac);
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

// One valid payee MN plus one MN whose collateral outpoint is `collat`:
// the DMN view whose UNFILTERED collateral index the filter consults.
static MnStateMachine mn_set_with_collateral(const uint256& collat_hash,
                                             uint32_t collat_index) {
    MNState payee;
    payee.isValid = true;
    payee.nRegisteredHeight = 2'300'000;
    payee.scriptPayout.m_data = p2pkh_script(0x30);
    payee.collateralOutpoint.hash  = raw256(0xE0);  // unrelated outpoint
    payee.collateralOutpoint.index = 0;

    MNState victim;
    victim.isValid = true;
    victim.nRegisteredHeight = 2'310'000;
    victim.scriptPayout.m_data = p2pkh_script(0x40);
    victim.collateralOutpoint.hash  = collat_hash;
    victim.collateralOutpoint.index = collat_index;

    MnStateMachine m;
    m.load({{raw256(0x01), payee}, {raw256(0x02), victim}}, H - 1);
    return m;
}

// ════════════════════════════════════════════════════════════════════════
// FINDING-2 defect demonstration — MUST FAIL on pre-fix master (the
// collateral-spending type-0 tx was selected and the committed root went
// stale for every template built while it sat in the mempool).
// ════════════════════════════════════════════════════════════════════════

TEST(DashCollateralSpendFilter, NormalTxSpendingCollateralExcludedFromTemplate) {
    UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);

    // An innocent fee-paying type-0 tx — MUST be selected.
    uint256 p0 = mint_hash(0x50);
    utxo.add_coin(Outpoint(p0, 0), Coin(100'000, {}, /*height=*/1, /*cb=*/false));
    auto innocent = make_spend(p0, 0, 90'000, /*salt=*/1);   // fee 10'000
    ASSERT_TRUE(mp.add_tx(innocent));

    // A type-0 tx spending MN collateral raw256(0xC0):0 — UTXO-priced (fee
    // known, HIGHER feerate than the innocent tx so ordering alone can never
    // exclude it) — MUST be excluded by the collateral filter.
    uint256 collat = raw256(0xC0);
    utxo.add_coin(Outpoint(collat, 0), Coin(100'000'000'000LL, {}, 1, false));
    auto spender = make_spend(collat, 0, 99'999'950'000LL, /*salt=*/2);  // fee 50'000
    ASSERT_TRUE(mp.add_tx(spender));

    auto mnstates = mn_set_with_collateral(collat, 0);
    auto w = build_embedded_workdata(
        H - 1, raw256(0xAB), mnstates, mp,
        0x1b104be3u, 1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER);

    // Only the innocent tx may be in the template.
    ASSERT_EQ(w.m_txs.size(), 1u)
        << "the collateral-spending type-0 tx leaked into the template "
        << "(verifier removes the MN => committed merkleRootMNList is stale)";
    EXPECT_EQ(w.m_tx_hashes[0], dash::coin::dash_txid(innocent));
    for (const auto& h : w.m_tx_hashes)
        EXPECT_NE(h, dash::coin::dash_txid(spender));

    // And its fee must have left the coinbase with it.
    const int64_t reward = compute_dash_block_reward_post_v20(H);
    EXPECT_EQ(w.m_coinbase_value, static_cast<uint64_t>(reward + 10'000))
        << "excluded tx's fee still counted into coinbasevalue";
}

// Defence in depth: the pre-emit hard gate must reject a template that
// carries a collateral-spending tx however it got there (cached template,
// viability bypass). Pre-fix the gate had no such check and the roots
// matched, so the template passed — this test fails there.
TEST(DashCollateralSpendFilter, EmitGateRejectsTemplateCarryingCollateralSpend) {
    uint256 collat = raw256(0xC0);
    uint256 prev_hash = raw256(0xAB);
    auto mnstates_seed = mn_set_with_collateral(collat, 0);

    // Fully-confirmed 2-entry SML so the rollover projection is a no-op and
    // the ONLY defect in the template is the collateral spend.
    std::vector<CSimplifiedMNListEntry> entries;
    for (uint8_t b : {0x01, 0x02}) {
        CSimplifiedMNListEntry e;
        e.nVersion = CSimplifiedMNListEntry::VER_BASIC_BLS;
        e.proRegTxHash = raw256(b);
        e.confirmedHash = raw256(0x77);
        e.isValid = true;
        entries.push_back(e);
    }
    CSimplifiedMNList sml(std::move(entries));

    NodeCoinState st;
    st.set_require_sml(true);
    st.sml() = sml;
    st.set_have_sml(true);
    st.set_sml_current_hash(prev_hash);
    st.mnstates().load(mnstates_seed.snapshot(), H - 1);
    st.set_tip(H - 1, prev_hash, 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);

    // Template with correct roots BUT carrying the collateral-spending tx.
    DashWorkData w;
    {
        auto cb = build_embedded_cbtx(H - 1, sml, st.qmgr(),
                                      0, std::array<uint8_t, 96>{}, 0, nullptr);
        w.m_coinbase_payload = encode_cbtx(cb);
    }
    w.m_txs.emplace_back(make_spend(collat, 0, 99'999'950'000LL, /*salt=*/2));

    DeclineReport why;
    EXPECT_FALSE(st.embedded_template_emit_ok(w, &why))
        << "emit gate passed a template whose tx spends a known MN collateral";
    EXPECT_EQ(why.cause, "emit-collateral-spend-in-template");

    // Same template without the offending tx passes.
    w.m_txs.clear();
    EXPECT_TRUE(st.embedded_template_emit_ok(w, &why))
        << "cause=" << why.cause << " value=" << why.value;
}

// ════════════════════════════════════════════════════════════════════════
// Predicate unit KATs (structural).
// ════════════════════════════════════════════════════════════════════════

TEST(DashCollateralSpendFilter, PredicateMatchesExactOutpointOnly) {
    uint256 collat = raw256(0xC0);
    auto mnstates = mn_set_with_collateral(collat, /*collat_index=*/1);

    // Exact outpoint (hash AND index) => hit, naming the victim MN.
    auto hit = make_spend(collat, 1, 1'000, 1);
    uint256 protx;
    EXPECT_TRUE(tx_spends_mn_collateral(mnstates, hit, &protx));
    EXPECT_EQ(protx, raw256(0x02));

    // Same hash, DIFFERENT index => not a collateral spend.
    auto near_miss = make_spend(collat, 0, 1'000, 2);
    EXPECT_FALSE(tx_spends_mn_collateral(mnstates, near_miss));

    // Unknown outpoint => "cannot check" posture: NOT excluded.
    auto unknown = make_spend(mint_hash(0x99), 0, 1'000, 3);
    EXPECT_FALSE(tx_spends_mn_collateral(mnstates, unknown));

    // Collateral spend buried in a multi-input tx => still a hit.
    auto multi = make_spend(mint_hash(0x99), 0, 1'000, 4);
    TxIn in2; in2.prevout.hash = collat; in2.prevout.index = 1;
    in2.sequence = 0xffffffffu;
    multi.vin.push_back(in2);
    EXPECT_TRUE(tx_spends_mn_collateral(mnstates, multi));
}
