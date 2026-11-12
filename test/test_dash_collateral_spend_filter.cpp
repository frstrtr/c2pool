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
#include <impl/dash/coin/vendor/mnhftx.hpp>
#include <impl/dash/coin/mnhf_check.hpp>
#include <impl/dash/coin/quorum_manager.hpp>
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
#include <set>
#include <utility>
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
    // Hand-seeded fixture: zero operator split, declared PROVEN as every
    // real ingest path does (h=2516595 serve gate).
    payee.payoutSplitProvenance = MNState::SPLIT_KNOWN;
    payee.collateralOutpoint.hash  = raw256(0xE0);  // unrelated outpoint
    payee.collateralOutpoint.index = 0;

    MNState victim;
    victim.isValid = true;
    victim.nRegisteredHeight = 2'310'000;
    victim.scriptPayout.m_data = p2pkh_script(0x40);
    victim.payoutSplitProvenance = MNState::SPLIT_KNOWN;   // h=2516595 serve gate
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

// ════════════════════════════════════════════════════════════════════════
// The exclusion takes the spend's in-body descendants with it. Selection is
// topological (mempool.hpp G1), so a child of the spend and that child's own
// child are packed after it; left behind, each spends an output the block
// does not create and a won block is rejected
// bad-txns-inputs-missingorspent. The exclusion runs in both postures: the
// bare builder and the default daemonless one (SML present,
// --embedded-include-mn-special-txs on).
// ════════════════════════════════════════════════════════════════════════

TEST(DashCollateralSpendFilter, ExcludedSpendTakesItsChildAndGrandchildOut) {
    UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);
    const uint256 p0 = mint_hash(0x50);
    utxo.add_coin(Outpoint(p0, 0), Coin(100'000, {}, 1, false));
    const auto innocent = make_spend(p0, 0, 90'000, /*salt=*/1);                  // fee 10'000
    const uint256 collat = raw256(0xC0);
    utxo.add_coin(Outpoint(collat, 0), Coin(100'000'000'000LL, {}, 1, false));
    const auto spend = make_spend(collat, 0, 99'999'950'000LL, /*salt=*/2);       // fee 50'000
    const auto child = make_spend(dash::coin::dash_txid(spend), 0,
                                  99'999'940'000LL, /*salt=*/3);                  // fee 10'000
    const auto grandchild = make_spend(dash::coin::dash_txid(child), 0,
                                       99'999'930'000LL, /*salt=*/4);             // fee 10'000
    ASSERT_TRUE(mp.add_tx(innocent));
    ASSERT_TRUE(mp.add_tx(spend));
    ASSERT_TRUE(mp.add_tx(child));
    ASSERT_TRUE(mp.add_tx(grandchild));

    std::vector<CSimplifiedMNListEntry> entries;
    for (uint8_t b : {0x01, 0x02}) {
        CSimplifiedMNListEntry e;
        e.nVersion = CSimplifiedMNListEntry::VER_BASIC_BLS;
        e.proRegTxHash = raw256(b);
        e.confirmedHash = raw256(0x77);
        e.isValid = true;
        entries.push_back(e);
    }
    const CSimplifiedMNList sml(std::move(entries));
    dash::coin::QuorumManager qmgr;
    auto build = [&](const MnStateMachine& mnstates, bool daemonless) {
        if (!daemonless)
            return build_embedded_workdata(H - 1, raw256(0xAB), mnstates, mp, 0x1b104be3u,
                                           1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER);
        return build_embedded_workdata(
            H - 1, raw256(0xAB), mnstates, mp, 0x1b104be3u, 1'700'000'000u,
            DASH_PUBKEY_VER, DASH_P2SH_VER, 1'700'000'100u, 0x20000000u, nullptr,
            &sml, &qmgr, 0, dash::coin::k_zero_cl_sig, 0, nullptr, nullptr,
            dash::coin::DASH_MN_RR_HEIGHT_MAINNET, nullptr,
            dash::coin::DASH_MN_MIN_CONFIRMATIONS_MAINNET, /*suppress=*/false,
            "utxo-immature-serving", nullptr, false, nullptr,
            /*include_mn_special_txs=*/true, nullptr, nullptr, nullptr,
            /*v24_active=*/false, nullptr, nullptr);
    };
    auto rides = [](const DashWorkData& w, const MutableTransaction& tx) {
        for (const auto& h : w.m_tx_hashes)
            if (h == dash::coin::dash_txid(tx)) return true;
        return false;
    };
    const int64_t reward = compute_dash_block_reward_post_v20(H);

    // Not vacuous: when the outpoint backs no masternode the whole chain rides.
    const auto no_mn = mn_set_with_collateral(raw256(0xC1), 0);
    for (bool daemonless : {false, true}) {
        const auto w = build(no_mn, daemonless);
        EXPECT_TRUE(rides(w, spend) && rides(w, child) && rides(w, grandchild))
            << "daemonless=" << daemonless << ": the selector packs the chain";
        EXPECT_EQ(w.m_coinbase_value, static_cast<uint64_t>(reward + 80'000));
    }

    const auto mnstates = mn_set_with_collateral(collat, 0);
    for (bool daemonless : {false, true}) {
        const auto w = build(mnstates, daemonless);
        EXPECT_TRUE(rides(w, innocent)) << "daemonless=" << daemonless;
        EXPECT_FALSE(rides(w, spend)) << "daemonless=" << daemonless;
        EXPECT_FALSE(rides(w, child))
            << "daemonless=" << daemonless << ": child of the excluded spend left in the body";
        EXPECT_FALSE(rides(w, grandchild))
            << "daemonless=" << daemonless << ": grandchild of the excluded spend left in the body";
        EXPECT_EQ(w.m_coinbase_value, static_cast<uint64_t>(reward + 10'000))
            << "daemonless=" << daemonless << ": the dropped fees must leave the coinbase";
    }
}

// ════════════════════════════════════════════════════════════════════════
// TOPOLOGY, defence in depth: a body tx that spends an output of a mempool tx
// the body does not carry before it. The builder drops it (and, by the same
// rule, its descendants) with their fees; the pre-emit gate refuses a final
// body that still carries one. Neither the tx-serve referee nor any other
// gate checked input topology, which is how an orphaned child of an excluded
// collateral spend could reach a miner.
// ════════════════════════════════════════════════════════════════════════

namespace {

// P (chain-funded), its child C, C's child G, and an independent U, all in
// the mempool; fees 10'000 each.
struct Chain {
    UTXOViewCache utxo{nullptr};
    Mempool mp;
    MutableTransaction p, c, g, u;
    Chain()
    {
        mp.set_utxo(&utxo);
        const uint256 fp = mint_hash(0x61), fu = mint_hash(0x62);
        utxo.add_coin(Outpoint(fp, 0), Coin(1'000'000, {}, 1, false));
        utxo.add_coin(Outpoint(fu, 0), Coin(1'000'000, {}, 1, false));
        p = make_spend(fp, 0, 990'000, 11);
        c = make_spend(dash::coin::dash_txid(p), 0, 980'000, 12);
        g = make_spend(dash::coin::dash_txid(c), 0, 970'000, 13);
        u = make_spend(fu, 0, 990'000, 14);
        for (const auto* t : {&p, &c, &g, &u}) EXPECT_TRUE(mp.add_tx(*t));
    }
};

std::vector<Mempool::SelectedTx> selection(std::initializer_list<const MutableTransaction*> txs)
{
    std::vector<Mempool::SelectedTx> out;
    for (const auto* t : txs) out.push_back(Mempool::SelectedTx{*t, 10'000, 200});
    return out;
}

} // namespace

TEST(DashBodyTopology, BuilderPassDropsATxWhoseMempoolParentIsNotServed) {
    Chain ch;
    using dash::coin::drop_txs_spending_unserved_mempool_parents;

    // P left out: C and, through C, G go with their fees; U stays.
    auto sel = selection({&ch.u, &ch.c, &ch.g});
    uint64_t fees = 30'000;
    EXPECT_EQ(drop_txs_spending_unserved_mempool_parents(sel, fees, ch.mp, H), 2u);
    ASSERT_EQ(sel.size(), 1u);
    EXPECT_EQ(dash::coin::dash_txid(sel[0].tx), dash::coin::dash_txid(ch.u));
    EXPECT_EQ(fees, 10'000u);

    // The whole chain, parents first: nothing to drop.
    auto full = selection({&ch.p, &ch.c, &ch.g, &ch.u});
    fees = 40'000;
    EXPECT_EQ(drop_txs_spending_unserved_mempool_parents(full, fees, ch.mp, H), 0u);
    EXPECT_EQ(full.size(), 4u);
    EXPECT_EQ(fees, 40'000u);

    // A child placed before its parent is dropped, its own child with it.
    auto reversed = selection({&ch.c, &ch.p, &ch.g});
    fees = 30'000;
    EXPECT_EQ(drop_txs_spending_unserved_mempool_parents(reversed, fees, ch.mp, H), 2u);
    ASSERT_EQ(reversed.size(), 1u);
    EXPECT_EQ(dash::coin::dash_txid(reversed[0].tx), dash::coin::dash_txid(ch.p));
    EXPECT_EQ(fees, 10'000u);
}

TEST(DashBodyTopology, EmitGateRefusesABodyTxWhoseMempoolParentIsNotEarlier) {
    const uint256 prev_hash = raw256(0xAB);
    auto seed = mn_set_with_collateral(raw256(0xC0), 0);
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

    UTXOViewCache utxo(nullptr);
    NodeCoinState st;
    st.set_require_sml(true);
    st.sml() = sml;
    st.set_have_sml(true);
    st.set_sml_current_hash(prev_hash);
    st.mnstates().load(seed.snapshot(), H - 1);
    st.mempool().set_utxo(&utxo);
    st.set_tip(H - 1, prev_hash, 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);
    const uint256 fp = mint_hash(0x61);
    utxo.add_coin(Outpoint(fp, 0), Coin(1'000'000, {}, 1, false));
    const auto p = make_spend(fp, 0, 990'000, 11);
    const auto c = make_spend(dash::coin::dash_txid(p), 0, 980'000, 12);
    ASSERT_TRUE(st.mempool().add_tx(p));
    ASSERT_TRUE(st.mempool().add_tx(c));

    auto body = [&](std::initializer_list<const MutableTransaction*> txs) {
        DashWorkData w;
        auto cb = build_embedded_cbtx(H - 1, sml, st.qmgr(),
                                      0, std::array<uint8_t, 96>{}, 0, nullptr);
        w.m_coinbase_payload = encode_cbtx(cb);
        for (const auto* t : txs) w.m_txs.emplace_back(*t);
        return w;
    };
    DeclineReport why;

    EXPECT_FALSE(st.embedded_template_emit_ok(body({&c}), &why));
    EXPECT_EQ(why.cause, "emit-tx-spends-unserved-mempool-parent");
    EXPECT_FALSE(st.embedded_template_emit_ok(body({&c, &p}), &why));
    EXPECT_EQ(why.cause, "emit-tx-spends-unserved-mempool-parent") << "parent after child";

    EXPECT_TRUE(st.embedded_template_emit_ok(body({&p, &c}), &why))
        << why.cause << " " << why.value;
}

// ════════════════════════════════════════════════════════════════════════
// An MNHF signal with an output. Dash Core's CheckTransaction lets a type-7
// tx carry inputs and outputs (consensus/tx_check.cpp:18-21), though its
// signer never adds any (MNHFTxPayload::PrepareTx, evo/mnhftx.cpp:37-45). A
// relayed signal B with a bad signature and one output, plus C spending B:0:
// both used to be selected (B lifted by the +0.1 DASH MNHF priority delta),
// the builder's MNHF screen then dropped B after every other check and kept
// C. That is an invalid block whose coinbase claims C's fee, or, with a
// pre-emit topology check, a template refused on every rebuild.
// ════════════════════════════════════════════════════════════════════════

TEST(DashBodyTopology, MnhfSignalWithAnOutputNeverOrphansItsChild) {
    UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);
    const uint256 f = mint_hash(0x70);
    utxo.add_coin(Outpoint(f, 0), Coin(1'000'000, {}, 1, false));

    MutableTransaction b;
    b.version = 3; b.type = dash::coin::vendor::MNHFTxPayload::SPECIALTX_TYPE; b.locktime = 0;
    dash::coin::vendor::MNHFTxPayload pl;
    pl.nVersion = 1;
    pl.signal.versionBit = 13;
    pl.signal.quorumHash = raw256(0x99);   // no such quorum: CheckMNHFTx refuses it
    {
        ::PackStream s;
        s << pl;
        auto sp = s.get_span();
        const auto* d = reinterpret_cast<const unsigned char*>(sp.data());
        b.extra_payload.assign(d, d + sp.size());
    }
    TxOut bo; bo.value = 0; bo.scriptPubKey.m_data = {0x51};
    b.vout.push_back(bo);
    const uint256 bid = dash::coin::dash_txid(b);

    MutableTransaction c;
    c.version = 1; c.type = 0; c.locktime = 77;
    TxIn i0; i0.prevout.hash = bid; i0.prevout.index = 0; i0.sequence = 0xffffffffu;
    TxIn i1; i1.prevout.hash = f;   i1.prevout.index = 0; i1.sequence = 0xffffffffu;
    c.vin.push_back(i0); c.vin.push_back(i1);
    TxOut co; co.value = 990'000; c.vout.push_back(co);                 // fee 10'000
    const uint256 cid = dash::coin::dash_txid(c);
    ASSERT_TRUE(mp.add_tx(b));
    ASSERT_TRUE(mp.add_tx(c));

    std::vector<CSimplifiedMNListEntry> entries;
    for (uint8_t x : {0x01, 0x02}) {
        CSimplifiedMNListEntry e;
        e.nVersion = CSimplifiedMNListEntry::VER_BASIC_BLS;
        e.proRegTxHash = raw256(x);
        e.confirmedHash = raw256(0x77);
        e.isValid = true;
        entries.push_back(e);
    }
    const CSimplifiedMNList sml(std::move(entries));
    dash::coin::QuorumManager qmgr;
    const auto mn = mn_set_with_collateral(raw256(0xC1), 0);
    dash::coin::MnhfCheckEnv env;   // wired, as in production; this signal fails it
    const auto w = build_embedded_workdata(
        H - 1, raw256(0xAB), mn, mp, 0x1b104be3u, 1'700'000'000u,
        DASH_PUBKEY_VER, DASH_P2SH_VER, 1'700'000'100u, 0x20000000u, nullptr,
        &sml, &qmgr, 0, dash::coin::k_zero_cl_sig, 0, nullptr, nullptr,
        dash::coin::DASH_MN_RR_HEIGHT_MAINNET, nullptr,
        dash::coin::DASH_MN_MIN_CONFIRMATIONS_MAINNET, /*suppress=*/false,
        "utxo-immature-serving", nullptr, false, nullptr,
        /*include_mn_special_txs=*/true, nullptr, nullptr, nullptr,
        /*v24_active=*/false, nullptr, &env);
    auto rides = [&](const uint256& id) {
        for (const auto& h : w.m_tx_hashes) if (h == id) return true;
        return false;
    };
    EXPECT_FALSE(rides(bid)) << "the refused signal rides";
    EXPECT_FALSE(rides(cid)) << "the child of the refused signal was left in the body";
    // Every body input that names a mempool tx names one earlier in the body.
    ASSERT_EQ(w.m_tx_hashes.size(), w.m_txs.size());
    std::set<uint256> earlier;
    for (size_t i = 0; i < w.m_txs.size(); ++i) {
        for (const auto& in : w.m_txs[i].vin)
            EXPECT_TRUE(earlier.count(in.prevout.hash) || !mp.contains(in.prevout.hash))
                << "body tx " << w.m_tx_hashes[i].GetHex().substr(0, 16)
                << " spends an output of mempool tx " << in.prevout.hash.GetHex().substr(0, 16)
                << " that the body does not carry before it";
        earlier.insert(w.m_tx_hashes[i]);
    }
    EXPECT_EQ(w.m_coinbase_value, static_cast<uint64_t>(compute_dash_block_reward_post_v20(H)))
        << "the coinbase claims the fee of a tx the block cannot carry";
}

// The txs placed before the mempool range (type-6 commitments, the pins that
// ride, type-9 unlocks) count as served: a selected child of one of them,
// should that parent also sit in the mempool, stays.
TEST(DashBodyTopology, BuilderPassCountsTheTxsPlacedBeforeTheRangeAsServed) {
    Chain ch;
    using dash::coin::drop_txs_spending_unserved_mempool_parents;
    auto sel = selection({&ch.c, &ch.g});
    uint64_t fees = 20'000;
    const std::set<uint256> placed_before{dash::coin::dash_txid(ch.p)};
    EXPECT_EQ(drop_txs_spending_unserved_mempool_parents(sel, fees, ch.mp, H, placed_before), 0u);
    EXPECT_EQ(sel.size(), 2u);
    EXPECT_EQ(fees, 20'000u);
    EXPECT_EQ(drop_txs_spending_unserved_mempool_parents(sel, fees, ch.mp, H), 2u)
        << "without it the parent is unserved";
    EXPECT_TRUE(sel.empty());
    EXPECT_EQ(fees, 0u);
}

// Builder to gate on the production branch, where m_tx_hashes lines up with
// the body. A CPFP pair (a parent below the block min fee rate on its own,
// paid for by its child) rides parent first and passes the gate; the same
// template with the parent cut out, ids kept aligned, is refused.
TEST(DashBodyTopology, BuilderCpfpTemplatePassesTheGateAndFailsItWithoutTheParent) {
    const uint256 prev_hash = raw256(0xAB);
    auto seed = mn_set_with_collateral(raw256(0xC0), 0);
    std::vector<CSimplifiedMNListEntry> entries;
    for (uint8_t b : {0x01, 0x02}) {
        CSimplifiedMNListEntry e;
        e.nVersion = CSimplifiedMNListEntry::VER_BASIC_BLS;
        e.proRegTxHash = raw256(b);
        e.confirmedHash = raw256(0x77);
        e.isValid = true;
        entries.push_back(e);
    }
    UTXOViewCache utxo(nullptr);
    NodeCoinState st;
    st.set_require_sml(true);
    st.sml() = CSimplifiedMNList(std::move(entries));
    st.set_have_sml(true);
    st.set_sml_current_hash(prev_hash);
    st.mnstates().load(seed.snapshot(), H - 1);
    st.mempool().set_utxo(&utxo);
    st.set_tip(H - 1, prev_hash, 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER, 1'700'000'100u, 0x20000000u);
    const uint256 fp = mint_hash(0x63);
    utxo.add_coin(Outpoint(fp, 0), Coin(1'000'000, {}, 1, false));
    const auto p = make_spend(fp, 0, 999'990, 21);                                // fee 10
    const auto c = make_spend(dash::coin::dash_txid(p), 0, 949'990, 22);          // fee 50'000
    ASSERT_TRUE(st.mempool().add_tx(p));
    ASSERT_TRUE(st.mempool().add_tx(c));

    const auto w = build_embedded_workdata(
        H - 1, prev_hash, std::as_const(st).mnstates(), st.mempool(), 0x1b104be3u,
        1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER, 1'700'000'100u, 0x20000000u, nullptr,
        &std::as_const(st).sml(), &std::as_const(st).qmgr(), 0, dash::coin::k_zero_cl_sig, 0,
        nullptr, nullptr, dash::coin::DASH_MN_RR_HEIGHT_MAINNET, nullptr,
        dash::coin::DASH_MN_MIN_CONFIRMATIONS_MAINNET);
    ASSERT_EQ(w.m_tx_hashes.size(), w.m_txs.size());
    auto index_of = [&](const DashWorkData& t, const MutableTransaction& tx) {
        for (size_t i = 0; i < t.m_tx_hashes.size(); ++i)
            if (t.m_tx_hashes[i] == dash::coin::dash_txid(tx)) return static_cast<long>(i);
        return -1L;
    };
    const long ip = index_of(w, p), ic = index_of(w, c);
    ASSERT_GE(ip, 0) << "the CPFP parent rides with its child";
    ASSERT_GE(ic, 0);
    EXPECT_LT(ip, ic) << "parent before child";
    EXPECT_EQ(w.m_coinbase_value,
              static_cast<uint64_t>(compute_dash_block_reward_post_v20(H) + 50'010));
    DeclineReport why;
    EXPECT_TRUE(st.embedded_template_emit_ok(w, &why))
        << why.cause << " " << why.value << " / " << why.threshold;

    auto cut = w;
    auto erase_at = [](auto& v, long i) { v.erase(v.begin() + i); };
    erase_at(cut.m_txs, ip);
    erase_at(cut.m_tx_hashes, ip);
    if (cut.m_tx_fees.size() == w.m_txs.size()) erase_at(cut.m_tx_fees, ip);
    if (cut.m_tx_data_hex.size() == w.m_txs.size()) erase_at(cut.m_tx_data_hex, ip);
    ASSERT_EQ(cut.m_tx_hashes.size(), cut.m_txs.size());
    EXPECT_FALSE(st.embedded_template_emit_ok(cut, &why));
    EXPECT_EQ(why.cause, "emit-tx-spends-unserved-mempool-parent");
}
