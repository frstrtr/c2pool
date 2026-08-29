// SPDX-License-Identifier: AGPL-3.0-or-later
//
// ── THE GAP-REPAIR SEAM AT ITS MONEY-PATH CALLER ───────────────────────────
//
// CoinStateMaintainer::on_block_connected historically had exactly one remedy
// for a payee-queue APPLY GAP: wipe + demote + authoritative re-seed (the E4
// fail-closed fix). dashd never pays that price — it reconstructs the list
// for ANY block from its per-block diff store (GetListForBlockInternal,
// evo/deterministicmns.cpp:778-870). mn_diff_store.hpp is that mechanism
// ported over ReplayMNState, and mn_gap_repair.hpp is the seam that lets the
// maintainer ask it for the list at height-1 BEFORE paying the wipe.
//
// THE CRITICAL SHAPE, pinned in every gap test here: THE TIP MOVES. A gap is
// blocks mined while the queue folded nothing — on a static tip the scenario
// cannot even be expressed (the vm905 death: tip ran ~20 ahead of the bridge,
// the wipe fired at the APPLY GAP, and the re-arm never caught the running
// target again). Every test below advances the serve tip across heights the
// queue never folded, then proves either the repair (queue byte-identical to
// a contiguous fold — dashd's own equivalence) or the UNCHANGED fail-closed
// floor (wipe + demote + re-seed ask) when the store cannot answer.
//
// End-to-end through the REAL store: records written with MnListDiff::build,
// reconstructed by MnDiffStore::reconstruct over a header-chain lookup, and
// projected through the same to_payee_state boundary main_dash wires — not a
// stubbed repair function.

#include <gtest/gtest.h>

#include <impl/dash/coin/coin_state_maintainer.hpp>
#include <impl/dash/coin/node_coin_state.hpp>
#include <impl/dash/coin/mn_diff_store.hpp>
#include <impl/dash/coin/mn_gap_repair.hpp>
#include <impl/dash/coin/replay_fold_engine.hpp>
#include <impl/dash/coin/replay_payee_publish.hpp>   // to_payee_state
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/block_producer.hpp>         // compute_merkle_root
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>

#include <core/uint256.hpp>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

using dash::coin::CoinStateMaintainer;
using dash::coin::MNState;
using dash::coin::MnGapRepairFn;
using dash::coin::MnGapRepairResult;
using dash::coin::MutableTransaction;
using dash::coin::NodeCoinState;
using dash::coin::WorkSelection;
using dash::coin::WorkSource;
using dash::coin::BlockType;
using dash::coin::DashWorkData;
using dash::coin::replay::DmlFoldEngine;
using dash::coin::replay::FoldConfig;
using dash::coin::replay::MnDiffRecord;
using dash::coin::replay::MnDiffStore;
using dash::coin::replay::MnListDiff;
using dash::coin::replay::ReplayMNState;
using dash::coin::replay::to_payee_state;
using dash::coin::vendor::CSimplifiedMNList;
using dash::coin::vendor::CSimplifiedMNListEntry;
using ::bitcoin_family::coin::TxIn;
using ::bitcoin_family::coin::TxOut;

namespace {

constexpr uint8_t  DASH_PUBKEY_VER = 76;
constexpr uint8_t  DASH_P2SH_VER   = 16;
constexpr uint32_t H       = 2'400'000;    // the block that finds the gap
constexpr uint32_t SEED_H  = H - 3;        // queue seeded as-of here
constexpr uint32_t BITS    = 0x1b104be3u;
constexpr uint32_t MTP     = 1'700'000'000u;

uint256 h256(uint64_t v)
{
    uint256 h;
    std::memset(h.data(), 0, 32);
    std::memcpy(h.data(), &v, sizeof(v));
    return h;
}

/// Synthetic hash-linked chain: hash(h) = h256(0xB00000 + h).
uint256 chain_hash(uint32_t h) { return h256(0xB00000ull + h); }

std::vector<unsigned char> p2pkh_script(uint8_t hashseed)
{
    std::vector<unsigned char> s{0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i)
        s.push_back(static_cast<unsigned char>(hashseed + i));
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

MutableTransaction make_spend(const uint256& prev, uint32_t idx,
                              int64_t out_value, uint32_t salt)
{
    MutableTransaction tx;
    tx.version = 1; tx.type = 0; tx.locktime = salt;
    TxIn in; in.prevout.hash = prev; in.prevout.index = idx;
    in.sequence = 0xffffffffu;
    tx.vin.push_back(in);
    TxOut o; o.value = out_value;
    tx.vout.push_back(o);
    return tx;
}

void bind_block(BlockType& b)
{
    std::vector<uint256> ids;
    for (const auto& tx : b.m_txs) ids.push_back(dash::coin::dash_txid(tx));
    b.m_merkle_root = dash::coin::compute_merkle_root(ids);
}

/// A block whose coinbase pays `payee` (the projected MN's script), bound to
/// its header — the readiness-preserving "normal" block shape the pre-existing
/// maintainer KATs use.
BlockType paying_block(const std::vector<unsigned char>& payee, uint32_t salt)
{
    BlockType blk;
    blk.m_txs.push_back(make_spend(h256(0x9000 + salt), 0, 500000000, salt));
    blk.m_txs[0].vout[0].scriptPubKey.m_data = payee;
    bind_block(blk);
    return blk;
}

ReplayMNState make_replay_mn(uint64_t i,
                             const std::vector<unsigned char>& payout,
                             int32_t last_paid)
{
    ReplayMNState st;
    st.internalId               = i;
    st.collateralOutpoint.hash  = h256(0x5000 + i);
    st.collateralOutpoint.index = static_cast<uint32_t>(i);
    st.nRegisteredHeight        = static_cast<int32_t>(2'300'000 + i);
    st.nLastPaidHeight          = last_paid;
    st.pubKeyOperator[0]        = static_cast<uint8_t>(0x40 + i);
    st.netInfo.ip[15]           = static_cast<uint8_t>(i + 1);
    st.netInfo.port_be          = 9999;
    st.scriptPayout.m_data.assign(payout.begin(), payout.end());
    return st;
}

uint256 sml_root_of(const DmlFoldEngine::Entries& list)
{
    std::vector<CSimplifiedMNListEntry> ents;
    ents.reserve(list.size());
    for (const auto& [protx, st] : list) ents.push_back(st.to_sml_entry(protx));
    CSimplifiedMNList sml(std::move(ents));
    return sml.CalcMerkleRoot();
}

std::vector<std::pair<uint256, MNState>>
to_payee_list(const DmlFoldEngine::Entries& list)
{
    std::vector<std::pair<uint256, MNState>> out;
    out.reserve(list.size());
    for (const auto& [protx, st] : list)
        out.emplace_back(protx, to_payee_state(st));
    return out;
}

std::string fresh_db_dir(const char* name)
{
    const auto dir = std::filesystem::temp_directory_path()
                   / ("c2pool_mn_gap_repair_kat_" + std::string(name) + "_"
                      + std::to_string(::getpid()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return (dir / "db").string();
}

// ── The fixture chain ──────────────────────────────────────────────────────
// Two masternodes with DISTINCT payout scripts, so payment ORDER is what the
// repair must reproduce — with shared addresses a wrong queue front is
// invisible to the coinbase cross-check (the whole E4 incident class).
//
//   L0 (as-of SEED_H = H-3): MN1 lastPaid H-10, MN2 lastPaid H-9
//   block H-2 pays MN1 (the older slot)  -> L1: MN1 lastPaid = H-2
//   block H-1 pays MN2                   -> L2: MN2 lastPaid = H-1
//   block H   pays MN1 again
struct Fixture
{
    std::vector<unsigned char> script1 = p2pkh_script(0x30);
    std::vector<unsigned char> script2 = p2pkh_script(0x60);
    DmlFoldEngine::Entries L0, L1, L2;

    Fixture()
    {
        L0.emplace(h256(1), make_replay_mn(0, script1,
                                           static_cast<int32_t>(H - 10)));
        L0.emplace(h256(2), make_replay_mn(1, script2,
                                           static_cast<int32_t>(H - 9)));
        L1 = L0;
        L1.at(h256(1)).nLastPaidHeight = static_cast<int32_t>(H - 2);
        L2 = L1;
        L2.at(h256(2)).nLastPaidHeight = static_cast<int32_t>(H - 1);
    }

    /// Write the grounding snapshot at SEED_H and diff rows for H-2, H-1
    /// (both root_matched AND payee_verified — the store refuses anything
    /// less). `skip_height` punches the unrepairable hole.
    void populate_store(MnDiffStore& store, uint32_t skip_height = 0) const
    {
        DmlFoldEngine eng{FoldConfig{}};
        std::vector<std::pair<uint256, ReplayMNState>> seed;
        for (const auto& [k, v] : L0) seed.emplace_back(k, v);
        eng.seed(std::move(seed), L0.size(), SEED_H, chain_hash(SEED_H));
        ASSERT_TRUE(store.put_snapshot(chain_hash(SEED_H),
                                       eng.save_snapshot()));

        const DmlFoldEngine::Entries* prev = &L0;
        const DmlFoldEngine::Entries* rows[] = {&L1, &L2};
        for (uint32_t i = 0; i < 2; ++i) {
            const uint32_t h = H - 2 + i;
            MnDiffRecord rec;
            rec.prev_hash              = chain_hash(h - 1);
            rec.merkle_root_mn_list    = sml_root_of(*rows[i]);
            rec.flags                  = MnDiffRecord::kFlagRootMatched
                                       | MnDiffRecord::kFlagPayeeVerified;
            rec.total_registered_count = 2;
            rec.diff                   = MnListDiff::build(*prev, *rows[i]);
            if (h != skip_height)
                ASSERT_TRUE(store.put_block(chain_hash(h), h, rec, nullptr));
            prev = rows[i];
        }
    }
};

/// hash -> (height, prev_hash) over the synthetic chain — the walk's
/// cross-check at every hop, exactly what main_dash wires off HeaderChain.
MnDiffStore::HeaderLookupFn synth_headers()
{
    return [](const uint256& hash)
        -> std::optional<std::pair<uint32_t, uint256>> {
        for (uint32_t h = H - 6; h <= H + 1; ++h) {
            if (chain_hash(h) == hash)
                return std::make_pair(h, chain_hash(h - 1));
        }
        return std::nullopt;
    };
}

/// The seam wired exactly as main_dash wires it: want_height -> hash off the
/// header chain -> MnDiffStore::reconstruct -> to_payee_state projection.
MnGapRepairFn make_repair_fn(MnDiffStore* store)
{
    return [store](uint32_t want) -> MnGapRepairResult {
        MnGapRepairResult out;
        out.as_of = want;
        if (store == nullptr) { out.error = "diff store absent"; return out; }
        DmlFoldEngine::Entries list;
        uint64_t trc = 0;
        std::string err;
        if (!store->reconstruct(chain_hash(want), synth_headers(), list, trc,
                                err)) {
            out.error = err;
            return out;
        }
        out.entries = to_payee_list(list);
        out.ok = true;
        return out;
    };
}

void expect_queue_byte_identical(NodeCoinState& a, NodeCoinState& b,
                                 const char* what)
{
    ASSERT_EQ(a.mnstates().size(), b.mnstates().size()) << what;
    auto ib = b.mnstates().entries().begin();
    for (const auto& [protx, mn] : a.mnstates().entries()) {
        EXPECT_EQ(protx, ib->first) << what;
        EXPECT_TRUE(mn == ib->second)
            << what << ": entry " << protx.GetHex().substr(0, 16)
            << " differs between the contiguous fold and the repaired queue";
        ++ib;
    }
    EXPECT_EQ(a.mnstates().last_applied_height(),
              b.mnstates().last_applied_height()) << what;
}

void expect_queue_equals(NodeCoinState& st, const DmlFoldEngine::Entries& want,
                         const char* what)
{
    ASSERT_EQ(st.mnstates().size(), want.size()) << what;
    for (const auto& [protx, rst] : want) {
        const MNState expect = to_payee_state(rst);
        auto it = st.mnstates().entries().find(protx);
        ASSERT_NE(it, st.mnstates().entries().end()) << what;
        EXPECT_TRUE(it->second == expect)
            << what << ": entry " << protx.GetHex().substr(0, 16);
    }
}

void tip(CoinStateMaintainer& m, uint32_t prev_height)
{
    m.on_new_tip(prev_height, chain_hash(prev_height), BITS, MTP,
                 DASH_PUBKEY_VER, DASH_P2SH_VER);
}

} // namespace

// ═══════════════════════════════════════════════════════════════════════════
// CASE 1 — an APPLY GAP of 2 blocks, AGAINST A MOVING TIP, repaired from the
// stored diffs; the repaired queue is BYTE-IDENTICAL to the queue a
// contiguous fold of the same blocks produces (dashd's own equivalence:
// GetListForBlockInternal(h) == the incrementally-built list at h).
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashMnGapRepair, ApplyGapAgainstMovingTipRepairedByteIdenticalToContiguousFold)
{
    Fixture fx;
    MnDiffStore store(fresh_db_dir("repair"));
    ASSERT_TRUE(store.open());
    fx.populate_store(store);

    // ── A: the reference — every block folded contiguously ───────────────
    NodeCoinState stA;
    CoinStateMaintainer A(stA);
    bool reseedA = false;
    A.set_on_mn_reseed([&]() { reseedA = true; });
    tip(A, SEED_H);
    A.on_mn_list_update(to_payee_list(fx.L0), SEED_H);
    ASSERT_TRUE(A.live());
    {
        auto r = A.on_block_connected(paying_block(fx.script1, 1), H - 2);
        ASSERT_FALSE(r.gap_detected);
        ASSERT_FALSE(r.payee_desync);
        ASSERT_EQ(r.paid, 1u);
    }
    tip(A, H - 2);
    {
        auto r = A.on_block_connected(paying_block(fx.script2, 2), H - 1);
        ASSERT_FALSE(r.gap_detected);
        ASSERT_EQ(r.paid, 1u);
    }
    tip(A, H - 1);
    // The stored-diff fixture really does describe the contiguous fold: A's
    // queue at H-1 is exactly to_payee_state(L2). This is the assertion that
    // makes the byte-identity below MEAN something.
    expect_queue_equals(stA, fx.L2, "contiguous fold at H-1 vs L2");

    // ── B: the gap — the TIP MOVES across two blocks the queue never saw ──
    NodeCoinState stB;
    CoinStateMaintainer B(stB);
    bool reseedB = false;
    B.set_on_mn_reseed([&]() { reseedB = true; });
    B.set_mn_gap_repair(make_repair_fn(&store));
    tip(B, SEED_H);
    B.on_mn_list_update(to_payee_list(fx.L0), SEED_H);
    ASSERT_TRUE(B.live());
    // Blocks H-2 and H-1 are mined while the queue folds nothing (the E4 /
    // vm905 shape: header lane keeps up, body ingest does not). The serve
    // tip RUNS — this is the movement without which the defect class cannot
    // be expressed at all.
    tip(B, H - 2);
    tip(B, H - 1);
    ASSERT_EQ(stB.mnstates().last_applied_height(), SEED_H)
        << "precondition: the queue cursor must be 2 behind the moved tip";

    // Block H connects. First apply reports the gap; the seam reconstructs
    // the list at H-1 from the stored diffs, reseeds through the single sink,
    // and re-applies THIS block. No wipe, no demotion, no re-seed ask.
    auto rB = B.on_block_connected(paying_block(fx.script1, 3), H);
    EXPECT_FALSE(rB.gap_detected)
        << "the returned result is the post-repair re-apply";
    EXPECT_FALSE(rB.payee_desync);
    EXPECT_EQ(rB.paid, 1u);
    EXPECT_FALSE(reseedB) << "a repaired gap must not fire the re-seed ask";
    EXPECT_TRUE(B.live()) << "a repaired gap must not demote the bundle";
    EXPECT_EQ(B.mn_snapshot_height(), H - 1)
        << "the repair reseeds as-of the reconstructed height";
    EXPECT_FALSE(B.mn_needs_reseed_latched());

    // ── the required equivalence ──────────────────────────────────────────
    {
        auto r = A.on_block_connected(paying_block(fx.script1, 3), H);
        ASSERT_EQ(r.paid, 1u);
    }
    expect_queue_byte_identical(stA, stB, "after block H");

    // And the repaired cursor is a REAL cursor: the next live block folds
    // contiguously on both, and the queues stay identical.
    tip(A, H);
    tip(B, H);
    {
        auto ra = A.on_block_connected(paying_block(fx.script2, 4), H + 1);
        auto rb = B.on_block_connected(paying_block(fx.script2, 4), H + 1);
        EXPECT_FALSE(ra.gap_detected);
        EXPECT_FALSE(rb.gap_detected);
        EXPECT_EQ(ra.paid, 1u);
        EXPECT_EQ(rb.paid, 1u);
    }
    expect_queue_byte_identical(stA, stB, "after block H+1");

    // The repaired arm still serves embedded work.
    bool fb = false;
    WorkSelection sel = stB.select_work([&]() { fb = true; return DashWorkData{}; });
    EXPECT_EQ(sel.source, WorkSource::Embedded);
    EXPECT_FALSE(fb);
}

// ═══════════════════════════════════════════════════════════════════════════
// CASE 2 — an APPLY GAP the store CANNOT repair (a diff row is absent): the
// pre-existing fail-closed path runs byte-for-byte unchanged — wipe, demote,
// authoritative re-seed ask. The repair seam only ever ADDS a lane in front
// of the wipe; this pins that the wipe was not lost behind it.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashMnGapRepair, ApplyGapNotRepairableStillWipesDemotesAndReseeds)
{
    Fixture fx;
    MnDiffStore store(fresh_db_dir("hole"));
    ASSERT_TRUE(store.open());
    fx.populate_store(store, /*skip_height=*/H - 2);   // the hole

    NodeCoinState st;
    CoinStateMaintainer m(st);
    bool reseed_fired = false;
    m.set_on_mn_reseed([&]() { reseed_fired = true; });
    m.set_mn_gap_repair(make_repair_fn(&store));
    tip(m, SEED_H);
    m.on_mn_list_update(to_payee_list(fx.L0), SEED_H);
    ASSERT_TRUE(m.live());
    tip(m, H - 2);       // the tip moves; the queue folds nothing
    tip(m, H - 1);

    // The repair fn is WIRED and is consulted — and the store refuses (the
    // walk hits the missing H-2 row; missing row = REFUSED, never an empty
    // list). Everything the E4 fail-closed fix demanded must still happen.
    auto r = m.on_block_connected(paying_block(fx.script1, 3), H);
    EXPECT_TRUE(r.gap_detected);
    EXPECT_EQ(r.paid, 0u) << "a gapped fold must not attribute the payment";
    EXPECT_EQ(st.mnstates().size(), 0u) << "stale-cursor queue must be wiped";
    EXPECT_FALSE(m.live()) << "an unrepairable gap must demote to fallback";
    EXPECT_TRUE(reseed_fired)
        << "an unrepairable gap must request an authoritative re-seed";
    EXPECT_TRUE(m.mn_needs_reseed_latched());
    EXPECT_EQ(m.mn_snapshot_height(), 0u);

    bool fb = false;
    WorkSelection sel = st.select_work([&]() { fb = true; return DashWorkData{}; });
    EXPECT_EQ(sel.source, WorkSource::DashdFallback);
    EXPECT_TRUE(fb);
}

// ═══════════════════════════════════════════════════════════════════════════
// CASE 3a — THE CONSUMER HALF OF THE G7 SPLIT, success arm: a seed stamped
// BELOW an already-moving tip is caught up to the tip from the stored diffs
// BEFORE serving arms. The publisher may now release within epsilon precisely
// because this gate exists.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashMnGapRepair, BelowTipSeedCatchesUpFromStoreAndArmsAtTheTip)
{
    Fixture fx;
    MnDiffStore store(fresh_db_dir("catchup"));
    ASSERT_TRUE(store.open());
    fx.populate_store(store);

    NodeCoinState st;
    st.set_require_fresh_mn_payee(true);   // serve only a tip-current queue
    CoinStateMaintainer m(st);
    m.set_mn_gap_repair(make_repair_fn(&store));

    // The tip has ALREADY moved past the seed's as-of when the seed lands —
    // the publisher-side epsilon window made this ordering routine.
    tip(m, H - 1);
    m.on_mn_list_update(to_payee_list(fx.L0), SEED_H);   // 2 below the tip

    EXPECT_TRUE(m.live())
        << "the catch-up succeeded, so serving must be armed";
    EXPECT_EQ(m.mn_snapshot_height(), H - 1)
        << "the queue cursor must be AT the tip, not at the seed stamp";
    expect_queue_equals(st, fx.L2, "caught-up queue vs L2");

    // The freshness gate agrees: the queue is current AT the tip and the
    // embedded arm serves.
    bool fb = false;
    WorkSelection sel = st.select_work([&]() { fb = true; return DashWorkData{}; });
    EXPECT_EQ(sel.source, WorkSource::Embedded);
    EXPECT_FALSE(fb);

    // And the caught-up cursor folds the next live block contiguously.
    auto r = m.on_block_connected(paying_block(fx.script1, 3), H);
    EXPECT_FALSE(r.gap_detected);
    EXPECT_EQ(r.paid, 1u);
}

// ═══════════════════════════════════════════════════════════════════════════
// CASE 3b — refusal arm, WITH the store wired: the catch-up walk refuses (a
// hole again) and the stamp is too old to serve — the seed is STORED but
// serving is NOT armed. Refusal-to-arm is not a wipe: no reseed latch, the
// entries stay, and the incumbent lane keeps its job.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashMnGapRepair, BelowTipSeedRefusedCatchUpStoredButNotArmed)
{
    Fixture fx;
    MnDiffStore store(fresh_db_dir("catchuphole"));
    ASSERT_TRUE(store.open());
    fx.populate_store(store, /*skip_height=*/H - 1);   // hole at the tip row

    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.set_mn_gap_repair(make_repair_fn(&store));
    tip(m, H - 1);
    m.on_mn_list_update(to_payee_list(fx.L0), SEED_H);

    EXPECT_FALSE(m.live())
        << "a below-tip queue front must never back a template";
    EXPECT_EQ(st.mnstates().size(), fx.L0.size())
        << "the seed itself is STORED — refusal to arm is not a wipe";
    EXPECT_EQ(m.mn_snapshot_height(), SEED_H);
    EXPECT_FALSE(m.mn_needs_reseed_latched());

    bool fb = false;
    WorkSelection sel = st.select_work([&]() { fb = true; return DashWorkData{}; });
    EXPECT_EQ(sel.source, WorkSource::DashdFallback);
    EXPECT_TRUE(fb);
}

// ═══════════════════════════════════════════════════════════════════════════
// CASE 3c — the consumer refuses a stamp that is too old when NO catch-up is
// wired at all. This is the bare currency gate — the exact behavioral change
// of the G7 split, and the RED-ON-BASE witness: before the split this seed
// armed serving with a queue front 2 blocks behind the tip.
// (Deliberately uses ONLY the pre-existing maintainer API so it compiles on
// the base commit; it FAILS there — live() came back true.)
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashMnGapRepair, BelowTipSeedWithoutCatchUpMustNotArmServing)
{
    Fixture fx;
    NodeCoinState st;
    CoinStateMaintainer m(st);
    tip(m, H - 1);                                        // the tip moved first
    m.on_mn_list_update(to_payee_list(fx.L0), SEED_H);    // stale stamp

    EXPECT_FALSE(m.live())
        << "a below-tip seed with no diff-store catch-up must not arm serving";
    EXPECT_EQ(st.mnstates().size(), fx.L0.size())
        << "the seed is stored — refusal to arm is not a wipe";
    EXPECT_FALSE(m.mn_needs_reseed_latched());

    bool fb = false;
    WorkSelection sel = st.select_work([&]() { fb = true; return DashWorkData{}; });
    EXPECT_EQ(sel.source, WorkSource::DashdFallback);
    EXPECT_TRUE(fb);
}
