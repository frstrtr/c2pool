// SPDX-License-Identifier: AGPL-3.0-or-later
/// D2 root memo — the REMAINING half of the 2026-08-07/08 hotel freeze class
/// (26 rigs -> 0, twice). D1 (test_dash_submit_gate_scaling.cpp) took the
/// serve gate off the per-share submit path; this suite pins that the gate
/// itself no longer re-hashes the world on every evaluation that remains
/// (~3 emit_ok per session per notify: ~78 per notify_all at 26 sessions).
///
/// WHY THE MEMO LIVES ON NodeCoinState AND NOT ON CalcMerkleRoot: emit_ok
/// does not hash the STORED SML. project_sml_confirmations returns a fresh
/// ~450 KB CSimplifiedMNList BY VALUE and the root was computed on THAT
/// per-call object — so a per-object cache is cold on every call by
/// construction. The memo must sit one level up, keyed by a mutation epoch
/// on the owning NodeCoinState, and on a hit it skips the projection copy
/// itself, not just the hashing.
///
/// THE THREE PINS, in order of what they cost when wrong:
///   T2 (stale serve = LOST BLOCK): a mutation of the SML or the quorum set
///      must invalidate the memo — a memo that never invalidates passes T1
///      forever while silently serving a bad-cbtx root on a winning share.
///   T3 (byte identity): the memoized root is byte-identical to the freshly
///      computed one — WHERE-and-HOW-OFTEN only, never WHAT.
///   T1 (the freeze): repeated emit_ok at a fixed epoch must not scale the
///      hash work with the call count.
///
/// The counters are on the ACTUAL hashing (vendor CalcMerkleRoot entry /
/// compute_merkle_root_quorums entry), not on a wrapper — so a memo defeated
/// by hashing a fresh per-call object (the exact dead-end above) still shows
/// up as a scaling count.
///
/// Constructed RED on pre-memo master: there, 100 warm emit_ok evaluations
/// cost 100 full SML-root computations + 100 full quorum-root computations
/// (measured by these counters); with the memo both deltas are 0.
///
/// Fixture mirrors test_dash_mn_confirm_rollover.cpp (helpers live in that
/// TU's anonymous namespace, so they are re-stated here) and the quorum
/// entries mirror test_dash_quorum_root.cpp's make_entry.

#include <gtest/gtest.h>

#include <impl/dash/coin/embedded_gbt.hpp>
#include <impl/dash/coin/sml_projection.hpp>
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/mn_state_db.hpp>
#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/node_coin_state.hpp>
#include <impl/dash/coin/quorum_manager.hpp>
#include <impl/dash/coin/quorum_root.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/vendor/llmq_commitment.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>

#include <core/uint256.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

using dash::coin::DashWorkData;
using dash::coin::DeclineReport;
using dash::coin::MNState;
using dash::coin::NodeCoinState;
using dash::coin::QuorumManager;
using dash::coin::build_embedded_cbtx;
using dash::coin::compute_merkle_root_local;
using dash::coin::compute_merkle_root_quorums;
using dash::coin::encode_cbtx;
using dash::coin::hash_commitment;
using dash::coin::quorum_root_compute_count;
using dash::coin::DASH_MN_MIN_CONFIRMATIONS_MAINNET;
using dash::coin::vendor::CCbTx;
using dash::coin::vendor::CFinalCommitment;
using dash::coin::vendor::CSimplifiedMNList;
using dash::coin::vendor::CSimplifiedMNListEntry;
using dash::coin::vendor::parse_cbtx;
using dash::coin::vendor::sml_calc_merkle_root_count;

namespace {

// Dash mainnet base58 version bytes (chainparams.cpp PUBKEY_ADDRESS=76,
// SCRIPT_ADDRESS=16) — same constants the rollover suite uses.
constexpr uint8_t DASH_PUBKEY_VER = 76;
constexpr uint8_t DASH_P2SH_VER   = 16;

// Template height well past V20 + MN_RR, matching mainnet steady state
// (same H as the rollover suite: proven outside every height-class refusal).
constexpr uint32_t H = 2'400'000;

uint256 raw256(uint8_t base) {
    uint256 h;
    for (size_t i = 0; i < 32; ++i)
        h.data()[i] = static_cast<uint8_t>(base + i);
    return h;
}

std::vector<unsigned char> p2pkh_script(uint8_t hashseed) {
    std::vector<unsigned char> s;
    s.push_back(0x76); s.push_back(0xa9); s.push_back(0x14);
    for (int i = 0; i < 20; ++i)
        s.push_back(static_cast<unsigned char>(hashseed + i));
    s.push_back(0x88); s.push_back(0xac);
    return s;
}

CSimplifiedMNListEntry sml_entry(const uint256& protx,
                                 const uint256& confirmed) {
    CSimplifiedMNListEntry e;
    e.nVersion      = CSimplifiedMNListEntry::VER_BASIC_BLS;
    e.proRegTxHash  = protx;
    e.confirmedHash = confirmed;
    e.netPort       = 9999;
    e.isValid       = true;
    return e;
}

MNState mn_state(uint32_t reg_height,
                 const std::vector<unsigned char>& payout) {
    MNState s;
    s.isValid             = true;
    s.nRegisteredHeight   = reg_height;
    s.nLastPaidHeight     = 0;
    s.scriptPayout.m_data = payout;
    s.payoutSplitProvenance = MNState::SPLIT_KNOWN;
    return s;
}

// A fully-specified non-indexed (v1) commitment, distinguishable by its
// serialized bytes (mirror of test_dash_quorum_root.cpp::make_commitment).
CFinalCommitment make_commitment(uint8_t llmqType, unsigned char hash_seed,
                                 int16_t quorumIndex) {
    CFinalCommitment c;
    c.nVersion = CFinalCommitment::LEGACY_BLS_NON_INDEXED_QUORUM_VERSION;
    c.llmqType = llmqType;
    for (int i = 0; i < 32; ++i) c.quorumHash.data()[i] = hash_seed;
    c.quorumIndex = quorumIndex;
    c.signers.assign(8, false);
    c.validMembers.assign(8, true);
    return c;
}

QuorumManager::Entry make_entry(uint8_t llmqType, unsigned char hash_seed,
                                int16_t quorumIndex, uint32_t mining_height) {
    QuorumManager::Entry e;
    e.commitment = make_commitment(llmqType, hash_seed, quorumIndex);
    e.key = QuorumManager::ActiveKey{llmqType, e.commitment.quorumHash};
    e.mining_height = mining_height;
    return e;
}

// The shared fixture: two MNs (MN2's registration height parameterized so a
// test can choose a below-threshold or crossing shape), a non-empty quorum
// set, and a NodeCoinState wired exactly as the rollover suite's passing
// emit-gate test wires it.
struct Rig {
    uint256 protx1 = raw256(0x01);
    uint256 protx2 = raw256(0x02);
    uint256 prev_hash = raw256(0xAB);
    uint32_t prev_height = H - 1;
    CSimplifiedMNList sml;
    NodeCoinState st;

    explicit Rig(uint32_t mn2_reg_height) {
        std::vector<CSimplifiedMNListEntry> entries;
        entries.push_back(sml_entry(protx1, raw256(0x77)));  // long confirmed
        entries.push_back(sml_entry(protx2, uint256()));     // awaiting rollover
        sml = CSimplifiedMNList(std::move(entries));

        st.set_require_sml(true);
        st.sml() = sml;
        st.set_have_sml(true);
        st.set_sml_current_hash(prev_hash);
        st.mnstates().load(
            {{protx1, mn_state(2'300'000, p2pkh_script(0x30))},
             {protx2, mn_state(mn2_reg_height, p2pkh_script(0x44))}},
            prev_height);
        std::vector<QuorumManager::Entry> active;
        active.push_back(make_entry(CFinalCommitment::LLMQ_400_60, 0x22, 0, 90));
        active.push_back(make_entry(CFinalCommitment::LLMQ_100_67, 0x33, 0, 95));
        st.qmgr().replace_state(std::move(active), {});
        st.set_tip(prev_height, prev_hash, 0x1b104be3u, 1'700'000'000u,
                   DASH_PUBKEY_VER, DASH_P2SH_VER);
    }

    // A template committing the CURRENT expected values: root of `list`
    // (caller passes the projected list where projection is non-identity)
    // + the plain quorum root over the CURRENT active set.
    DashWorkData template_committing(const CSimplifiedMNList& list) {
        DashWorkData w;
        CCbTx cb = build_embedded_cbtx(prev_height, list,
                                       std::as_const(st).qmgr(),
                                       0, std::array<uint8_t, 96>{}, 0,
                                       nullptr);
        w.m_coinbase_payload = encode_cbtx(cb);
        return w;
    }

    // INDEPENDENT quorum-root reference (mirror of the rollover suite's
    // oracle discipline): re-derive the leaf set + sort + merkle by hand,
    // never through the emit gate under test.
    uint256 reference_quorum_root() const {
        std::vector<uint256> leaves;
        for (const auto& e : std::as_const(st).qmgr().active_entries())
            leaves.push_back(hash_commitment(e.commitment));
        std::sort(leaves.begin(), leaves.end(),
                  [](const uint256& a, const uint256& b) {
                      return std::memcmp(a.data(), b.data(), 32) < 0;
                  });
        return compute_merkle_root_local(std::move(leaves));
    }
};

// Below-threshold registration: the confirmation-pass projection is the
// identity, so the raw tip SML is exactly what a valid template commits.
constexpr uint32_t BELOW_THRESHOLD_REG = H - DASH_MN_MIN_CONFIRMATIONS_MAINNET;
// Crossing registration: the projection flips MN2's confirmedHash, so the
// committed root differs from the raw tip root (projection non-identity).
constexpr uint32_t CROSSING_REG = H - 1 - DASH_MN_MIN_CONFIRMATIONS_MAINNET;

}  // namespace

// ── T1 — the freeze pin: hash work must not scale with emit_ok calls ─────
//
// RED on pre-memo master by construction: every evaluation re-projected the
// SML (fresh ~450 KB copy), re-hashed its ~full-list merkle root AND
// re-serialized + re-hashed every active quorum commitment. 100 warm calls
// == 100 + 100 full root computations there; == 0 + 0 here.
TEST(DashRootMemo, WarmEmitOkDoesNotScaleHashWorkWithCallCount)
{
    Rig rig(BELOW_THRESHOLD_REG);
    auto w = rig.template_committing(rig.sml);

    DeclineReport why;
    ASSERT_TRUE(rig.st.embedded_template_emit_ok(w, &why))
        << "fixture must PASS the gate or the scaling loop below never "
        << "reaches the root checks (cause=" << why.cause
        << " value=" << why.value << ")";

    const uint64_t sml_before    = sml_calc_merkle_root_count();
    const uint64_t quorum_before = quorum_root_compute_count();
    constexpr int N = 100;
    for (int i = 0; i < N; ++i)
        ASSERT_TRUE(rig.st.embedded_template_emit_ok(w, nullptr));
    const uint64_t sml_delta    = sml_calc_merkle_root_count() - sml_before;
    const uint64_t quorum_delta = quorum_root_compute_count() - quorum_before;

    EXPECT_EQ(sml_delta, 0u)
        << N << " warm emit_ok evaluations performed " << sml_delta
        << " full SML merkle-root computations — the memo is cold or "
        << "defeated (pre-memo master measures " << N << " here)";
    EXPECT_EQ(quorum_delta, 0u)
        << N << " warm emit_ok evaluations performed " << quorum_delta
        << " full quorum-root computations — the memo is cold or defeated "
        << "(pre-memo master measures " << N << " here)";
}

// ── T2 — the pin that matters MORE than the freeze: invalidation ─────────
//
// A memo that never invalidates passes T1 and silently approves a STALE
// root after the state moves — on a winning share that is a consensus-
// invalid block (bad-cbtx-mnmerkleroot / -quorummerkleroot), silently lost.
// Proven red by removing the epoch bump from the non-const accessors.
TEST(DashRootMemo, SmlMutationInvalidatesMemoizedRoot)
{
    Rig rig(BELOW_THRESHOLD_REG);
    auto stale = rig.template_committing(rig.sml);

    // Warm the memo on the pre-mutation state.
    DeclineReport why;
    ASSERT_TRUE(rig.st.embedded_template_emit_ok(stale, &why))
        << "cause=" << why.cause << " value=" << why.value;

    // Mutate the SML through the SAME mutable accessor every production
    // writer uses (apply_diff, warm-restart load, reorg wipe). netPort is an
    // SML-hashed field: the true committed root changes.
    const uint64_t epoch_before = rig.st.root_memo_epoch();
    rig.st.sml().mnList[0].netPort = 12345;
    EXPECT_GT(rig.st.root_memo_epoch(), epoch_before)
        << "handing out a mutable SML reference must bump the memo epoch";

    // The template committing the PRE-mutation root must now be REJECTED —
    // a stale memo would keep approving it.
    EXPECT_FALSE(rig.st.embedded_template_emit_ok(stale, &why))
        << "emit_ok approved the PRE-mutation root after an SML mutation: "
        << "the memo served a stale root (this is a silently lost block)";
    EXPECT_EQ(why.cause, std::string("emit-mnlist-root-drift"));

    // And the template committing the POST-mutation root must PASS —
    // proving the gate recomputed the real new value, not just "something
    // changed".
    CSimplifiedMNList mutated = rig.sml;
    mutated.mnList[0].netPort = 12345;
    auto fresh = rig.template_committing(mutated);
    EXPECT_TRUE(rig.st.embedded_template_emit_ok(fresh, &why))
        << "cause=" << why.cause << " value=" << why.value;
}

TEST(DashRootMemo, QuorumMutationInvalidatesMemoizedRoot)
{
    Rig rig(BELOW_THRESHOLD_REG);
    auto stale = rig.template_committing(rig.sml);

    DeclineReport why;
    ASSERT_TRUE(rig.st.embedded_template_emit_ok(stale, &why))
        << "cause=" << why.cause << " value=" << why.value;

    // Mutate the quorum set through the same mutable accessor the
    // maintainer's diff-apply path uses.
    const uint64_t epoch_before = rig.st.root_memo_epoch();
    std::vector<QuorumManager::Entry> active;
    active.push_back(make_entry(CFinalCommitment::LLMQ_400_60, 0x22, 0, 90));
    active.push_back(make_entry(CFinalCommitment::LLMQ_100_67, 0x33, 0, 95));
    active.push_back(make_entry(CFinalCommitment::LLMQ_400_85, 0x55, 0, 99));
    rig.st.qmgr().replace_state(std::move(active), {});
    EXPECT_GT(rig.st.root_memo_epoch(), epoch_before)
        << "handing out a mutable QuorumManager reference must bump the "
        << "memo epoch";

    EXPECT_FALSE(rig.st.embedded_template_emit_ok(stale, &why))
        << "emit_ok approved the PRE-mutation quorum root after the active "
        << "set changed: the memo served a stale root";
    EXPECT_EQ(why.cause, std::string("emit-quorum-root-drift"));

    auto fresh = rig.template_committing(rig.sml);
    EXPECT_TRUE(rig.st.embedded_template_emit_ok(fresh, &why))
        << "cause=" << why.cause << " value=" << why.value;
}

// ── T3 — byte identity: the memo changes WHERE/HOW OFTEN, never WHAT ─────
//
// Uses the CROSSING shape so the memoized value is the non-trivial
// PROJECTED root (the projection actually flips a confirmedHash) and both
// references are re-derived independently of the gate (rollover-suite
// oracle discipline: hand-copied list, hand-derived quorum leaves).
TEST(DashRootMemo, MemoizedRootsAreByteIdenticalToIndependentReference)
{
    Rig rig(CROSSING_REG);

    // Independent references.
    CSimplifiedMNList projected_ref = rig.sml;
    for (auto& e : projected_ref.mnList)
        if (e.proRegTxHash == rig.protx2) e.confirmedHash = rig.prev_hash;
    const uint256 ref_sml_root    = projected_ref.CalcMerkleRoot();
    const uint256 ref_quorum_root = rig.reference_quorum_root();
    ASSERT_NE(ref_sml_root, CSimplifiedMNList(rig.sml).CalcMerkleRoot())
        << "fixture defect: the projection must be non-identity here or the "
        << "test cannot tell the projected root from the tip root";

    // A template committing exactly the references must pass COLD...
    auto good = rig.template_committing(projected_ref);
    {
        CCbTx cb;
        ASSERT_TRUE(parse_cbtx(good.m_coinbase_payload, cb));
        ASSERT_EQ(cb.merkleRootMNList, ref_sml_root);
        ASSERT_EQ(cb.merkleRootQuorums, ref_quorum_root);
    }
    DeclineReport why;
    EXPECT_TRUE(rig.st.embedded_template_emit_ok(good, &why))
        << "cold: cause=" << why.cause << " value=" << why.value;
    // ...and WARM (the memoized compare against the same reference bytes),
    // without any further hashing.
    const uint64_t sml_before    = sml_calc_merkle_root_count();
    const uint64_t quorum_before = quorum_root_compute_count();
    EXPECT_TRUE(rig.st.embedded_template_emit_ok(good, &why))
        << "warm: cause=" << why.cause << " value=" << why.value;
    EXPECT_EQ(sml_calc_merkle_root_count() - sml_before, 0u);
    EXPECT_EQ(quorum_root_compute_count() - quorum_before, 0u);

    // A template with a flipped SML root must be rejected ON THE WARM PATH,
    // and the gate's own expected value (why.threshold) must name the
    // reference root — byte-for-byte the same first 12 hex digits the
    // decline report carries. If the memo changed WHAT we serve, this is
    // where it shows.
    DashWorkData bad = good;
    {
        CCbTx cb;
        ASSERT_TRUE(parse_cbtx(bad.m_coinbase_payload, cb));
        cb.merkleRootMNList.data()[0] ^= 0x01;
        bad.m_coinbase_payload = encode_cbtx(cb);
    }
    EXPECT_FALSE(rig.st.embedded_template_emit_ok(bad, &why));
    EXPECT_EQ(why.cause, std::string("emit-mnlist-root-drift"));
    EXPECT_EQ(why.threshold, ref_sml_root.GetHex().substr(0, 12))
        << "the memoized expected root drifted from the independently "
        << "computed reference";
}
