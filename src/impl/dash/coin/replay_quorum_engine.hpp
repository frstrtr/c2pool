// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// W4 of the DASH FULL-HISTORY REPLAY mode (the/docs/
/// DASH_FULL_HISTORY_REPLAY_MODE.md §3 "Rotated-quorum member sets are
/// self-derivable", §4.1, §6 W4): the QUORUM LANE — reconstruct quorum state
/// purely from replayed MINED qfcommits, with NO qrinfo P2P dependency.
///
/// This is a NEW, feature-gated engine — it is wired into NOTHING. The serve
/// path (dkg_commitments.hpp / quorum_manager.hpp / node_coin_state.hpp), the
/// wire-fed qrinfo consumer (vendor/quorum_members_rotated.hpp) and every
/// existing gate are untouched; W5 does the source inversion. Until then the
/// only callers are the KATs.
///
/// ─────────────────────────────────────────────────────────────────────────
/// WHAT THIS IS
/// ─────────────────────────────────────────────────────────────────────────
/// Three reconstructions, each transcribed from dashd v23.1.x and each
/// self-checked against chain-committed bytes:
///
///  1. ACTIVE QUORUM SETS per llmqType, from the replayed stream of mined
///     type-6 commitments (llmq/blockprocessor.cpp
///     GetMinedAndActiveCommitmentsUntilBlock):
///       * non-rotated type: the most recent `signingActiveQuorumCount`
///         MINED commitments (GetMinedCommitmentsUntilBlock — ordered by
///         mined height);
///       * rotated type: the most recent mined commitment PER quorumIndex
///         (GetLastMinedCommitmentsPerQuorumIndexUntilBlock, cycle 0).
///
///  2. merkleRootQuorums per block (evo/cbtx.cpp CalcCbTxMerkleRootQuorums):
///     leaves = SerializeHash(commitment) of every active commitment as of
///     the PREVIOUS block, then the block's OWN non-null commitments folded
///     in (rotated: replace the leaf with the same quorumIndex; non-rotated:
///     evict the OLDEST-mined active leaf once at capacity), all leaves
///     sorted (uint256 memcmp) and SHA256d-merkled. THE SELF-CHECK: every
///     mainnet block since DIP0008 commits this root in its cbTx — the
///     engine asserts equality at EVERY replayed block and hard-stops
///     (poisons) on the first mismatch, naming the height and both roots
///     (design doc §4.2 layer 3; same posture as W1's DML fold).
///
///  3. ROTATED (DIP-0024) QUORUM MEMBERSHIP — the piece that replaces the
///     qrinfo port (llmq/utils.cpp ComputeQuorumMembersByQuarterRotation,
///     ported EXACTLY, including BuildQuorumSnapshot + the skip-list
///     PRODUCER that the wire consumer in quorum_members_rotated.hpp
///     deliberately omitted): at every rotated cycle base H the engine
///       * replays the three PREVIOUS quarters from its OWN per-cycle
///         snapshot store (seeded at the Phase-1 anchor, self-produced
///         thereafter — "those snapshots are produced by the replay itself
///         at every cycle base", design doc §3),
///       * builds the NEW quarter (skip-list emission ported verbatim,
///         including the upstream `firstSkippedIndex == 0` sentinel quirk),
///       * stores the produced CQuorumSnapshot for cycle H (the input to
///         cycle H+C, H+2C, H+3C — the recurrence that makes qrinfo
///         unnecessary), and
///       * stores the 32 ordered member lists (proTxHash sequences,
///         index-aligned with commitment signers/validMembers bitsets).
///     Non-rotated membership (ComputeQuorumMembers over the work-block
///     list, post-V20 modifier) is derived at every non-rotated quorum base
///     for the same consumer.
///
/// The member store feeds exactly the resolver seam W1's DML fold engine
/// exposes (replay_fold_engine.hpp DmlFoldEngine::MembersFn): given
/// (llmqType, quorumHash) return the ORDERED member proTxHash list, so the
/// qfcommit PoSe-punish pass can attribute invalid-marked members. NOTE ONE
/// INTERFACE RECONCILIATION POINT for W5: this engine returns the TRUE
/// member-list length (upstream GetAllQuorumMembers may return fewer than
/// params.size members on a thin list; HandleQuorumCommitment iterates
/// members.size(), not the bitset size), while W1's fold_qfcommit currently
/// requires members.size() == validMembers.size() exactly. On mainnet-scale
/// lists the two agree; the strict check is W1's to relax at integration.
///
/// ─────────────────────────────────────────────────────────────────────────
/// INPUT INTERFACE (mirrors W1's consumer shape — parsed block + qfcommit
/// list; no hard coupling to any other work package)
/// ─────────────────────────────────────────────────────────────────────────
/// Per block the engine consumes a QuorumBlockInput: {height, block hash,
/// the cbTx fields it self-checks against (merkleRootQuorums) and folds
/// (bestCLSignature — the V20 hash-modifier input), and the block's parsed
/// type-6 payloads in tx order}. A convenience adapter builds that from a
/// parsed dash::coin::BlockType. The MN list at a WORK block (base − 8) is
/// injected via MnListAtFn — in integration W1/W3 serve it from the replayed
/// DML (historical lists); the KATs serve captured SMLs. Returning nullopt
/// fails member derivation closed for that cycle (named, non-poisoning: the
/// root self-check is commitment-only and keeps running).
///
/// ─────────────────────────────────────────────────────────────────────────
/// SCOPE GATES (fail closed, never drift — design doc §3)
/// ─────────────────────────────────────────────────────────────────────────
/// * V20 floor: the modifier era this engine reproduces is post-V20
///   (mainnet 1987776). Observation below the floor refuses — the pre-V20
///   modifier/member branches are Phase-2 (genesis replay) work and MUST
///   NOT be guessed.
/// * CHAINPARAMS vs ENABLED types: the quorums-root set iterates dashd's
///   CHAINPARAMS llmq list (mainnet: 50_60, 400_60, 400_85, 100_67, 60_75),
///   NOT the runtime-enabled set (dkg_commitments.hpp enabled_llmqs, which
///   correctly drops 50_60 on mainnet). LLMQ_50_60 stopped being MINED at
///   DIP0024 (~h 1738698) but its last 24 commitments remain in dashd's
///   active set FOREVER (GetMinedAndActiveCommitmentsUntilBlock walks the
///   chainparams list) and therefore in every committed merkleRootQuorums —
///   the "type=1 MINED-BUT-NOT-REQUIRED" reconcile class, seen from the
///   other side. A replay seeded at a modern anchor can never observe those
///   frozen commitments from blocks; they arrive via the anchor seed
///   (Phase 1) or the genesis replay (Phase 2).
/// * A commitment of a type not in the chainparams list, an unresolvable
///   quorumHash, an excess active set, or a root mismatch each poison the
///   engine — serving from a state that has already diverged from consensus
///   is the one unforgivable outcome (same rule as W1).

#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/dkg_commitments.hpp>       // LlmqParamsView, kLlmq*
#include <impl/dash/coin/quorum_root.hpp>           // hash_commitment, merkle
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/vendor/llmq_commitment.hpp>
#include <impl/dash/coin/vendor/quorum_members.hpp> // compute_quorum_modifier
#include <impl/dash/coin/vendor/quorum_rotation_info.hpp> // CQuorumSnapshot

#include <core/hash.hpp>
#include <core/log.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace coin {
namespace replay {

/// dashcore llmq/snapshot.h WORK_DIFF_DEPTH — the work block of a quorum
/// (cycle) base at height B is the block at B − 8.
inline constexpr uint32_t kWorkDiffDepth = 8;

/// The CHAINPARAMS llmq list (chainparams.cpp AddLLMQ order) — the set the
/// quorums-root fold iterates. NOT the runtime-enabled set; see the header
/// note on LLMQ_50_60. RE-DERIVE on a vendored-dashcore pin bump.
inline const std::vector<LlmqParamsView>& replay_chainparams_llmqs(LlmqNetwork net)
{
    static const std::vector<LlmqParamsView> kMainnet{
        kLlmq50_60, kLlmq60_75, kLlmq400_60, kLlmq400_85, kLlmq100_67};
    static const std::vector<LlmqParamsView> kTestnet{
        kLlmq50_60, kLlmq60_75, kLlmq400_60, kLlmq400_85, kLlmq100_67,
        kLlmq25_67};
    return net == LlmqNetwork::Mainnet ? kMainnet : kTestnet;
}

inline const LlmqParamsView* replay_llmq_params(LlmqNetwork net, uint8_t type)
{
    for (const auto& p : replay_chainparams_llmqs(net))
        if (p.type == type) return &p;
    return nullptr;
}

/// One MN of the list at a WORK block, as member computation consumes it.
/// In integration this is projected from W1's replayed DML (which carries
/// every field, collateral included); the KATs project it from captured
/// SMLs (which cannot carry the collateral — see the tie note below).
struct QuorumMnEntry {
    uint256                 proTxHash;
    uint256                 confirmedHash;
    bool                    is_valid{false};   // == !PoSe-banned (SML isValid)
    uint16_t                n_type{0};         // 0 regular, 1 Evo
    std::array<uint8_t, 48> pub_key_operator{};
    /// Upstream breaks a score TIE by collateralOutpoint
    /// (llmq/utils.cpp CalculateQuorum). A replay-fed list carries it and
    /// the tiebreak is ported EXACTLY; an SML-fed list cannot, and a tie
    /// then fails closed (a tie needs a SHA256 collision — correctness
    /// fence, not a live risk; same posture as quorum_members_rotated.hpp).
    bool                    has_collateral{false};
    uint256                 collateral_hash;
    uint32_t                collateral_index{0};
};

/// height → the full MN list at that height (a WORK block: cycle base − 8).
/// nullopt => member derivation for that cycle fails closed (named).
using MnListAtFn =
    std::function<std::optional<std::vector<QuorumMnEntry>>(uint32_t height)>;

// ═══════════════════════════════════════════════════════════════════════════
// Rotation machinery — dashd llmq/utils.cpp anonymous namespace, ported
// EXACTLY, including the snapshot/skip-list PRODUCER side.
// ═══════════════════════════════════════════════════════════════════════════

namespace rotdetail {

using MnRef = const QuorumMnEntry*;

/// CDeterministicMNList score: sha256(sha256(proTxHash‖confirmedHash) ‖
/// modifier) — single-SHA256 each step (dmnstate.h:141 precompute folded in).
inline std::array<uint8_t, 32> mn_score(const QuorumMnEntry& e,
                                        const uint256& modifier)
{
    std::array<uint8_t, 32> chwp{};
    CSHA256()
        .Write(e.proTxHash.data(), 32)
        .Write(e.confirmedHash.data(), 32)
        .Finalize(chwp.data());
    std::array<uint8_t, 32> score{};
    CSHA256()
        .Write(chwp.data(), 32)
        .Write(modifier.data(), 32)
        .Finalize(score.data());
    return score;
}

/// arith_uint256 '<' == little-endian numeric compare on the 32 bytes.
inline bool score_lt(const std::array<uint8_t, 32>& a,
                     const std::array<uint8_t, 32>& b)
{
    for (int i = 31; i >= 0; --i)
        if (a[i] != b[i]) return a[i] < b[i];
    return false;
}

/// dashd COutPoint operator< (uint256::Compare == memcmp on the internal LE
/// bytes, then the index).
inline bool outpoint_lt(const QuorumMnEntry& a, const QuorumMnEntry& b)
{
    const int c = std::memcmp(a.collateral_hash.data(),
                              b.collateral_hash.data(), 32);
    if (c != 0) return c < 0;
    return a.collateral_index < b.collateral_index;
}

/// CalculateScoresForQuorum eligibility: PoSe-banned out, unconfirmed out
/// (the proRegTxHash-grinding guard), and — platform type only — non-Evo out.
inline bool eligible(const QuorumMnEntry& e, bool evo_only)
{
    if (!e.is_valid) return false;
    if (e.confirmedHash.IsNull()) return false;
    if (evo_only && e.n_type != 1) return false;
    return true;
}

/// dashd CalculateQuorum with maxSize == 0: score every eligible candidate
/// and sort DESCENDING by score. Upstream sorts std::sort(rbegin, rend,
/// {score asc, tie: collateralOutpoint asc}) — equivalently, the FINAL
/// sequence is descending by score and, on an equal score, descending by
/// collateralOutpoint. Ported as a direct descending sort with that exact
/// tiebreak. An adjacent equal score where either side lacks collateral
/// info cannot be ordered upstream-identically → nullopt (fail closed).
inline std::optional<std::vector<MnRef>> calculate_quorum_all(
    const std::vector<MnRef>& candidates, const uint256& modifier,
    bool evo_only = false)
{
    struct Scored {
        std::array<uint8_t, 32> score;
        MnRef                   mn;
    };
    std::vector<Scored> scored;
    scored.reserve(candidates.size());
    for (MnRef e : candidates) {
        if (e == nullptr) return std::nullopt;
        if (!eligible(*e, evo_only)) continue;
        scored.push_back(Scored{mn_score(*e, modifier), e});
    }
    std::sort(scored.begin(), scored.end(), [](const Scored& a, const Scored& b) {
        if (a.score != b.score) return score_lt(b.score, a.score); // descending
        if (a.mn->has_collateral && b.mn->has_collateral)
            return outpoint_lt(*b.mn, *a.mn);   // tie: collateral DESC (see note)
        return false;                            // unordered; detected below
    });
    for (size_t i = 0; i + 1 < scored.size(); ++i) {
        if (scored[i].score == scored[i + 1].score
            && !(scored[i].mn->has_collateral
                 && scored[i + 1].mn->has_collateral)) {
            return std::nullopt;   // tie not resolvable from these inputs
        }
    }
    std::vector<MnRef> out;
    out.reserve(scored.size());
    for (const auto& s : scored) out.push_back(s.mn);
    return out;
}

inline std::vector<MnRef> all_refs(const std::vector<QuorumMnEntry>& list)
{
    std::vector<MnRef> v;
    v.reserve(list.size());
    for (const auto& e : list) v.push_back(&e);
    return v;
}

struct ProRegLess {
    bool operator()(const uint256& a, const uint256& b) const
    {
        return std::memcmp(a.data(), b.data(), 32) < 0;
    }
};
using ProRegSet = std::set<uint256, ProRegLess>;

inline MnRef find_by_protx(const std::vector<QuorumMnEntry>& list,
                           const uint256& protx)
{
    for (const auto& e : list)
        if (std::memcmp(e.proTxHash.data(), protx.data(), 32) == 0) return &e;
    return nullptr;
}

/// dashd GetQuorumQuarterMembersBySnapshot — the CONSUMER leg (replaying a
/// previous cycle's quarter from its committed snapshot). Identical
/// semantics to vendor/quorum_members_rotated.hpp's port, over replay
/// entries. Bounded iteration (refuse instead of spinning) is the one
/// deliberate deviation, shared with that port.
inline std::optional<std::vector<std::vector<MnRef>>>
get_quarter_members_by_snapshot(size_t num_quorums, size_t quarter_size,
                                const std::vector<QuorumMnEntry>& work_list,
                                const uint256& modifier,
                                const vendor::CQuorumSnapshot& snapshot)
{
    std::vector<MnRef> sorted_combined;
    {
        auto sorted_all = calculate_quorum_all(all_refs(work_list), modifier);
        if (!sorted_all) return std::nullopt;
        // Upstream sizes the bitset to the list TOTAL and indexes it over
        // the score-sorted ELIGIBLE list; a shorter bitset would be an OOB
        // read upstream — here it fails closed.
        if (snapshot.activeQuorumMembers.size() < sorted_all->size())
            return std::nullopt;
        std::vector<MnRef> used;
        used.reserve(sorted_all->size());
        size_t i = 0;
        for (MnRef mn : *sorted_all) {
            if (snapshot.activeQuorumMembers[i]) {
                used.push_back(mn);
            } else {
                if (mn->is_valid) sorted_combined.push_back(mn);
            }
            ++i;
        }
        sorted_combined.insert(sorted_combined.end(), used.begin(), used.end());
    }

    std::vector<std::vector<MnRef>> quarters(num_quorums);
    if (sorted_combined.empty()) return quarters;

    switch (snapshot.mnSkipListMode) {
    case vendor::CQuorumSnapshot::MODE_NO_SKIPPING: {
        size_t itm = 0;
        for (size_t i = 0; i < num_quorums; ++i) {
            while (quarters[i].size() < quarter_size) {
                quarters[i].push_back(sorted_combined[itm]);
                if (++itm == sorted_combined.size()) itm = 0;
            }
        }
        return quarters;
    }
    case vendor::CQuorumSnapshot::MODE_SKIPPING_ENTRIES: {
        // Skip list: first entry ABSOLUTE, later entries relative to it.
        // `first_entry_index == 0` is upstream's "not yet set" sentinel —
        // consensus behaviour, ported verbatim.
        size_t first_entry_index = 0;
        std::vector<int64_t> processed;
        processed.reserve(snapshot.mnSkipList.size());
        for (int32_t s : snapshot.mnSkipList) {
            if (first_entry_index == 0) {
                first_entry_index = static_cast<size_t>(s);
                processed.push_back(s);
            } else {
                processed.push_back(static_cast<int64_t>(first_entry_index) + s);
            }
        }
        int64_t idx = 0;
        size_t  itsk = 0;
        const uint64_t max_iters = static_cast<uint64_t>(processed.size())
            + static_cast<uint64_t>(num_quorums) * quarter_size
            + sorted_combined.size() + 1;
        uint64_t iters = 0;
        for (size_t i = 0; i < num_quorums; ++i) {
            while (quarters[i].size() < quarter_size) {
                if (++iters > max_iters) return std::nullopt;
                if (idx < 0
                    || static_cast<size_t>(idx) >= sorted_combined.size())
                    return std::nullopt;
                if (itsk < processed.size() && idx == processed[itsk]) {
                    ++itsk;
                } else {
                    quarters[i].push_back(
                        sorted_combined[static_cast<size_t>(idx)]);
                }
                ++idx;
                if (static_cast<size_t>(idx) == sorted_combined.size()) idx = 0;
            }
        }
        return quarters;
    }
    case vendor::CQuorumSnapshot::MODE_NO_SKIPPING_ENTRIES:
    case vendor::CQuorumSnapshot::MODE_ALL_SKIPPED:
    default:
        return quarters;   // upstream: empty quarters for these modes
    }
}

struct NewQuarterOutput {
    std::vector<std::vector<MnRef>> quarters;
    vendor::CQuorumSnapshot         snapshot;   // the PRODUCED cycle snapshot
};

/// dashd BuildNewQuorumQuarterMembers + BuildQuorumSnapshot — the PRODUCER
/// leg the wire consumer deliberately omitted. Emits the skip list exactly
/// as upstream (llmq/utils.cpp:408-448: `firstSkippedIndex` starts 0; the
/// first recorded skip is the ABSOLUTE index, every later one is relative)
/// and builds the CQuorumSnapshot for THIS cycle base: bitset sized to the
/// work list TOTAL (banned/unconfirmed included), bit i marking whether the
/// i-th entry of the score-sorted eligible list was used by any PREVIOUS
/// quarter; MODE_NO_SKIPPING on an empty skip list, MODE_SKIPPING_ENTRIES
/// otherwise (BuildQuorumSnapshot, llmq/utils.cpp:303-337).
inline std::optional<NewQuarterOutput> build_new_quarter_members(
    size_t num_quorums, size_t quarter_size,
    const std::vector<QuorumMnEntry>& work_list, const uint256& modifier,
    const std::array<std::vector<std::vector<MnRef>>, 3>& previous_quarters)
{
    NewQuarterOutput out;
    out.quarters.assign(num_quorums, {});

    size_t enabled = 0;
    for (const auto& e : work_list) if (e.is_valid) ++enabled;

    // MnsUsedAtH (union across quorum indexes, PREVIOUS quarters only) +
    // MnsUsedAtHIndexed[i]. AddMN keeps the FIRST insertion; post-V19
    // upstream drops members no longer in the H list (skipRemovedMNs — this
    // engine only serves post-V20, so always true) and PoSe-banned ones.
    ProRegSet          used_all;
    std::vector<MnRef> used_all_refs;
    std::vector<ProRegSet> used_indexed(num_quorums);
    for (size_t idx = 0; idx < num_quorums; ++idx) {
        for (size_t c = 0; c < previous_quarters.size(); ++c) { // H-C,H-2C,H-3C
            if (idx >= previous_quarters[c].size()) continue;
            for (MnRef mn : previous_quarters[c][idx]) {
                if (mn == nullptr) return std::nullopt;
                MnRef at_h = find_by_protx(work_list, mn->proTxHash);
                if (at_h == nullptr) continue;    // !allMns.HasMN
                if (!at_h->is_valid) continue;    // allMns.IsMNPoSeBanned
                if (used_all.insert(mn->proTxHash).second)
                    used_all_refs.push_back(mn);
                used_indexed[idx].insert(mn->proTxHash);
            }
        }
    }

    // The PRODUCED snapshot's bitset: sized to the work-list TOTAL, bit i
    // over the score-sorted eligible list — filled before the early-outs so
    // a produced snapshot exists exactly when upstream stores one. Upstream
    // builds it AFTER the fill loop; the inputs (work list + used_all) are
    // fixed before the loop, so the order is observationally identical.
    auto sorted_all = calculate_quorum_all(all_refs(work_list), modifier);
    if (!sorted_all) return std::nullopt;
    out.snapshot.activeQuorumMembers.assign(work_list.size(), false);
    {
        size_t i = 0;
        for (MnRef mn : *sorted_all) {
            if (used_all.count(mn->proTxHash))
                out.snapshot.activeQuorumMembers[i] = true;
            ++i;
        }
    }
    out.snapshot.mnSkipListMode = vendor::CQuorumSnapshot::MODE_NO_SKIPPING;
    out.snapshot.mnSkipList.clear();

    if (enabled < quarter_size) return out;   // upstream: empty quarters

    // MnsNotUsedAtH: everything in the H list no previous quarter used and
    // not PoSe-banned.
    std::vector<MnRef> not_used;
    not_used.reserve(work_list.size());
    for (const auto& e : work_list) {
        if (used_all.count(e.proTxHash)) continue;
        if (!e.is_valid) continue;
        not_used.push_back(&e);
    }

    auto sorted_used = calculate_quorum_all(used_all_refs, modifier);
    if (!sorted_used) return std::nullopt;
    auto sorted_combined = calculate_quorum_all(not_used, modifier);
    if (!sorted_combined) return std::nullopt;
    sorted_combined->insert(sorted_combined->end(),
                            sorted_used->begin(), sorted_used->end());
    if (sorted_combined->empty()) return out;

    // The fill loop with skip-list emission (llmq/utils.cpp:408-448).
    std::vector<int32_t> skip_list;
    size_t first_skipped_index = 0;
    size_t idx = 0;
    const uint64_t max_iters =
        static_cast<uint64_t>(num_quorums + 1) * sorted_combined->size()
        + static_cast<uint64_t>(num_quorums) * quarter_size + 1;
    uint64_t iters = 0;
    for (size_t i = 0; i < num_quorums; ++i) {
        const size_t used_count = used_indexed[i].size();
        bool   updated = false;
        size_t initial_loop_idx = idx;
        while (out.quarters[i].size() < quarter_size
               && (used_count + out.quarters[i].size()
                   < sorted_combined->size())) {
            if (++iters > max_iters) return std::nullopt;
            bool skip = true;
            MnRef cand = (*sorted_combined)[idx];
            if (!used_indexed[i].count(cand->proTxHash)) {
                used_indexed[i].insert(cand->proTxHash);
                out.quarters[i].push_back(cand);
                updated = true;
                skip    = false;
            }
            if (skip) {
                if (first_skipped_index == 0) {
                    first_skipped_index = idx;
                    skip_list.push_back(static_cast<int32_t>(idx));
                } else {
                    skip_list.push_back(
                        static_cast<int32_t>(idx - first_skipped_index));
                }
            }
            if (++idx == sorted_combined->size()) idx = 0;
            if (idx == initial_loop_idx) {
                if (!updated) {
                    // Not enough MNs: upstream abandons the whole new set
                    // (and still stores the snapshot it built).
                    out.quarters.assign(num_quorums, {});
                    return out;
                }
                updated = false;
            }
        }
    }

    if (!skip_list.empty()) {
        out.snapshot.mnSkipListMode =
            vendor::CQuorumSnapshot::MODE_SKIPPING_ENTRIES;
        out.snapshot.mnSkipList = std::move(skip_list);
    }
    return out;
}

} // namespace rotdetail

/// One cycle's inputs: the MN list at (cycleBase − 8) and GetHashModifier's
/// value for that cycle base.
struct RotationCycleInput {
    const std::vector<QuorumMnEntry>* mn_list{nullptr};
    uint256                           modifier;
};

struct RotationCycleOutput {
    /// signingActiveQuorumCount ordered member lists, each EXACTLY
    /// params.size proTxHashes, in dashd's consensus order
    /// ([H-3C quarter][H-2C][H-C][new]).
    std::vector<std::vector<uint256>> member_protx;
    /// The snapshot produced for THIS cycle base — the input the NEXT three
    /// cycles' member computations consume.
    vendor::CQuorumSnapshot           snapshot_at_h;
};

/// dashd ComputeQuorumMembersByQuarterRotation, producer edition. `cycles`
/// is indexed 0 = H (the cycle base being computed), 1 = H-C, 2 = H-2C,
/// 3 = H-3C; `snapshots` 0 = H-C, 1 = H-2C, 2 = H-3C.
inline std::optional<RotationCycleOutput> compute_rotation_cycle(
    const LlmqParamsView& params,
    const std::array<RotationCycleInput, 4>& cycles,
    const std::array<const vendor::CQuorumSnapshot*, 3>& snapshots,
    std::string* err = nullptr)
{
    auto fail = [&](const std::string& why) -> std::optional<RotationCycleOutput> {
        if (err) *err = why;
        return std::nullopt;
    };
    const size_t num_quorums = params.signing_active_quorum_count;
    const size_t quorum_size = params.size;
    if (!params.use_rotation) return fail("type is not a rotated LLMQ");
    if (num_quorums == 0 || quorum_size == 0 || quorum_size % 4 != 0)
        return fail("degenerate rotation params");
    const size_t quarter_size = quorum_size / 4;
    for (const auto& c : cycles)
        if (c.mn_list == nullptr) return fail("missing cycle MN list");
    for (const auto* s : snapshots)
        if (s == nullptr || !s->sane()) return fail("missing/insane snapshot");

    std::array<std::vector<std::vector<rotdetail::MnRef>>, 3> previous;
    for (size_t i = 0; i < 3; ++i) {
        auto q = rotdetail::get_quarter_members_by_snapshot(
            num_quorums, quarter_size, *cycles[i + 1].mn_list,
            cycles[i + 1].modifier, *snapshots[i]);
        if (!q) return fail("previous-quarter snapshot replay failed (cycle H-"
                            + std::to_string(i + 1) + "C)");
        previous[i] = std::move(*q);
    }

    auto built = rotdetail::build_new_quarter_members(
        num_quorums, quarter_size, *cycles[0].mn_list, cycles[0].modifier,
        previous);
    if (!built) return fail("new-quarter build failed");

    RotationCycleOutput out;
    out.snapshot_at_h = std::move(built->snapshot);
    out.member_protx.assign(num_quorums, {});
    for (size_t i = 0; i < num_quorums; ++i) {
        std::vector<rotdetail::MnRef> members;
        members.reserve(quorum_size);
        for (size_t c = previous.size(); c-- > 0;) {   // H-3C, H-2C, H-C
            members.insert(members.end(), previous[c][i].begin(),
                           previous[c][i].end());
        }
        members.insert(members.end(), built->quarters[i].begin(),
                       built->quarters[i].end());
        if (members.size() != quorum_size)
            return fail("assembled quorum index " + std::to_string(i) + " has "
                        + std::to_string(members.size()) + " members != "
                        + std::to_string(quorum_size) + " — refusing partial");
        out.member_protx[i].reserve(quorum_size);
        for (rotdetail::MnRef mn : members)
            out.member_protx[i].push_back(mn->proTxHash);
    }
    return out;
}

/// dashd ComputeQuorumMembers for a NON-rotated quorum (post-V20: list at
/// the WORK block, modifier from GetHashModifier at the quorum base). May
/// legitimately return fewer than params.size on a thin list — the TRUE
/// member-list length, exactly what HandleQuorumCommitment iterates.
inline std::optional<std::vector<uint256>> compute_nonrotated_members(
    const LlmqParamsView& params, bool evo_only,
    const std::vector<QuorumMnEntry>& work_list, const uint256& modifier,
    std::string* err = nullptr)
{
    if (params.use_rotation) {
        if (err) *err = "rotated type in non-rotated member computation";
        return std::nullopt;
    }
    auto sorted = rotdetail::calculate_quorum_all(
        rotdetail::all_refs(work_list), modifier, evo_only);
    if (!sorted) {
        if (err) *err = "score tie unresolvable from inputs";
        return std::nullopt;
    }
    std::vector<uint256> out;
    const size_t n = std::min<size_t>(params.size, sorted->size());
    out.reserve(n);
    for (size_t i = 0; i < n; ++i) out.push_back((*sorted)[i]->proTxHash);
    return out;
}

// ═══════════════════════════════════════════════════════════════════════════
// The engine
// ═══════════════════════════════════════════════════════════════════════════

struct QuorumReplayConfig {
    /// Feature flag — MUST be set explicitly; a default-constructed config
    /// refuses every observation, so nothing reaches this engine before W5
    /// wires it behind a node option (same rule as W1's FoldConfig).
    bool        enabled{false};
    LlmqNetwork network{LlmqNetwork::Mainnet};
    /// DEPLOYMENT_V20 activation (chainparams.cpp): mainnet 1987776,
    /// testnet 905100. Observation below refuses — pre-V20 modifier eras
    /// are Phase-2 work, fail closed, never guessed.
    uint32_t    v20_floor{1'987'776u};
    /// Retention for derived per-cycle state (members / snapshots /
    /// modifiers / block-hash window), in blocks behind the cursor. Must
    /// cover 3 rotated cycles + the longest mining window; the default is
    /// ~4 of the longest (576) interval.
    uint32_t    keep_depth{4096};
    bool        debug_logs{false};
};

/// Parsed per-block input — W1's consumer shape (parsed block + qfcommit
/// list), decoupled so KATs and the bulk-fetch lane (W2) can feed it
/// without constructing full BlockType objects.
struct QuorumBlockInput {
    uint32_t height{0};
    uint256  block_hash;
    /// cbTx answer key + V20 modifier input. Absent committed root =>
    /// the self-check cannot run at this block (refused when armed).
    std::optional<uint256> committed_merkle_root_quorums;
    std::optional<std::array<uint8_t, vendor::CCbTx::BLS_SIG_SIZE>> best_cl_sig;
    /// The block's type-6 payloads, in tx order (nulls included — the
    /// engine applies dashd's IsNull skip itself).
    std::vector<vendor::CFinalCommitmentTxPayload> commitments;
};

struct QuorumObserveResult {
    bool        ok{false};
    std::string error;              // on !ok: names height + blocking condition
    uint32_t    height{0};

    // THE self-check (filled whenever the fold completed far enough).
    uint256     computed_root;
    uint256     committed_root;
    bool        self_checked{false};

    // Observability counters.
    size_t      commitments_seen{0};
    size_t      commitments_null{0};
    size_t      commitments_ingested{0};
    size_t      member_cycles_derived{0};
    size_t      member_cycles_skipped{0};  // named misses (no MN list source…)
    std::vector<std::string> member_skip_reasons;
};

class QuorumReplayEngine
{
public:
    explicit QuorumReplayEngine(QuorumReplayConfig cfg) : m_cfg(std::move(cfg)) {}

    void set_mn_list_at_fn(MnListAtFn fn) { m_mn_list_at = std::move(fn); }

    // ── Seeding (Phase-1 trusted anchor; design doc §4.5) ────────────────
    // The seed is the same trust class as the versioned full-state
    // checkpoint W1/W3 define; the per-block root self-check then validates
    // it against consensus at anchor+1 (a wrong seed desyncs in ONE block).

    /// Declare the cursor: state is AT `height` (the next observable block
    /// is height+1).
    void seed_cursor(uint32_t height, const uint256& block_hash)
    {
        m_height     = height;
        m_block_hash = block_hash;
        m_seeded     = true;
        m_poisoned   = false;
        m_poison_reason.clear();
        // The cursor block is part of the observed chain: a quorum base at
        // the anchor height itself must resolve (an anchor mid-cycle sits
        // inside the rotated base run cycleBase..cycleBase+31).
        seed_block_hash(height, block_hash);
    }

    /// Register a historical height→hash mapping (quorum-base resolution
    /// for seeded commitments and for members_for()).
    void seed_block_hash(uint32_t height, const uint256& hash)
    {
        m_hash_by_height[height] = hash;
        m_height_by_hash[hash]   = height;
    }

    /// Seed a PRE-ANCHOR work block's cbTx bestCLSignature (or its absence).
    /// GetHashModifier reads exactly this plus the work block hash, both of
    /// which are chain data; without it the modifier at a cycle whose work
    /// block predates the anchor is underivable and the cycle is skipped by
    /// name. Post-anchor work blocks register the same fields by OBSERVATION
    /// — this seam exists only for the ≤3 pre-anchor cycles a Phase-1 rotated
    /// lane cannot reach (replay_quorum_bridge.hpp header note).
    void seed_work_block_cl(
        uint32_t height,
        const std::optional<std::array<uint8_t, vendor::CCbTx::BLS_SIG_SIZE>>& cl)
    {
        if (cl) m_cl_by_height[height] = *cl;
        m_cl_known.insert(height);
    }

    /// Seed one ACTIVE commitment (the anchor's active set — for mainnet
    /// that includes the frozen LLMQ_50_60 commitments; see header note).
    /// `base_height` is the quorum base block height (consensus-known from
    /// the anchor's header chain).
    bool seed_commitment(uint32_t base_height,
                         const vendor::CFinalCommitment& c, std::string& err)
    {
        const LlmqParamsView* p = replay_llmq_params(m_cfg.network, c.llmqType);
        if (p == nullptr) {
            err = "seed commitment names llmqType "
                + std::to_string(int(c.llmqType))
                + " not in the chainparams llmq list";
            return false;
        }
        StoredCommitment sc;
        sc.base_height = base_height;
        sc.mined_height = 0;   // unknown for a seed; ordering uses base_height
        sc.index       = c.quorumIndex;
        sc.quorum_hash = c.quorumHash;
        sc.hash        = hash_commitment(c);
        if (p->use_rotation) {
            auto& slot = m_rot[c.llmqType][c.quorumIndex];
            if (!slot.hash.IsNull() && slot.base_height >= base_height)
                return true;   // keep the newer one
            slot = sc;
        } else {
            auto& vec = m_nonrot[c.llmqType];
            vec.push_back(sc);
            std::sort(vec.begin(), vec.end(),
                      [](const StoredCommitment& a, const StoredCommitment& b) {
                          return a.base_height < b.base_height;
                      });
            // The active window keeps at most signingActiveQuorumCount.
            while (vec.size() > p->signing_active_quorum_count)
                vec.erase(vec.begin());
        }
        m_quorum_base_by_hash[key_of(c.llmqType, c.quorumHash)] = base_height;
        return true;
    }

    /// Seed a previous cycle's snapshot + modifier (rotated lane). At the
    /// Phase-1 anchor these come from the anchor state; from then on the
    /// engine produces its own.
    void seed_snapshot(uint8_t type, uint32_t cycle_base,
                       vendor::CQuorumSnapshot snap)
    {
        m_snapshots[{type, cycle_base}] = std::move(snap);
    }
    void seed_modifier(uint8_t type, uint32_t cycle_base, const uint256& m)
    {
        m_modifiers[{type, cycle_base}] = m;
    }

    /// Arm the per-block merkleRootQuorums self-check. Callers arm it once
    /// the commitment store is complete (a full anchor seed, or — in a
    /// warm-from-scan harness — once every type has reached its active
    /// quota). Unarmed, roots are still computed and reported, but a
    /// mismatch does not poison (warm-up must not look like divergence).
    void arm_self_check() { m_self_check = true; }
    bool self_check_armed() const { return m_self_check; }

    // ── Accessors ────────────────────────────────────────────────────────
    uint32_t           height() const        { return m_height; }
    const uint256&     block_hash() const    { return m_block_hash; }
    bool               poisoned() const      { return m_poisoned; }
    const std::string& poison_reason() const { return m_poison_reason; }

    /// Active commitment count for one type (rotated: per-index slots).
    size_t active_count(uint8_t type) const
    {
        if (auto it = m_rot.find(type); it != m_rot.end()) return it->second.size();
        if (auto it = m_nonrot.find(type); it != m_nonrot.end())
            return it->second.size();
        return 0;
    }

    /// Every chainparams type at its full active quota? (The warm-from-scan
    /// arming criterion: once true, the reconstructed set IS dashd's set —
    /// the K most recent mined commitments of a type are the K most recent
    /// regardless of where the scan started.)
    bool active_sets_complete() const
    {
        for (const auto& p : replay_chainparams_llmqs(m_cfg.network)) {
            if (active_count(p.type) < p.signing_active_quorum_count)
                return false;
        }
        return true;
    }

    /// WHICH types are short, and by how many — issue #90's missing half.
    ///
    /// `active_sets_complete()` is a bare bool, so a run that never completes
    /// cannot say WHY, and the fold_root_vs_committed counter it gates reads
    /// `0/N` forever with no blocking condition named. It has a NAME:
    ///
    ///   * MAINNET, LLMQ_50_60 (type 1) short by 24, PERMANENTLY. The type
    ///     stopped being MINED at DIP0024 (~h 1738698) but its last 24
    ///     commitments stay in dashd's active set forever, because
    ///     GetMinedAndActiveCommitmentsUntilBlock walks the CHAINPARAMS list
    ///     (v23.1.7 llmq/blockprocessor.cpp:664), not the runtime-enabled one.
    ///     A forward replay seeded at a modern anchor can NEVER observe them
    ///     from blocks. They must be SEEDED (seed_commitment(), 24 records) or
    ///     reached by a genesis replay (Phase 2).
    ///   * Any other type short: warm-up. It closes on its own within
    ///     signingActiveQuorumCount × dkgInterval blocks of the anchor —
    ///     576 blocks for the rotated type-5 ring, 96 for type 2/3.
    ///
    /// Empty => complete => the reconstructed set IS dashd's set and the root
    /// self-check may be armed.
    std::vector<std::pair<uint8_t, size_t>> active_set_shortfall() const
    {
        std::vector<std::pair<uint8_t, size_t>> out;
        for (const auto& p : replay_chainparams_llmqs(m_cfg.network)) {
            const size_t have = active_count(p.type);
            if (have < p.signing_active_quorum_count)
                out.emplace_back(p.type, p.signing_active_quorum_count - have);
        }
        return out;
    }

    /// Human-readable form of the above; "complete" when nothing is short.
    std::string active_set_shortfall_text() const
    {
        const auto miss = active_set_shortfall();
        if (miss.empty()) return "complete";
        std::string s;
        for (size_t i = 0; i < miss.size(); ++i) {
            if (i) s += ",";
            s += "type" + std::to_string(int(miss[i].first)) + ":short"
               + std::to_string(miss[i].second);
        }
        return s;
    }

    /// The W1 DmlFoldEngine::MembersFn contract: ORDERED member proTxHashes
    /// of the quorum (llmqType, quorumHash), or nullopt (caller fails
    /// closed). Resolution: quorumHash → observed/seeded height → the
    /// member list derived at that quorum's cycle.
    std::optional<std::vector<uint256>> members_for(uint8_t llmq_type,
                                                    const uint256& quorum_hash) const
    {
        auto hit = m_height_by_hash.find(quorum_hash);
        if (hit == m_height_by_hash.end()) return std::nullopt;
        auto mit = m_members.find({llmq_type, hit->second});
        if (mit == m_members.end()) return std::nullopt;
        return mit->second;
    }

    /// The produced (or seeded) per-cycle snapshot — the qrinfo replacement.
    std::optional<vendor::CQuorumSnapshot> snapshot_for(uint8_t type,
                                                        uint32_t cycle_base) const
    {
        auto it = m_snapshots.find({type, cycle_base});
        if (it == m_snapshots.end()) return std::nullopt;
        return it->second;
    }
    std::optional<uint256> modifier_for(uint8_t type, uint32_t cycle_base) const
    {
        auto it = m_modifiers.find({type, cycle_base});
        if (it == m_modifiers.end()) return std::nullopt;
        return it->second;
    }

    // ── observe_block — the per-block quorum fold + THE self-check ───────
    QuorumObserveResult observe_block(const QuorumBlockInput& in)
    {
        QuorumObserveResult r;
        r.height = in.height;

        if (!m_cfg.enabled) {
            r.error = "quorum replay engine is not enabled "
                      "(QuorumReplayConfig.enabled is the W4 feature flag; "
                      "W5 wires it)";
            return r;
        }
        if (m_poisoned) {
            r.error = "quorum replay engine is POISONED (" + m_poison_reason
                    + ") — re-seed required";
            return r;
        }
        if (!m_seeded) {
            r.error = "observe refused at h=" + std::to_string(in.height)
                    + ": engine has no seeded cursor";
            return r;
        }
        if (in.height < m_cfg.v20_floor) {
            r.error = "observe refused at h=" + std::to_string(in.height)
                    + ": below the V20 floor h="
                    + std::to_string(m_cfg.v20_floor)
                    + " (pre-V20 modifier eras are Phase-2 scope — fail "
                      "closed, never drift)";
            return r;
        }
        if (in.height != m_height + 1) {
            r.error = "observe refused at h=" + std::to_string(in.height)
                    + ": cursor is at h=" + std::to_string(m_height)
                    + " and the fold is forward-contiguous (only h="
                    + std::to_string(m_height + 1) + " is observable)";
            return r;
        }

        // Register this block in the height/hash window BEFORE anything
        // else — its own commitments may name earlier observed blocks, and
        // members_for() resolution needs every quorum base hash.
        m_hash_by_height[in.height] = in.block_hash;
        m_height_by_hash[in.block_hash] = in.height;
        if (in.best_cl_sig) m_cl_by_height[in.height] = *in.best_cl_sig;
        m_cl_known.insert(in.height);   // "observed" even when null CL

        // ── Per-cycle derivations at quorum/cycle bases ─────────────────
        derive_cycles_at(in.height, r);

        // ── merkleRootQuorums: fold the block's own commitments over the
        //    active set as of H−1 (CalcCbTxMerkleRootQuorums, verbatim
        //    fold rules), then self-check against the committed root. ────
        std::string fold_err;
        auto root = fold_root_with_block(in, r, fold_err);
        if (!root) {
            r.error = "quorum fold FAILED at h=" + std::to_string(in.height)
                    + ": " + fold_err;
            poison(r.error);
            return r;
        }
        r.computed_root = *root;
        if (m_self_check) {
            if (!in.committed_merkle_root_quorums) {
                r.error = "observe refused at h=" + std::to_string(in.height)
                        + ": self-check is armed but the block carries no "
                          "parseable cbTx merkleRootQuorums";
                poison(r.error);
                return r;
            }
            r.committed_root = *in.committed_merkle_root_quorums;
            r.self_checked = true;
            if (r.computed_root != r.committed_root) {
                r.error = "QUORUM ROOT MISMATCH at h="
                        + std::to_string(in.height)
                        + ": folded merkleRootQuorums "
                        + r.computed_root.GetHex()
                        + " != committed cbTx root " + r.committed_root.GetHex()
                        + " — HARD STOP, engine poisoned, re-seed required";
                poison(r.error);
                LOG_ERROR << "[QUORUM-REPLAY] " << r.error;
                return r;
            }
        } else if (in.committed_merkle_root_quorums) {
            r.committed_root = *in.committed_merkle_root_quorums;
        }

        // ── Ingest the block's non-null commitments into the mined store
        //    (they become "active as of this block", exactly dashd's
        //    ProcessBlock ordering: the root above used pindexPrev). ──────
        std::string ingest_err;
        if (!ingest_block_commitments(in, r, ingest_err)) {
            r.error = "quorum ingest FAILED at h=" + std::to_string(in.height)
                    + ": " + ingest_err;
            poison(r.error);
            return r;
        }

        prune(in.height);
        m_height     = in.height;
        m_block_hash = in.block_hash;
        r.ok = true;
        return r;
    }

    /// Convenience adapter: parsed dash block → QuorumBlockInput (mirrors
    /// W1's fold_block(block, height) consumer shape).
    static std::optional<QuorumBlockInput> input_from_block(
        const dash::coin::BlockType& block, uint32_t height,
        const uint256& block_hash, std::string* err = nullptr)
    {
        QuorumBlockInput in;
        in.height     = height;
        in.block_hash = block_hash;
        if (block.m_txs.empty()) {
            if (err) *err = "block has no transactions";
            return std::nullopt;
        }
        if (block.m_txs[0].type == 5) {
            vendor::CCbTx cb;
            if (!vendor::parse_cbtx(block.m_txs[0].extra_payload, cb)) {
                if (err) *err = "coinbase cbTx payload unparseable";
                return std::nullopt;
            }
            if (cb.nVersion >= vendor::CCbTx::VERSION_MERKLE_ROOT_QUORUMS)
                in.committed_merkle_root_quorums = cb.merkleRootQuorums;
            if (cb.nVersion >= vendor::CCbTx::VERSION_CLSIG_AND_BALANCE
                && cb.has_best_cl_signature())
                in.best_cl_sig = cb.bestCLSignature;
        }
        for (size_t i = 1; i < block.m_txs.size(); ++i) {
            const auto& tx = block.m_txs[i];
            if (tx.version != 3 || tx.type != 6) continue;
            vendor::CFinalCommitmentTxPayload qc;
            if (!vendor::parse_qfcommit_payload(tx.extra_payload, qc)) {
                if (err) *err = "unparseable qfcommit payload in tx["
                              + std::to_string(i) + "] (replay folds "
                                "byte-exact or not at all)";
                return std::nullopt;
            }
            in.commitments.push_back(std::move(qc));
        }
        return in;
    }

private:
    struct StoredCommitment {
        uint32_t base_height{0};    // quorum base block height
        uint32_t mined_height{0};   // 0 for anchor-seeded entries
        int16_t  index{0};
        uint256  quorum_hash;       // base block hash (for base re-resolution)
        uint256  hash;              // SerializeHash(commitment)
    };

    using TypeHeightKey = std::pair<uint8_t, uint32_t>;

    QuorumReplayConfig m_cfg;
    MnListAtFn         m_mn_list_at;

    // Mined/active commitment stores.
    std::map<uint8_t, std::vector<StoredCommitment>>       m_nonrot;
    std::map<uint8_t, std::map<int16_t, StoredCommitment>> m_rot;

    // Derived per-cycle state.
    std::map<TypeHeightKey, vendor::CQuorumSnapshot> m_snapshots;
    std::map<TypeHeightKey, uint256>                 m_modifiers;
    // Member lists keyed by (type, QUORUM BASE height): non-rotated at the
    // cycle base itself; rotated at cycleBase + quorumIndex.
    std::map<TypeHeightKey, std::vector<uint256>>    m_members;

    // Block index window.
    struct U256Less {
        bool operator()(const uint256& a, const uint256& b) const
        {
            return std::memcmp(a.data(), b.data(), 32) < 0;
        }
    };
    std::map<uint32_t, uint256>            m_hash_by_height;
    std::map<uint256, uint32_t, U256Less>  m_height_by_hash;
    std::map<uint32_t, std::array<uint8_t, vendor::CCbTx::BLS_SIG_SIZE>>
                                           m_cl_by_height;
    std::set<uint32_t>                     m_cl_known;
    // (type, quorumHash) → base height for commitments whose base predates
    // the window (anchor-seeded).
    std::map<std::string, uint32_t>        m_quorum_base_by_hash;

    uint32_t    m_height{0};
    uint256     m_block_hash;
    bool        m_seeded{false};
    bool        m_self_check{false};
    bool        m_poisoned{false};
    std::string m_poison_reason;

    void poison(const std::string& why)
    {
        m_poisoned      = true;
        m_poison_reason = why;
    }

    static std::string key_of(uint8_t type, const uint256& qh)
    {
        std::string k;
        k.push_back(static_cast<char>(type));
        k.append(reinterpret_cast<const char*>(qh.data()), 32);
        return k;
    }

    std::optional<uint32_t> resolve_base_height(uint8_t type,
                                                const uint256& qh) const
    {
        if (auto it = m_height_by_hash.find(qh); it != m_height_by_hash.end())
            return it->second;
        if (auto it = m_quorum_base_by_hash.find(key_of(type, qh));
            it != m_quorum_base_by_hash.end())
            return it->second;
        return std::nullopt;
    }

    /// GetHashModifier, post-V20 (llmq/utils.cpp:88-111): from the WORK
    /// block's own cbTx CL when non-null, else the work block hash.
    std::optional<uint256> compute_modifier(uint8_t type, uint32_t cycle_base,
                                            std::string* why) const
    {
        const uint32_t work_h = cycle_base - kWorkDiffDepth;
        auto hh = m_hash_by_height.find(work_h);
        if (hh == m_hash_by_height.end()) {
            if (why) *why = "work block h=" + std::to_string(work_h)
                          + " not in the observed window";
            return std::nullopt;
        }
        if (!m_cl_known.count(work_h)) {
            if (why) *why = "work block h=" + std::to_string(work_h)
                          + " has no observed cbTx CL field";
            return std::nullopt;
        }
        std::optional<std::array<uint8_t, vendor::CCbTx::BLS_SIG_SIZE>> cl;
        if (auto it = m_cl_by_height.find(work_h); it != m_cl_by_height.end())
            cl = it->second;
        return vendor::compute_quorum_modifier(type, work_h, cl, hh->second);
    }

    /// Per-cycle derivations at height H: for every chainparams type whose
    /// cycle base is H, compute + store the modifier, the member lists and
    /// (rotated) the produced snapshot. Failures are NAMED and non-
    /// poisoning: the root self-check does not depend on member derivation,
    /// and a missing member list fails its consumers closed at THEIR use
    /// site (W1's fold refuses the punish, exactly as designed).
    void derive_cycles_at(uint32_t H, QuorumObserveResult& r)
    {
        // Member derivation iterates the runtime-ENABLED set (types that can
        // actually mine commitments needing member resolution) — NOT the
        // chainparams list the root fold walks: mainnet's frozen LLMQ_50_60
        // mines nothing, so deriving its members every 24 blocks would be
        // dead weight with no consumer.
        for (const auto& p : enabled_llmqs(m_cfg.network)) {
            if (H % p.dkg_interval != 0 || H < kWorkDiffDepth) continue;

            std::string why;
            auto modifier = compute_modifier(p.type, H, &why);
            if (!modifier) {
                ++r.member_cycles_skipped;
                r.member_skip_reasons.push_back(
                    "type " + std::to_string(int(p.type)) + " cycle h="
                    + std::to_string(H) + ": modifier underivable — " + why);
                continue;
            }
            m_modifiers[{p.type, H}] = *modifier;

            if (!m_mn_list_at) {
                ++r.member_cycles_skipped;
                r.member_skip_reasons.push_back(
                    "type " + std::to_string(int(p.type)) + " cycle h="
                    + std::to_string(H) + ": no MN-list source installed");
                continue;
            }
            auto work_list = m_mn_list_at(H - kWorkDiffDepth);
            if (!work_list) {
                ++r.member_cycles_skipped;
                r.member_skip_reasons.push_back(
                    "type " + std::to_string(int(p.type)) + " cycle h="
                    + std::to_string(H) + ": MN list at work h="
                    + std::to_string(H - kWorkDiffDepth) + " unavailable");
                continue;
            }

            if (!p.use_rotation) {
                // Platform-type member selection is Evo-only post-V19; the
                // V20 floor guarantees post-V19 here (mainnet type 4,
                // testnet type 6 — vendor/quorum_members.hpp note).
                const bool evo_only =
                    (m_cfg.network == LlmqNetwork::Mainnet
                         ? p.type == vendor::kLlmqTypePlatformMainnet
                         : p.type == vendor::kLlmqTypePlatformTestnet);
                std::string err;
                auto members = compute_nonrotated_members(
                    p, evo_only, *work_list, *modifier, &err);
                if (!members) {
                    ++r.member_cycles_skipped;
                    r.member_skip_reasons.push_back(
                        "type " + std::to_string(int(p.type)) + " cycle h="
                        + std::to_string(H) + ": " + err);
                    continue;
                }
                m_members[{p.type, H}] = std::move(*members);
                ++r.member_cycles_derived;
                continue;
            }

            // Rotated: assemble the four cycle inputs. Previous-cycle
            // snapshots come from the OWN store (seeded at the anchor,
            // self-produced thereafter — the qrinfo-replacing recurrence).
            const uint32_t C = p.dkg_interval;
            if (H < 3 * C + kWorkDiffDepth) {
                ++r.member_cycles_skipped;
                r.member_skip_reasons.push_back(
                    "type " + std::to_string(int(p.type)) + " cycle h="
                    + std::to_string(H) + ": fewer than 3 previous cycles");
                continue;
            }
            std::array<std::vector<QuorumMnEntry>, 4> lists;
            std::array<RotationCycleInput, 4> cycles;
            std::array<const vendor::CQuorumSnapshot*, 3> snaps{};
            bool inputs_ok = true;
            std::string skip_why;
            lists[0] = std::move(*work_list);
            cycles[0].mn_list  = &lists[0];
            cycles[0].modifier = *modifier;
            for (size_t i = 1; i <= 3 && inputs_ok; ++i) {
                const uint32_t base = H - static_cast<uint32_t>(i) * C;
                auto sit = m_snapshots.find({p.type, base});
                if (sit == m_snapshots.end()) {
                    inputs_ok = false;
                    skip_why  = "snapshot for cycle base h="
                              + std::to_string(base)
                              + " neither produced nor seeded";
                    break;
                }
                snaps[i - 1] = &sit->second;
                auto mit = m_modifiers.find({p.type, base});
                if (mit == m_modifiers.end()) {
                    inputs_ok = false;
                    skip_why  = "modifier for cycle base h="
                              + std::to_string(base)
                              + " neither computed nor seeded";
                    break;
                }
                cycles[i].modifier = mit->second;
                auto prev_list = m_mn_list_at(base - kWorkDiffDepth);
                if (!prev_list) {
                    inputs_ok = false;
                    skip_why  = "MN list at work h="
                              + std::to_string(base - kWorkDiffDepth)
                              + " unavailable";
                    break;
                }
                lists[i] = std::move(*prev_list);
                cycles[i].mn_list = &lists[i];
            }
            if (!inputs_ok) {
                ++r.member_cycles_skipped;
                r.member_skip_reasons.push_back(
                    "type " + std::to_string(int(p.type)) + " cycle h="
                    + std::to_string(H) + ": " + skip_why);
                continue;
            }

            std::string err;
            auto out = compute_rotation_cycle(p, cycles, snaps, &err);
            if (!out) {
                ++r.member_cycles_skipped;
                r.member_skip_reasons.push_back(
                    "type " + std::to_string(int(p.type)) + " cycle h="
                    + std::to_string(H) + ": " + err);
                continue;
            }
            m_snapshots[{p.type, H}] = std::move(out->snapshot_at_h);
            for (size_t i = 0; i < out->member_protx.size(); ++i) {
                m_members[{p.type, H + static_cast<uint32_t>(i)}] =
                    std::move(out->member_protx[i]);
            }
            ++r.member_cycles_derived;
            if (m_cfg.debug_logs) {
                LOG_INFO << "[QUORUM-REPLAY] rotated cycle derived: type="
                         << int(p.type) << " base h=" << H << " ("
                         << p.signing_active_quorum_count << " member sets + "
                            "snapshot produced)";
            }
        }
    }

    /// CalcCbTxMerkleRootQuorums (evo/cbtx.cpp:119-210): active leaves as
    /// of H−1, block's own non-null commitments folded in (rotated: replace
    /// same quorumIndex; non-rotated: pop the OLDEST once at capacity —
    /// upstream pops the back of the most-recent-first vector), leaves
    /// sorted (uint256 memcmp) and merkled. `excess-quorums` and duplicate
    /// (mutation-equivalent) leaves fail closed.
    std::optional<uint256> fold_root_with_block(const QuorumBlockInput& in,
                                                QuorumObserveResult& r,
                                                std::string& err)
    {
        // Active leaves per type. Non-rotated vectors are kept OLDEST-first
        // in the store; the fold pops the FRONT (== upstream's pop_back of
        // its most-recent-first vector).
        std::map<uint8_t, std::vector<uint256>>        vec_hashes;
        std::map<uint8_t, std::map<int16_t, uint256>>  indexed_hashes;
        for (const auto& [type, vec] : m_nonrot) {
            auto& v = vec_hashes[type];
            v.reserve(vec.size());
            for (const auto& sc : vec) v.push_back(sc.hash);
        }
        for (const auto& [type, slots] : m_rot) {
            auto& m = indexed_hashes[type];
            for (const auto& [idx, sc] : slots) m[idx] = sc.hash;
        }

        for (const auto& qc : in.commitments) {
            ++r.commitments_seen;
            const auto& c = qc.commitment;
            if (dash::coin::qc_commitment_is_null(c)) {
                ++r.commitments_null;
                continue;   // "having null commitments is ok but we don't
                            //  use them here"
            }
            const LlmqParamsView* p =
                replay_llmq_params(m_cfg.network, c.llmqType);
            if (p == nullptr) {
                err = "block carries a commitment for llmqType "
                    + std::to_string(int(c.llmqType))
                    + " not in the chainparams llmq list";
                return std::nullopt;
            }
            const uint256 leaf = hash_commitment(c);
            if (p->use_rotation) {
                indexed_hashes[c.llmqType][c.quorumIndex] = leaf;
            } else {
                auto& v = vec_hashes[c.llmqType];
                if (v.size() == p->signing_active_quorum_count) {
                    // Evict the OLDEST (front of the oldest-first vector).
                    v.erase(v.begin());
                }
                v.push_back(leaf);
            }
        }

        for (const auto& [type, m] : indexed_hashes) {
            auto& v = vec_hashes[type];
            for (const auto& [idx, h] : m) v.push_back(h);
        }

        std::vector<uint256> leaves;
        for (const auto& [type, v] : vec_hashes) {
            const LlmqParamsView* p = replay_llmq_params(m_cfg.network, type);
            if (p == nullptr) {
                err = "active store carries llmqType " + std::to_string(int(type))
                    + " not in the chainparams llmq list";
                return std::nullopt;
            }
            if (v.size() > p->signing_active_quorum_count) {
                err = "excess-quorums for llmqType " + std::to_string(int(type))
                    + " (" + std::to_string(v.size()) + " > "
                    + std::to_string(p->signing_active_quorum_count) + ")";
                return std::nullopt;
            }
            leaves.insert(leaves.end(), v.begin(), v.end());
        }
        std::sort(leaves.begin(), leaves.end(),
                  [](const uint256& a, const uint256& b) {
                      return std::memcmp(a.data(), b.data(), 32) < 0;
                  });
        // Upstream rejects a MUTATED merkle (consensus/merkle duplicate
        // detection). Over sorted leaves a mutation is exactly an adjacent
        // duplicate — detect it directly and fail closed.
        for (size_t i = 0; i + 1 < leaves.size(); ++i) {
            if (leaves[i] == leaves[i + 1]) {
                err = "duplicate active-commitment leaf "
                    + leaves[i].GetHex().substr(0, 16)
                    + " (mutated-calc-cbtx-quorummerkleroot)";
                return std::nullopt;
            }
        }
        return compute_merkle_root_local(std::move(leaves));
    }

    bool ingest_block_commitments(const QuorumBlockInput& in,
                                  QuorumObserveResult& r, std::string& err)
    {
        for (const auto& qc : in.commitments) {
            const auto& c = qc.commitment;
            if (dash::coin::qc_commitment_is_null(c)) continue;
            const LlmqParamsView* p =
                replay_llmq_params(m_cfg.network, c.llmqType);
            if (p == nullptr) {
                err = "commitment for unknown llmqType "
                    + std::to_string(int(c.llmqType));
                return false;
            }
            auto base = resolve_base_height(c.llmqType, c.quorumHash);
            if (!base) {
                err = "commitment quorumHash "
                    + c.quorumHash.GetHex().substr(0, 16)
                    + " (type " + std::to_string(int(c.llmqType))
                    + ") resolves to no known block height — the accepted "
                      "chain cannot reference an unknown base";
                return false;
            }
            StoredCommitment sc;
            sc.base_height  = *base;
            sc.mined_height = in.height;
            sc.index        = c.quorumIndex;
            sc.quorum_hash  = c.quorumHash;
            sc.hash         = hash_commitment(c);
            if (p->use_rotation) {
                m_rot[c.llmqType][c.quorumIndex] = sc;
            } else {
                auto& v = m_nonrot[c.llmqType];
                v.push_back(sc);   // oldest-first; new is newest
                while (v.size() > p->signing_active_quorum_count)
                    v.erase(v.begin());
            }
            m_quorum_base_by_hash[key_of(c.llmqType, c.quorumHash)] = *base;
            ++r.commitments_ingested;
        }
        return true;
    }

    void prune(uint32_t H)
    {
        if (H <= m_cfg.keep_depth) return;
        const uint32_t floor = H - m_cfg.keep_depth;
        auto prune_th = [floor](auto& m) {
            for (auto it = m.begin(); it != m.end();) {
                if (it->first.second < floor) it = m.erase(it);
                else ++it;
            }
        };
        prune_th(m_snapshots);
        prune_th(m_modifiers);
        prune_th(m_members);
        for (auto it = m_hash_by_height.begin();
             it != m_hash_by_height.end() && it->first < floor;) {
            m_height_by_hash.erase(it->second);
            it = m_hash_by_height.erase(it);
        }
        for (auto it = m_cl_by_height.begin();
             it != m_cl_by_height.end() && it->first < floor;)
            it = m_cl_by_height.erase(it);
        for (auto it = m_cl_known.begin();
             it != m_cl_known.end() && *it < floor;)
            it = m_cl_known.erase(it);
        // m_quorum_base_by_hash: keep only bases still referenced by an
        // ACTIVE commitment (e.g. mainnet's frozen 50_60 bases, which stay
        // active forever) or recent enough for the height window. Without
        // this, one entry per ever-mined commitment would accumulate across
        // a genesis replay.
        std::set<std::string> live;
        for (const auto& [type, vec] : m_nonrot)
            for (const auto& sc : vec) live.insert(key_of(type, sc.quorum_hash));
        for (const auto& [type, slots] : m_rot)
            for (const auto& [idx, sc] : slots)
                live.insert(key_of(type, sc.quorum_hash));
        for (auto it = m_quorum_base_by_hash.begin();
             it != m_quorum_base_by_hash.end();) {
            if (it->second < floor && !live.count(it->first))
                it = m_quorum_base_by_hash.erase(it);
            else ++it;
        }
    }
};

} // namespace replay
} // namespace coin
} // namespace dash
