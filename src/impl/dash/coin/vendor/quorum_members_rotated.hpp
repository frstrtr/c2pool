// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// E1 Phase-L, item 3 — DIP-0024 ROTATED (quarter-rotation) quorum member-set
/// computation: the piece quorum_member_source.hpp's rotated branch was
/// fail-closed for.
///
/// This is a PORT, not a design. Source of truth is dashcore v23.1.7
/// src/llmq/utils.cpp (anonymous namespace):
///
///   * ComputeQuorumMembersByQuarterRotation  — assembles nQuorums (=
///     signingActiveQuorumCount, 32 for llmq_60_75) member vectors, each
///     `llmqParams.size` (60) long, from FOUR quarters:
///         [H-3C quarter][H-2C quarter][H-C quarter][NEW quarter]
///     in exactly that order. The upstream loop iterates the previous cycles
///     REVERSED (`prev_cycles | std::views::reverse`), which is why the OLDEST
///     quarter comes first. MEMBER INDEX IS CONSENSUS: it selects the
///     signers/validMembers bitset slot, so this order is not cosmetic.
///   * GetQuorumQuarterMembersBySnapshot — recovers the three PREVIOUS quarters
///     from the CQuorumSnapshot each cycle committed (active-member bitset +
///     skip-list), replayed against that cycle's own score-sorted MN list.
///   * BuildNewQuorumQuarterMembers — derives the NEW quarter at the cycle base
///     from the H list minus everything the previous quarters already used.
///
/// DAEMONLESS INPUTS — ALL FOUR AVAILABLE FROM ONE qrinfo
/// -----------------------------------------------------
/// Upstream reads `dmnman.GetListForBlock(cycleBase - WORK_DIFF_DEPTH)` for
/// each of the four cycles and `qsnapman.GetSnapshotForBlock(cycleBase)` for
/// the three previous ones. A single qrinfo carries exactly that set:
/// mnListDiff{H,AtHMinusC,AtHMinus2C,AtHMinus3C} are the lists at
/// cycleBase_i - 8 (llmq/snapshot.cpp ConstructCycle: m_work_index =
/// m_cycle_index - WORK_DIFF_DEPTH), and quorumSnapshotAtHMinus{C,2C,3C} are
/// the three snapshots. quorum_member_source.hpp already DIP-4 authenticates
/// every one of those diffs against its expected height before they get here,
/// so nothing in this header trusts a peer for anything other than the
/// snapshot bitsets — and a wrong bitset cannot forge a member set, it can
/// only produce one whose commitment then fails the BLS aggregate.
///
/// The per-cycle MODIFIER is likewise sourced from the qrinfo: upstream's
/// GetHashModifier(llmqParams, cycleBase) is post-V20
/// SerializeHash((type, workHeight, bestCLSignature)) with the CL taken from
/// the WORK block's own cbTx — and each cycle diff carries that exact cbTx.
/// The caller computes it with vendor::compute_quorum_modifier (shared with
/// the non-rotated path) and passes it in, so this header stays pure.
///
/// FAIL-CLOSED, and STRICTER THAN UPSTREAM IN EXACTLY ONE PLACE
/// ------------------------------------------------------------
/// Upstream breaks a score TIE by collateralOutpoint. The SML does not carry
/// the collateral outpoint, so a tie ANYWHERE in a sorted list could reorder
/// members we cannot resolve — and here, unlike the non-rotated path, the full
/// sorted list matters (the snapshot bitset indexes it), not just its head.
/// So ANY adjacent equal score in ANY sorted list -> std::nullopt. That needs
/// a SHA256 collision to trigger; it is a correctness fence, not a live risk.
///
/// Also nullopt: a snapshot bitset shorter than the list it indexes, a cycle
/// input missing, an assembled quorum that is not exactly `size` members, a
/// selected member with an all-zero operator key, or either fill loop failing
/// to terminate within its bound (upstream's loops can spin on pathological
/// input; we refuse instead of hanging the template thread).
///
/// OPERATOR KEY PROVENANCE — a real subtlety, ported faithfully
/// ------------------------------------------------------------
/// A member selected into the H-3C quarter is, upstream, the CDeterministicMN
/// object AS OF the H-3C cycle's work block, and CFinalCommitment::Verify uses
/// `members[i]->pdmnState->pubKeyOperator` — i.e. THAT cycle's key, not the
/// key the same masternode holds at H. So each quarter's members carry their
/// OWN cycle SML entry's pubKeyOperator and nVersion (BLS scheme flag). If a
/// masternode rotated its operator key mid-cycle, dashd verifies with the old
/// one; we reproduce that rather than "fixing" it.
///
/// DEVIATION NOTE (dedup): upstream's CDeterministicMNList::AddMN also enforces
/// uniqueness of service / owner key / operator key and throws (silently
/// caught) on a conflict. The SML cannot express collateral outpoints or owner
/// keys, so dedup here is by proRegTxHash only. A duplicate service or operator
/// key across two distinct proRegTxHashes is rejected by ProTx consensus, so
/// the two agree on any list a node will accept.

#include <impl/dash/coin/vendor/quorum_members.hpp>         // MemberOperatorKey, detail::mn_score/score_lt
#include <impl/dash/coin/vendor/quorum_rotation_info.hpp>   // CQuorumSnapshot
#include <impl/dash/coin/vendor/simplifiedmns.hpp>          // CSimplifiedMNList[Entry]

#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <set>
#include <vector>

namespace dash {
namespace coin {
namespace vendor {

/// One cycle's inputs: the SML AS OF (cycleBase - WORK_DIFF_DEPTH) and the
/// modifier GetHashModifier() yields for that cycle base.
struct RotatedCycleInput {
    const CSimplifiedMNList* sml{nullptr};
    uint256                  modifier;
};

/// The subset of LLMQParams the rotation needs.
struct RotatedQuorumParams {
    uint8_t  type{0};
    uint16_t size{0};                          // llmqParams.size (60)
    uint16_t signing_active_quorum_count{0};   // nQuorums (32)
};

namespace detail {

using MnRef = const CSimplifiedMNListEntry*;

/// Upstream memcmp ordering on proRegTxHash (the SML's own sort order) — used
/// only for the dedup sets, never for member order.
struct ProRegLess {
    bool operator()(const uint256& a, const uint256& b) const
    {
        return std::memcmp(a.data(), b.data(), 32) < 0;
    }
};
using ProRegSet = std::set<uint256, ProRegLess>;

/// CalculateScoresForQuorum's eligibility filter: PoSe-banned out
/// (ForEachMN(onlyValid=true) / IsBanned()), unconfirmed out (the
/// ProRegTxHash-grinding guard), and — for a platform type — non-Evo out.
/// The rotation path never sets evo_only (llmq_60_75 is not llmqTypePlatform);
/// the parameter exists so the filter reads identically to upstream.
inline bool rot_mn_eligible(const CSimplifiedMNListEntry& e, bool evo_only)
{
    if (!e.isValid) return false;
    if (e.confirmedHash.IsNull()) return false;
    if (evo_only && e.nType != CSimplifiedMNListEntry::TYPE_EVO) return false;
    return true;
}

/// dashcore CalculateQuorum<List> with maxSize == 0: score every eligible
/// candidate under `modifier` and sort DESCENDING. std::nullopt on a tie (see
/// the header note — upstream's collateralOutpoint tiebreak is not sourceable
/// from an SML).
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
        if (!rot_mn_eligible(*e, evo_only)) continue;
        scored.push_back(Scored{mn_score(*e, modifier), e});
    }
    std::sort(scored.begin(), scored.end(),
              [](const Scored& a, const Scored& b) {
                  return score_lt(b.score, a.score);   // descending
              });
    for (size_t i = 0; i + 1 < scored.size(); ++i) {
        if (scored[i].score == scored[i + 1].score) return std::nullopt;
    }
    std::vector<MnRef> out;
    out.reserve(scored.size());
    for (const auto& s : scored) out.push_back(s.mn);
    return out;
}

inline std::vector<MnRef> all_refs(const CSimplifiedMNList& sml)
{
    std::vector<MnRef> v;
    v.reserve(sml.mnList.size());
    for (const auto& e : sml.mnList) v.push_back(&e);
    return v;
}

inline MnRef find_by_protx(const CSimplifiedMNList& sml, const uint256& protx)
{
    for (const auto& e : sml.mnList)
        if (std::memcmp(e.proRegTxHash.data(), protx.data(), 32) == 0) return &e;
    return nullptr;
}

/// dashcore GetQuorumQuarterMembersBySnapshot (llmq/utils.cpp).
/// `sml`/`modifier` are the cycle's own work-block list and hash modifier.
/// Returns num_quorums quarters (each <= quarter_size), or nullopt if the
/// snapshot cannot be replayed deterministically.
inline std::optional<std::vector<std::vector<MnRef>>>
get_quorum_quarter_members_by_snapshot(
    size_t num_quorums, size_t quarter_size,
    const CSimplifiedMNList& sml, const uint256& modifier,
    const CQuorumSnapshot& snapshot)
{
    std::vector<MnRef> sorted_combined;
    {
        auto sorted_all = calculate_quorum_all(all_refs(sml), modifier);
        if (!sorted_all) return std::nullopt;

        // Upstream indexes snapshot.activeQuorumMembers[i] over the SCORE-
        // SORTED eligible list (BuildQuorumSnapshot sizes the bitset to the
        // list TOTAL, which is >= that). A short bitset would be an
        // out-of-bounds read upstream; here it fails closed.
        if (snapshot.activeQuorumMembers.size() < sorted_all->size())
            return std::nullopt;

        std::vector<MnRef> used;
        used.reserve(sorted_all->size());
        size_t i = 0;
        for (MnRef dmn : *sorted_all) {
            if (snapshot.activeQuorumMembers[i]) {
                used.push_back(dmn);
            } else {
                // Upstream re-checks !IsBanned here; calculate_quorum_all has
                // already dropped banned entries, so this is a no-op kept for
                // line-by-line traceability.
                if (dmn->isValid) sorted_combined.push_back(dmn);
            }
            ++i;
        }
        // ...and the already-used ones go to the END of the list.
        sorted_combined.insert(sorted_combined.end(), used.begin(), used.end());
    }

    std::vector<std::vector<MnRef>> quarters(num_quorums);
    if (sorted_combined.empty()) return quarters;   // upstream returns empty

    switch (snapshot.mnSkipListMode) {
    case CQuorumSnapshot::MODE_NO_SKIPPING: {
        size_t itm = 0;
        for (size_t i = 0; i < num_quorums; ++i) {
            while (quarters[i].size() < quarter_size) {
                quarters[i].push_back(sorted_combined[itm]);
                if (++itm == sorted_combined.size()) itm = 0;
            }
        }
        return quarters;
    }
    case CQuorumSnapshot::MODE_SKIPPING_ENTRIES: {
        // Skip list is stored RELATIVE TO THE FIRST SKIPPED INDEX (see
        // BuildNewQuorumQuarterMembers' skipList construction below): the
        // first entry is absolute, every later entry is first + s. Note the
        // upstream quirk that `first_entry_index == 0` is the "not yet set"
        // sentinel, so a genuine first skip at index 0 keeps taking the
        // first branch. Ported verbatim — it is consensus behaviour.
        size_t first_entry_index = 0;
        std::vector<int64_t> processed_skip_list;
        processed_skip_list.reserve(snapshot.mnSkipList.size());
        for (int32_t s : snapshot.mnSkipList) {
            if (first_entry_index == 0) {
                first_entry_index = static_cast<size_t>(s);
                processed_skip_list.push_back(s);
            } else {
                processed_skip_list.push_back(
                    static_cast<int64_t>(first_entry_index) + s);
            }
        }

        int64_t idx = 0;
        size_t  itsk = 0;
        // Termination bound: `itsk` only ever advances, so once it is spent
        // every iteration pushes. Upstream has no such bound; we refuse
        // rather than spin on the template thread.
        const uint64_t max_iters =
            static_cast<uint64_t>(processed_skip_list.size())
            + static_cast<uint64_t>(num_quorums) * quarter_size
            + sorted_combined.size() + 1;
        uint64_t iters = 0;
        for (size_t i = 0; i < num_quorums; ++i) {
            while (quarters[i].size() < quarter_size) {
                if (++iters > max_iters) return std::nullopt;
                if (idx < 0 || static_cast<size_t>(idx) >= sorted_combined.size())
                    return std::nullopt;
                if (itsk < processed_skip_list.size()
                    && idx == processed_skip_list[itsk]) {
                    ++itsk;
                } else {
                    quarters[i].push_back(sorted_combined[static_cast<size_t>(idx)]);
                }
                ++idx;
                if (static_cast<size_t>(idx) == sorted_combined.size()) idx = 0;
            }
        }
        return quarters;
    }
    case CQuorumSnapshot::MODE_NO_SKIPPING_ENTRIES:
    case CQuorumSnapshot::MODE_ALL_SKIPPED:
    default:
        // Upstream returns the EMPTY quarters for these two modes. The
        // assembled quorum will then be short of `size` and the caller fails
        // closed, which is the honest outcome: we cannot serve a member set
        // dashd would build from data the snapshot did not encode.
        return quarters;
    }
}

/// dashcore BuildNewQuorumQuarterMembers (llmq/utils.cpp) minus the snapshot
/// STORE (we are a consumer, never a producer, so BuildQuorumSnapshot and the
/// skipList it emits are deliberately not ported).
inline std::optional<std::vector<std::vector<MnRef>>>
build_new_quorum_quarter_members(
    size_t num_quorums, size_t quarter_size,
    const CSimplifiedMNList& all_mns, const uint256& modifier,
    const std::array<std::vector<std::vector<MnRef>>, 3>& previous_quarters)
{
    std::vector<std::vector<MnRef>> quarters(num_quorums);

    size_t enabled = 0;
    for (const auto& e : all_mns.mnList) if (e.isValid) ++enabled;
    if (enabled < quarter_size) return quarters;   // upstream: empty quarters

    // MnsUsedAtH (union over all quorum indices) + MnsUsedAtHIndexed[i].
    // Upstream stores the CDeterministicMN object FROM THE PREVIOUS QUARTER,
    // and AddMN keeps the FIRST insertion — so does this.
    ProRegSet          used_all;
    std::vector<MnRef> used_all_refs;
    std::vector<ProRegSet> used_indexed(num_quorums);

    // Post-V19 (and on testnet unconditionally) upstream drops previous-quarter
    // members that are no longer in the H list. This module only serves
    // post-V20, so skipRemovedMNs is ALWAYS true here.
    for (size_t idx = 0; idx < num_quorums; ++idx) {
        for (size_t c = 0; c < previous_quarters.size(); ++c) {   // H-C, H-2C, H-3C
            if (idx >= previous_quarters[c].size()) continue;
            for (MnRef mn : previous_quarters[c][idx]) {
                if (mn == nullptr) return std::nullopt;
                MnRef at_h = find_by_protx(all_mns, mn->proRegTxHash);
                if (at_h == nullptr) continue;          // !allMns.HasMN
                if (!at_h->isValid) continue;           // allMns.IsMNPoSeBanned
                if (used_all.insert(mn->proRegTxHash).second)
                    used_all_refs.push_back(mn);
                used_indexed[idx].insert(mn->proRegTxHash);
            }
        }
    }

    // MnsNotUsedAtH: everything in the H list that no quarter used and that is
    // not PoSe-banned (upstream iterates onlyValid=false then filters IsBanned).
    std::vector<MnRef> not_used;
    not_used.reserve(all_mns.mnList.size());
    for (const auto& e : all_mns.mnList) {
        if (used_all.count(e.proRegTxHash)) continue;
        if (!e.isValid) continue;
        not_used.push_back(&e);
    }

    auto sorted_used = calculate_quorum_all(used_all_refs, modifier);
    if (!sorted_used) return std::nullopt;
    auto sorted_combined = calculate_quorum_all(not_used, modifier);
    if (!sorted_combined) return std::nullopt;
    // NOT-USED first, then USED — upstream appends sortedMnsUsedAtHM.
    sorted_combined->insert(sorted_combined->end(),
                            sorted_used->begin(), sorted_used->end());
    if (sorted_combined->empty()) return quarters;

    size_t idx = 0;
    const uint64_t max_iters =
        static_cast<uint64_t>(num_quorums + 1) * sorted_combined->size()
        + static_cast<uint64_t>(num_quorums) * quarter_size + 1;
    uint64_t iters = 0;
    for (size_t i = 0; i < num_quorums; ++i) {
        const size_t used_count = used_indexed[i].size();
        bool   updated = false;
        size_t initial_loop_idx = idx;
        while (quarters[i].size() < quarter_size
               && (used_count + quarters[i].size() < sorted_combined->size())) {
            if (++iters > max_iters) return std::nullopt;
            bool skip = true;
            MnRef cand = (*sorted_combined)[idx];
            if (!used_indexed[i].count(cand->proRegTxHash)) {
                used_indexed[i].insert(cand->proRegTxHash);
                quarters[i].push_back(cand);
                updated = true;
                skip    = false;
            }
            (void)skip;   // upstream records a skipList here; producer-only.
            if (++idx == sorted_combined->size()) idx = 0;
            if (idx == initial_loop_idx) {
                // Full pass with nothing added => not enough MNs; upstream
                // abandons the WHOLE new quarter set.
                if (!updated) return std::vector<std::vector<MnRef>>(num_quorums);
                updated = false;
            }
        }
    }
    return quarters;
}

} // namespace detail

/// dashcore ComputeQuorumMembersByQuarterRotation. `cycles` is indexed
/// 0 = H (the cycle base), 1 = H-C, 2 = H-2C, 3 = H-3C; `snapshots` is
/// indexed 0 = H-C, 1 = H-2C, 2 = H-3C — i.e. the qrinfo field order.
///
/// Returns signing_active_quorum_count member vectors, EACH EXACTLY
/// params.size long and in dashd's consensus order, or std::nullopt.
inline std::optional<std::vector<std::vector<MemberOperatorKey>>>
compute_quorum_members_by_quarter_rotation(
    const RotatedQuorumParams& params,
    const std::array<RotatedCycleInput, 4>& cycles,
    const std::array<const CQuorumSnapshot*, 3>& snapshots)
{
    const size_t num_quorums = params.signing_active_quorum_count;
    const size_t quorum_size = params.size;
    if (num_quorums == 0 || quorum_size == 0) return std::nullopt;
    // Upstream computes quarterSize = size / 4 and assembles 4 of them; a size
    // that is not a multiple of 4 could never yield `size` members.
    if (quorum_size % 4 != 0) return std::nullopt;
    const size_t quarter_size = quorum_size / 4;

    for (const auto& c : cycles)
        if (c.sml == nullptr) return std::nullopt;
    for (const auto* s : snapshots)
        if (s == nullptr || !s->sane()) return std::nullopt;

    // The three PREVIOUS quarters, each replayed from its own cycle's snapshot.
    std::array<std::vector<std::vector<detail::MnRef>>, 3> previous;
    for (size_t i = 0; i < 3; ++i) {
        auto q = detail::get_quorum_quarter_members_by_snapshot(
            num_quorums, quarter_size, *cycles[i + 1].sml,
            cycles[i + 1].modifier, *snapshots[i]);
        if (!q) return std::nullopt;
        previous[i] = std::move(*q);
    }

    auto new_quarter = detail::build_new_quorum_quarter_members(
        num_quorums, quarter_size, *cycles[0].sml, cycles[0].modifier, previous);
    if (!new_quarter) return std::nullopt;

    // ORDER: oldest quarter first (upstream iterates the previous cycles
    // reversed), then the new one.
    std::vector<std::vector<MemberOperatorKey>> out(num_quorums);
    for (size_t i = 0; i < num_quorums; ++i) {
        std::vector<detail::MnRef> members;
        members.reserve(quorum_size);
        for (size_t c = previous.size(); c-- > 0;) {          // H-3C, H-2C, H-C
            members.insert(members.end(), previous[c][i].begin(),
                           previous[c][i].end());
        }
        members.insert(members.end(), (*new_quarter)[i].begin(),
                       (*new_quarter)[i].end());

        // A short (or over-long) quorum means the snapshots did not encode a
        // set we can reproduce — never serve a partial member set.
        if (members.size() != quorum_size) return std::nullopt;

        out[i].reserve(quorum_size);
        for (detail::MnRef mn : members) {
            if (detail::is_all_zero(mn->pubKeyOperator)) return std::nullopt;
            MemberOperatorKey k;
            k.pubKeyOperator = mn->pubKeyOperator;
            // The #812 finding: the SML entry's own nVersion is the only
            // unambiguous legacy/basic scheme signal, and each quarter's
            // members carry THEIR cycle's entry (see the header note).
            k.legacy_scheme = (mn->nVersion == CSimplifiedMNListEntry::VER_LEGACY_BLS);
            out[i].push_back(k);
        }
    }
    return out;
}

} // namespace vendor
} // namespace coin
} // namespace dash
