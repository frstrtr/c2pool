// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Serve-time PoSe pass over a template's OWN quorum commitments — the
/// HandleQuorumCommitment / PoSePunish leg of dashd's list rebuild, folded
/// into the merkleRootMNList the embedded template commits.
///
/// ─────────────────────────────────────────────────────────────────────────
/// WHY THIS EXISTS (incident h=2561514, 2026-10-26)
/// ─────────────────────────────────────────────────────────────────────────
/// The pre-emit gate used to refuse ANY real commitment carrying a clear
/// validMembers bit for a listed member ("every listed member valid" — a
/// sufficient but far-from-necessary no-op proof). On mainnet ~21% of non-null
/// commitments carry at least one invalid member, and almost none of those
/// punishments ban anyone, so the gate refused correct templates at most DKG
/// windows (2561514: 360 s dark with the committed root byte-identical to the
/// one the network accepted). This header replaces the predicate with dashd's
/// own pass, applied on the bounds a penalty oracle can PROVE.
///
/// ─────────────────────────────────────────────────────────────────────────
/// WHAT DASHD DOES (v23.1.7 — the order is consensus)
/// ─────────────────────────────────────────────────────────────────────────
///   CSpecialTxProcessor::RebuildListFromBlock (evo/specialtxman.cpp:185-470):
///     1. confirmedHash pass (:206-215)                  -> sml_projection.hpp
///     2. newList.DecreaseScores() (:229, deterministicmns.cpp:334-359):
///        every NON-banned MN with nPoSePenalty > 0 loses 1
///     3. vtx[1..] in block order (:232-453). A type-6 tx whose commitment is
///        !IsNull() (:432) resolves members = GetAllQuorumMembers(type,
///        quorumBase) (:447-449) and runs HandleQuorumCommitment (:159-174):
///            for i < members.size():
///              if (!mnList.HasMN(members[i]->proTxHash)) continue;
///              if (!qc.validMembers[i])
///                  mnList.PoSePunish(proTxHash, mnList.CalcPenalty(66));
///        Provider txs (types 1-4) are applied in the SAME loop, in tx order
///        (sml_special_fold.hpp).
///     4. collateral-spend removal (:455-470) — never in an embedded body
///        (sml_projection.hpp tx_spends_mn_collateral).
///   PoSePunish (deterministicmns.cpp:306-332):
///        p = min(max, p + penalty); if (!IsBanned() && p >= max) BanIfNotBanned
///   with max = CalcMaxPoSePenalty() = max(100, total MN count) (:292-298).
///   to_sml_entry (deterministicmns.cpp:45-52) hashes isValid = !IsBanned();
///   nPoSePenalty is NOT a leaf field (simplifiedmns.h:35). So ONLY A BAN
///   reaches merkleRootMNList; a punishment that stays below max is a byte
///   no-op for the committed root.
///
/// The embedded body places every type-6 tx directly after the coinbase,
/// before any provider tx (embedded_gbt.hpp; dashd node/miner.cpp:226-236), so
/// the pass runs AFTER the confirmation projection and BEFORE the types 1-4
/// fold: a ProUpServTx later in the same body must see (and revive) a ban
/// this pass applies. The MN count the punishments see is therefore the
/// previous list's count — no registration in the body precedes them.
///
/// ─────────────────────────────────────────────────────────────────────────
/// THE CRUX: nPoSePenalty(H-1) IS ON NO WIRE c2pool SPEAKS
/// ─────────────────────────────────────────────────────────────────────────
/// SML / mnlistdiff / qrinfo carry isValid only. The penalty therefore comes
/// from a PoSeOracle that answers with CERTAINTY BOUNDS {lo, hi} on the
/// post-(H-1) penalty. Decay and punishment are applied to BOTH bounds, and
/// the ban decision is taken only when it is provable either way:
///     lo_final >= max          => banned   (the leaf flips isValid=false)
///     hi_final <  max          => not banned (root untouched)
///     otherwise                => refuse (stage penalty-inexact)
/// The decision is taken once per MN after the whole pass: within one block a
/// penalty only grows, so "banned at some punish" == "banned at the last".
///
/// FREE EXACT SUB-PROOFS (no oracle needed — §3(c) of the design):
///   * the invalid-marked member is absent from the list: dashd skips it
///     (HasMN false, specialtxman.cpp:162-164);
///   * the member is already banned (isValid=false in the tip SML): the ban
///     branch is guarded by !IsBanned() (deterministicmns.cpp:319), so the
///     leaf cannot change.
///
/// ─────────────────────────────────────────────────────────────────────────
/// FAIL-CLOSED CONTRACT
/// ─────────────────────────────────────────────────────────────────────────
/// Any input that cannot be established EXACTLY refuses with a named stage —
/// the caller must not serve the template:
///   members-missing   the member set is not sourced, empty, or names a
///                     punished member by a null proTxHash
///   members-overrun   members.size() > validMembers.size() (cannot index)
///   oracle-not-at-tip the oracle's state is not the post-state of the tip
///                     this template builds on (or contradicts its isValid)
///   penalty-unknown   no oracle, or no/malformed penalty for this MN
///   penalty-inexact   the bounds straddle the ban threshold
/// With NO oracle wired the pass is exactly the old predicate's refusal set
/// minus the two sub-proofs above. Null commitments (IsNull) are untouched.
/// Nothing here mutates an input; the decision is pure.

#include <impl/dash/coin/dkg_commitments.hpp>     // qc_commitment_is_null
#include <impl/dash/coin/pose_penalty.hpp>        // dashd PoSe arithmetic (shared)
#include <impl/dash/coin/vendor/llmq_commitment.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>

#include <core/uint256.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

/// The index-aligned member proTxHashes of a quorum, exactly the vector
/// dashd's HandleQuorumCommitment indexes validMembers with
/// (GetAllQuorumMembers). Daemonlessly: the QuorumMemberSource set the BLS
/// verifier used. nullopt => not sourced.
using QcMembersFn = std::function<std::optional<std::vector<uint256>>(
    uint8_t llmq_type, const uint256& quorum_hash)>;

/// Certainty bounds on one MN's nPoSePenalty in the POST-state of the tip
/// block (after block H-1 connected). lo == hi => exact. `banned` is the
/// oracle's own IsBanned() for that state.
struct PoSePenaltyView {
    int32_t lo{0};
    int32_t hi{0};
    bool    banned{false};
};

/// THE ORACLE INTERFACE: per-MN penalty bounds at the tip; nullopt =>
/// unknown for this MN (an oracle that is not at the tip answers nullopt for
/// every MN — or names its state through PoSeOracleCursorFn below).
using PoSeOracleFn =
    std::function<std::optional<PoSePenaltyView>(const uint256& proTx)>;

/// OPTIONAL companion: the block whose post-state the oracle's penalties
/// describe, (height, hash). When supplied, the pass consults the oracle only
/// if it is exactly the tip the template builds on, and names the mismatch
/// (stage oracle-not-at-tip) instead of a bare penalty-unknown.
using PoSeOracleCursorFn =
    std::function<std::optional<std::pair<uint32_t, uint256>>()>;

/// The oracle as the pass consumes it. Default-constructed = no oracle: every
/// punishment of a listed, valid MN then refuses with penalty-unknown —
/// today's fail-closed behaviour.
struct PoSeOracle {
    PoSeOracleFn       penalty;
    PoSeOracleCursorFn cursor;   // optional (see above)

    bool wired() const { return static_cast<bool>(penalty); }
};

enum class QcPoseStage {
    Ok,
    MembersMissing,
    MembersOverrun,
    OracleNotAtTip,
    PenaltyUnknown,
    PenaltyInexact,
};

inline const char* qc_pose_stage_name(QcPoseStage s)
{
    switch (s) {
    case QcPoseStage::Ok:             return "ok";
    case QcPoseStage::MembersMissing: return "members-missing";
    case QcPoseStage::MembersOverrun: return "members-overrun";
    case QcPoseStage::OracleNotAtTip: return "oracle-not-at-tip";
    case QcPoseStage::PenaltyUnknown: return "penalty-unknown";
    case QcPoseStage::PenaltyInexact: return "penalty-inexact";
    }
    return "unknown";
}

/// The outcome of the pass over one plan.
struct QcPoseDecision {
    QcPoseStage stage{QcPoseStage::Ok};

    // The refusing commitment (plan index + identity) and, for the penalty /
    // oracle stages, the MN concerned. Meaningful only when !ok().
    size_t   qc_index{0};
    uint8_t  llmq_type{0};
    int16_t  quorum_index{0};
    uint256  quorum_hash;
    uint256  pro_tx_hash;

    unsigned punished{0};        ///< PoSePunish calls dashd makes (member present)
    unsigned absent{0};          ///< invalid-marked members dashd skips (HasMN false)
    unsigned already_banned{0};  ///< punishes of an already-banned MN (no leaf change)
    std::vector<uint256> bans;   ///< MNs whose isValid flips to false (first-punish order)

    bool ok() const { return stage == QcPoseStage::Ok; }
};

namespace detail {

inline const vendor::CSimplifiedMNListEntry*
pose_find_entry(const vendor::CSimplifiedMNList& sml, const uint256& pro)
{
    for (const auto& e : sml.mnList)
        if (e.proRegTxHash == pro) return &e;
    return nullptr;
}

} // namespace detail

/// dashd's DecreaseScores + HandleQuorumCommitment + PoSePunish over the
/// non-null commitments of `plan`, in plan (= block) order, decided on
/// oracle bounds. `base` is the tip SML or its confirmation projection: the
/// pass reads only entry presence, isValid and the entry count, none of which
/// the confirmedHash pass changes. (prev_height, prev_hash) is the tip the
/// template builds on — the only state an oracle may describe.
inline QcPoseDecision decide_qc_pose(
    const vendor::CSimplifiedMNList& base,
    const std::vector<vendor::CFinalCommitment>& plan,
    const QcMembersFn& members,
    const PoSeOracle* oracle,
    uint32_t prev_height,
    const uint256& prev_hash)
{
    QcPoseDecision d;
    auto refuse = [&d](QcPoseStage s, size_t i,
                       const vendor::CFinalCommitment& c,
                       const uint256& pro) -> QcPoseDecision {
        d.stage        = s;
        d.qc_index     = i;
        d.llmq_type    = c.llmqType;
        d.quorum_index = c.quorumIndex;
        d.quorum_hash  = c.quorumHash;
        d.pro_tx_hash  = pro;
        d.bans.clear();          // a refused pass proves no ban
        return d;
    };

    // CalcMaxPoSePenalty / CalcPenalty(66) over the list the punishments see:
    // the previous list (every type-6 tx precedes every provider tx).
    const int32_t max_penalty = pose::calc_max_pose_penalty(base.mnList.size());
    const int32_t penalty =
        pose::calc_penalty(max_penalty, pose::kQcPunishPercent);

    // Per-MN bounds, accumulated across commitments (two quorums punishing
    // the same MN in one block, e.g. types 1 and 4 sharing a mining window).
    struct Bounds { uint256 pro; int64_t lo; int64_t hi; size_t last_qc; };
    std::vector<Bounds> acc;
    std::optional<bool> oracle_at_tip;   // cursor (if any) read once per pass

    for (size_t i = 0; i < plan.size(); ++i) {
        const auto& c = plan[i];
        if (qc_commitment_is_null(c)) continue;          // IsNull() (:432)

        const std::optional<std::vector<uint256>> ms =
            members ? members(c.llmqType, c.quorumHash) : std::nullopt;
        if (!ms || ms->empty())
            return refuse(QcPoseStage::MembersMissing, i, c, uint256());
        if (ms->size() > c.validMembers.size())
            return refuse(QcPoseStage::MembersOverrun, i, c, uint256());
        for (size_t k = 0; k < ms->size(); ++k) {
            if (c.validMembers[k]) continue;
            const uint256& pro = (*ms)[k];
            // A null proTxHash would read as "absent" below and silently skip
            // a punishment dashd applies — an unidentified PUNISHED member is
            // unsourced. (Identities of valid members are never needed.)
            if (pro.IsNull())
                return refuse(QcPoseStage::MembersMissing, i, c, uint256());
            const auto* e = detail::pose_find_entry(base, pro);
            if (e == nullptr) { ++d.absent; continue; }  // !HasMN (:162-164)
            ++d.punished;
            if (!e->isValid) { ++d.already_banned; continue; }  // :319 guard

            Bounds* b = nullptr;
            for (auto& x : acc)
                if (x.pro == pro) { b = &x; break; }
            if (b == nullptr) {
                if (oracle == nullptr || !oracle->wired())
                    return refuse(QcPoseStage::PenaltyUnknown, i, c, pro);
                if (oracle->cursor && !oracle_at_tip) {
                    const auto cur = oracle->cursor();
                    oracle_at_tip = cur.has_value()
                        && cur->first == prev_height && cur->second == prev_hash;
                }
                if (oracle_at_tip.has_value() && !*oracle_at_tip)
                    return refuse(QcPoseStage::OracleNotAtTip, i, c, pro);
                const auto v = oracle->penalty(pro);
                if (!v || v->lo < 0 || v->hi < v->lo)
                    return refuse(QcPoseStage::PenaltyUnknown, i, c, pro);
                // The tip SML says this MN is valid; an oracle that holds it
                // banned is not describing this tip.
                if (v->banned)
                    return refuse(QcPoseStage::OracleNotAtTip, i, c, pro);
                // DecreaseScores runs once per block BEFORE the tx pass
                // (specialtxman.cpp:229), on every non-banned MN.
                acc.push_back(Bounds{pro, pose::decayed(v->lo),
                                     pose::decayed(v->hi), i});
                b = &acc.back();
            }
            b->lo      = pose::punished(b->lo, penalty, max_penalty);
            b->hi      = pose::punished(b->hi, penalty, max_penalty);
            b->last_qc = i;
        }
    }

    for (const auto& b : acc) {
        if (pose::punish_bans(/*was_banned=*/false, b.lo, max_penalty)) {
            d.bans.push_back(b.pro);          // provably banned
            continue;
        }
        if (!pose::punish_bans(/*was_banned=*/false, b.hi, max_penalty))
            continue;                         // provably not banned
        return refuse(QcPoseStage::PenaltyInexact, b.last_qc,
                      plan[b.last_qc], b.pro);
    }
    return d;
}

/// Apply a decision's bans to a list copy: isValid=false on each banned
/// entry (BanIfNotBanned -> to_sml_entry). isValid is not a sort key, so the
/// memcmp(proRegTxHash) order — and therefore the leaf order — is unchanged.
inline void apply_qc_pose_bans(vendor::CSimplifiedMNList& sml,
                               const std::vector<uint256>& bans)
{
    for (const auto& pro : bans)
        for (auto& e : sml.mnList)
            if (e.proRegTxHash == pro) { e.isValid = false; break; }
}

/// The pass as a fold: a COPY of `base` with the decision applied. On a
/// refusal the copy is `base` unchanged and must not be committed.
struct SmlPoseFold {
    vendor::CSimplifiedMNList sml;
    QcPoseDecision decision;
    bool ok() const { return decision.ok(); }
};

inline SmlPoseFold fold_qc_pose(
    const vendor::CSimplifiedMNList& base,
    const std::vector<vendor::CFinalCommitment>& plan,
    const QcMembersFn& members,
    const PoSeOracle* oracle,
    uint32_t prev_height,
    const uint256& prev_hash)
{
    SmlPoseFold out;
    out.decision = decide_qc_pose(base, plan, members, oracle,
                                  prev_height, prev_hash);
    out.sml = base;
    if (out.decision.ok()) apply_qc_pose_bans(out.sml, out.decision.bans);
    return out;
}

} // namespace coin
} // namespace dash
