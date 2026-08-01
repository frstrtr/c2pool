// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Daemonless superblock sourcing — governance object + vote store
/// (E-SUPERBLOCK). In-process, keyed by object hash, with a funding-signal
/// vote tally, mirroring dashcore's CGovernanceManager object/vote store +
/// CSuperblockManager::GetBestSuperblock trigger selection.
///
/// WHY IN-MEMORY (not LevelDB): governance triggers are CYCLE-EPHEMERAL — a
/// trigger for superblock height H is created by masternodes inside the
/// maturity window before H and erased shortly after H executes (confirmed
/// live: testnet `gobject count` shows triggers:0 outside the window). There
/// is nothing durable to persist across the ~monthly cycle the way the SML /
/// credit-pool state is persisted; a restart re-runs govsync and rebuilds the
/// store from the network in seconds. (Contrast E3's SMLDb/QuorumDb, which
/// persist per-block-mutating consensus state to avoid a cold ~450 kB re-pull.)
///
/// FAIL-CLOSED DISCIPLINE (E1/E2 parity): a trigger is only ELIGIBLE to back a
/// superblock template when its WEIGHTED funding-signal absolute-yes tally
/// reaches the network funding threshold AND every counted vote was
/// cryptographically verified (BLS operator-key — see the vote-verifier
/// contract in coin_state_maintainer.hpp) AND the voting MN still resolves by
/// collateral in the DMN list at tally time (weight seam below — UNFILTERED
/// by PoSe-ban, dashcore GetMNByCollateral; only the threshold DENOMINATOR is
/// valid-weighted). An incomplete / unverified / sub-threshold view yields NO
/// winning trigger, so the arm refuses and routes to the reward-safe dashd
/// fallback — the mandate: NEVER guess superblock payees.

#include <impl/dash/coin/governance_object.hpp>

#include <core/uint256.hpp>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace dash {
namespace coin {

/// dashcore chainparams consensus.nGovernanceMinQuorum (verified against
/// dashpay/dash chainparams.cpp; testnet value confirmed live via
/// getgovernanceinfo.governanceminquorum == 1).
inline constexpr int DASH_GOV_MIN_QUORUM_MAINNET = 10;
inline constexpr int DASH_GOV_MIN_QUORUM_TESTNET = 1;

/// dashcore evo/dmn_types.h voting weights (CountMatchingVotes weighs each
/// vote by GetMnType(dmn->nType).voting_weight): Regular=1, Evo=4.
inline constexpr int DASH_VOTE_WEIGHT_REGULAR = 1;
inline constexpr int DASH_VOTE_WEIGHT_EVO     = 4;

/// dashcore CGovernanceObject::UpdateSentinelVariables threshold:
///   nAbsVoteReq = max(nGovernanceMinQuorum, nWeightedMnCount / 10)
/// where nWeightedMnCount = tip MN list GetCounts().m_valid_weighted (each
/// valid MN counted at its voting weight, EvoNodes 4x). Returns 0 (fail
/// closed — no trigger can ever win) when either input is unknown/non-positive.
/// Cross-checked live: testnet getgovernanceinfo.fundingthreshold == 17 with
/// min-quorum 1 (weighted count ~170..179).
inline int governance_funding_threshold(int weighted_mn_count, int min_quorum)
{
    if (weighted_mn_count <= 0 || min_quorum <= 0) return 0;  // unknown => fail closed
    return std::max(min_quorum, weighted_mn_count / 10);
}

/// A single counted funding vote (already BLS-operator-verified by the caller
/// before it reaches the tally — see CoinStateMaintainer::set_vote_verifier).
/// Keyed by the voting masternode's collateral outpoint so a re-vote replaces
/// the prior (dashcore keeps only the latest vote per (MN, signal) pair).
struct GovFundingVote {
    int32_t outcome{VOTE_OUTCOME_NONE};  // NONE / YES / NO / ABSTAIN — NONE is
                                         // a STORED outcome (dashcore parity:
                                         // a newer NONE replaces a stored YES,
                                         // dropping the yes-count)
    int64_t timestamp{0};                // newer replaces older
};

class GovernanceStore {
public:
    /// Bound on stored triggers (F2 hardening): real networks carry a handful
    /// of competing triggers per cycle (typically 1-3); a peer streaming more
    /// than this is hostile or broken, and an unbounded map is a memory bomb.
    static constexpr size_t MAX_TRIGGERS = 64;

    /// Network funding threshold — the WEIGHTED absolute-yes count a trigger's
    /// funding tally must reach to be considered triggered. Derive it with
    /// governance_funding_threshold() from the current weighted MN count and
    /// re-seed on every SML update (CoinStateMaintainer does this — the
    /// threshold tracks the list as it grows/shrinks, matching dashcore's
    /// per-tally recomputation). Must be > 0 for ANY trigger to win (a zero /
    /// unknown threshold fails closed — an unbounded view is never triggered).
    void set_funding_threshold(int t) { m_funding_threshold = t; }
    int  funding_threshold() const { return m_funding_threshold; }

    /// Vote-weight + membership-at-tally seam (dashcore CountMatchingVotes):
    /// given a voting MN's collateral-outpoint key ("<txid>-<index>"), return
    /// its CURRENT voting weight — DASH_VOTE_WEIGHT_REGULAR (1) for a regular
    /// MN, DASH_VOTE_WEIGHT_EVO (4) for an EvoNode, and 0 ONLY when the
    /// outpoint is not in the DMN list at all at tally time (dashcore drops
    /// exactly those votes: GetMNByCollateral == nullptr => not counted).
    /// GetMNByCollateral is the UNFILTERED lookup — a PoSe-BANNED MN still
    /// resolves and its vote still counts at FULL weight in dashd; do NOT
    /// filter by ban status here (see gov_vote_weight_for_key in
    /// coin_state_maintainer.hpp — the threshold DENOMINATOR alone is
    /// valid-weighted, dashcore's own asymmetry).
    ///
    /// UNSET (default) => every vote weighs 0 => no tally can reach any
    /// positive threshold => FAIL CLOSED. NOTE for the follow-up implementer:
    /// the DIP-4 SML does NOT carry collateral outpoints, so this mapping
    /// needs the full deterministic MN list (protx info / DMN state) — do NOT
    /// try to fake it from the SML alone.
    void set_vote_weight_fn(std::function<int(const std::string&)> fn) {
        m_vote_weight_fn = std::move(fn);
    }

    /// Ingest a parsed superblock trigger (from a govobj MNGOVERNANCEOBJECT of
    /// ObjectType==TRIGGER whose vchData parsed via parse_superblock_trigger).
    /// Idempotent by object hash. Returns false (dropped) when the store is
    /// full (MAX_TRIGGERS) and the hash is new — bounded-store hardening.
    bool add_trigger(const GovernanceTrigger& t) {
        auto it = m_triggers.find(t.object_hash);
        if (it == m_triggers.end() && m_triggers.size() >= MAX_TRIGGERS)
            return false;
        m_triggers[t.object_hash] = t;
        return true;
    }
    bool has_trigger(const uint256& h) const {
        return m_triggers.count(h) != 0;
    }
    size_t trigger_count() const { return m_triggers.size(); }

    /// Ingest a VERIFIED funding-signal vote for a parent object. The caller
    /// (maintainer) MUST have verified the vote's signature BEFORE calling —
    /// for TRIGGER funding votes that is a BLS signature by the voting MN's
    /// OPERATOR key over govvote_signature_hash (dashcore CGovernanceVote::
    /// IsValid with useVotingKey=false -> CheckSignature(pubKeyOperator);
    /// the ECDSA/keyIDVoting path applies ONLY to PROPOSAL funding votes,
    /// which this store does not tally). The store trusts what it is given
    /// and only tallies verified votes (see FAIL-CLOSED note above).
    void add_verified_funding_vote(const uint256& parent_hash,
                                   const std::string& mn_outpoint_key,
                                   int32_t outcome, int64_t timestamp) {
        auto& per_obj = m_funding_votes[parent_hash];
        auto it = per_obj.find(mn_outpoint_key);
        if (it != per_obj.end()) {
            // dashcore v23.1.7 CGovernanceObject::ProcessVote replacement rule
            // (governance/object.cpp), matched EXACTLY:
            //   new nTime <  stored  => "Obsolete vote"            => reject
            //   new nTime == stored  => reject ONLY when the new OUTCOME <
            //                           the stored outcome (upstream's
            //                           explicit "arbitrary comparison ... to
            //                           pick the winning vote" tie-break);
            //                           otherwise accept (replace)
            //   new nTime >  stored  => accept (replace) — ANY valid outcome,
            //                           including NONE (a newer NONE drops a
            //                           stored YES from the tally)
            // A diverging rule here means c2pool and dashd keep DIFFERENT
            // latest-votes for the same MN => tally divergence => the wrong
            // trigger can win locally => wrong superblock payees.
            if (timestamp < it->second.timestamp) return;
            if (timestamp == it->second.timestamp &&
                outcome < it->second.outcome)
                return;
        }
        per_obj[mn_outpoint_key] = GovFundingVote{outcome, timestamp};
    }

    /// dashcore CGovernanceObject::GetAbsoluteYesCount(VOTE_SIGNAL_FUNDING) ==
    /// GetYesCount - GetNoCount, where CountMatchingVotes weighs every vote by
    /// the voting MN's CURRENT weight (EvoNodes 4x) and counts nothing ONLY
    /// for an MN no longer in the DMN list at all (membership-at-tally via the
    /// unfiltered GetMNByCollateral — PoSe-banned MNs still count). A stored
    /// NONE/ABSTAIN outcome contributes to neither side (but a NONE that
    /// REPLACED a YES has already removed that yes — dashcore parity). With
    /// the weight seam unset every vote weighs 0 (fail closed).
    int absolute_yes_count(const uint256& object_hash) const {
        auto it = m_funding_votes.find(object_hash);
        if (it == m_funding_votes.end()) return 0;
        int yes = 0, no = 0;
        for (const auto& [k, v] : it->second) {
            const int w = m_vote_weight_fn ? m_vote_weight_fn(k) : 0;
            if (w <= 0) continue;                 // not in valid set / seam unset
            if (v.outcome == VOTE_OUTCOME_YES) yes += w;
            else if (v.outcome == VOTE_OUTCOME_NO) no += w;
        }
        return yes - no;
    }

    /// dashcore CSuperblockManager::IsSuperblockTriggered(height): is there any
    /// eligible trigger for `height` whose funding tally reaches the threshold?
    bool is_superblock_triggered(int32_t height) const {
        return static_cast<bool>(get_best_superblock(height));
    }

    /// dashcore CSuperblockManager::GetBestSuperblock(height): among the
    /// triggers that (a) pay THIS height and (b) reached the funding threshold,
    /// return the one with the highest absolute-yes tally. Deterministic
    /// tie-break: lowest object hash (dashcore GetBestSuperblockInternal keeps
    /// the first max in ascending-hash map order — strict '>' — which is the
    /// lowest hash among equals, so all nodes converge on the same winner).
    /// nullopt when none qualifies — i.e. the height is unfunded OR our view
    /// is not yet trigger-confident.
    std::optional<GovernanceTrigger> get_best_superblock(int32_t height) const {
        if (m_funding_threshold <= 0) return std::nullopt; // unknown => fail closed
        const GovernanceTrigger* best = nullptr;
        int best_yes = -1;
        for (const auto& [hash, trig] : m_triggers) {
            if (trig.event_block_height != height) continue;
            int yes = absolute_yes_count(hash);
            if (yes < m_funding_threshold) continue;       // not triggered
            if (yes > best_yes ||
                (yes == best_yes && best && hash < best->object_hash)) {
                best = &trig;
                best_yes = yes;
            }
        }
        if (!best) return std::nullopt;
        return *best;
    }

    /// Drop triggers/votes for heights at or below `executed_height` — dashcore
    /// erases executed triggers. Keeps the store bounded across cycles.
    /// CoinStateMaintainer calls this from the block-connect leg whenever a
    /// superblock height is crossed.
    void prune_executed(int32_t executed_height) {
        for (auto it = m_triggers.begin(); it != m_triggers.end();) {
            if (it->second.event_block_height <= executed_height) {
                m_funding_votes.erase(it->first);
                it = m_triggers.erase(it);
            } else {
                ++it;
            }
        }
    }

    void clear() { m_triggers.clear(); m_funding_votes.clear(); }

private:
    std::map<uint256, GovernanceTrigger> m_triggers;
    // object hash -> (mn collateral-outpoint key -> latest verified funding vote)
    std::map<uint256, std::map<std::string, GovFundingVote>> m_funding_votes;
    int m_funding_threshold{0};  // 0 = unknown => fail closed
    // outpoint key -> current voting weight (0 = absent). Unset => fail closed.
    std::function<int(const std::string&)> m_vote_weight_fn;
};

} // namespace coin
} // namespace dash
