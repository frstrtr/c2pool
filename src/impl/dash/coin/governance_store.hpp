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
/// superblock template when its funding-signal absolute-yes tally reaches the
/// network funding threshold AND every counted vote was cryptographically
/// verified (verify seam below). An incomplete / unverified / sub-threshold
/// view yields NO winning trigger, so the arm refuses and routes to the
/// reward-safe dashd fallback — the mandate is: NEVER guess superblock payees.

#include <impl/dash/coin/governance_object.hpp>

#include <core/uint256.hpp>

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace dash {
namespace coin {

/// A single counted funding vote (already ECDSA-verified + MN-membership
/// checked by the caller before it reaches the tally). Keyed by the voting
/// masternode's outpoint so a re-vote replaces the prior (dashcore keeps only
/// the latest vote per (MN, signal) pair).
struct GovFundingVote {
    int32_t outcome{VOTE_OUTCOME_NONE};  // YES / NO / ABSTAIN
    int64_t timestamp{0};                // newer replaces older
};

class GovernanceStore {
public:
    /// Network funding threshold — the absolute-yes count a trigger's funding
    /// tally must reach to be considered triggered. dashcore keys this off the
    /// weighted MN count (~10%); main_dash seeds it from the SML size (or, when
    /// available, dashd getgovernanceinfo.fundingthreshold as a cross-check).
    /// Must be > 0 for ANY trigger to win (a zero/unknown threshold fails
    /// closed — we never treat an unbounded view as triggered).
    void set_funding_threshold(int t) { m_funding_threshold = t; }
    int  funding_threshold() const { return m_funding_threshold; }

    /// Ingest a parsed superblock trigger (from a govobj MNGOVERNANCEOBJECT of
    /// ObjectType==TRIGGER whose vchData parsed via parse_superblock_trigger).
    /// Idempotent by object hash.
    void add_trigger(const GovernanceTrigger& t) {
        m_triggers[t.object_hash] = t;
    }
    bool has_trigger(const uint256& h) const {
        return m_triggers.count(h) != 0;
    }
    size_t trigger_count() const { return m_triggers.size(); }

    /// Ingest a VERIFIED funding-signal vote for a parent object. The caller
    /// (maintainer) MUST have verified the vote's ECDSA signature against the
    /// voting masternode's keyIDVoting (from the SML) and confirmed the MN is
    /// in the valid set BEFORE calling — the store trusts what it is given and
    /// only tallies verified votes (see FAIL-CLOSED note above).
    void add_verified_funding_vote(const uint256& parent_hash,
                                   const std::string& mn_outpoint_key,
                                   int32_t outcome, int64_t timestamp) {
        auto& per_obj = m_funding_votes[parent_hash];
        auto it = per_obj.find(mn_outpoint_key);
        if (it != per_obj.end() && it->second.timestamp >= timestamp)
            return; // keep the newer vote (dashcore latest-wins per MN)
        per_obj[mn_outpoint_key] = GovFundingVote{outcome, timestamp};
    }

    /// dashcore CGovernanceObject::GetAbsoluteYesCount(VOTE_SIGNAL_FUNDING):
    /// yes-count minus no-count over the counted (verified) funding votes.
    int absolute_yes_count(const uint256& object_hash) const {
        auto it = m_funding_votes.find(object_hash);
        if (it == m_funding_votes.end()) return 0;
        int yes = 0, no = 0;
        for (const auto& [k, v] : it->second) {
            if (v.outcome == VOTE_OUTCOME_YES) ++yes;
            else if (v.outcome == VOTE_OUTCOME_NO) ++no;
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
    /// tie-break: lowest object hash (matches dashcore's ordering intent so all
    /// nodes converge on the same winner). nullopt when none qualifies —
    /// i.e. the height is unfunded OR our view is not yet trigger-confident.
    std::optional<GovernanceTrigger> get_best_superblock(int32_t height) const {
        if (m_funding_threshold <= 0) return std::nullopt; // unknown → fail closed
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
    // object hash -> (mn outpoint key -> latest verified funding vote)
    std::map<uint256, std::map<std::string, GovFundingVote>> m_funding_votes;
    int m_funding_threshold{0};  // 0 = unknown → fail closed
};

} // namespace coin
} // namespace dash
