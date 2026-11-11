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
/// TRI-STATE (C1/C2/C3): besides the funded-winner selection the store keeps
/// what makes "NOT triggered at H" provable or not — triggers we could not
/// admit (unparsed / store-full / signature not yet checkable / parents known
/// only through an orphan YES vote), votes we could not verify, and executed-
/// trigger history. superblock.hpp resolve_superblock_payments reads them.
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
#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <set>
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

/// dashd's std::map<uint256, ...> iteration order: base_blob::Compare is a
/// memcmp over the 32 raw (internal, little-endian) bytes — NOT the
/// arithmetic order c2pool's uint256::operator< uses (most-significant word
/// first). SuperblockManager::GetBestSuperblockInternal (superblock.cpp
/// 523-542) keeps the FIRST maximum in that order (strict '>'), so a tie
/// between equally-voted triggers resolves to the memcmp-smallest hash.
inline bool gov_hash_less_dashd(const uint256& a, const uint256& b)
{
    return std::memcmp(a.data(), b.data(), 32) < 0;
}

/// C2/C3 — a TRIGGER-type governance object we could NOT admit to the
/// trigger map but whose existence makes "no trigger is funded at H"
/// unprovable. Any record that applies to H turns the superblock verdict at
/// H into Unknown (refuse) for BOTH the triggered and the unfunded path: the
/// object we could not hold may be the network's winner.
enum class GovOutstandingKind : uint8_t {
    Unparsed,          // MN signature verified, schedule parse failed (our
                       // parser is narrower than dashd's in places)
    StoreFull,         // verified + parsed, dropped at MAX_TRIGGERS
    UnverifiedPending, // signature not checkable yet (MN not in a current DMN
                       // view / no BLS backend) — retried, never stored
    OrphanYesVote,     // a VERIFIED operator-key FUNDING YES vote whose parent
                       // trigger we do not hold (withheld / rejected by us /
                       // not yet arrived) — real masternodes only vote YES on
                       // triggers dashd accepted
};

inline const char* gov_outstanding_reason(GovOutstandingKind k)
{
    switch (k) {
        case GovOutstandingKind::Unparsed:          return "trigger-unparsed";
        case GovOutstandingKind::StoreFull:         return "trigger-store-full";
        case GovOutstandingKind::UnverifiedPending: return "trigger-unverified-pending";
        case GovOutstandingKind::OrphanYesVote:     return "trigger-orphan-votes";
    }
    return "trigger-outstanding";
}

class GovernanceStore {
public:
    /// Bound on stored triggers (F2 hardening): real networks carry a handful
    /// of competing triggers per cycle (typically 1-3); a peer streaming more
    /// than this is hostile or broken, and an unbounded map is a memory bomb.
    static constexpr size_t MAX_TRIGGERS = 64;
    /// Bound on outstanding (non-admitted) trigger records. Overflow is
    /// itself a blocker until the cycle prunes (fail closed).
    static constexpr size_t MAX_OUTSTANDING = 256;
    /// Bound on votes we could not verify yet (per parent, any outcome).
    /// Overflow is a blocker for every height until the cycle prunes.
    static constexpr size_t MAX_UNVERIFIABLE_VOTES = 8192;
    /// Hashes of triggers pruned as executed/expired (dashd keeps them in
    /// mapErasedGovernanceObjects): a re-synced copy or a late vote for one
    /// of them is history, not a competitor. Oldest-first eviction.
    static constexpr size_t MAX_ERASED = 1024;

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
        // A verified vote from this voter supersedes an earlier unverifiable
        // one (the voter is now resolvable).
        auto uit = m_unverifiable.find(parent_hash);
        if (uit != m_unverifiable.end() && uit->second.erase(mn_outpoint_key)) {
            if (m_unverifiable_total > 0) --m_unverifiable_total;
            if (uit->second.empty()) m_unverifiable.erase(uit);
        }
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

    /// dashcore SuperblockManager::GetBestSuperblockInternal (Dash Core v24
    /// governance/superblock.cpp:523-542) as reached through
    /// IsSuperblockTriggered: dashd picks the max-absolute-yes trigger at the
    /// height among ALL triggers there, and IsSuperblockTriggered only lets a
    /// superblock exist when some trigger reached the threshold — so the
    /// winner is the max-yes trigger, which is necessarily >= threshold. We
    /// restrict the scan to >= threshold candidates: same max, same set of
    /// ties. Tie-break: the FIRST maximum in dashd's std::map order — memcmp
    /// over the raw hash bytes (gov_hash_less_dashd), NOT uint256::operator<
    /// (arithmetic order), which would pick a different winner on a tie.
    /// nullopt when none qualifies — the height is not triggered in OUR view
    /// (which, alone, proves nothing about the network: see ambiguous_at()
    /// and outstanding_blocker()).
    std::optional<GovernanceTrigger> get_best_superblock(int32_t height) const {
        if (m_funding_threshold <= 0) return std::nullopt; // unknown => fail closed
        const GovernanceTrigger* best = nullptr;
        int best_yes = -1;
        for (const auto& [hash, trig] : m_triggers) {
            if (trig.event_block_height != height) continue;
            int yes = absolute_yes_count(hash);
            if (yes < m_funding_threshold) continue;       // not triggered
            if (yes > best_yes ||
                (yes == best_yes && best &&
                 gov_hash_less_dashd(hash, best->object_hash))) {
                best = &trig;
                best_yes = yes;
            }
        }
        if (!best) return std::nullopt;
        return *best;
    }

    // ── C1: STRICT ABSENCE — may "not triggered at H" be asserted at all? ───

    /// Raw (unweighted) count of stored verified votes with `outcome` on a
    /// trigger. Unweighted on purpose: a YES from an MN our weight seam
    /// cannot resolve is still evidence someone wants this trigger funded.
    size_t raw_vote_count(const uint256& object_hash, int32_t outcome) const {
        auto it = m_funding_votes.find(object_hash);
        if (it == m_funding_votes.end()) return 0;
        size_t n = 0;
        for (const auto& [k, v] : it->second)
            if (v.outcome == outcome) ++n;
        return n;
    }
    /// Weighted NO count (what a down-vote must carry to count as one).
    int weighted_no_count(const uint256& object_hash) const {
        auto it = m_funding_votes.find(object_hash);
        if (it == m_funding_votes.end()) return 0;
        int no = 0;
        for (const auto& [k, v] : it->second) {
            if (v.outcome != VOTE_OUTCOME_NO) continue;
            const int w = m_vote_weight_fn ? m_vote_weight_fn(k) : 0;
            if (w > 0) no += w;
        }
        return no;
    }

    /// Why "not triggered at `height`" can NOT be asserted from the stored
    /// triggers, or nullopt when every stored trigger at the height is
    /// POSITIVELY voted down. dashd IsSuperblockTriggered is a pure function
    /// of the trigger set + tally; our copy of both can be partial (votes not
    /// yet streamed, a voter our DMN view cannot resolve), so a stored
    /// trigger at H only permits "not triggered" when it carries counted
    /// votes, NONE of them YES, and a weighted NO side — any YES (raw), any
    /// positive absolute-yes, a trigger with no counted votes at all, or any
    /// vote we could not verify keeps the height AMBIGUOUS. (dashd's own
    /// trigger creator always votes YES on the trigger it supports —
    /// governance/signing.cpp VoteGovernanceTriggers — so in practice any
    /// stored trigger at H blocks the unfunded verdict; that is intended.)
    std::optional<std::string> ambiguous_at(int32_t height) const {
        for (const auto& [hash, trig] : m_triggers) {
            if (trig.event_block_height != height) continue;
            if (unverifiable_vote_count(hash) > 0) return std::string("trigger-unverified-votes");
            if (absolute_yes_count(hash) > 0)       return std::string("trigger-ambiguous");
            if (raw_vote_count(hash, VOTE_OUTCOME_YES) > 0)
                return std::string("trigger-ambiguous");
            if (weighted_no_count(hash) <= 0)       return std::string("trigger-ambiguous");
        }
        return std::nullopt;
    }

    /// Any stored trigger at `height` carrying a vote we could not verify:
    /// its true tally is unknown, so it may out-vote (or be) the winner.
    /// Blocks BOTH verdicts.
    bool unverified_votes_at(int32_t height) const {
        for (const auto& [hash, trig] : m_triggers)
            if (trig.event_block_height == height && unverifiable_vote_count(hash) > 0)
                return true;
        return false;
    }

    // ── C2/C3: outstanding (non-admitted) trigger objects ──────────────────

    /// Record a trigger-type object we could not admit. `event_height` is the
    /// parsed superblock height, or 0 when unknown (an unparseable object, an
    /// orphan vote's parent) => blocks EVERY height of the current cycle
    /// until prune_cycle(). Idempotent per hash (the newest kind wins).
    /// Overflow (MAX_OUTSTANDING) is itself a cycle-wide blocker.
    void note_outstanding(const uint256& hash, GovOutstandingKind kind,
                          int32_t event_height) {
        auto it = m_outstanding.find(hash);
        if (it == m_outstanding.end() && m_outstanding.size() >= MAX_OUTSTANDING) {
            m_outstanding_overflow = true;
            return;
        }
        m_outstanding[hash] = Outstanding{kind, event_height};
    }
    void clear_outstanding(const uint256& hash) { m_outstanding.erase(hash); }
    bool is_outstanding(const uint256& hash) const { return m_outstanding.count(hash) != 0; }
    std::optional<GovOutstandingKind> outstanding_kind(const uint256& hash) const {
        auto it = m_outstanding.find(hash);
        if (it == m_outstanding.end()) return std::nullopt;
        return it->second.kind;
    }
    size_t outstanding_count() const { return m_outstanding.size(); }
    bool outstanding_overflow() const { return m_outstanding_overflow; }

    /// The first outstanding record that applies to `height` (its own height,
    /// or unknown-height => cycle-wide), as a stable refusal token.
    std::optional<std::string> outstanding_blocker(int32_t height) const {
        if (m_outstanding_overflow) return std::string("trigger-outstanding-overflow");
        if (m_unverifiable_overflow) return std::string("trigger-unverified-votes");
        for (const auto& [hash, rec] : m_outstanding) {
            if (rec.event_height == 0 || rec.event_height == height)
                return std::string(gov_outstanding_reason(rec.kind));
        }
        return std::nullopt;
    }

    /// Hashes of the stored triggers paying `height` (C4 vote re-sync).
    std::vector<uint256> trigger_hashes_at(int32_t height) const {
        std::vector<uint256> out;
        for (const auto& [hash, trig] : m_triggers)
            if (trig.event_block_height == height) out.push_back(hash);
        return out;
    }
    /// Parents recorded only through an orphan YES vote (fetch candidates).
    std::vector<uint256> orphan_yes_parents() const {
        std::vector<uint256> out;
        for (const auto& [hash, rec] : m_outstanding)
            if (rec.kind == GovOutstandingKind::OrphanYesVote) out.push_back(hash);
        return out;
    }

    /// A vote on `parent_hash` whose signature could not be checked yet
    /// (voter not in a current DMN view, or no BLS backend). Kept per voter
    /// until a verified vote from the same voter replaces it or the parent is
    /// pruned. Any such vote on a trigger at H keeps H Unknown.
    void note_unverifiable_vote(const uint256& parent_hash,
                                const std::string& mn_outpoint_key) {
        auto it = m_unverifiable.find(parent_hash);
        if (it != m_unverifiable.end() && it->second.count(mn_outpoint_key)) return;
        if (m_unverifiable_total >= MAX_UNVERIFIABLE_VOTES) {
            m_unverifiable_overflow = true;
            return;
        }
        m_unverifiable[parent_hash].insert(mn_outpoint_key);
        ++m_unverifiable_total;
    }
    /// The held vote turned out INVALID on retry (forged / wrong key): it no
    /// longer clouds the tally.
    void clear_unverifiable_vote(const uint256& parent_hash,
                                 const std::string& mn_outpoint_key) {
        auto it = m_unverifiable.find(parent_hash);
        if (it == m_unverifiable.end() || !it->second.erase(mn_outpoint_key)) return;
        if (m_unverifiable_total > 0) --m_unverifiable_total;
        if (it->second.empty()) m_unverifiable.erase(it);
    }
    size_t unverifiable_vote_count(const uint256& parent_hash) const {
        auto it = m_unverifiable.find(parent_hash);
        return it == m_unverifiable.end() ? 0 : it->second.size();
    }
    size_t unverifiable_vote_total() const { return m_unverifiable_total; }

    /// Executed/expired trigger history (see MAX_ERASED).
    bool is_erased(const uint256& hash) const { return m_erased.count(hash) != 0; }
    void note_erased(const uint256& hash) {
        if (!m_erased.insert(hash).second) return;
        m_erased_order.push_back(hash);
        while (m_erased_order.size() > MAX_ERASED) {
            m_erased.erase(m_erased_order.front());
            m_erased_order.pop_front();
        }
    }

    /// Drop triggers/votes for heights at or below `executed_height` — dashcore
    /// erases executed triggers (SuperblockManager::Clean / IsExpired; dashd
    /// keeps an EXECUTED trigger for one more cycle only to answer syncs,
    /// superblock.cpp:338-372 — it can never pay a future height, because a
    /// trigger pays exactly its event_block_height). Called from EVERY block
    /// connect with the connected height, so a trigger re-synced after a
    /// restart for an already-executed superblock is dropped on the next
    /// block instead of sitting in the store until the next superblock.
    /// Pruned hashes are remembered (note_erased) so their late votes are
    /// history, not orphans. Height-bound outstanding records go too.
    void prune_executed(int32_t executed_height) {
        for (auto it = m_triggers.begin(); it != m_triggers.end();) {
            if (it->second.event_block_height <= executed_height) {
                drop_votes_of(it->first);
                note_erased(it->first);
                it = m_triggers.erase(it);
            } else {
                ++it;
            }
        }
        for (auto it = m_outstanding.begin(); it != m_outstanding.end();) {
            if (it->second.event_height != 0 &&
                it->second.event_height <= executed_height) {
                drop_votes_of(it->first);
                note_erased(it->first);
                it = m_outstanding.erase(it);
            } else {
                ++it;
            }
        }
    }

    /// The superblock at `sb_height` has been connected: the cycle the
    /// unknown-height records belonged to is over. Clears them and the
    /// overflow latches (a fresh cycle re-proves itself from scratch).
    void prune_cycle() {
        for (auto it = m_outstanding.begin(); it != m_outstanding.end();) {
            if (it->second.event_height == 0) {
                drop_votes_of(it->first);
                it = m_outstanding.erase(it);
            } else {
                ++it;
            }
        }
        m_outstanding_overflow = false;
        if (m_unverifiable_overflow) {
            m_unverifiable.clear();
            m_unverifiable_total = 0;
            m_unverifiable_overflow = false;
        }
    }

    void clear() {
        m_triggers.clear();
        m_funding_votes.clear();
        m_outstanding.clear();
        m_outstanding_overflow = false;
        m_unverifiable.clear();
        m_unverifiable_total = 0;
        m_unverifiable_overflow = false;
    }

private:
    struct Outstanding {
        GovOutstandingKind kind{GovOutstandingKind::Unparsed};
        int32_t event_height{0};   // 0 = unknown => cycle-wide
    };

    void drop_votes_of(const uint256& hash) {
        m_funding_votes.erase(hash);
        auto it = m_unverifiable.find(hash);
        if (it != m_unverifiable.end()) {
            m_unverifiable_total -= std::min(m_unverifiable_total, it->second.size());
            m_unverifiable.erase(it);
        }
    }

    std::map<uint256, GovernanceTrigger> m_triggers;
    // object hash -> (mn collateral-outpoint key -> latest verified funding vote)
    std::map<uint256, std::map<std::string, GovFundingVote>> m_funding_votes;
    int m_funding_threshold{0};  // 0 = unknown => fail closed
    // outpoint key -> current voting weight (0 = absent). Unset => fail closed.
    std::function<int(const std::string&)> m_vote_weight_fn;
    // C2/C3 non-admitted trigger objects (+ orphan-YES parents).
    std::map<uint256, Outstanding> m_outstanding;
    bool m_outstanding_overflow{false};
    // parent hash -> voters whose vote could not be verified yet.
    std::map<uint256, std::set<std::string>> m_unverifiable;
    size_t m_unverifiable_total{0};
    bool m_unverifiable_overflow{false};
    // executed/expired trigger hashes (bounded, oldest evicted first).
    std::set<uint256> m_erased;
    std::deque<uint256> m_erased_order;
};

} // namespace coin
} // namespace dash
