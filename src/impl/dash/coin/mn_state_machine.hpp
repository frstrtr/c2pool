// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Phase C-PAY step 4: per-block DMN state machine.
///
/// Mirrors dashcore's evo/specialtxman.cpp::RebuildListFromBlock @ cfad414
/// in the order-of-operations + the field-update semantics. This is the
/// piece that turns the bootstrap state from step 3a/3b into a live,
/// auto-maintained DMN list that step 5 can project payee selections
/// against.
///
/// Apply order (matches dashcore exactly):
///
///   Pass 1 — special-tx records (skip coinbase, walk i=1+):
///     PROVIDER_REGISTER (type 1):  AddMN with proRegTxHash = tx.GetHash()
///         + collateralOutpoint resolution (null hash → tx's own output)
///         + collateral-collision check (replaces an existing MN that
///           shared the same external collateral outpoint)
///     PROVIDER_UPDATE_SERVICE (type 2): netInfo + scriptOperatorPayout
///         + Evo platform fields; PoSe-revive if MN was banned
///     PROVIDER_UPDATE_REGISTRAR (type 3): pubKeyOperator + keyIDVoting
///         + scriptPayout; if pubKeyOperator changed, ResetOperatorFields
///         + BanIfNotBanned (until a ProUpServTx revives)
///     PROVIDER_UPDATE_REVOKE (type 4): ResetOperatorFields + ban +
///         nRevocationReason
///
///   Pass 2 — collateral spends (skip coinbase, walk i=1+):
///     For each vin, check m_collateral_index; if matched, remove the MN.
///     dashcore does this AFTER pass 1 so a brand-new MN registered THIS
///     block can have its collateral spent in a later tx of the same
///     block (rare but consensus-correct). We mirror.
///
///   Pass 3 — payee resolution (PROJECTION attribution, dashd-exact):
///     Mirrors dashcore evo/deterministicmns.cpp BuildNewListFromBlock:
///     the payee is COMPUTED from the pre-block list (GetMNPayee on
///     pindexPrev == find_expected_payee() before pass 1) and — if still
///     present after passes 1/2 (newList.HasMN) — marked
///     nLastPaidHeight = height. The coinbase is only used as a
///     CROSS-CHECK: if it does not pay the projected MN's scriptPayout,
///     this state has desynced from the network's payment schedule and
///     the apply reports payee_desync (caller fails closed + re-seeds)
///     instead of guessing an attribution.
///
///     HISTORY (soak-found 2026-07-22, e4-e1e2b, 13x bad-cb-payee):
///     the previous OBSERVATION attribution (scan coinbase outputs,
///     pick_paid_mn per matching output) was not idempotent: any
///     duplicated/replayed attribution of one block re-picked within a
///     shared-payoutAddress group (53 testnet MNs share one address) and
///     marked the NEXT MN of the group, silently shifting the group's
///     payment cursor one slot ahead FOREVER. The embedded arm then
///     emitted the wrong coinbase payee at every height where the
///     one-ahead group cursor changed the projected address (~10% of
///     serves; dashd rejected each with bad-cb-payee). Projection
///     attribution + the whole-apply monotonic-height guard remove the
///     divergence class structurally; the desync flag turns any residual
///     mismatch into an immediate fail-closed instead of silent wrongness.
///     For Evo MNs, nConsecutivePayments increments if last payment was
///     at height-1, else resets to 1 (unchanged).
///
/// Things we DELIBERATELY don't model (with consequence notes):
///   - Confirmation pass (dashcore: nMasternodeMinimumConfirmations →
///     confirmedHash). Phase L doesn't use confirmedHash; the SML
///     already sync'd from the network has the correct confirmedHash
///     equivalent baked in. Defer.
///   - DecreaseScores (PoSe penalty decay). We don't track nPoSePenalty
///     beyond storing the field. Phase C-PAY's projection algorithm
///     doesn't read nPoSePenalty (only nPoSeBanHeight via isValid),
///     so this is acceptable.
///   - Quorum commitment processing inside per-block (Phase C-QUO's
///     QuorumManager already handles this via the SML diff path,
///     separately).
///   - Operator-payout tracking (scriptOperatorPayout matches in
///     coinbase). Smaller revenue stream; defer until consumer needs it.
///   - PoSe ban via empty netInfo at registration (dashcore's
///     BanIfNotBanned at line specialtxman.cpp:304). Edge case for
///     newly-registered MNs that haven't yet sent a ProUpServTx; the
///     net effect for projection is the same as nLastPaidHeight=0
///     (they sort to the bottom of the payee queue).
///
/// Reorg story: the state machine is forward-only. On a chain reorg
/// the caller (main_dash tip-changed handler) wipes mn_state_db AND
/// calls load() with the empty vector, then re-bootstraps from the
/// snapshot path; subsequent on_full_block calls re-apply forward
/// from snapshot height.

#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/mn_state_db.hpp>
#include <impl/dash/coin/vendor/providertx.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>
#include <impl/bitcoin_family/coin/base_transaction.hpp>

#include <core/hash.hpp>
#include <core/log.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

// Strict weak ordering on TxPrevOut (uint256 + uint32) for std::map
// keys. We use uint256 operator< (CompareTo, big-endian-integer
// ordering) — the map is INTERNAL (never compared against dashcore
// wire data), so any consistent ordering works. NOT the memcmp
// ordering Bug A required for the SML merkle leaf sort.
struct TxPrevOutLess {
    bool operator()(const bitcoin_family::coin::TxPrevOut& a,
                    const bitcoin_family::coin::TxPrevOut& b) const
    {
        if (a.hash != b.hash) return a.hash < b.hash;
        return a.index < b.index;
    }
};

class MnStateMachine
{
public:
    struct ApplyResult {
        size_t registered{0};
        size_t updated{0};
        size_t revoked{0};
        // ── REINSTATEMENT, measured ──────────────────────────────────────
        // A PoSe revive reaches us as a ProUpServTx (dashcore
        // specialtxman.cpp:361-370). Before these two counters existed the
        // revive branch incremented only `updated`, so a bridge could report
        // "REINSTATED: 0" whether it had seen no revive, or had seen one and
        // silently thrown it away. Those are different facts and now have
        // different counters.
        //
        // revived: ProUpServTx revives APPLIED (banHeight cleared,
        //          revivedHeight set) — the reinstatement actually happened.
        size_t revived{0};
        // revive_dropped_unknown: ProUpServTx naming a proTxHash this set has
        //          NO entry for. This is the SEED-COMPLETENESS defect's
        //          signature: a `protx list valid`-filtered seed omits
        //          PoSe-banned masternodes entirely, and the replay's only
        //          insertion path is ProRegTx — which a long-registered
        //          masternode will never emit again. Every count here is a
        //          masternode dashd has put back in the payment queue and we
        //          have not, i.e. a permanent one-slot offset in every later
        //          projection. NON-ZERO IS A DEFECT, not a statistic.
        size_t revive_dropped_unknown{0};
        size_t spent{0};       // collateral spent → MN removed
        size_t paid{0};        // projected payee marked paid this block
        size_t total_after{0};
        // Duplicate / out-of-order delivery: height <= last applied height.
        // The WHOLE apply was skipped (no state mutation). A re-run of the
        // old observation-attribution over an already-applied block marked
        // the NEXT MN of a shared-payoutAddress group — the soak-found
        // bad-cb-payee corruption this guard closes.
        bool skipped_out_of_order{false};
        // NON-CONTIGUOUS delivery: height > cursor + 1 — one or more blocks
        // between the cursor (seed as-of height or last applied block) and
        // this one were NEVER folded. dashd advanced its DIP-3 payment
        // cursor at each skipped block; ours did not, so from here on the
        // projected payee is some earlier queue slot than dashd's. Within a
        // shared-payoutAddress group that divergence is INVISIBLE to the
        // pass-3 coinbase cross-check (the script still matches) and only
        // surfaces — as a served bad-cb-payee — when the lagged cursor
        // crosses an address-group boundary. The WHOLE apply is refused (no
        // state mutation); the caller must fail closed + re-seed, exactly
        // like payee_desync.
        //
        // SOAK EVIDENCE (E4 re-soak 2026-07-23, binary 7daa4d61): seed
        // as-of 1519820; blocks 1519821+1519822 mined during header sync
        // were never folded; folds 1519823..1519826 each marked the wrong
        // (2-slots-behind) yeRZB-group MN silently; at 1519827 dashd's head
        // rotated to the yVXDA group while ours was still yeRZB-member
        // 05b68797... -> bad-cb-payee served for the whole window.
        bool gap_detected{false};
        // The coinbase does NOT pay the MN this machine projects as the
        // deterministic payee: this state desynced from the network's DMN
        // payment schedule (missed block / corrupted seed / replay). The
        // payment was NOT attributed — never guess. Caller must fail
        // closed (stop backing templates with this payee set) + re-seed.
        bool payee_desync{false};
        // The DIP-3 payee this machine projected from the PRE-block list
        // (pass 0). Present whenever the pre-block list was non-empty,
        // whether or not the coinbase agreed. Surfaced so a caller can name
        // the MN in its own diagnostics without re-deriving it — and
        // re-deriving POST-apply gives a DIFFERENT answer, because a
        // successful mark moves that MN to the back of the queue.
        std::optional<uint256> projected_payee;
        // Number of ranked candidates PERMANENTLY excluded this block by the
        // SML-attested PoSe-ban recovery walk (see set_sml_validity_fn). 0 on
        // every ordinary block. A nonzero value means the projected payee
        // disagreed with the coinbase AND the SML proved the disagreement was
        // a post-anchor consensus PoSe ban rather than a real desync.
        size_t sml_recovered{0};
    };

    /// ─────────────────────────────────────────────────────────────────────
    /// WHAT A MISMATCH LEAVES BEHIND, SO IT CAN BE RE-ASKED
    /// ─────────────────────────────────────────────────────────────────────
    /// When pass 3 reports payee_desync it has already refused to attribute
    /// anything — no state was guessed. But the block's own passes 1/2 DID
    /// run, and `ranked` was computed from the PRE-block list, which no longer
    /// exists once those passes have run. So a caller that later obtains a
    /// BETTER-DATED masternode list cannot simply re-apply the block: the
    /// forward-only cursor refuses it, and re-deriving `ranked` post-apply
    /// gives a different queue.
    ///
    /// This is the exact context needed to re-adjudicate ONLY pass 3 against a
    /// list we did not have when the block arrived. It is written on every
    /// payee_desync and cleared the moment another block is applied, so it can
    /// only ever describe the height the cursor is standing on.
    struct PendingPayeeAdjudication {
        bool                   present{false};
        uint32_t               height{0};
        std::vector<uint256>   ranked;      ///< PRE-block DIP-3 queue, in order
        std::optional<uint256> projected;   ///< ranked.front()
    };
    const PendingPayeeAdjudication& pending_payee_adjudication() const
    {
        return m_pending;
    }

    /// Outcome of readjudicate_payee(). `refusal` is a sentence, not a code:
    /// it lands verbatim in the lane's fail-closed line, which is the only
    /// record an operator gets.
    struct ReadjudicateResult {
        bool                   recovered{false};
        size_t                 excluded{0};   ///< queue heads permanently retired
        std::optional<uint256> accepted;      ///< who the payment was attributed to
        std::string            refusal;
    };

    /// Optional validity attestation for a proTxHash, sourced from the
    /// Simplified Masternode List. THREE-state on purpose:
    ///
    ///   std::nullopt — the proTxHash is ABSENT from the SML. No opinion.
    ///                  Never treated as evidence of anything.
    ///   false        — the SML ATTESTS INVALID (PoSe-banned / revoked).
    ///   true         — the SML ATTESTS VALID.
    ///
    /// The distinction is load-bearing. "Absent" and "attested valid" both
    /// BLOCK a demotion; only "attested invalid" may license one. A two-state
    /// bool would collapse "I don't know" into one of the other two answers
    /// and, either way, let the recovery walk act on non-evidence.
    ///
    /// DEFAULT IS NULL. With no hook installed this class behaves EXACTLY as
    /// it did before the hook existed — same mutations, same ApplyResult
    /// flags, same log lines. Every pre-existing caller and KAT is untouched.
    using SmlValidityFn = std::function<std::optional<bool>(const uint256&)>;

    void set_sml_validity_fn(SmlValidityFn fn) { m_sml_validity = std::move(fn); }
    bool has_sml_validity_fn() const { return static_cast<bool>(m_sml_validity); }

    /// Cumulative budget for SML-attested exclusions over the lifetime of
    /// this machine (i.e. per bridge). The recovery walk REPAIRS a bounded,
    /// expected phenomenon — a handful of masternodes PoSe-banned in the
    /// window between a pinned anchor and the tip. A replay that needs dozens
    /// of them is not being repaired, it is being overridden, and the honest
    /// response to that is to fail closed. The caller sizes the budget
    /// against its replay distance; see MnCheckpointLane::pump().
    /// FRESHNESS GATE for the reactive demotion walk. The height the
    /// installed SML is CURRENT AT (0 = unknown, which keeps the pre-gate
    /// behaviour for callers that do not track it).
    ///
    /// Why this is load-bearing: recover_from_sml_ban() turns an attestation
    /// into a PERMANENT exclusion. A STALE SML can attest isValid=false for a
    /// masternode that has since been revived; combined with a coincidental
    /// runner-up script match, that licenses a wrong permanent demotion and a
    /// published queue that diverges from dashd's for the rest of the run.
    /// An SML older than the height being adjudicated cannot speak to that
    /// height, so it is not evidence — nullopt, never false.
    /// Setting this ONCE opts the machine into fail-closed freshness: from
    /// then on a height of 0 means "the SML covers NOTHING", not "covers
    /// everything". The distinction matters because 0 is exactly what a warm
    /// restart (F1) and an unpaired list/height (F2) produce, and in both
    /// cases the honest answer is that we cannot date the attestation.
    /// Callers that never call this keep the pre-gate behaviour byte for byte.
    void set_sml_current_height(uint32_t h)
    {
        m_sml_height       = h;
        m_sml_height_known = true;
    }
    uint32_t sml_current_height() const     { return m_sml_height; }

    void set_sml_recovery_cap(size_t n) { m_sml_recovery_cap = n; }
    size_t sml_recovery_cap() const     { return m_sml_recovery_cap; }
    size_t sml_recovered_total() const  { return m_sml_recovered_total; }
    /// Zero the SPENT half of the per-bridge demotion-walk budget.
    ///
    /// load() deliberately does NOT do this — it reloads the ENTRIES, and a
    /// caller that reloads a snapshot mid-run must not thereby hand itself a
    /// fresh licence to override the projection. But a bridge that is RE-ARMED
    /// from its anchor is a NEW bridge: the budget is documented as
    /// "per-bridge", and carrying the previous bridge's spend into it would
    /// start the replay with the walk already exhausted — silently converting
    /// the first post-anchor PoSe ban into a terminal fail-close. Only
    /// MnCheckpointLane::rearm() calls this, on exactly that boundary.
    void reset_sml_recovery_budget() { m_sml_recovered_total = 0; }

    /// How deep pass 0's ranked candidate list goes. The recovery walk can
    /// never look past this depth, which bounds both the work and the blast
    /// radius: a genuine desync cannot be "walked off" by marching down an
    /// unbounded queue until something happens to match.
    static constexpr size_t kPayeeCandidates = 8;

    /// dashcore CompareByLastPaid_GetHeight (deterministicmns.cpp:158-167),
    /// extracted so the projection scan, the shared-payoutAddress
    /// disambiguator and the premature-exclusion recovery can never drift
    /// apart. Also normalises dashd's -1 "never" sentinels (stored as
    /// UINT32_MAX by older snapshots), which cast back to int would otherwise
    /// beat every real height.
    static int payee_score(const MNState& st)
    {
        constexpr uint32_t SENTINEL = std::numeric_limits<uint32_t>::max();
        auto sane = [](uint32_t v) -> uint32_t {
            return (v == SENTINEL) ? 0u : v;
        };
        const uint32_t lastPaid = sane(st.nLastPaidHeight);
        const uint32_t revived  = sane(st.nPoSeRevivedHeight);
        int h = static_cast<int>(lastPaid);
        if (revived != 0 && static_cast<int>(revived) > h) {
            h = static_cast<int>(revived);
        } else if (h == 0) {
            h = static_cast<int>(st.nRegisteredHeight);
        }
        return h;
    }

    /// dashcore CompareByLastPaid: score ascending, ties by proTxHash memcmp
    /// ascending (LE-byte wire order, NOT c2pool's CompareTo).
    static bool payee_order_before(int a_score, const uint256& a,
                                   int b_score, const uint256& b)
    {
        if (a_score != b_score) return a_score < b_score;
        return std::memcmp(a.data(), b.data(), 32) < 0;
    }

    /// as_of_height: the chain height this snapshot is CURRENT AT (0 =
    /// unknown / cold). It seeds the forward-contiguous apply cursor: the
    /// snapshot's lastPaidHeight set IS the DIP-3 payment queue as dashd
    /// held it AFTER connecting block as_of_height, so the ONLY block
    /// apply_block may fold next is as_of_height + 1. Folding a later block
    /// on top of the seed (the E4 soak's 1519823-on-a-1519820-seed) means
    /// the skipped blocks' payments were never attributed and the queue
    /// cursor is stale — apply_block reports gap_detected instead.
    void load(std::vector<std::pair<uint256, MNState>> entries,
              uint32_t as_of_height = 0)
    {
        m_entries.clear();
        m_collateral_index.clear();
        m_last_applied_height = as_of_height;
        // A pending mismatch describes a queue that no longer exists once the
        // set is reloaded. Leaving it would let a re-armed lane re-adjudicate
        // an old height against a new set.
        m_pending = PendingPayeeAdjudication{};
        for (auto& [h, st] : entries) {
            m_collateral_index[st.collateralOutpoint] = h;
            m_entries.emplace(h, std::move(st));
        }
    }

    // Height of the last block folded by apply_block (0 = none since load).
    // apply_block is FORWARD-ONLY: any call at height <= this is skipped
    // whole (see ApplyResult::skipped_out_of_order).
    uint32_t last_applied_height() const { return m_last_applied_height; }

    size_t size() const { return m_entries.size(); }

    using Entries = std::map<uint256, MNState>;
    const Entries& entries() const { return m_entries; }

    std::optional<uint256> find_by_collateral(
        const bitcoin_family::coin::TxPrevOut& outpoint) const
    {
        auto it = m_collateral_index.find(outpoint);
        if (it == m_collateral_index.end()) return std::nullopt;
        return it->second;
    }

    // Linear scan over scriptPayout — used by pass 3 (payee resolution)
    // and by Phase C-PAY step 5 (`[PAY]` log-only verification). At
    // ~3000 active MNs and a typical 10-output coinbase that's ~30k
    // memcmp comparisons per block (microseconds). Acceptable.
    std::optional<uint256> find_by_payout_script(
        const std::vector<unsigned char>& script) const
    {
        if (script.empty()) return std::nullopt;
        for (const auto& [h, st] : m_entries) {
            if (st.scriptPayout.m_data == script) return h;
        }
        return std::nullopt;
    }

    // Walk a block's coinbase outputs and return the FIRST output that
    // matches a known MN's scriptPayout. Used by step 5 to cross-check
    // projection vs observation. Returns nullopt if nothing matched
    // (DMN state empty pre-bootstrap, OR coinbase paid an unknown
    // address — e.g. superblock budget output).
    std::optional<uint256> find_paid_in_block_first(
        const dash::coin::BlockType& block) const
    {
        if (block.m_txs.empty()) return std::nullopt;
        for (const auto& vout : block.m_txs[0].vout) {
            // Use pick_paid_mn (lowest-h disambiguation) instead of
            // find_by_payout_script (first-map-iteration), to mirror
            // dashd's GetMNPayee selection when multiple MNs share a
            // scriptPayout. MUST be called PRE-apply_block so the
            // lowest-h MN is the one dashd actually paid; post-apply
            // the just-paid MN has the highest h and would be missed.
            if (auto m = pick_paid_mn(vout.scriptPubKey.m_data)) {
                return m;
            }
        }
        return std::nullopt;
    }

    // Selection-aware payee lookup (the fix for the shared-payoutAddress
    // attribution bug). When N MNs map to the same scriptPayout, dashd's
    // CDeterministicMNList::GetMNPayee picks the one with the lowest
    // CompareByLastPaid_GetHeight. Mirror that here so apply_block
    // attributes payments to the correct MN in our state, keeping us in
    // sync with dashd's projection.
    std::optional<uint256> pick_paid_mn(
        const std::vector<unsigned char>& script) const
    {
        if (script.empty()) return std::nullopt;
        constexpr uint32_t SENTINEL = std::numeric_limits<uint32_t>::max();
        auto sane = [](uint32_t v) {
            return (v == SENTINEL) ? 0u : v;
        };
        std::optional<uint256> best;
        int best_h = std::numeric_limits<int>::max();
        for (const auto& [hash, st] : m_entries) {
            if (!st.isValid) continue;
            // Bug 14 guard: nPoSeBanHeight is write-only on the selection
            // path, so a divergent persisted snapshot could carry
            // isValid==true alongside a live ban height and pay a banned MN
            // on the boolean alone. Reconciled invariant: isValid==true =>
            // ban height clear (0, or the -1/UINT32_MAX never-banned
            // sentinel). Fail-closed (a crash here would kill the daemonless
            // payee projection outright, worse than a skip) with a logged
            // warning so the invariant violation is never silent.
            if (sane(st.nPoSeBanHeight) != 0) {
                LOG_INFO << "[MNS] fail-closed: valid MN " << hash.GetHex().substr(0,16)
                         << " carries live PoSe banHeight=" << st.nPoSeBanHeight
                         << " (divergent snapshot) -- excluded from selection";
                continue;
            }
            if (st.scriptPayout.m_data != script) continue;
            const int h = payee_score(st);
            bool better = !best.has_value()
                       || payee_order_before(h, hash, best_h, *best);
            if (better) {
                best_h = h;
                best   = hash;
            }
        }
        return best;
    }

    // Phase C-PAY step 5: vendor of dashcore
    // CDeterministicMNList::GetMNPayee() @ cfad414 (deterministicmns.cpp:184).
    //
    // For Dash mainnet at height > 2,128,896 (MN_RR activation), the
    // Evo 4-in-a-row bonus path is DEAD (`if isv19Active &&
    // !isMNRewardReallocation` evaluates to false). All current and
    // future blocks just use the standard CompareByLastPaid scan.
    // c2pool-dash's header checkpoint is at h=2.4M so we always
    // operate post-MN_RR — we omit the Evo bonus path with a TODO
    // for testnet support pre-1,066,900.
    //
    // CompareByLastPaid_GetHeight (line 158-167):
    //   h = nLastPaidHeight
    //   if nPoSeRevivedHeight > h: h = nPoSeRevivedHeight
    //   else if h == 0: h = nRegisteredHeight
    //
    // CompareByLastPaid (line 169-177):
    //   ah == bh: tiebreak by proTxHash ascending
    //   else:     ah < bh
    //
    // CRITICAL: tiebreaker uses dashcore's uint256 operator< which is
    // memcmp(LE-byte) — NOT c2pool's CompareTo (BE-integer). Same
    // gotcha as Bug A in vendor/simplifiedmns.hpp's sort. We use
    // std::memcmp directly to match dashcore's wire semantics.
    // Dump a MN's projection-relevant state (one-shot diagnostic).
    void debug_dump_mn(const uint256& hash, const char* tag) const {
        auto it = m_entries.find(hash);
        if (it == m_entries.end()) {
            LOG_INFO << "[MNS-DBG " << tag << "] hash=" << hash.GetHex().substr(0,16)
                     << " NOT IN m_entries";
            return;
        }
        const auto& s = it->second;
        // Hex-dump scriptPayout for byte-level comparison vs coinbase outputs.
        std::string sphex;
        sphex.reserve(s.scriptPayout.m_data.size() * 2);
        const char* hex = "0123456789abcdef";
        for (auto b : s.scriptPayout.m_data) {
            sphex.push_back(hex[(b >> 4) & 0xf]);
            sphex.push_back(hex[b & 0xf]);
        }
        LOG_INFO << "[MNS-DBG " << tag << "] hash=" << hash.GetHex().substr(0,16)
                 << " isValid=" << s.isValid
                 << " nType=" << int(s.nType)
                 << " lastPaid=" << s.nLastPaidHeight
                 << " registered=" << s.nRegisteredHeight
                 << " revived=" << s.nPoSeRevivedHeight
                 << " banHeight=" << s.nPoSeBanHeight
                 << " revoke=" << int(s.nRevocationReason)
                 << " scriptPayout(" << s.scriptPayout.m_data.size() << ")=" << sphex;
    }

    /// The first `k` masternodes of the DIP-3 payment queue, in dashd's
    /// CompareByLastPaid order (ascending). ranked[0] IS find_expected_payee()
    /// — the two share this scan so they can never disagree.
    ///
    /// Why a LIST and not just the winner: PoSe bans are consensus-driven and
    /// never appear as a transaction, so apply_block cannot observe one. If
    /// dashd banned the MN at the head of our queue after our snapshot was
    /// taken, dashd's payee is the SECOND entry of OUR queue and the coinbase
    /// cross-check fails. Only the SML carries that ban. Recovering needs the
    /// runners-up, in order, computed on the SAME pre-block state dashd
    /// projects from.
    std::vector<uint256> rank_payee_candidates(size_t k) const
    {
        std::vector<std::pair<int, uint256>> cands;
        if (k == 0) return {};
        cands.reserve(m_entries.size());
        // Defensive: dashd's protx info JSON reports "lastPaidHeight": -1
        // (and PoSeRevivedHeight: -1, PoSeBanHeight: -1) as sentinel for
        // "never paid / never revived / never banned". Snapshots dumped by
        // earlier c2pool versions stored those sentinels as UINT32_MAX
        // (uint32_t wrap of int -1). When cast back to `int` for the
        // CompareByLastPaid_GetHeight scoring, UINT32_MAX → -1, which beats
        // every positive height — the lowest-proTxHash never-paid MN wins
        // forever, producing a constant `expected` across all heights and
        // a 100% [PAY] MISMATCH rate. Normalize here so a buggy in-tree
        // snapshot still produces correct payee selection without re-dump.
        constexpr uint32_t SENTINEL = std::numeric_limits<uint32_t>::max();
        auto sane_height = [](uint32_t v) -> uint32_t {
            return (v == SENTINEL) ? 0u : v;
        };
        for (const auto& [hash, st] : m_entries) {
            if (!st.isValid) continue;
            // Bug 14 guard (see pick_paid_mn): fail-closed on the write-only
            // ban field so a divergent snapshot cannot project a banned MN.
            if (sane_height(st.nPoSeBanHeight) != 0) {
                LOG_INFO << "[MNS] fail-closed: valid MN " << hash.GetHex().substr(0,16)
                         << " carries live PoSe banHeight=" << st.nPoSeBanHeight
                         << " (divergent snapshot) -- excluded from projection";
                continue;
            }
            cands.emplace_back(payee_score(st), hash);
        }
        // dashcore CompareByLastPaid: score ascending, ties broken by
        // proTxHash memcmp ascending (LE-byte, NOT c2pool's CompareTo).
        auto by_last_paid = [](const std::pair<int, uint256>& a,
                               const std::pair<int, uint256>& b) {
            return payee_order_before(a.first, a.second, b.first, b.second);
        };
        if (cands.size() > k) {
            std::partial_sort(cands.begin(), cands.begin() + k, cands.end(),
                              by_last_paid);
            cands.resize(k);
        } else {
            std::sort(cands.begin(), cands.end(), by_last_paid);
        }
        std::vector<uint256> out;
        out.reserve(cands.size());
        for (auto& c : cands) out.push_back(c.second);
        return out;
    }

    std::optional<uint256> find_expected_payee() const
    {
        auto ranked = rank_payee_candidates(1);
        if (ranked.empty()) return std::nullopt;
        return ranked.front();
    }

    // Dump entire current state for persistence (mn_state_db.write_all).
    std::vector<std::pair<uint256, MNState>> snapshot() const
    {
        std::vector<std::pair<uint256, MNState>> out;
        out.reserve(m_entries.size());
        for (const auto& [h, st] : m_entries) {
            out.emplace_back(h, st);
        }
        return out;
    }

    // ─────────────────────────────────────────────────────────────────
    // sync_validity_from_sml — reconcile per-MN liveness from the SML
    // ─────────────────────────────────────────────────────────────────
    //
    // Phase C-PAY Bug 12 fix (2026-05-03), extended by Bug 14 (2026-05-04).
    //
    // **Problem (Bug 12).** PoSe bans aren't tx-driven. Dash Core applies
    // them via consensus rules (CDeterministicMNManager triggers a ban
    // when an MN crosses MAX_PoSe_PENALTY from missed quorums). They
    // never appear as a special tx in any block. So apply_block(), which
    // walks special txs, can never observe them — the MN stays
    // isValid=true in MnStateMachine forever after a real-world ban.
    // find_expected_payee() then deterministically picks that phantom-
    // eligible MN until manually re-snapshotted from RPC.
    //
    // **Problem (Bug 14).** The mirror class on the revive side: when an
    // implicitly-banned MN is later revived by a ProUpServTx, the apply
    // path's revival branch is gated on `nPoSeBanHeight != 0` (mirroring
    // dashcore specialtxman.cpp:361-370). If we never observed the ban
    // (Bug 12 territory), banHeight stays 0 and the gate fails — so
    // nPoSeRevivedHeight stays at its OLD value. find_expected_payee
    // uses max(nLastPaidHeight, nPoSeRevivedHeight) for queue position,
    // so the MN keeps winning as oldest-unpaid until manually reseeded.
    // Live-observed 2026-05-04: MN 13dcc4eb...4e8c, dashd
    // PoSeRevivedHeight=2465346, our state revived=2396789 → 57+ [PAY]
    // MISMATCH all with the same expected= over ~6 hours.
    //
    // **Fix.** The SML feed (Phase C-SML, mnlistdiff p2p messages,
    // root-verified bit-exact against the coinbase's
    // merkleRootMNList) carries the authoritative
    // CSimplifiedMNListEntry::isValid for every active MN. After each
    // successful root MATCH we project that view onto our m_entries.
    // Bug 12 synced isValid alone; Bug 14 extends the contract to the
    // full causally-coupled triple — see "Field-ownership contract"
    // below.
    //
    // **Field-ownership contract** (post-Bug-14):
    //   - SML owns the triple (isValid, nPoSeBanHeight, nPoSeRevivedHeight)
    //     — they're causally one piece of state. SML's isValid is the
    //     boolean projection of dashd's authoritative ban/revive epoch;
    //     when SML flips it we update banHeight + revivedHeight
    //     consistently using current_height as a conservative bound.
    //   - this owns: nLastPaidHeight, nRegisteredHeight, scriptPayout,
    //                collateralOutpoint, nType (timing + identity facets
    //                that are tx-driven and reach us via apply_block)
    //
    // **Sync semantics** (per flip direction):
    //   - false→true (revive): set nPoSeRevivedHeight = max(existing,
    //     current_height) — monotonic, never rolls back; clear
    //     nPoSeBanHeight = 0. After this, apply_block's ProUpServTx
    //     revival branch becomes consistent: the next explicit ProUpServTx
    //     (if any) is a no-op on these fields, not a stale-state trap.
    //   - true→false (ban): set nPoSeBanHeight = current_height ONLY if
    //     not already set (preserve apply_block's exact ban height when
    //     known via tx; SML's view is approximate by ≤ diff cadence).
    //
    // **Why current_height is a safe bound.** SML diffs lag the chain
    // tip by ≤ a small number of blocks (<= the diff request cadence).
    // The actual ban/revive height ≤ current_height always. For the
    // scheduler this means: revivedHeight may be slightly later than
    // chain (worst case: MN gets pushed slightly further back in queue
    // than dashd would — a transient under-payment of 1-2 blocks);
    // banHeight may be slightly later (banned-window length metric is
    // truncated, but ban itself is correctly observed). Both directions
    // are strictly better than the pre-fix behavior of a stuck queue.
    //
    // Idempotent: safe to call after every SML root MATCH (live diff)
    // and once at startup post-load_sml + post-load_into (catches any
    // persisted divergence). O(|SML|) — ~3700 entries on Dash mainnet,
    // microseconds.
    struct SyncFromSmlResult {
        size_t scanned{0};            // SML entries iterated
        size_t matched{0};            // also present in m_entries
        size_t flipped_to_invalid{0}; // m_entries[h].isValid: true → false
        size_t flipped_to_valid{0};   // m_entries[h].isValid: false → true
        size_t revived_height_set{0}; // Bug 14: nPoSeRevivedHeight
                                      // bumped on a flip-to-valid
        size_t ban_height_set{0};     // Bug 14: nPoSeBanHeight set
                                      // on a flip-to-invalid (was 0)
        // SML had it, m_entries didn't. A NO-OP THAT DOES NOT SELF-HEAL.
        //
        // This field used to be commented "apply_block will register on the
        // next ProRegTx for this MN (or the next load() reseed from
        // snapshot)". BOTH of those are FALSE for the case that matters — a
        // masternode PoSe-banned before the set was seeded:
        //   • there is no next ProRegTx. The masternode registered long ago;
        //     ProRegTx is emitted ONCE per registration and will not recur.
        //     Its revive arrives as a ProUpServTx, which apply_block drops
        //     for an unknown proTxHash (revive_dropped_unknown).
        //   • a reseed re-reads the SAME source. If that source was
        //     `protx list valid` it filters the banned masternode out again,
        //     so the reseed reproduces the gap exactly.
        // A comment asserting a recovery that cannot happen is why the gap
        // went unseen; the recovery is SEED COMPLETENESS (seed the REGISTERED
        // set, carrying PoSeBanHeight), not this counter.
        //
        // With a registered-set seed this number is ~0, and a non-zero value
        // is a real anomaly worth reporting — an SML entry we have no record
        // of at all.
        size_t sml_only{0};
    };
    SyncFromSmlResult sync_validity_from_sml(
        const vendor::CSimplifiedMNList& sml,
        uint32_t current_height)
    {
        SyncFromSmlResult r;
        for (const auto& sml_entry : sml.mnList) {
            ++r.scanned;
            auto it = m_entries.find(sml_entry.proRegTxHash);
            if (it == m_entries.end()) {
                ++r.sml_only;
                continue;
            }
            ++r.matched;
            if (it->second.isValid == sml_entry.isValid) continue;

            // Flip detected — apply the (isValid, banHeight,
            // revivedHeight) triple update atomically.
            if (sml_entry.isValid) {
                // false→true (revive): clear ban, bump revivedHeight
                // monotonically. Whether the original ban was tx-driven
                // (we observed it via apply_block's ProUpRevTx /
                // ProUpRegTx-key-change branches) or implicit (Bug 12
                // class — dashd's PoSePenalty consensus rule), the SML
                // flipping back to valid is the authoritative signal
                // that the MN is back. Setting revivedHeight here
                // closes the apply_block-revival-gate hole (Bug 14
                // class) for implicit revivals.
                ++r.flipped_to_valid;
                if (current_height > it->second.nPoSeRevivedHeight) {
                    it->second.nPoSeRevivedHeight = current_height;
                    ++r.revived_height_set;
                }
                it->second.nPoSeBanHeight = 0;
            } else {
                // true→false (ban): record banHeight only if we don't
                // already have one. apply_block sets it precisely when
                // the ban is tx-driven (ProUpRevTx, key-change in
                // ProUpRegTx); SML's current_height is an upper bound
                // for the implicit case. Don't clobber a precise
                // height with our approximation.
                ++r.flipped_to_invalid;
                if (it->second.nPoSeBanHeight == 0) {
                    it->second.nPoSeBanHeight = current_height;
                    ++r.ban_height_set;
                }
            }
            it->second.isValid = sml_entry.isValid;
        }
        return r;
    }

    /// Masternodes that would be projected as payee: valid, with no live PoSe
    /// ban height. This — NOT size() — is the number to compare against
    /// dashd's `protx list valid`. size() counts REGISTERED masternodes, and
    /// the two moving in opposite directions is precisely the defect the
    /// bridge's wholesale sync_validity_from_sml() fold exists to fix.
    size_t eligible_size() const
    {
        constexpr uint32_t SENTINEL = std::numeric_limits<uint32_t>::max();
        size_t n = 0;
        for (const auto& [hash, st] : m_entries) {
            if (!st.isValid) continue;
            const uint32_t ban =
                (st.nPoSeBanHeight == SENTINEL) ? 0u : st.nPoSeBanHeight;
            if (ban != 0) continue;
            ++n;
        }
        return n;
    }

    /// Masternodes PRESENT in the set but payee-INELIGIBLE (PoSe-banned).
    /// size() - eligible_size().
    ///
    /// This exists so a caller can tell "no masternode needed reinstating"
    /// apart from "reinstatement is structurally impossible here". A set
    /// seeded from `protx list valid` carries ZERO ineligible entries — not
    /// because none were banned, but because the banned ones were filtered
    /// out — and in such a set no ProUpServTx revive can ever find an entry
    /// to revive, so a "REINSTATED: 0" is not a measurement.
    size_t ineligible_size() const { return m_entries.size() - eligible_size(); }

    /// What the installed SML hook says about a proTxHash, verbatim (nullopt
    /// = absent from the SML / no hook). Exposed so a caller's fail-closed
    /// diagnostic can NAME the masternode it projected and state whether the
    /// SML considers it valid, instead of listing hypotheses.
    std::optional<bool> sml_opinion(const uint256& h) const
    {
        if (!m_sml_validity) return std::nullopt;
        return m_sml_validity(h);
    }

    /// True when the installed SML is new enough to speak about `height`.
    /// Exposed so a caller's fail-closed diagnostic can say "the SML is
    /// STALE" rather than "the SML had no opinion", which are different
    /// operator actions.
    bool sml_covers(uint32_t height) const
    {
        // Caller never declared a height: pre-gate behaviour, unchanged.
        if (!m_sml_height_known) return true;
        // Declared, but zero — warm restart with no height restored, or a
        // list/height pair that desynchronised. FAIL CLOSED: an undated
        // attestation cannot license a permanent exclusion.
        if (m_sml_height == 0) return false;
        return m_sml_height >= height;
    }

    /// ─────────────────────────────────────────────────────────────────────
    /// readjudicate_payee — the ON-DEMAND arm of the PoSe repair
    /// ─────────────────────────────────────────────────────────────────────
    ///
    /// THE DEFECT THIS CLOSES, measured on mainnet (contabo daemonless soak,
    /// anchor 2513000):
    ///
    ///     h=2513000  protx list valid 2068  projected payee PRESENT   <- fold
    ///     h=2513400                   2068  PRESENT
    ///     h=2513488                   2066  ABSENT   <- PoSe-banned in here
    ///     h=2513489                   2066  ABSENT   <- we projected it anyway
    ///     next scheduled fold point   2513500        <- ELEVEN BLOCKS LATE
    ///
    /// The fold MECHANISM was right; its GRANULARITY was wrong. A ban landing
    /// strictly INSIDE a fold interval is invisible to fold points, and the
    /// reactive walk that does fire at the mismatch was consulting a list up
    /// to `fold_interval - 1` blocks stale.
    ///
    /// Shrinking the interval is the wrong fix twice over: it pays a network
    /// round trip continuously, AND it still leaves a window. Asking AT the
    /// mismatch pays a round trip only when a mismatch actually happens, and
    /// leaves NO window — the list is dated at the very height being judged.
    ///
    /// CONTRACT. `sml` MUST be dated exactly at `height` and MUST already have
    /// been DIP-4 client-verified by the caller (historical_sml.hpp). This
    /// function does not authenticate; it adjudicates. `height` must be the
    /// height of the pending mismatch AND the current apply cursor — both are
    /// checked, and a mismatch on either is a refusal, never an attempt.
    ///
    /// WHY A LIST DATED AT `height` IS THE RIGHT JUDGE. dashd chooses block
    /// H's payee from the list as of H-1, so a masternode banned exactly AT H
    /// would still have been paid at H. We only get here because the projected
    /// masternode was NOT paid, so any ban this list attests for it either
    /// predates H (the case we are repairing) or is simultaneous with H — and
    /// in the simultaneous case the masternode is genuinely out from H onward,
    /// so retiring it with banHeight=H is exactly right for every later block.
    ///
    /// The ACCEPTANCE evidence is unchanged and unrelaxed: the accepted
    /// candidate's scriptPayout must EXACTLY equal an output this block pays.
    /// A better-dated list buys a better attestation; it never buys a guess.
    ///
    /// NO BUDGET IS SPENT. The budgeted walk (recover_from_sml_ban) is bounded
    /// because it acts on the LIVE TIP list — an approximation, dated
    /// elsewhere, that could in principle license a wrong permanent demotion.
    /// This walk acts on a list whose merkle root is committed in the coinbase
    /// of the very block being adjudicated, so the bound that matters is on
    /// the number of ROUND TRIPS, which is the caller's on-demand fold cap.
    /// Charging both would make one legitimate ban cost two budgets.
    ReadjudicateResult readjudicate_payee(const dash::coin::BlockType& block,
                                          uint32_t height,
                                          const vendor::CSimplifiedMNList& sml)
    {
        ReadjudicateResult out;
        if (!m_pending.present) {
            out.refusal = "there is no pending payee mismatch to re-adjudicate";
            return out;
        }
        if (m_pending.height != height) {
            out.refusal = "the pending mismatch is at h="
                        + std::to_string(m_pending.height) + ", not h="
                        + std::to_string(height);
            return out;
        }
        // BACKSTOP, not enforcement. The lane pauses its replay while the
        // request is outstanding, so nothing can move the cursor between the
        // mismatch and this call — and mutation testing agrees: deleting this
        // guard produces no red today. It is kept because the load-bearing
        // pause lives in ANOTHER file, and a future caller that reaches here
        // by a third route must not adjudicate a height it is not standing on.
        if (m_last_applied_height != height) {
            out.refusal = "the apply cursor has moved to h="
                        + std::to_string(m_last_applied_height)
                        + " since the mismatch at h=" + std::to_string(height)
                        + " — refusing to adjudicate a height we are no longer"
                          " standing on";
            return out;
        }
        if (block.m_txs.empty()) {
            out.refusal = "the block carries no coinbase to cross-check against";
            return out;
        }

        // The attestation source for THIS walk is the passed list and nothing
        // else. m_sml_validity (the live tip list) is deliberately not
        // consulted: mixing a tip-dated opinion into a height-exact
        // adjudication would reintroduce the staleness this exists to remove.
        std::map<uint256, bool> attested;
        for (const auto& e : sml.mnList) attested[e.proRegTxHash] = e.isValid;
        auto attest = [&attested](const uint256& h) -> std::optional<bool> {
            auto it = attested.find(h);
            if (it == attested.end()) return std::nullopt;
            return it->second;
        };
        auto paid_in_cb = [&block](const std::vector<unsigned char>& script) {
            if (script.empty()) return false;
            for (const auto& vout : block.m_txs[0].vout)
                if (vout.scriptPubKey.m_data == script) return true;
            return false;
        };

        const WalkOutcome w =
            walk_to_paid_candidate(m_pending.ranked, attest, paid_in_cb);
        if (!w.accepted) {
            out.refusal = std::string("the masternode list dated exactly at h=")
                        + std::to_string(height) + " does not license a repair: "
                        + (w.refusal ? w.refusal : "no candidate accepted");
            return out;
        }

        const std::string demoted_hexes =
            commit_walk_outcome(w, height,
                                [this, height](Entries::iterator it) {
                                    mark_paid_entry(it, height);
                                });
        out.recovered = true;
        out.excluded  = w.demoted.size();
        out.accepted  = w.accepted;
        LOG_WARNING << "[MNS-SM] ON-DEMAND PoSe RE-ADJUDICATION h=" << height
                    << ": projected payee(s) [" << demoted_hexes
                    << "] attested INVALID by the masternode list dated EXACTLY"
                       " at h=" << height << " (DIP-4 client-verified against"
                       " this block's own coinbase commitment) — excluded"
                       " for the rest of this replay with banHeight=" << height
                    << " (REVOCABLE: the entry is KEPT, so a later ProUpServTx"
                       " revive reinstates it — see ApplyResult::revived)"
                    << "; payment attributed to "
                    << out.accepted->GetHex().substr(0, 16)
                    << " whose scriptPayout matches this coinbase exactly. No"
                       " demotion-walk budget was spent: this list is not an"
                       " approximation of the height it judges, it IS that"
                       " height.";
        m_pending = PendingPayeeAdjudication{};
        return out;
    }

    // Process a single block. Mutates state per dashcore's
    // RebuildListFromBlock algorithm. Returns counts for logging.
    ApplyResult apply_block(const dash::coin::BlockType& block,
                            uint32_t height)
    {
        ApplyResult r;

        // ── Pass 0: forward-only guard + payee projection ──────────
        // dashcore connects blocks strictly forward; mirror that here so a
        // duplicated or out-of-order delivery can NEVER mutate this state.
        // (Soak-found 2026-07-22: one extra attribution pass over an
        // already-applied block shifted a shared-payoutAddress group's
        // payment cursor one slot ahead permanently -> intermittent
        // bad-cb-payee on the embedded serve arm.)
        if (m_last_applied_height != 0 && height <= m_last_applied_height) {
            r.skipped_out_of_order = true;
            r.total_after = m_entries.size();
            return r;
        }

        // Forward-CONTIGUITY guard (E4 re-soak fix, shared-address cursor
        // lag): dashcore's BuildNewListFromBlock folds every block in
        // sequence — the payee mark at height N is computed on the list
        // that folded N-1. A gap (height > cursor + 1) means dashd
        // advanced the payment queue at blocks we never saw; folding this
        // block on the stale queue would attribute its payment to an
        // earlier queue slot than dashd did. With shared payout addresses
        // that wrong-specific-MN advance passes the pass-3 script
        // cross-check (same address) and stays silently wrong until an
        // address-group boundary — where the arm serves bad-cb-payee.
        // Refuse the whole apply; the caller fails closed + re-seeds an
        // authoritative snapshot (never guess across a gap).
        if (m_last_applied_height != 0
            && height > m_last_applied_height + 1) {
            r.gap_detected = true;
            r.total_after = m_entries.size();
            LOG_WARNING << "[MNS-SM] PAYEE APPLY GAP: block h=" << height
                        << " on cursor h=" << m_last_applied_height
                        << " (" << (height - m_last_applied_height - 1)
                        << " block(s) never folded) — apply refused"
                           " (fail closed, re-seed required)";
            return r;
        }

        // dashcore BuildNewListFromBlock computes the payee from the
        // PRE-block list (oldList.GetMNPayee(pindexPrev)) BEFORE folding
        // this block's special txs; the mark lands after passes 1/2 (and
        // only if the MN survived them — newList.HasMN). Mirror exactly.
        //
        // We keep the top-K queue, not just the winner. ranked[0] IS what
        // find_expected_payee() returns, so the ordinary path is unchanged;
        // the runners-up exist only for the SML-attested PoSe-ban recovery in
        // pass 3, and are computed HERE, from the PRE-block state, because
        // that is the list dashd projects from.
        const std::vector<uint256> ranked =
            rank_payee_candidates(kPayeeCandidates);
        const std::optional<uint256> projected =
            ranked.empty() ? std::optional<uint256>{}
                           : std::optional<uint256>{ranked.front()};
        r.projected_payee = projected;

        // Past the guards, so this block WILL be applied: any pending
        // re-adjudication belongs to an earlier height and is now unusable
        // (its `ranked` was computed on a list this block is about to change).
        // Dropping it here is what makes pending_payee_adjudication() mean
        // "the cursor is standing on an unresolved mismatch" and nothing else.
        m_pending = PendingPayeeAdjudication{};

        // ── Pass 1: special-tx records ─────────────────────────────
        // Walk all non-coinbase txs (i=1+). The order of types within
        // a block is whatever the miner included; dashcore handles
        // them in tx-list order via the if/else-if chain.
        for (size_t i = 1; i < block.m_txs.size(); ++i) {
            const auto& tx = block.m_txs[i];
            if (tx.type < 1 || tx.type > 4) continue;
            if (tx.extra_payload.empty()) continue;
            switch (tx.type) {
              case 1: { // PROVIDER_REGISTER
                vendor::CProRegTx ptx;
                if (!vendor::parse_protx_payload(tx.extra_payload, ptx)) {
                    LOG_WARNING << "[MNS-SM] CProRegTx parse failed h=" << height;
                    break;
                }
                uint256 proRegTxHash = compute_tx_hash(tx);
                MNState st;
                st.nVersion          = ptx.nVersion;
                st.nType             = ptx.nType;
                st.nRegisteredHeight = height;
                st.nLastPaidHeight   = 0;
                st.isValid           = true;
                // collateralOutpoint resolution: null hash means
                // "this tx's own output at index N is the collateral".
                if (ptx.collateralOutpoint.hash.IsNull()) {
                    st.collateralOutpoint.hash  = proRegTxHash;
                    st.collateralOutpoint.index = ptx.collateralOutpoint.index;
                } else {
                    st.collateralOutpoint = ptx.collateralOutpoint;
                }
                st.keyIDOwner        = ptx.keyIDOwner;
                st.pubKeyOperator    = ptx.pubKeyOperator;
                st.keyIDVoting       = ptx.keyIDVoting;
                st.nOperatorReward   = ptx.nOperatorReward;
                st.scriptPayout.m_data = ptx.scriptPayout.m_data;
                st.netInfo           = ptx.netInfo;
                if (ptx.nType == vendor::MnType::EVO) {
                    st.platformNodeID    = ptx.platformNodeID;
                    st.platformP2PPort   = ptx.platformP2PPort;
                    st.platformHTTPPort  = ptx.platformHTTPPort;
                }
                // Replace any existing MN sharing the same collateral
                // outpoint (external-collateral re-registration case
                // — dashcore specialtxman.cpp:267-279).
                auto coll_it = m_collateral_index.find(st.collateralOutpoint);
                if (coll_it != m_collateral_index.end()) {
                    m_entries.erase(coll_it->second);
                    m_collateral_index.erase(coll_it);
                }
                m_collateral_index[st.collateralOutpoint] = proRegTxHash;
                m_entries.emplace(proRegTxHash, std::move(st));
                ++r.registered;
                break;
              }
              case 2: { // PROVIDER_UPDATE_SERVICE
                vendor::CProUpServTx ptx;
                if (!vendor::parse_protx_payload(tx.extra_payload, ptx)) {
                    LOG_WARNING << "[MNS-SM] CProUpServTx parse failed h=" << height;
                    break;
                }
                auto it = m_entries.find(ptx.proTxHash);
                if (it == m_entries.end()) {
                    // NOT a benign no-op. A ProUpServTx is the ONLY way a
                    // PoSe-banned masternode gets revived, and the only
                    // insertion paths this machine has are the seed and
                    // ProRegTx — neither of which will ever produce an entry
                    // for a masternode that registered long before the seed
                    // and was banned before it. Dropping this silently is how
                    // a seed built from `protx list valid` (which filters
                    // banned masternodes OUT) puts our payment queue
                    // permanently one slot ahead of dashd's. Count it and
                    // NAME it.
                    ++r.revive_dropped_unknown;
                    LOG_WARNING
                        << "[MNS-SM] ProUpServTx h=" << height << " for proTx "
                        << ptx.proTxHash.GetHex().substr(0, 16)
                        << " DROPPED: no entry in this masternode set. If that"
                           " masternode was PoSe-banned when the set was"
                           " seeded, the seed was `valid`-filtered and is"
                           " INCOMPLETE — dashd has just put this masternode"
                           " back in the payment queue and we cannot, so every"
                           " later payee projection is one queue slot ahead."
                           " Re-seed from `protx list registered true` / a"
                           " registered-set checkpoint anchor.";
                    break;
                }
                it->second.netInfo = ptx.netInfo;
                it->second.scriptOperatorPayout.m_data =
                    ptx.scriptOperatorPayout.m_data;
                if (ptx.nType == vendor::MnType::EVO) {
                    it->second.platformNodeID = ptx.platformNodeID;
                    if (ptx.nVersion < vendor::ProTxVersion::EXT_ADDR) {
                        it->second.platformP2PPort  = ptx.platformP2PPort;
                        it->second.platformHTTPPort = ptx.platformHTTPPort;
                    }
                }
                // PoSe revive (dashcore specialtxman.cpp:361-370). This is
                // also what makes every PERMANENT exclusion this machine
                // records REVOCABLE: the demotion walk and the on-demand
                // re-adjudication both retire a masternode by setting a
                // NONZERO banHeight and leaving the entry in place, precisely
                // so this branch can undo it when the chain says so.
                if (it->second.nPoSeBanHeight != 0) {
                    it->second.nPoSeBanHeight   = 0;
                    it->second.nPoSeRevivedHeight = height;
                    it->second.isValid          = true;
                    ++r.revived;
                }
                ++r.updated;
                break;
              }
              case 3: { // PROVIDER_UPDATE_REGISTRAR
                vendor::CProUpRegTx ptx;
                if (!vendor::parse_protx_payload(tx.extra_payload, ptx)) {
                    LOG_WARNING << "[MNS-SM] CProUpRegTx parse failed h=" << height;
                    break;
                }
                auto it = m_entries.find(ptx.proTxHash);
                if (it == m_entries.end()) break;
                bool key_changed = (it->second.pubKeyOperator
                                  != ptx.pubKeyOperator);
                it->second.pubKeyOperator   = ptx.pubKeyOperator;
                it->second.keyIDVoting      = ptx.keyIDVoting;
                it->second.scriptPayout.m_data = ptx.scriptPayout.m_data;
                if (key_changed) {
                    // dashcore: ResetOperatorFields + BanIfNotBanned.
                    it->second.nPoSeBanHeight = height;
                    it->second.isValid        = false;
                }
                ++r.updated;
                break;
              }
              case 4: { // PROVIDER_UPDATE_REVOKE
                vendor::CProUpRevTx ptx;
                if (!vendor::parse_protx_payload(tx.extra_payload, ptx)) {
                    LOG_WARNING << "[MNS-SM] CProUpRevTx parse failed h=" << height;
                    break;
                }
                auto it = m_entries.find(ptx.proTxHash);
                if (it == m_entries.end()) break;
                it->second.nPoSeBanHeight   = height;
                it->second.isValid          = false;
                it->second.nRevocationReason = ptx.nReason;
                // Operator key reset (until a future ProUpServTx
                // provides a new operator key + revives).
                it->second.pubKeyOperator.fill(0);
                ++r.revoked;
                break;
              }
            }
        }

        // ── Pass 2: collateral spends ──────────────────────────────
        // Walk all non-coinbase txs again; for each vin, check if it
        // spends a known MN's collateral. dashcore does this AFTER
        // pass 1 — we mirror.
        for (size_t i = 1; i < block.m_txs.size(); ++i) {
            const auto& tx = block.m_txs[i];
            for (const auto& in : tx.vin) {
                auto it = m_collateral_index.find(in.prevout);
                if (it == m_collateral_index.end()) continue;
                m_entries.erase(it->second);
                m_collateral_index.erase(it);
                ++r.spent;
            }
        }

        // ── Pass 3: payee resolution (PROJECTION, dashd-exact) ─────
        // dashcore evo/deterministicmns.cpp BuildNewListFromBlock: mark the
        // PROJECTED payee (computed pass 0 from the pre-block list), not an
        // MN inferred from scanning coinbase outputs. Observation-based
        // attribution (the pre-2026-07 code) re-derived the paid MN with
        // pick_paid_mn per matching output; that inference is not
        // idempotent under duplicated/replayed applies within a
        // shared-payoutAddress group and once wrong stayed wrong forever
        // (self-perpetuating one-slot-ahead group cursor; soak-found
        // bad-cb-payee at ~10% of embedded serves). The coinbase is now
        // only the CROSS-CHECK: an accepted block by definition pays
        // dashd's projected MN, so if it does not pay OURS, our queue has
        // desynced — report payee_desync, attribute nothing, and let the
        // caller fail closed + re-seed (never guess).
        if (projected && !block.m_txs.empty()) {
            // Exact script-equality against a coinbase output. Reused by the
            // recovery walk below — "the accepted candidate's script matches
            // an output the block actually pays" is the ONLY acceptance
            // evidence, and it is never relaxed to "close enough".
            auto paid_in_cb = [&](const std::vector<unsigned char>& script) {
                if (script.empty()) return false;
                for (const auto& vout : block.m_txs[0].vout) {
                    if (vout.scriptPubKey.m_data == script) return true;
                }
                return false;
            };
            auto mark_paid = [&](Entries::iterator it) {
                mark_paid_entry(it, height);
                ++r.paid;
            };

            auto it = m_entries.find(*projected);
            // Mirrors dashcore's newList.HasMN(payee->proRegTxHash): a
            // payee whose MN was removed by THIS block's passes 1/2 is
            // silently skipped (no mark, no desync).
            if (it != m_entries.end()) {
                if (paid_in_cb(it->second.scriptPayout.m_data)) {
                    mark_paid(it);
                } else if (!recover_from_sml_ban(ranked, height, paid_in_cb,
                                                 mark_paid, r)) {
                    r.payee_desync = true;
                    // Keep the PRE-block queue alive so a caller that goes and
                    // fetches a masternode list dated exactly at this height
                    // can re-adjudicate ONLY this decision, without re-applying
                    // a block the forward-only cursor would refuse.
                    m_pending.present   = true;
                    m_pending.height    = height;
                    m_pending.ranked    = ranked;
                    m_pending.projected = projected;
                    LOG_WARNING << "[MNS-SM] PAYEE DESYNC h=" << height
                                << ": coinbase does not pay projected MN "
                                << projected->GetHex().substr(0, 16)
                                << " — attribution withheld (fail closed)";
                }
            }
        }

        m_last_applied_height = height;
        r.total_after = m_entries.size();
        return r;
    }

private:
    // ─────────────────────────────────────────────────────────────────────
    // recover_from_sml_ban — the ONLY licensed alternative to payee_desync
    // ─────────────────────────────────────────────────────────────────────
    //
    // A PoSe ban is applied by dashd's CDeterministicMNManager from consensus
    // (accumulated MAX_PoSe_PENALTY), never as a special tx. apply_block walks
    // special txs, so it is STRUCTURALLY incapable of seeing one: an MN banned
    // after our snapshot/anchor was taken stays isValid=true in m_entries
    // forever and keeps its place at the head of our payment queue. dashd
    // skipped it; the block pays the NEXT eligible masternode; our pass-3
    // cross-check sees a mismatch and reports payee_desync. On the checkpoint
    // bridge that is terminal, so a single post-anchor ban permanently
    // prevents the daemonless arm from ever publishing a masternode set.
    //
    // The SML is the only carrier of that ban, so it is the only thing that
    // can license a repair. This walk requires, for EVERY step:
    //
    //   * the demoted candidate to be ATTESTED INVALID by the hook. Absent
    //     from the SML is not evidence. Attested valid is counter-evidence
    //     and stops the walk immediately.
    //   * the accepted candidate's scriptPayout to EXACTLY equal an output
    //     the block actually pays. Never a prefix, never an address-family
    //     guess, never "the only unexplained output".
    //
    // If either cannot be satisfied at any step, the walk refuses and the
    // caller reports payee_desync EXACTLY as before. There is no partial
    // outcome: on refusal nothing is mutated.
    //
    // On acceptance the demoted entries are flipped isValid=false with
    // nPoSeBanHeight = height. The exclusion is STANDING — it holds for every
    // later block of the replay — but it is NOT IRREVOCABLE, and the
    // distinction is load-bearing. One-shot exclusion would be strictly
    // wrong: the MN would return to the head of the queue at its next turn
    // (~|MN set| blocks later — ~2068 on DASH mainnet) and desync the replay
    // all over again. Equally, an exclusion that could never be lifted would
    // be wrong in the other direction: the chain revives PoSe-banned
    // masternodes inside a normal bridge window (mainnet e8626fcd… was
    // excluded here and revived by a ProUpServTx at 2515219, well inside the
    // same window). Keeping the ENTRY and marking it with a NONZERO ban
    // height is what satisfies both: pass 1's ProUpServTx revival branch is
    // gated on nPoSeBanHeight != 0, so a genuine revival lifts the exclusion
    // and is counted (ApplyResult::revived). Deleting the entry, or excluding
    // it with banHeight left at 0, would silently make the exclusion
    // permanent in the literal sense.
    //
    // Returns true iff a payment was attributed (r.paid / r.sml_recovered
    // updated); false means "no licensed repair" and the caller must desync.
    /// The WALK ITSELF, with no opinion about where the attestations came
    /// from. Two callers need identical stepping rules and identical refusal
    /// semantics — the budgeted tip-SML walk below, and the on-demand
    /// re-adjudication against a list dated exactly at the height. Two copies
    /// of these rules would be two places for the acceptance evidence to rot.
    ///
    /// Mutates NOTHING. `refusal` names the FIRST rule that stopped it, so a
    /// caller's fail-closed line can say which one rather than listing them.
    struct WalkOutcome {
        std::vector<uint256>   demoted;
        std::optional<uint256> accepted;
        const char*            refusal{nullptr};
    };

    template <typename AttestFn, typename PaidInCbFn>
    WalkOutcome walk_to_paid_candidate(const std::vector<uint256>& ranked,
                                       const AttestFn& attest,
                                       const PaidInCbFn& paid_in_cb) const
    {
        WalkOutcome w;
        if (ranked.size() < 2) {
            w.refusal = "fewer than two payee candidates were ranked, so there"
                        " is no runner-up to attribute the payment to";
            return w;
        }
        for (size_t i = 0; i + 1 < ranked.size(); ++i) {
            const std::optional<bool> att = attest(ranked[i]);
            // nullopt (absent from the list) or true (attested valid): no
            // licence to demote. Stop — this is a real desync.
            if (!att.has_value()) {
                w.refusal = "the list has NO ENTRY for the projected candidate,"
                            " and absent is never evidence of a ban";
                break;
            }
            if (*att) {
                w.refusal = "the list attests the projected candidate VALID —"
                            " that is counter-evidence, not a missed ban";
                break;
            }
            w.demoted.push_back(ranked[i]);

            auto nit = m_entries.find(ranked[i + 1]);
            // The next candidate was removed by THIS block's passes 1/2
            // (collateral spend / re-registration). We cannot test its script
            // and the list cannot attest a departed MN, so refuse rather than
            // skip over it.
            if (nit == m_entries.end()) {
                w.refusal = "the next ranked candidate was removed by this"
                            " block's own special txs / collateral spends, so"
                            " its script cannot be cross-checked";
                break;
            }
            if (paid_in_cb(nit->second.scriptPayout.m_data)) {
                w.accepted = ranked[i + 1];
                w.refusal  = nullptr;
                break;
            }
            // Not paid either — the loop's next iteration must independently
            // earn the right to demote ranked[i+1] too.
        }
        if (!w.accepted && !w.refusal) {
            w.refusal = "no candidate in the ranked queue has a scriptPayout"
                        " this coinbase pays exactly";
        }
        return w;
    }

    /// Commit an accepted WalkOutcome: PERMANENT exclusions with a nonzero ban
    /// height (so the ProUpServTx revival branch stays functional), then the
    /// attribution. Returns the demoted hashes for the log line.
    template <typename MarkPaidFn>
    std::string commit_walk_outcome(const WalkOutcome& w, uint32_t height,
                                    const MarkPaidFn& mark_paid)
    {
        std::string demoted_hexes;
        for (const auto& d : w.demoted) {
            auto dit = m_entries.find(d);
            if (dit != m_entries.end()) {
                dit->second.isValid        = false;
                dit->second.nPoSeBanHeight = height;
            }
            if (!demoted_hexes.empty()) demoted_hexes += ",";
            demoted_hexes += d.GetHex().substr(0, 16);
        }
        auto ait = m_entries.find(*w.accepted);
        if (ait != m_entries.end()) mark_paid(ait);
        return demoted_hexes;
    }

    /// dashcore's payee mark (nLastPaidHeight + the EVO consecutive-payment
    /// counter), shared by every path that attributes a payment.
    void mark_paid_entry(Entries::iterator it, uint32_t height)
    {
        const bool was_consecutive = (it->second.nLastPaidHeight == height - 1);
        it->second.nLastPaidHeight = height;
        if (it->second.nType == vendor::MnType::EVO) {
            it->second.nConsecutivePayments =
                was_consecutive ? it->second.nConsecutivePayments + 1 : 1;
        } else {
            it->second.nConsecutivePayments = 0;
        }
    }

    template <typename PaidInCbFn, typename MarkPaidFn>
    bool recover_from_sml_ban(const std::vector<uint256>& ranked,
                              uint32_t height,
                              const PaidInCbFn& paid_in_cb,
                              const MarkPaidFn& mark_paid,
                              ApplyResult& r)
    {
        if (!m_sml_validity) return false;   // null hook → pre-hook behaviour

        const WalkOutcome w = walk_to_paid_candidate(
            ranked,
            [this, height](const uint256& h) { return sml_attest(h, height); },
            paid_in_cb);
        if (!w.accepted) return false;
        const std::vector<uint256>& demoted = w.demoted;

        // Budget check LAST, so a refusal here mutates nothing either.
        if (m_sml_recovered_total + demoted.size() > m_sml_recovery_cap) {
            LOG_WARNING << "[MNS-SM] SML BAN-RECOVERY REFUSED h=" << height
                        << ": " << demoted.size() << " further exclusion(s) would"
                           " exceed the per-bridge cap of " << m_sml_recovery_cap
                        << " (already used " << m_sml_recovered_total
                        << ") — failing closed instead of overriding the"
                           " projection wholesale";
            return false;
        }

        const std::string demoted_hexes =
            commit_walk_outcome(w, height, mark_paid);
        const std::optional<uint256>& accepted = w.accepted;

        r.sml_recovered        = demoted.size();
        m_sml_recovered_total += demoted.size();
        LOG_WARNING << "[MNS-SM] SML BAN-RECOVERY h=" << height
                    << ": projected payee(s) [" << demoted_hexes
                    << "] attested INVALID by the SML (consensus PoSe ban, not"
                       " tx-visible) — excluded for the rest of this replay"
                       " with banHeight=" << height
                    << " (REVOCABLE: the entry is KEPT, so a later ProUpServTx"
                       " revive reinstates it); payment attributed to "
                    << accepted->GetHex().substr(0, 16)
                    << " whose scriptPayout matches this coinbase exactly"
                       " (bridge total " << m_sml_recovered_total << "/"
                    << m_sml_recovery_cap << ")";
        return true;
    }

    Entries                                                             m_entries;
    std::map<bitcoin_family::coin::TxPrevOut, uint256, TxPrevOutLess>   m_collateral_index;

    // The unresolved mismatch the cursor is standing on, if any. Written by
    // pass 3, cleared by the next apply_block and by a successful
    // readjudicate_payee(). See PendingPayeeAdjudication.
    PendingPayeeAdjudication m_pending;

    // Optional SML attestation hook (see set_sml_validity_fn). NULL by
    // default: no hook, no recovery, byte-identical pre-hook behaviour.
    /// Attestation AS USED BY THE WALK: sml_opinion() narrowed by the
    /// freshness gate. A stale SML is downgraded to "no opinion" per entry,
    /// which is exactly what stops it licensing a permanent demotion.
    std::optional<bool> sml_attest(const uint256& h, uint32_t height) const
    {
        if (!m_sml_validity) return std::nullopt;
        if (!sml_covers(height)) {
            LOG_WARNING << "[MNS-SM] SML CANNOT DATE h=" << height
                        << ": applied SML height="
                        << (m_sml_height == 0 ? std::string("UNKNOWN (warm"
                               " restart with no restored height, or a"
                               " list/height pair that desynchronised)")
                                              : std::to_string(m_sml_height))
                        << " — treating it as NO OPINION (an undated or stale"
                           " ban attestation would license a PERMANENT"
                           " demotion of a since-revived masternode)";
            return std::nullopt;
        }
        return m_sml_validity(h);
    }

    SmlValidityFn m_sml_validity;
    uint32_t      m_sml_height{0};
    bool          m_sml_height_known{false};
    size_t        m_sml_recovery_cap{0};
    size_t        m_sml_recovered_total{0};

    // Forward-only apply cursor: height of the last block folded by
    // apply_block (0 = none since load). See ApplyResult::skipped_out_of_order.
    uint32_t m_last_applied_height{0};

    // Compute a tx's identifying hash. Mirrors dashcore's
    // CTransaction::GetHash() which is SHA256d(serialized_tx).
    // Dash has no segwit so there's no witness/non-witness distinction.
    static uint256 compute_tx_hash(const MutableTransaction& tx)
    {
        ::PackStream s;
        s << tx;
        auto sp = s.get_span();
        uint256 h;
        CHash256()
            .Write(std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(sp.data()), sp.size()))
            .Finalize(std::span<unsigned char>(h.data(), 32));
        return h;
    }
};

} // namespace coin
} // namespace dash