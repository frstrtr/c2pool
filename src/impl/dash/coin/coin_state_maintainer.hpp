// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Phase C-TEMPLATE step 7 (S8 embedded_gbt live-wire, follow-on to #673):
/// the maintainer that POPULATES the node-held NodeCoinState off the
/// reception + think update path, replacing the set_tip-on-demand pattern
/// where a caller poked NodeCoinState::set_tip() directly.
///
/// #672 landed select_dash_work() as the branch point; #673 landed
/// NodeCoinState as the node-held bundle whose populated() flips the hot arm.
/// But #673 left publication to whoever calls set_tip() -- fine for the KAT,
/// wrong for a live node: the tip advances on the header/think path, the MN
/// list advances on the mnlistdiff reception path, and mempool txs arrive on
/// the relay path, all ASYNCHRONOUSLY. The bundle must only go live once the
/// prerequisites the embedded template needs are actually present, else the
/// selector would build a template against a stale/empty MN list.
///
/// CoinStateMaintainer is that ordering gate. It owns no state of its own
/// beyond readiness flags + the last tip params; it drives a NodeCoinState&
/// the node owns. The reception/think slices call the on_*() event methods;
/// the maintainer republishes (calls set_tip) only when BOTH the MN list has
/// been seeded AND a tip has arrived. Until then, and after any invalidating
/// event (reorg / MN-list gap), populated() stays false and select_work()
/// routes to the retained dashd getblocktemplate fallback.
///
/// STRICTLY single-coin: src/impl/dash/coin/ only, no bitcoin_family / src/core
/// reach. The dashd RPC arm is NEVER removed -- it is the always-reachable
/// safety path and the [GBT-XCHECK] cross-check whenever the bundle is not live.

#include <impl/dash/coin/node_coin_state.hpp>    // NodeCoinState
#include <impl/dash/coin/governance_store.hpp>   // GovernanceStore (daemonless superblock)
#include <impl/dash/coin/govsync_status.hpp>     // GovSyncStatus (R5 completeness determination)
#include <impl/dash/coin/governance_object.hpp>  // parse_superblock_trigger, govvote_signature_hash
#include <impl/dash/coin/superblock.hpp>         // get_superblock_payments (R6 cross-check + provider)
#include <impl/dash/coin/mn_state_machine.hpp>   // MNState
#include <impl/dash/coin/block.hpp>            // BlockType
#include <impl/dash/coin/transaction.hpp>        // MutableTransaction
#include <impl/dash/coin/vendor/smldiff.hpp>     // vendor::CSimplifiedMNListDiff + apply_diff
#include <impl/dash/coin/vendor/quorum_tail.hpp> // vendor::parse_quorum_tail
#include <impl/dash/coin/vendor/cbtx.hpp>        // vendor::parse_cbtx (bestCL*/creditPool seed)
#include <impl/dash/coin/credit_pool.hpp>        // CreditPool (independent per-block accrual, E2)
#include <impl/dash/coin/subsidy.hpp>            // compute_dash_platform_reward_post_v20_mn_rr
#include <impl/dash/coin/block_producer.hpp>     // block_body_binds_to_header (E2 finding A body↔header bind)
#include <impl/dash/crypto/hash_x11.hpp>         // dash::crypto::hash_x11 (block identity for the seed)

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/log.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <ctime>
#include <functional>
#include <iterator>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

// ── R3 governance-tally MN resolution (dashcore v23.1.7 parity) ─────────────
//
// Both the vote-VERIFY path (CGovernanceVote::IsValid) and the vote-COUNT path
// (CGovernanceObject::CountMatchingVotes) in dashcore resolve the voting
// masternode with CDeterministicMNList::GetMNByCollateral — the UNFILTERED
// lookup (evo/deterministicmns.h keeps GetValidMNByCollateral as a SEPARATE
// accessor, and governance uses the unfiltered one in both places). So a
// PoSe-BANNED MN's vote still VERIFIES and still COUNTS at its full voting
// weight in dashd. Filtering banned MNs out of the tally here would diverge:
// dropping a banned MN's NO vote inflates (yes − no) in c2pool vs dashd, and
// natural PoSe-ban churn triggers that with no attacker (wrong trigger wins =>
// wrong superblock payees => lost block).
//
// THE ASYMMETRY TO PRESERVE: dashcore's funding THRESHOLD denominator
// (UpdateSentinelVariables: nAbsVoteReq = max(nGovernanceMinQuorum,
// nWeightedMnCount / 10)) uses GetCounts().m_valid_weighted — the VALID set.
// So: per-vote tally UNFILTERED, threshold denominator valid-only. That is
// dashcore's own asymmetry; reseed_funding_threshold() below keeps the
// valid-only denominator and these helpers keep the unfiltered tally.

/// dashcore GetMNByCollateral over the node's live DMN view: UNFILTERED —
/// resolves PoSe-banned entries too. nullptr only when the collateral outpoint
/// is not in the DMN list at all (dashcore then rejects the vote / counts 0).
inline const MNState* gov_mn_by_collateral(
    const MnStateMachine& mns, const bitcoin_family::coin::TxPrevOut& outpoint)
{
    auto pro = mns.find_by_collateral(outpoint);
    if (!pro) return nullptr;
    auto it = mns.entries().find(*pro);
    return it == mns.entries().end() ? nullptr : &it->second;
}

/// dashcore CountMatchingVotes per-vote weight for a stored vote key
/// ("<collateral-txid-hex>-<index>", GovOutPoint::to_key()): EvoNode 4x,
/// Regular 1x, 0 ONLY for an outpoint not in the DMN list (unknown MN). A
/// PoSe-banned MN still weighs in at full weight — see the parity note above.
inline int gov_vote_weight_for_key(const MnStateMachine& mns,
                                   const std::string& key)
{
    const auto dashpos = key.rfind('-');
    if (dashpos == std::string::npos) return 0;
    bitcoin_family::coin::TxPrevOut op;
    op.hash.SetHex(key.substr(0, dashpos));
    try {
        op.index = static_cast<uint32_t>(std::stoul(key.substr(dashpos + 1)));
    } catch (...) { return 0; }
    const MNState* mn = gov_mn_by_collateral(mns, op);
    if (!mn) return 0;
    return (mn->nType == vendor::MnType::EVO) ? DASH_VOTE_WEIGHT_EVO
                                              : DASH_VOTE_WEIGHT_REGULAR;
}

/// Drives a node-owned NodeCoinState from the async update events the running
/// node observes. Non-copyable (holds a reference to the node's holder). The
/// node constructs exactly one, wired to its NodeCoinState member; the
/// reception (mnlistdiff / mempool) and header/think (tip) slices call the
/// on_*() methods as their respective updates land.
class CoinStateMaintainer {
public:
    explicit CoinStateMaintainer(NodeCoinState& state) : m_state(state) {}
    CoinStateMaintainer(const CoinStateMaintainer&) = delete;
    CoinStateMaintainer& operator=(const CoinStateMaintainer&) = delete;

    // ── E-SUPERBLOCK: daemonless governance object/vote ingestion ─────────

    /// The node-owned governance object/vote store (daemonless superblock payee
    /// sourcing). main_dash routes the NodeCoinState superblock provider
    /// through superblock_schedule() below (which folds the desync latch).
    GovernanceStore&       gov_store()       { return m_gov_store; }
    const GovernanceStore& gov_store() const { return m_gov_store; }

    /// Governance chain parameters. `testnet` selects the DASH base58 version
    /// pair the CHAIN-STRICT trigger address decode accepts (a wrong-chain
    /// payee fails the trigger closed — dashd "Invalid Dash Address" parity);
    /// `min_quorum` is chainparams nGovernanceMinQuorum for the funding
    /// threshold (DASH_GOV_MIN_QUORUM_MAINNET / _TESTNET). Until this is set,
    /// min_quorum stays 0 => governance_funding_threshold() yields 0 => the
    /// tally can never trigger (fail closed).
    void set_gov_params(bool testnet, int min_quorum) {
        m_gov_testnet = testnet;
        m_gov_min_quorum = min_quorum;
        reseed_funding_threshold();
    }

    /// Superblock context for the R6 desync cross-check + store pruning:
    /// `is_superblock_fn(height)` — is this height a superblock height (same
    /// predicate NodeCoinState holds); `budget_fn(height)` — the superblock
    /// budget cap in duffs (superblock_budget). Unset (default) => the
    /// cross-check and superblock_schedule() are inert (nullopt => fail
    /// closed), matching the KAT posture.
    void set_superblock_ctx(std::function<bool(uint32_t)> is_superblock_fn,
                            std::function<int64_t(uint32_t)> budget_fn) {
        m_sb_is_fn     = std::move(is_superblock_fn);
        m_sb_budget_fn = std::move(budget_fn);
    }

    /// The daemonless superblock schedule for `height`, folding EVERY local
    /// gate: the R6 desync latch (a proven-wrong governance view must never
    /// serve again until re-proven), the superblock ctx being wired, and
    /// get_superblock_payments' threshold/budget gates. This is what the
    /// NodeCoinState provider closure calls — never reach around it to the
    /// raw store. nullopt => NOT trigger-confident => dashd fallback.
    std::optional<std::vector<SuperblockPayment>>
    superblock_schedule(uint32_t height) const {
        if (m_gov_desync_latched) return std::nullopt;   // R6 latch: fail closed
        if (!m_sb_budget_fn) return std::nullopt;        // ctx not wired
        return get_superblock_payments(
            m_gov_store, static_cast<int32_t>(height), m_sb_budget_fn(height));
    }

    /// R6 desync latch state (observability / tests).
    bool gov_desync_latched() const { return m_gov_desync_latched; }

    // ── R5 govsync-completeness determination ────────────────────────────────
    // Models dashcore CMasternodeSync's governance-phase completion (peer
    // coverage + time-quiescence) — the "is governance synced" gate the
    // NodeCoinState superblock guard consults via set_superblock_sync_complete_fn.
    // Fed from the SAME reception path as the GovernanceStore (on_govobject /
    // on_govvote re-arm quiescence) plus note_govsync_requested from the govsync
    // send site. gov_sync_complete() is the production predicate main_dash wires.

    /// Completeness tunables (main_dash sets these from the deployment; a
    /// single-peer deployment leaves min_peers unmet => permanently INCOMPLETE
    /// => reward-safe dashd fallback). See govsync_status.hpp for the model.
    void set_gov_sync_params(size_t min_peers, int64_t settle_secs,
                             int64_t quiesce_secs) {
        m_gov_sync_status.set_params(min_peers, settle_secs, quiesce_secs);
    }

    /// Override the wall-clock source (default std::time). Tests inject a fake
    /// clock so the settle/quiesce windows are deterministic.
    void set_now_fn(std::function<int64_t()> fn) { m_now_fn = std::move(fn); }

    /// The govsync send site (main_dash) calls this whenever it issues an
    /// MNGOVERNANCESYNC to a peer — records peer coverage + (re)arms quiescence.
    void note_govsync_requested(const std::string& peer_key) {
        m_gov_sync_status.note_govsync_requested(peer_key, m_now_fn());
    }

    /// The production completeness predicate: TRUE only when the daemonless
    /// governance view has provably caught up (peer coverage + settle + quiesce).
    /// Default (nothing synced) => false => superblock heights fail closed.
    bool gov_sync_complete() const {
        return m_gov_sync_status.is_complete(m_now_fn());
    }

    /// Observability handle (logs / tests).
    const GovSyncStatus& gov_sync_status() const { return m_gov_sync_status; }

    /// Vote verification seam — the contract the follow-up implementer MUST
    /// build to (WRONG-SCHEME WARNING: trigger funding votes are NOT
    /// ECDSA/keyIDVoting-signed; that path applies only to PROPOSAL funding
    /// votes — dashcore governance/object.cpp: onlyVotingKeyAllowed =
    /// (type == PROPOSAL && signal == FUNDING)):
    ///   1. Look the voting MN up by its COLLATERAL OUTPOINT in the
    ///      deterministic MN list at verify time (unknown MN => reject) —
    ///      UNFILTERED, dashcore GetMNByCollateral: a PoSe-banned MN's vote
    ///      still verifies (and counts), see gov_mn_by_collateral above. Note
    ///      the DIP-4 SML does not carry collateral outpoints — this needs the
    ///      full DMN view (protx info), see GovernanceStore::set_vote_weight_fn.
    ///   2. BLS-verify vch_sig with the MN's OPERATOR key (pubKeyOperator from
    ///      the DMN state; basic scheme post-v19) over the digest
    ///      govvote_signature_hash(outpoint, parent, outcome, signal, time)
    ///      — dashcore CGovernanceVote::CheckSignature(CBLSPublicKey):
    ///      sig.SetBytes(vchSig, false); sig.VerifyInsecure(pubKey,
    ///      GetSignatureHash(), false). Requires the bls-signatures lib and a
    ///      from-wire vote + operator-key vector pin BEFORE enabling.
    ///   3. Enforce dashcore CGovernanceVote::IsValid's time bound:
    ///      nTime <= now + 60*60 (an hour of clock skew, no more).
    /// UNSET (default) => NO vote is counted => the funding tally stays 0 =>
    /// no trigger ever reaches threshold => the superblock arm FAILS CLOSED to
    /// dashd. This default stands until BLS vote-verify is pinned; nothing in
    /// this file verifies votes today.
    struct GovVoteContext {
        uint256              parent_hash;
        uint256              mn_outpoint_hash;
        uint32_t             mn_outpoint_index{0};
        int32_t              outcome{0};
        int32_t              signal{0};
        int64_t              time{0};
        std::vector<uint8_t> vch_sig;
        uint256              vote_hash;   // govvote_signature_hash (BLS signing digest)
    };
    void set_vote_verifier(std::function<bool(const GovVoteContext&)> fn) {
        m_vote_verifier = std::move(fn);
    }

    /// Reception path (govobj): ingest a governance object. Only TRIGGER objects
    /// (type 2) whose vchData parses as a valid superblock payment schedule are
    /// added to the store; everything else (proposals, malformed triggers) is
    /// dropped. The trigger's payee vector is re-derived from its OWN vchData
    /// (parse_superblock_trigger), never guessed — a parse failure fails closed.
    /// NOTE: wire vchData is the PLAINTEXT JSON bytes (dashcore
    /// GetDataAsPlainString does no hex layer; RPC DataHex is hex OF these
    /// bytes). The parse is CHAIN-STRICT per set_gov_params.
    void on_govobject(const uint256& object_hash, int32_t object_type,
                      const std::vector<uint8_t>& vch_data) {
        // R5: ANY object arrival (trigger, proposal, or malformed) proves the
        // peer is still streaming its set — re-arm the quiescence window BEFORE
        // the type filter, so a stream of proposals still keeps us "mid-sync".
        m_gov_sync_status.note_object_arrival(m_now_fn());
        if (object_type != GOVERNANCE_OBJECT_TRIGGER) return;   // only superblock triggers
        std::string plain(vch_data.begin(), vch_data.end());
        auto trig = parse_superblock_trigger(plain, object_hash, m_gov_testnet);
        if (!trig) return;                                      // malformed → fail closed
        if (!m_gov_store.add_trigger(*trig)) {
            LOG_WARNING << "[GOVSYNC] trigger store FULL ("
                        << m_gov_store.trigger_count()
                        << ") — dropping trigger "
                        << object_hash.GetHex().substr(0, 16);
            return;
        }
        LOG_INFO << "[GOVSYNC] trigger " << object_hash.GetHex().substr(0, 16)
                 << " for superblock h=" << trig->event_block_height << " with "
                 << trig->payments.size() << " payee(s), total="
                 << trig->total_amount() << " duffs";
    }

    /// Reception path (govobjvote): ingest a governance vote. Only FUNDING-signal
    /// votes on a KNOWN trigger are relevant; the vote is counted ONLY if the
    /// verifier confirms its signature — for trigger funding votes that is BLS
    /// by the MN's OPERATOR key (see set_vote_verifier — default UNSET =>
    /// never counted => fail closed).
    void on_govvote(const GovVoteContext& v, const std::string& mn_outpoint_key) {
        // R5: ANY vote arrival re-arms the quiescence window (mid-sync signal),
        // BEFORE the signal/outcome/known-trigger filters below.
        m_gov_sync_status.note_vote_arrival(m_now_fn());
        if (v.signal != VOTE_SIGNAL_FUNDING) return;            // only the superblock tally axis
        // dashcore CGovernanceVote::IsValid outcome range: NONE..ABSTAIN
        // (nVoteOutcome < VOTE_OUTCOME_NONE || >= VOTE_OUTCOME_UNKNOWN =>
        // reject). NONE is a VALID, STORED outcome — a newer NONE vote
        // REPLACES a stored YES in dashd's per-(MN,signal) record, dropping
        // the yes-count. Dropping NONE here would leave a stale YES tallied
        // in c2pool after the voter withdrew it (tally inflation vs dashd).
        if (v.outcome < VOTE_OUTCOME_NONE || v.outcome > VOTE_OUTCOME_ABSTAIN)
            return;
        if (!m_gov_store.has_trigger(v.parent_hash)) return;    // vote for a non-trigger → ignore
        if (!m_vote_verifier || !m_vote_verifier(v)) {
            // Unverified (default) or failed verify: DO NOT count. Fail closed.
            return;
        }
        m_gov_store.add_verified_funding_vote(
            v.parent_hash, mn_outpoint_key, v.outcome, v.time);
    }

    /// Reception path (mnlistdiff): replace the masternode set the embedded
    /// coinbase pays. An EMPTY list is treated as a gap -- it cannot back a
    /// valid payee, so it clears MN-readiness and drops the bundle to fallback
    /// rather than publishing a template with no masternode payment.
    ///
    /// as_of_height (E2c): the chain height the snapshot is CURRENT AT
    /// (0 = unknown). Recorded so on_block_connected() can skip re-applying
    /// blocks the snapshot already reflects -- replaying a historical coinbase
    /// payment on top of an already-current lastPaidHeight set falsely
    /// re-bumps the front of the GetMNPayee queue when several MNs share one
    /// payoutAddress (live-observed: E2b's 288-block UTXO bootstrap replay
    /// scrambled the seeded queue and the embedded template projected the
    /// wrong payee).
    void on_mn_list_update(std::vector<std::pair<uint256, MNState>> mnstates,
                           uint32_t as_of_height = 0) {
        // With the anti-mint latch on, a snapshot with NO height cannot arm
        // MN-readiness either: an unheighted set leaves the apply cursor at 0,
        // which disables apply_block's contiguity guard — the exact condition
        // under which a stale queue advances silently.
        m_have_mn = !mnstates.empty()
                    && (!m_require_seeded_mn || as_of_height != 0);
        m_mn_snapshot_height = as_of_height;
        // An authoritative (non-empty) resync clears the payee-desync latch:
        // the queue is trustworthy again from this snapshot forward.
        if (m_have_mn) {
            m_mn_needs_reseed = false;
            m_state.set_mn_needs_reseed(false);
        }
        // as_of_height also seeds the machine's forward-contiguous apply
        // cursor (E4 re-soak fix): the snapshot IS the payment queue as of
        // that block, so only as_of+1 may fold next; a later block reports
        // gap_detected and on_block_connected fails closed instead of
        // silently advancing a stale queue (blocks mined between the seed
        // fetch and the first live full-block ingest were the soak's
        // 2-slot cursor lag -> bad-cb-payee at the address-group boundary).
        m_state.mnstates().load(std::move(mnstates), as_of_height);
        // Startup / reseed join (2026-07-30): the PAYEE axis was just (re)seeded
        // -- reconcile it against an already-present SML so a warm-loaded or
        // live-advanced SML's authoritative isValid lands on the fresh queue
        // immediately, without waiting for the next mnlistdiff. Handles the
        // seed-arrives-after-SML startup ordering (mirror of the on_mnlistdiff
        // reconcile, which handles SML-arrives-after-seed). No-op when no SML has
        // applied yet (m_have_mn_sml false) or nothing flipped. Height falls back
        // to the seed's as_of_height when no live diff has set m_sml_current_height.
        if (m_have_mn && m_have_mn_sml) {
            const uint32_t vh = m_sml_current_height ? m_sml_current_height
                                                     : as_of_height;
            const auto vr = m_state.mnstates().sync_validity_from_sml(
                m_state.sml(), vh);
            if (vr.flipped_to_invalid || vr.flipped_to_valid)
                LOG_INFO << "[SML->PAYEE] seed reconcile: -"
                         << vr.flipped_to_invalid << " banned +"
                         << vr.flipped_to_valid << " revived @ h=" << vh;
        }
        // BODY-FIRST: an authoritative snapshot loaded as-of the pending tip
        // completes the payee axis — the last promotion precondition when the
        // credit-pool seed already reached the tip (diff-before-seed order).
        const bool promoted = maybe_promote_pending_tip();
        if (!m_have_mn)
            demote();
        else
            republish();
        // The promotion just closed a pending window during which the work
        // source cached a fallback (or old-tip) decision. Re-issue work
        // event-driven — same sink as the body-fold promotion — so the next
        // template request re-evaluates the arm instead of riding the stale
        // cache until an unrelated signal lands.
        if (promoted)
            notify_state_dirty();
    }

    /// Reception path (mnlistdiff, SML axis — DAEMONLESS CCbTx source): apply a
    /// raw deterministic-MN-list diff off the live coin-P2P feed. This is the
    /// consensus-commitment counterpart to on_mn_list_update (which drives the
    /// PAYEE MnStateMachine): it advances the NodeCoinState-held SML
    /// (merkleRootMNList) and QuorumManager (merkleRootQuorums), and seeds the
    /// version-appropriate bestCL*/creditPool from the diff's authoritative
    /// embedded cbTx. All heavy lifting is the already-tested vendor code
    /// (apply_diff / parse_quorum_tail / parse_cbtx) — this method is the wire.
    ///
    /// NOTE (consensus-timing, FLAGGED for byte-parity review): the diff
    /// advances the SML/quorum set to `diff.blockHash`. dashd's GBT for the
    /// NEXT block computes the CbTx roots over the DMN/quorum state AS OF that
    /// next block's connect. Whether requesting mnlistdiff(base, TIP) leaves the
    /// SML at exactly the state dashd commits for TIP+1 is the #1 item the live
    /// byte-parity KAT against a running dashd must confirm; do not assume.
    void on_mnlistdiff(const vendor::CSimplifiedMNListDiff& diff) {
        check_tip_body_overdue();
        // E2 credit-pool persist locals: set when the diff's cbTx re-anchors the
        // pool, flushed (aligned with the SML persist) at the bottom so a restart
        // resumes the credit pool at the SAME tip as SMLDb/QuorumDb.
        bool     cp_seeded  = false;
        int64_t  cp_balance = 0;
        uint32_t cp_height  = 0;

        // H-7 base-continuity: an INCREMENTAL diff is only valid when its
        // baseBlockHash matches the block our SML/quorum state is CURRENT AT.
        // Applying a diff whose base is some other block upserts/erases MN +
        // quorum records relative to a state we are not in — silently corrupting
        // the roots (ghost MNs/quorums). A ZERO base is a full snapshot and
        // always safe (it replaces, not patches). When have_at is ZERO (cold OR
        // post-wipe, review H-1) this ALSO rejects any INCREMENTAL (non-null
        // base): only a full snapshot re-seeds us, so a skipped-delta wipe cannot
        // be papered over by a later clean incremental. Reject + keep prior state.
        const uint256 have_at = m_state.sml_current_hash();
        if (!diff.baseBlockHash.IsNull() && diff.baseBlockHash != have_at) {
            LOG_WARNING << "[SML] REJECT diff: base "
                        << diff.baseBlockHash.GetHex().substr(0, 16)
                        << " != SML-current " << have_at.GetHex().substr(0, 16)
                        << " (base-continuity guard) — awaiting a full/base-matched diff";
            return;
        }

        // #814 review R1 hardening (BLOCK-LOSING without it): a ZERO-base diff
        // REPLACES the whole SML/quorum/credit-pool state — so while we HOLD
        // state, only a genuine FORWARD tip-resync may do that. A stale
        // historical full snapshot (e.g. a duplicate Phase-L member-sourcing
        // reply leaking past the demux, or an unsolicited push from a
        // malicious peer) whose height is at/below the height we are current
        // at must NOT roll the tip state back to a ~10-30-block-old block
        // (wrong merkleRootMNList/merkleRootQuorums on the next template =
        // lost block if won). The snapshot's own authoritative cbTx.nHeight is
        // the freshness key; a full snapshot whose cbTx cannot be parsed while
        // we hold state is equally rejected (cannot prove freshness = fail
        // closed). Cold (have_at ZERO — first sync or post-reorg/heal wipe)
        // stays permissive: that IS the resync this guard must not block.
        if (diff.baseBlockHash.IsNull() && !have_at.IsNull()) {
            std::optional<uint32_t> snap_h;
            if (diff.cbTx.type == 5 && !diff.cbTx.extra_payload.empty()) {
                vendor::CCbTx probe;
                if (vendor::parse_cbtx(diff.cbTx.extra_payload, probe)
                    && probe.nHeight > 0)
                    snap_h = static_cast<uint32_t>(probe.nHeight);
            }
            if (!snap_h || *snap_h <= m_sml_current_height) {
                LOG_WARNING << "[SML] REJECT ZERO-base snapshot @ "
                            << diff.blockHash.GetHex().substr(0, 16)
                            << " (h=" << (snap_h ? static_cast<int64_t>(*snap_h) : -1)
                            << " <= current h=" << m_sml_current_height
                            << ") — stale/unproven full snapshot must not "
                               "replace tip state (review #814 R1)";
                return;
            }
        }

        // review PR #780 H-1 (HIGH): parse the quorum tail FIRST. quorumsdiff
        // deltas are BASE-RELATIVE — if a tail fails to parse (wire-format drift:
        // proto bump / new CFinalCommitment version), skipping its qmgr apply
        // while the SML advances PERMANENTLY loses that delta (the next
        // incremental rides the advanced base), leaving merkleRootQuorums
        // silently wrong forever. Heal it like a quorum-axis reorg: wipe SML +
        // qmgr (on_sml_reorg drops have_sml + resets sml_current_hash=ZERO so the
        // embedded arm fails closed) and force a full-snapshot re-sync via
        // m_on_full_resync (resets the sml_base tracker to ZERO). Do NOT apply
        // this diff's SML — we are discarding it and re-syncing from zero.
        vendor::QuorumTail qt;
        if (!vendor::parse_quorum_tail(diff.quorum_tail, qt)) {
            LOG_WARNING << "[SML] quorum tail parse FAILED (wire-format drift?) "
                           "— wiping SML/quorum state + forcing full re-sync (H-1)";
            m_state.set_quorum_healthy(false);
            on_sml_reorg();               // wipe + demote + notify_state_dirty
            if (m_on_full_resync) m_on_full_resync();
            return;
        }

        // A ZERO-base diff is a FULL snapshot: it must REPLACE the state, not
        // be upserted onto it — an MN deregistered between our held state and
        // the snapshot would otherwise linger as a ghost entry (wrong
        // merkleRootMNList on the next template). Cold/post-wipe states are
        // empty so this is a no-op there; it only matters for the (now
        // R1-guarded) forward full-resync over held state.
        if (diff.baseBlockHash.IsNull()) {
            m_state.sml().mnList.clear();
            m_state.qmgr().clear();
        }

        // 1) SML (merkleRootMNList). apply_diff erases deletedMNs, upserts
        //    diff.mnList, and re-sorts by proRegTxHash (memcmp order — the
        //    Bug-A-critical ordering, already pinned by test_dash_simplifiedmns).
        auto sml_r = vendor::apply_diff(m_state.sml(), diff);
        // F2: the list has just advanced to diff.blockHash UNCONDITIONALLY,
        // but m_sml_current_height advances only if this diff's cbTx parses as
        // a type-5 CCbTx with nHeight > 0 (below). An unparseable cbTx is NOT a
        // rejection — the diff still applies — so the pair (list, height) can
        // silently desynchronise, leaving a consumer folding a list that
        // describes H2 at cursor H1. A peer can trigger that deliberately and
        // choose H1. Break the pairing here and let the height branch below
        // re-establish it; consumers that need the two to agree read
        // sml_height_paired() and treat "unpaired" as "no height at all".
        m_sml_height_paired = false;

        // 2) Quorum set (merkleRootQuorums) — tail already parsed clean above.
        auto qr = m_state.qmgr().apply(qt);
        const size_t q_added = qr.added_or_updated;
        const size_t q_deleted = qr.deleted;
        m_state.set_quorum_healthy(true);

        // 2b) qc-plan-underivable tee: newQuorums are COMPLETE DIP-4
        //     CFinalCommitments (pubkey, vvec hash, quorumSig, membersSig,
        //     bitsets), not just (llmqType, quorumHash) existence — hand them
        //     to the wired consumer (main_dash funnels them through the SAME
        //     MineableCommitmentCache admission path the qfcommit push uses)
        //     instead of dropping the crypto payload on the floor after the
        //     has_mined bookkeeping above. Fired only for an ACCEPTED diff:
        //     every reject/heal path (base-continuity, stale-snapshot R1,
        //     malformed-tail H-1) returned before this point, so a consumer
        //     never sees commitments off a diff whose SML apply was refused.
        //     Optional (unset in KATs = no-op).
        if (m_on_new_quorum_commitments && !qt.newQuorums.empty())
            m_on_new_quorum_commitments(qt.newQuorums);

        // 3) bestCL* + creditPool: the diff's embedded cbTx is the coinbase of
        //    diff.blockHash and its extra_payload is the authoritative type-5
        //    CCbTx for that height. Seed the fields the roots don't carry so the
        //    next template's CCbTx matches dashd. Fails SAFE (leaves prior seed).
        if (diff.cbTx.type == 5 && !diff.cbTx.extra_payload.empty()) {
            vendor::CCbTx observed;
            if (vendor::parse_cbtx(diff.cbTx.extra_payload, observed)) {
                // R1-hardening freshness tracker: the height the SML/quorum
                // state is now current at (authoritative off the diff's own
                // cbTx). Monotone by construction: incrementals ride the
                // base-continuity guard, full snapshots the R1 guard above.
                if (observed.nHeight > 0) {
                    m_sml_current_height =
                        static_cast<uint32_t>(observed.nHeight);
                    // The height now describes THIS list, at this application
                    // point. This is the only place the pair is valid.
                    m_sml_height_paired = true;
                }
                if (observed.nVersion >= vendor::CCbTx::VERSION_CLSIG_AND_BALANCE) {
                    // Seed with the cbTx's OWN nHeight (authoritative off the
                    // wire) as the seed height — the independent freshness key.
                    // When this step is skipped (non-type-5 / parse-fail cbTx) or
                    // the seed does not advance to the tip, the seed height stays
                    // behind m_prev_height and the freshness gate fails closed
                    // instead of committing a lagged creditPoolBalance (soak fix).
                    m_state.set_credit_pool(observed.creditPoolBalance,
                                            diff.blockHash, observed.nHeight);
                    // E2: re-anchor the independent running accrual to this
                    // authoritative snapshot value/height so the per-block advance
                    // (on_block_connected) continues contiguously from here, and
                    // record it for the aligned CreditPoolDb persist below (same
                    // blockHash/height as the SML persist → matching restart tip).
                    m_credit_pool_sm.seed(observed.creditPoolBalance,
                                          static_cast<uint32_t>(observed.nHeight));
                    cp_seeded  = true;
                    cp_balance = observed.creditPoolBalance;
                    cp_height  = static_cast<uint32_t>(observed.nHeight);
                    // bestCLHeightDiff is relative to (cbHeight-1); recover the
                    // absolute best-CL height so the next template re-derives its
                    // own diff against ITS height. Only adopt when the observed
                    // sig is non-null (a real ChainLock for the window).
                    if (observed.has_best_cl_signature()) {
                        int32_t cb_h = observed.nHeight;
                        int32_t best_h = (cb_h - 1)
                            - static_cast<int32_t>(observed.bestCLHeightDiff);
                        // H-7 monotonic-bestCL: only adopt a ChainLock that does
                        // NOT regress our best. A stale/replayed diff carrying an
                        // older bestCL must not roll the committed bestCL* back
                        // (that would desync the next template's CCbTx from dashd).
                        if (best_h > 0 && best_h >= m_state.best_cl_height())
                            m_state.set_best_cl(best_h, observed.bestCLSignature,
                                                ClProvenance::ChainCommitted);
                    }
                    // Record what THIS block's coinbase committed, keyed by its
                    // own on-wire nHeight. Distinct from the "best" above: this
                    // is the term dashcore's CheckCbTxBestChainlock inequality
                    // is stated against (block H-1's committed CL), and it is
                    // recorded even when NULL — "block H-1 committed nothing"
                    // is a legal, constraint-free state, not an absence of
                    // information. See NodeCoinState::set_tip_cbtx_chainlock.
                    m_state.set_tip_cbtx_chainlock(
                        observed.nHeight, observed.has_best_cl_signature(),
                        observed.nHeight - 1
                            - static_cast<int32_t>(observed.bestCLHeightDiff));
                }
            }
        }

        m_have_mn_sml = m_state.sml().size() != 0;
        m_state.set_have_sml(m_have_mn_sml);
        // Record the block the SML is now current at: the freshness gate
        // (NodeCoinState::make_embedded_work_inputs) compares this to the tip
        // we build on, and the next incremental diff's base must match it.
        m_state.set_sml_current_hash(diff.blockHash);
        LOG_INFO << "[SML] applied diff: SML +" << sml_r.added_or_updated
                 << " -" << sml_r.deleted << " => " << m_state.sml().size()
                 << " MNs; quorums +" << q_added << " -" << q_deleted
                 << " => " << m_state.qmgr().active_count()
                 << " active; have_sml=" << (m_have_mn_sml ? "yes" : "no");

        // -- PAYEE-axis validity reconcile (Bug 12/14 wiring, 2026-07-30) ------
        // The SML just advanced and carries the AUTHORITATIVE per-MN isValid.
        // PoSe bans are CONSENSUS-driven, not tx-driven, so apply_block() can
        // NEVER observe them -- the PAYEE MnStateMachine keeps a phantom-eligible
        // banned MN as isValid=true forever and find_expected_payee determinist-
        // ically projects it (daemonless payee-desync, live-observed ~h2513489).
        // sync_validity_from_sml() is the reconciler that fixes exactly this and
        // was DEAD CODE (zero production callers) until this line. It reconciles
        // the BOOLEAN off the freshly-applied SML (ban/revive heights stay SML-
        // approximate, bounded by m_sml_current_height -- see the function's
        // field-ownership contract) and early-continues on entries whose isValid
        // did NOT flip, so queue POSITION for unchanged nodes is never perturbed.
        // Guarded on a non-empty SML (an empty set is a gap, handled below).
        if (m_have_mn_sml) {
            const auto vr = m_state.mnstates().sync_validity_from_sml(
                m_state.sml(), m_sml_current_height);
            if (vr.flipped_to_invalid || vr.flipped_to_valid)
                LOG_INFO << "[SML->PAYEE] validity reconcile: -"
                         << vr.flipped_to_invalid << " banned +"
                         << vr.flipped_to_valid << " revived (scanned "
                         << vr.scanned << ", matched " << vr.matched
                         << ") @ h=" << m_sml_current_height;
        }
        // SML/quorum persistence (SMLDb/QuorumDb): the applied state is now
        // current AT diff.blockHash — flush it so a restart resumes from this
        // tip incrementally instead of a cold mnlistdiff(zero, tip). Only when
        // a non-empty SML actually applied (an empty set is a gap, not a
        // persistable tip). main_dash points this at SMLDb::write_sml +
        // QuorumDb::write_quorums; unset (KAT posture) makes it a no-op.
        if (m_have_mn_sml && m_on_sml_persist)
            m_on_sml_persist(diff.blockHash);
        // E2: persist the credit-pool tip alongside the SML tip (same blockHash +
        // height), so the CreditPoolDb sentinel (cp_hash == sml_hash) holds and a
        // warm restart restores the pool to exactly the SML's resume point. Only
        // when the SML actually applied non-empty (a persistable tip) AND the
        // diff carried a v3+ cbTx seed.
        if (m_have_mn_sml && cp_seeded && m_on_credit_pool_persist)
            m_on_credit_pool_persist(diff.blockHash, cp_height, cp_balance);
        // E-SUPERBLOCK (R4): the SML just changed, so the governance funding
        // threshold changes with it — re-derive max(minQuorum, weighted/10)
        // from the CURRENT weighted MN count on EVERY accepted diff (dashcore
        // recomputes nAbsVoteReq per tally; a one-shot seed would freeze a
        // cold-start 0 forever or drift as the list grows).
        reseed_funding_threshold();
        // BODY-FIRST: a diff whose authoritative cbTx re-anchored the
        // credit-pool seed AT the pending header tip carries the same block
        // inputs a tip-body fold does — promote the serve tip off it (this is
        // the cold-start path: the initial header sync ends at a tip whose
        // body is never inv'd, and the tip-targeted mnlistdiff is what makes
        // it servable).
        maybe_promote_pending_tip();
        if (!m_have_mn_sml)
            demote();
        else
            republish();
        // H-6: the SML just advanced (potentially catching up to a moved tip).
        // Bump work-generation + re-notify so a fresh template is issued now
        // that the freshness gate can pass — otherwise miners stay on the dashd
        // fallback until the next unrelated work signal.
        notify_state_dirty();
    }

    /// Verifier seam for live ChainLock adoption: BLS-verifies a clsig's
    /// recovered threshold signature against the quorum that dashcore's
    /// SelectQuorumForSigning says must have signed it. Installed by main_dash
    /// from chainlock_verify.hpp; UNSET IS FAIL-CLOSED (see on_new_chainlock).
    using ChainLockVerifyFn = std::function<bool(
        int32_t height, const uint256& block_hash,
        const std::array<uint8_t, 96>& sig)>;

    void set_chainlock_verify_fn(ChainLockVerifyFn fn) {
        m_chainlock_verify = std::move(fn);
    }

    /// ChainLock reception: adopt the freshly-observed ChainLock as the best CL
    /// for the CCbTx bestCL* fields. The clsig message carries {height,
    /// block_hash, 96-byte recovered threshold sig}. Only advances forward.
    ///
    /// ⚠ VERIFICATION IS MANDATORY. This value is committed into the coinbase
    /// of every template we then serve (bestCLHeightDiff / bestCLSignature). A
    /// clsig arrives from an arbitrary p2p peer, so adopting one unverified
    /// would let a hostile peer choose our coinbase's ChainLock fields — dashd
    /// would reject the resulting block and we would lose it. When no verifier
    /// is installed, or verification FAILS, we adopt NOTHING and keep the
    /// lagging-but-chain-committed bestCL derived from an observed block's
    /// CCbTx (the pre-existing behaviour) — a refusal costs freshness, an
    /// erroneous acceptance costs a block.
    void on_new_chainlock(int32_t height, const uint256& block_hash,
                          const std::array<uint8_t, 96>& sig) {
        if (height <= m_state.best_cl_height()) return;   // never regress
        if (!m_chainlock_verify) return;                  // no verifier => fail closed
        if (!m_chainlock_verify(height, block_hash, sig)) {
            LOG_WARNING << "[CL] rejected unverified ChainLock height=" << height
                        << " block=" << block_hash.GetHex().substr(0, 16) << "...";
            return;
        }
        // BlsVerified is the ONLY provenance that lets the consensus-exact gate
        // commit a ChainLock NEWER than the one block H-1 committed — that is
        // the case dashcore makes us prove with BLS (specialtxman.cpp:164-167).
        m_state.set_best_cl(height, sig, ClProvenance::BlsVerified);
        LOG_INFO << "[CL] adopted VERIFIED ChainLock height=" << height
                 << " block=" << block_hash.GetHex().substr(0, 16) << "...";
        // A fresher bestCL* changes the next template's committed CCbTx —
        // re-issue work so the served template carries the new ChainLock.
        notify_state_dirty();
    }

    /// Reorg (SML axis): a chain reorganisation can invalidate the incremental
    /// SML/quorum state (the diffs we applied were relative to an orphaned
    /// branch). Wipe the SML + quorum set and drop have_sml so the embedded arm
    /// falls back to dashd until a fresh cold-start mnlistdiff(zero, new-tip)
    /// rebuilds them. main_dash.cpp calls this from the header-chain reorg hook
    /// and then re-requests a full diff. (Distinct from on_invalidate, which
    /// only drops tip-readiness and deliberately KEEPS the MN payee list.)
    void on_sml_reorg() {
        m_state.sml().mnList.clear();
        m_state.qmgr().clear();
        m_have_mn_sml = false;
        m_state.set_have_sml(false);
        // Drop the SML's current-at marker so (a) the freshness gate fails until
        // a fresh cold-start diff lands, and (b) the next diff is accepted as a
        // full snapshot (base-continuity guard treats ZERO current as cold).
        m_state.set_sml_current_hash(uint256::ZERO);
        // Reset the R1 freshness tracker too: post-reorg the new branch's
        // heights may legitimately be at/below the old ones — the cold
        // full-snapshot resync must not be blocked by the stale-guard.
        m_sml_current_height = 0;
        m_sml_height_paired  = false;
        // ── Credit-pool axis: REORG UNDO from the retained full-block buffer ──
        // A reorg whose fork point is still inside the bounded full-block
        // buffer does not need the cold wipe on this axis: the retained
        // fork-point body's OWN coinbase CCbTx carries the creditPoolBalance
        // the chain committed AT that height (an independent, network-accepted
        // value — the same non-self-referential source the per-block advance
        // verifies against). Rolling the pool back to the fork point from that
        // retained body lets the new branch's bodies advance CONTIGUOUSLY and
        // verify, instead of the seed sitting at -1 until the next mnlistdiff
        // re-anchor. The fork point is found by comparing retained body hashes
        // against the NEW branch's height index (the header chain has already
        // switched when this runs). Beyond the buffer — or with the buffer /
        // lookup unwired (KAT posture, dashd-RPC posture) — the existing
        // wipe + cold-resync path below is UNCHANGED.
        // NOTE the deliberate asymmetry: the SML/quorum axis above is still
        // wiped even inside the buffer. Bodies cannot reconstruct the DMN
        // list — a cbTx commits merkleRootMNList, and a root is not a list —
        // so the mnlistdiff cold-resync (one request/response round-trip,
        // re-issued by main_dash's reorg wiring) remains the only sound
        // MN-root recovery.
        bool cp_undone = false;
        if (m_block_buffer_enabled && m_chain_hash_at_height_fn
            && !m_block_buffer.empty()) {
            std::optional<uint32_t> fork_h;
            for (auto it = m_block_buffer.rbegin();
                 it != m_block_buffer.rend(); ++it) {
                auto on_chain = m_chain_hash_at_height_fn(it->first);
                if (on_chain && *on_chain == it->second.hash) {
                    fork_h = it->first;
                    break;
                }
            }
            if (fork_h) {
                // Retained bodies ABOVE the fork point are orphan-branch
                // bodies — drop them (they must never re-seed anything).
                while (!m_block_buffer.empty()
                       && m_block_buffer.rbegin()->first > *fork_h) {
                    m_block_buffer.erase(std::prev(m_block_buffer.end()));
                    ++m_block_buffer_evictions;
                }
                const auto& rb = m_block_buffer.rbegin()->second;
                if (!rb.block.m_txs.empty() && rb.block.m_txs[0].type == 5
                    && !rb.block.m_txs[0].extra_payload.empty()) {
                    vendor::CCbTx cb;
                    if (vendor::parse_cbtx(rb.block.m_txs[0].extra_payload, cb)
                        && cb.nVersion >= vendor::CCbTx::VERSION_CLSIG_AND_BALANCE
                        && cb.nHeight == static_cast<int32_t>(*fork_h)) {
                        m_credit_pool_sm.seed(cb.creditPoolBalance, *fork_h);
                        m_state.set_credit_pool(cb.creditPoolBalance, rb.hash,
                                                static_cast<int32_t>(*fork_h));
                        cp_undone = true;
                        LOG_INFO << "[EMB-DASH] reorg undo: credit pool rolled"
                                    " back to fork point h=" << *fork_h
                                 << " balance=" << cb.creditPoolBalance
                                 << " from retained body (buffer depth="
                                 << m_block_buffer.size()
                                 << ") — no cold credit-pool wipe inside the"
                                    " buffer";
                    }
                }
            }
        }
        if (!cp_undone) {
            // Invalidate the credit-pool seed's freshness (height -1 != any
            // tip), so the arm fails closed on the credit-pool axis until a
            // fresh re-seed.
            m_state.set_credit_pool(0, uint256::ZERO, -1);
            // E2: wipe the independent running accrual as well — its balance
            // was built on the now-orphaned branch. It re-bootstraps from the
            // first post-reorg block's / full-snapshot's authoritative cbTx
            // (never a stale carry-over).
            m_credit_pool_sm.clear();
        }
        // Wipe the PERSISTED SML/quorum stores too. The on-disk state is now for
        // an orphaned branch; it is self-consistent so the root-verify on the
        // next restart WOULD pass and serve a wrong-branch template. Clearing it
        // forces a cold full-snapshot re-sync (main_dash points this at
        // SMLDb::clear + QuorumDb::clear; unset in KATs = no-op).
        if (m_on_sml_clear) m_on_sml_clear();
        // E-SUPERBLOCK (R4): the SML is gone — the funding threshold derived
        // from it is meaningless. Re-seed (=> 0 with an empty list) so no
        // trigger can be considered funded until a fresh SML lands.
        reseed_funding_threshold();
        demote();
        // Re-issue work so miners are moved off any embedded template that was
        // built on the now-orphaned branch onto the dashd fallback immediately.
        notify_state_dirty();
    }

    /// Reception path (mempool relay): fold a relayed tx into the local
    /// mempool. Mempool contents are OPTIONAL for viability -- an empty
    /// mempool yields a valid coinbase-only template -- so this never gates
    /// publication; it only enriches the next assembled template. Returns the
    /// mempool's accept verdict (false = rejected: bad utxo ref / already in).
    bool on_mempool_tx(const MutableTransaction& tx) {
        // Mempool relay is the highest-cadence event through the maintainer,
        // so it doubles as the clock the tip-body-overdue bound is checked on
        // (the maintainer owns no timer; see check_tip_body_overdue).
        check_tip_body_overdue();
        return m_state.mempool().add_tx(tx);
    }

    /// Header / think path: the chain tip advanced. Stash the params the
    /// embedded template needs and mark tip-readiness, then republish if the
    /// MN list is also ready. curtime/version left 0 defer to
    /// build_embedded_workdata()'s own SAFE-ADDITIVE defaults.
    ///
    /// BODY-FIRST SERVE TIP (operator direction off soak0804e / #1089): under
    /// set_body_first_serve_tip(true) this records the HEADER tip only. The
    /// SERVE tip (m_prev_* — the template height and the threshold every
    /// freshness gate compares against) advances ONLY once the block inputs
    /// for this exact tip block have been parsed: the tip body's coinbase
    /// CCbTx folded (on_block_connected) or an authoritative mnlistdiff cbTx
    /// at the tip (on_mnlistdiff). That is dashd's own ordering — its tip
    /// advances after full-block processing — and it removes the
    /// creditpool-stale window as a class: we never DECLARE a tip we cannot
    /// yet serve. Header-tip consumers (stale-work invalidation, job rebuild,
    /// won-block detection, mnlistdiff pull — all wired in main_dash off the
    /// header chain's tip-changed callback) are NOT delayed; only the serve
    /// tip is. Between header and body the arm keeps serving prev=old-tip
    /// work — the same propagation-window behaviour every pool has — named
    /// `tip-body-pending`, which is a NORMAL TRANSIENT, not an error state.
    void on_new_tip(uint32_t prev_height, const uint256& prev_hash,
                    uint32_t bits_for_next, uint32_t mtp_at_tip,
                    uint8_t address_version, uint8_t address_p2sh_version,
                    uint32_t curtime = 0, uint32_t version = 0) {
        m_hdr_prev_height          = prev_height;
        m_hdr_prev_hash            = prev_hash;
        m_hdr_bits_for_next        = bits_for_next;
        m_hdr_mtp_at_tip           = mtp_at_tip;
        m_hdr_address_version      = address_version;
        m_hdr_address_p2sh_version = address_p2sh_version;
        m_hdr_curtime              = curtime;
        m_hdr_version              = version;
        m_have_hdr_tip             = true;
        if (!m_body_first_serve_tip) {
            // Header-first (legacy, DEFAULT): promote immediately —
            // byte-identical to the pre-split behaviour.
            promote_serve_tip();
            republish();
            return;
        }
        // Body-first: a new header tip opens (or re-opens) the body-pending
        // window. A body/diff that already made the credit-pool seed current
        // AT this exact block (body raced ahead of the header event) promotes
        // immediately.
        m_tip_body_pending  = true;
        m_tip_pending_since = m_now_fn();
        m_tip_overdue_latched = false;
        if (maybe_promote_pending_tip()) {
            republish();
            // Promotion is a serve-arm transition, not just a state write: the
            // work source may hold a fallback template cached during the (now
            // closed) pending window. Fire the same event-driven re-issue path
            // the body-fold promotion uses (bump + notify), so the very next
            // template request re-evaluates the arm — without this the stale
            // cached decision keeps serving dashd-fallback until the next
            // unrelated work signal.
            notify_state_dirty();
            return;
        }
        m_state.set_tip_body_pending_dbg(true);
        LOG_INFO << "[EMB-DASH] tip-body-pending h=" << prev_height << " "
                 << prev_hash.GetHex().substr(0, 16)
                 << "... — serve tip holds at "
                 << (m_have_tip ? ("h=" + std::to_string(m_prev_height))
                                : std::string("none"))
                 << " until the tip body folds (normal transient,"
                    " dashd-equivalent propagation window)";
    }

    /// Header / think path (block connect): fold a newly-connected block's
    /// special txs into the DMN list incrementally, mirroring dashcore's
    /// RebuildListFromBlock (MnStateMachine::apply_block). This is the LIVE
    /// driver that keeps the masternode set the embedded coinbase pays current
    /// BETWEEN full mnlistdiff snapshots -- on_mn_list_update() stays the
    /// authoritative resync and is UNCHANGED. MN-readiness is refreshed from
    /// the post-apply list size: a block that empties the set (all collateral
    /// spent) drops the bundle to the dashd fallback rather than backing a
    /// template with a phantom payee. Returns apply_block's ApplyResult.
    MnStateMachine::ApplyResult
    on_block_connected(const dash::coin::BlockType& block, uint32_t height) {
        // EVENT-DRIVEN RESUME (soak0804e, creditpool-stale ~3.3% wall-clock):
        // between the header tip advance (on_new_tip) and this body fold the
        // credit-pool seed is exactly one block behind the tip and the serve
        // gate CORRECTLY refuses (value = threshold-1; consensus demands exact
        // creditPoolBalance equality — dashd specialtxman.cpp:749-755). The
        // ingest was already event-driven, but the RESUME was not: a successful
        // tip-body fold ended in republish() without firing the state-dirty
        // sink, so no work re-issue happened until the next unrelated signal
        // (template request / mnlistdiff / next tip, up to minutes away).
        // Detect the stale->fresh transition on the credit-pool axis — the
        // seed becoming current AT the tip — and fire the same re-issue path
        // every other async advance uses (H-6). Historical window fills advance
        // the seed to heights BELOW the tip and can never fire this, so the
        // E2b bootstrap causes no notify storm. The refusal between
        // tip-advance and body-parse is untouched: this is latency work, the
        // gate itself is not weakened.
        check_tip_body_overdue();
        const bool cp_was_current_at_tip =
            m_have_tip
            && m_state.credit_pool_height() == static_cast<int32_t>(m_prev_height);
        auto r = on_block_connected_impl(block, height);
        // BODY-FIRST serve-tip promotion: if this fold made the credit-pool
        // seed current AT the pending header tip, the serve tip advances NOW —
        // atomically with the credit-pool/MN-root input advance that just
        // happened inside the impl (single-threaded event path; nothing can
        // observe the state between the fold and this promotion). The
        // atomicity invariant this pins: the serve height never exceeds the
        // height whose body has been parsed.
        if (maybe_promote_pending_tip()) {
            republish();
            notify_state_dirty();
            return r;
        }
        const bool cp_now_current_at_tip =
            m_have_tip
            && m_state.credit_pool_height() == static_cast<int32_t>(m_prev_height);
        if (!cp_was_current_at_tip && cp_now_current_at_tip)
            notify_state_dirty();
        return r;
    }

private:
    /// The body of on_block_connected. Reached ONLY through the public wrapper
    /// above (which detects the credit-pool stale->fresh transition around it).
    MnStateMachine::ApplyResult
    on_block_connected_impl(const dash::coin::BlockType& block, uint32_t height) {
        // E2 finding A (reward-critical, defence-in-depth): this component EXTRACTS
        // the reward-critical creditPoolBalance from the block's coinbase, so it
        // validates its own input at the trust boundary. The body↔header binding is
        // the outer wire's job (wire_full_block_ingest), but ANY caller reaching
        // on_block_connected directly (tests / future legs) must not adopt an
        // unbound body. A body whose tx set does not fold to the header's committed
        // merkle root (forged/mutated) is refused: no credit-pool advance, no
        // apply_block, no state change — the prior (valid) seed is retained.
        if (!dash::coin::block_body_binds_to_header(block)) {
            LOG_WARNING << "[CREDITPOOL] on_block_connected h=" << height
                        << " body merkle root != header commitment — REFUSED "
                           "(no advance, no apply_block)";
            MnStateMachine::ApplyResult r;
            r.total_after = m_state.mnstates().size();
            return r;
        }

        // E2 (independent credit-pool advance): fold THIS block's own credit-pool
        // accrual so the DIP-0027 balance tracks the tip on every ingested block,
        // NOT only when the periodic mnlistdiff re-seeds it. This is what lets the
        // freshness gate pass daemonlessly between diffs and — paired with the
        // CreditPoolDb restore in main_dash — on the tip that existed at restart.
        // Runs BEFORE the MN snapshot fence: the credit pool is a distinct axis
        // (asset-lock/unlock + platform-reward), independent of the payee set.
        advance_credit_pool_on_block(block, height);

        // Bounded full-block retention (LTC-style "highest sufficient number
        // of full blocks"): the body is merkle-bound (checked above), so it is
        // eligible for the reorg-undo buffer. No-op unless enabled.
        buffer_insert(block, height);

        // E-SUPERBLOCK (R6): superblock desync cross-check + store pruning —
        // the superblock analogue of the MN payee-desync latch below (#807,
        // block 2508008 class). Runs ONLY at superblock heights (the predicate
        // guard means non-superblock heights can never false-fire) and only
        // when our governance view was trigger-confident for this height: the
        // ingested block's actual coinbase is the network's verdict on the
        // superblock schedule, so every (script, amount) we WOULD have served
        // must appear among its outputs. A mismatch proves our view wrong —
        // NEVER serve from it again: clear the store, latch the desync (only a
        // restart / future re-proof path unlatches), demote to the dashd
        // fallback, and log loudly.
        cross_check_superblock_on_block(block, height);

        // E2c snapshot fence: blocks the payout-bearing snapshot already
        // reflects (height <= its as-of height) must NOT be re-folded -- the
        // snapshot's registrations/spends/lastPaid ARE those blocks' effects,
        // and re-attributing their coinbase payments corrupts the shared-
        // payoutAddress payee queue (see on_mn_list_update). The E2b UTXO
        // lane's own subscription to the same event is unaffected (it needs
        // every block for the UTXO view; it holds no MN state).
        if (m_mn_snapshot_height != 0 && height <= m_mn_snapshot_height) {
            MnStateMachine::ApplyResult r;
            r.total_after = m_state.mnstates().size();
            return r;
        }
        // ── UNSEEDED PAYEE FOLD (soak-found 2026-08-03, phantom-desync class).
        // The payee machine may fold a block ONLY while an authoritative,
        // height-stamped snapshot is in force. Without one it holds no payment
        // queue, so a projection off it is a guess -- precisely what the
        // anti-mint latch below refuses to SERVE, but which was still being
        // COMPUTED, and whose mismatch was then reported as a divergence.
        //
        // MEASURED, three independent runs (contabo soaks 0803c/d/e, started at
        // tips 2515478/2515518/2515558, identical heights every time). In the
        // pure-daemonless posture nothing seeds this machine until
        // MnCheckpointLane publishes. Meanwhile the lane's own request_window()
        // downloads HISTORICAL block bodies from the anchor forward, and both
        // the lane and this maintainer subscribe to the SAME
        // Node::block_connected event -- so those historical bodies were folded
        // in here too. Both of MnStateMachine::apply_block's ordering guards are
        // conditioned on `m_last_applied_height != 0`, so a cold cursor accepts
        // the first body and then rides the window contiguously.
        //
        // The chain did the rest. Block 2513167 carried the first ProRegTx in
        // the window; it registered the ONE entry this set held. Block 2513168
        // projected it -- a one-element queue ranks by nothing, so nRegisteredHeight
        // and payee_score() never entered into it -- the real coinbase paid the
        // real queue head, and that was reported as PAYEE DESYNC. Wipe, demote,
        // and one of only three bridge re-arms spent on a masternode set that
        // never existed. The wipe resets the cursor to 0, re-opening the same
        // hole, so it repeated at the next registration (2513260 -> 2513261) and
        // stopped only when a live tip block pinned the cursor forward and the
        // out-of-order guard began dropping the remaining bodies. Of the nine
        // ProRegTx in 2513001..2515567, both that landed inside the unguarded
        // run mis-scored; the other seven were never applied at all.
        //
        // Refuse the fold, and SAY WHICH refusal this is. "No seed yet" and "the
        // queue diverged from the chain" are opposite conditions -- one is
        // ordinary startup, the other is a defect -- and in the log they were
        // indistinguishable.
        if (m_require_seeded_mn && m_mn_snapshot_height == 0) {
            ++m_unseeded_payee_folds;
            if (m_unseeded_payee_first_h == 0) m_unseeded_payee_first_h = height;
            m_unseeded_payee_last_h = height;
            if (m_unseeded_payee_folds == 1
                || (m_unseeded_payee_folds % 1000) == 0) {
                LOG_INFO
                    << "[EMB-DASH] payee fold SKIPPED at h=" << height
                    << ": no authoritative masternode snapshot is in force"
                       " (snapshot height 0, "
                    << (m_mn_needs_reseed ? "re-seed pending after a wipe"
                                          : "never seeded")
                    << ") — NOT a divergence. An unseeded payee machine has no"
                       " payment queue, so any projection off it would be a"
                       " guess and any mismatch a phantom. "
                    << m_unseeded_payee_folds << " block(s) skipped so far (h="
                    << m_unseeded_payee_first_h << ".." << height
                    << "). Folding resumes when the checkpoint bridge or an RPC"
                       " seed publishes a height-stamped set.";
            }
            MnStateMachine::ApplyResult r;
            r.total_after = m_state.mnstates().size();
            return r;
        }
        auto r    = m_state.mnstates().apply_block(block, height);
        // PAYEE DESYNC (soak-found 2026-07-22, bad-cb-payee class): the
        // connected block's coinbase does not pay the MN our queue projects.
        // The payee set can no longer back a template — serving from it
        // WOULD emit a coinbase dashd rejects with bad-cb-payee. Fail
        // CLOSED: wipe the payee set (a desynced queue must not be trusted
        // for later heights either), drop MN-readiness so get_work() routes
        // to the dashd fallback, and ask main for an authoritative re-seed
        // (protx list) when a coin RPC is configured. The wipe also resets
        // the snapshot fence so the re-seed's as_of re-arms it.
        // PAYEE APPLY GAP (E4 re-soak 2026-07-23, bad-cb-payee at 1519827):
        // one or more blocks between the seed/cursor and this one were never
        // folded (mined during header sync / ingest outage). dashd advanced
        // its payment queue at each of them; ours is now some slots behind,
        // and within a shared-payoutAddress group the divergence is invisible
        // to the coinbase cross-check until it surfaces as a served
        // bad-cb-payee at an address-group boundary. Same fail-closed
        // treatment as a desync: the queue cannot be trusted — wipe, demote,
        // re-seed authoritatively (protx list at the current tip).
        if (r.payee_desync || r.gap_detected) {
            LOG_WARNING << "[EMB-DASH] MN payee queue "
                        << (r.gap_detected ? "APPLY GAP" : "DESYNC")
                        << " at h=" << height
                        << " — wiping payee set, demoting to dashd fallback,"
                           " requesting authoritative re-seed";
            m_state.mnstates().load({});
            m_mn_snapshot_height = 0;
            m_have_mn = false;
            // Latch: only an authoritative on_mn_list_update resync may re-arm
            // MN-readiness. Without this, a stray ProRegTx observed in a later
            // block would register into the wiped set and republish a 1-MN
            // "queue" — a guessed payee by another name.
            m_mn_needs_reseed = true;
            m_state.set_mn_needs_reseed(true);   // MAKE THE STATE SAY ITS NAME
            demote();
            notify_state_dirty();
            if (m_on_mn_reseed) m_on_mn_reseed();
            return r;
        }
        // ANTI-MINT (E2d): with the latch on, block-connect alone can NEVER
        // arm MN-readiness. Absent a seed the payee set starts empty and
        // m_mn_snapshot_height is 0; the first live block carrying a ProRegTx
        // would otherwise register one masternode, flip size() != 0, and let
        // populated() serve a template whose entire "payment queue" is that
        // single accidental registration — a guessed payee, i.e. a coinbase
        // the network rejects. Only an authoritative height-stamped snapshot
        // (the E2c RPC seed or the E2d checkpoint bridge) may arm it.
        m_have_mn = !m_mn_needs_reseed
                    && m_state.mnstates().size() != 0
                    && (!m_require_seeded_mn || m_mn_snapshot_height != 0);
        if (!m_have_mn)
            demote();
        else
            republish();
        return r;
    }

public:
    /// Reorg / MN-list gap / mempool flush: invalidate the live bundle so the
    /// next get_work falls back to dashd until a fresh tip rebuilds it. The
    /// stashed tip params are dropped -- a reorg means the old prev_hash is no
    /// longer the tip, so we must NOT auto-republish it; a subsequent
    /// on_new_tip() re-arms tip-readiness. The MN list (which survives a mere
    /// reorg) is left in place.
    void on_invalidate() {
        m_have_tip = false;
        // Body-first bookkeeping: the header tip we were awaiting a body for
        // is invalidated with everything else; a fresh on_new_tip re-arms.
        m_have_hdr_tip = false;
        m_tip_body_pending = false;
        m_state.set_tip_body_pending_dbg(false);
        demote();
    }

    /// Wire a "state changed, re-issue work" sink (main_dash points this at
    /// DASHWorkSource::bump_work_generation + stratum notify_all). Invoked when
    /// the SML/quorum set advances, the bestCL* moves, or a reorg wipes the
    /// bundle — the events that change (or invalidate) the next served template
    /// but do NOT flow through the header tip-change notify. Optional: unset
    /// (KAT posture) makes every notify_state_dirty() a no-op.
    void set_on_state_dirty(std::function<void()> fn) {
        m_on_state_dirty = std::move(fn);
    }

    /// ANTI-MINT LATCH (E2d, #738). When enabled, MN-readiness requires an
    /// AUTHORITATIVE, HEIGHT-STAMPED snapshot — the E2c `protx list` seed or
    /// the E2d checkpoint bridge — and can never be armed by leg 3
    /// (block-connect) alone.
    ///
    /// The hole this closes only becomes reachable once the arm can run
    /// without a coin RPC. On a cold daemonless start the payee set is empty
    /// and the apply cursor is 0, so apply_block's contiguity guard is
    /// inactive; the first connected block containing a ProRegTx registers
    /// exactly one masternode, mnstates().size() != 0 flips m_have_mn, and
    /// with the tip half already live populated() starts serving templates
    /// whose DIP-3 payment queue is that one accidental registration. dashd
    /// rejects the resulting coinbase (bad-cb-payee) and the block is lost.
    ///
    /// Default OFF so existing construction sites are unaffected; main_dash
    /// turns it on for the whole embedded arm.
    void set_require_seeded_mn_set(bool on) { m_require_seeded_mn = on; }
    bool require_seeded_mn_set() const { return m_require_seeded_mn; }

    /// BODY-FIRST SERVE TIP (operator direction, soak0804e follow-up to
    /// #1089). When enabled, on_new_tip records the HEADER tip only; the
    /// SERVE tip (what m_prev_height / every freshness gate sees) advances
    /// exactly when the block inputs for that tip have been parsed — the tip
    /// body's coinbase folded, or an authoritative mnlistdiff cbTx at the tip
    /// — atomically with the credit-pool advance. Default OFF: every existing
    /// construction site (KATs, the dashd-RPC/ZMQ tip posture, whose tip feed
    /// has NO body feed and would otherwise never promote) keeps byte-
    /// identical header-first behaviour. main_dash enables it for the
    /// coin-P2P daemonless arm, where full bodies demonstrably flow.
    /// REQUIRES the v20+ CCbTx posture (promotion is keyed on the credit-pool
    /// seed becoming current at the tip) — exactly the posture the daemonless
    /// arm already requires for the creditpool freshness gate.
    void set_body_first_serve_tip(bool on) { m_body_first_serve_tip = on; }
    bool body_first_serve_tip() const { return m_body_first_serve_tip; }

    /// Body-first observability (STATE SAYS ITS OWN NAME): is the maintainer
    /// currently holding the serve tip below a known header tip, awaiting the
    /// tip body? TRUE is the normal ~1-2 s propagation transient, never an
    /// error state.
    bool tip_body_pending() const { return m_tip_body_pending; }
    /// The header tip (advances on headers exactly as before) and the serve
    /// tip (advances body-first when enabled). serve <= header always under
    /// body-first — the atomicity invariant.
    uint32_t header_tip_height() const { return m_have_hdr_tip ? m_hdr_prev_height : 0; }
    uint32_t serve_tip_height()  const { return m_have_tip ? m_prev_height : 0; }

    /// How long a body-pending window may last before the serve tip is
    /// DEMOTED instead of continuing to serve old-tip work (the doomed-tip
    /// bound the operator direction names for the lost-body tail: past the
    /// propagation window, prev=old-height work is knowingly doomed and
    /// refusing is safer than serving it). The p2p body-rerequest watchdog
    /// (10 s, up to 4 rotated peers) should resolve a lost body well inside
    /// this. Checked opportunistically on maintainer events (mempool relay is
    /// the high-cadence clock). Overridable for tests.
    void set_tip_body_overdue_secs(int64_t s) { m_tip_body_overdue_secs = s; }

    /// Bounded full-block buffer (LTC-style retention, operator direction):
    /// retain merkle-bound bodies above the last ChainLocked height + margin,
    /// floor 6, cap 24 (~1 h of DASH blocks). ChainLock depth is the
    /// principled reachability cap — nothing at or below a ChainLocked block
    /// can reorg — and DASH ChainLocks normally land within seconds, so the
    /// steady-state depth is the floor. Purpose: reorg undo for the
    /// credit-pool axis without a wipe + cold-resync inside the buffer depth
    /// (see on_sml_reorg); beyond it the existing wipe + reseed path stays.
    /// Default OFF (no retention, no memory cost) — main_dash enables it for
    /// the daemonless arm alongside body-first.
    void set_full_block_buffer(bool on) { m_block_buffer_enabled = on; }
    /// Height -> hash lookup on the CURRENT chain (main_dash wires the header
    /// chain's height index). The reorg-undo fork-point search compares
    /// retained body hashes against it. Unset => undo never fires (existing
    /// wipe path, KAT posture).
    void set_chain_hash_at_height_fn(
        std::function<std::optional<uint256>(uint32_t)> fn) {
        m_chain_hash_at_height_fn = std::move(fn);
    }
    size_t   block_buffer_depth()     const { return m_block_buffer.size(); }
    uint64_t block_buffer_evictions() const { return m_block_buffer_evictions; }
    uint32_t block_buffer_lowest_height() const {
        return m_block_buffer.empty() ? 0 : m_block_buffer.begin()->first;
    }
    uint32_t block_buffer_highest_height() const {
        return m_block_buffer.empty() ? 0 : m_block_buffer.rbegin()->first;
    }

    /// The unseeded-payee-fold guard's own witnesses: how many blocks it
    /// refused to fold because no height-stamped masternode snapshot was in
    /// force, and the height span they covered. A nonzero count during a
    /// checkpoint bridge is EXPECTED and benign — it is the historical block
    /// bodies the bridge is downloading, which belong to the lane's private
    /// replay machine and not to this one.
    size_t   unseeded_payee_folds_skipped() const { return m_unseeded_payee_folds; }
    uint32_t unseeded_payee_first_height()  const { return m_unseeded_payee_first_h; }
    uint32_t unseeded_payee_last_height()   const { return m_unseeded_payee_last_h; }

    /// Height the applied SML/quorum state is current AT (0 = none yet),
    /// tracked off each accepted mnlistdiff's cbTx.nHeight. Read-only;
    /// exposed so the daemonless MN-set bridge can (a) fold the SML's PoSe
    /// verdicts at the ONE cursor position where a wholesale fold is valid,
    /// and (b) refuse a demotion attested by an SML older than the height
    /// being adjudicated. See MnCheckpointLane::maybe_fold_sml().
    uint32_t sml_current_height() const { return m_sml_current_height; }

    /// Whether m_sml_current_height actually describes the SML currently held.
    /// FALSE after a diff advanced the list without a parseable type-5 cbTx to
    /// advance the height with it (F2). A consumer that pairs the two — the
    /// daemonless bridge folds a list AT a height — must treat an unpaired
    /// height as NO height, not as a stale-but-usable one: folding a list that
    /// describes H2 at cursor H1 is the EARLY case, off by H2-H1 blocks, whose
    /// worst outcome is a script-invisible wrong-queue publish.
    bool sml_height_paired() const { return m_sml_height_paired; }

    /// Warm-restart restore (F1). main_dash loads a persisted SML and its
    /// height from SMLDb; without this the height stayed 0 while have_sml()
    /// was true, so every freshness check keyed on it silently passed. Mirrors
    /// restore_credit_pool(), which already exists for the same reason.
    void restore_sml_height(uint32_t h)
    {
        m_sml_current_height = h;
        m_sml_height_paired  = (h != 0);
    }

    /// Wire the authoritative MN re-seed sink (main_dash points this at the
    /// E2c `protx list registered true` seed fetch when a coin RPC is configured).
    /// Invoked from on_block_connected's payee-desync fail-closed path AFTER
    /// the payee set is wiped and the bundle demoted — the arm stays on the
    /// dashd fallback until the re-seed lands via on_mn_list_update. Optional:
    /// unset (KAT posture / pure daemonless) leaves the arm failed closed,
    /// which is the safe terminal state (never serve a guessed payee).
    void set_on_mn_reseed(std::function<void()> fn) {
        m_on_mn_reseed = std::move(fn);
    }

    /// Wire a "force a full mnlistdiff re-sync from ZERO" sink (main_dash resets
    /// the sml_base request tracker to ZERO and re-requests getmnlistd(ZERO,tip)).
    /// Invoked on the H-1 quorum-tail-failure heal path: after wiping the
    /// base-relative state, the next request MUST be a full snapshot so the
    /// skipped delta cannot be silently ridden over. Optional (unset in KATs =
    /// no-op; the wipe + base-continuity guard alone still fail the arm closed).
    void set_on_full_resync(std::function<void()> fn) {
        m_on_full_resync = std::move(fn);
    }

    /// Wire the mnlistdiff QUORUM-COMMITMENT tee (qc-plan-underivable fix).
    /// Invoked from on_mnlistdiff with `tail.newQuorums` of every ACCEPTED
    /// diff — the full CFinalCommitments the wire already carries. main_dash
    /// points this at the MineableCommitmentCache ingest (the SAME admission
    /// path the coin-P2P qfcommit push subscription uses), which removes the
    /// be-connected-at-the-inv transport dependency the push-only feed had:
    /// mnlistdiff is request/response and re-requested on every fresh
    /// handshake, so a commitment missed as a push is still sourced. Optional
    /// (unset in KATs / non-embedded postures = no-op).
    void set_on_new_quorum_commitments(
        std::function<void(const std::vector<vendor::CFinalCommitment>&)> fn) {
        m_on_new_quorum_commitments = std::move(fn);
    }

    /// Wire the SML/quorum PERSISTENCE sink (main_dash points this at
    /// SMLDb::write_sml + QuorumDb::write_quorums). Invoked after each accepted
    /// mnlistdiff that leaves a non-empty SML applied, with the block hash the
    /// state is now current at, so a restart resumes incrementally from that
    /// tip. Optional (unset in KATs = no-op; persistence is a restart
    /// optimisation, never a correctness prerequisite for the running arm).
    void set_on_sml_persist(std::function<void(const uint256&)> fn) {
        m_on_sml_persist = std::move(fn);
    }

    /// Wire the SML/quorum store WIPE sink (main_dash points this at
    /// SMLDb::clear + QuorumDb::clear). Invoked on the reorg / H-1 heal path
    /// where the in-memory state is discarded: the persisted state is now for an
    /// orphaned branch and MUST be wiped so a restart cold-resyncs rather than
    /// loading a self-consistent wrong-branch state. Optional (unset = no-op).
    void set_on_sml_clear(std::function<void()> fn) {
        m_on_sml_clear = std::move(fn);
    }

    /// Wire the credit-pool PERSISTENCE sink (main_dash points this at
    /// CreditPoolDb::write_state). Invoked from on_mnlistdiff after an accepted
    /// diff re-anchors the pool, with the same (blockHash, height) the SML persist
    /// uses so the on-disk credit-pool tip matches SMLDb/QuorumDb exactly (E2).
    /// Optional (unset in KATs = no-op; the running arm never needs persistence).
    void set_on_credit_pool_persist(
        std::function<void(const uint256&, uint32_t, int64_t)> fn) {
        m_on_credit_pool_persist = std::move(fn);
    }

    /// Restore the independent running credit-pool accrual on a warm restart
    /// (main_dash calls this when CreditPoolDb loads a tip matching the SML's).
    /// Seeds the state machine to the persisted balance/height so the first
    /// post-restart block advances contiguously (and verifies against its own
    /// from-wire cbTx) instead of the arm falling back to dashd for the restart
    /// tip. The caller sets the NodeCoinState freshness seed in parallel (E2).
    void restore_credit_pool(int64_t balance, uint32_t height) {
        m_credit_pool_sm.seed(balance, height);
    }

    /// True iff both prerequisites are met AND the holder is currently live.
    bool live() const { return m_state.populated(); }

private:
    void notify_state_dirty() {
        if (m_on_state_dirty) m_on_state_dirty();
    }

    // Block identity hash (Dash: X11 of the 80-byte header). Marks the credit-pool
    // seed as current AT this exact block; cheap (~0.1 ms) and computed off the
    // ingested block, never from any template we built.
    static uint256 block_identity_hash(const dash::coin::BlockType& block) {
        auto packed = ::pack(
            static_cast<const bitcoin_family::coin::BlockHeaderType&>(block));
        return dash::crypto::hash_x11(packed.get_span());
    }

    // E2 — INDEPENDENT per-block credit-pool advance + non-self-referential verify.
    //
    // Every ingested block carries, in its OWN coinbase CCbTx, the creditPoolBalance
    // dashd committed for that height. That is the independent, off-the-wire source
    // of truth. We (a) run our own accrual state machine forward across the block
    // and (b) require the result to equal the block's own committed value. Two
    // independent sources are compared — our recomputation vs dashd's committed
    // value at the same height — NOT a built template against its own seed (the
    // self-consistent-but-stale trap that refuted 3 prior soaks). The seed's height
    // is taken straight off the wire (cbTx.nHeight == connected height, checked),
    // so it can never be mistaken as current at a height we did not observe.
    /// Fold an on-chain coinbase CCbTx into the two bestCL data the template
    /// gate needs. `observed` MUST already have been validated to carry its own
    /// nHeight off the wire (the caller does this).
    ///
    ///  - set_tip_cbtx_chainlock: what THIS block committed, keyed by its own
    ///    height. Recorded even when null — "committed nothing" is a legal
    ///    state that REMOVES the consensus constraint, not missing information.
    ///  - set_best_cl: the value we would ourselves commit next. Tagged
    ///    ChainCommitted: the network accepted this signature inside a block, so
    ///    re-committing it needs no local BLS — the same justification dashd's
    ///    miner relies on (v23.1.7 src/node/miner.cpp:143-146).
    ///
    /// Monotonic on both axes: a late or duplicate OLD block can never roll
    /// either back (a regressed bestCL would desync our CCbTx from dashd's).
    void adopt_chain_committed_chainlock(const vendor::CCbTx& observed) {
        const int32_t committed_cl_h =
            observed.nHeight - 1 - static_cast<int32_t>(observed.bestCLHeightDiff);
        m_state.set_tip_cbtx_chainlock(observed.nHeight,
                                       observed.has_best_cl_signature(),
                                       committed_cl_h);
        if (observed.has_best_cl_signature() && committed_cl_h > 0
            && committed_cl_h >= m_state.best_cl_height())
            m_state.set_best_cl(committed_cl_h, observed.bestCLSignature,
                                ClProvenance::ChainCommitted);
    }

    void advance_credit_pool_on_block(const dash::coin::BlockType& block,
                                      uint32_t height) {
        if (block.m_txs.empty()) return;                 // no coinbase
        const auto& cb = block.m_txs[0];                 // coinbase = tx 0
        if (cb.type != 5 || cb.extra_payload.empty())
            return;                                      // pre-v20 / non-CbTx: leave prior seed
        vendor::CCbTx observed;
        if (!vendor::parse_cbtx(cb.extra_payload, observed)) return;
        if (observed.nVersion < vendor::CCbTx::VERSION_CLSIG_AND_BALANCE) return;
        // Never seed a balance against a height we did not verify off the wire.
        if (observed.nHeight != static_cast<int32_t>(height)) {
            LOG_WARNING << "[CREDITPOOL] block cbTx nHeight " << observed.nHeight
                        << " != connected height " << height
                        << " — skip credit-pool advance";
            return;
        }
        // ── bestCL axis (rides the SAME validated parse; own monotonic guards).
        // This block's coinbase is the authoritative statement of what the
        // chain committed AT this height, and once this height is the tip it is
        // precisely the "previous block's committed ChainLock" that dashcore's
        // CheckCbTxBestChainlock measures our next template against. Recording
        // it here — not only on the far rarer mnlistdiff — is what lets
        // BestClPolicy::ConsensusExact evaluate the real rule every block.
        adopt_chain_committed_chainlock(observed);

        const int64_t from_wire = observed.creditPoolBalance;
        // Network-aware platform-share gate (E4 re-soak fix): the MN_RR
        // activation height is per-chainparams; the state holds the network's
        // value. With the mainnet constant hard-coded here, testnet heights got
        // reward=0, the contiguous advance under-accrued by exactly one block's
        // platform reward, and every block fired ACCRUAL DRIFT + re-seeded.
        const int64_t reward =
            dash::coin::compute_dash_platform_reward_post_v20_mn_rr(
                height, m_state.mn_rr_height());

        // Nit C — monotonic guard: never regress the freshness seed on a
        // duplicate/late OLD block. A contiguous advance is height ==
        // sm.height()+1 and a forward gap is height > sm.height()+1 (both >
        // sm.height()); only height <= sm.height() is a backwards/duplicate
        // delivery — skip it so it cannot roll the seed back to a stale height.
        // (Same-height reorgs are handled by on_sml_reorg's wipe, not here.)
        if (m_credit_pool_sm.initialized()
            && height <= m_credit_pool_sm.height())
            return;

        if (m_credit_pool_sm.initialized()
            && m_credit_pool_sm.height() + 1 == height) {
            // CONTIGUOUS: advance the running accrual by THIS block's own delta
            // (platform reward + Σ assetLocks − Σ assetUnlocks) and cross-check it
            // against the block's OWN committed balance (the independent verify).
            m_credit_pool_sm.apply_block(block, height, reward);
            if (m_credit_pool_sm.balance() != from_wire) {
                // Drift: our model disagrees with the wire. Fail CLOSED — do not
                // advance the freshness seed (get_work falls back to the reward-safe
                // dashd path for this height). Re-anchor the state machine to the
                // authoritative wire value so the next block re-verifies, and surface
                // the drift for soak triage. (Making the advance correct — not
                // relaxing the gate — is the fix if this ever fires.)
                LOG_WARNING << "[CREDITPOOL] ACCRUAL DRIFT h=" << height
                            << " computed=" << m_credit_pool_sm.balance()
                            << " from-wire=" << from_wire
                            << " — freshness seed NOT advanced (fail closed to fallback)";
                m_credit_pool_sm.seed(from_wire, height);
                return;
            }
            // Verified: an independently-confirmed advance to this height.
        } else {
            // NON-CONTIGUOUS (cold / gap / first block post-restart before a diff
            // re-anchor): no running prediction to verify against, so bootstrap
            // directly from the block's own committed balance. Still non-self-
            // referential — value AND height come straight off the wire.
            m_credit_pool_sm.seed(from_wire, height);
        }
        // Advance the freshness seed to THIS block: height == the tip we build the
        // next template on, so the credit-pool freshness gate passes at the right
        // height without waiting for the next mnlistdiff.
        m_state.set_credit_pool(from_wire, block_identity_hash(block),
                                static_cast<int32_t>(height));
    }

    // E-SUPERBLOCK (R4): derive the funding threshold from the CURRENT SML —
    // dashcore UpdateSentinelVariables: nAbsVoteReq = max(nGovernanceMinQuorum,
    // weighted_valid_MN_count / 10), where each valid MN counts at its voting
    // weight (Regular 1, EvoNode 4 — evo/dmn_types.h). Empty list or unset
    // min-quorum (set_gov_params not called) => 0 => fail closed. Called on
    // every accepted mnlistdiff, on SML reorg wipes, and from set_gov_params.
    //
    // NOTE the deliberate ASYMMETRY (dashcore's own, DO NOT "fix"): this
    // DENOMINATOR is computed over the VALID set only (GetCounts()
    // .m_valid_weighted — the `isValid` filter below stays), while the
    // per-vote TALLY resolves voters UNFILTERED (GetMNByCollateral — a
    // PoSe-banned MN's vote still counts; see gov_vote_weight_for_key).
    void reseed_funding_threshold() {
        int weighted = 0;
        for (const auto& e : m_state.sml().mnList) {
            if (!e.isValid) continue;
            weighted += (e.nType == vendor::CSimplifiedMNListEntry::TYPE_EVO)
                            ? DASH_VOTE_WEIGHT_EVO
                            : DASH_VOTE_WEIGHT_REGULAR;
        }
        m_gov_store.set_funding_threshold(
            governance_funding_threshold(weighted, m_gov_min_quorum));
    }

    // E-SUPERBLOCK (R6): superblock desync cross-check (see the call site in
    // on_block_connected for the rationale). Compares the schedule we WOULD
    // have served at `height` against the actual coinbase outputs of the
    // network-accepted block at that height.
    void cross_check_superblock_on_block(const dash::coin::BlockType& block,
                                         uint32_t height) {
        if (!m_sb_is_fn || !m_sb_is_fn(height)) return;   // not a superblock height
        // Resolve our confident view FIRST (superblock_schedule folds the
        // latch + threshold/budget gates), THEN prune the executed cycle.
        auto ours = superblock_schedule(height);
        if (ours && !ours->empty() && !block.m_txs.empty()) {
            const auto& cb = block.m_txs[0];
            bool all_found = true;
            for (const auto& sp : *ours) {
                bool found = false;
                for (const auto& out : cb.vout) {
                    if (out.value == sp.amount &&
                        out.scriptPubKey.m_data.size() == sp.script.size() &&
                        std::equal(sp.script.begin(), sp.script.end(),
                                   out.scriptPubKey.m_data.begin())) {
                        found = true;
                        break;
                    }
                }
                if (!found) { all_found = false; break; }
            }
            if (!all_found) {
                LOG_WARNING << "[GOVSYNC] SUPERBLOCK DESYNC at h=" << height
                            << " — our trigger-confident schedule ("
                            << ours->size() << " payee(s)) does NOT match the "
                               "accepted block's coinbase. Clearing governance "
                               "store + LATCHING the superblock arm closed "
                               "(superblock heights fail to dashd until "
                               "restart); re-issuing work.";
                m_gov_store.clear();
                m_gov_sync_status.reset();   // R5: a proven-wrong view is no
                                             // longer "complete"; force re-sync
                m_gov_desync_latched = true;
                // Transient invalidate + re-issue so any currently-published
                // template is rebuilt. The MN axis is a separate axis — if it
                // is healthy the arm re-publishes for NON-superblock heights;
                // superblock heights stay closed via the latch above
                // (superblock_schedule => nullopt => resolve_superblock
                // refuses => dashd fallback).
                demote();
                notify_state_dirty();
            }
        }
        // The cycle at `height` has executed — dashcore erases executed
        // triggers; prune keeps the store bounded across cycles (F2).
        m_gov_store.prune_executed(static_cast<int32_t>(height));
    }

    // ── BODY-FIRST serve-tip machinery ───────────────────────────────────

    /// Copy the stashed header-tip params into the SERVE slots. In
    /// header-first (legacy) mode this runs inside on_new_tip, byte-identical
    /// to the old direct assignment; in body-first mode it runs only from
    /// maybe_promote_pending_tip().
    void promote_serve_tip() {
        m_prev_height          = m_hdr_prev_height;
        m_prev_hash            = m_hdr_prev_hash;
        m_bits_for_next        = m_hdr_bits_for_next;
        m_mtp_at_tip           = m_hdr_mtp_at_tip;
        m_address_version      = m_hdr_address_version;
        m_address_p2sh_version = m_hdr_address_p2sh_version;
        m_curtime              = m_hdr_curtime;
        m_version              = m_hdr_version;
        m_have_tip             = true;
        m_tip_body_pending     = false;
        m_tip_overdue_latched  = false;
    }

    /// Promote the pending header tip to the serve tip iff the credit-pool
    /// seed is current AT that exact block (hash AND height — the hash match
    /// is what keeps a same-height competing block's body from promoting the
    /// wrong tip's params). The seed is the witness that the tip block's
    /// inputs were parsed: the body fold and the mnlistdiff cbTx re-anchor
    /// both stamp it with the block's own identity. Returns true iff
    /// promotion happened; caller republishes.
    bool maybe_promote_pending_tip() {
        if (!m_body_first_serve_tip || !m_tip_body_pending) return false;
        if (!m_have_hdr_tip) return false;
        if (m_state.credit_pool_current_hash() != m_hdr_prev_hash) return false;
        if (m_state.credit_pool_height()
            != static_cast<int32_t>(m_hdr_prev_height)) return false;
        // The PAYEE axis must be current at the tip too (its cursor advances
        // in the tip-body apply_block, or a snapshot loaded as-of the tip):
        // promoting off a tip-targeted mnlistdiff that outraced the body
        // would advance the serve tip into a payee-stale refusal — trading
        // the removed creditpool-stale window for an identical one on the
        // payee axis. An EMPTY payee machine (pre-seed cold start, post-wipe)
        // has no cursor to be stale and does not hold promotion back — the
        // MN-readiness half of populated() already gates serving there.
        if (!m_state.mnstates().entries().empty()
            && m_state.mnstates().last_applied_height() != m_hdr_prev_height)
            return false;
        promote_serve_tip();
        m_state.set_tip_body_pending_dbg(false);
        LOG_INFO << "[EMB-DASH] serve tip promoted h=" << m_prev_height << " "
                 << m_prev_hash.GetHex().substr(0, 16)
                 << "... (body-first: tip block inputs parsed, credit-pool"
                    " seed current at tip)";
        return true;
    }

    /// Doomed-tip bound: a body-pending window that outlives
    /// m_tip_body_overdue_secs (lost body the p2p watchdog could not recover,
    /// or a credit-pool ACCRUAL DRIFT that blocks the seed) must stop serving
    /// old-tip work — past the propagation window that work is knowingly
    /// doomed, and refusing (dashd fallback / not-populated) is the safe
    /// state. Promotion re-arms the serve tip when the inputs finally land.
    /// The maintainer owns no timer, so this is checked opportunistically on
    /// every maintainer event (mempool relay being the high-cadence clock).
    void check_tip_body_overdue() {
        if (!m_body_first_serve_tip || !m_tip_body_pending) return;
        if (m_tip_overdue_latched) return;
        if (m_now_fn() - m_tip_pending_since < m_tip_body_overdue_secs) return;
        m_tip_overdue_latched = true;
        LOG_WARNING << "[EMB-DASH] tip-body-overdue h=" << m_hdr_prev_height
                    << " pending for "
                    << (m_now_fn() - m_tip_pending_since)
                    << "s (> " << m_tip_body_overdue_secs
                    << "s) — demoting the serve tip: serving h="
                    << m_prev_height << "-based work past the propagation"
                       " window is doomed-tip work; failing closed until the"
                       " tip block's inputs land";
        if (!m_have_tip) return;   // nothing was being served anyway
        m_have_tip = false;
        demote();
        notify_state_dirty();
    }

    /// Bounded full-block retention (see set_full_block_buffer). Called from
    /// on_block_connected_impl AFTER the merkle bind check — only bound
    /// bodies are retained. Retention depth: heights above the last
    /// ChainLocked height + a 2-block margin, clamped to [floor 6, cap 24];
    /// no ChainLock observed => the cap alone bounds it (a ChainLock outage
    /// of ~1 h exhausts the buffer and the wipe path takes over, by design).
    void buffer_insert(const dash::coin::BlockType& block, uint32_t height) {
        if (!m_block_buffer_enabled) return;
        m_block_buffer[height] =
            RetainedBlock{block_identity_hash(block), block};
        ++m_block_buffer_inserts;
        const uint32_t hi = m_block_buffer.rbegin()->first;
        const int32_t  cl = m_state.best_cl_height();
        uint64_t depth_target = kBlockBufferCap;
        if (cl > 0 && static_cast<uint32_t>(cl) <= hi)
            depth_target = static_cast<uint64_t>(hi - static_cast<uint32_t>(cl))
                           + kBlockBufferClMargin;
        depth_target = std::min<uint64_t>(
            std::max<uint64_t>(depth_target, kBlockBufferFloor),
            kBlockBufferCap);
        while (!m_block_buffer.empty()
               && m_block_buffer.begin()->first + depth_target <= hi) {
            m_block_buffer.erase(m_block_buffer.begin());
            ++m_block_buffer_evictions;
        }
        // Periodic depth line (soak-greppable measurement, ~once per cap's
        // worth of inserts ≈ 1 h at steady state).
        if ((m_block_buffer_inserts % kBlockBufferCap) == 1)
            LOG_INFO << "[EMB-DASH] full-block buffer depth="
                     << m_block_buffer.size() << " span=["
                     << m_block_buffer.begin()->first << ".." << hi
                     << "] target=" << depth_target << " cl_h=" << cl
                     << " evictions=" << m_block_buffer_evictions;
    }

    // Publish only when both prerequisites are present; otherwise leave the
    // holder in whatever (un)published state it is in -- callers reach demote()
    // explicitly for the invalidating transitions.
    void republish() {
        // Publish the two publish-preconditions FIRST, whichever way this
        // goes: a refusal that says only "not-populated" cannot tell an
        // operator whether headers are still syncing or the MN set was never
        // seeded, and those need opposite responses.
        m_state.set_populate_inputs(m_have_tip, m_have_mn);
        if (m_have_tip && m_have_mn)
            m_state.set_tip(m_prev_height, m_prev_hash, m_bits_for_next,
                            m_mtp_at_tip, m_address_version, m_address_p2sh_version,
                            m_curtime, m_version);
    }

    void demote() {
        m_state.set_populate_inputs(m_have_tip, m_have_mn);
        if (m_state.populated())
            m_state.invalidate();
    }

    NodeCoinState& m_state;
    GovernanceStore m_gov_store;             // E-SUPERBLOCK: govsync object/vote store
    GovSyncStatus   m_gov_sync_status;       // R5: govsync-completeness determination
    // Wall-clock source for the completeness settle/quiesce windows (default
    // std::time; tests inject a fake clock).
    std::function<int64_t()> m_now_fn{[]() {
        return static_cast<int64_t>(std::time(nullptr));
    }};
    // Vote-verify seam (unset = fail closed). Contract: BLS by the MN's
    // OPERATOR key for trigger funding votes — see set_vote_verifier docs.
    std::function<bool(const GovVoteContext&)> m_vote_verifier;
    bool m_gov_testnet{false};       // chain-strict trigger address decode
    int  m_gov_min_quorum{0};        // chainparams nGovernanceMinQuorum (0 = unset => fail closed)
    bool m_gov_desync_latched{false};// R6: proven-wrong governance view => never serve
    std::function<bool(uint32_t)>    m_sb_is_fn;      // superblock-height predicate (R6)
    std::function<int64_t(uint32_t)> m_sb_budget_fn;  // superblock budget cap (duffs)
    std::function<void()> m_on_state_dirty;  // SML/bestCL/reorg -> re-issue work
    std::function<void()> m_on_mn_reseed;    // payee desync -> authoritative protx re-seed
    std::function<void()> m_on_full_resync;  // H-1 heal -> reset sml_base + full re-sync
    std::function<void(const uint256&)> m_on_sml_persist;  // accepted diff -> SMLDb/QuorumDb write
    std::function<void()> m_on_sml_clear;    // reorg/heal -> SMLDb/QuorumDb wipe (extended to CreditPoolDb)
    // qc-plan-underivable tee: accepted diff's full tail.newQuorums ->
    // MineableCommitmentCache admission (see set_on_new_quorum_commitments).
    std::function<void(const std::vector<vendor::CFinalCommitment>&)>
        m_on_new_quorum_commitments;
    ChainLockVerifyFn     m_chainlock_verify; // unset => live ChainLocks never adopted (fail closed)
    // E2: independent DIP-0027 credit-pool accrual, advanced per ingested block
    // (on_block_connected) and re-anchored per accepted mnlistdiff. Verified
    // against each block's own from-wire cbTx; persisted via the hook below.
    CreditPool m_credit_pool_sm;
    std::function<void(const uint256&, uint32_t, int64_t)> m_on_credit_pool_persist;

    bool m_have_mn{false};
    bool m_have_tip{false};
    bool m_have_mn_sml{false};   // a non-empty SML has been applied (CCbTx source)
    // E2d anti-mint latch — see set_require_seeded_mn_set(). Default FALSE so
    // every existing construction site (the KATs, the dashd-RPC posture) keeps
    // byte-identical behaviour; main_dash opts the embedded arm in.
    bool m_require_seeded_mn{false};

    // Height the SML/quorum state is current at (0 = unknown/cold), tracked
    // off each accepted diff's cbTx.nHeight — the freshness key the #814 R1
    // stale-ZERO-base-snapshot guard compares against.
    uint32_t m_sml_current_height{0};

    // Whether m_sml_current_height describes the SML currently held — see
    // sml_height_paired(). Starts FALSE: a cold maintainer has no height.
    bool m_sml_height_paired{false};

    // Height the last MN-set snapshot was current at (0 = none/unknown);
    // on_block_connected skips re-applying blocks at or below it.
    uint32_t m_mn_snapshot_height{0};

    // Payee-desync latch: set when on_block_connected wiped a desynced payee
    // queue; only a non-empty on_mn_list_update resync clears it. While set,
    // MN-readiness must not re-arm off incidental per-block registrations.
    bool m_mn_needs_reseed{false};

    // Blocks the unseeded-payee-fold guard refused, and the height span they
    // covered. Counted rather than merely skipped so a test can assert the
    // guard FIRED: "no payee desync was reported" is also what a silently
    // broken block_connected subscription produces, and the two must not be
    // the same observation.
    size_t   m_unseeded_payee_folds{0};
    uint32_t m_unseeded_payee_first_h{0};
    uint32_t m_unseeded_payee_last_h{0};

    // SERVE-TIP params, applied on republish(). Under body-first these lag
    // the header tip by the body-pending window; header-first (default)
    // they are assigned directly in on_new_tip via promote_serve_tip().
    uint32_t m_prev_height{0};
    uint256  m_prev_hash;
    uint32_t m_bits_for_next{0};
    uint32_t m_mtp_at_tip{0};
    uint8_t  m_address_version{0};
    uint8_t  m_address_p2sh_version{0};
    uint32_t m_curtime{0};
    uint32_t m_version{0};

    // HEADER-TIP stash (body-first split). Always written by on_new_tip;
    // promoted into the serve slots immediately (header-first) or on the tip
    // block's inputs being parsed (body-first).
    bool     m_have_hdr_tip{false};
    uint32_t m_hdr_prev_height{0};
    uint256  m_hdr_prev_hash;
    uint32_t m_hdr_bits_for_next{0};
    uint32_t m_hdr_mtp_at_tip{0};
    uint8_t  m_hdr_address_version{0};
    uint8_t  m_hdr_address_p2sh_version{0};
    uint32_t m_hdr_curtime{0};
    uint32_t m_hdr_version{0};

    // Body-first mode + pending-window state. Defaults keep every existing
    // construction site byte-identical (header-first).
    bool    m_body_first_serve_tip{false};
    bool    m_tip_body_pending{false};
    bool    m_tip_overdue_latched{false};
    int64_t m_tip_pending_since{0};
    int64_t m_tip_body_overdue_secs{30};

    // Bounded full-block buffer (reorg undo). Keyed by height; hash is the
    // block's own X11 identity, used by the fork-point search.
    struct RetainedBlock {
        uint256 hash;
        dash::coin::BlockType block;
    };
    static constexpr size_t   kBlockBufferFloor    = 6;
    static constexpr size_t   kBlockBufferCap      = 24;   // ~1 h of DASH blocks
    static constexpr uint32_t kBlockBufferClMargin = 2;
    bool m_block_buffer_enabled{false};
    std::map<uint32_t, RetainedBlock> m_block_buffer;
    uint64_t m_block_buffer_inserts{0};
    uint64_t m_block_buffer_evictions{0};
    std::function<std::optional<uint256>(uint32_t)> m_chain_hash_at_height_fn;
};

} // namespace coin
} // namespace dash
