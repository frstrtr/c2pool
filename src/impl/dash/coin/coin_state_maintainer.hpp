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

#include <atomic>                                // std::atomic (dashboard netdiff publish)
#include <impl/dash/coin/node_coin_state.hpp>    // NodeCoinState
#include <impl/dash/coin/sml_resync_watchdog.hpp> // SmlResyncWatchdog (bounded getmnlistd re-request)
#include <impl/dash/coin/governance_store.hpp>   // GovernanceStore (daemonless superblock)
#include <impl/dash/coin/govsync_status.hpp>     // GovSyncStatus (R5 completeness determination)
#include <impl/dash/coin/governance_object.hpp>  // parse_superblock_trigger, govvote_signature_hash
#include <impl/dash/coin/superblock.hpp>         // resolve_superblock_payments (tri-state verdict, R6/C5 cross-check)
#include <impl/dash/coin/deployment_status.hpp>  // V24State (R6 v24-strict payment matching)
#include <impl/dash/coin/vendor/masternode_payments.hpp> // C5: GetBlockTxOutsForPayee (MN-derived block value)
#include <impl/dash/coin/mn_state_machine.hpp>   // MNState
#include <impl/dash/coin/mn_gap_repair.hpp>      // MnGapRepairFn (diff-store gap repair seam)
#include <impl/dash/coin/lane_diag.hpp>          // diag::MnSource (population attribution)
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
#include <core/inject_ledger_obs.hpp>          // core::obs::best_chainlock (read-only mirror)

#include <algorithm>
#include <array>
#include <cstdint>
#include <ctime>
#include <deque>
#include <functional>
#include <iterator>
#include <map>
#include <optional>
#include <set>
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

/// RemoveInvalidVotes parity seam (MED-4): fingerprint (SHA256d) of the
/// CURRENT operator key of the masternode behind a stored vote key, nullopt
/// when it is not in the DMN list (UNFILTERED lookup, as the tally). A stored
/// trigger funding vote counts only while this still equals the fingerprint
/// it verified under — dashd drops it when the key changes or the MN leaves
/// (governance.cpp:1180-1226, votedb.cpp:81-101).
inline std::optional<uint256> gov_operator_fp_for_key(const MnStateMachine& mns,
                                                      const std::string& key)
{
    const auto dashpos = key.rfind('-');
    if (dashpos == std::string::npos) return std::nullopt;
    bitcoin_family::coin::TxPrevOut op;
    op.hash.SetHex(key.substr(0, dashpos));
    try {
        op.index = static_cast<uint32_t>(std::stoul(key.substr(dashpos + 1)));
    } catch (...) { return std::nullopt; }
    const MNState* mn = gov_mn_by_collateral(mns, op);
    if (!mn) return std::nullopt;
    return ::Hash(std::span<const unsigned char>(mn->pubKeyOperator.data(),
                                                 mn->pubKeyOperator.size()));
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

    /// The block hash the applied SML cursor is actually current at — the ONE
    /// source of truth for the getmnlistd request base. on_mnlistdiff advances
    /// this (via set_sml_current_hash) only after an accepted, base-contiguous
    /// apply (:719); on_sml_reorg zeroes it (:865). The tip-advance and
    /// handshake send paths request base = this hash so base -> target is always
    /// contiguous with what the SML has actually applied: an overlapping,
    /// leaked, or base-rejected reply can never strand the request base ahead of
    /// the cursor (the reception-time tracker's failure mode). Passthrough to
    /// NodeCoinState::sml_current_hash().
    const uint256& sml_current_hash() const { return m_state.sml_current_hash(); }

    // ── E-SUPERBLOCK: daemonless governance object/vote ingestion ─────────

    /// The node-owned governance object/vote store (daemonless superblock payee
    /// sourcing). main_dash routes the NodeCoinState superblock resolver
    /// through superblock_resolution() below (which folds every local gate).
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
    /// cross-check is inert and every verdict is Unknown (fail closed),
    /// matching the KAT posture.
    void set_superblock_ctx(std::function<bool(uint32_t)> is_superblock_fn,
                            std::function<int64_t(uint32_t)> budget_fn) {
        m_sb_is_fn     = std::move(is_superblock_fn);
        m_sb_budget_fn = std::move(budget_fn);
    }

    /// C4: chainparams nSuperblockMaturityWindow (Dash Core v24
    /// chainparams.cpp: mainnet 1662, testnet 8). Two legs per superblock H:
    ///   A  tip == H - window (masternodes start creating triggers for H —
    ///      governance/signing.cpp CreateSuperblockCandidate): per-trigger vote
    ///      re-sync for every trigger held at H;
    ///   B  tip == H - late_lead() (= max(3, window/8): testnet H-3, mainnet
    ///      H-207): a FRESH nProp=0 re-prime of every peer (the coin-P2P
    ///      client enforces its once-per-hour-per-peer window), which re-opens
    ///      every peer's coverage proof, plus the vote re-sync again. Leg B is
    ///      deliberately NOT H-1: the vote burst it triggers re-arms R5
    ///      quiescence, and the proof must re-close before H's template.
    /// 0 (default) disables both legs.
    void set_superblock_maturity_window(int32_t w) { m_sb_maturity_window = w > 0 ? w : 0; }
    int32_t late_lead() const {
        return m_sb_maturity_window > 0 ? std::max<int32_t>(3, m_sb_maturity_window / 8) : 0;
    }

    /// Leg B re-prime seam (main_dash: CoinClient::send_govsync_prime() and
    /// note_govsync_requested for every peer actually primed). Never sent
    /// more than once per hour per peer; never the per-object vote sync.
    void set_on_gov_reprime(std::function<void()> fn) { m_on_gov_reprime = std::move(fn); }

    /// MAINNET GATE. The NotTriggered verdict (serve a normal coinbase at a
    /// superblock height) is OFF unless explicitly enabled: on mainnet it
    /// stays off unless the operator passes the explicit opt-in flag; testnet
    /// enables it. Disabled => a proven-unfunded height is still Unknown
    /// ("not-triggered-disabled") and refuses, exactly master's behaviour.
    void set_not_triggered_enabled(bool v) { m_not_triggered_enabled = v; }
    bool not_triggered_enabled() const { return m_not_triggered_enabled; }

    /// "Our DMN view has folded the serve tip" — after a startup window in
    /// which every signature was CannotVerify, held trigger records without a
    /// buffered object are re-fetched by hash once this turns true.
    void set_gov_view_current_fn(std::function<bool()> fn) { m_gov_view_current_fn = std::move(fn); }

    /// C4 seams (main_dash wires both to the coin-P2P client):
    ///   vote_resync(hash)  — per-object vote sync (MNGOVERNANCESYNC nProp=hash
    ///                        with a NON-empty filter; v24 net_governance.cpp
    ///                        116-162). Never the nProp=0 full sync.
    ///   object_fetch(hash) — fetch a missing parent object (MNGOVERNANCESYNC
    ///                        nProp=hash, EMPTY filter — dashd's own orphan-vote
    ///                        parent request, net_governance.cpp:47-61/258-265).
    /// Unset => nothing is sent (the KAT posture).
    void set_on_trigger_vote_resync(std::function<void(const uint256&)> fn) {
        m_on_vote_resync = std::move(fn);
    }
    void set_on_gov_object_fetch(std::function<void(const uint256&)> fn) {
        m_on_object_fetch = std::move(fn);
    }

    /// The daemonless superblock VERDICT for `height`, folding EVERY local
    /// gate: the R6 desync latch (a proven-wrong governance view never serves
    /// again until restart), the superblock ctx being wired, the vote-backlog
    /// overflow, and resolve_superblock_payments (threshold, outstanding
    /// objects, unverified votes, budget, C1 strict absence, R5 completeness
    /// for the unfunded verdict). This is what the NodeCoinState resolver
    /// closure calls — never reach around it to the raw store.
    SuperblockResolution superblock_resolution(uint32_t height) const {
        auto r = resolve_at(height, gov_sync_complete());
        if (r.verdict == SuperblockVerdict::NotTriggered) {
            if (!m_not_triggered_enabled)
                return SuperblockResolution::unknown("not-triggered-disabled");
            m_sb_not_triggered_served.store(height, std::memory_order_relaxed);
        }
        return r;
    }

    /// Optional-vector view of superblock_resolution: the winning schedule
    /// (Triggered), {} (NotTriggered — a normal coinbase), nullopt (Unknown).
    std::optional<std::vector<SuperblockPayment>>
    superblock_schedule(uint32_t height) const {
        auto r = superblock_resolution(height);
        switch (r.verdict) {
            case SuperblockVerdict::Triggered:    return std::move(r.payments);
            case SuperblockVerdict::NotTriggered: return std::vector<SuperblockPayment>{};
            case SuperblockVerdict::Unknown:      break;
        }
        return std::nullopt;
    }

    /// R6 desync latch state (observability / tests).
    bool gov_desync_latched() const { return m_gov_desync_latched; }
    /// Why the latch fired ("" while unlatched).
    const std::string& gov_desync_reason() const { return m_gov_desync_reason; }

    // ── R5 govsync-completeness determination ────────────────────────────────
    // Models dashcore CMasternodeSync's governance-phase completion (peer
    // coverage + time-quiescence) — the "is governance synced" gate the
    // NodeCoinState superblock guard consults via set_superblock_sync_complete_fn.
    // Fed from the SAME reception path as the GovernanceStore (on_govobject /
    // on_govvote re-arm quiescence) plus note_govsync_requested from the govsync
    // send site. gov_sync_complete() is the production predicate main_dash wires.

    /// Completeness tunables (main_dash sets these from the deployment; a
    /// single-peer deployment leaves min_peers unmet => permanently INCOMPLETE
    /// => every superblock height refuses). See govsync_status.hpp for the model.
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
    /// The coin-P2P client's coverage proof for `peer_key` closed / lapsed
    /// (CoinClient::set_on_govsync_coverage). Only ANSWERED peers count.
    void note_govsync_answered(const std::string& peer_key) {
        m_gov_sync_status.note_govsync_answered(peer_key, m_now_fn());
    }
    void note_govsync_unanswered(const std::string& peer_key) {
        m_gov_sync_status.note_govsync_unanswered(peer_key);
    }

    /// The production completeness predicate: TRUE only when the daemonless
    /// governance view has provably caught up (peer coverage + settle + quiesce).
    /// Default (nothing synced) => false => superblock heights fail closed.
    bool gov_sync_complete() const {
        return m_gov_sync_status.is_complete(m_now_fn());
    }

    /// Observability handle (logs / tests).
    const GovSyncStatus& gov_sync_status() const { return m_gov_sync_status; }

    /// Tri-state signature check (C3 + vote verify). CannotVerify is NOT a
    /// rejection: the signer is not resolvable in a CURRENT DMN view yet, or
    /// no BLS backend is compiled in — the object/vote is held aside and
    /// blocks the superblock verdict it could affect (fail closed) instead of
    /// being dropped (which could hide the network's winner) or admitted
    /// (which could let a forgery win or fill the store).
    enum class GovSigCheck : uint8_t { Valid, Invalid, CannotVerify };

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
    ///      GetSignatureHash(), false).
    ///   3. Enforce dashcore CGovernanceVote::IsValid's time bound:
    ///      nTime <= now + 60*60 (an hour of clock skew, no more).
    /// UNSET (default) => every vote is CannotVerify => it never counts, and a
    /// trigger carrying one is Unknown (fail closed). The bool form maps
    /// true => Valid, false => Invalid; the tri-state form (production) can
    /// also say CannotVerify.
    struct GovVoteContext {
        uint256              parent_hash;
        uint256              mn_outpoint_hash;
        uint32_t             mn_outpoint_index{0};
        int32_t              outcome{0};
        int32_t              signal{0};
        int64_t              time{0};
        std::vector<uint8_t> vch_sig;
        uint256              vote_hash;   // govvote_signature_hash (BLS signing digest)
        uint256              vote_id;     // govvote_identity_hash (memo key; null = unknown)
        std::string          peer_key;    // delivering session (orphan budget)
    };
    void set_vote_verifier(std::function<bool(const GovVoteContext&)> fn) {
        if (!fn) { m_vote_check = nullptr; return; }
        m_vote_check = [f = std::move(fn)](const GovVoteContext& v) {
            return f(v) ? GovSigCheck::Valid : GovSigCheck::Invalid;
        };
    }
    void set_vote_check(std::function<GovSigCheck(const GovVoteContext&)> fn) {
        m_vote_check = std::move(fn);
    }

    /// C3 — trigger-object signature seam. dashcore admits a TRIGGER only when
    /// IsValidLocally(fCheckCollateral=true) holds (Dash Core v24
    /// governance/object.cpp:746-761, called from ProcessObject /
    /// AddGovernanceObjectInternal, governance.cpp:228-271/307-321): the
    /// masternode named by the object's collateral outpoint must exist in the
    /// TIP list (GetMNByCollateral) and the object's vchSig must verify under
    /// its OPERATOR key over CGovernanceObject::GetSignatureHash
    /// (govobject_signature_hash) — sig.SetBytes(vchSig,false);
    /// VerifyInsecure(pubKeyOperator, hash, false), object.cpp:566-575. An
    /// unverified trigger is NEVER stored. UNSET => every trigger is
    /// CannotVerify (held, blocks its height, never stored — fail closed).
    struct GovObjectContext {
        uint256              object_hash;        // govobject_hash (identity)
        int32_t              object_type{0};
        std::vector<uint8_t> vch_data;           // plaintext JSON bytes
        uint256              mn_outpoint_hash;
        uint32_t             mn_outpoint_index{0};
        std::vector<uint8_t> vch_sig;
        uint256              sig_hash;           // govobject_signature_hash
        std::string          peer_key;           // delivering session
    };
    void set_object_verifier(std::function<GovSigCheck(const GovObjectContext&)> fn) {
        m_object_check = std::move(fn);
    }

    /// Reception path (govobj): ingest a governance object.
    ///   PROPOSAL  — remembered by hash (its funding votes are voting-key
    ///               votes this store never tallies; knowing the hash keeps
    ///               them out of the orphan path).
    ///   TRIGGER   — C3 signature check FIRST (Invalid => dropped, as dashd
    ///               drops it; CannotVerify => held as UnverifiedPending and
    ///               retried every block), THEN the chain-strict schedule
    ///               parse (failure => Unparsed: C2, blocks the cycle), THEN
    ///               the bounded store (full => StoreFull: C2, blocks). A
    ///               trigger for an already-connected height is history.
    /// NOTE: wire vchData is the PLAINTEXT JSON bytes (dashcore
    /// GetDataAsPlainString does no hex layer; RPC DataHex is hex OF these
    /// bytes).
    void on_govobject(const GovObjectContext& o) {
        // An object we already processed (stored, history, proposal, rejected)
        // is not news: it must not re-arm R5 quiescence (MED-3).
        if (m_objects_seen.count(o.object_hash)) return;
        // R5: ANY NEW object arrival (trigger, proposal, or malformed) proves
        // the peer is still streaming its set — re-arm the quiescence window
        // BEFORE the type filter, so a stream of proposals still keeps us
        // "mid-sync".
        m_gov_sync_status.note_object_arrival(m_now_fn());
        if (o.object_type == GOVERNANCE_OBJECT_PROPOSAL) {
            note_object_seen(o.object_hash);
            note_proposal(o.object_hash);
            drop_orphans_of(o.object_hash);
            m_gov_store.clear_outstanding(o.object_hash);
            return;
        }
        if (o.object_type != GOVERNANCE_OBJECT_TRIGGER) return;
        ++m_gov_triggers_seen;
        if (m_gov_store.has_trigger(o.object_hash) || m_gov_store.is_erased(o.object_hash))
            return;                                             // idempotent / history
        ingest_trigger_object(o);
    }

    /// Back-compat form (KATs): an object with no signer / signature. A
    /// TRIGGER here is CannotVerify unless a test verifier says otherwise.
    void on_govobject(const uint256& object_hash, int32_t object_type,
                      const std::vector<uint8_t>& vch_data) {
        GovObjectContext o;
        o.object_hash = object_hash;
        o.object_type = object_type;
        o.vch_data    = vch_data;
        on_govobject(o);
    }

    /// Reception path (govobjvote): ingest a governance vote. Only FUNDING-
    /// signal votes matter. A vote on a STORED trigger is verified (Valid =>
    /// tallied; CannotVerify => recorded as unverifiable — keeps the
    /// trigger's height Unknown — and retried every block; Invalid =>
    /// dropped). A vote whose parent we do NOT hold is an ORPHAN (dashd keeps
    /// orphan votes and asks for the parent: governance.cpp:278-305,
    /// net_governance.cpp:258-265): buffered (bounded) so a later trigger
    /// arrival still gets it without a re-download, and — when it is a
    /// non-Invalid YES — it marks its parent OrphanYesVote (a masternode wants
    /// a trigger we do not hold funded => "not triggered" is unprovable this
    /// cycle) and the parent is fetched.
    void on_govvote(const GovVoteContext& v, const std::string& mn_outpoint_key) {
        // MED-3 verified-vote memo: a vote already settled (tallied or proven
        // invalid) is never BLS-verified again and — being no news — never
        // re-arms R5 quiescence. A per-object re-sync re-delivers the whole
        // vote set; without this every re-sync re-verified thousands of votes
        // on the io thread and reopened the sync window right before H.
        if (!v.vote_id.IsNull() && m_votes_seen.count(v.vote_id)) {
            ++m_gov_votes_memo_hits;
            return;
        }
        // R5: ANY NEW vote arrival re-arms the quiescence window (mid-sync
        // signal), BEFORE the signal/outcome/known-trigger filters below.
        m_gov_sync_status.note_vote_arrival(m_now_fn());
        if (v.signal != VOTE_SIGNAL_FUNDING) {                  // only the superblock tally axis
            note_vote_seen(v.vote_id);
            return;
        }
        // dashcore CGovernanceVote::IsValid outcome range: NONE..ABSTAIN
        // (nVoteOutcome < VOTE_OUTCOME_NONE || >= VOTE_OUTCOME_UNKNOWN =>
        // reject). NONE is a VALID, STORED outcome — a newer NONE vote
        // REPLACES a stored YES in dashd's per-(MN,signal) record, dropping
        // the yes-count. Dropping NONE here would leave a stale YES tallied
        // in c2pool after the voter withdrew it (tally inflation vs dashd).
        if (v.outcome < VOTE_OUTCOME_NONE || v.outcome > VOTE_OUTCOME_ABSTAIN) {
            note_vote_seen(v.vote_id);
            return;
        }
        if (m_gov_store.has_trigger(v.parent_hash)) {
            tally_vote(v, mn_outpoint_key);
            return;
        }
        // History (executed/expired trigger) or a proposal's funding vote
        // (voting-key path, never tallied here).
        if (m_gov_store.is_erased(v.parent_hash) || is_proposal(v.parent_hash)) {
            note_vote_seen(v.vote_id);
            return;
        }
        ingest_orphan_vote(v, mn_outpoint_key);
    }

    /// Observability (EMBED-STATUS / tests).
    uint64_t gov_triggers_seen() const      { return m_gov_triggers_seen; }
    uint64_t gov_triggers_rejected() const  { return m_gov_triggers_rejected; }
    uint64_t gov_votes_memo_hits() const    { return m_gov_votes_memo_hits; }
    uint64_t gov_orphans_dropped() const    { return m_orphan_dropped; }
    uint64_t gov_c5_unverified() const      { return m_c5_unverified; }
    size_t   gov_pending_objects() const    { return m_pending_objects.size(); }
    size_t   gov_orphan_votes() const       { return m_orphan_total; }
    size_t   gov_unverifiable_votes() const { return m_unverifiable_votes.size(); }
    /// Last verdict this node handed the serve path as NotTriggered (0 = none).
    uint32_t gov_not_triggered_served_height() const {
        return m_sb_not_triggered_served.load(std::memory_order_relaxed);
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
    ///
    /// `source` NAMES the lane that produced this snapshot — "dashd-seed"
    /// (E2c protx-list RPC), "mn-ckpt" (E2d compiled-in anchor replayed
    /// forward) or "replay-fold" (the root-checked full-history DML fold).
    /// Logged verbatim, because the three are NOT interchangeable and a bare
    /// "populated" cannot tell an RPC-seeded payee queue from a daemonlessly
    /// derived one — the ambiguity that let a LAN run be read as proof of a
    /// daemonless serve when its payee half had come from dashd.
    void on_mn_list_update(std::vector<std::pair<uint256, MNState>> mnstates,
                           uint32_t as_of_height = 0,
                           const std::string& source = std::string()) {
        m_mn_source = source.empty() ? std::string("unnamed") : source;
        LOG_INFO << "[PAYEE-QUEUE] snapshot source=" << m_mn_source
                 << " as_of_h=" << as_of_height
                 << " mns=" << mnstates.size()
                 << (mnstates.empty() ? " (EMPTY -> set-gap, demoting)" : "");
        // ── DAEMONLESS CLASSIFICATION (the 2026-08-04 misreading) ────────
        // #1128's line above names the lane; this states the CONSEQUENCE, and
        // it is the half that actually cost the day: we read a run as proof of
        // a daemonless serve when its payee half had come from dashd, and only
        // an A/B with --coin-rpc removed exposed it. The predicate is derived
        // from the very string #1128 passed in — never inferred from which
        // flags were on the command line — and it rides the standing
        // [EMBED-STATUS] line so the question is answerable at any moment, not
        // only at the instant a snapshot lands.
        LOG_INFO << "[PAYEE-QUEUE] daemonless="
                 << (mn_source_daemonless() ? 1 : 0)
                 << " (source=" << m_mn_source
                 << " => " << (mn_source_daemonless()
                                   ? "no daemon supplied this payee queue"
                                   : "a daemon (or an un-named caller) supplied"
                                     " this payee queue; a run using it has NOT"
                                     " proven a daemonless serve")
                 << ")";
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
        // ── CONSUMER CURRENCY GATE (the G7 split, consumer half) ─────────
        // This consumer holds BOTH operands — the seed's as_of_height and
        // serve_tip_height() — and historically compared neither: currency
        // was enforced only publisher-side (replay_payee_publish.hpp G7).
        // With the publisher's exact-tip demand relaxed by kPublishEpsilon,
        // the enforcement moves HERE: accept and STORE a below-tip seed, but
        // arm m_have_mn for SERVING only when the queue cursor is current.
        // If the seed is behind the serve tip, immediately attempt the
        // diff-store catch-up for (as_of .. tip]; arming happens only at
        // cursor == tip. A catch-up refusal costs nothing (mirror of G7's
        // publisher-side economics): the seed stays stored, serving stays
        // un-armed, and the incumbent lane keeps its job. This gate does NOT
        // replace publisher G7 — the ε bound keeps the cheap refusal there;
        // this is the zero-cost currency check that guarantees no serve ever
        // projects a below-tip queue front.
        {
            const uint32_t serve_tip = serve_tip_height();
            if (m_have_mn && as_of_height != 0 && serve_tip != 0
                && as_of_height < serve_tip) {
                bool caught_up = false;
                if (m_mn_gap_repair) {
                    auto rep = m_mn_gap_repair(serve_tip);
                    if (rep.ok && !rep.entries.empty()
                        && rep.as_of == serve_tip) {
                        LOG_INFO << "[PAYEE-QUEUE] below-tip seed as_of_h="
                                 << as_of_height << " CAUGHT UP to serve tip"
                                    " h=" << serve_tip
                                 << " from the diff store ("
                                 << rep.entries.size() << " MNs)";
                        m_state.mnstates().load(std::move(rep.entries),
                                                rep.as_of);
                        m_mn_snapshot_height = rep.as_of;
                        as_of_height         = rep.as_of;
                        caught_up            = true;
                    }
                }
                if (!caught_up) {
                    LOG_WARNING
                        << "[PAYEE-QUEUE] seed as_of_h=" << as_of_height
                        << " is BEHIND serve tip h=" << serve_tip
                        << " and the diff-store catch-up "
                        << (m_mn_gap_repair ? "refused" : "is not wired")
                        << " — seed STORED but serving NOT armed (a queue"
                           " front below the tip must never back a"
                           " template); the incumbent lane keeps its job";
                    m_have_mn = false;
                }
            }
        }
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
            // ── FRESHNESS GATE (contabo, 2026-08-05, h=2516956) ───────────
            // An SML OLDER than the snapshot cannot speak to the snapshot's
            // height. The snapshot already reflects every ban and revive up
            // to as_of_height; an older attestation can only undo them.
            //
            // MEASURED. A replay-fold snapshot as-of h=2516955 — byte-exact
            // with dashd's list at that height, independently re-derived —
            // was reconciled 13 ms after publication against an SML dated
            // h=2478000, ~39,000 blocks stale:
            //     [SML->PAYEE] seed reconcile: -6 banned +21 revived @ h=2478000
            // Twenty-one masternodes the chain had banned were revived in the
            // payee queue, one of them went to the front, and the very next
            // block disagreed:
            //     [MNS-SM] PAYEE DESYNC h=2516956: coinbase does not pay
            //              projected MN 8ef71d8296c6e516
            // (dashd's own list at 2516955 carries that masternode with
            // PoSeBanHeight=2485482 — banned. So did ours. The reconcile
            // un-banned it.)
            //
            // This was always wrong; it only became REACHABLE when a lane
            // started publishing snapshots newer than the SML sync had got
            // to. Fail closed and say so: the queue keeps the snapshot's own
            // authoritative isValid, and the next mnlistdiff reconciles it
            // for real once the SML has caught up.
            // Two ways an SML fails to speak to this snapshot: it is DATED
            // and older, or it cannot be dated at all. sml_height_paired() is
            // false after a warm restart and whenever a diff advanced the list
            // without a parseable cbTx — and the maintainer's own rule for
            // that case is already written down: a height of 0 means "the SML
            // covers NOTHING", not "covers everything". An undatable
            // attestation cannot adjudicate a dated authoritative list either.
            const bool sml_undatable = !m_sml_height_paired;
            if (as_of_height != 0 && (sml_undatable || vh < as_of_height)) {
                LOG_WARNING
                    << "[SML->PAYEE] seed reconcile REFUSED: "
                    << (sml_undatable
                            ? std::string("the SML cannot be dated"
                                          " (sml_height_paired=false)")
                            : "the SML is at h=" + std::to_string(vh) + " ("
                              + std::to_string(as_of_height - vh)
                              + " blocks STALE)")
                    << " but the snapshot is as-of h=" << as_of_height
                    << " — an attestation that cannot speak to that height is"
                       " not evidence; the snapshot's own isValid stands until"
                       " the SML catches up";
            } else {
                const auto vr = m_state.mnstates().sync_validity_from_sml(
                    m_state.sml(), vh);
                if (vr.flipped_to_invalid || vr.flipped_to_valid)
                    LOG_INFO << "[SML->PAYEE] seed reconcile: -"
                             << vr.flipped_to_invalid << " banned +"
                             << vr.flipped_to_valid << " revived @ h=" << vh;
            }
        }
        // BODY-FIRST: an authoritative snapshot loaded as-of the pending tip
        // completes the payee axis — the last promotion precondition when the
        // credit-pool seed already reached the tip (diff-before-seed order).
        // Kept AHEAD of the telemetry below so the logged state is the state
        // after promotion, and so `promoted` reaches its use at the tail.
        const bool promoted = maybe_promote_pending_tip();
        // POST-STATE, which #1128's [PAYEE-QUEUE] line above cannot carry:
        // that one fires at entry, before the load, the SML reconcile and the
        // promotion. This is the same snapshot AFTER all of them, so "the
        // queue was replaced" and "the queue is now usable" stop being the
        // same sentence.
        LOG_INFO << "[PAYEE-QUEUE] applied source=" << m_mn_source
                 << " eligible=" << m_state.mnstates().eligible_size()
                 << " as_of=" << as_of_height
                 << " have_mn=" << (m_have_mn ? 1 : 0)
                 << " reseed_latch=" << (m_mn_needs_reseed ? 1 : 0)
                 << " tip_promoted=" << (promoted ? 1 : 0);
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

    /// ── STANDING-STATE READOUTS (telemetry only) ─────────────────────────
    /// The two halves of populated(), the snapshot cursor and the authoritative
    /// population source, exposed so the periodic [EMBED-STATUS] line can name
    /// each precondition instead of an operator grepping four markers to
    /// reconstruct them. Read-only; nothing here is consulted by a gate.
    bool     have_tip() const { return m_have_tip; }
    bool     have_mn()  const { return m_have_mn; }
    /// DASHBOARD ONLY: last published header-tip work bits (0 = never published
    /// a real tip). Thread-safe read for the web/think thread; the value is
    /// written only from republish() on the coin-p2p io thread. Never gates
    /// anything — feeds the daemonless network-difficulty graph.
    uint32_t published_bits_for_next() const {
        return m_published_bits_for_next.load(std::memory_order_relaxed);
    }
    uint32_t mn_snapshot_height() const { return m_mn_snapshot_height; }
    bool     mn_needs_reseed_latched() const { return m_mn_needs_reseed; }
    /// Is the CURRENT payee queue backed by a lane that needs no daemon?
    /// Classified from the source string #1128's publishers pass in (its
    /// kPayeeSource* constants are exactly these tokens) — never inferred
    /// from configuration. mn_source() itself is #1128's accessor and is
    /// unchanged; this is the consequence the string alone does not state.
    bool mn_source_daemonless() const
    {
        return diag::mn_source_is_daemonless(
            diag::mn_source_from_name(m_mn_source));
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
            // ── TARGET-ALREADY-HELD CARVE-OUT (reseed-wedge, soak-found) ──
            // A getmnlistd(base=B, target=T) reply that lands AFTER the SML
            // already advanced to T (a raced/duplicate reply: another diff
            // won the advance first) has base != have_at but
            // diff.blockHash == have_at. It is REDUNDANT, not
            // out-of-sequence: the state it would produce is the state we
            // already hold, so continuity is not at risk. Rejecting it as a
            // base-continuity violation was wrong in exactly one costly way:
            // the reject swallowed the very advance the payee-desync reseed
            // latch (m_mn_needs_reseed, set on the wipe below) was waiting
            // on, and the latch then stayed latched forever — the wedge log
            // showed have_mn=0 mn_entries=0 with the SML advanced, serving
            // nothing until a restart.
            //
            // DISJOINT from a genuinely out-of-sequence diff by
            // construction: that one has BOTH base != have_at AND
            // target != have_at, and still takes the reject below UNCHANGED
            // (pinned by OutOfSequenceDiffStillRejectedAndKeepsLatch).
            //
            // Do NOT apply the diff — we are already at its target; the diff
            // is evidence of currency, not of change. Clearing the latch
            // alone cannot restore serving here (the desync wipe emptied the
            // payee queue, and m_have_mn re-arms only off a NON-EMPTY
            // authoritative snapshot), so also RE-DRIVE the existing
            // authoritative re-seed transport (m_on_mn_reseed — the same ask
            // the wipe itself fired): its daemonless answers gate on the SML
            // being current, which this very diff has just proven, so an ask
            // that was refused mid-advance can succeed now. Bounded: fires
            // only while latched, i.e. once per wedge episode. Reward-safe
            // either way: main_dash runs require_seeded_mn=true, so with the
            // queue empty and m_mn_snapshot_height==0 MN-readiness stays
            // DOWN until the authoritative on_mn_list_update lands — the
            // carve-out unwedges the latch, it cannot mint a guessed payee.
            if (diff.blockHash == have_at) {
                if (m_mn_needs_reseed) {
                    m_mn_needs_reseed = false;
                    m_state.set_mn_needs_reseed(false);
                    LOG_INFO << "[SML] diff target already held ..."
                             << discriminating_hash_tail(diff.blockHash)
                             << " (base ..."
                             << discriminating_hash_tail(diff.baseBlockHash)
                             << " raced the SML advance) — redundant no-op,"
                                " NOT out-of-sequence; reseed latch cleared,"
                                " re-driving the authoritative payee re-seed"
                                " (the queue is still empty until it lands)";
                    if (m_on_mn_reseed) m_on_mn_reseed();
                } else {
                    LOG_INFO << "[SML] diff target already held ..."
                             << discriminating_hash_tail(diff.blockHash)
                             << " (base ..."
                             << discriminating_hash_tail(diff.baseBlockHash)
                             << ") — redundant no-op (raced/duplicate reply);"
                                " state unchanged";
                }
                return;
            }
            // Discriminating TAILs: these two hashes are compared for
            // INEQUALITY, so rendering the difficulty padding they share made
            // the line unable to show the very difference it reports.
            LOG_WARNING << "[SML] REJECT diff: base ..."
                        << discriminating_hash_tail(diff.baseBlockHash)
                        << " != SML-current ..." << discriminating_hash_tail(have_at)
                        << " @ h=" << (m_sml_height_paired
                                           ? std::to_string(m_sml_current_height)
                                           : std::string("n/a"))
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
                    // PR-5: publication height. Same rule as the body fold —
                    // a diff-derived pool ABOVE the serve tip is held for the
                    // promotion below (maybe_promote_pending_tip) to publish.
                    // Under the default-off flag this is m_state.set_credit_pool
                    // verbatim.
                    publish_credit_pool_at(observed.creditPoolBalance,
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
                        if (best_h > 0 && best_h >= m_state.best_cl_height()) {
                            m_state.set_best_cl(best_h, observed.bestCLSignature,
                                                ClProvenance::ChainCommitted);
                            publish_chain_committed_chainlock(best_h);
                        }
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
        // Publish the HEIGHT beside the hash, from the same statement, so the
        // freshness pair can never disagree about which block it describes.
        // Diagnostic only — no gate reads it; it exists so a `dmn-stale`
        // refusal can say HOW FAR behind the DML is instead of only THAT it
        // differs (see NodeCoinState::set_sml_current_height).
        m_state.set_sml_current_height(
            m_sml_height_paired ? static_cast<int64_t>(m_sml_current_height)
                                : static_cast<int64_t>(-1));
        LOG_INFO << "[SML] applied diff @ h="
                 << (m_sml_height_paired
                         ? std::to_string(m_sml_current_height)
                         : std::string("n/a"))
                 // The discriminating TAIL, not the difficulty padding: this
                 // line is the corroborating evidence for every dmn-stale
                 // episode, and printing the leading nibbles of a PoW hash left
                 // it unable to corroborate anything.
                 << " ..." << discriminating_hash_tail(diff.blockHash)
                 << ": SML +" << sml_r.added_or_updated
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
        // the case dashcore makes us prove with BLS (specialtxman.cpp:74-88).
        m_state.set_best_cl(height, sig, ClProvenance::BlsVerified);
        // S4 read-only mirror (/api/tx-inject/ledger, getblockchaininfo).
        ::core::obs::best_chainlock().publish(
            {height, block_hash, "bls-verified", static_cast<int64_t>(std::time(nullptr))});
        LOG_INFO << "[CL] adopted VERIFIED ChainLock height=" << height
                 << " block=" << block_hash.GetHex().substr(0, 16) << "...";
        // A fresher bestCL* changes the next template's committed CCbTx —
        // re-issue work so the served template carries the new ChainLock.
        notify_state_dirty();
    }

    /// Verifier seam for isdlock adoption (G4 conflict-tx-lock feed):
    /// BLS-verifies a deterministic InstantSend lock's recovered threshold
    /// signature against the ROTATED LLMQ_60_75 quorum dashcore's
    /// SelectQuorumForSigning designates (islock_verify.hpp). Installed by
    /// main_dash; UNSET IS FAIL-CLOSED (see on_new_isdlock).
    using IslockVerifyFn = std::function<bool(
        const std::vector<std::pair<uint256, uint32_t>>& inputs,
        const uint256& txid, const uint256& cycle_hash,
        const std::array<uint8_t, 96>& sig)>;

    void set_islock_verify_fn(IslockVerifyFn fn) {
        m_islock_verify = std::move(fn);
    }

    /// isdlock reception: fold a VERIFIED deterministic InstantSend lock into
    /// the mempool's islock-conflict tracking (on_islock -> Mempool::
    /// add_islock), arming the already-merged G4 selection guard.
    ///
    /// ⚠ VERIFICATION IS MANDATORY. An isdlock arrives from an arbitrary p2p
    /// peer, and adopting one decides which mempool txs our served templates
    /// may NOT contain (add_islock evicts a conflicting entry immediately and
    /// the G4 guard drops conflicting candidate packages from selection). An
    /// unverified adoption would let a hostile peer evict arbitrary txs from
    /// our templates — the same threat model as the ChainLock coinbase fields
    /// (on_new_chainlock above). When no verifier is installed, or
    /// verification FAILS, we adopt NOTHING: the map stays exactly as it was
    /// and selection is unchanged (the pre-existing behaviour). A refusal
    /// costs only parity with dashd's conflict handling — islock exclusion is
    /// an optimization, not consensus for us; an erroneous acceptance costs
    /// template fees on demand.
    void on_new_isdlock(const std::vector<std::pair<uint256, uint32_t>>& inputs,
                        const uint256& txid, const uint256& cycle_hash,
                        const std::array<uint8_t, 96>& sig) {
        if (!m_islock_verify) return;                     // no verifier => fail closed
        if (!m_islock_verify(inputs, txid, cycle_hash, sig)) {
            LOG_WARNING << "[ISLOCK] rejected unverified isdlock txid="
                        << txid.GetHex().substr(0, 16) << "... cycle="
                        << cycle_hash.GetHex().substr(0, 16) << "...";
            return;
        }
        LOG_INFO << "[ISLOCK] adopted VERIFIED isdlock txid="
                 << txid.GetHex().substr(0, 16) << "... inputs="
                 << inputs.size();
        on_islock(txid, inputs);
    }

    /// Verifier seam for DSTX adoption (W5-B CoinJoin broadcast tx):
    /// BLS-verifies the mixing masternode's OPERATOR signature over
    /// SerializeHash(tx‖protxHash‖sigTime) against the SML's
    /// pubKeyOperator(protxHash) — dashd ValidateDSTX
    /// (net_processing.cpp:3549-3615) / CCoinJoinBroadcastTx::CheckSignature
    /// (coinjoin.cpp:73-81). Installed by main_dash; UNSET IS FAIL-CLOSED
    /// (see on_new_dstx).
    using DstxVerifyFn = std::function<bool(
        const dash::coin::MutableTransaction& tx, const uint256& txid,
        const uint256& protx_hash, const std::array<uint8_t, 96>& sig,
        int64_t sig_time)>;

    void set_dstx_verify_fn(DstxVerifyFn fn) {
        m_dstx_verify = std::move(fn);
    }

    /// DSTX reception: admit a VERIFIED CoinJoin broadcast tx into the
    /// mempool at fee=0 with dashd's +0.1 COIN prioritisation delta
    /// (Mempool::add_dstx), so selection ranks it exactly where dashd's
    /// GetModFeesWithAncestors sort puts it while the coinbase fee term
    /// stays base (0) — both matching dashd bit-for-bit.
    ///
    /// ⚠ VERIFICATION IS MANDATORY. A DSTX is a zero-fee tx that enters the
    /// served template at TOP modified-fee priority; adopting one unverified
    /// would let an arbitrary peer stuff zero-fee txs into our templates
    /// (template pollution ⇒ tx-merkle divergence from dashd ⇒ the #1218
    /// guard refuses/swaps serving — availability, not validity, but still
    /// an attack surface). When no verifier is installed, or verification
    /// FAILS, we adopt NOTHING: the pool stays exactly as it was.
    ///
    /// KNOWN PHASE-1 DIVERGENCE (deliberate, documented): dashd additionally
    /// rate-limits DSTX-es per masternode (IsValidForMixingTxes, MAX=5 since
    /// the MN's last DSQ, masternode/meta.cpp:124-128). Mirroring that
    /// counter without ingesting the DSQ queue stream (inv 32) would only
    /// ever INCREMENT ⇒ permanent false refusals, so phase 1 omits it: an MN
    /// spamming >5 DSTX between queues makes embedded a SUPERSET of dashd
    /// for those txs and the tx-merkle guard refuses serving (never an
    /// invalid block). If soak attributes mismatch events here, phase 2
    /// adds the DSQ leg for exactness.
    void on_new_dstx(const dash::coin::MutableTransaction& tx,
                     const uint256& txid, const uint256& protx_hash,
                     const std::array<uint8_t, 96>& sig, int64_t sig_time) {
        if (!m_dstx_verify) return;                      // no verifier => fail closed
        if (!m_dstx_verify(tx, txid, protx_hash, sig, sig_time)) {
            LOG_WARNING << "[DSTX] rejected unverified dstx txid="
                        << txid.GetHex().substr(0, 16) << "... protx="
                        << protx_hash.GetHex().substr(0, 16) << "...";
            return;
        }
        const bool admitted = m_state.mempool().add_dstx(tx);
        LOG_INFO << "[DSTX] VERIFIED dstx txid=" << txid.GetHex().substr(0, 16)
                 << "... protx=" << protx_hash.GetHex().substr(0, 16)
                 << (admitted ? "... admitted fee=0 delta=+0.1 COIN"
                              : "... delta applied to already-pooled tx");
    }

    /// Reorg (SML axis): a chain reorganisation can invalidate the incremental
    /// SML/quorum state (the diffs we applied were relative to an orphaned
    /// branch). Wipe the SML + quorum set and drop have_sml so the embedded arm
    /// falls back to dashd until a fresh cold-start mnlistdiff(zero, new-tip)
    /// rebuilds them. main_dash.cpp calls this from the header-chain reorg hook
    /// and then re-requests a full diff. (Distinct from on_invalidate, which
    /// only drops tip-readiness and deliberately KEEPS the MN payee list.)
    void on_sml_reorg() {
        // The mempool's recent-spent ring (external-collateral proof) holds
        // the spends of every connected block; the ones the reorg
        // disconnected are no longer chain spends. Forget them against the
        // switched chain's height index; unwired (KAT / RPC posture) the
        // ring is cleared, which only gives up proof.
        if (const size_t n = m_state.mempool().forget_chain_spends_off_chain(
                m_chain_hash_at_height_fn))
            LOG_INFO << "[EMB-DASH] reorg: forgot the recorded spends of " << n
                     << " block(s) no longer on the active chain"
                        " (external-collateral proof)";
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
                        // Rollback: write straight through and drop anything
                        // held — a held pool was derived on the branch that
                        // just went away (PR-5).
                        discard_held_credit_pool();
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
            // fresh re-seed. A HELD pool (PR-5) is dropped with it: it was
            // derived on the orphaned branch and must never be published.
            discard_held_credit_pool();
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
    ///
    /// ██ SOLE-INGESTION-PATH INVARIANT ██ This method (fed exclusively by
    /// wire_mempool_ingest <- interfaces::Node::new_tx <- dashd-peer relay)
    /// is the ONLY route into Mempool::add_tx. The audit's two
    /// N-A-BY-SOURCE-INVARIANT rows (bad-txns-nonfinal, mandatory-script-
    /// verify-flag; DASH_CONNECTBLOCK_REJECT_SURFACE_AUDIT.md §6) hold only
    /// while that stays true -- see the invariant block atop mempool.hpp
    /// before adding any other caller.
    bool on_mempool_tx(const MutableTransaction& tx) {
        // Mempool relay is the highest-cadence event through the maintainer,
        // so it doubles as the clock the tip-body-overdue bound is checked on
        // (the maintainer owns no timer; see check_tip_body_overdue).
        check_tip_body_overdue();
        return m_state.mempool().add_tx(tx);
    }

    /// G4 seam (audit conflict-tx-lock): fold a relayed InstantSend lock into
    /// the mempool's islock-conflict tracking -- evicts a conflicting pool
    /// entry immediately and keeps the outpoints excluded from template
    /// selection (Mempool::add_islock, incl. the documented residual race).
    /// FEED: the coin-P2P isdlock parse leg (dashd-peer relay, same source
    /// invariant as on_mempool_tx): inv(MSG_ISDLOCK) → isdlock handler →
    /// Node::new_islock → wire_islock_ingest → here. Also drives the IS
    /// mining-safety hold's IsLocked short-circuit (mempool.hpp). On an
    /// un-wired node (no coin-P2P) nothing calls this and selection
    /// behaviour is unchanged (empty map, hold self-disarmed).
    void on_islock(const uint256& locked_txid,
                   const std::vector<std::pair<uint256, uint32_t>>& inputs) {
        m_state.mempool().add_islock(locked_txid, inputs);
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
    ///
    /// ── WHAT `tip-body-pending` ACTUALLY NAMES ──────────────────────────────
    /// It is one state with two very different costs, and they must not be
    /// confused (they were: see the guard in node_coin_state.hpp's decline
    /// refinement).
    ///
    /// THE STATE: we hold the tip HEADER (h, hash) but at least one of the
    /// three per-block derived axes is still at h-1, so
    /// maybe_promote_pending_tip() has not run. The header commits to those
    /// axes; it does not carry them:
    ///   • credit-pool seed — the next block's DIP4 CbTx must carry
    ///     creditPoolBalance derived AT the tip. That number moves with the
    ///     tip block's asset-lock/unlock special txs, which live in the tip
    ///     block's BODY. Outstanding fetch: getdata BLOCK <tip hash> on the
    ///     coin-P2P leg (or a tip-targeted mnlistdiff whose cbTx carries it).
    ///   • payee cursor — nLastPaidHeight advances by the tip block's own
    ///     masternode payment, which is a coinbase output in the same BODY.
    ///     Without it the next template pays the previous winner again:
    ///     bad-cb-payee, a rejected block, a lost share.
    ///   • SML currency — merkleRootMNList must be computed over the list AS
    ///     OF the tip. A cbTx commits that ROOT; a root is not a list, so the
    ///     body CANNOT supply it. Outstanding fetch: a separate getmnlistd
    ///     round trip (base = serve tip, target = header tip).
    /// So the template cannot be built not because we lack the header's
    /// difficulty/time fields — we stashed those above — but because three
    /// coinbase-committed values are functions of the tip BLOCK.
    ///
    /// COST A (steady state): a serve tip already exists, we keep serving
    /// h-1 work, and no refusal is emitted at all. The window is the block's
    /// propagation + parse latency and nothing else. MEASURED on the
    /// instrumented daemonless soak (86406d07, 2026-08-09 14:39–16:05,
    /// h=2519019..2519049): 31 windows opened, 31 closed BY PROMOTION, 0
    /// overdue demotes; median 0.771 s, p90 2.909 s. 30 of the 31 cost ZERO
    /// seconds off the embedded arm.
    ///
    /// COST B (cold start / post-demote): no serve tip exists yet, so the
    /// pending window IS the refusal. One-time, and it shares its episode
    /// with `not-populated` — on that same soak the whole cold start was a
    /// single 126 s episode (not-populated 102 s → tip-body-pending 19 s →
    /// not-populated 5 s → RESUMED), the 19 s being the sole window of the 31
    /// that cost anything, and the MN seed, not the block body, being its
    /// longest pole (the body folded 5 s before have_mn came up). It belongs
    /// to the cold-start lane (#1162/#1151), not to a steady-state budget.
    ///
    /// SO: do NOT try to shorten this wait. Promotion already fires the
    /// instant the inputs land; the residue is network. The defect this
    /// state had was in its NAME, not its duration.
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

        // B.8 (dashd removeForBlock -> removeProTxConflicts): evict the pending
        // provider txs this block invalidates — operator key changed/revoked,
        // collateral spent or re-registered, duplicate keys / collateral /
        // service / platform id — and record the block's spent outpoints for
        // the external-collateral proof. Runs HERE, before apply_block,
        // because the collateral and operator-key rules read the PRE-block
        // masternode list. Drop-only. The spends are recorded under this
        // block's height + hash so a reorg (on_sml_reorg) or a refusal below
        // can forget them again.
        const uint256 connected_hash = block_identity_hash(block);
        {
            const MnStateMachine& pre = std::as_const(m_state).mnstates();
            m_state.mempool().remove_protx_conflicts_for_block(
                block,
                [&pre](const bitcoin_family::coin::TxPrevOut& op) {
                    return pre.find_by_collateral(op);
                },
                // dashd validForProTxKey: the key's bytes under the holder's
                // own scheme (the store is canonical basic; re-encode).
                [&pre](const uint256& protx)
                    -> std::optional<std::array<uint8_t, vendor::BLS_PUBKEY_SIZE>> {
                    auto it = pre.entries().find(protx);
                    if (it == pre.entries().end()) return std::nullopt;
                    return vendor::opkey_for_leaf(
                        it->second.pubKeyOperator,
                        it->second.nVersion < vendor::ProTxVersion::BASIC_BLS);
                },
                Mempool::ChainPos{height, connected_hash});
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
        // Every block: prune executed/expired triggers, retry held signature
        // checks, and fire the C4 vote re-syncs at H - window and H - 1.
        governance_on_block(height);

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
        // CONSENSUS REFUSAL (v23.1.9 port): dashd rejects this block. The apply
        // mutated nothing and the cursor stayed put, so the set is still right
        // for the previous block — no wipe, no re-seed. Stop serving on this
        // block; the valid block at this height (the chain the network
        // ChainLocks) folds normally, and a child of the refused block trips
        // the gap guard.
        if (!r.refused.empty()) {
            LOG_WARNING << "[EMB-DASH] MN payee fold REFUSED block h=" << height
                        << ": " << r.refused
                        << " — dashd rejects it; not serving on it (demote)";
            // Its spends are not chain spends: they must not prove an
            // external collateral absent.
            m_state.mempool().forget_chain_spends_of_block(connected_hash);
            demote();
            return r;
        }
        // ── DIFF-STORE GAP REPAIR (dashd GetListForBlockInternal analogue,
        // evo/deterministicmns.cpp:778-870, as a cold repair path). An APPLY
        // GAP means blocks between the cursor and this one were never folded
        // into the payee queue. dashd never wipes on that — it reconstructs
        // the list for ANY block from its per-block diff store. When the
        // ported store (mn_diff_store.hpp) is wired and can reconstruct the
        // list AT height-1 — every row present, digest-good, root_matched
        // AND payee_verified, SML root equal to the chain's committed root —
        // reseed through the EXISTING single sink (on_mn_list_update: the
        // reseed latch clears on a non-empty height-stamped set, the anti-
        // mint invariant below is respected, not bypassed) and re-apply the
        // block the caller still holds. ANY refusal falls through to the
        // unchanged wipe chain below; repair only ADDS a lane in front of
        // it, it removes nothing. payee_desync is NOT repairable this way
        // (the queue disagreed with the chain at a contiguous height — that
        // is a divergence, not a gap) and takes the wipe path as always.
        if (r.gap_detected && !r.payee_desync && m_mn_gap_repair) {
            auto rep = m_mn_gap_repair(height - 1);
            if (rep.ok && !rep.entries.empty() && rep.as_of == height - 1) {
                LOG_INFO << "[EMB-DASH] MN payee APPLY GAP at h=" << height
                         << " REPAIRED from the diff store: queue reseeded"
                            " as-of h=" << rep.as_of << " ("
                         << rep.entries.size() << " MNs, source="
                         << kPayeeSourceMnDiffRepair
                         << "); re-applying the held block";
                on_mn_list_update(std::move(rep.entries), rep.as_of,
                                  kPayeeSourceMnDiffRepair);
                // Pass-3's coinbase cross-check inside this re-apply is the
                // final tripwire: a payee_desync here falls through to the
                // wipe chain below exactly as an unrepaired gap would.
                r = m_state.mnstates().apply_block(block, height);
            } else {
                LOG_WARNING << "[EMB-DASH] MN payee APPLY GAP at h=" << height
                            << " NOT repairable from the diff store ("
                            << (rep.error.empty() ? "refused" : rep.error)
                            << ") — falling through to the wipe/demote path";
            }
        }
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
                        << (m_fallback_armed
                                ? " — wiping payee set, demoting to dashd fallback,"
                                  " requesting authoritative re-seed"
                                : " — wiping payee set and requesting an"
                                  " authoritative re-seed; DAEMONLESS: no dashd"
                                  " fallback is armed, so NO work is served until"
                                  " the re-seed publishes");
            // F2: a gap is not divergence. The queue was never offered
            // cursor+1 and is still correct as of its cursor, so keep a copy
            // the re-seed may resume from. A desync (even one reported
            // together with a gap after a repair re-apply) is divergence and
            // keeps no seed.
            m_last_reseed_reason = r.payee_desync ? ReseedReason::Desync
                                                  : ReseedReason::Gap;
            m_gap_seed.reset();
            if (!r.payee_desync && m_mn_snapshot_height != 0) {
                const MnStateMachine& sm = std::as_const(m_state).mnstates();
                if (!sm.entries().empty() && sm.last_applied_height() != 0) {
                    GapSeed g;
                    g.entries.assign(sm.entries().begin(), sm.entries().end());
                    g.as_of      = sm.last_applied_height();
                    g.as_of_hash = (g.as_of == m_payee_cursor_hash_height)
                                       ? m_payee_cursor_hash : uint256();
                    g.source     = m_mn_source;
                    m_gap_seed   = std::move(g);
                }
            }
            m_state.mnstates().load({});
            m_mn_snapshot_height = 0;
            m_have_mn = false;
            // The wiped queue has NO source any more. Leaving the last
            // lane's name standing would make [PAYEE-QUEUE]/[EMBED-STATUS]
            // keep claiming a backing that no longer exists — and, worse,
            // keep claiming it was DAEMONLESS. Same class of misreading the
            // source field exists to end.
            m_mn_source.clear();
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
        // A CLEAN fold advanced the queue to `height`: remember which block
        // it folded (the gap seed's R4 evidence) and hand the queue to the
        // live cursor persistence (F3).
        if (!r.skipped_out_of_order
            && std::as_const(m_state).mnstates().last_applied_height() == height) {
            m_payee_cursor_hash        = block_identity_hash(block);
            m_payee_cursor_hash_height = height;
            if (m_on_payee_folded && m_mn_snapshot_height != 0
                && !m_mn_needs_reseed)
                m_on_payee_folded(std::as_const(m_state).mnstates().entries(),
                                  height, m_payee_cursor_hash);
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
        m_state.set_tip_body_pending_axis("");
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

    /// PUBLICATION HEIGHT (PR-5). When enabled (and body-first is on), the
    /// derived credit pool is PUBLISHED at the SERVE tip instead of at the
    /// body height: a pool derived for a block ABOVE the serve tip is held in
    /// a pending slot and published atomically with the promotion that makes
    /// that block the serve tip. See publish_credit_pool_at() for the dashd
    /// mechanism this ports and why the current write is not merely
    /// gate-tripping but reward-WRONG for the tip we are actually building on.
    ///
    /// MONEY PATH -> default OFF. Turning it on changes what the embedded arm
    /// serves during a held window: it serves serve-tip-based work where it
    /// previously refused with `creditpool-stale`. main_dash exposes it as
    /// --embedded-creditpool-publish-at-serve-tip; nothing enables it
    /// implicitly.
    void set_credit_pool_publish_at_serve_tip(bool on) {
        m_cp_publish_at_serve_tip = on;
    }
    bool credit_pool_publish_at_serve_tip() const {
        return m_cp_publish_at_serve_tip;
    }
    /// Observability (STATE SAYS ITS OWN NAME): is a derived credit pool
    /// currently HELD above the serve tip, awaiting promotion? -1 = nothing
    /// held.
    int32_t held_credit_pool_height() const {
        return m_cp_pending_valid ? m_cp_pending_height : -1;
    }

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

    /// The lane that last populated the payee queue — "dashd-seed",
    /// "mn-ckpt", "replay-fold", "unnamed", or empty when nothing has ever
    /// populated it. Diagnostic; the serve gate does not branch on it.
    const std::string& mn_source() const { return m_mn_source; }

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

    /// WHY the last authoritative re-seed was asked for (read by the re-seed
    /// sink, which keeps its no-argument signature). A GAP and a DESYNC are
    /// opposite evidence and the MN-CKPT re-arm must not treat them alike:
    ///   * Desync — the connected block's coinbase disagreed with the queue at
    ///     a contiguous height: the queue itself is wrong (divergence);
    ///   * Gap    — the queue was never offered cursor+1 (a transport hole):
    ///     the queue is CORRECT as of its cursor, it is merely behind.
    /// Every re-drive of the ask (the SML carve-out) repeats the last reason.
    enum class ReseedReason { None, Desync, Gap };
    ReseedReason last_reseed_reason() const { return m_last_reseed_reason; }
    static const char* reseed_reason_name(ReseedReason r) {
        switch (r) {
            case ReseedReason::None:   return "none";
            case ReseedReason::Desync: return "desync";
            case ReseedReason::Gap:    return "gap";
        }
        return "unknown";
    }

    /// The payee queue exactly as it stood when an APPLY GAP wiped it: still
    /// contiguous through `as_of`, so a re-seed may RESUME from it (replay
    /// as_of+1 .. tip) instead of replaying from a persisted cursor or the
    /// anchor. Captured only for a gap (never a desync), only off an
    /// authoritative height-stamped snapshot, and handed out once.
    struct GapSeed {
        std::vector<std::pair<uint256, MNState>> entries;
        uint32_t    as_of{0};
        uint256     as_of_hash;     // block folded at as_of (null: snapshot load)
        std::string source;         // the lane that seeded the lineage
    };
    std::optional<GapSeed> take_gap_seed() {
        std::optional<GapSeed> out;
        out.swap(m_gap_seed);
        return out;
    }
    bool has_gap_seed() const { return m_gap_seed.has_value(); }

    /// Called after every CLEAN payee fold (no gap, no desync, not skipped)
    /// with the queue as of `height` and the block folded there. main_dash
    /// points this at MnCheckpointLane::note_live_fold so the bridge cursor is
    /// persisted at the tip (F3) and a restart / gap re-seed resumes from
    /// blocks-since-the-last-fold instead of blocks-since-the-last-publish.
    using PayeeFoldedFn = std::function<void(const MnStateMachine::Entries&,
                                             uint32_t height,
                                             const uint256& block_hash)>;
    void set_on_payee_folded(PayeeFoldedFn fn) { m_on_payee_folded = std::move(fn); }

    /// The ordered-connect cursor PayeeFoldFeeder delivers against: the
    /// payee machine's apply cursor WHILE an authoritative, height-stamped,
    /// non-empty snapshot is in force; 0 otherwise (unseeded, unheighted,
    /// wiped awaiting its re-seed), which puts the feeder in passthrough.
    /// Read through the const accessor: this runs per block and per tick and
    /// must not bump the root-memo epoch.
    uint32_t payee_fold_cursor() const {
        if (m_mn_needs_reseed || m_mn_snapshot_height == 0) return 0;
        const MnStateMachine& sm = std::as_const(m_state).mnstates();
        if (sm.entries().empty()) return 0;
        return sm.last_applied_height();
    }

    /// Is a dashd fallback arm actually configured? Purely for the wording of
    /// the fail-closed lines: on a daemonless node "demoting to dashd
    /// fallback" serves NO work, and the log must say so (F4). Default true
    /// keeps every existing line byte-identical.
    void set_fallback_armed(bool armed) { m_fallback_armed = armed; }

    /// Wire the MN diff-store gap-repair seam (mn_gap_repair.hpp; main_dash
    /// points this at MnDiffStore::reconstruct over the PoW-validated header
    /// chain — the c2pool port of dashd's snapshot+diff walk,
    /// evo/deterministicmns.cpp:778-870). Consulted in exactly two places:
    ///   * on_block_connected's APPLY-GAP branch, BEFORE the wipe chain —
    ///     a gap that CAN be repaired from stored, root+payee-verified diffs
    ///     re-seeds through on_mn_list_update and re-applies the held block;
    ///   * on_mn_list_update's consumer currency gate (the G7 split) —
    ///     a below-tip seed is caught up to the serve tip before it may arm
    ///     serving.
    /// Optional: unset leaves BOTH paths byte-identical to their historical
    /// fail-closed behavior (wipe/demote/re-seed; exact-currency arming).
    void set_mn_gap_repair(MnGapRepairFn fn) {
        m_mn_gap_repair = std::move(fn);
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

    /// Wire the bounded getmnlistd re-request (main_dash points this at
    /// coin_p2p->send_getmnlistd). Fired from check_tip_body_overdue's diff-
    /// phase sub-threshold when the SML currency is stuck behind the header tip
    /// — the companion that keeps the fourth-axis conjunct from converting a
    /// diff outage into a silent doomed-tip window (see check_tip_body_overdue).
    /// Optional: unset in KATs = no re-request wired, so the conjunct's blocking
    /// behaviour is testable without a live peer. `base` is the SML's current
    /// block, `target` the header tip to advance it to.
    void set_on_sml_rerequest(
        std::function<void(const uint256& base, const uint256& target)> fn) {
        m_on_sml_rerequest = std::move(fn);
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
            && committed_cl_h >= m_state.best_cl_height()) {
            m_state.set_best_cl(committed_cl_h, observed.bestCLSignature,
                                ClProvenance::ChainCommitted);
            publish_chain_committed_chainlock(committed_cl_h);
        }
    }

    /// S4 read-only mirror of a chain-committed ChainLock adoption: the cbTx
    /// carries only the height, so the block hash comes from the current
    /// chain's height index when one is wired (null = unknown, never guessed).
    void publish_chain_committed_chainlock(int32_t height) {
        ::core::obs::BestChainLock cl;
        cl.height = height;
        if (m_chain_hash_at_height_fn && height > 0)
            if (auto h = m_chain_hash_at_height_fn(static_cast<uint32_t>(height))) cl.blockhash = *h;
        cl.provenance = "chain-committed";
        cl.updated_at = static_cast<int64_t>(std::time(nullptr));
        ::core::obs::best_chainlock().publish(cl);
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
        // Advance the freshness seed to THIS block. The comment that used to
        // stand here asserted "height == the tip we build the next template
        // on" — true in header-first mode, and true in body-first mode ONLY
        // when this fold promotes the serve tip. When promotion is held (the
        // fourth axis, maybe_promote_pending_tip:1820-1822), the serve tip
        // stays at H-1 while this write moved the pool to H: the pool AHEAD of
        // the tip, which is exactly the `creditpool-stale value=threshold+1`
        // class. publish_credit_pool_at() makes the assertion true by
        // construction under the flag — it publishes at the serve tip and
        // holds anything above it for the promotion to publish.
        publish_credit_pool_at(from_wire, block_identity_hash(block),
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

    // E-SUPERBLOCK (R6 + C5): superblock desync cross-check (see the call
    // site in on_block_connected for the rationale). Resolves the STRUCTURAL
    // verdict our store held for `height` (R5 forced true: the question is
    // what the store says, not whether we served) and holds it against the
    // network-accepted coinbase at that height:
    //   Triggered    => R6: the coinbase must carry our schedule exactly as
    //                   CSuperblock::IsValid matches it (v24-strict when v24
    //                   is active at the height); a miss latches.
    //   NotTriggered => C5 (reverse R6): when that verdict was or could have
    //                   been served, the coinbase must stay within the
    //                   non-superblock block value; more latches.
    void cross_check_superblock_on_block(const dash::coin::BlockType& block,
                                         uint32_t height) {
        if (!m_sb_is_fn || !m_sb_is_fn(height)) return;   // not a superblock height
        if (!block.m_txs.empty()) {
            const auto res = resolve_at(height, /*sync_complete=*/true);
            if (res.verdict == SuperblockVerdict::Triggered) {
                const bool v24 = m_state.v24_state_for(height) == V24State::ACTIVE;
                if (!coinbase_carries_schedule(block.m_txs[0], res.payments, v24))
                    latch_gov_desync(height,
                        "our trigger-confident schedule (" +
                        std::to_string(res.payments.size()) +
                        " payee(s)) does NOT match the accepted block's coinbase");
            } else if (res.verdict == SuperblockVerdict::NotTriggered &&
                       (gov_sync_complete() ||
                        m_sb_not_triggered_served.load(std::memory_order_relaxed) == height)) {
                reverse_check_not_triggered(block, height);
            }
        }
        // The cycle at `height` has executed — its unknown-height records
        // (unparsed objects, orphan-YES parents, overflow latches) are over.
        // Height-bound pruning runs for every block in governance_on_block.
        end_gov_cycle(height);
    }

    // ── E-SUPERBLOCK private machinery ───────────────────────────────────

    /// Bounds for the maintainer-side governance buffers (see on_govvote).
    static constexpr size_t GOV_MAX_PENDING_OBJECTS   = GovernanceStore::MAX_OUTSTANDING;
    static constexpr size_t GOV_MAX_ORPHAN_VOTES      = 16384;   // global, oldest kept
    static constexpr size_t GOV_MAX_ORPHANS_PER_PEER  = 4096;    // buffered per peer per cycle
    static constexpr size_t GOV_ORPHAN_VERIFY_BUDGET  = 4096;    // BLS verifies per peer per cycle
    static constexpr size_t GOV_SEEN_CAP              = 262144;
    /// Triggers stay resolvable this many blocks past their height, so a
    /// reorg that re-folds the superblock block sees the same view (MED-5).
    static constexpr int32_t GOV_REORG_KEEP           = 32;
    static constexpr size_t GOV_MAX_UNVERIFIABLE_RETRY = 8192;
    static constexpr size_t GOV_MAX_PROPOSALS         = 4096;

    struct HeldVote {
        GovVoteContext v;
        std::string    key;
        bool           verified{false};   // orphan buffer: signature already Valid
    };

    /// The verdict with every local gate, for an explicit R5 value (the
    /// cross-check evaluates the STRUCTURAL verdict with R5 forced true).
    SuperblockResolution resolve_at(uint32_t height, bool sync_complete) const {
        if (m_gov_desync_latched) return SuperblockResolution::unknown("trigger-latched");
        if (!m_sb_budget_fn)      return SuperblockResolution::unknown("trigger-ctx-unwired");
        return resolve_superblock_payments(m_gov_store, static_cast<int32_t>(height),
                                           m_sb_budget_fn(height), sync_complete);
    }

    GovSigCheck check_object(const GovObjectContext& o) const {
        return m_object_check ? m_object_check(o) : GovSigCheck::CannotVerify;
    }
    GovSigCheck check_vote(const GovVoteContext& v) const {
        return m_vote_check ? m_vote_check(v) : GovSigCheck::CannotVerify;
    }

    void ingest_trigger_object(const GovObjectContext& o) {
        const auto chk = check_object(o);
        if (chk == GovSigCheck::Invalid) {
            // dashd IsValidLocally false => ProcessObject returns false, the
            // object is never stored or relayed (governance.cpp:262-270).
            ++m_gov_triggers_rejected;
            note_object_seen(o.object_hash);
            // Real masternodes vote only on triggers dashd accepted, so a
            // (non-Invalid) masternode YES already buffered for an object we
            // now reject means OUR check disagrees with the network: keep the
            // unfunded verdict unprovable (OrphanYesVote) instead of clearing.
            if (has_orphan_yes(o.object_hash))
                m_gov_store.note_outstanding(o.object_hash,
                                             GovOutstandingKind::OrphanYesVote, 0);
            else
                m_gov_store.clear_outstanding(o.object_hash);
            LOG_WARNING << "[GOVSYNC] trigger " << o.object_hash.GetHex().substr(0, 16)
                        << " REJECTED: masternode signature invalid (dashd "
                           "IsValidLocally parity) — not stored";
            drop_pending_object(o.object_hash);
            return;
        }
        std::string plain(o.vch_data.begin(), o.vch_data.end());
        auto trig = parse_superblock_trigger(plain, o.object_hash, m_gov_testnet);
        if (chk == GovSigCheck::CannotVerify) {
            const int32_t eh = trig ? trig->event_block_height : 0;
            if (trig && is_history_height(eh)) {           // cannot matter any more
                m_gov_store.note_erased(o.object_hash);
                drop_pending_object(o.object_hash);
                return;
            }
            m_gov_store.note_outstanding(o.object_hash,
                                         GovOutstandingKind::UnverifiedPending, eh);
            hold_pending_object(o);
            LOG_INFO << "[GOVSYNC] trigger " << o.object_hash.GetHex().substr(0, 16)
                     << " signature NOT YET VERIFIABLE (signer not in a current "
                        "DMN view / no BLS backend) — held, blocks h="
                     << (eh ? std::to_string(eh) : std::string("cycle"));
            return;
        }
        drop_pending_object(o.object_hash);
        admit_verified_trigger(o, trig);
    }

    void admit_verified_trigger(const GovObjectContext& o,
                                const std::optional<GovernanceTrigger>& trig) {
        if (!trig) {
            // C2: a masternode-signed TRIGGER we cannot parse. dashd may parse
            // it (our parser is deliberately narrower in places), so its
            // existence makes every verdict this cycle unprovable.
            m_gov_store.note_outstanding(o.object_hash, GovOutstandingKind::Unparsed, 0);
            note_object_seen(o.object_hash);
            LOG_WARNING << "[GOVSYNC] trigger " << o.object_hash.GetHex().substr(0, 16)
                        << " signed but UNPARSEABLE — superblock verdicts this "
                           "cycle are Unknown (fail closed)";
            return;
        }
        if (is_history_height(trig->event_block_height)) {
            // Executed / expired: dashd keeps executed triggers for a cycle to
            // serve syncs (superblock.cpp:338-372), they can never pay again.
            m_gov_store.note_erased(o.object_hash);
            m_gov_store.clear_outstanding(o.object_hash);
            drop_orphans_of(o.object_hash);
            note_object_seen(o.object_hash);
            return;
        }
        if (!m_gov_store.add_trigger(*trig)) {
            m_gov_store.note_outstanding(o.object_hash, GovOutstandingKind::StoreFull,
                                         trig->event_block_height);
            LOG_WARNING << "[GOVSYNC] trigger store FULL ("
                        << m_gov_store.trigger_count()
                        << ") — dropping trigger "
                        << o.object_hash.GetHex().substr(0, 16)
                        << " (recorded: h=" << trig->event_block_height
                        << " verdict is Unknown)";
            return;
        }
        m_gov_store.clear_outstanding(o.object_hash);
        note_object_seen(o.object_hash);
        LOG_INFO << "[GOVSYNC] trigger " << o.object_hash.GetHex().substr(0, 16)
                 << " (signature verified) for superblock h="
                 << trig->event_block_height << " with "
                 << trig->payments.size() << " payee(s), total="
                 << trig->total_amount() << " duffs";
        replay_orphans_of(o.object_hash);
    }

    /// A height at or below the serve tip has been connected: a trigger for
    /// it can never pay again.
    bool is_history_height(int32_t event_height) const {
        return m_have_tip && event_height > 0 &&
               static_cast<int64_t>(event_height) + GOV_REORG_KEEP <=
                   static_cast<int64_t>(m_prev_height);
    }

    void tally_vote(const GovVoteContext& v, const std::string& key) {
        switch (check_vote(v)) {
            case GovSigCheck::Valid:
                m_gov_store.add_verified_funding_vote(v.parent_hash, key, v.outcome, v.time);
                note_vote_seen(v.vote_id);
                return;
            case GovSigCheck::CannotVerify:
                m_gov_store.note_unverifiable_vote(v.parent_hash, key);
                if (m_unverifiable_votes.size() < GOV_MAX_UNVERIFIABLE_RETRY)
                    m_unverifiable_votes.push_back(HeldVote{v, key});
                return;
            case GovSigCheck::Invalid:
                // forged / wrong key: never counted (and no longer clouding
                // the tally if it was held as unverifiable before)
                m_gov_store.clear_unverifiable_vote(v.parent_hash, key);
                note_vote_seen(v.vote_id);
                return;
        }
    }

    void note_vote_seen(const uint256& id) {
        if (id.IsNull() || !m_votes_seen.insert(id).second) return;
        m_votes_seen_order.push_back(id);
        while (m_votes_seen_order.size() > GOV_SEEN_CAP) {
            m_votes_seen.erase(m_votes_seen_order.front());
            m_votes_seen_order.pop_front();
        }
    }
    void note_object_seen(const uint256& id) {
        if (!m_objects_seen.insert(id).second) return;
        m_objects_seen_order.push_back(id);
        while (m_objects_seen_order.size() > GOV_SEEN_CAP) {
            m_objects_seen.erase(m_objects_seen_order.front());
            m_objects_seen_order.pop_front();
        }
    }

    bool has_orphan_yes(const uint256& parent) const {
        auto it = m_orphan_votes.find(parent);
        if (it == m_orphan_votes.end()) return false;
        for (const auto& h : it->second)
            if (h.v.outcome == VOTE_OUTCOME_YES) return true;
        return false;
    }

    void ingest_orphan_vote(const GovVoteContext& v, const std::string& key) {
        // LOW-6: a peer streaming orphan votes (parent unknown) gets a bounded
        // BLS budget and a bounded buffer per cycle; past either the votes are
        // dropped, never verified, and never turn into a blocker. Dropping is
        // safe: the unfunded verdict is already impossible while ANY trigger
        // for H is held, and a dropped vote of a trigger we later hold is
        // re-requested by the C4 legs.
        auto& budget = m_orphan_peer_budget[v.peer_key];
        // Only a BLS-shaped (96-byte) signature costs a pairing; anything else
        // (a proposal's 65-byte voting-key signature) is rejected for free.
        const bool bls_shaped = v.vch_sig.size() == 96;
        if ((bls_shaped && budget.verifies >= GOV_ORPHAN_VERIFY_BUDGET) ||
            budget.buffered >= GOV_MAX_ORPHANS_PER_PEER ||
            m_orphan_total >= GOV_MAX_ORPHAN_VOTES) {
            ++m_orphan_dropped;
            return;
        }
        if (bls_shaped) ++budget.verifies;
        const auto chk = check_vote(v);
        if (chk == GovSigCheck::Invalid) {               // proposal (ECDSA) votes land here
            note_vote_seen(v.vote_id);
            return;
        }
        m_orphan_votes[v.parent_hash].push_back(HeldVote{v, key, chk == GovSigCheck::Valid});
        ++m_orphan_total;
        ++budget.buffered;
        if (v.outcome != VOTE_OUTCOME_YES) return;
        // A (verified or not-yet-verifiable) masternode YES for a trigger we do
        // not hold. Keep a stronger existing record (pending/unparsed/full
        // carry the parent's height or block the cycle already).
        if (!m_gov_store.is_outstanding(v.parent_hash))
            m_gov_store.note_outstanding(v.parent_hash, GovOutstandingKind::OrphanYesVote, 0);
        if (m_on_object_fetch && m_fetched_parents.insert(v.parent_hash).second) {
            LOG_INFO << "[GOVSYNC] orphan FUNDING YES for unknown parent "
                     << v.parent_hash.GetHex().substr(0, 16)
                     << " — fetching the object (verdicts Unknown until it lands)";
            m_on_object_fetch(v.parent_hash);
        }
    }

    void replay_orphans_of(const uint256& parent) {
        auto it = m_orphan_votes.find(parent);
        if (it == m_orphan_votes.end()) return;
        auto held = std::move(it->second);
        m_orphan_total -= std::min(m_orphan_total, held.size());
        m_orphan_votes.erase(it);
        for (const auto& h : held) tally_vote(h.v, h.key);
    }

    void drop_orphans_of(const uint256& parent) {
        auto it = m_orphan_votes.find(parent);
        if (it == m_orphan_votes.end()) return;
        m_orphan_total -= std::min(m_orphan_total, it->second.size());
        m_orphan_votes.erase(it);
    }

    void hold_pending_object(const GovObjectContext& o) {
        for (auto& p : m_pending_objects)
            if (p.object_hash == o.object_hash) { p = o; return; }
        if (m_pending_objects.size() >= GOV_MAX_PENDING_OBJECTS) return; // record still blocks
        m_pending_objects.push_back(o);
    }
    void drop_pending_object(const uint256& h) {
        m_pending_objects.erase(
            std::remove_if(m_pending_objects.begin(), m_pending_objects.end(),
                           [&](const GovObjectContext& p) { return p.object_hash == h; }),
            m_pending_objects.end());
    }

    void note_proposal(const uint256& h) {
        if (!m_proposals.insert(h).second) return;
        m_proposal_order.push_back(h);
        while (m_proposal_order.size() > GOV_MAX_PROPOSALS) {
            m_proposals.erase(m_proposal_order.front());
            m_proposal_order.pop_front();
        }
    }
    bool is_proposal(const uint256& h) const { return m_proposals.count(h) != 0; }

    /// Re-run every held signature check (the DMN view or BLS backend may
    /// have caught up). Cheap: the buffers are bounded and a CannotVerify
    /// answer returns before any pairing.
    void retry_gov_pending() {
        // LOW-6: records held while the DMN view did not exist yet (startup:
        // every signer was unresolvable) but whose object did not fit the
        // buffer — once the view is current, ask for the object again by hash
        // so it is verified for real instead of blocking until cycle end.
        if (m_gov_view_current_fn && m_gov_view_current_fn() && m_on_object_fetch) {
            for (const auto& h : m_gov_store.outstanding_hashes(GovOutstandingKind::UnverifiedPending)) {
                bool held = false;
                for (const auto& p : m_pending_objects)
                    if (p.object_hash == h) { held = true; break; }
                if (held) continue;
                m_gov_store.clear_outstanding(h);
                m_on_object_fetch(h);
            }
        }
        if (!m_pending_objects.empty()) {
            auto pending = std::move(m_pending_objects);
            m_pending_objects.clear();
            for (const auto& o : pending) {
                if (m_gov_store.has_trigger(o.object_hash) || m_gov_store.is_erased(o.object_hash))
                    continue;
                ingest_trigger_object(o);
            }
        }
        if (!m_unverifiable_votes.empty()) {
            auto held = std::move(m_unverifiable_votes);
            m_unverifiable_votes.clear();
            for (const auto& h : held) {
                if (!m_gov_store.has_trigger(h.v.parent_hash)) continue;
                tally_vote(h.v, h.key);   // CannotVerify re-queues itself
            }
        }
        // Orphans held as not-yet-verifiable: settle them, and lift an
        // OrphanYesVote blocker whose only YES turned out Invalid.
        for (auto it = m_orphan_votes.begin(); it != m_orphan_votes.end();) {
            auto& bucket = it->second;
            for (auto h = bucket.begin(); h != bucket.end();) {
                if (h->verified) { ++h; continue; }
                const auto chk = check_vote(h->v);
                if (chk == GovSigCheck::Invalid) {
                    h = bucket.erase(h);
                    if (m_orphan_total > 0) --m_orphan_total;
                    continue;
                }
                if (chk == GovSigCheck::Valid) h->verified = true;
                ++h;
            }
            const uint256 parent = it->first;
            if (m_gov_store.outstanding_kind(parent) == GovOutstandingKind::OrphanYesVote &&
                !has_orphan_yes(parent))
                m_gov_store.clear_outstanding(parent);
            if (bucket.empty()) it = m_orphan_votes.erase(it);
            else ++it;
        }
    }

    /// C4: per-trigger vote re-sync for superblock height `sb_h` (never the
    /// nProp=0 full sync — dashd penalises repeats, net_governance.cpp
    /// 116-130). Also re-asks the parent of every orphan-YES record.
    void request_trigger_votes(uint32_t sb_h, const char* leg) {
        size_t n_votes = 0, n_fetch = 0;
        if (m_on_vote_resync) {
            for (const auto& h : m_gov_store.trigger_hashes_at(static_cast<int32_t>(sb_h))) {
                m_on_vote_resync(h);
                ++n_votes;
            }
        }
        if (m_on_object_fetch) {
            for (const auto& h : m_gov_store.orphan_yes_parents()) {
                m_on_object_fetch(h);
                ++n_fetch;
            }
        }
        LOG_INFO << "[GOVSYNC] C4 " << leg << " for superblock h=" << sb_h
                 << ": per-trigger vote re-sync x" << n_votes
                 << ", orphan-parent fetch x" << n_fetch
                 << " (triggers=" << m_gov_store.trigger_count()
                 << " outstanding=" << m_gov_store.outstanding_count() << ")";
    }

    /// Governance bookkeeping on EVERY connected block (after the R6/C5
    /// cross-check): prune executed/expired triggers (restart-resynced
    /// history included), retry held signature checks, and fire the C4
    /// re-syncs at H - maturity window and H - 1.
    void governance_on_block(uint32_t height) {
        // MED-5: keep a trigger resolvable GOV_REORG_KEEP blocks past its
        // height, so a reorg re-folding the superblock block resolves the
        // same verdict (and the C5/R6 cross-check cannot false-latch on it).
        if (height > static_cast<uint32_t>(GOV_REORG_KEEP))
            m_gov_store.prune_executed(static_cast<int32_t>(height) - GOV_REORG_KEEP);
        if (!m_sb_is_fn) return;
        retry_gov_pending();
        if (m_sb_maturity_window <= 0) return;
        const uint32_t win  = static_cast<uint32_t>(m_sb_maturity_window);
        const uint32_t lead = static_cast<uint32_t>(late_lead());
        if (m_sb_is_fn(height + win))
            request_trigger_votes(height + win, "A:H-maturity-window");
        if (lead != win && m_sb_is_fn(height + lead)) {
            // Leg B: fresh full-sync re-prime FIRST (re-opens every peer's
            // coverage proof), then the per-trigger vote re-sync.
            if (m_on_gov_reprime) m_on_gov_reprime();
            request_trigger_votes(height + lead, "B:H-late-lead");
        }
    }

    /// The superblock at `height` is connected: end the cycle's unknown-height
    /// bookkeeping, and lift a desync latch set in an EARLIER cycle — the
    /// latched cycle and the whole following one refused; the next cycle
    /// re-proves itself from a fresh view (MED-5).
    void end_gov_cycle(uint32_t height) {
        m_gov_store.prune_cycle();
        m_orphan_votes.clear();
        m_orphan_total = 0;
        m_orphan_peer_budget.clear();
        m_fetched_parents.clear();
        if (m_gov_desync_latched && height > m_gov_desync_height) {
            LOG_WARNING << "[GOVSYNC] superblock desync latch (set at h="
                        << m_gov_desync_height << ": " << m_gov_desync_reason
                        << ") LIFTED at h=" << height
                        << " — the next cycle must re-prove itself";
            m_gov_desync_latched = false;
            m_gov_desync_reason.clear();
        }
    }

    void latch_gov_desync(uint32_t height, const std::string& why) {
        LOG_WARNING << "[GOVSYNC] SUPERBLOCK DESYNC at h=" << height << " — " << why
                    << ". Clearing governance store + LATCHING the superblock "
                       "arm closed (every superblock height refuses until the "
                       "next cycle's superblock connects); re-issuing work.";
        m_gov_store.clear();
        m_gov_sync_status.reset();   // R5: a proven-wrong view is no
                                     // longer "complete"; force re-sync
        m_gov_desync_latched = true;
        m_gov_desync_reason = why;
        m_gov_desync_height = height;
        m_votes_seen.clear();
        m_votes_seen_order.clear();
        m_objects_seen.clear();
        m_objects_seen_order.clear();
        m_pending_objects.clear();
        m_unverifiable_votes.clear();
        // Transient invalidate + re-issue so any currently-published
        // template is rebuilt. The MN axis is a separate axis — if it
        // is healthy the arm re-publishes for NON-superblock heights;
        // superblock heights stay closed via the latch (Unknown
        // "trigger-latched" => resolve_superblock refuses).
        demote();
        notify_state_dirty();
    }

    /// dashcore CSuperblock::IsValid payment matching (Dash Core v24
    /// governance/superblock.cpp:296-333): every expected payment, IN ORDER,
    /// must find a (script, amount)-equal output at or after the previous
    /// match — from v24 strictly after it (each payment consumes a distinct
    /// output), before v24 at the previous index inclusive.
    static bool coinbase_carries_schedule(const dash::coin::MutableTransaction& cb,
                                          const std::vector<SuperblockPayment>& pays,
                                          bool v24) {
        int idx = -1;
        const int n = static_cast<int>(cb.vout.size());
        for (const auto& sp : pays) {
            bool found = false;
            const int start = v24 ? idx + 1 : std::max(idx, 0);
            for (int j = start; j < n; ++j) {
                const auto& out = cb.vout[j];
                if (out.value == sp.amount &&
                    out.scriptPubKey.m_data.size() == sp.script.size() &&
                    std::equal(sp.script.begin(), sp.script.end(),
                               out.scriptPubKey.m_data.begin())) {
                    idx = j;
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }
        return true;
    }

    /// C5 helper — the maximum block value (subsidy + fees) the accepted
    /// coinbase's OWN masternode payment admits, fee-free:
    ///   masternodeReward R = GetMasternodePayment(h, subsidy + fees)
    ///                      = (subsidy + fees) * 3 / 4        (payments.cpp
    ///                        96-101, every post-realloc era)
    /// and GetBlockTxOuts pays exactly R as [platform OP_RETURN P] + owner
    /// payouts / shares + operator (payments.cpp:131-199; the splits sum to
    /// R - P exactly). So R = P + sum(MN outputs), recognised by the projected
    /// payee's scripts and then RE-DERIVED and matched output-for-output with
    /// strict multiplicity. floor(3V/4) = R  =>  V <= (4R + 3) / 3.
    /// nullopt (with `why`) whenever any step cannot be proven.
    std::optional<int64_t> mn_derived_block_value_max(const dash::coin::BlockType& block,
                                                      uint32_t height,
                                                      std::string& why) const {
        namespace pay = vendor::payments;
        const auto& cb = block.m_txs[0];
        const int64_t P = dash::coin::compute_dash_platform_reward_post_v20_mn_rr(
            height, m_state.mn_rr_height());
        if (P <= 0) { why = "pre-evo-reward-era"; return std::nullopt; }
        const MnStateMachine& mns = std::as_const(m_state).mnstates();
        if (mns.last_applied_height() + 1 != height) {
            why = "mn-view-not-at-parent(" + std::to_string(mns.last_applied_height()) + ")";
            return std::nullopt;
        }
        const auto expected = mns.find_expected_payee();
        if (!expected) { why = "mn-payee-unresolved"; return std::nullopt; }
        auto eit = mns.entries().find(*expected);
        if (eit == mns.entries().end()) { why = "mn-payee-unresolved"; return std::nullopt; }
        const pay::DmnPayee payee = pay::dmn_payee_of(eit->second);

        std::vector<pay::CTxOut> actual;
        actual.reserve(cb.vout.size());
        for (const auto& o : cb.vout) actual.emplace_back(o.value, o.scriptPubKey.m_data);

        // Probe the payee's script set (amounts are irrelevant here; the probe
        // reward is large enough that no split rounds to zero and small enough
        // that operator/owner products stay inside int64).
        std::vector<pay::CTxOut> probe;
        pay::GetBlockTxOutsForPayee(&payee, /*masternodeReward=*/1'000'000'000'000LL, P,
                                    /*evo_reward_era=*/true, probe);
        std::map<pay::CScript, size_t> want;
        for (size_t i = 1; i < probe.size(); ++i) ++want[probe[i].scriptPubKey];
        int64_t mn_sum = 0;
        for (const auto& [script, n_expected] : want) {
            size_t n_found = 0;
            for (const auto& a : actual) {
                if (a.scriptPubKey != script) continue;
                ++n_found;
                mn_sum += a.nValue;
            }
            if (n_found > n_expected) {          // an MN script also used elsewhere
                why = "mn-script-ambiguous";
                return std::nullopt;
            }
        }
        const int64_t R = mn_sum + P;
        std::vector<pay::CTxOut> exact;
        pay::GetBlockTxOutsForPayee(&payee, R, P, /*evo_reward_era=*/true, exact);
        if (pay::FindUnmatchedMasternodePayment(exact, actual, /*strict_multiplicity=*/true) != -1) {
            why = "mn-outputs-unverified";
            return std::nullopt;
        }
        return (4 * R + 3) / 3;
    }

    /// C5 (reverse R6): our verdict at the superblock height `height` was
    /// NotTriggered, but did the network pay a superblock? dashd caps a
    /// not-triggered superblock height's coinbase at blockReward = subsidy +
    /// fees (payments.cpp:365-373); a triggered one may carry blockReward +
    /// the trigger total. Coinbase value above the MN-derived block-value
    /// ceiling therefore proves a superblock we called absent. Anything we
    /// cannot prove is treated as a desync too (fail closed).
    void reverse_check_not_triggered(const dash::coin::BlockType& block, uint32_t height) {
        std::string why;
        const auto vmax = mn_derived_block_value_max(block, height, why);
        int64_t total = 0;
        for (const auto& o : block.m_txs[0].vout) total += o.value;
        if (!vmax) {
            // MED-5: our OWN masternode view failing to re-derive the payment
            // (view not at the parent, a script shared with another output,
            // a projection the payee axis already disputes) is not evidence
            // about governance. Logged and counted, never latched: the latch
            // is reserved for positive evidence the network paid a superblock.
            ++m_c5_unverified;
            LOG_WARNING << "[GOVSYNC] superblock h=" << height << " NOT-TRIGGERED "
                        << "verdict could NOT be cross-checked against the accepted "
                        << "coinbase (" << why << "); not latched";
            return;
        }
        if (total > *vmax) {
            latch_gov_desync(height, "our verdict was NOT-TRIGGERED but the accepted "
                                     "coinbase pays " + std::to_string(total) +
                                     " > block value ceiling " + std::to_string(*vmax) +
                                     " (the network paid a superblock we did not see)");
            return;
        }
        LOG_INFO << "[GOVSYNC] superblock h=" << height << " NOT-TRIGGERED verdict "
                 << "confirmed by the accepted coinbase (value " << total
                 << " <= ceiling " << *vmax << ")";
    }

    // ── BODY-FIRST serve-tip machinery ───────────────────────────────────

    // ── PR-5: PUBLICATION HEIGHT of the credit pool ──────────────────────
    //
    // THE MECHANISM, from dashd v23.1.7. dashd has no single "current" credit
    // pool at all. CCreditPoolManager::GetCreditPool(block_index)
    // (src/evo/creditpool.cpp:224-239) DERIVES the pool FOR THE BLOCK YOU ASK
    // ABOUT, walking back to the nearest cached ancestor, and caches the
    // result keyed by that block's own hash+height
    // (creditpool.cpp:218 AddToCache(block_index->GetBlockHash(),
    // block_index->nHeight, pool), store at creditpool.h:115). Deriving the
    // pool at H therefore leaves the pool at H-1 exactly as available as it
    // was. Every consumer asks for the pool AT THE BLOCK IT IS BUILDING OR
    // VALIDATING ON, never "the newest one":
    //   * template  : CChainstateHelper::GetCreditPool passthrough
    //                 (evo/chainhelper.cpp:48-51), called with pindexPrev;
    //   * validation: GetCreditPoolDiffForBlock ->
    //                 cpoolman.GetCreditPool(pindexPrev)
    //                 (creditpool.cpp:325-333), and the connect-time path
    //                 CSpecialTxProcessor (evo/specialtxman.cpp:565)
    //                 GetCreditPool(pindex->pprev).
    // The committed balance of a block at height X is the pool at X-1 plus
    // that block's own deltas (specialtxman.cpp:745-755).
    //
    // WE have ONE published slot, and node_coin_state.hpp:1334-1340 measures
    // its height against the SERVE tip while node_coin_state.hpp:1096-1103
    // builds the next CbTx's creditPoolBalance from its VALUE. Writing that
    // slot at the BODY height while the serve tip is still H-1 (promotion
    // held on the fourth axis, :1820-1822) is therefore wrong twice over:
    //   1. the freshness gate reports `creditpool-stale` with value =
    //      threshold+1 -- the pool is AHEAD of the tip, never behind, which is
    //      why every one of the 48 measured episodes carried exactly +1;
    //   2. had the gate not refused, the template built on H-1 would have
    //      committed the pool at H -- the wrong base, a bad-cbtx block.
    // Publishing at the serve tip fixes both: the pool the arm serves from is
    // the pool at the block it builds on, which is what dashd does by
    // construction.
    //
    // Every credit-pool ADVANCE routes through here. The rollback paths
    // (reorg undo / cold wipe) write m_state directly and clear the pending
    // slot -- they move the seed to or below the tip, never above it.
    void publish_credit_pool_at(int64_t balance, const uint256& at_hash,
                                int32_t at_height) {
        const bool hold =
            m_cp_publish_at_serve_tip
            && m_body_first_serve_tip
            // No serve tip yet (cold start / post-demote): there is no tip for
            // the pool to run ahead OF, so publish, exactly as today.
            // NO DEADLOCK IS CLAIMED. An earlier revision of this comment said
            // holding here "would deadlock the arm"; that was not demonstrable
            // and is retracted -- every pending slot reachable from a cold
            // start is drained by the very next promotion, which matches it
            // via credit_pool_derived_at and publishes it in the same step.
            // What the conjunct actually buys is the INTERMEDIATE state: with
            // no serve tip the pool lands in the PUBLISHED slot rather than a
            // slot only a promotion can drain, so a node whose promotion is
            // held on another axis still has a published pool. That, and only
            // that, is what ColdStartPublishesImmediatelyWithPublicationHeightOn
            // asserts -- and it is red without this line.
            && m_have_tip
            && at_height > static_cast<int32_t>(m_prev_height);
        m_cp_pending_valid   = hold;
        m_cp_pending_balance = balance;
        m_cp_pending_hash    = at_hash;
        m_cp_pending_height  = at_height;
        if (hold) {
            LOG_INFO
                << "[CREDITPOOL] derived h=" << at_height
                << " HELD above the serve tip h=" << m_prev_height
                << " — publishing at the serve tip (dashd derives the pool at"
                   " pindexPrev; the template building on h=" << m_prev_height
                << " must commit the pool at h=" << m_prev_height << ")";
            return;
        }
        m_state.set_credit_pool(balance, at_hash, at_height);
    }

    /// Drop anything held (rollback paths: the branch it was derived on is
    /// gone, or the seed is being invalidated outright).
    ///
    /// NOT inert bookkeeping — MONEY PATH. The pending slot answers
    /// credit_pool_derived_at(), which IS the credit-pool promotion
    /// precondition, so a slot that survives a rollback lets the next
    /// promotion at that same hash/height publish the ORPHANED branch's
    /// balance. On the cold-wipe path (:942) that silently undoes the
    /// deliberate fail-closed write of (0, ZERO, -1) one line later.
    /// Covered red-on-mutation by ColdWipeDiscardsHeldPoolSoTheOrphanCannot-
    /// BeRepublished and ReorgUndoDiscardsHeldPoolDerivedAboveTheForkPoint —
    /// emptying this body turns both red (orphan pool republished at H, serve
    /// tip promoted onto it).
    void discard_held_credit_pool() { m_cp_pending_valid = false; }

    /// Is the credit pool DERIVED at exactly this block — published already,
    /// or held pending publication? This is the promotion precondition: what
    /// matters is that we HAVE the pool for that block, not which slot it is
    /// sitting in.
    bool credit_pool_derived_at(const uint256& at_hash, uint32_t at_height) const {
        if (m_cp_pending_valid
            && m_cp_pending_hash == at_hash
            && m_cp_pending_height == static_cast<int32_t>(at_height))
            return true;
        return m_state.credit_pool_current_hash() == at_hash
               && m_state.credit_pool_height() == static_cast<int32_t>(at_height);
    }

    /// Publish a HELD pool at the moment the serve tip becomes its block.
    /// Called from maybe_promote_pending_tip immediately before
    /// promote_serve_tip, so the publication and the serve-tip advance are one
    /// indivisible step on the single io thread — the same atomicity the whole
    /// body-first design rests on. A pending slot for a DIFFERENT block is
    /// left alone (it is not this tip's pool).
    void publish_held_credit_pool_at(const uint256& at_hash, uint32_t at_height) {
        if (!m_cp_pending_valid) return;
        if (m_cp_pending_hash != at_hash
            || m_cp_pending_height != static_cast<int32_t>(at_height))
            return;
        m_state.set_credit_pool(m_cp_pending_balance, m_cp_pending_hash,
                                m_cp_pending_height);
        m_cp_pending_valid = false;
    }

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

    /// Promote the pending header tip to the serve tip iff ALL FOUR derived
    /// axes are current AT that exact block (hash AND height — the hash match
    /// is what keeps a same-height competing block's body from promoting the
    /// wrong tip's params). This is the PUBLISH-LAST invariant that makes the
    /// serve tip atomic in the way dashcore's ConnectBlock is: dashd advances
    /// DML, quorums, credit pool and ChainLocks together inside one block-
    /// connect, so its getblocktemplate never sees the tip at height N with a
    /// derived axis at N-1. We advance each axis on its own network round trip
    /// (getmnlistd, qrinfo) or local fold, so they CAN momentarily disagree —
    /// and the gate exists to refuse rather than serve a wrong payee. Gating
    /// promotion on all four here means the serve tip is only ever published
    /// once they agree, which makes those refusals structurally unreachable in
    /// steady state instead of merely rare. The single io thread is the
    /// atomicity primitive — no lock, no event, no thread is added.
    ///
    /// The four axes, each a witness that the tip block's inputs were parsed:
    ///   1. credit-pool seed  (hash + height)   — body fold / mnlistdiff cbTx
    ///   2. payee cursor       (height)          — tip-body apply_block
    ///   3. SML currency       (hash)            — on_mnlistdiff (fourth axis,
    ///      added here; makes node_coin_state.hpp clause 12 `dmn-stale`
    ///      structurally unsatisfiable in steady state WITHOUT relaxing it)
    /// Returns true iff promotion happened; caller republishes.
    bool maybe_promote_pending_tip() {
        if (!m_body_first_serve_tip || !m_tip_body_pending) return false;
        // Every early return below records WHICH conjunct is the unmet one, so
        // a `tip-body-pending` refusal can say what it is waiting FOR. Static
        // literals only (NodeCoinState stores the pointer, never a copy).
        if (!m_have_hdr_tip) {
            m_state.set_tip_body_pending_axis("header-tip");
            return false;
        }
        // Credit-pool axis: the pool must be DERIVED at this exact block —
        // published already (flag off / at-or-below the serve tip), or HELD
        // pending publication (PR-5). Asking "do we have the pool for this
        // block" rather than "is the published slot at this block" is what
        // lets the publication ride the promotion instead of preceding it.
        if (!credit_pool_derived_at(m_hdr_prev_hash, m_hdr_prev_height)) {
            m_state.set_tip_body_pending_axis("credit-pool-seed");
            return false;
        }
        // The PAYEE axis must be current at the tip too (its cursor advances
        // in the tip-body apply_block, or a snapshot loaded as-of the tip):
        // promoting off a tip-targeted mnlistdiff that outraced the body
        // would advance the serve tip into a payee-stale refusal — trading
        // the removed creditpool-stale window for an identical one on the
        // payee axis. An EMPTY payee machine (pre-seed cold start, post-wipe)
        // has no cursor to be stale and does not hold promotion back — the
        // MN-readiness half of populated() already gates serving there.
        if (!m_state.mnstates().entries().empty()
            && m_state.mnstates().last_applied_height() != m_hdr_prev_height) {
            m_state.set_tip_body_pending_axis("payee-cursor");
            return false;
        }
        // ── FOURTH AXIS: the SML currency (dmn-stale, clause 12) ────────────
        // Folding the tip body we already hold cannot advance the SML — a cbTx
        // commits merkleRootMNList, and a root is not a list — so the currency
        // hash advances ONLY via on_mnlistdiff, on its own getmnlistd round
        // trip. Promoting before that lands would advance the serve tip into a
        // dmn-stale refusal, the exact window this conjunct removes.
        //
        // ZERO carve-out (cold start AND post-reorg-wipe, which the step-1
        // audit proved land the IDENTICAL uint256::ZERO sentinel, so they
        // collapse to one case — mirroring the empty-payee-machine carve-out
        // above). A ZERO currency hash is "the SML covers nothing", which the
        // require_sml half of populated() (surfacing as clause 10 no-dmn-set,
        // evaluated BEFORE clause 12) already gates. It must NOT hold promotion
        // back, or a cold node would DEADLOCK: the currency hash cannot become
        // the tip until a full snapshot lands, and nothing drives that if
        // promotion — and therefore the whole embedded arm — waited on it
        // first. Test: ColdSmlDoesNotBlockPromotion pins that a future reader
        // cannot "tighten" this into a cold-start deadlock.
        if (!m_state.sml_current_hash().IsNull()
            && m_state.sml_current_hash() != m_hdr_prev_hash) {
            m_state.set_tip_body_pending_axis("sml-currency");
            return false;
        }
        // PUBLISH-WITH-PROMOTION (PR-5): the held pool for this exact block
        // becomes the published pool in the same indivisible step that makes
        // the block the serve tip. No observer can see the pool at H with the
        // serve tip at H-1 — the creditpool-stale window is not shortened, it
        // ceases to have a state to exist in.
        publish_held_credit_pool_at(m_hdr_prev_hash, m_hdr_prev_height);
        promote_serve_tip();
        m_state.set_tip_body_pending_dbg(false);
        m_state.set_tip_body_pending_axis("");
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

        // ── DIFF-PHASE SUB-THRESHOLD (#1153 policy, wired here) ─────────────
        // LOAD-BEARING COMPANION to the fourth-axis conjunct, NOT an optional
        // extra: the conjunct now holds the tip body-pending whenever the SML
        // currency is behind the header tip. If that is because a getmnlistd
        // was never sent or never answered — p2p_client.hpp drops it SILENTLY
        // with no primary peer — then without a re-request the tip stays
        // pending until the 30 s hard demote below, and the conjunct will have
        // converted what used to be a LOUD instant dmn-stale refusal into up
        // to 30 s of QUIET H-1 serving. H-1 work solved past the propagation
        // window orphans, so the conjunct ALONE is a regression in the diff-
        // outage case; the conjunct + this re-request is the fix.
        //
        // Bounded by SmlResyncWatchdog (min_quiet ~4 s « the 30 s demote, so it
        // fires inside the silent window; geometric backoff; hard cap, after
        // which the demote takes over exactly as today). Target is the HEADER
        // tip, base is where the SML actually is — byte-identical to the
        // getmnlistd main_dash's tip-change path already sends, so the base-
        // continuity guard accepts the reply. (Deliberately the header tip, not
        // the serve tip m_prev_hash: we are DRIVING the SML forward to enable
        // promotion, not gating the current serve — the two diverge during a
        // body-pending window and only the header tip converges the conjunct.)
        if (m_on_sml_rerequest && m_have_hdr_tip
            && !m_state.sml_current_hash().IsNull()
            && m_state.sml_current_hash() != m_hdr_prev_hash) {
            if (auto req = m_sml_resync.observe(m_hdr_prev_hash,
                                                m_state.sml_current_hash(),
                                                m_now_fn())) {
                LOG_WARNING << "[EMB-DASH] SML behind tip h=" << m_hdr_prev_height
                            << " (currency ..."
                            << discriminating_hash_tail(m_state.sml_current_hash())
                            << " != tip ..." << discriminating_hash_tail(m_hdr_prev_hash)
                            << ") — re-requesting getmnlistd (attempt "
                            << req->attempt << ") before the doomed-tip demote";
                m_on_sml_rerequest(req->base, req->target);
            }
        }

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
        // DASHBOARD ONLY: publish the header-tip work bits for the daemonless
        // network-difficulty graph feed. Runs on the coin-p2p io thread; the
        // web/think thread reads it via published_bits_for_next() (atomic). Does
        // NOT touch NodeCoinState, so it respects the #1134 no-off-io-read rule.
        // Store only a real value: m_have_tip present and bits != 0. Absence is
        // never written, so the feed can never fabricate a difficulty.
        if (m_have_tip && m_bits_for_next != 0)
            m_published_bits_for_next.store(m_bits_for_next,
                                            std::memory_order_relaxed);
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
    // Vote-verify seam (unset = CannotVerify = never counted). Contract: BLS
    // by the MN's OPERATOR key for trigger funding votes — see
    // set_vote_verifier docs.
    std::function<GovSigCheck(const GovVoteContext&)> m_vote_check;
    // C3 trigger-object signature seam (unset = CannotVerify = never stored).
    std::function<GovSigCheck(const GovObjectContext&)> m_object_check;
    bool m_gov_testnet{false};       // chain-strict trigger address decode
    int  m_gov_min_quorum{0};        // chainparams nGovernanceMinQuorum (0 = unset => fail closed)
    bool m_gov_desync_latched{false};// R6/C5: proven-wrong governance view => never serve
    std::string m_gov_desync_reason; // why the latch fired
    std::function<bool(uint32_t)>    m_sb_is_fn;      // superblock-height predicate (R6)
    std::function<int64_t(uint32_t)> m_sb_budget_fn;  // superblock budget cap (duffs)
    int32_t m_sb_maturity_window{0};                  // C4: nSuperblockMaturityWindow
    std::function<void(const uint256&)> m_on_vote_resync;   // C4 per-trigger vote sync
    std::function<void(const uint256&)> m_on_object_fetch;  // orphan parent fetch
    // C5: the last height superblock_resolution() answered NotTriggered for
    // (written from the serve path's const call, read on block connect).
    mutable std::atomic<uint32_t> m_sb_not_triggered_served{0};
    // C3 held objects / votes awaiting a verifiable signer; C4 orphans.
    std::vector<GovObjectContext> m_pending_objects;
    std::vector<HeldVote> m_unverifiable_votes;
    std::map<uint256, std::vector<HeldVote>> m_orphan_votes;
    size_t m_orphan_total{0};
    struct OrphanBudget { size_t verifies{0}; size_t buffered{0}; };
    std::map<std::string, OrphanBudget> m_orphan_peer_budget;   // per peer, per cycle
    uint64_t m_orphan_dropped{0};
    uint64_t m_c5_unverified{0};
    uint64_t m_gov_votes_memo_hits{0};
    std::set<uint256> m_votes_seen;                // MED-3 settled-vote memo
    std::deque<uint256> m_votes_seen_order;
    std::set<uint256> m_objects_seen;              // processed objects (no R5 re-arm)
    std::deque<uint256> m_objects_seen_order;
    uint32_t m_gov_desync_height{0};
    bool m_not_triggered_enabled{false};           // MAINNET GATE (default OFF)
    std::function<void()> m_on_gov_reprime;        // leg B fresh nProp=0 re-prime
    std::function<bool()> m_gov_view_current_fn;   // DMN view folded the tip
    std::set<uint256> m_fetched_parents;     // orphan parents asked this cycle
    std::set<uint256> m_proposals;           // known proposal hashes (bounded)
    std::deque<uint256> m_proposal_order;
    uint64_t m_gov_triggers_seen{0};
    uint64_t m_gov_triggers_rejected{0};
    std::function<void()> m_on_state_dirty;  // SML/bestCL/reorg -> re-issue work
    std::function<void()> m_on_mn_reseed;    // payee desync -> authoritative protx re-seed
    ReseedReason m_last_reseed_reason{ReseedReason::None};   // F2: why the last ask fired
    std::optional<GapSeed> m_gap_seed;       // F2: the queue a GAP wiped (resume point)
    PayeeFoldedFn m_on_payee_folded;         // F3: clean fold -> live cursor persistence
    uint256  m_payee_cursor_hash;            // block folded at m_payee_cursor_hash_height
    uint32_t m_payee_cursor_hash_height{0};
    bool     m_fallback_armed{true};         // F4: wording only (daemonless = false)
    MnGapRepairFn m_mn_gap_repair;           // diff-store gap repair (mn_gap_repair.hpp); unset = historical fail-closed
    std::function<void()> m_on_full_resync;  // H-1 heal -> reset sml_base + full re-sync
    std::function<void(const uint256&, const uint256&)> m_on_sml_rerequest;  // SML-behind-tip -> bounded getmnlistd(base,target)
    // #1153 policy: bounds the getmnlistd re-request to at most a few attempts
    // per stuck (tip, sml) pair. min_quiet 4 s « the 30 s doomed-tip demote, so
    // it fires INSIDE the silent window the conjunct would otherwise open.
    SmlResyncWatchdog m_sml_resync{SmlResyncWatchdog::Config{
        /*min_quiet_sec=*/4, /*backoff_mult=*/2, /*max_attempts=*/3}};
    std::function<void(const uint256&)> m_on_sml_persist;  // accepted diff -> SMLDb/QuorumDb write
    std::function<void()> m_on_sml_clear;    // reorg/heal -> SMLDb/QuorumDb wipe (extended to CreditPoolDb)
    // qc-plan-underivable tee: accepted diff's full tail.newQuorums ->
    // MineableCommitmentCache admission (see set_on_new_quorum_commitments).
    std::function<void(const std::vector<vendor::CFinalCommitment>&)>
        m_on_new_quorum_commitments;
    ChainLockVerifyFn     m_chainlock_verify; // unset => live ChainLocks never adopted (fail closed)
    IslockVerifyFn        m_islock_verify;    // unset => isdlocks never adopted (fail closed, G4 stays dormant)
    DstxVerifyFn          m_dstx_verify;      // unset => DSTX-es never admitted (fail closed, W5-B stays dormant)
    // E2: independent DIP-0027 credit-pool accrual, advanced per ingested block
    // (on_block_connected) and re-anchored per accepted mnlistdiff. Verified
    // against each block's own from-wire cbTx; persisted via the hook below.
    CreditPool m_credit_pool_sm;
    std::function<void(const uint256&, uint32_t, int64_t)> m_on_credit_pool_persist;

    bool m_have_mn{false};
    bool m_have_tip{false};
    bool m_have_mn_sml{false};   // a non-empty SML has been applied (CCbTx source)
    // Which lane last populated the payee queue ("dashd-seed" / "mn-ckpt" /
    // "replay-fold" / "unnamed"). Diagnostic only — nothing branches on it —
    // but it is the difference between "this node serves" and "this node
    // serves WITHOUT a daemon", which no other field records.
    std::string m_mn_source;
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

    // DASHBOARD ONLY: header-tip work bits mirrored for the web/think thread's
    // network-difficulty graph feed. Written from republish() (coin-p2p io
    // thread), read via published_bits_for_next(). Atomic so the cross-thread
    // read needs no lock and never touches NodeCoinState (#1134 rule).
    std::atomic<uint32_t> m_published_bits_for_next{0};

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
    // PR-5 publication height. m_cp_pending_* holds a credit pool DERIVED for
    // a block above the serve tip until promotion publishes it (see
    // publish_credit_pool_at). Default OFF => the pending slot is never used
    // and every write goes straight through, byte-identical to header-first.
    bool    m_cp_publish_at_serve_tip{false};
    bool    m_cp_pending_valid{false};
    int64_t m_cp_pending_balance{0};
    uint256 m_cp_pending_hash;
    int32_t m_cp_pending_height{-1};
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
