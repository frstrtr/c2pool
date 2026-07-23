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
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

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
    ///   1. Look the voting MN up by its COLLATERAL OUTPOINT in the valid
    ///      deterministic MN set at verify time (unknown MN => reject). Note
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
        if (v.outcome != VOTE_OUTCOME_YES && v.outcome != VOTE_OUTCOME_NO &&
            v.outcome != VOTE_OUTCOME_ABSTAIN)
            return;                                             // dashcore IsValid outcome range
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
        m_have_mn = !mnstates.empty();
        m_mn_snapshot_height = as_of_height;
        // An authoritative (non-empty) resync clears the payee-desync latch:
        // the queue is trustworthy again from this snapshot forward.
        if (m_have_mn)
            m_mn_needs_reseed = false;
        m_state.mnstates().load(std::move(mnstates));
        if (!m_have_mn)
            demote();
        else
            republish();
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

        // 1) SML (merkleRootMNList). apply_diff erases deletedMNs, upserts
        //    diff.mnList, and re-sorts by proRegTxHash (memcmp order — the
        //    Bug-A-critical ordering, already pinned by test_dash_simplifiedmns).
        auto sml_r = vendor::apply_diff(m_state.sml(), diff);

        // 2) Quorum set (merkleRootQuorums) — tail already parsed clean above.
        auto qr = m_state.qmgr().apply(qt);
        const size_t q_added = qr.added_or_updated;
        const size_t q_deleted = qr.deleted;
        m_state.set_quorum_healthy(true);

        // 3) bestCL* + creditPool: the diff's embedded cbTx is the coinbase of
        //    diff.blockHash and its extra_payload is the authoritative type-5
        //    CCbTx for that height. Seed the fields the roots don't carry so the
        //    next template's CCbTx matches dashd. Fails SAFE (leaves prior seed).
        if (diff.cbTx.type == 5 && !diff.cbTx.extra_payload.empty()) {
            vendor::CCbTx observed;
            if (vendor::parse_cbtx(diff.cbTx.extra_payload, observed)) {
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
                            m_state.set_best_cl(best_h, observed.bestCLSignature);
                    }
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

    /// ChainLock reception: adopt the freshly-observed ChainLock as the best CL
    /// for the CCbTx bestCL* fields. The clsig message carries {height,
    /// block_hash, 96-byte recovered threshold sig}. Only advances forward.
    void on_new_chainlock(int32_t height,
                          const std::array<uint8_t, 96>& sig) {
        if (height > m_state.best_cl_height()) {
            m_state.set_best_cl(height, sig);
            // A fresher bestCL* changes the next template's committed CCbTx —
            // re-issue work so the served template carries the new ChainLock.
            notify_state_dirty();
        }
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
        // Invalidate the credit-pool seed's freshness too (height -1 != any tip),
        // so the arm fails closed on the credit-pool axis until a fresh re-seed.
        m_state.set_credit_pool(0, uint256::ZERO, -1);
        // E2: wipe the independent running accrual as well — its balance was built
        // on the now-orphaned branch. It re-bootstraps from the first post-reorg
        // block's / full-snapshot's authoritative cbTx (never a stale carry-over).
        m_credit_pool_sm.clear();
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
        return m_state.mempool().add_tx(tx);
    }

    /// Header / think path: the chain tip advanced. Stash the params the
    /// embedded template needs and mark tip-readiness, then republish if the
    /// MN list is also ready. curtime/version left 0 defer to
    /// build_embedded_workdata()'s own SAFE-ADDITIVE defaults.
    void on_new_tip(uint32_t prev_height, const uint256& prev_hash,
                    uint32_t bits_for_next, uint32_t mtp_at_tip,
                    uint8_t address_version, uint8_t address_p2sh_version,
                    uint32_t curtime = 0, uint32_t version = 0) {
        m_prev_height          = prev_height;
        m_prev_hash            = prev_hash;
        m_bits_for_next        = bits_for_next;
        m_mtp_at_tip           = mtp_at_tip;
        m_address_version      = address_version;
        m_address_p2sh_version = address_p2sh_version;
        m_curtime              = curtime;
        m_version              = version;
        m_have_tip             = true;
        republish();
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
        if (r.payee_desync) {
            LOG_WARNING << "[EMB-DASH] MN payee queue DESYNC at h=" << height
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
            demote();
            notify_state_dirty();
            if (m_on_mn_reseed) m_on_mn_reseed();
            return r;
        }
        m_have_mn = !m_mn_needs_reseed && m_state.mnstates().size() != 0;
        if (!m_have_mn)
            demote();
        else
            republish();
        return r;
    }

    /// Reorg / MN-list gap / mempool flush: invalidate the live bundle so the
    /// next get_work falls back to dashd until a fresh tip rebuilds it. The
    /// stashed tip params are dropped -- a reorg means the old prev_hash is no
    /// longer the tip, so we must NOT auto-republish it; a subsequent
    /// on_new_tip() re-arms tip-readiness. The MN list (which survives a mere
    /// reorg) is left in place.
    void on_invalidate() {
        m_have_tip = false;
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

    /// Wire the authoritative MN re-seed sink (main_dash points this at the
    /// E2c `protx list valid true` seed fetch when a coin RPC is configured).
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

    // Publish only when both prerequisites are present; otherwise leave the
    // holder in whatever (un)published state it is in -- callers reach demote()
    // explicitly for the invalidating transitions.
    void republish() {
        if (m_have_tip && m_have_mn)
            m_state.set_tip(m_prev_height, m_prev_hash, m_bits_for_next,
                            m_mtp_at_tip, m_address_version, m_address_p2sh_version,
                            m_curtime, m_version);
    }

    void demote() {
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
    // E2: independent DIP-0027 credit-pool accrual, advanced per ingested block
    // (on_block_connected) and re-anchored per accepted mnlistdiff. Verified
    // against each block's own from-wire cbTx; persisted via the hook below.
    CreditPool m_credit_pool_sm;
    std::function<void(const uint256&, uint32_t, int64_t)> m_on_credit_pool_persist;

    bool m_have_mn{false};
    bool m_have_tip{false};
    bool m_have_mn_sml{false};   // a non-empty SML has been applied (CCbTx source)

    // Height the last MN-set snapshot was current at (0 = none/unknown);
    // on_block_connected skips re-applying blocks at or below it.
    uint32_t m_mn_snapshot_height{0};

    // Payee-desync latch: set when on_block_connected wiped a desynced payee
    // queue; only a non-empty on_mn_list_update resync clears it. While set,
    // MN-readiness must not re-arm off incidental per-block registrations.
    bool m_mn_needs_reseed{false};

    // Last observed tip params, applied on republish().
    uint32_t m_prev_height{0};
    uint256  m_prev_hash;
    uint32_t m_bits_for_next{0};
    uint32_t m_mtp_at_tip{0};
    uint8_t  m_address_version{0};
    uint8_t  m_address_p2sh_version{0};
    uint32_t m_curtime{0};
    uint32_t m_version{0};
};

} // namespace coin
} // namespace dash
