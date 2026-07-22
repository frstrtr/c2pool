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
#include <impl/dash/coin/mn_state_machine.hpp>   // MNState
#include <impl/dash/coin/block.hpp>            // BlockType
#include <impl/dash/coin/transaction.hpp>        // MutableTransaction
#include <impl/dash/coin/vendor/smldiff.hpp>     // vendor::CSimplifiedMNListDiff + apply_diff
#include <impl/dash/coin/vendor/quorum_tail.hpp> // vendor::parse_quorum_tail
#include <impl/dash/coin/vendor/cbtx.hpp>        // vendor::parse_cbtx (bestCL*/creditPool seed)

#include <core/uint256.hpp>
#include <core/log.hpp>

#include <array>
#include <cstdint>
#include <functional>
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
        // Wipe the PERSISTED SML/quorum stores too. The on-disk state is now for
        // an orphaned branch; it is self-consistent so the root-verify on the
        // next restart WOULD pass and serve a wrong-branch template. Clearing it
        // forces a cold full-snapshot re-sync (main_dash points this at
        // SMLDb::clear + QuorumDb::clear; unset in KATs = no-op).
        if (m_on_sml_clear) m_on_sml_clear();
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
        m_have_mn = m_state.mnstates().size() != 0;
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

    /// True iff both prerequisites are met AND the holder is currently live.
    bool live() const { return m_state.populated(); }

private:
    void notify_state_dirty() {
        if (m_on_state_dirty) m_on_state_dirty();
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
    std::function<void()> m_on_state_dirty;  // SML/bestCL/reorg -> re-issue work
    std::function<void()> m_on_full_resync;  // H-1 heal -> reset sml_base + full re-sync
    std::function<void(const uint256&)> m_on_sml_persist;  // accepted diff -> SMLDb/QuorumDb write
    std::function<void()> m_on_sml_clear;    // reorg/heal -> SMLDb/QuorumDb wipe

    bool m_have_mn{false};
    bool m_have_tip{false};
    bool m_have_mn_sml{false};   // a non-empty SML has been applied (CCbTx source)

    // Height the last MN-set snapshot was current at (0 = none/unknown);
    // on_block_connected skips re-applying blocks at or below it.
    uint32_t m_mn_snapshot_height{0};

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
