// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Phase C-TEMPLATE step 6 (S8 embedded_gbt live-wire, follow-on to #672):
/// the node-held embedded coin-state bundle that flips select_dash_work()'s
/// hot arm live.
///
/// #672 landed select_dash_work() (work_source.hpp) as the stable branch
/// point, but every caller still presents has_state=false, so 100% of the
/// running node's get_work path routes to the retained dashd
/// getblocktemplate fallback. This holder is the in-process coin-state the
/// DASH node maintains as mnlistdiff / mempool / header-tip updates arrive --
/// masternode list + mempool + header-tip params. make_embedded_work_inputs()
/// presents it as a viable() EmbeddedWorkInputs so select_dash_work() takes
/// the oracle-parity embedded path (build_embedded_workdata, pinned by
/// test_dash_embedded_gbt vs frstrtr/p2pool-dash getwork()).
///
/// STRICTLY single-coin: src/impl/dash/ only, no bitcoin_family / src/core
/// reach. The external-daemon (dashd RPC) arm is NEVER removed -- populated()
/// == false always routes there, and it remains the [GBT-XCHECK] cross-check.

#include <impl/dash/coin/work_source.hpp>        // EmbeddedWorkInputs, select_dash_work, WorkSelection
#include <impl/dash/coin/mn_state_machine.hpp>   // MnStateMachine
#include <impl/dash/coin/mempool.hpp>            // Mempool
#include <impl/dash/coin/rpc_data.hpp>           // DashWorkData
#include <impl/dash/coin/quorum_manager.hpp>     // QuorumManager (merkleRootQuorums source)
#include <impl/dash/coin/quorum_root.hpp>        // compute_merkle_root_quorums (pre-emit recompute)
#include <impl/dash/coin/vendor/simplifiedmns.hpp> // vendor::CSimplifiedMNList (merkleRootMNList source)
#include <impl/dash/coin/vendor/cbtx.hpp>        // vendor::parse_cbtx (pre-emit CbTx self-check)
#include <impl/dash/coin/subsidy.hpp>            // compute_dash_platform_reward_post_v20_mn_rr (creditPool re-check)

#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <functional>

namespace dash {
namespace coin {

/// In-process coin-state the running node maintains for LOCAL template
/// assembly. Non-copyable: it owns a Mempool (itself non-copyable) and is
/// node-owned, never duplicated. The maintainer mutates mnstates()/mempool()
/// in place and calls set_tip() once the tip advances; get_work reads it
/// through select_work().
class NodeCoinState {
public:
    NodeCoinState() = default;
    NodeCoinState(const NodeCoinState&) = delete;
    NodeCoinState& operator=(const NodeCoinState&) = delete;

    // Mutable accessors for the maintainer (the reception / think slices seed
    // these from mnlistdiff + relayed mempool txs).
    MnStateMachine& mnstates() { return m_mnstates; }
    Mempool&        mempool()  { return m_mempool; }

    // ── SML / quorum consensus-commitment state (daemonless CCbTx) ────────
    // The deterministic MN list + LLMQ quorum set the CCbTx extra_payload
    // commits to. Populated by CoinStateMaintainer::on_mnlistdiff (apply_diff
    // + QuorumManager::apply) off the live coin-P2P mnlistdiff feed. These are
    // the merkleRootMNList / merkleRootQuorums sources build_embedded_workdata
    // needs to emit a MAINNET-VALID type-5 coinbase. Persisted across restarts
    // by SMLDb/QuorumDb (sml_quorum_db.hpp): main_dash warms these on startup
    // from the last root-verified state and requests an INCREMENTAL
    // mnlistdiff(persisted-tip, tip) rather than a cold mnlistdiff(zero, tip);
    // a corrupt/stale store fails closed to the cold path.
    vendor::CSimplifiedMNList& sml() { return m_sml; }
    QuorumManager&             qmgr() { return m_qmgr; }
    const vendor::CSimplifiedMNList& sml() const { return m_sml; }
    const QuorumManager&             qmgr() const { return m_qmgr; }

    /// Mark whether a valid SML is present (set by the maintainer after the
    /// first accepted mnlistdiff yields a non-empty list). When require_sml
    /// is enabled (the mainnet / DIP-0004 posture), viability additionally
    /// requires this — the embedded arm must NOT serve a template with an
    /// empty/absent CCbTx (that block would be consensus-invalid).
    void set_have_sml(bool v) { m_have_sml = v; }
    bool have_sml() const { return m_have_sml; }

    /// The block hash the applied SML is CURRENT AT (== the last accepted
    /// mnlistdiff's blockHash; ZERO before the first diff / after a reorg wipe).
    /// Under require_sml, template viability additionally requires this to equal
    /// the tip we are building on (prev_hash) — so during the tip-change ->
    /// getmnlistd round-trip, before the fresh diff lands, the embedded arm
    /// serves nothing (H-6: no stale-SML template at a moved tip; fail to the
    /// dashd fallback until the SML catches up to the new tip).
    void set_sml_current_hash(const uint256& h) { m_sml_current_hash = h; }
    const uint256& sml_current_hash() const { return m_sml_current_hash; }

    /// Seed the version-appropriate CCbTx fields the SML/quorum roots do not
    /// carry: the best-ChainLock height+signature and the DIP-0027 credit-pool
    /// balance. Sourced by the maintainer from the diff's embedded cbTx (the
    /// authoritative wire form as-of blockHash) and from new_chainlock events.
    void set_best_cl(int32_t height, const std::array<uint8_t, 96>& sig) {
        m_best_cl_height = height;
        m_best_cl_sig    = sig;
    }
    /// Seed the DIP-0027 credit-pool balance, its block hash, AND its HEIGHT.
    /// The seed rides a SEPARATE on_mnlistdiff step (the diff's embedded cbTx)
    /// from the SML/merkleRoot axis and can LAG one block while the SML is already
    /// at the tip (re-soak bad-cbtx-assetlocked-amount). at_height is the seed
    /// cbTx's OWN nHeight (authoritative off the wire) — the block the balance is
    /// current after. The freshness gate keys on this HEIGHT vs the tip
    /// (m_prev_height): an INDEPENDENT check. A hash tag or a value self-check
    /// cannot catch a seed one block behind — its built value is stale_seed +
    /// reward, self-consistent but wrong; comparing the seed's own height to the
    /// tip does. (3 consecutive soaks refuted the hash- and value-self-checks.)
    void set_credit_pool(int64_t balance, const uint256& at_hash, int32_t at_height) {
        m_credit_pool = balance;
        m_credit_pool_current_hash = at_hash;
        m_credit_pool_height = at_height;
    }
    int32_t best_cl_height() const { return m_best_cl_height; }
    int64_t credit_pool() const { return m_credit_pool; }
    const uint256& credit_pool_current_hash() const { return m_credit_pool_current_hash; }
    int32_t credit_pool_height() const { return m_credit_pool_height; }

    /// MN-payee freshness gate (E4 re-soak fix, bad-cb-payee at 1519827).
    /// The projected masternode payee for height prev+1 is only dashd-exact
    /// when the payee queue (MnStateMachine) has folded EVERY block through
    /// the tip we build on: dashd computes GetMNPayee(pindexPrev) on the
    /// list that connected pindexPrev. When enabled, viability + the
    /// pre-emit gate require mnstates().last_applied_height() == prev_height
    /// (the load(as_of) seed counts as "folded through as_of"). A queue
    /// still catching up — the soak's seed-at-1519820 serving 1519823..27,
    /// or a tip header that outran its full block — fails closed to the
    /// reward-safe dashd fallback instead of serving a stale-cursor payee.
    /// Default OFF preserves prior unit-test posture.
    void set_require_fresh_mn_payee(bool v) { m_require_fresh_mn_payee = v; }

    /// creditPool freshness gate (soak fix). dashcore CheckCreditPoolDiffForBlock
    /// rejects a block whose committed creditPoolBalance is off by a block's
    /// accrual (bad-cbtx-assetlocked-amount). When enabled, viability + the
    /// pre-emit gate require the credit-pool seed to be current AT the tip
    /// (credit_pool_current_hash == prev_hash); a lagged seed fails closed to the
    /// reward-safe dashd fallback. Default OFF preserves prior unit-test posture.
    void set_require_fresh_credit_pool(bool v) { m_require_fresh_credit_pool = v; }

    /// Network MN_RR activation height (dashcore Params().GetConsensus()
    /// .MN_RRHeight — per-chainparams). Gates the DIP-0027 platform-share
    /// credit-pool accrual in the template build, the pre-emit value re-check,
    /// and the per-block advance. main_dash sets the testnet value; the
    /// mainnet default keeps every existing caller byte-unchanged. E4 re-soak
    /// fix: leaving the MAINNET constant in force on testnet zeroes the
    /// platform reward and biases every committed creditPoolBalance low by
    /// exactly one block's platform reward (constant 66,966,830 duffs).
    void set_mn_rr_height(int h) { m_mn_rr_height = h; }
    int mn_rr_height() const { return m_mn_rr_height; }

    /// Enable the SML-required viability gate. main_dash.cpp turns this on for
    /// the embedded coin-P2P arm so a template is only served once the CCbTx
    /// commitment inputs are present (review finding H3: no mid-sync half-built block).
    /// Default OFF preserves the pre-CCbTx KAT/testnet posture byte-for-byte.
    void set_require_sml(bool v) { m_require_sml = v; }

    /// Record the header-tip parameters and mark the bundle live. Call after
    /// the tip advances AND the MN list + mempool are seeded; until then the
    /// selector must route to the dashd fallback. curtime/version left 0 use
    /// build_embedded_workdata()'s own SAFE-ADDITIVE defaults.
    void set_tip(uint32_t prev_height, const uint256& prev_hash,
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
        m_populated            = true;
    }

    /// Invalidate the bundle (reorg / mempool flush / MN list gap) so the next
    /// get_work falls back to dashd until the state is rebuilt.
    void invalidate() { m_populated = false; }

    bool populated() const { return m_populated; }

    /// Coinbase-maturity mining gate (E2b/#738) — the dash analog of the LTC
    /// EmbeddedCoinNode::set_utxo_ready_fn (main_ltc.cpp ~1785-1801). When
    /// set, embedded-template viability additionally requires the predicate
    /// (UtxoLane::mining_utxo_ready: blocks_connected >= 106) so templates
    /// cannot include txs spending immature coinbase outputs; until then
    /// has_state stays false and get_work routes to the retained dashd
    /// fallback. Unset (default) preserves the pre-E2b behaviour exactly.
    void set_utxo_ready_fn(std::function<bool()> fn) {
        m_utxo_ready_fn = std::move(fn);
    }

    /// Superblock-height guard. On a Dash superblock height the coinbase MUST
    /// pay the governance/treasury (superblock) outputs; the embedded template
    /// does not compute those, so emitting a normal coinbase there is a
    /// consensus-invalid (bad-superblock) block. When set, viability refuses the
    /// embedded arm for a next-block height the predicate flags as a superblock,
    /// routing get_work to the reward-safe dashd fallback (which returns the
    /// correct superblock template). main_dash supplies the network-aware cycle.
    /// The predicate takes the NEXT block height (prev_height + 1). Unset
    /// (default) preserves prior behaviour exactly.
    void set_is_superblock_fn(std::function<bool(uint32_t)> fn) {
        m_is_superblock_fn = std::move(fn);
    }

    /// DKG mining-phase guard (review PR #780 BLOCKER-1, CRITICAL). On a height
    /// where a quorum commitment (type-6) is required in-block, the embedded arm
    /// cannot produce a valid block: it strips all special txs (so it omits the
    /// mandatory commitment => bad-qc-missing) AND computes merkleRootQuorums
    /// without the current block's commitments (=> wrong root). When the
    /// predicate flags the next-block height as a commitment window, viability
    /// refuses the embedded arm and get_work routes to the reward-safe dashd
    /// fallback (which builds the correct qc block). The predicate takes the NEXT
    /// block height (prev_height + 1). Unset (default) preserves prior behaviour.
    void set_commitment_window_fn(std::function<bool(uint32_t)> fn) {
        m_commitment_window_fn = std::move(fn);
    }

    /// bestCL freshness guard (review PR #780 BLOCKER-2, HIGH). dashcore
    /// CheckCbTxBestChainlock rejects a block whose committed bestCLSignature is
    /// null or older than the previous block's committed ChainLock
    /// (bad-cbtx-null-clsig / -older-clsig), and the arm cannot self-verify BLS.
    /// When enabled, viability requires the best observed ChainLock height to be
    /// within one block of the tip (best_cl_height >= prev_height - 1) — a
    /// sufficient condition: the previous block's committed ChainLock height is
    /// <= prev_height - 1, so a CL that fresh is guaranteed non-null and >= it.
    /// If we have not observed a recent clsig (post-restart / relay gap) the arm
    /// fails closed to the dashd fallback. Default OFF preserves prior behaviour.
    void set_require_fresh_bestcl(bool v) { m_require_fresh_bestcl = v; }

    /// Quorum-set health (review PR #780 nit): parse_quorum_tail fails SAFE (keeps
    /// SML sync, skips quorum tracking). On a malformed tail the QuorumManager is
    /// left STALE while the SML advances, so merkleRootQuorums would be computed
    /// over the wrong set with no other viability signal. The maintainer sets
    /// this false when a diff's quorum tail fails to parse; viability then refuses
    /// the embedded arm. Default true (an empty tail parses fine).
    void set_quorum_healthy(bool v) { m_quorum_healthy = v; }
    bool quorum_healthy() const { return m_quorum_healthy; }

    /// BLOCKER-3 pre-emit HARD GATE. Before the embedded arm's template is
    /// served/mined, re-validate the BUILT CbTx against consensus invariants;
    /// any failure => the caller must fall back to the reward-safe dashd path.
    /// This is the active safety cross-check on the hot path (the shadow
    /// gbt_xcheck/cbtx_xcheck only run in run_mine_block/tests). Checks:
    ///   - height-class guards re-asserted (superblock / DKG commitment window /
    ///     bestCL freshness) — defence in depth even if viability was bypassed;
    ///   - the payload is a parseable CCbTx at nHeight == prev+1;
    ///   - both merkle roots re-derived from the current SML/QuorumManager match
    ///     the committed roots (catches encode/plumb drift);
    ///   - a non-null ChainLock is committed when freshness is required.
    /// Only enforced under the require_sml (embedded/CCbTx) posture; the legacy
    /// empty-payload posture is unchanged.
    bool embedded_template_emit_ok(const DashWorkData& w) const {
        if (!m_require_sml) return true;
        // Symmetry with viability (review PR #780 nit): a stale quorum set must
        // never reach emit. (Under the H-1 heal this is already gated by
        // have_sml=false, but re-asserting keeps the defence-in-depth uniform.)
        if (!m_quorum_healthy) return false;
        const uint32_t next_h = m_prev_height + 1;
        if (m_is_superblock_fn && m_is_superblock_fn(next_h)) return false;
        if (m_commitment_window_fn && m_commitment_window_fn(next_h)) return false;
        if (m_require_fresh_bestcl
            && m_best_cl_height < static_cast<int32_t>(m_prev_height) - 1)
            return false;
        // SOAK FIX (independent HEIGHT check): the credit-pool seed's OWN cbTx
        // height must be the tip we build on, else the accrual commits a stale
        // creditPoolBalance (bad-cbtx-assetlocked-amount). Independent of the
        // seed's value/hash — the only check that catches a one-block-behind seed.
        if (m_require_fresh_credit_pool
            && m_credit_pool_height != static_cast<int32_t>(m_prev_height))
            return false;
        // E4 re-soak fix: the payee queue must have folded every block
        // through the tip this template builds on, else the projected
        // masternode payee is a stale queue slot (bad-cb-payee). Re-assert
        // at emit so a cached template built before the queue lagged (or a
        // viability bypass) can never reach a miner.
        if (m_require_fresh_mn_payee
            && m_mnstates.last_applied_height() != m_prev_height)
            return false;
        vendor::CCbTx cb;
        if (!vendor::parse_cbtx(w.m_coinbase_payload, cb)) return false;
        if (cb.nHeight != static_cast<int32_t>(next_h)) return false;
        auto sml_copy = m_sml;
        if (cb.merkleRootMNList != sml_copy.CalcMerkleRoot()) return false;
        if (cb.merkleRootQuorums != compute_merkle_root_quorums(m_qmgr)) return false;
        if (m_require_fresh_bestcl && !cb.has_best_cl_signature()) return false;
        // SOAK RE-FIX (build-vs-serve skew): re-derive the expected creditPool
        // from the CURRENT seed at emit/serve time and require the BUILT CbTx to
        // commit exactly that — mirroring the merkle-root re-derivation above.
        // The prior hash-tag proxy (credit_pool_current_hash == prev_hash) passed
        // while a CACHED template still carried a stale creditPoolBalance built
        // from an older seed; this VALUE check catches it (the seed baked into
        // the cached CbTx no longer matches m_credit_pool + this block's reward).
        // Uses the SAME accrual build_embedded_workdata does, so it is a pure
        // seed-delta check (the platform reward cancels): built == current seed.
        if (m_require_fresh_credit_pool) {
            const int64_t expected_credit_pool =
                m_credit_pool
                + compute_dash_platform_reward_post_v20_mn_rr(next_h,
                                                              m_mn_rr_height);
            if (cb.creditPoolBalance != expected_credit_pool) return false;
        }
        return true;
    }

    /// Assemble the selector input. has_state is populated() gated by the
    /// optional UTXO-maturity predicate; the two required pointers are always
    /// non-null (members), so viable() reduces to that gate -- exactly the
    /// semantics work_source.hpp documents.
    EmbeddedWorkInputs make_embedded_work_inputs() const {
        EmbeddedWorkInputs e;
        e.has_state            = m_populated
                                 && (!m_utxo_ready_fn || m_utxo_ready_fn())
                                 && (!m_is_superblock_fn
                                     || !m_is_superblock_fn(m_prev_height + 1))
                                 // BLOCKER-1: refuse DKG commitment-window heights.
                                 && (!m_commitment_window_fn
                                     || !m_commitment_window_fn(m_prev_height + 1))
                                 // BLOCKER-2: refuse a stale/absent bestCL.
                                 && (!m_require_fresh_bestcl
                                     || m_best_cl_height
                                            >= static_cast<int32_t>(m_prev_height) - 1)
                                 // SOAK FIX (independent HEIGHT check): refuse a
                                 // credit-pool seed whose OWN cbTx height is not
                                 // the tip we build on — catches a seed lagging by
                                 // a block even when its (self-consistent) value
                                 // and hash-tag look fresh (bad-cbtx-assetlocked-amount).
                                 && (!m_require_fresh_credit_pool
                                     || m_credit_pool_height
                                            == static_cast<int32_t>(m_prev_height))
                                 // E4 re-soak fix (bad-cb-payee at 1519827):
                                 // refuse a payee queue that has not folded
                                 // every block through the tip we build on —
                                 // its projected payee is a stale queue slot
                                 // (dashd-exact projection requires
                                 // GetMNPayee on the list that connected
                                 // pindexPrev).
                                 && (!m_require_fresh_mn_payee
                                     || m_mnstates.last_applied_height()
                                            == m_prev_height)
                                 && (!m_require_sml
                                     || (m_have_sml
                                         && m_quorum_healthy
                                         && m_sml_current_hash == m_prev_hash));
        e.prev_height          = m_prev_height;
        e.prev_hash            = m_prev_hash;
        e.mnstates             = &m_mnstates;
        e.mempool              = &m_mempool;
        e.bits_for_next        = m_bits_for_next;
        e.mtp_at_tip           = m_mtp_at_tip;
        e.address_version      = m_address_version;
        e.address_p2sh_version = m_address_p2sh_version;
        e.curtime              = m_curtime;
        e.version              = m_version;
        e.mn_rr_height         = m_mn_rr_height;
        // CCbTx seams: pass the SML + quorum set ONLY when present, so a
        // legacy/testnet-without-SML bundle still builds the pre-CCbTx template
        // (empty payload) byte-for-byte, while a live daemonless bundle emits
        // the real type-5 coinbase. build_embedded_workdata folds these into
        // build_embedded_cbtx (merkleRootMNList + merkleRootQuorums + bestCL* +
        // creditPool) when both pointers are non-null.
        if (m_have_sml) {
            e.sml              = &m_sml;
            e.qmgr             = &m_qmgr;
            e.best_cl_height   = m_best_cl_height;
            e.best_cl_sig      = m_best_cl_sig;
            e.credit_pool      = m_credit_pool;
        }
        return e;
    }

    /// Live get_work entry point: prefer the locally-assembled embedded
    /// template when this bundle is populated, else the supplied dashd
    /// getblocktemplate fallback. Thin wrapper over select_dash_work() so the
    /// node call site is one line. dashd_fallback is REQUIRED -- it is the
    /// always-reachable safety path and the cross-check arm.
    WorkSelection select_work(
        const std::function<DashWorkData()>& dashd_fallback) const {
        return select_dash_work(make_embedded_work_inputs(), dashd_fallback);
    }

private:
    MnStateMachine m_mnstates;
    Mempool        m_mempool;
    vendor::CSimplifiedMNList m_sml;         // merkleRootMNList source (mnlistdiff-fed)
    QuorumManager  m_qmgr;                    // merkleRootQuorums source (quorum-tail-fed)
    int32_t  m_best_cl_height{0};             // best observed ChainLock height
    std::array<uint8_t, 96> m_best_cl_sig{};  // best observed ChainLock signature
    int64_t  m_credit_pool{0};                // DIP-0027 credit-pool balance (seeded from cbTx)
    bool     m_have_sml{false};               // a non-empty SML has been applied
    uint256  m_sml_current_hash;              // block hash the SML is current at (ZERO = cold/reorg)
    bool     m_require_sml{false};            // gate viability on have_sml (embedded arm)
    std::function<bool()> m_utxo_ready_fn;   // optional UTXO maturity gate (E2b)
    std::function<bool(uint32_t)> m_is_superblock_fn;  // refuse embedded on superblock heights
    std::function<bool(uint32_t)> m_commitment_window_fn;  // refuse embedded on DKG commitment heights
    bool     m_require_fresh_bestcl{false};  // refuse embedded on a stale/absent bestCL
    bool     m_require_fresh_credit_pool{false}; // refuse embedded on a lagged credit-pool seed
    bool     m_require_fresh_mn_payee{false};    // refuse embedded on a lagged payee queue (stale cursor)
    int      m_mn_rr_height{DASH_MN_RR_HEIGHT_MAINNET}; // network MN_RR activation height (platform-share gate)
    uint256  m_credit_pool_current_hash;     // block hash the credit-pool seed is current at
    int32_t  m_credit_pool_height{-1};       // seed cbTx's OWN height (-1 = never seeded)
    bool     m_quorum_healthy{true};         // last diff's quorum tail parsed OK
    uint32_t m_prev_height{0};
    uint256  m_prev_hash;
    uint32_t m_bits_for_next{0};
    uint32_t m_mtp_at_tip{0};
    uint8_t  m_address_version{0};
    uint8_t  m_address_p2sh_version{0};
    uint32_t m_curtime{0};
    uint32_t m_version{0};
    bool     m_populated{false};
};

} // namespace coin
} // namespace dash
