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
#include <impl/dash/coin/dkg_commitments.hpp>    // QcBlockPlan (E1 daemonless DKG-window serving)
#include <impl/dash/coin/vendor/simplifiedmns.hpp> // vendor::CSimplifiedMNList (merkleRootMNList source)
#include <impl/dash/coin/sml_projection.hpp>     // confirmedHash rollover projection + collateral-spend predicate
#include <impl/dash/coin/vendor/cbtx.hpp>        // vendor::parse_cbtx (pre-emit CbTx self-check)
#include <impl/dash/coin/subsidy.hpp>            // compute_dash_platform_reward_post_v20_mn_rr (creditPool re-check)

#include <impl/dash/coin/governance_object.hpp>  // SuperblockPayment (daemonless superblock schedule)

#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace dash {
namespace coin {

/// Where the currently-held best ChainLock came from. The bestCL* fields are
/// COMMITTED into the coinbase of every template we serve, and dashcore
/// re-verifies a non-null committed signature with BLS
/// (specialtxman.cpp:164-167 VerifyChainLock => bad-cbtx-invalid-clsig), so
/// "how do we justify this signature" is a consensus question, not bookkeeping.
///
///  - Unknown        : no provenance recorded. FAIL-CLOSED — the consensus-exact
///                     gate refuses to serve from it. This is the DEFAULT for
///                     set_best_cl() so that any future/unaudited writer cannot
///                     silently make the gate permissive.
///  - ChainCommitted : read out of a connected block's own coinbase CCbTx. The
///                     network already accepted that signature IN that block, so
///                     re-committing it needs no local BLS at all — this is
///                     exactly what dashd's own miner does when it holds nothing
///                     fresher (dash v23.1.7 src/node/miner.cpp:143-146,153-156).
///  - BlsVerified    : a live clsig off the wire that PASSED local BLS
///                     verification against its signing quorum
///                     (CoinStateMaintainer::on_new_chainlock, itself fail-closed
///                     when no verifier is installed).
enum class ClProvenance { Unknown, ChainCommitted, BlsVerified };

/// Policy for the bestCL viability/pre-emit gate. See set_bestcl_policy().
///
///  - Off             : no bestCL gate (pre-#780 behaviour).
///  - Freshness       : the ORIGINAL proxy — require the best observed ChainLock
///                      to be within one block of the tip. Conservative,
///                      over-restrictive, and the DEFAULT when the gate is on.
///  - ConsensusExact  : require exactly what dashcore requires, no more.
enum class BestClPolicy { Off, Freshness, ConsensusExact };

/// What the embedded arm does while the UTXO/fee lane is below its maturity
/// depth (UtxoLane::mining_utxo_ready == false, i.e. blocks_connected < 106).
/// See set_utxo_immature_policy() for the reasoning and the default.
///
///  - Refuse          : DEFAULT — p2pool semantics, the project design law: an
///                      unsynced node does not serve block templates. Refuse
///                      the arm ("utxo-immature") and route to the dashd
///                      fallback (full templates where one is armed) for the
///                      whole immature window.
///  - ServeEmptyTxSet : explicit OPT-IN for pure-daemonless deployments with
///                      no fallback to route to: stay viable and serve a
///                      COINBASE-ONLY template. Consensus never requires a
///                      mempool transaction, so a tx-free block is fully
///                      valid; with zero txs the fee term is exactly 0, so
///                      subsidy / MN payment / creditPool are all exact and
///                      nothing can be overstated.
enum class UtxoImmaturePolicy { ServeEmptyTxSet, Refuse };

/// The DISCRIMINATING tail of a block-hash display hex, for log/diagnostic use.
///
/// WHY THIS EXISTS (measured, hotel node 109.161.52.148, 2026-08-06). Every
/// `dmn-stale` refusal in a 5h33m window printed
///
///     cause=dmn-stale value=000000000000 threshold=000000000000
///
/// — 114 of 114 identical, and the two sides equal, on a refusal whose ENTIRE
/// meaning is that the two sides DIFFER. The fields were not unpopulated: they
/// were `uint256::GetHex().substr(0, 12)`, i.e. the twelve MOST-significant
/// nibbles of a PROOF-OF-WORK hash, which are zero by construction. The live
/// tip hashes in the same log confirm it directly: `000000000000000e`,
/// `000000000000001c`, `0000000000000018` — at mainnet difficulty the first
/// ~14 nibbles are the difficulty padding and carry no information at all.
///
/// So the operator contract established by #1039 ("every decline names cause,
/// value and threshold") was honoured in SHAPE and empty in SUBSTANCE, and no
/// one could tell a genuinely stale DML from a broken predicate. Taking the
/// TAIL instead of the head is the whole fix: the low-order nibbles are the
/// hash's entropy.
///
/// Deliberately NOT applied to ProTx / transaction hashes elsewhere in this
/// file (`mn-confirm-rollover-pending`, `mn-payout-split-unprovable`): those
/// are ordinary double-SHA256 tx ids with no difficulty padding, so their
/// leading nibbles ARE discriminating and their existing rendering is correct.
inline std::string discriminating_hash_tail(const uint256& h, size_t n = 12)
{
    const std::string hex = h.GetHex();
    return hex.size() <= n ? hex : hex.substr(hex.size() - n);
}

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
    //
    // D2 (2026-08-07/08 hotel freeze, remaining half of the class): handing
    // out a MUTABLE reference to any input of the two committed-root
    // computations bumps the root-memo epoch — the caller MAY mutate, and a
    // memoized root that survives a mutation is a WRONG BLOCK
    // (bad-cbtx-mnmerkleroot / bad-cbtx-quorummerkleroot, silently lost).
    // Over-invalidation on a read-through-non-const access only costs one
    // recompute; under-invalidation costs a block — so the bump rides the
    // accessor, not the callers' discipline. Read-only callers on the
    // emit-ok hot path must use the const accessors (std::as_const at the
    // main_dash qc-plan sites) or they re-chill the memo every evaluation.
    // mnstates() bumps too: the confirmation-pass projection reads MN
    // registration heights from it (sml_projection.hpp).
    MnStateMachine& mnstates() { bump_root_memo_epoch(); return m_mnstates; }
    // Mempool contents feed the template TX SET, not either committed root —
    // no epoch bump (a per-tx bump would chill the memo for nothing).
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
    // Non-const access == possible mutation == root-memo epoch bump (see the
    // mnstates() note above; same rule, same failure mode).
    vendor::CSimplifiedMNList& sml() { bump_root_memo_epoch(); return m_sml; }
    QuorumManager&             qmgr() { bump_root_memo_epoch(); return m_qmgr; }
    const vendor::CSimplifiedMNList& sml() const { return m_sml; }
    const QuorumManager&             qmgr() const { return m_qmgr; }

    /// Root-memo mutation epoch (D2). Bumped by every non-const accessor /
    /// setter whose target feeds the projected-SML root or the quorum root; a
    /// cached root is valid only while its epoch matches. All mutators run on
    /// the single-threaded ioc, so a plain uint64 needs no lock — do not add
    /// one. Exposed read-only as a test seam.
    uint64_t root_memo_epoch() const { return m_root_memo_epoch; }

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

    /// #127 null-arm freshness predicate (the require_sml tip-currency half).
    /// TRUE iff the folded SML is current AT the tip we build on: non-null and
    /// equal to prev_hash. This is exactly the conjunct the viability gate
    /// enforces before it refuses (see the `m_require_sml && m_sml_current_hash
    /// != m_prev_hash` refuse below), exposed so the DkgNullEvidenceFn can
    /// re-assert the SAME freshness the arm's own viability already proved —
    /// defence in depth, so a null can never be decided on a view the arm
    /// would itself reject. The height-DATABLE half (sml_height_paired) lives
    /// in the maintainer and is AND'd there by the production null-evidence fn.
    bool sml_current_at_prev() const {
        return !m_sml_current_hash.IsNull() && m_sml_current_hash == m_prev_hash;
    }

    /// The HEIGHT that same applied SML is current at, authoritative off the
    /// accepted diff's own cbTx.nHeight (CoinStateMaintainer::m_sml_current_height).
    /// -1 = never reported.
    ///
    /// DIAGNOSTIC-ONLY — nothing in the viability decision reads it. It exists
    /// because the `dmn-stale` refusal below compares two BLOCK HASHES, and a
    /// hash can only ever say "different", never "how far behind". Every long
    /// dmn-stale episode measured on the hotel node (2026-08-06: 5 episodes,
    /// 586 s of the 592 s total) was closed by the NEXT BLOCK arriving rather
    /// than by the SML catching up at the same tip — a distinction the hash
    /// alone cannot express, and the height makes obvious at a glance.
    ///
    /// Published from the SAME statement that publishes the hash, so the pair
    /// can never disagree about which block it describes.
    void set_sml_current_height(int64_t h) { m_sml_current_height = h; }
    int64_t sml_current_height_dbg() const { return m_sml_current_height; }

    /// Seed the version-appropriate CCbTx fields the SML/quorum roots do not
    /// carry: the best-ChainLock height+signature and the DIP-0027 credit-pool
    /// balance. Sourced by the maintainer from the diff's embedded cbTx (the
    /// authoritative wire form as-of blockHash) and from new_chainlock events.
    /// `prov` records HOW this signature is justified — see ClProvenance. It
    /// defaults to Unknown (fail-closed under BestClPolicy::ConsensusExact) so
    /// that a writer added later cannot make the gate permissive by omission.
    void set_best_cl(int32_t height, const std::array<uint8_t, 96>& sig,
                     ClProvenance prov = ClProvenance::Unknown) {
        m_best_cl_height = height;
        m_best_cl_sig    = sig;
        m_best_cl_prov   = prov;
    }
    ClProvenance best_cl_provenance() const { return m_best_cl_prov; }

    /// Record the ChainLock the TIP BLOCK ITSELF committed, straight off that
    /// block's coinbase CCbTx.
    ///
    /// THIS IS THE DATUM THE CONSENSUS RULE IS STATED IN. dashcore's
    /// CheckCbTxBestChainlock (dash v23.1.7 src/evo/specialtxman.cpp:102-177)
    /// constrains our block at height H only RELATIVE to what block H-1
    /// committed:
    ///
    ///     prevCL = GetNonNullCoinbaseChainlock(pindex->pprev)   // :129-131
    ///     if (prevCL) {
    ///         if (!cbTx.bestCLSignature.IsValid())      -> bad-cbtx-null-clsig    // :134-137
    ///         if (cbTx.bestCLHeightDiff > prevCL.diff+1) -> bad-cbtx-older-clsig  // :138-140
    ///     }
    ///
    /// i.e. "committed CL height must not go BACKWARDS from the previous
    /// block's". Nothing in the rule mentions the tip, wall-clock freshness, or
    /// how recently a ChainLock was produced. Knowing block H-1's committed
    /// (sig, heightDiff) is therefore NECESSARY AND SUFFICIENT to prove our own
    /// committed value legal before we serve it.
    ///
    /// `block_height` is the height of the block whose coinbase supplied this
    /// (validated by the caller against the CCbTx's own nHeight), `has_sig` is
    /// false when that coinbase committed a NULL bestCLSignature (dashcore then
    /// imposes NO constraint on us at all), and `cl_height` is the absolute
    /// height that coinbase's committed ChainLock refers to,
    /// block_height - bestCLHeightDiff - 1.
    void set_tip_cbtx_chainlock(int32_t block_height, bool has_sig, int32_t cl_height) {
        // Monotonic on the block axis: a late/duplicate delivery of an OLDER
        // block must not roll the provenance height back (same discipline as
        // the credit-pool seed's Nit-C guard).
        if (block_height <= m_tip_cbtx_at_height) return;
        m_tip_cbtx_at_height = block_height;
        m_tip_cbtx_cl_null   = !has_sig;
        m_tip_cbtx_cl_height = has_sig ? cl_height : -1;
    }
    int32_t tip_cbtx_at_height() const { return m_tip_cbtx_at_height; }
    int32_t tip_cbtx_cl_height() const { return m_tip_cbtx_cl_height; }
    bool    tip_cbtx_cl_null()   const { return m_tip_cbtx_cl_null; }
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

    /// #996 payee fail-closed gate. When enabled (default ON), viability
    /// refuses the embedded arm at any height where a MN payment is due but
    /// the NON-empty payee queue cannot resolve it to a live SML entry — the
    /// builder would otherwise emit a coinbase claiming m_payment_amount with
    /// no MN output (fail-OPEN, bad-cb-payee). An EMPTY queue never trips:
    /// it means no masternode set at all (a network with none serves
    /// normally; a mid-sync empty queue is already fail-closed by
    /// require_sml + require_fresh_mn_payee), not a resolution failure.
    /// Refusal downgrades to the reward-safe dashd GBT fallback; it is a
    /// template-SERVE refusal (free), never a block-SUBMIT refusal. Exposed
    /// for the negative-pass test.
    void set_require_resolvable_payee(bool v) { m_require_resolvable_payee = v; }
    void set_require_provable_payout_split(bool v) { m_require_provable_payout_split = v; }

    /// creditPool freshness gate (soak fix). dashcore CheckCreditPoolDiffForBlock
    /// rejects a block whose committed creditPoolBalance is off by a block's
    /// accrual (bad-cbtx-assetlocked-amount). When enabled, viability + the
    /// pre-emit gate require the credit-pool seed to be current AT the tip
    /// (credit_pool_current_hash == prev_hash); a lagged seed fails closed to the
    /// reward-safe dashd fallback. Default OFF preserves prior unit-test posture.
    void set_require_fresh_credit_pool(bool v) { m_require_fresh_credit_pool = v; }

    /// #107 PHASE 2 (--embedded-accrue-asset-locks, default OFF). When ON, the
    /// embedded CbTx creditPoolBalance accrues the pending type-8 DIP-0027
    /// asset-lock term (Σ first-OP_RETURN value over the mempool's pending
    /// locks, asset_lock_fold.hpp / dashd creditpool.cpp:262-276) so it matches
    /// what dashd commits — the gbt-xcheck-modulo-special-explained swap then
    /// stops firing on the type-8-only case. The SAME term is added to the
    /// emit-gate's expected creditPool (embedded_template_emit_ok) so a fresh
    /// build satisfies the freshness gate instead of tripping
    /// emit-creditpool-value-drift (PR body B2). Consensus caveat (B1): a block
    /// committing this accrual is valid ONLY once the same type-8 txs ride the
    /// served body (tx-serving, blocked on #125); until then the accrual makes
    /// the classification match but a submitted coinbase-only block would be
    /// bad-cbtx-assetlocked-amount. Hence default OFF.
    void set_accrue_pending_asset_locks(bool v) { m_accrue_pending_asset_locks = v; }
    bool accrue_pending_asset_locks() const { return m_accrue_pending_asset_locks; }

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

    /// Network nMasternodeMinimumConfirmations (dashcore Params().GetConsensus()
    /// .nMasternodeMinimumConfirmations — per-chainparams: mainnet 15, testnet/
    /// devnet/regtest 1; see sml_projection.hpp). Gates the confirmedHash
    /// rollover projection in the template build, the viability clause and the
    /// pre-emit root re-check. main_dash sets the testnet value next to
    /// set_mn_rr_height; the mainnet default keeps every existing caller
    /// byte-unchanged.
    void set_mn_min_confirmations(int c) {
        bump_root_memo_epoch();   // D2: projection threshold input
        m_mn_min_confirmations = c;
    }
    int mn_min_confirmations() const { return m_mn_min_confirmations; }

    /// HEADER-SYNC gate (the DASH half of a cross-lane asymmetry: bch 13, ltc
    /// 12, nmc 12, btc 6, dgb 6 callers of is_synced(); DASH had ZERO —
    /// HeaderChain::is_synced() was DEFINED AND NEVER CALLED, machinery that
    /// compiled and could not be reached).
    ///
    /// Every other freshness gate on this class is RELATIVE to our own tip:
    /// credit-pool height == prev_height, SML hash == prev_hash, payee cursor
    /// == prev_height. All of them hold perfectly on a node thousands of blocks
    /// behind but internally CONSISTENT — a peer answering getmnlistd at OUR
    /// tip returns a diff for that old block, the credit pool advances off the
    /// same old blocks, and the payee queue folds them in step. Nothing in the
    /// set can tell "current" from "self-consistently stale", because none of
    /// them compares against anything outside our own view.
    ///
    /// This is that comparison. LTC's builder is the reference pattern in our
    /// own tree: template_builder.hpp:116 defaults is_synced() to FALSE so a
    /// subclass must positively PROVE sync, and :376 THROWS rather than serve.
    /// Unset here (default) leaves the clause unevaluated so every pre-existing
    /// KAT is byte-unchanged; main_dash wires it to HeaderChain::is_synced() so
    /// the production daemonless arm cannot mine on a stale tip.
    void set_chain_synced_fn(std::function<bool()> fn) {
        m_chain_synced_fn = std::move(fn);
    }

    /// DIAGNOSTIC: which half of the publish precondition the maintainer is
    /// still missing. `populated()` is set by set_tip() only when the
    /// maintainer holds BOTH a tip and an authoritative MN set, so a bare
    /// "not-populated" collapses two very different operator situations —
    /// "still syncing headers" and "the MN set has not been seeded/bridged" —
    /// into one uninformative word. The maintainer publishes both bits here so
    /// the refusal can carry them as its MEASURED value. Never read by any
    /// serve or reward path. Unset => the report prints "n/a", not "0".
    void set_populate_inputs(bool have_tip, bool have_mn) {
        m_have_tip_dbg = have_tip ? 1 : 0;
        m_have_mn_dbg  = have_mn ? 1 : 0;
    }

    /// DIAGNOSTIC (body-first serve tip): the maintainer knows a newer header
    /// tip whose block inputs (body / tip-targeted mnlistdiff cbTx) have not
    /// been parsed yet. This is the NORMAL ~1-2 s propagation transient of
    /// the body-first split, not an error state; publishing it here lets a
    /// not-populated refusal during that window (cold start / overdue demote)
    /// carry its own name instead of masquerading as a header-sync fault.
    /// Never read by any serve or reward path.
    void set_tip_body_pending_dbg(bool v) { m_tip_body_pending_dbg = v; }
    bool tip_body_pending_dbg() const { return m_tip_body_pending_dbg; }

    /// WHICH promotion conjunct is the one still unmet, as a static string
    /// literal ("credit-pool-seed" / "payee-cursor" / "sml-currency" /
    /// "header-tip"). `tip-body-pending` names a WAIT; on its own it does NOT
    /// name what is being waited FOR, and the three axes have different owners
    /// and different repair paths — the credit-pool seed and the payee cursor
    /// both come from the tip BLOCK BODY (one getdata BLOCK on the coin-P2P
    /// leg), while the SML currency comes from a SEPARATE getmnlistd round
    /// trip that the block body cannot supply (a cbTx commits
    /// merkleRootMNList, and a root is not a list). An operator reading
    /// `cause=tip-body-pending` alone cannot tell a slow body from a silently
    /// dropped diff request; `awaiting=sml-currency` says it in one line.
    ///
    /// LIFETIME: the pointer must be a string literal (every call site passes
    /// one). Diagnostic only; no serve or reward path reads it.
    void set_tip_body_pending_axis(const char* axis) {
        m_tip_body_pending_axis = axis ? axis : "";
    }
    const char* tip_body_pending_axis() const { return m_tip_body_pending_axis; }

    /// The same two bits, READABLE. They existed only inside the decline
    /// string, so the standing state ("why would this node not serve RIGHT
    /// NOW, before anyone asks it for work") could not be printed at all — an
    /// operator had to provoke a decline to learn it. -1 == never reported.
    /// Telemetry only; no serve or reward path reads these.
    int have_tip_dbg() const { return m_have_tip_dbg; }
    int have_mn_dbg()  const { return m_have_mn_dbg; }

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
        // D2: prev_height/prev_hash are inputs of the confirmation-pass
        // projection (confirmations = prev_height - reg_height; confirmedHash
        // = prev_hash), so a tip move invalidates the memoized projected root.
        bump_root_memo_epoch();
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
    /// set, the predicate (UtxoLane::mining_utxo_ready: blocks_connected >= 106)
    /// reports whether the UTXO view is deep enough to price mempool txs, so a
    /// template can never include a tx whose fee we cannot compute exactly.
    ///
    /// WHAT THE ARM DOES while that predicate is false is set separately by
    /// set_utxo_immature_policy(): by DEFAULT (Refuse -- p2pool semantics, an
    /// unsynced node does not serve templates) it declines ("utxo-immature")
    /// and get_work routes to the retained dashd fallback for the whole
    /// window, the pre-existing behaviour. Under the opt-in
    /// UtxoImmaturePolicy::ServeEmptyTxSet the arm stays viable and serves a
    /// COINBASE-ONLY template (fees exactly 0, nothing to overstate). Unset
    /// (default) leaves both moot: with no predicate installed the window does
    /// not exist and nothing is suppressed.
    void set_utxo_ready_fn(std::function<bool()> fn) {
        m_utxo_ready_fn = std::move(fn);
    }

    /// WINDOW-2 currency gate (--embedded-serve-mempool-txs only). Optional
    /// predicate answering "has the embedded UTXO view already connected+
    /// evicted the block whose hash is passed?" (UtxoLane::utxo_current_at).
    /// When set AND mempool-tx serving is armed, make_embedded_work_inputs
    /// suppresses the fee-carrying body while the just-promoted serve tip is
    /// NOT yet current in the UTXO/mempool view -- the diff-driven promotion
    /// can race ahead of the full-block connect, and a template built on that
    /// tip could otherwise select a tx already spent/conflicted by it (an
    /// invalid, thrown-away block). Coinbase-only in that sub-second window
    /// reproduces dashd's invariant (removeForBlock runs inside ConnectBlock,
    /// before any template on the new tip). Unset (default) => no Window-2
    /// gate, byte-identical to the pre-existing behaviour.
    void set_utxo_current_fn(std::function<bool(const uint256&)> fn) {
        m_utxo_current_fn = std::move(fn);
    }

    /// What to do during the immature window the predicate above reports.
    ///
    /// ── WHY THE DEFAULT IS Refuse (operator design law, p2pool semantics) ────
    /// An unsynced node is a node with unverified state, and the project rule --
    /// stated repeatedly by the operator, and the behaviour p2pool always had --
    /// is that an unsynced node does not serve block templates. Miners idling is
    /// the correct posture: cheaper than hashing work the node cannot fully
    /// stand behind. Where an external dashd fallback is armed, the refusal is
    /// also strictly better than any degraded serve -- the fallback returns FULL
    /// templates. So the default refuses ("utxo-immature") for the whole
    /// blocks_connected < 106 window, exactly as before this policy existed.
    ///
    /// ── WHY ServeEmptyTxSet EXISTS AS AN OPT-IN ──────────────────────────────
    /// On a PURE-DAEMONLESS node there is no fallback to route to: the refusal
    /// costs the whole window (~106 blocks x ~150 s ~= 4.4 h of a cold start)
    /// with nothing served by anyone. For operators who prefer a subsidy-only
    /// block over no block, the opt-in serves a COINBASE-ONLY template instead.
    /// That is consensus-safe by construction: consensus never requires a
    /// mempool transaction, and with zero selected txs the fee term is exactly
    /// 0 -- there is nothing to overstate, so the bad-cb-amount risk the
    /// maturity gate guards (this builder has no TestBlockValidity equivalent;
    /// fee exactness rides entirely on the UTXO lane) is structurally absent in
    /// that mode. Every other viability gate -- chain-synced, qc plan,
    /// superblock, bestCL, credit pool, payee freshness, SML/quorum roots --
    /// still has to pass either way. The cost is the forgone fees, which the
    /// builder reports on every such template (m_txset_forgone_fees).
    ///
    /// main_dash: --embedded-utxo-immature-serve-empty selects the opt-in;
    /// flag absent = Refuse, byte-identical to the pre-policy behaviour.
    void set_utxo_immature_policy(UtxoImmaturePolicy p) {
        m_utxo_immature_policy = p;
    }
    UtxoImmaturePolicy utxo_immature_policy() const {
        return m_utxo_immature_policy;
    }

    /// ── Mempool-tx serving switch (--embedded-serve-mempool-txs) ─────────
    /// DEFAULT OFF: the embedded arm serves a COINBASE-ONLY body even with a
    /// mature UTXO lane (suppress_mempool_txs=true, cause
    /// "mempool-txs-disabled"). Consensus never requires a mempool tx, and
    /// with zero txs every committed value (subsidy, MN payment, creditPool)
    /// is exact — the same argument as the utxo-immature serving mode.
    ///
    /// Turning it ON puts the whole mempool-tx body path in the block
    /// production lane: topological selection (G1), sigop caps (G2),
    /// coinbase-maturity (G3) and islock-conflict (G4) guards all live in
    /// Mempool::get_sorted_txs_with_fees (see
    /// DASH_CONNECTBLOCK_REJECT_SURFACE_AUDIT.md). Fees ride the coinbase.
    /// The switch exists so the fee-carrying path is an explicit operator
    /// decision, soak-gated like every other production posture — not an
    /// implicit consequence of the UTXO lane maturing.
    void set_serve_mempool_txs(bool on) { m_serve_mempool_txs = on; }
    bool serve_mempool_txs() const { return m_serve_mempool_txs; }

    /// PINNED LOCAL TX (--pin-local-tx-hex, donation-dust consolidation): an
    /// operator-supplied, externally-signed, zero-fee tx that can only reach
    /// the chain through OUR OWN block. Stored by value; the work-inputs
    /// bundle hands the builder a pointer, and the builder re-gates admission
    /// against the live UTXO view on every template
    /// (Mempool::pinned_tx_admissible) — exclusion-only failure, never a
    /// template refusal. Call on the io thread before serving starts.
    /// PIN GATE for the SERVED-DASHD arm, as a VALUE (#1134).
    ///
    /// The embedded builder gates and appends in one place because both happen
    /// beside the coin state. The served-dashd arm cannot: it appends on the
    /// re-source thread, where touching m_mempool/m_mnstates is the serve-path
    /// heap-corruption shape. So the gate runs HERE and only the verdict
    /// crosses. `out_tx` receives a pointer to the pin, which is safe to hand
    /// out because it is written once before serving and never mutated.
    ///
    /// The height is OURS (m_prev_height + 1), not the template's: a served
    /// dashd template can reach the splice with height 0, and a zero height
    /// makes the coinbase-maturity arm read every coinbase-sourced input as
    /// immature. An unknown tip is REFUSED by name rather than guessed at.
    /// One verdict PER PIN, in file order. The vector is empty when no pin is
    /// configured. Judged at OUR tip; an unknown tip refuses by name rather
    /// than guessing (a zero height marks every coinbase input immature).
    std::vector<PinVerdict> evaluate_pinned_txs(
        const std::vector<MutableTransaction>** out_txs) const {
        std::vector<PinVerdict> out;
        if (!m_have_pinned_local_tx) return out;
        if (out_txs) *out_txs = &m_pinned_local_txs;
        out.reserve(m_pinned_local_txs.size());
        for (const auto& tx : m_pinned_local_txs) {
            if (m_prev_height == 0) {
                PinVerdict v; v.cause = "tip-unknown"; out.push_back(v);
                continue;
            }
            out.push_back(pin_gate_verdict(tx, m_mempool, m_mnstates,
                                           m_prev_height + 1));
        }
        return out;
    }

    /// Is ANY pin configured? Read by the legacy get_work() adapter, which has
    /// no splice, so it can NAME the omission instead of shipping a template
    /// that silently lacks the donation.
    bool has_pinned_local_txs() const { return m_have_pinned_local_tx; }

    void set_pinned_local_tx(MutableTransaction tx) {
        m_pinned_local_txs.clear();
        m_pinned_local_txs.push_back(std::move(tx));
        m_have_pinned_local_tx = true;
    }
    void set_pinned_local_txs(std::vector<MutableTransaction> txs) {
        m_pinned_local_txs = std::move(txs);
        m_have_pinned_local_tx = !m_pinned_local_txs.empty();
    }

    /// Second source for the PIN GATE's coin lookups (money-path). Forwarded
    /// to the mempool, which consults it only for inputs its own UTXO view
    /// cannot resolve — see Mempool::set_external_coin_lookup for why that is
    /// not a relaxation. Wired once at startup, before any template build.
    void set_pin_external_coin_lookup(
        std::function<bool(const ::core::coin::Outpoint&, ::core::coin::Coin&)> fn)
    {
        m_mempool.set_external_coin_lookup(std::move(fn));
    }

    /// PR-C1 (embedded-fold-live): wire the full-history replay UTXO fold as the
    /// LIVE serve-path input-pricing source (main_dash.cpp, under
    /// --embedded-fold-live). Forwarded to the mempool, which consults it in
    /// compute_fee_locked ONLY after the forward UTXO view and every in-pool
    /// parent miss -- so a mempool tx whose inputs predate the forward view (was
    /// permanently fee-unknown and template-excluded) is priced from a set proven
    /// byte-equal to dashd's and becomes fee_fold_proven. The pin gate's own
    /// second-source seam (set_pin_external_coin_lookup) is separately pointed at
    /// the same fold, retiring the gettxout/--coin-rpc pin lookup. Unset
    /// (default) => viability + fee pricing are byte-identical to master.
    void set_fold_coin_lookup(
        std::function<bool(const ::core::coin::Outpoint&, ::core::coin::Coin&)> fn)
    {
        m_mempool.set_fold_coin_lookup(std::move(fn));
    }

    /// PR-C1 (embedded-fold-live) AT-TIP SERVING GUARD forwarder. Carries the
    /// FoldLiveController::at_tip answer (fold caught up to the serve tip AND
    /// chain-identical) into the mempool, which consults the fold ONLY while it
    /// holds. Behind tip / mid-reorg / stranded => the mempool withholds
    /// (byte-identical to master). Unset (default) => no guard, fold never wired.
    void set_fold_at_tip_gate(std::function<bool()> fn)
    {
        m_mempool.set_fold_at_tip_gate(std::move(fn));
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
        m_is_superblock_fn = fn;
        // Same cycle for the payee machine's pass-3 payout-split
        // observation: a lone treasury payee at a superblock height
        // presents the same 2-output shape as an operator split, so
        // adoption there is ambiguous and must be skipped (h=2516595
        // split-provenance lane).
        m_mnstates.set_superblock_height_fn(std::move(fn));
    }

    /// Daemonless superblock provider (E-SUPERBLOCK). When enabled (see
    /// set_require_superblock_provider), the superblock-height guard consults
    /// this instead of unconditionally refusing. The provider takes the NEXT
    /// block height and returns:
    ///   - nullopt              => NOT trigger-confident (govsync incomplete /
    ///                             stale / votes unverified) => FAIL CLOSED to
    ///                             the reward-safe dashd fallback;
    ///   - empty vector         => confidently UNFUNDED superblock => the arm
    ///                             may serve a NORMAL template (no extra outs);
    ///   - non-empty vector     => the winning trigger's budget-valid (script,
    ///                             amount) schedule => the arm serves and emits
    ///                             exactly those treasury outputs.
    /// The provider is only ever CALLED at superblock heights (gated by
    /// m_is_superblock_fn), so a non-superblock height never touches it.
    void set_superblock_provider(
        std::function<std::optional<std::vector<SuperblockPayment>>(uint32_t)> fn) {
        m_superblock_provider = std::move(fn);
    }

    /// Enable the daemonless superblock arm (--embedded-superblock opt-in).
    /// Default OFF preserves the prior REWARD-SAFE posture EXACTLY: every
    /// superblock height refuses the embedded arm and routes to the dashd
    /// fallback (which builds the correct superblock template). When ON, the
    /// superblock provider above resolves the schedule daemonlessly, still
    /// failing closed on any under-synced / unverified / over-budget view.
    void set_require_superblock_provider(bool v) { m_require_superblock_provider = v; }

    /// GOVSYNC-COMPLETENESS GATE (structural reward-safety invariant, R5).
    /// The dangerous failure mode of daemonless superblock sourcing is a
    /// PARTIAL governance view: a store missing the higher-yes competing
    /// trigger (or its votes) yields a CONFIDENT wrong winner — dashd
    /// validates against ITS best trigger and rejects our block. A per-trigger
    /// threshold cannot see what it never received, so trigger-confidence
    /// alone is NOT sufficient to serve.
    ///
    /// This predicate must return true ONLY when the governance sync is
    /// provably COMPLETE (objects+votes fully streamed and quiesced against
    /// enough peers, counts cross-checked). It is DEFAULT-ABSENT, and
    /// resolve_superblock REFUSES the serve path while it is absent or false
    /// — so landing vote-verification alone can NEVER open the serve path;
    /// the completeness predicate must be wired deliberately, together with
    /// its own proof obligations. No production caller sets it yet.
    void set_superblock_sync_complete_fn(std::function<bool()> fn) {
        m_superblock_sync_complete_fn = std::move(fn);
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

    /// E1 — daemonless DKG-window serving. When set, this SUPERSEDES the
    /// commitment-window refusal: at every height the plan fn derives the
    /// mandatory type-6 commitment set + the with-block merkleRootQuorums
    /// from local state only (header chain + mnlistdiff-fed QuorumManager,
    /// see dkg_commitments.hpp). nullopt => the set cannot be derived
    /// safely and viability fails closed to the dashd fallback — the same
    /// reward-safe outcome as the PHASE-1 refusal, but now only when
    /// genuinely unable instead of for the whole 9-block window. Unset
    /// (default) preserves the refusal posture exactly.
    ///
    /// TWO shapes, and the two-argument one is what production wires. A bare
    /// `std::optional<QcBlockPlan>` throws away the identity of what was
    /// missing, and the refusal downstream then had nothing to print but the
    /// literal "nullopt" — a value that cannot disagree with anything. The
    /// QcPlanGap out-parameter carries the offending quorum (llmqType,
    /// quorumIndex, quorumHash, per-slot gap reason) to the decline's VALUE
    /// field. The one-argument overload stays for providers that genuinely
    /// have no reason to report; it names ITSELF ("reason-unreported") rather
    /// than pretending the gap was measured.
    void set_qc_plan_fn(
        std::function<std::optional<QcBlockPlan>(uint32_t, QcPlanGap*)> fn) {
        m_qc_plan_fn = std::move(fn);
    }
    void set_qc_plan_fn(std::function<std::optional<QcBlockPlan>(uint32_t)> fn) {
        m_qc_plan_fn = [f = std::move(fn)](uint32_t h, QcPlanGap* gap)
            -> std::optional<QcBlockPlan> {
            auto plan = f(h);
            if (!plan && gap != nullptr) {
                *gap = QcPlanGap{};
                gap->stage = QcPlanStage::Unreported;
            }
            return plan;
        };
    }

    /// PoSe no-op proof for one REAL (non-null) type-6 commitment — the
    /// enforcement of the #1083 landmine comment at the inclusion site
    /// (embedded_gbt.hpp). dashd's verifier PoSe-punishes every member a
    /// non-null in-block commitment marks invalid (specialtxman.cpp:159-174),
    /// which can flip that MN's validity in the SAME block's list and change
    /// the merkleRootMNList this coinbase commits — bad-cbtx-mnmerkleroot, a
    /// silently lost block. c2pool does not fold that pass, so the pre-emit
    /// gate refuses any real commitment whose PoSe pass is not PROVABLY a
    /// no-op (qc_pose_pass_provably_noop: every listed member valid).
    ///
    /// The fn answers exactly that question for one commitment:
    ///   true    => the PoSe pass provably touches nothing — servable;
    ///   false   => at least one listed member would be punished — refuse;
    ///   nullopt => cannot be established (member set not sourced) — refuse.
    /// UNSET (default) => the capability is absent and every non-null
    /// commitment is refused (fail-closed insurance until a real PoSe fold
    /// into the committed MN root is built). Null commitments are exempt by
    /// dashd's own IsNull() guard (specialtxman.cpp:427-432) and are never
    /// consulted, so the all-null production plans are byte-unchanged.
    void set_qc_pose_noop_fn(
        std::function<std::optional<bool>(const vendor::CFinalCommitment&)> fn) {
        m_qc_pose_noop_fn = std::move(fn);
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
    ///
    /// ⚠ THE FRESHNESS PREDICATE IS A PROXY, AND IT IS EXPENSIVE. See
    /// set_bestcl_policy() for the consensus-exact replacement and the measured
    /// cost of keeping this one. This setter is retained verbatim: it selects
    /// BestClPolicy::Freshness, which stays the default, so every existing
    /// caller and KAT keeps byte-identical behaviour.
    void set_require_fresh_bestcl(bool v) {
        m_require_fresh_bestcl = v;
        m_bestcl_policy = v ? BestClPolicy::Freshness : BestClPolicy::Off;
    }

    /// Select the bestCL gate policy. `Freshness` (the default whenever the
    /// gate is enabled) is the original #780 BLOCKER-2 proxy. `ConsensusExact`
    /// enforces dashcore's ACTUAL rule and nothing more.
    ///
    /// WHY THE PROXY IS WRONG (and it is a proxy — its own docs above call it
    /// "a sufficient condition"). dashcore constrains the committed ChainLock
    /// ONLY relative to the previous block's committed ChainLock; it never asks
    /// for freshness. dashd's own miner, when it holds nothing newer than what
    /// block H-1 committed, RE-COMMITS block H-1's exact signature with
    /// heightDiff = prevDiff + 1 and mines on (dash v23.1.7
    /// src/node/miner.cpp:143-146 "We don't know any CL, therefore inserting the
    /// CL of the previous block" and :153-156 "Our best CL isn't newer:
    /// inserting CL from previous block"). That path needs no ChainLock of our
    /// own and no BLS verification whatsoever. Our builder already produces
    /// byte-identically the same CCbTx in that situation — embedded_gbt.hpp
    /// computes heightDiff = prev_height - best_cl_height, which for a bestCL
    /// sourced from block H-1's coinbase is exactly prevDiff + 1. Only this
    /// gate stopped us serving it.
    ///
    /// WHAT ConsensusExact REQUIRES INSTEAD. Not freshness, but PROVENANCE: we
    /// must hold block H-1's OWN committed ChainLock (set_tip_cbtx_chainlock,
    /// fed from the connected block's coinbase), because that is the only term
    /// the consensus inequality is stated against. Given it, the value we would
    /// commit is provably legal before we serve. Without it we fail closed to
    /// the dashd fallback, exactly as before.
    ///
    /// FAIL-CLOSED ON A BLS-DARK BUILD. ConsensusExact never becomes permissive
    /// when BLS is stubbed out. Committing something NEWER than block H-1's
    /// ChainLock is the only case dashcore makes us prove with BLS, and that
    /// case additionally requires ClProvenance::BlsVerified — which
    /// on_new_chainlock can only produce through an installed, succeeding
    /// verifier. A BLS-dark build therefore holds only ChainCommitted values and
    /// re-commits block H-1's signature: dashd's own no-ChainLock behaviour.
    void set_bestcl_policy(BestClPolicy p) {
        m_bestcl_policy = p;
        m_require_fresh_bestcl = (p != BestClPolicy::Off);
    }
    BestClPolicy bestcl_policy() const { return m_bestcl_policy; }

    /// The ONE bestCL decision, shared by viability and the pre-emit gate so
    /// they can never drift apart. Returns nullopt when the bestCL axis is
    /// viable; otherwise {cause, value, threshold} for the decline report.
    ///
    /// Every refusal below is a refusal to SERVE — the caller routes to the
    /// reward-safe dashd fallback, exactly as the freshness proxy did.
    std::optional<std::array<std::string, 3>> bestcl_decline() const {
        const int32_t prev_h = static_cast<int32_t>(m_prev_height);
        auto no = [](const char* c, std::string v, std::string t) {
            return std::optional<std::array<std::string, 3>>{
                std::array<std::string, 3>{c, std::move(v), std::move(t)}};
        };
        switch (m_bestcl_policy) {
        case BestClPolicy::Off:
            return std::nullopt;

        case BestClPolicy::Freshness:
            // best_cl_height 0 means "no clsig ever observed", NOT "ChainLock at
            // height 0" — print n/a rather than report a measurement never taken.
            if (m_best_cl_height < prev_h - 1)
                return no("bestcl-stale",
                          m_best_cl_height > 0 ? std::to_string(m_best_cl_height)
                                               : std::string("n/a"),
                          ">=" + std::to_string(static_cast<int64_t>(prev_h) - 1));
            return std::nullopt;

        case BestClPolicy::ConsensusExact:
            // (1) PROVENANCE OF THE CONSTRAINT. Without block H-1's own
            // committed ChainLock we cannot evaluate dashcore's inequality at
            // all, so we must not serve. This is the same INDEPENDENT-HEIGHT
            // discipline the credit-pool seed uses: a value alone cannot tell
            // you it is one block behind; its height can.
            if (m_tip_cbtx_at_height != prev_h)
                return no("bestcl-tip-cbtx-stale",
                          m_tip_cbtx_at_height > 0
                              ? std::to_string(m_tip_cbtx_at_height)
                              : std::string("n/a"),
                          std::to_string(prev_h));

            if (m_tip_cbtx_cl_null) {
                // Block H-1 committed a NULL ChainLock =>
                // GetNonNullCoinbaseChainlock returns nullopt and dashcore
                // imposes NO constraint (specialtxman.cpp:130-141 is skipped
                // entirely). We may commit null, or any signature we can
                // justify. Committing null is what dashd does here when it
                // holds nothing (miner.cpp:167-171).
                if (m_best_cl_height <= 0) return std::nullopt;
                break;   // non-null: fall through to the justification check
            }

            // (2) NON-NULL. dashcore :134-137 bad-cbtx-null-clsig — once block
            // H-1 committed a real ChainLock, ours may not be null.
            if (m_best_cl_height <= 0)
                return no("bestcl-absent", "n/a",
                          "non-null (prev committed CL @"
                              + std::to_string(m_tip_cbtx_cl_height) + ")");
            // (3) NOT OLDER. dashcore :138-140 bad-cbtx-older-clsig, restated on
            // the absolute-height axis: bestCLHeightDiff > prevDiff + 1 is
            // exactly "our committed CL height < the previous block's".
            if (m_best_cl_height < m_tip_cbtx_cl_height)
                return no("bestcl-older-than-prev",
                          std::to_string(m_best_cl_height),
                          ">=" + std::to_string(m_tip_cbtx_cl_height));
            break;
        }

        // (4) JUSTIFICATION. Reached only under ConsensusExact with a non-null
        // value about to be committed. dashcore BLS-verifies what we commit
        // (specialtxman.cpp:164-167 => bad-cbtx-invalid-clsig), so we must be
        // able to say why this signature is good:
        //   - ChainCommitted: the network already accepted it inside block H-1.
        //     Re-committing it is dashd's own fallback and needs no local BLS.
        //   - BlsVerified: we verified it ourselves against its signing quorum.
        // Anything ELSE — including a value ADVANCED past block H-1's committed
        // ChainLock without local verification — is refused. This is what keeps
        // a BLS-dark build from silently becoming permissive: with no verifier
        // installed on_new_chainlock adopts nothing, so nothing ever advances
        // past ChainCommitted and this arm is never reached with an unproven
        // signature.
        const bool advancing =
            !m_tip_cbtx_cl_null && m_best_cl_height > m_tip_cbtx_cl_height;
        if (advancing && m_best_cl_prov != ClProvenance::BlsVerified)
            return no("bestcl-unverified-advance",
                      std::to_string(m_best_cl_height) + "@"
                          + prov_name(m_best_cl_prov),
                      ">" + std::to_string(m_tip_cbtx_cl_height)
                          + " requires bls-verified");
        if (m_best_cl_prov == ClProvenance::Unknown)
            return no("bestcl-unjustified", "provenance=unknown",
                      "chain-committed|bls-verified");
        return std::nullopt;
    }

    static const char* prov_name(ClProvenance p) {
        switch (p) {
        case ClProvenance::ChainCommitted: return "chain-committed";
        case ClProvenance::BlsVerified:    return "bls-verified";
        default:                           return "unknown";
        }
    }

    /// Quorum-set health (review PR #780 nit): parse_quorum_tail fails SAFE (keeps
    /// SML sync, skips quorum tracking). On a malformed tail the QuorumManager is
    /// left STALE while the SML advances, so merkleRootQuorums would be computed
    /// over the wrong set with no other viability signal. The maintainer sets
    /// this false when a diff's quorum tail fails to parse; viability then refuses
    /// the embedded arm. Default true (an empty tail parses fine).
    void set_quorum_healthy(bool v) { m_quorum_healthy = v; }
    bool quorum_healthy() const { return m_quorum_healthy; }

    /// DIAGNOSTIC MIRROR of the maintainer's payee-desync latch, so
    /// classify_decline() can report "mn-needs-reseed" instead of the far less
    /// useful "not-populated". Purely observational: nothing on the serve or
    /// reward path reads it.
    void set_mn_needs_reseed(bool v) { m_mn_needs_reseed = v; }
    bool mn_needs_reseed() const { return m_mn_needs_reseed; }

    /// Number of times embedded_template_emit_ok() has been evaluated on this
    /// state (counted at the top of the gate, before any early return). Test
    /// seam: pins that submit-path tip reads never evaluate the serve gate
    /// (the 2026-08-07/08 hotel freeze amplifier).
    uint64_t emit_ok_call_count() const { return m_emit_ok_calls; }

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
    /// `why` mirrors dashd's `TestBlockValidity(BlockValidationState& state, ...)`
    /// (dashcore src/node/miner.cpp:337): an optional out-param naming the
    /// FAILING check, so the caller can say what it discarded instead of
    /// logging a bare "pre-emit check FAILED". Defaulted null keeps every
    /// existing caller and KAT source-compatible.
    bool embedded_template_emit_ok(const DashWorkData& w,
                                   DeclineReport* why = nullptr) const {
        // Call counter FIRST, before any early return: the regression gate in
        // test_dash_submit_gate_scaling.cpp pins that a submit-path tip READ
        // (get_current_gbt_prevhash) never evaluates this gate -- the
        // 2026-08-07/08 hotel freeze was this method's SML CalcMerkleRoot
        // running per share submit on the io thread.
        ++m_emit_ok_calls;
        auto reject = [why](const char* c, std::string v, std::string t) -> bool {
            if (why) {
                why->viable    = false;
                why->cause     = c;
                why->value     = std::move(v);
                why->threshold = std::move(t);
            }
            return false;
        };
        if (why) *why = DeclineReport{};
        if (!m_require_sml) return true;
        // Symmetry with viability (review PR #780 nit): a stale quorum set must
        // never reach emit. (Under the H-1 heal this is already gated by
        // have_sml=false, but re-asserting keeps the defence-in-depth uniform.)
        if (!m_quorum_healthy)
            return reject("emit-quorum-unhealthy", "quorum-tail-parse-failed", "parsed-ok");
        // Defence in depth (the pre-emit gate re-asserts the height-class
        // guards even if viability was bypassed): a cached template built while
        // synced must not be SERVED after the chain has fallen behind.
        if (m_chain_synced_fn && !m_chain_synced_fn())
            return reject("emit-chain-not-synced",
                          "tip=" + std::to_string(m_prev_height) + ",synced=false",
                          "header-tip-current");
        const uint32_t next_h = m_prev_height + 1;
        // Superblock height-class guard (E-SUPERBLOCK): refuse unless the
        // daemonless govsync provider is trigger-confident for this height
        // (resolve_superblock().ok folds disabled-arm + unfunded cases).
        if (!resolve_superblock(next_h).ok)
            return reject("emit-superblock-refused", "not-trigger-confident",
                          "trigger-confident@h=" + std::to_string(next_h));
        // E1: with a qc plan installed the DKG-window heights are SERVED,
        // not refused — re-derive the mandatory type-6 set here and require
        // the BUILT template to carry exactly it (count + payload bytes, in
        // order). Any drift => discard for the reward-safe fallback. Without
        // a plan fn the PHASE-1 refusal stays.
        std::optional<QcBlockPlan> qc_plan;
        if (m_qc_plan_fn) {
            QcPlanGap qc_gap;
            qc_plan = m_qc_plan_fn(next_h, &qc_gap);
            if (!qc_plan)   // underivable — fail closed, NAMING what was missing
                return reject("emit-qc-plan-underivable", qc_gap.describe(),
                              "derivable-qc-plan@h=" + std::to_string(next_h));
            // Collect the type-6 payloads actually in the template.
            std::vector<std::vector<unsigned char>> got;
            for (const auto& tx : w.m_txs)
                if (tx.type == vendor::CFinalCommitmentTxPayload::SPECIALTX_TYPE)
                    got.push_back(tx.extra_payload);
            if (got.size() != qc_plan->commitments.size())
                return reject("emit-qc-count-drift", std::to_string(got.size()),
                              std::to_string(qc_plan->commitments.size()));
            for (size_t i = 0; i < got.size(); ++i) {
                auto expect = build_qc_tx(next_h, qc_plan->commitments[i]);
                if (got[i] != expect.extra_payload)
                    return reject("emit-qc-payload-drift", "qc[" + std::to_string(i) + "]-bytes",
                                  "planned-qc[" + std::to_string(i) + "]-bytes");
            }
            // ── PoSe-fold gate on REAL commitments (the #1083 landmine, now
            // ENFORCED — a comment refuses nothing). A verified real
            // commitment carrying !validMembers[i] for a listed member makes
            // dashd's verifier PoSePunish that MN (specialtxman.cpp:159-174),
            // and a punishment crossing the ban threshold flips the MN's
            // validity in THIS block's list — the committed merkleRootMNList
            // above is then wrong: bad-cbtx-mnmerkleroot, a silently lost
            // block. c2pool folds no PoSe pass, so serve a real commitment
            // ONLY when its PoSe pass is PROVABLY a no-op (every listed
            // member valid — the common case, so real-commitment serving
            // stays unblocked). Absent capability / unprovable => refuse:
            // fail-closed insurance until a real PoSe fold (mirror of the
            // confirmedHash rollover projection) is built. Null commitments
            // are exempt by dashd's own IsNull() guard (specialtxman.cpp:432)
            // — all-null plans are byte-unchanged through here.
            for (size_t i = 0; i < qc_plan->commitments.size(); ++i) {
                const auto& c = qc_plan->commitments[i];
                if (qc_commitment_is_null(c)) continue;   // IsNull() exempt
                const std::optional<bool> noop =
                    m_qc_pose_noop_fn ? m_qc_pose_noop_fn(c) : std::nullopt;
                if (!noop.has_value() || !*noop)
                    return reject(
                        "emit-qc-real-pose-unfolded",
                        "qc[" + std::to_string(i) + "]:type="
                            + std::to_string(static_cast<int>(c.llmqType))
                            + ",quorum=" + c.quorumHash.GetHex().substr(0, 12)
                            + ",pose_noop="
                            + (noop.has_value() ? "unproven" : "n/a"),
                        "pose-pass-provably-noop(all-listed-members-valid)");
            }
        } else if (m_commitment_window_fn && m_commitment_window_fn(next_h)) {
            return reject("emit-dkg-commitment-window",
                          "in-window@h=" + std::to_string(next_h), "off-window");
        }
        // Same single decision as viability, prefixed for the emit surface.
        if (auto cl = bestcl_decline()) {
            const std::string cause = "emit-" + (*cl)[0];
            return reject(cause.c_str(), (*cl)[1], (*cl)[2]);
        }
        // SOAK FIX (independent HEIGHT check): the credit-pool seed's OWN cbTx
        // height must be the tip we build on, else the accrual commits a stale
        // creditPoolBalance (bad-cbtx-assetlocked-amount). Independent of the
        // seed's value/hash — the only check that catches a one-block-behind seed.
        if (m_require_fresh_credit_pool
            && m_credit_pool_height != static_cast<int32_t>(m_prev_height))
            return reject("emit-creditpool-stale",
                          m_credit_pool_height >= 0 ? std::to_string(m_credit_pool_height)
                                                    : std::string("n/a"),
                          std::to_string(m_prev_height));
        // E4 re-soak fix: the payee queue must have folded every block
        // through the tip this template builds on, else the projected
        // masternode payee is a stale queue slot (bad-cb-payee). Re-assert
        // at emit so a cached template built before the queue lagged (or a
        // viability bypass) can never reach a miner.
        if (m_require_fresh_mn_payee
            && m_mnstates.last_applied_height() != m_prev_height)
            return reject("emit-payee-stale",
                          m_mnstates.last_applied_height() != 0
                              ? std::to_string(m_mnstates.last_applied_height())
                              : std::string("n/a"),
                          std::to_string(m_prev_height));
        // Incident h=2516595 (bad-cb-payee) mirror of the viability clause:
        // a template whose scheduled MN has an UNPROVEN operator-reward
        // split must never reach a miner, even via a cached template or a
        // viability bypass.
        if (m_require_provable_payout_split) {
            if (auto protx = mn_payout_split_unprovable_at_tip())
                return reject("emit-mn-payout-split-unprovable",
                              "protx=" + protx->GetHex().substr(0, 12),
                              "payout-set-known");
            // Structural re-derivation (defence in depth against a builder
            // that ignores the split — the exact h=2516595 defect): the
            // BUILT template's MN payment amounts must be dashd's
            // GetBlockTxOuts split of ITS OWN m_payment_amount —
            //   operator = floor(mn_payment * bps / 10000), owner = rest —
            // whenever the scheduled entry says a split is due. Amount
            // presence is checked (not scripts: the packed payee is an
            // address token; the builder KATs pin script identity).
            const auto expected = m_mnstates.find_expected_payee();
            if (expected && w.m_payment_amount > 0) {
                const auto it = m_mnstates.entries().find(*expected);
                if (it != m_mnstates.entries().end()) {
                    const int64_t mn_payment =
                        static_cast<int64_t>(w.m_payment_amount);
                    const int64_t op_due =
                        it->second.operator_payment_of(mn_payment);
                    if (op_due > 0) {
                        // Occurrence-counted so a 50/50 split (owner amount
                        // == operator amount) needs TWO outputs, not one
                        // double-matched.
                        const uint64_t own_amt =
                            static_cast<uint64_t>(mn_payment - op_due);
                        const uint64_t op_amt = static_cast<uint64_t>(op_due);
                        size_t own_n = 0, op_n = 0;
                        for (const auto& p : w.m_packed_payments) {
                            if (p.payee == "!6a") continue;
                            if (p.amount == own_amt) ++own_n;
                            if (p.amount == op_amt)  ++op_n;
                        }
                        const bool owner_ok =
                            own_amt == op_amt ? own_n >= 2 : own_n >= 1;
                        const bool op_ok =
                            own_amt == op_amt ? op_n >= 2 : op_n >= 1;
                        if (!owner_ok || !op_ok)
                            return reject(
                                "emit-mn-payout-split-drift",
                                "owner=" + std::to_string(mn_payment - op_due)
                                    + (owner_ok ? "-present" : "-MISSING")
                                    + ",operator=" + std::to_string(op_due)
                                    + (op_ok ? "-present" : "-MISSING"),
                                "both-split-amounts-in-template");
                    }
                }
            }
        }
        // FINDING-2 defence in depth: no template tx may spend a known MN
        // collateral outpoint. dashd's verifier removes that MN from the list
        // for THIS block (specialtxman.cpp:457-464, ALL txs, no special-tx
        // guard), so a committed root built from the unmodified list is
        // bad-cbtx-mnmerkleroot — a silently lost block on a winning share.
        // The builder already filters these out of selection; re-assert here
        // so a cached/bypassed template can never reach a miner.
        for (const auto& tx : w.m_txs) {
            uint256 protx;
            if (tx_spends_mn_collateral(m_mnstates, tx, &protx))
                return reject("emit-collateral-spend-in-template",
                              "mn=" + protx.GetHex().substr(0, 12),
                              "no-template-tx-spends-mn-collateral");
        }
        vendor::CCbTx cb;
        if (!vendor::parse_cbtx(w.m_coinbase_payload, cb))
            return reject("emit-cbtx-unparseable",
                          std::to_string(w.m_coinbase_payload.size()) + "-payload-bytes",
                          "parseable-CCbTx");
        if (cb.nHeight != static_cast<int32_t>(next_h))
            return reject("emit-cbtx-height-drift", std::to_string(cb.nHeight),
                          std::to_string(next_h));
        // FINDING-1: the root block next_h must commit is the tip SML with the
        // verifier's height-driven confirmation pass applied (specialtxman.cpp
        // :206-215 — see sml_projection.hpp). Comparing against the RAW tip
        // root here would re-approve the exact stale root the rollover
        // poisons, so re-derive the PROJECTED root; fail closed when the pass
        // is unprojectable (a null-confirmedHash entry with no known
        // registration height — at most ~nMasternodeMinimumConfirmations
        // blocks per unknown registration).
        //
        // D2 (2026-08-07/08 hotel freeze, remaining half of the class): the
        // projection returns a FRESH ~450 KB copy of the SML by value and its
        // root was re-hashed (~2000 x SHA256d) on EVERY evaluation — ~3 per
        // session per notify on the single io thread even after D1 removed
        // the per-share amplifier. Both the projected root and the quorum
        // root below are memoized at THIS level (per-NodeCoinState, epoch-
        // invalidated), because a memo on the per-call projection object is
        // cold by construction — that dead-end is what the deleted
        // "CalcMerkleRoot() caches upstream" comment in embedded_gbt.hpp
        // wrongly assumed. On an epoch match the projection copy itself is
        // skipped, not just the hashing. WHERE-and-HOW-OFTEN only: the
        // memoized value is byte-identical to the fresh computation
        // (test_dash_root_memo.cpp T3), and any epoch bump forces a full
        // recompute (T2 — a memo that never invalidates serves a stale root,
        // which is a silently LOST BLOCK, strictly worse than the freeze).
        if (!(m_sml_root_memo_valid
              && m_sml_root_memo_epoch == m_root_memo_epoch)) {
            auto proj = project_sml_confirmations(m_sml, m_prev_height,
                                                  m_prev_hash, m_mnstates,
                                                  m_mn_min_confirmations);
            if (!proj.ok)   // NOT memoized: fail-closed stays re-evaluated
                return reject("emit-mn-confirm-rollover-pending",
                              "protx=" + proj.unprojectable_protx.GetHex().substr(0, 12),
                              "known-registration-height");
            m_sml_root_memo       = proj.sml.CalcMerkleRoot();
            m_sml_root_memo_epoch = m_root_memo_epoch;
            m_sml_root_memo_valid = true;
        }
        if (cb.merkleRootMNList != m_sml_root_memo)
            return reject("emit-mnlist-root-drift",
                          cb.merkleRootMNList.GetHex().substr(0, 12),
                          m_sml_root_memo.GetHex().substr(0, 12));
        // E1: under a qc plan the committed root must be the WITH-BLOCK root
        // (fold of the plan's commitments over the active set — equal to the
        // plain root while the plan is all-null, diverging only once Phase L
        // serves real commitments). Without a plan, the plain PROVEN root —
        // memoized on the same epoch (D2: compute_merkle_root_quorums
        // re-serializes and SHA256d's every active commitment per call, the
        // second unmemoized root on this same path).
        if (!qc_plan
            && !(m_quorum_root_memo_valid
                 && m_quorum_root_memo_epoch == m_root_memo_epoch)) {
            m_quorum_root_memo       = compute_merkle_root_quorums(m_qmgr);
            m_quorum_root_memo_epoch = m_root_memo_epoch;
            m_quorum_root_memo_valid = true;
        }
        const uint256 expected_quorum_root = qc_plan
            ? qc_plan->merkle_root_quorums
            : m_quorum_root_memo;
        if (cb.merkleRootQuorums != expected_quorum_root)
            return reject("emit-quorum-root-drift",
                          cb.merkleRootQuorums.GetHex().substr(0, 12),
                          expected_quorum_root.GetHex().substr(0, 12));
        // A null committed clsig is a defect ONLY when dashcore forbids it —
        // i.e. when block H-1 itself committed a non-null ChainLock
        // (specialtxman.cpp:134-137). Under ConsensusExact, when block H-1
        // committed null, a null commit is legal and is what dashd emits
        // (miner.cpp:167-171); refusing it there would be pure loss.
        const bool null_commit_forbidden =
            m_bestcl_policy == BestClPolicy::ConsensusExact
                ? !m_tip_cbtx_cl_null
                : m_require_fresh_bestcl;
        if (null_commit_forbidden && !cb.has_best_cl_signature())
            return reject("emit-bestcl-null-committed", "null-clsig", "non-null-clsig");
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
            int64_t expected_credit_pool =
                m_credit_pool
                + compute_dash_platform_reward_post_v20_mn_rr(next_h,
                                                              m_mn_rr_height);
            // #107 PHASE 2 (B2): when the asset-lock fold is armed the builder
            // ADDED the pending type-8 term to the committed pool. Re-derive it
            // here from the SAME source (m_mempool's pending type-8 locks) with
            // the SAME arithmetic (asset_lock_fold.hpp) so the freshness gate
            // EXPECTS the accrued value instead of rejecting it. Off (default)
            // this term is 0 and the check is byte-identical to before.
            if (m_accrue_pending_asset_locks) {
                expected_credit_pool +=
                    pending_asset_lock_fold(m_mempool.pending_asset_lock_txs())
                        .accrued;
            }
            if (cb.creditPoolBalance != expected_credit_pool)
                return reject("emit-creditpool-value-drift",
                              std::to_string(cb.creditPoolBalance),
                              std::to_string(expected_credit_pool));
        }
        return true;
    }

    /// Assemble the selector input. has_state is populated() gated by the
    /// optional UTXO-maturity predicate; the two required pointers are always
    /// non-null (members), so viable() reduces to that gate -- exactly the
    /// semantics work_source.hpp documents.
    EmbeddedWorkInputs make_embedded_work_inputs() const {
        EmbeddedWorkInputs e;
        // E1: with a qc plan fn installed, DKG-window heights are SERVED
        // daemonlessly — the plan carries the mandatory type-6 set + the
        // with-block merkleRootQuorums. A nullopt plan (header gap / below
        // serve floor) refuses exactly like the PHASE-1 posture. Without a
        // plan fn the BLOCKER-1 window refusal below stays authoritative.
        std::optional<QcBlockPlan> qc_plan;
        // The gap is the qc clause's VALUE. It travels WITH the bool, because
        // a bare bool is exactly what left the refusal with nothing to print.
        QcPlanGap qc_gap;
        bool qc_ok = true;
        if (m_qc_plan_fn && m_populated) {
            qc_plan = m_qc_plan_fn(m_prev_height + 1, &qc_gap);
            qc_ok = qc_plan.has_value();
        }
        // Resolve the superblock disposition ONCE (fail-closed unless the
        // daemonless provider is trigger-confident) and thread the schedule.
        SuperblockDisposition sb = resolve_superblock(m_prev_height + 1);
        // #996 fail-closed: a MN payment is due at the tip we build on but the
        // NON-empty payee queue resolves no payee (find_expected_payee()
        // nullopt -- every entry isValid=false -- or, defensively, a projected
        // payee absent from the SML entry set); an empty queue means no
        // masternode set at all, not a resolution failure, and never trips.
        // The embedded builder would omit the MN coinbase output while
        // m_payment_amount still claims it:
        // fail-OPEN on a money path (bad-cb-payee). Refusing downgrades to the
        // dashd GBT fallback -- a template-SERVE refusal (free), not a
        // block-SUBMIT refusal.
        const bool payee_resolvable =
            !m_require_resolvable_payee || mn_payee_resolvable_at_tip();
        // Evaluated ONCE here, like qc_ok / sb_ok, and threaded into BOTH the
        // viability clause and the tx-suppression flag -- so the decision to
        // serve and the decision about what to serve cannot observe different
        // answers from the same predicate.
        const bool utxo_immature = m_utxo_ready_fn && !m_utxo_ready_fn();
        // ── THE decision, and its reason, from ONE evaluation ────────────────
        // dashd's ValidationState idiom (consensus/validation.h:69): the call
        // that returns false is the call that records why. Previously this was
        // a ten-clause AND producing a bare bool, with classify_decline()
        // holding an independent SECOND transcription of the same clauses for
        // logging — and the two had already drifted (classify_decline never
        // checked payee_resolvable, so a #996 money-path refusal surfaced as
        // "viable-race"). There is now exactly one list.
        e.decline   = evaluate_viability(qc_ok, qc_gap, sb.ok, payee_resolvable,
                                         utxo_immature);
        e.has_state = e.decline.viable;
        // NAME THE STATE: while the UTXO lane is immature under the OPT-IN
        // serving policy we DO serve, but only a coinbase-only body. The
        // builder marks the template (m_txset_empty_cause) and logs the
        // forgone fees, so this degraded-but-valid mode is never silent.
        // Two suppressed-body producers, most-specific cause first: the
        // utxo-immature serving window names itself; otherwise the default-OFF
        // --embedded-serve-mempool-txs posture does. Fee-carrying templates
        // require BOTH a mature UTXO lane AND the explicit operator opt-in.
        const bool utxo_immature_serving =
            utxo_immature
            && m_utxo_immature_policy == UtxoImmaturePolicy::ServeEmptyTxSet;
        // WINDOW 2 (intra-node eviction lag). The serve tip was promoted to H
        // by the diff-driven path (mnlistdiff-at-tip / cbTx credit-pool
        // re-anchor) BEFORE the embedded UTXO lane connected block H, so the
        // view is still at H-1: H's spent outpoints resolve as unspent and the
        // selection stale-input guard (which checks vins against the LIVE view)
        // is structurally blind to them, so H's txs would be packed into an H+1
        // template -> bad-txns-inputs-missingorspent on a winning share = a
        // thrown-away found block. dashd cannot expose this window because
        // CTxMemPool::removeForBlock runs synchronously inside ConnectBlock
        // before SetTip. Reproduce that invariant fail-closed: while the just-
        // promoted serve tip is NOT yet current in the UTXO/mempool view, serve
        // coinbase-only (fees=0, exact). Only armed when mempool-tx serving is
        // ON and the currency fn is wired; self-heals when the raced full_block
        // connects and evicts (median tip-body window 0.771s, p90 2.9s).
        const bool utxo_stale_at_tip =
            m_serve_mempool_txs
            && static_cast<bool>(m_utxo_current_fn)
            && !m_utxo_current_fn(m_prev_hash);
        e.suppress_mempool_txs =
            utxo_immature_serving || utxo_stale_at_tip || !m_serve_mempool_txs;
        // Most-specific cause first so soak greps attribute the window. The
        // cold-start immature window names itself; the Window-2 eviction lag is
        // next; the default-OFF posture is the residual.
        e.suppress_cause =
              utxo_immature_serving ? "utxo-immature-serving"
            : utxo_stale_at_tip     ? "utxo-stale-at-tip"
            :                         "mempool-txs-disabled";
        if (m_require_resolvable_payee && !payee_resolvable) {
            LOG_WARNING << "[EMBED-GATE] h=" << (m_prev_height + 1)
                        << " REFUSE embedded template: MN payment due but payee"
                        << " unresolvable from a non-empty MN set"
                        << " (find_expected_payee nullopt or projected payee"
                        << " absent from SML set) -- falling back to dashd GBT"
                        << " [#996 bad-cb-payee fail-closed].";
        }
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
        e.mn_min_confirmations = m_mn_min_confirmations;
        // Pinned local tx: pointer into this state (same lifetime discipline
        // as mnstates/mempool); the builder gates admission per template.
        e.pinned_local_txs     = m_have_pinned_local_tx
                                     ? &m_pinned_local_txs : nullptr;
        // #107 phase 2: accrue pending type-8 asset locks into the CbTx pool.
        e.accrue_pending_asset_locks = m_accrue_pending_asset_locks;
        // E-SUPERBLOCK: hand the resolved treasury schedule to the builder.
        // Empty at non-superblock heights and confidently-unfunded superblocks
        // (normal block); the winning trigger's payees at a funded superblock.
        e.superblock_payments  = std::move(sb.payments);
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
        // E1: hand the daemonless qc plan to the template builder — the
        // mandatory type-6 txs to place after the coinbase and the
        // with-block merkleRootQuorums the CbTx must commit.
        if (qc_plan) {
            e.qc_commitments       = std::move(qc_plan->commitments);
            e.has_quorum_root_override = true;
            e.quorum_root_override = qc_plan->merkle_root_quorums;
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

    /// DIAGNOSTIC surface over the SINGLE evaluation in
    /// make_embedded_work_inputs(). This does NOT re-derive anything: it runs
    /// the same bundle assembly and returns the reason that assembly recorded,
    /// so the name an operator reads is by construction the name of the branch
    /// that actually fired. (Before, this method held its own copy of the
    /// clause list — the drift that mislabelled #996 payee-unresolvable
    /// refusals as "viable-race".)
    ///
    /// NOTE: this classifies embedded VIABILITY only. The live get_work mainnet
    /// gate (--embedded-mainnet, work_source.cpp) sits ABOVE it; a wholly-unfed
    /// bundle surfaces as "not-populated", which on a gate-off node is how the
    /// absent mainnet opt-in manifests here.
    DeclineReport describe_decline() const {
        return make_embedded_work_inputs().decline;
    }

    /// Legacy string form — byte-identical wire text for every pre-existing
    /// cause, because the shadow ledger and its KATs key on it. New callers
    /// should take describe_decline(), which keeps value and threshold apart.
    std::string classify_decline() const {
        const DeclineReport d = describe_decline();
        if (d.viable) return "viable-race";
        if (d.cause == "bestcl-stale")
            return d.cause + " h=" + d.value + " vs tip=" + std::to_string(m_prev_height);
        if (d.cause == "creditpool-stale" || d.cause == "payee-stale")
            return d.cause + " h=" + d.value + " vs tip=" + d.threshold;
        if (d.cause == "dmn-stale")
            return "dmn-stale sml=" + d.value + " vs tip=" + d.threshold;
        return d.cause;
    }

private:
    /// THE clause list. The ONLY transcription of embedded-arm viability:
    /// make_embedded_work_inputs() derives has_state from `.viable`, and
    /// describe_decline()/classify_decline() read the very same object, so the
    /// decision and its name are one thing. Clauses are evaluated in the order
    /// the old AND used, and the FIRST unmet one is returned — exactly one
    /// named cause, never a list of maybes.
    ///
    /// qc_ok / sb_ok / payee_resolvable are passed IN because the caller has
    /// already paid for them (the qc plan and superblock schedule are needed by
    /// the builder regardless); re-invoking those predicates here would double
    /// the cost on a per-template path and, worse, could observe a different
    /// answer than the one the bundle was built from.
    /// `qc_gap` rides alongside `qc_ok` for the same reason the other inputs
    /// are passed in: it was measured at the one place that CAN measure it —
    /// the plan call — and re-deriving it here would mean a second plan build
    /// that could answer differently. It is meaningful only when !qc_ok.
    DeclineReport evaluate_viability(bool qc_ok, const QcPlanGap& qc_gap,
                                     bool sb_ok,
                                     bool payee_resolvable,
                                     bool utxo_immature) const {
        const uint32_t next_h = m_prev_height + 1;
        const std::string tip = std::to_string(m_prev_height);
        auto refuse = [](const char* c, std::string v, std::string t) {
            DeclineReport r;
            r.viable    = false;
            r.cause     = c;
            r.value     = std::move(v);
            r.threshold = std::move(t);
            return r;
        };

        // Evaluated once; the SAME value the pre-emit gate uses.
        const auto cl_decline = bestcl_decline();

        DeclineReport d;   // viable by default

        if (!m_populated)
            // Say WHICH half the maintainer is missing. -1 means it has never
            // reported, which is "n/a" — not "0", which would read as "we
            // measured have_tip and it was false".
            d = refuse("not-populated",
                       (m_have_tip_dbg < 0 || m_have_mn_dbg < 0)
                           ? std::string("n/a")
                           : "have_tip=" + std::to_string(m_have_tip_dbg)
                                 + ",have_mn=" + std::to_string(m_have_mn_dbg),
                       "have_tip=1,have_mn=1");
        else if (m_chain_synced_fn && !m_chain_synced_fn())
            // Checked EARLY: on a stale tip every relative gate below can be
            // satisfied and still be wrong, so their answers are not evidence.
            d = refuse("chain-not-synced", "tip=" + tip + ",synced=false",
                       "header-tip-current");
        else if (!qc_ok)
            // NAME THE MISSING QUORUM. "nullopt" satisfied the #1038/#1039
            // cause/value/threshold shape and defeated its purpose: it is a
            // value that cannot disagree with anything, so the largest
            // addressable refusal class was unactionable from the log alone.
            d = refuse("qc-plan-underivable", qc_gap.describe(),
                       "derivable-qc-plan@h=" + std::to_string(next_h));
        else if (utxo_immature
                 && m_utxo_immature_policy == UtxoImmaturePolicy::Refuse)
            // The DEFAULT posture (p2pool semantics: an unsynced node does not
            // serve templates). Under the opt-in ServeEmptyTxSet policy the
            // immature window is SERVED with a coinbase-only body instead --
            // see set_utxo_immature_policy(); the arm stays viable and
            // make_embedded_work_inputs sets suppress_mempool_txs so the
            // builder emits no mempool txs.
            d = refuse("utxo-immature", "utxo_ready=false", "utxo_ready=true");
        else if (!sb_ok)
            d = refuse("superblock-refused", "not-trigger-confident",
                       "trigger-confident@h=" + std::to_string(next_h));
        else if (!m_qc_plan_fn && m_commitment_window_fn && m_commitment_window_fn(next_h))
            d = refuse("dkg-commitment-window", "in-window@h=" + std::to_string(next_h),
                       "off-window");
        else if (cl_decline)
            // ONE decision, shared with the pre-emit gate (bestcl_decline()).
            d = refuse((*cl_decline)[0].c_str(), (*cl_decline)[1], (*cl_decline)[2]);
        else if (m_require_fresh_credit_pool
                 && m_credit_pool_height != static_cast<int32_t>(m_prev_height))
            // -1 is the member's own "never seeded" sentinel.
            d = refuse("creditpool-stale",
                       m_credit_pool_height >= 0 ? std::to_string(m_credit_pool_height)
                                                 : std::string("n/a"),
                       tip);
        else if (m_require_fresh_mn_payee
                 && m_mnstates.last_applied_height() != m_prev_height)
            // 0 means the payee queue has never folded a block.
            d = refuse("payee-stale",
                       m_mnstates.last_applied_height() != 0
                           ? std::to_string(m_mnstates.last_applied_height())
                           : std::string("n/a"),
                       tip);
        else if (m_require_sml && !m_have_sml)
            d = refuse("no-dmn-set", std::to_string(m_sml.size()) + "-entries",
                       ">=1-entry");
        else if (m_require_sml && !m_quorum_healthy)
            d = refuse("quorum-unhealthy", "quorum-tail-parse-failed", "parsed-ok");
        else if (m_require_sml && m_sml_current_hash != m_prev_hash)
            // A ZERO sml hash is "cold / wiped by reorg", not a block hash.
            //
            // Report the HEIGHT first and the discriminating hash TAIL second.
            // Both halves are load-bearing:
            //   * the height answers the only question an operator can act on —
            //     HOW FAR behind is the DML? one block (the ordinary tip-change
            //     round trip, ~54 ms measured) or many (a lost diff that will
            //     not self-heal until the next block)?
            //   * the hash tail still distinguishes a same-height fork from a
            //     lag, which the height alone cannot.
            // Before this, both fields rendered as twelve zeros — see
            // discriminating_hash_tail() for the measurement.
            d = refuse("dmn-stale",
                       m_sml_current_hash.IsNull()
                           ? std::string("cold/wiped")
                           : "h=" + (m_sml_current_height >= 0
                                         ? std::to_string(m_sml_current_height)
                                         : std::string("n/a"))
                                 + ",..." + discriminating_hash_tail(m_sml_current_hash),
                       "h=" + tip + ",..." + discriminating_hash_tail(m_prev_hash));
        else if (m_require_sml && find_unprojectable_confirmation(m_sml, m_mnstates))
            // FINDING-1 fail-closed fallback: an SML entry awaits its
            // height-driven confirmedHash rollover (specialtxman.cpp:206-215)
            // but the DMN view holds no registration height for it, so the
            // pass — and therefore the merkleRootMNList block next_h must
            // commit — cannot be projected. Refusing here costs at most
            // ~nMasternodeMinimumConfirmations blocks of embedded serve per
            // unknown registration; serving would risk a committed stale root
            // (bad-cbtx-mnmerkleroot = a silently lost winning share).
            d = refuse("mn-confirm-rollover-pending",
                       "protx=" + find_unprojectable_confirmation(m_sml, m_mnstates)
                                      ->GetHex().substr(0, 12),
                       "known-registration-height");
        else if (!payee_resolvable)
            d = refuse("payee-unresolvable",
                       std::to_string(m_mnstates.entries().size())
                           + "-entries-none-payable",
                       "expected-payee-in-SML@h=" + std::to_string(next_h));
        else if (m_require_provable_payout_split) {
            // Incident h=2516595 (bad-cb-payee): serving a height whose
            // scheduled MN carries an UNPROVEN operator-reward split builds
            // a coinbase dashd deterministically rejects — the won block is
            // lost. The value names the masternode so the operator can see
            // WHICH entry is starving the arm (a fresh checkpoint reseed or
            // one canonical payment of that MN clears it).
            if (auto protx = mn_payout_split_unprovable_at_tip())
                d = refuse("mn-payout-split-unprovable",
                           "protx=" + protx->GetHex().substr(0, 12),
                           "payout-set-known");
        }

        if (d.viable) return d;

        // DIAGNOSTIC REFINEMENT — renames an already-taken refusal, never
        // creates one. Both of these are strictly more informative than the
        // clause they replace, and neither is part of has_state, so they can
        // only run once viability has already failed. (The old classify_decline
        // checked m_prev_hash.IsNull() unconditionally and could therefore
        // report "no-tip" for an arm that was in fact serving.)
        if (m_mn_needs_reseed) {
            // The smoke rig once reported 639 consecutive "not-populated"
            // declines while the real cause was a payee desync that only an
            // authoritative re-seed clears — invisible to anyone reading the
            // classification.
            d.cause     = "mn-needs-reseed";
            d.value     = "latched";
            d.threshold = "cleared-by-authoritative-reseed";
        } else if (d.cause == "not-populated" && m_tip_body_pending_dbg
                   && m_have_tip_dbg == 0 && m_have_mn_dbg == 1) {
            // Body-first serve tip: a header tip is known but its block
            // inputs have not been parsed yet (cold start before the first
            // promotion, or an overdue-demoted pending window). The named
            // transient — NOT a header-sync fault, NOT an error state; the
            // value keeps both populate halves visible.
            //
            // ONLY WHEN THE TIP HALF IS THE ONE UNMET (have_tip=0, have_mn=1).
            // The pending flag says a header tip is awaiting its body; it does
            // NOT say the body is what is holding serving back. Two states the
            // unguarded rename got wrong, both measured on the instrumented
            // daemonless soak (86406d07, 2026-08-09 14:39–15:53):
            //
            //   have_tip=0, have_mn=0 — cold start. At 14:40:55 the arm was
            //   relabelled `tip-body-pending` while BOTH halves were unmet,
            //   and the MN half was the LONGER pole: the body folded at
            //   14:41:15 (have_tip 0→1) but the arm stayed down another 5 s
            //   waiting on have_mn. 19 s were charged to the block body when
            //   the MN seed owned the whole 126 s cold-start episode.
            //
            //   have_tip=1, have_mn=0 — a body-pending window opened while a
            //   serve tip already exists (steady state: we keep serving H-1
            //   work, which is correct and not a decline at all) and the MN
            //   set is what went away. There the tip body is not blocking
            //   ANYTHING and naming it sends the operator at the wrong lane.
            //
            // Both now keep `not-populated`, whose value already names the two
            // halves. The rename survives exactly where it is true: no serve
            // tip, MN set ready, the tip block's inputs the only thing missing.
            d.cause     = "tip-body-pending";
            d.threshold = "tip-body-folded";
            // …and WHICH input. See set_tip_body_pending_axis: the credit-pool
            // seed and the payee cursor arrive with the block body, the SML
            // currency only with a getmnlistd reply, so the two point at
            // different repair paths. Appended, never substituted — the
            // populate halves stay visible.
            if (m_tip_body_pending_axis && *m_tip_body_pending_axis)
                d.value += std::string(",awaiting=") + m_tip_body_pending_axis;
        } else if (d.cause == "not-populated" && m_prev_hash.IsNull()
                   && m_have_tip_dbg < 0) {
            // ONLY when the maintainer has told us nothing (never reported).
            //
            // Measured on the daemonless rig 2026-08-03: the header chain was
            // at h=2515420 and advancing every ~60 s, and this refinement was
            // reporting "no-tip". THIS CLASS's m_prev_hash is null merely
            // BECAUSE set_tip() has not run — a consequence of not publishing,
            // not an independent fact — and set_tip() only runs once the
            // maintainer holds BOTH halves. So while the MN set is unseeded,
            // prev_hash stays null forever no matter how current the headers
            // are, and relabelling to "no-tip" told the operator the exact
            // opposite of the truth: chase a header-sync fault that does not
            // exist, while the real blocker (have_mn=0) went unnamed.
            //
            // When the maintainer HAS reported, its have_tip/have_mn pair is
            // strictly better information than our own null pointer, in both
            // directions — have_tip=0 says headers, have_tip=1 says MN set —
            // so it wins.
            d.cause     = "no-tip";
            d.value     = "prev_hash=null,maintainer-never-reported";
            d.threshold = "prev_hash!=null";
        }
        return d;
    }

    // #996 helper: is the MN payee the embedded builder will need actually
    // resolvable at the tip we build on? Mirrors embedded_gbt.hpp's build-time
    // condition (build_embedded_workdata gates the MN PackedPayment on
    // mn_payment > 0). Returns false ONLY when a MN payment is due and the
    // NON-empty payee queue resolves no payee: every entry isValid=false (an
    // unobserved PoSe ban) or, defensively, the projection names a payee
    // absent from entries(). An EMPTY queue is not a resolution failure -- it
    // means no masternode set at all: either a network that legitimately has
    // none (the builder emits no MN output and dashd expects none) or a queue
    // not yet seeded, which the armed posture already fails closed via
    // require_sml (have_sml + sml current at tip) and require_fresh_mn_payee
    // (last_applied_height == prev_height). Firing on the empty set made the
    // embedded arm permanently non-viable on no-MN-set networks. Uses the
    // fee-free subsidy floor: mempool fees only RAISE block_value, so if the
    // floor MN payment is <= 0 no MN output is due and an absent payee is
    // legitimately fine -- the gate never over-refuses at a genuine
    // no-MN-payment height.
    bool mn_payee_resolvable_at_tip() const {
        if (m_mnstates.entries().empty()) return true;  // no MN set: nothing to resolve
        const uint32_t next_h = m_prev_height + 1;
        const int64_t reward = compute_dash_block_reward_post_v20(next_h);
        const int64_t platform_reward =
            compute_dash_platform_reward_post_v20_mn_rr(next_h, m_mn_rr_height);
        const int64_t mn_payment_floor =
            compute_dash_mn_payment_post_v20(reward) - platform_reward;
        if (mn_payment_floor <= 0) return true;   // no MN payment due at this height
        const auto expected = m_mnstates.find_expected_payee();
        if (!expected) return false;              // #996: nullopt while payment due
        return m_mnstates.entries().find(*expected) != m_mnstates.entries().end();
    }

    // Incident h=2516595 (bad-cb-payee): the scheduled payee's operator-
    // reward split must be PROVEN before the embedded arm may build the
    // height. dashd pays the MN share as a SET (owner + optional operator
    // output, masternode/payments.cpp GetBlockTxOuts) and validates scripts
    // AND amounts; the SML wire can never prove the split
    // (CSimplifiedMNListEntry keeps the payout scripts mem-only), so
    // provenance comes from checkpoint/seed rows, ProTx replay, or observed
    // canonical payouts — see MNState::payoutSplitProvenance. Returns the
    // scheduled proRegTxHash when the height must be REFUSED
    // (cause=mn-payout-split-unprovable), nullopt when serving is safe.
    // Follows mn_payee_resolvable_at_tip()'s no-payment-due carve-outs so
    // it can never over-refuse a height with no MN payment.
    std::optional<uint256> mn_payout_split_unprovable_at_tip() const {
        if (m_mnstates.entries().empty()) return std::nullopt;
        const uint32_t next_h = m_prev_height + 1;
        const int64_t reward = compute_dash_block_reward_post_v20(next_h);
        const int64_t platform_reward =
            compute_dash_platform_reward_post_v20_mn_rr(next_h, m_mn_rr_height);
        const int64_t mn_payment_floor =
            compute_dash_mn_payment_post_v20(reward) - platform_reward;
        if (mn_payment_floor <= 0) return std::nullopt;
        const auto expected = m_mnstates.find_expected_payee();
        if (!expected) return std::nullopt;   // payee-unresolvable owns this
        const auto it = m_mnstates.entries().find(*expected);
        if (it == m_mnstates.entries().end()) return std::nullopt; // ditto
        if (it->second.payout_split_provable()) return std::nullopt;
        return *expected;
    }

    /// Superblock disposition for a candidate next height. ok=false => refuse
    /// (fail closed). payments empty+ok => normal block; non-empty+ok => emit.
    struct SuperblockDisposition {
        bool ok{true};
        std::vector<SuperblockPayment> payments;
    };

    SuperblockDisposition resolve_superblock(uint32_t next_h) const {
        // Not a superblock height => nothing to do, arm serves normally.
        if (!m_is_superblock_fn || !m_is_superblock_fn(next_h))
            return SuperblockDisposition{true, {}};
        // It IS a superblock height. If the daemonless arm is not enabled,
        // refuse (route to the reward-safe dashd fallback) — old behaviour.
        if (!m_require_superblock_provider || !m_superblock_provider)
            return SuperblockDisposition{false, {}};
        // R5 COMPLETENESS GATE (structural): a trigger-confident answer from a
        // PARTIAL governance view is the confidently-wrong-winner hazard, so
        // the serve path additionally requires the govsync-completeness
        // predicate to be PRESENT and TRUE. Default-absent => refuse => the
        // reward-safe dashd fallback — landing vote-verify alone can never
        // open this path.
        if (!m_superblock_sync_complete_fn || !m_superblock_sync_complete_fn())
            return SuperblockDisposition{false, {}};
        // Consult the governance provider: nullopt => not trigger-confident =>
        // fail closed; a value (possibly empty = unfunded) => arm may serve.
        auto sched = m_superblock_provider(next_h);
        if (!sched) return SuperblockDisposition{false, {}};
        return SuperblockDisposition{true, std::move(*sched)};
    }

    // D2 root memo (2026-08-07/08 hotel freeze, remaining half of the class).
    // The epoch is bumped by every non-const accessor / setter whose target
    // feeds either committed root (sml()/qmgr()/mnstates()/set_tip()/
    // set_mn_min_confirmations()); the cached roots are valid only while
    // their captured epoch matches. Single-threaded ioc => plain uint64, no
    // lock (same discipline as every other member here). The cached values
    // are mutable because embedded_template_emit_ok() is const — same
    // pattern as m_emit_ok_calls below.
    void bump_root_memo_epoch() { ++m_root_memo_epoch; }
    uint64_t m_root_memo_epoch{0};
    mutable bool     m_sml_root_memo_valid{false};
    mutable uint64_t m_sml_root_memo_epoch{0};
    mutable uint256  m_sml_root_memo;         // projected-SML merkle root
    mutable bool     m_quorum_root_memo_valid{false};
    mutable uint64_t m_quorum_root_memo_epoch{0};
    mutable uint256  m_quorum_root_memo;      // plain active-set quorum root

    MnStateMachine m_mnstates;
    Mempool        m_mempool;
    vendor::CSimplifiedMNList m_sml;         // merkleRootMNList source (mnlistdiff-fed)
    QuorumManager  m_qmgr;                    // merkleRootQuorums source (quorum-tail-fed)
    int32_t  m_best_cl_height{0};             // best observed ChainLock height
    std::array<uint8_t, 96> m_best_cl_sig{};  // best observed ChainLock signature
    ClProvenance m_best_cl_prov{ClProvenance::Unknown};  // how it is justified (fail-closed default)
    // Block H-1's OWN committed ChainLock, off its coinbase CCbTx. This is the
    // term dashcore's CheckCbTxBestChainlock inequality is written against.
    int32_t  m_tip_cbtx_at_height{0};         // height of the block that supplied it (0 = never)
    int32_t  m_tip_cbtx_cl_height{-1};        // absolute CL height it committed (-1 = null/none)
    bool     m_tip_cbtx_cl_null{false};       // that coinbase committed a NULL bestCLSignature
    int64_t  m_credit_pool{0};                // DIP-0027 credit-pool balance (seeded from cbTx)
    bool     m_have_sml{false};               // a non-empty SML has been applied
    uint256  m_sml_current_hash;              // block hash the SML is current at (ZERO = cold/reorg)
    int64_t  m_sml_current_height{-1};        // DIAGNOSTIC ONLY, -1 = never reported; see set_sml_current_height
    bool     m_require_sml{false};            // gate viability on have_sml (embedded arm)
    // How many times embedded_template_emit_ok() was EVALUATED (incremented at
    // its top, before any early return). Test seam for the 2026-08-07/08 hotel
    // freeze regression gate: the serve gate re-derives the full SML merkle
    // root, so the count of evaluations per submit-path tip read must be ZERO
    // (test_dash_submit_gate_scaling.cpp). mutable because the gate is const.
    mutable uint64_t m_emit_ok_calls{0};
    std::function<bool()> m_utxo_ready_fn;   // optional UTXO maturity gate (E2b)
    // WINDOW-2 currency gate: optional predicate "is the UTXO view current at
    // this tip hash?" (UtxoLane::utxo_current_at). Unset => no Window-2 gate.
    std::function<bool(const uint256&)> m_utxo_current_fn;
    // Default REFUSES the immature window (p2pool semantics: an unsynced node
    // does not serve templates) -- byte-identical to the pre-policy behaviour.
    // ServeEmptyTxSet is the pure-daemonless opt-in (subsidy-only block beats
    // no block when there is no fallback). See set_utxo_immature_policy().
    UtxoImmaturePolicy m_utxo_immature_policy{UtxoImmaturePolicy::Refuse};
    // --embedded-serve-mempool-txs: DEFAULT OFF — coinbase-only serving; the
    // fee-carrying mempool-tx body path is an explicit operator opt-in (see
    // set_serve_mempool_txs).
    bool m_serve_mempool_txs{false};
    // #107 PHASE 2 (--embedded-accrue-asset-locks): DEFAULT OFF — accrue the
    // pending type-8 asset-lock term into the CbTx creditPoolBalance. See
    // set_accrue_pending_asset_locks. Consumed by make_embedded_work_inputs
    // (builder) and embedded_template_emit_ok (matching emit-gate re-derivation).
    bool m_accrue_pending_asset_locks{false};
    // Pinned local tx (set_pinned_local_tx): held by value for the lifetime of
    // this state; the bundle exposes a pointer only when the flag is set.
    // MULTIPLE pins: the donation consolidation had to be SPLIT after
    // 152258 bytes was rejected as bad-txns-oversize and cost block
    // 2517855. Four quarter-sized transactions ride ONE template.
    std::vector<MutableTransaction> m_pinned_local_txs;
    bool               m_have_pinned_local_tx{false};
    std::function<bool()> m_chain_synced_fn; // optional ABSOLUTE header-sync gate (never serve a stale tip)
    std::function<bool(uint32_t)> m_is_superblock_fn;  // superblock-height predicate
    // E-SUPERBLOCK: daemonless governance-sourced superblock schedule provider
    // + opt-in gate. Default gate OFF => every superblock height refuses (old
    // reward-safe behaviour); ON => resolve_superblock consults the provider.
    std::function<std::optional<std::vector<SuperblockPayment>>(uint32_t)> m_superblock_provider;
    bool m_require_superblock_provider{false};
    // R5 govsync-completeness gate: absent (default) or false => superblock
    // heights refuse the embedded arm even when the provider is confident.
    std::function<bool()> m_superblock_sync_complete_fn;
    std::function<bool(uint32_t)> m_commitment_window_fn;  // refuse embedded on DKG commitment heights
    // E1: serve DKG windows daemonlessly. The QcPlanGap out-param is how a
    // refusal learns WHICH quorum it lacked (see set_qc_plan_fn).
    std::function<std::optional<QcBlockPlan>(uint32_t, QcPlanGap*)> m_qc_plan_fn;
    // PoSe no-op proof for a REAL commitment (emit-qc-real-pose-unfolded gate);
    // unset => capability absent => every non-null commitment refused.
    std::function<std::optional<bool>(const vendor::CFinalCommitment&)> m_qc_pose_noop_fn;
    bool     m_require_fresh_bestcl{false};  // refuse embedded on a stale/absent bestCL
    BestClPolicy m_bestcl_policy{BestClPolicy::Off};  // Freshness stays the default when enabled
    bool     m_require_fresh_credit_pool{false}; // refuse embedded on a lagged credit-pool seed
    bool     m_require_fresh_mn_payee{false};    // refuse embedded on a lagged payee queue (stale cursor)
    // #996: fail-CLOSED default -- reads only mnstates (always present), needs
    // no external freshness wiring, and guards a money path, so unlike the
    // freshness gates above it defaults ON.
    bool     m_require_resolvable_payee{true};   // refuse embedded when a due MN payee is unresolvable (#996)
    bool     m_require_provable_payout_split{true}; // refuse embedded when the scheduled MN's operator-reward split is unproven (h=2516595 bad-cb-payee)
    int      m_mn_rr_height{DASH_MN_RR_HEIGHT_MAINNET}; // network MN_RR activation height (platform-share gate)
    int      m_mn_min_confirmations{DASH_MN_MIN_CONFIRMATIONS_MAINNET}; // network nMasternodeMinimumConfirmations (rollover projection)
    uint256  m_credit_pool_current_hash;     // block hash the credit-pool seed is current at
    int32_t  m_credit_pool_height{-1};       // seed cbTx's OWN height (-1 = never seeded)
    bool     m_quorum_healthy{true};         // last diff's quorum tail parsed OK
    // Mirror of CoinStateMaintainer's payee-desync latch, published here purely
    // so classify_decline() can NAME it. Never consulted by any serve/reward
    // path — the latch itself lives (and gates) in the maintainer.
    bool     m_mn_needs_reseed{false};
    // Publish-precondition mirror (-1 = the maintainer has never reported).
    int8_t   m_have_tip_dbg{-1};
    int8_t   m_have_mn_dbg{-1};
    // Body-first serve tip: header tip known, block inputs not yet parsed
    // (set_tip_body_pending_dbg). Diagnostic only, never gates anything.
    bool     m_tip_body_pending_dbg{false};
    // Which promotion conjunct is unmet (set_tip_body_pending_axis). Always a
    // string literal — never an owning pointer. Diagnostic only.
    const char* m_tip_body_pending_axis{""};
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
