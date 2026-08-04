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

    /// Network nMasternodeMinimumConfirmations (dashcore Params().GetConsensus()
    /// .nMasternodeMinimumConfirmations — per-chainparams: mainnet 15, testnet/
    /// devnet/regtest 1; see sml_projection.hpp). Gates the confirmedHash
    /// rollover projection in the template build, the viability clause and the
    /// pre-emit root re-check. main_dash sets the testnet value next to
    /// set_mn_rr_height; the mainnet default keeps every existing caller
    /// byte-unchanged.
    void set_mn_min_confirmations(int c) { m_mn_min_confirmations = c; }
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
    void set_qc_plan_fn(std::function<std::optional<QcBlockPlan>(uint32_t)> fn) {
        m_qc_plan_fn = std::move(fn);
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

    /// DIAGNOSTIC MIRROR of the maintainer's payee-desync latch, so
    /// classify_decline() can report "mn-needs-reseed" instead of the far less
    /// useful "not-populated". Purely observational: nothing on the serve or
    /// reward path reads it.
    void set_mn_needs_reseed(bool v) { m_mn_needs_reseed = v; }
    bool mn_needs_reseed() const { return m_mn_needs_reseed; }

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
            qc_plan = m_qc_plan_fn(next_h);
            if (!qc_plan)   // underivable — fail closed
                return reject("emit-qc-plan-underivable", "nullopt",
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
        } else if (m_commitment_window_fn && m_commitment_window_fn(next_h)) {
            return reject("emit-dkg-commitment-window",
                          "in-window@h=" + std::to_string(next_h), "off-window");
        }
        if (m_require_fresh_bestcl
            && m_best_cl_height < static_cast<int32_t>(m_prev_height) - 1)
            return reject("emit-bestcl-stale",
                          m_best_cl_height > 0 ? std::to_string(m_best_cl_height)
                                               : std::string("n/a"),
                          ">=" + std::to_string(static_cast<int64_t>(m_prev_height) - 1));
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
        auto proj = project_sml_confirmations(m_sml, m_prev_height, m_prev_hash,
                                              m_mnstates,
                                              m_mn_min_confirmations);
        if (!proj.ok)
            return reject("emit-mn-confirm-rollover-pending",
                          "protx=" + proj.unprojectable_protx.GetHex().substr(0, 12),
                          "known-registration-height");
        if (cb.merkleRootMNList != proj.sml.CalcMerkleRoot())
            return reject("emit-mnlist-root-drift",
                          cb.merkleRootMNList.GetHex().substr(0, 12),
                          proj.sml.CalcMerkleRoot().GetHex().substr(0, 12));
        // E1: under a qc plan the committed root must be the WITH-BLOCK root
        // (fold of the plan's commitments over the active set — equal to the
        // plain root while the plan is all-null, diverging only once Phase L
        // serves real commitments). Without a plan, the plain PROVEN root.
        const uint256 expected_quorum_root = qc_plan
            ? qc_plan->merkle_root_quorums
            : compute_merkle_root_quorums(m_qmgr);
        if (cb.merkleRootQuorums != expected_quorum_root)
            return reject("emit-quorum-root-drift",
                          cb.merkleRootQuorums.GetHex().substr(0, 12),
                          expected_quorum_root.GetHex().substr(0, 12));
        if (m_require_fresh_bestcl && !cb.has_best_cl_signature())
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
            const int64_t expected_credit_pool =
                m_credit_pool
                + compute_dash_platform_reward_post_v20_mn_rr(next_h,
                                                              m_mn_rr_height);
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
        bool qc_ok = true;
        if (m_qc_plan_fn && m_populated) {
            qc_plan = m_qc_plan_fn(m_prev_height + 1);
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
        // ── THE decision, and its reason, from ONE evaluation ────────────────
        // dashd's ValidationState idiom (consensus/validation.h:69): the call
        // that returns false is the call that records why. Previously this was
        // a ten-clause AND producing a bare bool, with classify_decline()
        // holding an independent SECOND transcription of the same clauses for
        // logging — and the two had already drifted (classify_decline never
        // checked payee_resolvable, so a #996 money-path refusal surfaced as
        // "viable-race"). There is now exactly one list.
        e.decline   = evaluate_viability(qc_ok, sb.ok, payee_resolvable);
        e.has_state = e.decline.viable;
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
    DeclineReport evaluate_viability(bool qc_ok, bool sb_ok,
                                     bool payee_resolvable) const {
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
            d = refuse("qc-plan-underivable", "nullopt",
                       "derivable-qc-plan@h=" + std::to_string(next_h));
        else if (m_utxo_ready_fn && !m_utxo_ready_fn())
            d = refuse("utxo-immature", "utxo_ready=false", "utxo_ready=true");
        else if (!sb_ok)
            d = refuse("superblock-refused", "not-trigger-confident",
                       "trigger-confident@h=" + std::to_string(next_h));
        else if (!m_qc_plan_fn && m_commitment_window_fn && m_commitment_window_fn(next_h))
            d = refuse("dkg-commitment-window", "in-window@h=" + std::to_string(next_h),
                       "off-window");
        else if (m_require_fresh_bestcl
                 && m_best_cl_height < static_cast<int32_t>(m_prev_height) - 1)
            // best_cl_height 0 means "no clsig ever observed", NOT "ChainLock at
            // height 0" — print n/a rather than report a measurement never taken.
            d = refuse("bestcl-stale",
                       m_best_cl_height > 0 ? std::to_string(m_best_cl_height)
                                            : std::string("n/a"),
                       ">=" + std::to_string(static_cast<int64_t>(m_prev_height) - 1));
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
            d = refuse("dmn-stale",
                       m_sml_current_hash.IsNull()
                           ? std::string("n/a")
                           : m_sml_current_hash.GetHex().substr(0, 12),
                       m_prev_hash.GetHex().substr(0, 12));
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
    std::function<std::optional<QcBlockPlan>(uint32_t)> m_qc_plan_fn;  // E1: serve DKG windows daemonlessly
    bool     m_require_fresh_bestcl{false};  // refuse embedded on a stale/absent bestCL
    bool     m_require_fresh_credit_pool{false}; // refuse embedded on a lagged credit-pool seed
    bool     m_require_fresh_mn_payee{false};    // refuse embedded on a lagged payee queue (stale cursor)
    // #996: fail-CLOSED default -- reads only mnstates (always present), needs
    // no external freshness wiring, and guards a money path, so unlike the
    // freshness gates above it defaults ON.
    bool     m_require_resolvable_payee{true};   // refuse embedded when a due MN payee is unresolvable (#996)
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
