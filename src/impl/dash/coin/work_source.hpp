// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Phase C-TEMPLATE step 5 (capstone): embedded-vs-dashd work-source selector.
///
/// build_embedded_workdata() (embedded_gbt.hpp) is source-complete and pinned
/// by test_dash_embedded_gbt (oracle: frstrtr/p2pool-dash getwork(),
/// older-than-v35 semantics). What was missing is a LIVE consumer: the running
/// node's get_work path must PREFER the locally-assembled embedded template and
/// fall back to dashd getblocktemplate only when the embedded coin-state bundle
/// is unavailable.
///
/// select_dash_work() is that branch point. When the EmbeddedWorkInputs bundle
/// is viable (masternode list + mempool + header-tip params all present) it
/// assembles the template LOCALLY via build_embedded_workdata() — the
/// oracle-parity path. Otherwise it invokes the supplied dashd fallback.
///
/// The external-daemon (dashd RPC) arm is NEVER removed: it is BOTH the fallback
/// AND the [GBT-XCHECK] cross-check. viable()==false must always route there.

#include <impl/dash/coin/embedded_gbt.hpp>       // build_embedded_workdata
#include <impl/dash/coin/mn_state_machine.hpp>   // MnStateMachine
#include <impl/dash/coin/mempool.hpp>            // Mempool
#include <impl/dash/coin/rpc_data.hpp>           // DashWorkData

#include <core/uint256.hpp>

#include <array>
#include <ctime>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

/// ONE named refusal, carried up the call chain BESIDE the decision that
/// produced it.
///
/// PRIOR ART (dashcore v23.1.7, src/consensus/validation.h:69 `ValidationState`):
/// dashd never returns a bare bool for "I cannot build this". Every refusal
/// path calls `state.Invalid(result, reject_reason, debug_message)`, which
/// RETURNS FALSE WHILE RECORDING WHY — the boolean and its reason are produced
/// by the same statement and so cannot drift. That state is threaded down
/// through `BuildNewListFromBlock` / `CalcCbTxMerkleRootQuorums` /
/// `GetCreditPoolDiffForBlock` / `TestBlockValidity` (src/node/miner.cpp:291-341)
/// and surfaced to the caller by `BIP22ValidationResult` (src/rpc/mining.cpp:515);
/// the getblocktemplate PRE-conditions ("…is not connected!", "…is in initial
/// sync and waiting for blocks…", "…is syncing with network…" — the last being
/// dashd's OWN superblock-not-synced refusal, src/rpc/mining.cpp:727-741) throw
/// a typed, named JSONRPCError. Either way the caller learns WHY; nothing
/// degrades silently.
///
/// We adopt the IDIOM, not the file. dashd's `Result` enum is block-rejection
/// taxonomy (BLOCK_MUTATED, BLOCK_CHAINLOCK …) with no overlap with arm
/// viability, and dashd's refusals THROW — which on our per-template hot path
/// would be swallowed by the caller's catch-all (work_source.cpp) and reproduce
/// the exact silence this type exists to end. So: reason RETURNED, not thrown,
/// and never re-derived by a parallel copy of the predicate list.
///
/// WHY IT MATTERS HERE, MEASURED: before this struct, `has_state` and
/// `NodeCoinState::classify_decline()` were two independent transcriptions of
/// the same ten-clause AND — and they HAD already drifted. classify_decline()
/// omitted the #996 `mn_payee_resolvable_at_tip()` clause entirely, so a
/// genuine unresolvable-payee refusal (a money path) was reported as
/// "viable-race", a benign race. A returned reason makes that unrepresentable.
///
/// `value` / `threshold` are STRINGS, not numbers, for one reason: a field that
/// was never evaluated must print the literal "n/a" and NEVER "0". Three
/// members of the coin state use zero/negative as "never measured" —
/// best_cl_height==0 is "no ChainLock ever observed", credit_pool_height==-1 is
/// "never seeded", last_applied_height()==0 is "never folded". Printing those
/// as heights reads like a measurement and is not one.
struct DeclineReport {
    std::string cause{"viable"};   ///< single greppable token, never a list, no spaces
    std::string value{"n/a"};      ///< what we MEASURED ("n/a" = never evaluated)
    std::string threshold{"n/a"};  ///< what it had to be ("n/a" = not numeric)
    bool        viable{true};      ///< true => no refusal; cause/value/threshold unused

    std::string one_line() const {
        return "cause=" + cause + " value=" + value + " threshold=" + threshold;
    }
};

/// The inputs build_embedded_workdata() consumes, plus a validity flag. For the
/// embedded path to be taken, has_state must be true AND both pointers non-null
/// (viable()). Until NodeImpl carries embedded coin-state in-process, callers
/// leave has_state=false and the selector routes to the dashd fallback.
struct EmbeddedWorkInputs {
    bool                  has_state{false};
    /// The reason has_state is false, produced by the SAME evaluation that set
    /// it. Hand-built test bundles leave it viable=true; production fills it in
    /// NodeCoinState::make_embedded_work_inputs().
    DeclineReport         decline;
    uint32_t              prev_height{0};
    uint256               prev_hash;
    const MnStateMachine* mnstates{nullptr};
    const Mempool*        mempool{nullptr};
    uint32_t              bits_for_next{0};
    uint32_t              mtp_at_tip{0};
    uint8_t               address_version{0};
    uint8_t               address_p2sh_version{0};
    // Optional seams. 0 => use build_embedded_workdata's own SAFE-ADDITIVE
    // defaults (std::time(nullptr) / 0x20000000 BIP9 baseline).
    uint32_t              curtime{0};
    uint32_t              version{0};

    // CCbTx (DIP-0004 type-5 extra_payload) seams. When sml AND qmgr are both
    // non-null, build_embedded_workdata folds the real type-5 payload
    // (merkleRootMNList + merkleRootQuorums + version-appropriate bestCL* +
    // creditPool) so the assembled coinbase is MAINNET-VALID. Left null by
    // legacy callers => empty payload (pre-CCbTx behavior, byte-unchanged).
    const vendor::CSimplifiedMNList* sml{nullptr};
    const QuorumManager*             qmgr{nullptr};
    int32_t                          best_cl_height{0};
    std::array<uint8_t, 96>          best_cl_sig{};
    int64_t                          credit_pool{0};
    // Network MN_RR activation height for the DIP-0027 platform-share accrual
    // (per-chainparams in dashcore). Mainnet default; main_dash sets the
    // testnet value via NodeCoinState::set_mn_rr_height (E4 re-soak fix).
    int                              mn_rr_height{DASH_MN_RR_HEIGHT_MAINNET};
    // Consensus::Params.nMasternodeMinimumConfirmations for the confirmedHash
    // rollover projection (sml_projection.hpp): mainnet 15, testnet/devnet/
    // regtest 1. Threaded from NodeCoinState::set_mn_min_confirmations.
    int                              mn_min_confirmations{DASH_MN_MIN_CONFIRMATIONS_MAINNET};

    // E1 daemonless DKG-window seams (dkg_commitments.hpp QcBlockPlan,
    // populated by NodeCoinState::make_embedded_work_inputs when a qc plan fn
    // is installed): the mandatory type-6 commitment set for this height
    // (empty off-window / all-mined) and the with-block merkleRootQuorums the
    // CbTx must commit. Absent (default) => pre-E1 behavior byte-for-byte
    // (no qc txs, plain compute_merkle_root_quorums root).
    std::vector<vendor::CFinalCommitment> qc_commitments;
    bool                             has_quorum_root_override{false};
    uint256                          quorum_root_override;
    // E-SUPERBLOCK seam: the governance-sourced treasury payout schedule for a
    // FUNDED superblock height (superblock.hpp::get_superblock_payments). Held
    // by value so it outlives the build closure. Empty => normal block (either
    // a non-superblock height or a confidently-unfunded superblock). It is only
    // ever populated when NodeCoinState resolved a trigger-confident, budget-
    // valid schedule; an under-synced superblock view leaves has_state=false
    // (viable()==false) so the arm fails closed to dashd instead.
    std::vector<SuperblockPayment>   superblock_payments;

    // UTXO-IMMATURE SERVING (see NodeCoinState::set_utxo_immature_policy). True
    // while the UTXO/fee lane is still below its maturity depth AND the policy
    // is ServeEmptyTxSet: the arm stays VIABLE (has_state true) and the builder
    // emits a coinbase-only body instead of the arm refusing outright. Does not
    // participate in viable() -- it is not a reason to serve or not serve, only
    // a statement about WHAT is served.
    bool                             suppress_mempool_txs{false};

    // NAME-THE-STATE for the suppressed body: WHY it is coinbase-only.
    // "utxo-immature-serving" (the historical producer) or
    // "mempool-txs-disabled" (--embedded-serve-mempool-txs default-OFF
    // posture; see NodeCoinState::set_serve_mempool_txs). String literal
    // lifetime only — never a computed string.
    const char*                      suppress_cause{"utxo-immature-serving"};

    // PINNED LOCAL TX (donation-dust consolidation lane): non-null when the
    // operator supplied --pin-local-tx-hex and NodeCoinState holds the parsed
    // tx. The builder gates admission per template; a null pointer is the
    // byte-unchanged legacy shape. Points into NodeCoinState (same lifetime
    // discipline as mnstates/mempool).
    const MutableTransaction*        pinned_local_tx{nullptr};

    bool viable() const {
        return has_state && mnstates != nullptr && mempool != nullptr;
    }
};

enum class WorkSource { Embedded, DashdFallback };

struct WorkSelection {
    DashWorkData work;
    WorkSource   source{WorkSource::DashdFallback};
    /// WHY the fallback arm was chosen, carried out of the SAME branch that
    /// chose it (dashd's ValidationState idiom — see DeclineReport). viable on
    /// the Embedded branch. The arm-selection call site logs THIS; it must
    /// never re-derive a reason of its own, because a reason computed beside
    /// the branch instead of by it can be right today and lie tomorrow.
    DeclineReport decline;
};

/// Injectable core — the routing decision, testable without a live daemon or a
/// populated MN/mempool harness. Production binds embedded_builder to the real
/// build_embedded_workdata() closure (see the 2-arg overload below).
inline WorkSelection select_dash_work(
    const EmbeddedWorkInputs& emb,
    const std::function<DashWorkData()>& embedded_builder,
    const std::function<DashWorkData()>& dashd_fallback)
{
    if (emb.viable())
        return WorkSelection{embedded_builder(), WorkSource::Embedded, DeclineReport{}};
    // The two pointer members are the only part of viable() that has_state does
    // not already cover, so name them rather than inherit a stale bundle reason.
    DeclineReport why = emb.decline;
    if (emb.has_state && (emb.mnstates == nullptr || emb.mempool == nullptr)) {
        why.viable    = false;
        why.cause     = "bundle-pointers-null";
        why.value     = std::string(emb.mnstates ? "mnstates=ok" : "mnstates=null")
                      + "," + (emb.mempool ? "mempool=ok" : "mempool=null");
        why.threshold = "mnstates!=null,mempool!=null";
    }
    WorkSelection out{dashd_fallback(), WorkSource::DashdFallback, std::move(why)};
    // PINNED LOCAL TX on the SERVED-dashd arm (option B, donation lane): the
    // dashd mempool cannot carry the >100KB zero-fee consolidation (policy
    // standardness), so the pin rides OUR served copy of dashd's template
    // instead. Same shared gate as the embedded arm (splice_pinned_tx);
    // coinbase value untouched (fee 0) — stratum merkle branches and the
    // submitblock body both derive from the appended tx vectors. Fail-closed:
    // without the verify view (mempool+mnstates, i.e. --embedded-utxo) the
    // pin is EXCLUDED with a named cause, never included unverified.
    // A PLACEHOLDER fallback is not a template. The serve path binds this arm
    // to a no-op closure returning DashWorkData{} (#1134: the real dashd RPC
    // must not run on the io thread), so splicing here judged a throwaway —
    // that is what produced `pinned tx EXCLUDED h=0` on the production primary
    // on 2026-08-07 while the REAL served template went unspliced. The serve
    // path now gates beside the coin state and appends at the real template
    // (DASHWorkSource::resolve_coin_state_arm + the re-source site); callers
    // that pass a genuine fallback still splice here.
    // The test is deliberately narrow: ONLY a value indistinguishable from a
    // default-constructed DashWorkData counts as a placeholder. Anything
    // carrying a height, a previous block, or transactions is a template that
    // told us something, and we splice into it. Refusing on any single missing
    // field would silently drop the pin from real templates.
    const bool fallback_is_placeholder =
        out.work.m_height == 0 && out.work.m_previous_block.IsNull()
        && out.work.m_txs.empty();
    if (emb.pinned_local_tx != nullptr && !fallback_is_placeholder) {
        if (emb.mempool == nullptr || emb.mnstates == nullptr) {
            LOG_INFO << "[dashd-splice] pinned tx EXCLUDED h="
                     << out.work.m_height << " cause=no-verify-view ("
                     << (emb.mempool ? "mempool=ok" : "mempool=null") << ","
                     << (emb.mnstates ? "mnstates=ok" : "mnstates=null")
                     << ") — enable --embedded-utxo to verify the pin";
        } else {
            // HEIGHT (measured on the primary 2026-08-07): dashd's GBT reply
            // does not always carry m_height by the time we splice — the live
            // node logged `pinned tx EXCLUDED h=0`. A zero height makes the
            // coinbase-maturity arm of the gate nonsense (next_height 0 marks
            // every coinbase input immature), so take the bundle's own tip
            // when dashd's copy is unset. emb.prev_height is the header tip we
            // just evaluated the arm against, so prev_height + 1 is the height
            // this template builds.
            if (out.work.m_height == 0 && emb.prev_height != 0)
                out.work.m_height = emb.prev_height + 1;
            splice_pinned_tx(out.work, *emb.pinned_local_tx,
                             *emb.mempool, *emb.mnstates, "dashd-splice");
        }
    }
    return out;
}

/// Production entry point: builds the embedded template from `emb` when viable,
/// else calls `dashd_fallback` (the retained external-daemon getblocktemplate
/// arm). dashd_fallback is REQUIRED — it is the always-reachable safety path.
inline WorkSelection select_dash_work(
    const EmbeddedWorkInputs& emb,
    const std::function<DashWorkData()>& dashd_fallback)
{
    return select_dash_work(
        emb,
        [&emb]() {
            return build_embedded_workdata(
                emb.prev_height, emb.prev_hash, *emb.mnstates, *emb.mempool,
                emb.bits_for_next, emb.mtp_at_tip,
                emb.address_version, emb.address_p2sh_version,
                emb.curtime ? emb.curtime
                            : static_cast<uint32_t>(std::time(nullptr)),
                emb.version ? emb.version : 0x20000000u,
                // underfill-observation seam left default (nullptr); the CCbTx
                // seams thread the SML/quorum/bestCL/creditPool through so the
                // LIVE embedded arm emits the real type-5 payload (empty when
                // sml/qmgr null — legacy callers unchanged).
                /*underfill_tripped=*/nullptr,
                emb.sml, emb.qmgr,
                emb.best_cl_height, emb.best_cl_sig, emb.credit_pool,
                // E1: mandatory type-6 set + with-block quorum root.
                emb.qc_commitments.empty() ? nullptr : &emb.qc_commitments,
                emb.has_quorum_root_override ? &emb.quorum_root_override
                                             : nullptr,
                emb.mn_rr_height,
                // E-SUPERBLOCK: funded superblock schedule (empty => normal block).
                emb.superblock_payments.empty() ? nullptr
                                                : &emb.superblock_payments,
                // confirmedHash rollover projection threshold (sml_projection.hpp).
                emb.mn_min_confirmations,
                // Coinbase-only serving: body suppressed, fees exactly 0;
                // the cause names WHICH suppressed mode this is
                // (utxo-immature-serving vs mempool-txs-disabled).
                emb.suppress_mempool_txs,
                emb.suppress_cause,
                // Pinned local tx (donation consolidation): admission gated
                // inside the builder per template; null => byte-unchanged.
                emb.pinned_local_tx);
        },
        dashd_fallback);
}

} // namespace coin
} // namespace dash
