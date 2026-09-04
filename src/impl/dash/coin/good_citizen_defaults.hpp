// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// GOOD-CITIZEN DEFAULT for the daemonless (dashd-cut) posture: SERVE THE
/// FULL MEMPOOL unless the operator explicitly opts out.
///
/// == WHY THIS EXISTS ========================================================
/// A node started WITHOUT any dashd arm (--coin-rpc / --coin-rpc-auth /
/// --submit-block all absent) serves templates built ONLY by the embedded
/// builder. Before this resolver, the mempool-tx serving levers all defaulted
/// OFF (the repo's money-path flag rule), so a daemonless node's templates
/// were coinbase-only: a pool that wins a block with them mines a block that
/// processes ZERO DASH transactions. That is a bad network citizen — it hurts
/// chain throughput and user confirmation times, and it directly undermines
/// the claim that this pool is infrastructure worth funding. The baseline for
/// a daemonless node is what dashd's own CreateNewBlock does: include every
/// valid mempool transaction, filling the block.
///
/// On a dashd-ARMED node the defaults stay exactly as before (all OFF):
/// there the gbt cross-check / fallback already serves dashd's full template
/// when the embedded body is coinbase-only, so tx fullness is provided by
/// dashd and flipping embedded defaults would change served bytes on
/// deployments that did not ask for it.
///
/// == WHAT IS FLIPPED (daemonless posture only) ==============================
///   serve_mempool_txs  — the embedded builder packs the selected mempool set
///                        (G1-G4 guarded; blockMinFeeRate + nConsecutiveFailed
///                        selection parity; IS/CL-hold).
///   tx_serve_own_set   — REQUIRED with the above in daemonless mode: it arms
///                        the serve-time internal-consistency referee
///                        (tx_serve_referee.hpp — coinbase fee-exact, every tx
///                        fee_fold_proven, no intra-set double-spend, ZERO
///                        dashd calls). Without it a fee-carrying template
///                        would serve with no serve-time self-validation,
///                        because the only other referee call site lives in
///                        the dashd gbt-xcheck branch that a daemonless node
///                        never enters.
///   mempool_ingest     — the coin-P2P MSG_TX pull; without it the mempool
///                        never fills and "serving" is vacuously coinbase-only.
///   ingest_isdlock     — islock knowledge feed for the InstantSend mining
///                        hold (conflict defence). The hold self-gates on feed
///                        liveness, so this only ADDS safety.
///   ingest_dstx        — CoinJoin DSTX lane; without it CoinJoin txs are
///                        structurally excluded from served blocks (a
///                        fullness gap vs dashd).
///   embedded_mainnet   THE GATE. Without it resolve_embedded_arm returns
///                        DashdFallback/NoOptIn and a daemonless node (no
///                        dashd, no --coin-rpc) serves NOTHING — miners idle.
///                        Flipping it ON in the daemonless posture also implies
///                        coin-P2P discovery (arm_resolution.hpp discover_implied),
///                        so a bare `--run` syncs and serves. Byte-parity of the
///                        mainnet embedded template is proven (v0.2.4 gate-lift).
///   embedded_utxo      the E2b UTXO/fee lane. Without it no mempool tx ever
///                        fee-proves (fee_fold_proven=false → coinbase-only), so
///                        serve_mempool_txs above is vacuous. Selection still
///                        admits only fee_fold_proven txs (never overstated).
///   null_arm           #127: at a required-not-yet-mined DKG window slot,
///                        serve the consensus-valid NULL commitment (dashd's own
///                        GetMineableCommitments behaviour) instead of refusing
///                        the whole height. Freshness-gated: unproven ⇒ no null ⇒
///                        refuse (today's benign gap), NEVER a guessed reject.
///   superblock         daemonless superblock payee sourcing via govsync. Three
///                        fail-closed layers (BLS operator-key vote verify +
///                        EvoNode-4x weight, completeness, desync latch); a
///                        non-confident trigger refuses exactly as today, never a
///                        guessed payee. Implies the govsync pull at the call site.
///   include_mn_special_txs  the special-tx superset (DIP types 1-4). The builder
///                        DROPS any tx the SML fold cannot apply exactly and the
///                        emit gate re-folds and rejects on root drift, so an
///                        included special tx always commits a folded MN root.
///   accrue_asset_locks type-8 DIP-0027 asset-lock accrual. Body membership and
///                        creditPool accrual are the SAME bit (embedded_gbt.hpp
///                        allow_locks == accrue), so CbTx creditPoolBalance always
///                        reflects the served body.
///   accrue_asset_unlocks  type-9 asset-unlock admission. INERT until the
///                        CreditPool INDEX follower is seeded (work_source.hpp
///                        passes nullptr today); the predicate, not the flag,
///                        admits — so defaulting it ON is safe and honest.
///
/// Each lever keeps an explicit opt-out (--<flag>=false). An explicit ON is
/// honoured in both postures. The resolver is a pure function so the
/// truth table is KAT-testable (test_dash_good_citizen_defaults.cpp).
///
/// == REWARD SAFETY ==========================================================
/// The flip arms exactly the ladder proven live on the production money node
/// (block 2526820: 48 mempool txs + coinbase, arm=EMBEDDED, self-validation
/// OK, chainlocked). All build-time guards are unconditional once armed:
/// selection admits only fee_fold_proven txs against the spent-aware UTXO
/// view, the utxo-stale-at-tip window serves coinbase-only fail-closed
/// (node_coin_state.hpp Window 2), admission rejects already-confirmed txs,
/// and the referee fail-closes to no-work (last good work held) — never an
/// unvalidated serve. A node without the embedded UTXO lane degrades to
/// coinbase-only (nothing fee-proves), never to an unsafe serve.

namespace dash {
namespace coin {

/// One mempool-serving lever as requested on the command line. `on` is the
/// positive flag; `explicit_off` records the --<flag>=false spelling. Both
/// false = "operator said nothing" = eligible for the good-citizen default.
struct TxServeLever {
    bool on{false};
    bool explicit_off{false};
};

/// The levers the good-citizen default governs. The first five arm the mempool
/// FILL + serve + referee lane; the next seven are the template-completeness
/// levers (arm gate, fee lane, null slot, superblock, special-tx superset,
/// asset-lock/unlock accrual) that make "serve the full mempool" non-vacuous —
/// without them a bare `--run` either serves nothing (embedded_mainnet OFF) or a
/// coinbase-only body.
struct TxServeLevers {
    TxServeLever serve_mempool_txs;
    TxServeLever tx_serve_own_set;
    TxServeLever mempool_ingest;
    TxServeLever ingest_isdlock;
    TxServeLever ingest_dstx;
    TxServeLever embedded_mainnet;
    TxServeLever embedded_utxo;
    TxServeLever null_arm;
    TxServeLever superblock;
    TxServeLever include_mn_special_txs;
    TxServeLever accrue_asset_locks;
    TxServeLever accrue_asset_unlocks;
};

/// Resolved arming decision plus the facts a caller needs to log truthfully.
struct TxServeResolution {
    bool serve_mempool_txs{false};
    bool tx_serve_own_set{false};
    bool mempool_ingest{false};
    bool ingest_isdlock{false};
    bool ingest_dstx{false};
    bool embedded_mainnet{false};
    bool embedded_utxo{false};
    bool null_arm{false};
    bool superblock{false};
    bool include_mn_special_txs{false};
    bool accrue_asset_locks{false};
    bool accrue_asset_unlocks{false};
    /// True iff the daemonless default flipped at least one lever ON that the
    /// operator did not spell out — the caller logs WHICH posture armed it.
    bool defaulted_any{false};
    /// True iff the resolved combination can serve fee-carrying templates
    /// with the serve-time referee disarmed: serve_mempool_txs ON while
    /// tx_serve_own_set is OFF in the daemonless posture. Impossible via
    /// defaults (the resolver arms them together); reachable only by an
    /// explicit operator opt-out — the caller must WARN, loudly.
    bool unsafe_serve_without_referee{false};
};

/// THE resolver. `daemonless_posture` is the operator-declared cut posture:
/// no --coin-rpc, no --coin-rpc-auth, no --submit-block on the command line.
/// (A stray ~/.dashcore/dash.conf may still arm a dashd fallback inside
/// run_node; that only ADDS guards — the gbt cross-check — on top of the
/// referee, so the flip is safe in that corner too, and the operator's
/// declared posture, not the stray file, decides the default.)
inline TxServeResolution resolve_good_citizen_tx_serve(
    bool daemonless_posture, const TxServeLevers& req)
{
    const auto resolve = [daemonless_posture](const TxServeLever& l,
                                              bool& defaulted) -> bool {
        if (l.explicit_off) return false;          // operator opt-out wins
        if (l.on) return true;                     // explicit ON honoured
        if (daemonless_posture) { defaulted = true; return true; }
        return false;                              // dashd-armed: unchanged
    };

    TxServeResolution r;
    r.serve_mempool_txs = resolve(req.serve_mempool_txs, r.defaulted_any);
    r.tx_serve_own_set  = resolve(req.tx_serve_own_set,  r.defaulted_any);
    r.mempool_ingest    = resolve(req.mempool_ingest,    r.defaulted_any);
    r.ingest_isdlock    = resolve(req.ingest_isdlock,    r.defaulted_any);
    r.ingest_dstx       = resolve(req.ingest_dstx,       r.defaulted_any);
    r.embedded_mainnet  = resolve(req.embedded_mainnet,  r.defaulted_any);
    r.embedded_utxo     = resolve(req.embedded_utxo,     r.defaulted_any);
    r.null_arm          = resolve(req.null_arm,          r.defaulted_any);
    r.superblock        = resolve(req.superblock,        r.defaulted_any);
    r.include_mn_special_txs =
        resolve(req.include_mn_special_txs, r.defaulted_any);
    r.accrue_asset_locks =
        resolve(req.accrue_asset_locks,   r.defaulted_any);
    r.accrue_asset_unlocks =
        resolve(req.accrue_asset_unlocks, r.defaulted_any);
    r.unsafe_serve_without_referee =
        daemonless_posture && r.serve_mempool_txs && !r.tx_serve_own_set;
    return r;
}

} // namespace coin
} // namespace dash
