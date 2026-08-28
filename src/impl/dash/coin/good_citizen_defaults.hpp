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

/// The five levers the good-citizen default governs.
struct TxServeLevers {
    TxServeLever serve_mempool_txs;
    TxServeLever tx_serve_own_set;
    TxServeLever mempool_ingest;
    TxServeLever ingest_isdlock;
    TxServeLever ingest_dstx;
};

/// Resolved arming decision plus the facts a caller needs to log truthfully.
struct TxServeResolution {
    bool serve_mempool_txs{false};
    bool tx_serve_own_set{false};
    bool mempool_ingest{false};
    bool ingest_isdlock{false};
    bool ingest_dstx{false};
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
    r.unsafe_serve_without_referee =
        daemonless_posture && r.serve_mempool_txs && !r.tx_serve_own_set;
    return r;
}

} // namespace coin
} // namespace dash
