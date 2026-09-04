// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// GOOD-CITIZEN mempool-serving posture resolver for DGB — a PURE function so
/// the truth table is KAT-testable (test in dgb_mempool_ingest_test).
///
/// == WHY THIS EXISTS ========================================================
/// A daemonless DGB node (--coin-p2p-discover, no digibyted) builds every
/// served template from the embedded builder alone: unlike DASH, the DGB RPC
/// arm supplies only previousblockhash+bits, so there is no gbt cross-check /
/// fallback that could inject a daemon's full transactions[]. The embedded
/// builder is the SOLE transactions[] source in EVERY posture. The baseline a
/// good network citizen serves is what digibyted's own CreateNewBlock does:
/// include the valid, fee-paying mempool set, filling the block.
///
/// == THE TWO LEVERS =========================================================
///   embedded_utxo      — arms the embedded UTXO fee-proof lane (this PR, S1):
///                        open the UTXO view, fee-prove each relayed tx against
///                        it, so make_mempool_tx_source can select fee_known txs
///                        into a FEE-BEARING GBT template. Without it no tx ever
///                        fee-proves (fee_known=false) and the template stays
///                        coinbase-only — the exact behaviour before this lane.
///   serve_mempool_txs  — RESERVED for the reward-critical S2 follow-on: commit
///                        the selected set into the actually-mined stratum job
///                        (merkle branches + BIP141 witness commitment + fold
///                        fees into the connection coinbase). Until S2 lands the
///                        won block is coinbase-only + subsidy-only by
///                        construction (won_block_serialize fail-closes when the
///                        job carries no merkle branches), so this lever is inert
///                        here. It is carried in the struct so the resolver's
///                        contract does not change shape when S2 wires it.
///
/// == DEFAULT (this PR) ======================================================
/// embedded_utxo defaults OFF. It is dormant infrastructure: its only consumer
/// that changes SERVED bytes — the S2 job-commit — is not wired yet, and it
/// imposes a UTXO view build. When S2 lands, the good-citizen default for the
/// daemonless posture flips ON (serve the full mempool unless the operator opts
/// out), matching the DASH good_citizen_defaults rationale. An explicit
/// --embedded-serve-mempool-txs / =false is always honoured in both directions.
///
/// == REWARD SAFETY ==========================================================
/// Arming embedded_utxo only makes fees COMPUTABLE for the advisory GBT
/// template. It does NOT touch the connection coinbase (subsidy-only) or the
/// won-block merkle (coinbase-only, fail-closed) — those are S2. Selection
/// admits only fee_known txs against the spent-aware view (never overstated),
/// so the worst case of a stale view is an advisory template with a wrong fee
/// number, never an invalid block.

namespace dgb {
namespace coin {

/// One serving lever as requested on the command line. `on` is the positive
/// flag; `explicit_off` records the --<flag>=false spelling. Both false =
/// "operator said nothing" = eligible for the good-citizen default.
struct TxServeLever {
    bool on{false};
    bool explicit_off{false};
};

/// The levers the resolver governs (see header comment).
struct TxServeLevers {
    TxServeLever embedded_utxo;      // S1: fee-proof lane (this PR)
    TxServeLever serve_mempool_txs;  // S2: commit into the mined block (reserved)
};

/// The resolved posture.
struct TxServePosture {
    bool arm_embedded_utxo{false};   // open UTXO view + fee-prove relayed txs
    bool arm_serve_mempool_txs{false};
};

/// Pure resolver.
///
/// `good_citizen_default_on` is the default the daemonless posture would apply
/// when the operator said nothing. This PR passes it false (dormant S1 infra);
/// the S2 follow-on flips it true for the daemonless arm. An explicit ON always
/// wins; an explicit OFF always wins. serve_mempool_txs can never be armed
/// without embedded_utxo (a fee-bearing commit requires fee-proved txs), so the
/// resolver clamps it.
inline TxServePosture resolve_tx_serve_posture(const TxServeLevers& levers,
                                               bool good_citizen_default_on)
{
    auto resolve = [&](const TxServeLever& l) -> bool {
        if (l.explicit_off) return false;   // explicit opt-out wins
        if (l.on)           return true;    // explicit opt-in wins
        return good_citizen_default_on;     // silence -> the posture default
    };

    TxServePosture out;
    out.arm_embedded_utxo     = resolve(levers.embedded_utxo);
    out.arm_serve_mempool_txs = resolve(levers.serve_mempool_txs);
    // Clamp: no fee-bearing commit without the fee-proof lane behind it.
    if (!out.arm_embedded_utxo)
        out.arm_serve_mempool_txs = false;
    return out;
}

} // namespace coin
} // namespace dgb
