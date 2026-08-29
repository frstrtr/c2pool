// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// SERVE-TIME INTERNAL-CONSISTENCY REFEREE for the embedded (daemonless)
/// block-template tx-serving path.
///
/// == WHAT THIS REPLACES, AND WHY =============================================
/// The prior referee (work_source.cpp #130 branch, cause
/// "gbt-xcheck-txmerkle-mismatch") was a dashd-PARITY test: it recomputed the
/// non-coinbase tx-merkle-root of OUR selection and dashd's getblocktemplate
/// and, on ANY difference, threw away our template and served dashd's instead.
///
/// That is the wrong question. Two independently-connected nodes never hold
/// identical mempools (relay is gossip; admission is per-node policy over a
/// per-node UTXO view; each side snapshots at a different instant), so a
/// DIFFERENT-BUT-VALID tx set is NORMAL and produces a perfectly valid block.
/// The consensus requirement for the tx set is NOT parity with dashd; it is:
///
///   (a) coinbase fee-consistency -- the coinbase claims exactly the block
///       subsidy + the sum of the served per-tx fees (+ the treasury slice on
///       a funded superblock height). An over-claim is the bad-cb-amount
///       orphan vector.
///   (b) every served mempool tx is fee_fold_proven -- each vin present and
///       unspent in our UTXO view at build time, in_sum >= out_sum (the
///       selector's exclusion-discipline, strictly stronger than fee_known).
///   (c) no intra-set double-spend -- no two served txs spend the same coin.
///   (d) per-tx consensus/policy validity beyond (a)-(c) -- delegated to the
///       MEMPOOL VALIDITY GATE (mempool_validity_gate.hpp), a sustained
///       testmempoolaccept readiness window that gates the ARMING of
///       --embedded-serve-mempool-txs. Once armed, that residual is covered;
///       it is NOT a per-template serve gate and must not re-introduce a
///       set-difference-from-dashd fallback.
///
/// When (a)-(c) hold on an armed template the block is reward-safe: serving OUR
/// OWN set is correct and the daemonless mandate is met. If any fails the
/// caller MUST fail-close to the dashd fallback (safety preserved). The dashd
/// tx-merkle cross-check is kept as a SHADOW/diagnostic (the caller logs the
/// divergence) but is no longer serve-blocking.
///
/// == WHY THESE CHECKS ARE SOUND BY CONSTRUCTION ==============================
/// (a) embedded_gbt.hpp: block_value = reward + total_fees; m_coinbase_value =
///     block_value (+ superblock_total on a funded superblock height). Every
///     m_tx_fees entry is 0 (type-6 quorum commitments, zero-fee pins) or a
///     real fee that was folded into total_fees (asset-unlock payload fees;
///     mempool-selected fees), so Sum(m_tx_fees) == total_fees EXACTLY. The
///     subsidy is a pure function of height (subsidy.hpp), re-derived here with
///     the SAME function the builder used, so the equality below is the
///     builder's own invariant re-asserted at serve time -- it catches any
///     corruption of m_coinbase_value / m_tx_fees / the superblock slice
///     between build and serve.
/// (b) mempool.hpp get_sorted_txs_with_fees selects ONLY fee_fold_proven
///     entries ("if(!e.fee_fold_proven) continue;"). The builder records that
///     guarantee in the stamp; the referee fail-closes if it is ever false.
/// (c) folded here over the actual served vins -- fully independent of dashd.

#include <impl/dash/coin/rpc_data.hpp>
// utxo_adapter.hpp declares dash::coin::dash_txid, which subsidy.hpp uses in
// its computed_block_fees helper at namespace-parse time -- include it FIRST
// so this header is self-contained (work_source.cpp already has it via
// block_producer.hpp, but the referee unit test includes us standalone).
#include <impl/dash/coin/utxo_adapter.hpp>
#include <impl/dash/coin/subsidy.hpp>

#include <cstdint>
#include <set>
#include <string>
#include <utility>

namespace dash {
namespace coin {

/// Verdict of tx_serve_internal_referee. serve_own_set == true means the
/// embedded template is reward-safe to serve as-is despite differing from
/// dashd's tx set; false means the caller must fail-close to dashd and record
/// fail_cause. detail is a human-readable line for the log / status surface.
struct TxServeRefereeVerdict {
    bool        serve_own_set{false};
    std::string fail_cause;   // empty iff serve_own_set
    std::string detail;
};

/// Runs the internal-consistency referee over an armed embedded template. The
/// caller invokes this only on the tx-serve axis (m_mempool_tx_count > 0) after
/// the CbTx axes (#1216 creditPool / quorum / MN-root) have already been
/// cleared, so this function reasons about the tx SELECTION axis alone.
inline TxServeRefereeVerdict tx_serve_internal_referee(const DashWorkData& w)
{
    TxServeRefereeVerdict v;

    // (pre) PROVENANCE. Only a body the embedded mempool-serving path built
    // and stamped is eligible. A template that reached this axis with
    // m_mempool_tx_count>0 but no stamp is not one this referee can vouch for
    // -> fail-close. (Byte-neutral in practice: the caller runs the referee
    // only when the serve flag armed the build, which is exactly when the
    // stamp is set.)
    if (!w.m_tx_serve_stamp.armed) {
        v.fail_cause = "tx-serve-unstamped";
        v.detail     = "template carries mempool txs but no embedded serve"
                       " stamp (unproven provenance)";
        return v;
    }

    // (b) Every served mempool tx passed the fee-fold proof at selection.
    if (!w.m_tx_serve_stamp.all_mempool_fee_fold_proven) {
        v.fail_cause = "tx-serve-fee-fold-unproven";
        v.detail     = "a served mempool tx is not fee_fold_proven";
        return v;
    }

    // (a) COINBASE FEE-CONSISTENCY. coinbase_value must equal subsidy + the sum
    // of served per-tx fees + the treasury slice. Any over-claim is
    // bad-cb-amount; equality is the by-construction invariant re-asserted.
    uint64_t fee_sum = 0;
    for (uint64_t f : w.m_tx_fees) fee_sum += f;
    const uint64_t subsidy =
        static_cast<uint64_t>(compute_dash_block_reward_post_v20(w.m_height));
    const uint64_t expect =
        subsidy + fee_sum + w.m_tx_serve_stamp.superblock_total;
    if (w.m_coinbase_value != expect) {
        v.fail_cause = "tx-serve-coinbase-inconsistent";
        v.detail     = "coinbase_value=" + std::to_string(w.m_coinbase_value)
                     + " != subsidy=" + std::to_string(subsidy)
                     + " + fees=" + std::to_string(fee_sum)
                     + " + superblock="
                     + std::to_string(w.m_tx_serve_stamp.superblock_total);
        return v;
    }

    // (c) NO INTRA-SET DOUBLE-SPEND. No two served txs may spend the same
    // outpoint. Folds over the actual served vins (coinbase is not in m_txs);
    // type-6 quorum commitments and type-9 unlocks carry no vin, so they add
    // nothing. The "inputs unspent at tip" half of the double-spend guard is
    // the fee-fold proof (b), taken against the live UTXO view at build time.
    std::set<std::pair<std::string, uint32_t>> spent;
    for (const auto& tx : w.m_txs) {
        for (const auto& in : tx.vin) {
            auto key = std::make_pair(in.prevout.hash.GetHex(),
                                      in.prevout.index);
            if (!spent.insert(key).second) {
                v.fail_cause = "tx-serve-double-spend";
                v.detail     = "two served txs spend outpoint "
                             + key.first + ":" + std::to_string(key.second);
                return v;
            }
        }
    }

    v.serve_own_set = true;
    v.detail = "internally consistent: coinbase fee-exact ("
             + std::to_string(w.m_coinbase_value) + "="
             + std::to_string(subsidy) + "+" + std::to_string(fee_sum)
             + "+" + std::to_string(w.m_tx_serve_stamp.superblock_total)
             + "), all fee_fold_proven, no double-spend";
    return v;
}

} // namespace coin
} // namespace dash
