// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// /local_stats "ltc_utxo" (#2137, DESIGN 9.1): the depth of the UTXO view the
// embedded LTC template prices against, and the mempool counters of what that
// view cannot price. A partial (accrual) view admits a tx spending a coin
// older than the view fee-unknown, and an unpriced tx is never selected: the
// largest class of the fee gap to litecoind. These keys let the referee
// measure it instead of inferring it.
//
//   anchor_height     first height whose coins the view holds: the sync
//                     state's when the set records one ("sync_state"), else
//                     the first block this process connected into an empty
//                     set ("observed": a cold start or a re-anchor), else
//                     null ("unknown": an accrual view loaded from disk)
//   anchor_source     which of the three
//   best_height / best_block, blocks_connected
//   depth             best_height - anchor_height + 1 (null when unknown)
//   behind            the header tip's height - best_height (0 at the tip)
//   complete          built from genesis and its best block IS the tip
//   (main_ltc adds "mode": "full" | "accrual", and "full": the full set's
//   lane while it builds, --ltc-utxo-full)
//   missing_inputs / inputs_invalid   admission refusals by those codes
//                     (missing_inputs counts only with a set from genesis:
//                     a partial view admits such a tx fee-unknown)
//   admitted_unpriced txs admitted fee-unknown against the view
//   still_unknown     pool entries whose fee is unknown now

#include "mempool.hpp"

#include <core/coin/utxo_view_cache.hpp>
#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>

namespace ltc {
namespace coin {

/// `observed_anchor`: the first height connected into an empty set by this
/// process (0 = none). `chain_height` / `chain_tip`: the header chain's tip
/// (a null hash: no tip).
inline nlohmann::json utxo_view_json(const core::coin::UTXOViewCache* utxo,
                                     uint32_t observed_anchor,
                                     uint32_t chain_height, const uint256& chain_tip,
                                     const Mempool* pool)
{
    nlohmann::json j = nlohmann::json::object();
    std::optional<uint32_t> anchor;
    std::string source = "unknown";
    uint32_t best_height = 0;
    uint256 best_hash;
    if (utxo) {
        const auto best = utxo->get_best();
        best_hash = best.first;
        best_height = best.second;
        const auto ss = utxo->sync_state();
        if (ss.tracked()) {
            anchor = ss.anchor_height;
            source = "sync_state";
        } else if (observed_anchor != 0 && !best_hash.IsNull() && observed_anchor <= best_height) {
            anchor = observed_anchor;
            source = "observed";
        }
        j["blocks_connected"] = utxo->blocks_connected();
        j["complete"] = !chain_tip.IsNull() && utxo->complete(chain_height, chain_tip);
    } else {
        j["blocks_connected"] = 0;
        j["complete"] = false;
    }
    j["anchor_height"] = anchor ? nlohmann::json(*anchor) : nlohmann::json(nullptr);
    j["anchor_source"] = source;
    j["best_height"] = best_height;
    j["best_block"] = best_hash.GetHex();
    j["depth"] = (anchor && !best_hash.IsNull() && *anchor <= best_height)
        ? nlohmann::json(best_height - *anchor + 1) : nlohmann::json(nullptr);
    j["behind"] = chain_height > best_height ? chain_height - best_height : 0;
    if (pool) {
        const auto& st = pool->reject_stats();
        j["missing_inputs"] = st.by_code[Mempool::Reject::missing_inputs].load(std::memory_order_relaxed);
        j["inputs_invalid"] = st.by_code[Mempool::Reject::inputs_invalid].load(std::memory_order_relaxed);
        j["admitted_unpriced"] = st.admitted_unpriced.load(std::memory_order_relaxed);
        j["still_unknown"] = pool->unpriced_count();
    }
    return j;
}

} // namespace coin
} // namespace ltc
