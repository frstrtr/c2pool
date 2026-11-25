// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// GET /mempool_entry?txid=HEX body (fee-parity shadow tooling): Mempool::Probe
// as JSON. Pure: no node state, no locks; main_dash binds it to the live pool.
//
// "candidate" is the template selector's own gate (fee_fold_proven); "reason"
// names the first thing that keeps the tx out, in the order the selector
// meets them, so a comparator can bucket every miss without re-deriving it.

#include "mempool.hpp"

#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <string>

namespace dash::coin {

inline const char* mempool_probe_reason(const Mempool::Probe& p)
{
    if (!p.in_pool) return "not-in-pool";
    if (p.fee_fold_proven) return "candidate";
    if (p.n_vin_unresolved > 0) {
        if (p.first_unresolved_parent_in_pool) return "parent-in-pool-output-missing";
        if (p.first_unresolved_coin_spent) return "input-spent";
        return "input-not-in-any-coin-source";
    }
    if (p.n_vin == 0) return "input-free-special-tx-unpriced";  // e.g. a malformed asset-unlock payload
    if (p.fee_known) return "fee-forced-not-proven";   // a DSTX the fold could not price
    // Every input resolves now, but the entry is still unpriced: it waits for
    // recompute_unknown_fees (block connect), or its outputs exceed its inputs.
    return "fee-unknown-inputs-resolvable";
}

inline nlohmann::json mempool_probe_json(const uint256& txid, const Mempool::Probe& p)
{
    nlohmann::json j{
        {"txid", txid.GetHex()},
        {"in_pool", p.in_pool},
        {"reason", mempool_probe_reason(p)},
        {"sources", {{"utxo_view", p.utxo_view},
                     {"fold_live", p.fold_live},
                     {"fee_coin_lookup", p.fee_coin_lookup}}},
    };
    if (!p.in_pool) return j;
    j["time_added"]       = static_cast<int64_t>(p.time_added);
    j["fee_known"]        = p.fee_known;
    j["fee_fold_proven"]  = p.fee_fold_proven;
    j["in_feerate_index"] = p.in_feerate_index;
    j["fee"]              = p.fee;
    j["fee_delta"]        = p.fee_delta;
    j["base_size"]        = p.base_size;
    j["type"]             = p.tx_type;
    j["n_vin"]            = p.n_vin;
    j["n_vin_unresolved"] = p.n_vin_unresolved;
    if (p.n_vin_unresolved > 0) {
        j["first_unresolved"] = {
            {"vin", p.first_unresolved_vin},
            {"prevout_hash", p.first_unresolved_hash.GetHex()},
            {"prevout_index", p.first_unresolved_index},
            {"parent_in_pool", p.first_unresolved_parent_in_pool},
            {"coin_spent", p.first_unresolved_coin_spent},
        };
    }
    return j;
}

} // namespace dash::coin
