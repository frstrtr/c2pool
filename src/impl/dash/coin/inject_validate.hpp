// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// POST /api/tx-inject/validate — the reply of the inject dry run
/// (NodeCoinState::validate_inject; c2wallet Scan & Plan, node slice N3).
///
///   { ok, dry_run: true, would_admit, cause, gate, txid, armed,
///     fee (duffs, null when unpriced), next_height (null: tip unknown),
///     immature_at_next_height, script_failed_input?,
///     inputs: [{ txid, vout, resolved, source, value, height, coinbase,
///                spendable_from_height, immature, mempool_spent_by? }],
///     conflicts: [{ txid, vout, spent_by }],
///     http_status }
///
/// `cause` is what a submit would answer first ("inject-disabled", a pool
/// cap, an add_inject gate name), then what admission does not check:
///   "inject-tip-unknown"              the node has no tip yet, so maturity
///                                     cannot be judged (transient: ask again)
///   "inject-immature-coinbase-input"  a coinbase input below 100
///                                     confirmations at next_height: the
///                                     template build would drop the tx
///                                     silently (wait for spendable_from_height)
///   "inject-input-spent-in-mempool"   another pool tx spends an input
///                                     (conflicts[] names it; the selector
///                                     would keep one of the two)
/// A dry run refused by its own budget answers the submit's local names
/// "inject-rate-limited-count" / "inject-rate-limited-bytes" with nothing
/// analysed (retry after the 60 s window). `ok` = cause "ok". http_status as
/// for a submit: 200 ok, 409 inject-disabled, 422 otherwise. Unknown fields
/// stay absent, never guessed: an input from an unconfirmed pool parent has
/// height and spendable_from_height null.

#include "node_coin_state.hpp"

#include <nlohmann/json.hpp>

namespace dash {
namespace coin {

inline nlohmann::json inject_validate_json(const NodeCoinState::InjectValidateResult& r)
{
    using nlohmann::json;
    json j = json::object();
    j["ok"] = r.ok;
    j["dry_run"] = true;
    j["would_admit"] = r.would_admit;
    j["cause"] = r.cause;
    j["gate"] = r.gate.empty() ? json(nullptr) : json(r.gate);
    j["txid"] = r.txid.GetHex();
    j["armed"] = r.armed;
    j["next_height"] = r.next_height != 0 ? json(r.next_height) : json(nullptr);
    json inputs = json::array();
    json conflicts = json::array();
    if (r.analysed) {
        j["fee"] = r.dry.priced ? json(r.dry.fee) : json(nullptr);
        j["immature_at_next_height"] = r.immature_at_next_height;
        if (r.dry.script_failed_input) j["script_failed_input"] = *r.dry.script_failed_input;
        for (const auto& in : r.dry.inputs) {
            json e = {{"txid", in.op.txid.GetHex()}, {"vout", in.op.index}, {"resolved", in.resolved},
                      {"source", in.source}};
            const bool confirmed = in.resolved && std::string(in.source) != "mempool";
            e["value"] = in.resolved ? json(in.value) : json(nullptr);
            e["height"] = confirmed ? json(in.height) : json(nullptr);
            e["coinbase"] = in.resolved ? json(in.coinbase) : json(nullptr);
            if (confirmed) {
                const uint64_t from = static_cast<uint64_t>(in.height) +
                                      (in.coinbase ? NodeCoinState::kCoinbaseMaturity : 1);
                e["spendable_from_height"] = from;
                e["immature"] = r.next_height != 0 ? json(from > r.next_height) : json(nullptr);
            } else {
                e["spendable_from_height"] = nullptr;
                e["immature"] = nullptr;
            }
            if (in.pool_spender) {
                e["mempool_spent_by"] = in.pool_spender->GetHex();
                conflicts.push_back({{"txid", in.op.txid.GetHex()}, {"vout", in.op.index},
                                     {"spent_by", in.pool_spender->GetHex()}});
            }
            inputs.push_back(std::move(e));
        }
    } else {
        j["fee"] = nullptr;
        j["immature_at_next_height"] = nullptr;
    }
    j["inputs"] = std::move(inputs);
    j["conflicts"] = std::move(conflicts);
    j["http_status"] = r.ok ? 200 : (r.cause == "inject-disabled" ? 409 : 422);
    return j;
}

} // namespace coin
} // namespace dash
