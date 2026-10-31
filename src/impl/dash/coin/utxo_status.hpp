// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// The `utxo` object of /local_stats (DESIGN S2 4.6) and its one-line form
/// for [EMBED-STATUS]. Telemetry only.
///
///   utxo: { mode: "full" | "accrual" | "off", best_height, best_block,
///           state: "verifying-base" | "catching-up" | "serving" | "withheld",
///           coins, connected, strict_refusals, bad_bodies, rewinds,
///           catch_up: { next, target }, withheld_reason, full_refused,
///           import_seconds,
///           assumeutxo: { assumed, base_height, base_hash, muhash, validated,
///                         validation: { mode: "none", status: "idle" } } }

#include "utxo_lane.hpp"

#include <nlohmann/json.hpp>

#include <string>

namespace dash {
namespace coin {

inline nlohmann::json utxo_status_json(UtxoLane& lane, const std::string& full_refused = std::string(),
                                       double import_seconds = -1)
{
    nlohmann::json u = nlohmann::json::object();
    u["mode"] = lane.full() ? "full" : (lane.live() ? "accrual" : "off");
    if (lane.live() && lane.cache()) {
        u["best_height"] = lane.cache()->get_best_height();
        u["best_block"] = lane.cache()->get_best_block().GetHex();
    }
    if (!full_refused.empty()) u["full_refused"] = full_refused;
    if (import_seconds >= 0) u["import_seconds"] = static_cast<int64_t>(import_seconds);
    if (lane.full()) {
        const auto st = lane.full_status();
        u["state"] = st.state;
        u["coins"] = st.coins;
        u["connected"] = st.connected;
        u["strict_refusals"] = st.strict_refusals;
        u["bad_bodies"] = st.bad_bodies;
        u["rewinds"] = st.rewinds;
        if (st.fill_end != 0)
            u["catch_up"] = {{"next", st.fill_next}, {"target", st.fill_end}};
        if (!st.withheld_reason.empty()) u["withheld_reason"] = st.withheld_reason;
        u["assumeutxo"] = {
            {"assumed", true},
            {"base_height", st.base_height},
            {"base_hash", st.base_hash.GetHex()},
            {"muhash", st.muhash.GetHex()},
            {"base_verified", st.base_verified},
            {"validated", st.validated},
            {"validation", {{"mode", "none"}, {"status", "idle"}}},
        };
    }
    return u;
}

/// "utxo=full/serving best=2564100 refusals=0" for [EMBED-STATUS].
inline std::string utxo_status_line(UtxoLane& lane)
{
    std::string s = std::string("utxo=") + (lane.full() ? "full" : (lane.live() ? "accrual" : "off"));
    if (lane.full()) {
        const auto st = lane.full_status();
        s += "/" + st.state + " best=" + std::to_string(st.best_height) +
             " refusals=" + std::to_string(st.strict_refusals);
    } else if (lane.live() && lane.cache()) {
        s += " best=" + std::to_string(lane.cache()->get_best_height());
    }
    return s;
}

} // namespace coin
} // namespace dash
