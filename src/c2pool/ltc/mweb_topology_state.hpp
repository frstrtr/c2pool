// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <core/web_server.hpp>
#include <nlohmann/json.hpp>

namespace c2pool::ltc {

// Adds the work template's MWEB state to the LTC row of /api/node_topology.
//
// mweb_active:   the cached template's rules name MWEB.
// mweb_degraded: the node serves work it cannot assemble an LTC block from
//                until MWEB state for the tip arrives.
//
// Before the first template (subsidy 0) neither key is written. A false here
// would claim MWEB is off when the node simply has no template yet.
inline void add_mweb_topology_state(nlohmann::json& coins,
                                    const core::MiningInterface::WorkSnapshot& work)
{
    if (work.subsidy == 0 || !coins.is_array())
        return;
    for (auto& row : coins) {
        if (row.value("coin", std::string{}) != "LTC")
            continue;
        row["mweb_active"] = work.mweb_active;
        row["mweb_degraded"] = work.degraded;
    }
}

} // namespace c2pool::ltc
