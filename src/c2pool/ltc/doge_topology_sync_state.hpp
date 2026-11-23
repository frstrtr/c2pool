#pragma once

// D-DOGE tip row: what the DOGE row of /api/node_topology reports about the
// embedded DOGE chain. Display only.

#include <cstdint>

#include <nlohmann/json.hpp>

namespace c2pool::topology {

// synced: the embedded DOGE UTXO view holds the mining-gate depth.
// height: the embedded DOGE header chain tip. A chain with no tip yet
// (height 0) writes no height key, so the card shows no tip rather than 0.
inline nlohmann::json doge_topology_sync_state(int blocks_connected,
                                               int gate_depth,
                                               uint32_t header_tip)
{
    nlohmann::json r = nlohmann::json::object();
    r["synced"] = blocks_connected >= gate_depth;
    if (header_tip > 0)
        r["height"] = static_cast<int>(header_tip);
    return r;
}

} // namespace c2pool::topology
