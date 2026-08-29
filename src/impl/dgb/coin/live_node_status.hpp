#pragma once
// dgb::coin::make_live_node_status -- SSOT for the dashboard "live node"
// status object (D-DGB.LIVEADAPTER).
//
// The embedded DGB work source (EmbeddedCoinNode) reports height 0 / synced
// false whenever no live embedded coin-daemon P2P node is feeding its
// HeaderChain -- which is EVERY run today, since the M3 embedded header ingest
// has not landed. Emitting that raw 0/false to the operator dashboard is a
// FAKE ZERO: it is indistinguishable from a real, connected node parked at
// genesis. This helper is the single place both /api/spv_progress and
// /api/node_topology route through, so a null (absent) live-node handle always
// renders as a labelled "no live node" state with NULL height/synced -- never
// a zero masquerading as a real reading, and never a dereference.
#include <nlohmann/json.hpp>

namespace dgb::coin {

// live   -- true iff a live embedded coin-daemon node handle is present.
// height -- the embedded chain tip height; emitted ONLY when live.
// synced -- the embedded sync flag; emitted ONLY when live.
// When !live the height/synced fields are JSON null (not 0/false) and a
// "state":"no live node" label is attached for the dashboard to render.
inline nlohmann::json make_live_node_status(bool live, long long height, bool synced)
{
    nlohmann::json s = nlohmann::json::object();
    s["live"]   = live;
    s["state"]  = live ? "live" : "no live node";
    s["height"] = live ? nlohmann::json(height) : nlohmann::json(nullptr);
    s["synced"] = live ? nlohmann::json(synced) : nlohmann::json(nullptr);
    return s;
}

} // namespace dgb::coin
