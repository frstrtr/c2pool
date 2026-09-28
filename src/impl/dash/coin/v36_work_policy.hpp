// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ---------------------------------------------------------------------------
// dash::coin::resolve_v36_work_policy -- where the DASH v36 network takes its
// mining work from (operator decision, 2026-09-28).
//
// A v36 share commits the template's transactions through the coinbase
// merkle_link, and the finder assembles the won block from the template bodies
// it served. The transaction source for the DASH v36 network is dashd
// getblocktemplate (--coin-rpc / --coin-daemon with credentials): the embedded
// (daemonless) template arm is not served to miners on that network yet. So:
//
//   public profile (share v16)          -> unchanged: embedded arm as today,
//                                          stratum served
//   DASH v36 network + dashd RPC armed  -> dashd templates only, stratum served
//   DASH v36 network, no dashd RPC      -> no mining work at all: stratum is NOT
//                                          started (the node still relays the
//                                          sharechain) and says why
//
// Pure: the caller passes the profile's share version decision and whether the
// dashd RPC arm was constructed; main_dash.cpp applies the result.
// ---------------------------------------------------------------------------

namespace dash::coin
{

struct V36WorkPolicy
{
    bool        dashd_templates_only{false};   // DASHWorkSource::set_dashd_templates_only
    bool        serve_stratum{true};           // start the stratum listener
    const char* reason{"public-profile"};
};

inline V36WorkPolicy resolve_v36_work_policy(bool v36_network, bool rpc_armed)
{
    if (!v36_network)
        return V36WorkPolicy{false, true, "public-profile"};
    if (rpc_armed)
        return V36WorkPolicy{true, true, "v36-network-dashd-templates"};
    return V36WorkPolicy{true, false, "v36-network-requires-coin-rpc"};
}

} // namespace dash::coin
