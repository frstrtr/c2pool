// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ---------------------------------------------------------------------------
// dash::coin::resolve_v36_work_policy -- where the DASH v36 network takes its
// mining work from (operator decisions, 2026-09-28 and 2026-10-21).
//
// A v36 share commits the template's transactions through the coinbase
// merkle_link, and the finder assembles the won block from the template bodies
// it served. Either template arm can be that source: both fill the same
// DashWorkData (m_tx_hashes and m_tx_data_hex), the stratum snapshot freezes
// those bodies whichever arm built the work, and the won block goes out through
// broadcast_won_block (coin-P2P relay and/or dashd submitblock). Peers verify a
// v36 share from its merkle_link alone, so they never see which arm served it.
//
//   public profile (share v16)            -> unchanged: embedded arm as today,
//                                            stratum served
//   DASH v36 network + dashd RPC armed    -> dashd templates only, stratum
//                                            served (unchanged)
//   DASH v36 network, no dashd RPC,       -> embedded (daemonless) templates,
//     embedded arm eligible                  stratum served; won blocks relay
//                                            over coin-P2P (2026-10-21)
//   DASH v36 network, no dashd RPC,       -> no mining work at all: stratum is NOT
//     embedded arm not eligible              started (the node still relays the
//                                            sharechain) and says why
//
// "Embedded arm eligible" is ArmResolution::arm == WorkArm::EmbeddedEligible:
// the arm is enabled (--testnet or --embedded-mainnet, which the daemonless
// posture turns on by default) and a coin-state feed is armed. The caller also
// passes false when the operator asked for dashd but its creds did not
// resolve, so that node gets no work instead of templates it did not ask for.
//
// Pure: the caller passes the profile's share version decision, whether the
// dashd RPC arm was constructed, and the embedded arm resolution; main_dash.cpp
// applies the result.
// ---------------------------------------------------------------------------

namespace dash::coin
{

struct V36WorkPolicy
{
    bool        dashd_templates_only{false};   // DASHWorkSource::set_dashd_templates_only
    bool        serve_stratum{true};           // start the stratum listener
    const char* reason{"public-profile"};
};

inline V36WorkPolicy resolve_v36_work_policy(bool v36_network, bool rpc_armed,
                                             bool embedded_eligible)
{
    if (!v36_network)
        return V36WorkPolicy{false, true, "public-profile"};
    if (rpc_armed)
        return V36WorkPolicy{true, true, "v36-network-dashd-templates"};
    if (embedded_eligible)
        return V36WorkPolicy{false, true, "v36-network-embedded-templates"};
    return V36WorkPolicy{true, false, "v36-network-requires-coin-rpc"};
}

} // namespace dash::coin
