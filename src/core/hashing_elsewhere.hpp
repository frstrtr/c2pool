// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// "Hashing on another node": the one rule that both the dashboard's stratum
// session state (core/web_server.cpp: a failback session reads standby, not
// stalled) and the DASH alert relay's RETURNED rule (impl/dash/alert_detector.hpp:
// a rig that moved to another node is not paged) apply, fed from one sharechain
// read, so the dashboard and the pager cannot disagree about such a rig.
//
// All nodes are peers. A rig keeps a stratum connection to its pool 1 and to
// its pool 2. After a failover to this node and a failback, its session here
// stays open, receives work and submits nothing, which locally looks exactly
// like a hung rig. The sharechain tells the two apart: every share carries its
// payout ADDRESS, and a share minted on another node (received from a pool
// peer, not minted here) proves that the address still hashes there.
//
// For a worker that is not hashing here:
//   newest_elsewhere  newest share time (unix s) carrying its payout address
//                     and minted on another node; 0 = none seen
//   last_here         its last accepted share on this node (unix s); 0 = never
//   It is hashing on another node iff
//     newest_elsewhere >  last_here + kElsewhereMarginSeconds   (after it left)
//     newest_elsewhere >= now - kElsewhereHorizonSeconds        (still there)
//     and no worker of that address is hashing on this node.
//
// The horizon is a fixed 15 minutes, the stratum silence floor: a session is
// only called silent after 15 minutes without a share, so any qualifying share
// is also newer than the session's last share here. A window derived from the
// address's expected share interval would need the pool and address hashrates;
// the fixed window errs the safe way: an address whose shares on the other
// node are sparser than one per 15 minutes (a small miner on a large pool)
// reads stalled between those shares, as it did before this rule.
//
// Limits. Shares name the address, not the worker:
// - With rigs of one address on two nodes, a rig that is truly broken reads
//   "hashing elsewhere" on its BACKUP node while siblings hash on the primary.
//   The primary still flags it (stalled there, and its siblings hash there, so
//   the rule does not apply on that node).
// - A sibling hashing HERE voids the rule for every worker of that address
//   (failover moves a whole farm; one rig stopping while its siblings carry on
//   here is a hung rig), so a rig that returned to its first pool reads stalled
//   here while a sibling still hashes here.
// - Share times come from the minting node's clock (NTP-synced peers
//   assumed); the margin absorbs small skew.
// - When the sharechain cannot be read there is no evidence: the dashboard
//   keeps "stalled"; the relay waits (bounded) and then pages.

#include <cstdint>
#include <map>
#include <optional>
#include <string>

namespace core::stratum {

inline constexpr int64_t kElsewhereMarginSeconds = 60;
inline constexpr int64_t kElsewhereHorizonSeconds = 900;
// A per-address snapshot older than this is no evidence (the sharechain was
// not readable for that long).
inline constexpr int64_t kElsewhereSnapshotMaxAgeSeconds = 120;

inline bool hashing_elsewhere(int64_t newest_elsewhere, int64_t last_here, int64_t now,
                              bool address_hashing_here,
                              int64_t margin = kElsewhereMarginSeconds,
                              int64_t horizon = kElsewhereHorizonSeconds)
{
    if (address_hashing_here || newest_elsewhere <= 0) return false;
    return newest_elsewhere > last_here + margin && newest_elsewhere >= now - horizon;
}

// Payout address of a stratum username or worker key ("ADDRESS.worker").
inline std::string payout_address_of(const std::string& key)
{
    const auto dot = key.find('.');
    return dot == std::string::npos ? key : key.substr(0, dot);
}

// One sharechain read: per payout address, the newest share time minted on
// another node. A coin main builds it (DASH: newest_share_time_by_address with
// peer_received_only, impl/dash/dashboard_views.hpp) and hands the same
// snapshot to the dashboard and to the alert relay.
struct AddressActivity {
    bool valid{false};       // false: the sharechain has not been read
    int64_t built_at{0};     // unix seconds of the read
    std::map<std::string, int64_t> newest_elsewhere;

    // Evidence for `address` at `now`: nullopt = unknown (not read, or the
    // read is older than the max age); 0 = no share minted elsewhere.
    std::optional<int64_t> newest(const std::string& address, int64_t now) const
    {
        if (!valid || now - built_at > kElsewhereSnapshotMaxAgeSeconds) return std::nullopt;
        const auto it = newest_elsewhere.find(address);
        return it == newest_elsewhere.end() ? int64_t{0} : it->second;
    }
};

}  // namespace core::stratum
