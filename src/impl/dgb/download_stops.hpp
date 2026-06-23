#pragma once

// SSOT for the requester-side download stops-list — the bound that
// NodeImpl::download_shares puts on a SHAREREQ so a peer cannot dump an
// unbounded single-branch burst in reply.  This is the mirror of the
// responder-side get_shares_walk.hpp: the walk decides how far a peer walks UP
// from each requested hash; the stops list tells it where to STOP, namely at
// any share we already hold.  Until now this computation was inline in
// download_shares() with ZERO coverage in any tree — a drift in the nth-parent
// depth, the head-inclusion, the null-parent skip, or the 100-cap would let a
// c2pool-dgb peer (or a c2pool-dgb peer vs a p2pool-merged-v36 reference node)
// silently request the wrong span with no compile error, and on the bootstrap
// path (parents=random(500)) overgrow one lineage past 2*CHAIN_LENGTH+10 until
// clean_tracker drop-tails collapse the branch and verified resets to 0 (the
// exact failure the inline comment documents).
//
// Oracle: p2pool node.py download_shares():
//     stops=list(set(tracker.heads) | set(
//         tracker.get_nth_parent_hash(head, min(max(0, height-1), 10))
//         for head in tracker.heads))[:100]
//
// Per-coin isolation: dgb/ only.  Header-only, additive; this slice does not
// rewire node.cpp (that is the byte-identity-fenced delegation follow-on) — it
// pins the stops construction as a free function so the KAT can exercise it
// against a fake head set with no NodeImpl/tracker standup.  Determinism note:
// the survivor set under the 100-cap is fixed by std::set<uint256> ordering, so
// the function reproduces the inline std::set insert + ordered-iteration exactly.

#include <algorithm>
#include <cstddef>
#include <functional>
#include <set>
#include <vector>

#include <core/uint256.hpp>

namespace dgb {

// Per-head nth-parent depth — p2pool: min(max(0, height-1), 10).  height is the
// accumulated height of the head share; a head at height <= 1 contributes only
// itself (nth == 0 -> no parent inserted).
inline int download_stops_nth(int acc_height)
{
    return std::min(std::max(0, acc_height - 1), 10);
}

// Build the stops list for a SHAREREQ.  heads is the current head-hash set;
// get_acc_height(head) returns the head accumulated height; get_nth_parent(head,
// nth) returns the nth ancestor (or a null uint256 if it cannot be resolved,
// which is skipped, matching the inline guard).  cap bounds the result (p2pool
// [:100]); survivors under the cap are the ordered-first entries of the
// deduplicated set, exactly as the inline std::set<uint256> iteration yields.
inline std::vector<uint256> compute_download_stops(
    const std::vector<uint256>& heads,
    const std::function<int(const uint256&)>& get_acc_height,
    const std::function<uint256(const uint256&, int)>& get_nth_parent,
    std::size_t cap = 100)
{
    std::set<uint256> stop_set;
    for (const auto& head_hash : heads)
    {
        stop_set.insert(head_hash);
        int nth = download_stops_nth(get_acc_height(head_hash));
        if (nth > 0)
        {
            uint256 parent = get_nth_parent(head_hash, nth);
            if (!parent.IsNull())
                stop_set.insert(parent);
        }
    }

    std::vector<uint256> stops;
    std::size_t count = 0;
    for (const auto& s : stop_set)
    {
        if (count++ >= cap)
            break;
        stops.push_back(s);
    }
    return stops;
}

} // namespace dgb
