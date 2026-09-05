// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// SSOT for the requester-side parent-share download CONTINUATION under an
// empty / timed-out SHAREREQ reply — the p2pool-parity piece that the c2pool
// download loop was missing.
//
// THE GAP (bip110 federation cold-attach ~1.4 shares/min vs p2pool thousands):
// p2pool's downloader (node.py:108-141) is a self-driving loop over desired_var.
// A round-trip that times out (node.py:127-129 `continue`) or returns an empty
// batch (node.py:138-140 `sleep(1); continue`) does NOT end the walk — it
// immediately re-requests the SAME still-missing desired hash from a freshly
// chosen random peer. c2pool's NodeImpl::download_shares instead only chained
// the NEXT request on a NON-empty reply (success → download_shares(oldest_parent));
// an empty/timed-out reply just incremented a failure counter and RETURNED,
// stranding the whole chain-walk until the next periodic think/clean tick. On a
// quiet chain (bip110) that tick is minutes apart, so one dead round-trip cost
// ~30 min of sync — the exact `parents=145` → `parents=3` gap in the node2 log.
//
// This header pins the two continuation DECISIONS as pure functions so a KAT can
// prove they match p2pool without standing up a NodeImpl / ReplyMatcher / peer
// set. NodeImpl wires them: on an empty reply it calls should_retry_after_empty()
// and, if true, arms a 1s retry timer; when that timer fires it drains the
// pending set through plan_download_retries() and re-issues download_shares for
// each survivor against a fresh random peer — the c2pool spelling of
// `sleep(1); continue`. The permanent-failure ceiling (MAX_EMPTY_RETRIES) stands
// in for p2pool's desired_var naturally dropping a hash the network no longer has.
//
// Per-coin isolation: bip110/ only. Header-only, additive.

#include <cstddef>
#include <functional>
#include <vector>

#include <core/uint256.hpp>

namespace bip110 {
namespace pool {

// Decision A — after an EMPTY (timeout or no-matching-shares) reply for a target
// hash, do we re-schedule a retry? `fail_count_after_increment` is the target's
// failure counter AFTER this empty reply is counted. We retry while it is still
// strictly below the permanent-failure ceiling; at/above it we stop (the share
// is treated as pruned from the network). Mirrors p2pool: keep looping on the
// desired hash until desired_var no longer lists it.
inline bool should_retry_after_empty(int fail_count_after_increment,
                                     int max_empty_retries)
{
    return fail_count_after_increment < max_empty_retries;
}

struct RetryDrainResult
{
    // Hashes to re-issue download_shares() for, in input order.
    std::vector<uint256> to_request;
    // True when the pending set was non-empty but there were no peers to ask —
    // p2pool's `if not self.peers: sleep(1); continue`. NodeImpl re-arms the 1s
    // timer instead of dropping the walk, so it resumes the moment a peer exists.
    bool rearm_no_peers = false;
};

// Decision B — when the 1s retry timer fires, which pending hashes get a fresh
// download_shares? Skip any that (a) arrived meanwhile (already in the local
// share chain) or (b) already hit the permanent-failure ceiling. Order over the
// input is preserved. With no peers, request nothing and signal a re-arm.
inline RetryDrainResult plan_download_retries(
    const std::vector<uint256>& pending,
    bool have_peers,
    const std::function<bool(const uint256&)>& in_chain,
    const std::function<int(const uint256&)>& fail_count,
    int max_empty_retries)
{
    RetryDrainResult r;
    if (pending.empty())
        return r;
    if (!have_peers) {
        r.rearm_no_peers = true;
        return r;
    }
    for (const auto& h : pending) {
        if (in_chain(h))
            continue;
        if (fail_count(h) >= max_empty_retries)
            continue;
        r.to_request.push_back(h);
    }
    return r;
}

} // namespace pool
} // namespace bip110
