#pragma once

// head_retention.hpp — pure, side-effect-free predicate for the clean_tracker()
// "eat away at heads" garbage-collection step (node.cpp Step 2). Extracted into a
// header so the retention policy can be exercised by a KAT without a live node.
//
// This is the c2pool port of two p2pool-merged-v36 kr1z1s convergence hotfixes
// (see p2pool node.py Node.clean_tracker):
//
//   F2  (#23, 9953edd6)  — protect a head whose FRONTIER (the oldest-downloaded
//                          shares, reverse[tail]) received a share recently,
//                          REGARDLESS of the head's verification state, and widen
//                          the freshness window 120s -> 300s. On master the
//                          protection was gated on `!verified.contains(head)` and
//                          120s, so the instant the incremental verifier verified
//                          a still-downloading head it LOST protection and was
//                          purged mid-catch-up — the 505,935-share re-download
//                          livelock.
//
//   #25(B) (9a2a90e8)    — protect a head whose missing parent think() is still
//                          requesting (its `desired` set) unless every connected
//                          peer has failed to serve that parent (parent_abandoned).
//                          A slow / black-hole peer can no longer trigger the
//                          purge + full re-download loop; a peer re-advertising an
//                          unservable fragment cannot pin the tracker because the
//                          head becomes reapable once the parent is abandoned.
//
// NONE of this touches share format, Share::check(), or PPLNS — it is local GC
// scheduling only, so the verify SET stays byte-identical and there is no
// sharechain-fork risk.

#include <cstdint>

namespace ltc {

// All inputs a single head needs for the retain/reap decision. Timestamps are
// unix seconds; `now` is the current time in the same unit.
struct HeadGcInput {
    // Guard 1: this head is among the top-5 scored heads (decorated_heads[-5:]).
    bool in_top5{false};
    // Guard 1b (c2pool restart-reorg): this head is on the converging challenger
    // segment (a c2pool-specific protection, not present in p2pool). Kept as-is.
    bool in_supersede_segment{false};

    // Guard 2: when this head itself was last seen.
    int64_t head_time_seen{0};

    // Guard 3 (F2): does reverse[tail] (the frontier) exist, and what is the
    // newest time_seen across it? A fresh frontier means shares are still
    // arriving for this chain (it is actively downloading toward a common
    // ancestor). This is evaluated regardless of `head_verified` after the fix.
    bool frontier_present{false};
    int64_t frontier_max_time_seen{0};

    // Whether this head is already in the verified tracker. On master this gated
    // Guard 3 (protection only while UNVERIFIED); after the F2 fix it does not.
    bool head_verified{false};

    // #25(B): think() still wants this head's missing parent (tail is in the
    // `desired` set) and the peer set has not collectively abandoned it.
    bool tail_in_desired{false};
    bool parent_abandoned{false};

    int64_t now{0};
};

// The FRONTIER freshness window (seconds). p2pool node.py: 300 after the F2 fix
// (was 120, gated on unverified).
inline constexpr int64_t kFrontierFreshWindow = 300;
// The head-freshness window (Guard 2). p2pool node.py:366 — 300.
inline constexpr int64_t kHeadFreshWindow = 300;

// True  => KEEP this head (do not reap it this cycle).
// False => the head may be removed by the GC walk.
//
// Byte-faithful to p2pool node.py Node.clean_tracker after #23 + #25(B):
//   1.  in top5                                             -> keep
//   1b. on the converging challenger segment (c2pool)       -> keep
//   2.  head seen < 300s ago                                -> keep
//   2b. (#25B) tail still desired AND not abandoned         -> keep   [PRIMARY]
//   3.  (F2) frontier seen < 300s ago, ANY verified state   -> keep
//   else                                                     -> reap
inline bool head_retained(const HeadGcInput& in)
{
    // Guard 1 — top-5 scored heads (p2pool node.py:363).
    if (in.in_top5)
        return true;

    // Guard 1b — c2pool converging-challenger segment (restart-reorg).
    if (in.in_supersede_segment)
        return true;

    // Guard 2 — head seen recently (p2pool node.py:366).
    if (in.head_time_seen > in.now - kHeadFreshWindow)
        return true;

    // Guard 2b — #25(B): the node is ACTIVELY downloading this head's missing
    // parent (tail in `desired`) and the peer set has not collectively given up
    // on it. This is the PRIMARY protection: a slow / black-hole peer can no
    // longer trigger the purge + full re-download loop. Bounded by
    // parent_abandoned so a peer re-advertising an unservable fragment cannot
    // pin memory.
    if (in.tail_in_desired && !in.parent_abandoned)
        return true;

    // Guard 3 — F2: protect any head whose FRONTIER received a share in the last
    // 300s, REGARDLESS of the head's verification state. On master this was gated
    // on `!head_verified` and 120s; that gate is the kr1z1s livelock and is gone.
    if (in.frontier_present && in.frontier_max_time_seen > in.now - kFrontierFreshWindow)
        return true;

    return false;
}

} // namespace ltc
