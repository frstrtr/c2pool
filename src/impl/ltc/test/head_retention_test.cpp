// head_retention_test.cpp — KAT for the clean_tracker() head-retention predicate
// (p2pool-merged-v36 kr1z1s convergence hotfixes F2 (#23) + #25(B)).
//
// RED on master semantics (Guard 3 gated on `!verified` + 120s, no desired-parent
// guard), GREEN after the fix (Guard 3 ungated + 300s, Guard 2b desired&&!abandoned).
//
// Mirrors p2pool test_convergence.py:313-387 and test_minority_fork_livelock.py:331-366.

#include <gtest/gtest.h>
#include "../head_retention.hpp"

using ltc::HeadGcInput;
using ltc::head_retained;

namespace {

// A head that is NOT trivially protected: not top-5, not on a supersede segment,
// itself seen long ago (so Guard 1/1b/2 never fire and the test isolates
// Guard 2b / Guard 3).
HeadGcInput base_old_head(int64_t now)
{
    HeadGcInput in;
    in.now = now;
    in.in_top5 = false;
    in.in_supersede_segment = false;
    in.head_time_seen = now - 10000;   // ancient: Guard 2 cannot fire
    in.head_verified = false;
    in.frontier_present = false;
    in.frontier_max_time_seen = 0;
    in.tail_in_desired = false;
    in.parent_abandoned = false;
    return in;
}

} // namespace

// Regression guard (GREEN on both master and fix): a still-downloading UNVERIFIED
// head with a fresh frontier is protected. Master already did this.
TEST(HeadRetention, downloading_head_retained_when_unverified)
{
    const int64_t now = 1'000'000;
    auto in = base_old_head(now);
    in.head_verified = false;
    in.frontier_present = true;
    in.frontier_max_time_seen = now - 60;   // 60s: fresh under both 120s and 300s
    EXPECT_TRUE(head_retained(in));
}

// RED on master: once F1's incremental verifier VERIFIES a still-downloading head,
// master's Guard 3 (`!verified`) stops protecting it and it is purged mid-catch-up.
// The fix drops the verified gate: a fresh frontier protects it regardless.
TEST(HeadRetention, downloading_head_retained_after_it_becomes_verified)
{
    const int64_t now = 1'000'000;
    auto in = base_old_head(now);
    in.head_verified = true;                // <- master loses protection here
    in.frontier_present = true;
    in.frontier_max_time_seen = now - 200;  // 200s: fresh under the fixed 300s window
    EXPECT_TRUE(head_retained(in));
}

// GREEN on both: a genuinely dead fork (frontier >300s stale, not desired, not
// top-5) is still reaped. The 300s window self-lapses after download activity stops.
TEST(HeadRetention, dead_head_still_reaped)
{
    const int64_t now = 1'000'000;
    auto in = base_old_head(now);
    in.head_verified = false;
    in.frontier_present = true;
    in.frontier_max_time_seen = now - 301;  // just past the window
    in.tail_in_desired = false;
    EXPECT_FALSE(head_retained(in));
}

// RED on master: the node is still requesting this head's missing parent
// (tail in `desired`) but a peer STALLED so no fresh frontier shares arrived
// (frontier >300s stale). Master has no desired-parent guard, so it reaps the
// partial chain and re-downloads from scratch — the 12,929-request relapse loop.
// The fix protects it via Guard 2b.
TEST(HeadRetention, head_with_outstanding_request_survives_peer_stall)
{
    const int64_t now = 1'000'000;
    auto in = base_old_head(now);
    in.frontier_present = true;
    in.frontier_max_time_seen = now - 400;  // peer stalled: frontier gone stale
    in.tail_in_desired = true;              // but we still WANT the parent
    in.parent_abandoned = false;            // and not every peer has failed it
    EXPECT_TRUE(head_retained(in));
}

// GREEN on both (invariant): once EVERY connected peer has failed to serve the
// missing parent, the head is abandoned and becomes reapable — memory stays
// bounded, an unservable re-advertised fragment cannot pin the tracker.
TEST(HeadRetention, head_reaped_when_all_peers_failed_the_parent)
{
    const int64_t now = 1'000'000;
    auto in = base_old_head(now);
    in.frontier_present = true;
    in.frontier_max_time_seen = now - 400;  // stale frontier
    in.tail_in_desired = true;
    in.parent_abandoned = true;             // <- whole peer set gave up
    EXPECT_FALSE(head_retained(in));
}

// GREEN on both: top-5 and supersede-segment protections are unconditional.
TEST(HeadRetention, top5_and_supersede_always_kept)
{
    const int64_t now = 1'000'000;
    auto in = base_old_head(now);
    in.frontier_present = false;
    in.tail_in_desired = false;

    auto t5 = in; t5.in_top5 = true;
    EXPECT_TRUE(head_retained(t5));

    auto ss = in; ss.in_supersede_segment = true;
    EXPECT_TRUE(head_retained(ss));
}

// GREEN on both: a recently-seen head is kept by Guard 2 regardless of everything
// downstream.
TEST(HeadRetention, recently_seen_head_kept)
{
    const int64_t now = 1'000'000;
    auto in = base_old_head(now);
    in.head_time_seen = now - 100;   // < 300s
    EXPECT_TRUE(head_retained(in));
}
