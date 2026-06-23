// dgb think() Phase-1 DESIRED-EMIT decision conformance KAT.
//
// FENCED, additive (no production code touched this slice). Pins
// src/impl/dgb/think_p1_desired_emit.hpp against the p2pool data.py think()
// Phase-1 oracle for the requester-side desired-emit decision per unverified
// head whose verify walk found nothing:
//
//   if last is null            -> SkipNoParent     (no parent hash to request)
//   else if head_h >= 2*CL+10  -> SkipPruningZone  (parent re-pruned at once)
//   else if already_desired    -> SkipDuplicate    (desired = set() dedup)
//   else                       -> EmitRequest
//
// Two layers of evidence:
//   1. Truth-table cases HAND-DERIVED from the oracle ladder (NOT read back from
//      the subject — a KAT that asks its subject for the answer passes
//      vacuously), incl. the inclusive 2*CL+10 prune boundary and the
//      check-ORDER precedence (no-parent before prune-zone before dedup).
//   2. A NON-CIRCULAR delegation anchor: a verbatim re-implementation of the
//      pre-delegation inline ladder from share_tracker.hpp think() Phase 1,
//      asserted EQUAL to the SSOT across an exhaustive input matrix. This is the
//      guarantee the future share_tracker rewire preserves byte-identical
//      behaviour — proven WITHOUT the SSOT appearing on both sides.
//
// Pure arithmetic/bools: links only core (no chain standup). MUST appear in BOTH
// this dir's CMakeLists.txt AND the build.yml --target allowlist, or it becomes
// a #143 NOT_BUILT sentinel (compiled-out, silently "passing").

#include <impl/dgb/think_p1_desired_emit.hpp>

#include <gtest/gtest.h>

#include <cstdint>

namespace {

using dgb::ThinkP1DesiredEmit;
using dgb::think_p1_desired_emit;

// ---- SkipNoParent: a null parent short-circuits BEFORE every other check,
//      regardless of height / prune-zone / dedup state.
TEST(ThinkP1DesiredEmit, NullParentSkipsFirst)
{
    constexpr int32_t CL = 10;
    EXPECT_EQ(think_p1_desired_emit(true, 0,    CL, false), ThinkP1DesiredEmit::SkipNoParent);
    EXPECT_EQ(think_p1_desired_emit(true, 5,    CL, false), ThinkP1DesiredEmit::SkipNoParent);
    // even in the prune zone and already-desired, null parent still wins.
    EXPECT_EQ(think_p1_desired_emit(true, 1000, CL, true),  ThinkP1DesiredEmit::SkipNoParent);
}

// ---- SkipPruningZone: non-null parent, head at/over the inclusive 2*CL+10
//      threshold. Precedence: prune-zone check is BEFORE the dedup check.
TEST(ThinkP1DesiredEmit, PruningZoneInclusiveAndBeforeDedup)
{
    constexpr int32_t CL = 10;            // threshold = 2*10 + 10 = 30
    EXPECT_EQ(think_p1_desired_emit(false, 29, CL, false), ThinkP1DesiredEmit::EmitRequest);
    EXPECT_EQ(think_p1_desired_emit(false, 30, CL, false), ThinkP1DesiredEmit::SkipPruningZone); // inclusive
    EXPECT_EQ(think_p1_desired_emit(false, 31, CL, false), ThinkP1DesiredEmit::SkipPruningZone);
    // prune-zone outranks dedup: already_desired=true must NOT change the verdict.
    EXPECT_EQ(think_p1_desired_emit(false, 30, CL, true),  ThinkP1DesiredEmit::SkipPruningZone);

    constexpr int32_t CL2 = 24;           // threshold = 2*24 + 10 = 58
    EXPECT_EQ(think_p1_desired_emit(false, 57, CL2, false), ThinkP1DesiredEmit::EmitRequest);
    EXPECT_EQ(think_p1_desired_emit(false, 58, CL2, false), ThinkP1DesiredEmit::SkipPruningZone);
}

// ---- SkipDuplicate vs EmitRequest: non-null parent, below prune zone, gated
//      only by whether the parent hash is already in the desired set.
TEST(ThinkP1DesiredEmit, DedupGatesEmissionBelowPruneZone)
{
    constexpr int32_t CL = 10;
    EXPECT_EQ(think_p1_desired_emit(false, 0,  CL, false), ThinkP1DesiredEmit::EmitRequest);
    EXPECT_EQ(think_p1_desired_emit(false, 0,  CL, true),  ThinkP1DesiredEmit::SkipDuplicate);
    EXPECT_EQ(think_p1_desired_emit(false, 15, CL, false), ThinkP1DesiredEmit::EmitRequest);
    EXPECT_EQ(think_p1_desired_emit(false, 15, CL, true),  ThinkP1DesiredEmit::SkipDuplicate);
}

// ---- NON-CIRCULAR delegation anchor.
// Verbatim transcription of the pre-delegation inline ladder as it stands in
// share_tracker.hpp think() Phase 1 (walk0 + for/else branches, identical):
//
//     if (!last.IsNull()) {
//         if (head_height >= 2 * CL_prune + 10) { /* skip: pruning zone */ }
//         else if (!desired_hashes.count(last)) { /* emit */ }
//         /* else: implicit skip — duplicate */
//     }
//     /* else: implicit skip — no parent */
//
// Reproduced WITHOUT calling the SSOT, then asserted equal to it.
ThinkP1DesiredEmit inline_reference(bool last_is_null, int32_t head_height,
                                    int32_t CL, bool already_desired)
{
    if (!last_is_null) {
        if (head_height >= 2 * CL + 10) {
            return ThinkP1DesiredEmit::SkipPruningZone;
        } else if (!already_desired) {
            return ThinkP1DesiredEmit::EmitRequest;
        } else {
            return ThinkP1DesiredEmit::SkipDuplicate;
        }
    }
    return ThinkP1DesiredEmit::SkipNoParent;
}

TEST(ThinkP1DesiredEmit, DelegationMatchesPreDelegationInlineLadder)
{
    // Exhaustive matrix across both CHAIN_LENGTH values, heights straddling the
    // prune boundary, and both dedup/null states.
    for (int32_t CL : {1, 10, 24, 50}) {
        for (int32_t h = 0; h <= 2 * CL + 12; ++h) {
            for (bool last_is_null : {false, true}) {
                for (bool dup : {false, true}) {
                    EXPECT_EQ(
                        think_p1_desired_emit(last_is_null, h, CL, dup),
                        inline_reference(last_is_null, h, CL, dup))
                        << " CL=" << CL << " h=" << h
                        << " null=" << last_is_null << " dup=" << dup;
                }
            }
        }
    }
}

} // namespace
