// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// SSOT for the think() Phase-4 HEAD-SCORE KEY construction — the per-head sort
// keys that, within the already-chosen best tail, decide which verified head a
// c2pool-dgb node treats as best_share (the chain tip it builds on and mines).
//
// This is currently OPEN-CODED inline in share_tracker.hpp think() Phase 4 (the
// `decorated_heads.push_back({{adjusted_work, -reason, -ts}, hh})` /
// `traditional_sort.push_back({{work_score, -ts, -reason}, hh})` block). The
// consensus-sensitive bit is the naughty-punishment deduction: a head whose
// share is naughty (invalid embedded block) has ONE share's worth of work
// deducted from its score so it sorts mathematically behind an honest head of
// equal raw work. A silent drift here — deducting twice, deducting on reason==0,
// flipping a tiebreak sign — would change which head wins with NO compile error.
// Lifting it to one header-only SSOT lets a KAT pin the exact key fields.
//
// Oracle: p2pool data.py OkayTracker.think() Phase 4:
//     decorated_heads = sorted((
//         (self.verified.get_work(self.verified.get_nth_parent_hash(
//              h, min(5, self.verified.get_height(h))))
//          - (min(punish, 1) * bitcoin_data.target_to_average_attempts(
//              share.target)),
//          -reason, -share.time_seen), h) for ...)
//   i.e. key0 = work_at_recent_ancestor minus (one share's attempts iff
//   punished), key1 = -reason, key2 = -time_seen. The traditional (debug /
//   protect) key is (work_at_recent_ancestor, -time_seen, -reason).
//   min(punish, 1) => deduct EXACTLY ONE share's work regardless of how large
//   the naughty count is, and deduct NOTHING when reason == 0.
//
// Per-coin isolation: dgb/ only. Header-only, additive; this slice does NOT
// rewire share_tracker.hpp (byte-identity-fenced delegation = follow-on) — it
// pins the key arithmetic as a free template exercised by the KAT with
// lightweight stand-in types (no ShareTracker/TrackerView standup). Consensus-
// neutral: pure key construction, no value semantics changed. Sibling of
// think_p3_best_head.hpp / think_p1_walk_bounds.hpp.

#include <cstdint>

namespace dgb {

// The two sort keys think() Phase 4 builds per head, mirroring the inline
// DecoratedData<HeadScore> / DecoratedData<TraditionalScore> payloads.
//   Selection key (HeadScore):    (adjusted_work, neg_reason, neg_time_seen)
//   Traditional key (debug/keep): (work_score,    neg_time_seen, neg_reason)
// std::sort is ascending and the inline picks back() as best, so a LARGER
// adjusted_work wins, then a LARGER neg_reason (== smaller reason == less
// punished), then a LARGER neg_time_seen (== smaller time_seen == seen first).
template <typename Work>
struct ThinkP4HeadKeys {
    Work    adjusted_work;   // work_score, minus one share's work iff punished
    Work    work_score;      // raw work at the recent (<=5-back) ancestor
    int32_t neg_reason;      // -reason  (reason = naughty count, 0 if honest)
    int64_t neg_time_seen;   // -time_seen
};

// Build the Phase-4 head-score keys for one head.
//   work_score      : verified work at the head's <=5-deep ancestor.
//   head_share_work : the head share's OWN work (the per-share attempt count
//                     deducted as the punishment when reason > 0).
//   reason          : naughty count (>0 => head's embedded block was invalid).
//   time_seen       : when the head share was first seen.
// Matches the inline `adjusted_work = work_score; if (reason > 0) adjusted_work
// -= head_share_work;` and the two push_back tuples in share_tracker.hpp think()
// Phase 4 exactly. Punishment is applied iff reason > 0 (== min(reason,1)==1)
// and deducts head_share_work EXACTLY ONCE.
template <typename Work>
ThinkP4HeadKeys<Work> think_p4_head_score_keys(Work work_score,
                                               Work head_share_work,
                                               int32_t reason,
                                               int64_t time_seen)
{
    Work adjusted_work = work_score;
    if (reason > 0)
        adjusted_work = adjusted_work - head_share_work;
    return ThinkP4HeadKeys<Work>{
        adjusted_work,
        work_score,
        -reason,
        -time_seen,
    };
}

} // namespace dgb