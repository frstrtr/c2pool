// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// SSOT for the think() Phase-3 per-tail BEST-HEAD selection — the inner
// max-by-work pick that, for each verified tail, chooses which of that tail's
// verified heads represents the tail when it is scored and sorted in Phase 3.
//
// This is currently OPEN-CODED inline in share_tracker.hpp think() Phase 3
// (the `max(verified.tails[tail_hash], key=verified.get_work)` loop just before
// score()).  A silent drift — wrong tiebreak direction, picking an unverified
// head, or strict-vs-non-strict comparison — would change which head a tail is
// scored by and therefore which tail/chain a c2pool-dgb node treats as best,
// with NO compile error.  Lifting it to one header-only SSOT lets a KAT pin the
// exact selection: skip unverified candidates, first-seen wins, replace only on
// a STRICTLY greater work (so a later equal-work head never displaces an
// earlier one — matching Python max(..., key=...) first-max semantics).
//
// Oracle: p2pool data.py OkayTracker.think() Phase 3:
//     decorated_tails = sorted((self.score(
//         max(self.verified.tails[tail_hash], key=self.verified.get_work), ...
//   i.e. per tail_hash, the head with maximal verified work; Python max keeps
//   the FIRST element on ties.
//
// Per-coin isolation: dgb/ only.  Header-only, additive; this slice does NOT
// rewire share_tracker.hpp (byte-identity-fenced delegation = follow-on) — it
// pins the pick as a free template so the KAT exercises it with lightweight
// stand-in types (no ShareTracker/TrackerView standup, no uint256 dependency).
// Consensus-neutral: pure selection, no value semantics changed.  Sibling of
// think_p1_walk_bounds.hpp / think_p2_walk_bounds.hpp.

#include <iterator>
#include <type_traits>

namespace dgb {

template <typename Hash, typename Work>
struct ThinkP3BestHead {
    Hash head;   // the chosen head (default-constructed when !found)
    Work work;   // its verified work (default-constructed when !found)
    bool found;  // false => no verified head among the candidates
};

// Pick the maximal-work verified head among head_hashes.
//   is_verified(h) -> bool : whether candidate h is in the verified view.
//   get_work(h)    -> Work : candidate h's accumulated verified work.
// Semantics mirror Python max(verified.tails[t], key=verified.get_work):
//   skip non-verified, first verified seen wins, replace only on STRICTLY
//   greater work (first-max tiebreak). Equivalent to the inline
//   `if (first || w > best_work)` loop in share_tracker.hpp think() Phase 3.
template <typename HashRange, typename ContainsFn, typename WorkFn>
auto think_p3_best_head_by_work(const HashRange& head_hashes,
                                ContainsFn&& is_verified,
                                WorkFn&& get_work)
    -> ThinkP3BestHead<
           typename std::decay<decltype(*std::begin(head_hashes))>::type,
           typename std::decay<decltype(get_work(*std::begin(head_hashes)))>::type>
{
    using Hash = typename std::decay<decltype(*std::begin(head_hashes))>::type;
    using Work = typename std::decay<decltype(get_work(*std::begin(head_hashes)))>::type;
    ThinkP3BestHead<Hash, Work> r{Hash{}, Work{}, false};
    for (const auto& hh : head_hashes) {
        if (!is_verified(hh)) continue;
        Work w = get_work(hh);
        if (!r.found || w > r.work) {
            r.head = hh;
            r.work = w;
            r.found = true;
        }
    }
    return r;
}

} // namespace dgb