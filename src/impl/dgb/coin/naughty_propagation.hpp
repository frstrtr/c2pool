#pragma once

// SSOT for DGB NAUGHTY-PROPAGATION ancestor punishment -- the pure-integer
// generation arithmetic that taints the descendants of a share which built (or
// would build) an invalid block. A share is marked naughty=1 when it carries an
// excessive block reward (data.py:535-536); thereafter EVERY descendant inherits
// an incrementing generation counter, and that counter is what get_emphemeral
// dispute / best-share selection reads to walk back off a naughty tail
// (data.py:608-611, best_descendent skips naughty children at data.py:812-813).
//
// The propagation rule is consensus-bearing: it decides which shares the pool
// will refuse to build on and which descendants it punishes, so a silent drift
// in the "+1 per generation" step or the "reset after 6 generations" clamp would
// re-rank sharechain tails with NO compile error, diverging operator-facing chain
// selection from the p2pool reference the V36 master-compat invariant pins.
//
// Oracle: p2pool-dgb-scrypt data.py:543-549, evaluated for every share at
// construction after the excessive-reward check:
//
//     if self.share_data['previous_share_hash'] and \
//             tracker.items[self.share_data['previous_share_hash']].naughty:
//         print "naughty ancestor found %i generations ago" % ...
//         self.naughty = 1 + tracker.items[self.share_data['previous_share_hash']].naughty
//         if self.naughty > 6:
//             self.naughty = 0
//
// Two observable facts pinned here:
//   1. The guard is "parent EXISTS and parent.naughty is truthy". Python treats
//      naughty==0 as falsy, so a non-naughty parent leaves self.naughty UNTOUCHED
//      (it keeps whatever the excessive-reward branch set -- 0 normally, 1 if this
//      very share is itself a bad-reward share). Propagation NEVER zeroes an
//      already-naughty share whose parent happens to be clean.
//   2. When the parent IS naughty (1..6), the child generation is parent+1, and
//      a child that would reach generation 7 wraps back to 0 -- i.e. punishment
//      spans exactly 6 generations (parent gen 1 -> ... -> gen 6 kept; the would-be
//      gen-7 descendant is forgiven). "third and fourth generation" in the oracle
//      comment is hyperbole; the code clamps at 6.
//
// Per-coin isolation: dgb/ only. Header-only, additive. This slice does NOT yet
// rewire share_tracker.hpp -- that is the byte-identity delegation follow-on. The
// inline body at share_tracker.hpp:561-577 computes the identical value
// (parent_idx->naughty + 1, then > 6 -> 0), so the follow-on is provably
// value-identical. Pure unsigned arithmetic -> no core link needed.

#include <cstdint>
#include <optional>

namespace dgb {

// Child naughty generation given a NAUGHTY parent (parent_naughty >= 1).
// Oracle data.py:547-549: self.naughty = 1 + parent.naughty; if > 6 -> 0.
// Precondition: caller has already established the parent is naughty; this is the
// bare arithmetic so a KAT can pin the +1 step and the 6-generation reset clamp.
inline std::uint32_t naughty_child_generation(std::uint32_t parent_naughty)
{
    std::uint32_t child = 1u + parent_naughty;  // data.py:547
    if (child > 6u)                              // data.py:548
        child = 0u;                              // data.py:549 -- reset after 6 generations
    return child;
}

// Full propagation INCLUDING the oracle's "parent is naughty" guard
// (data.py:543). Returns the value to assign to the child's naughty counter, or
// std::nullopt when no propagation applies -- i.e. the parent is not naughty, in
// which case the oracle leaves self.naughty untouched (the caller must NOT
// overwrite it). This mirrors the inline guard at share_tracker.hpp:567
// (`parent_idx->naughty > 0`): assign only inside the if-branch.
inline std::optional<std::uint32_t> propagate_naughty_from_parent(std::uint32_t parent_naughty)
{
    if (parent_naughty == 0u)        // data.py:543 -- non-naughty parent is falsy
        return std::nullopt;         // leave child's naughty as-is
    return naughty_child_generation(parent_naughty);
}

}  // namespace dgb
