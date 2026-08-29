// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// SSOT for the DGB GET_HEIGHT_AND_LAST chain-walk endpoints -- the pure integer
// arithmetic that every consumer of forest.get_height_and_last() applies to the
// resolved (height, last) pair before walking the sharechain. forest returns
//
//     (delta.height, delta.tail)              [p2pool util/forest.py:171-173]
//
// where `last` (delta.tail) is the hash one past the deepest reachable ancestor,
// or null when the walk bottoms out at a genesis/rooted tail. Two facts about
// that pair drive consensus-bearing windowing across the DGB tree:
//
//   1. The ROOTED-TAIL invariant. A verified head is only fully rooted once it
//      has >= REAL_CHAIN_LENGTH ancestors; below that it must still be hanging
//      off an unrooted tail (last is None). p2pool asserts this at every window
//      entry point:
//        data.py:161   assert height >= net.REAL_CHAIN_LENGTH or last is None
//        data.py:696   if height < CHAIN_LENGTH + 1 and last is not None: raise
//
//   2. The PPLNS / payout WINDOW DEPTH. The trailing payout walk is clamped to
//      the configured chain length and is only live once at least one share is
//      in range:
//        depth  = min(height, REAL_CHAIN_LENGTH)         (redistribute.hpp:453)
//        active = depth >= 1
//      which mirrors the oracle PPLNS bound
//        _pplns_max_shares = max(0, min(height, REAL_CHAIN_LENGTH) - 1)
//      (see pplns_weight_walk.hpp:96 / p2pool get_chain(best, min(height, CL))).
//
//   3. The MONITOR min-height gate. The pool monitor's diagnostic cycle is a
//      no-op until the chain is deep enough to be statistically meaningful:
//        if (height < 10) return 0;                       (pool_monitor.hpp:98)
//      Diagnostic-only, but pinned here so a silent drift of the floor is caught.
//
// A silent drift in the REAL_CHAIN_LENGTH clamp, the >=1 activation, or the
// rooted-tail invariant would re-window PPLNS payout with NO compile error --
// diverging operator-facing reward distribution from the p2pool-dgb-scrypt
// reference the V36 master-compat invariant pins.
//
// Oracle: p2pool-dgb-scrypt util/forest.py:171-173 (get_height_and_last) +
//   data.py:160-161 (generate_transaction rooted-tail assert) +
//   data.py:695-696 (attempt_verify rooted-tail raise) +
//   networks/digibyte.py (REAL_CHAIN_LENGTH = 12*60*60//15 = 2880).
//
// Per-coin isolation: dgb/ only. Header-only, additive, free functions over the
// already-resolved (height, last) pair -- the get_delta_to_last skip-list walk
// stays in the forest. This slice does NOT rewire redistribute.hpp / pool_monitor.hpp
// / share_check.hpp -- that is the byte-identity delegation follow-on. The lifted
// bodies are verbatim copies of the inline guards (same int32_t height type,
// same min()/comparison), so the follow-on is provably value-identical.
// Consensus-neutral: pure arithmetic, no value semantics changed.

#include <algorithm>
#include <cstdint>

namespace dgb {

// Minimum sharechain depth before the pool monitor's diagnostic cycle runs.
// p2pool/c2pool pool_monitor.hpp:98 -- diagnostic floor, not consensus.
static constexpr int32_t MONITOR_MIN_HEIGHT = 10;

// ROOTED-TAIL invariant (data.py:161, data.py:696). A resolved head must either
// have at least `real_chain_length` ancestors, or still be hanging off an
// unrooted tail (last is null). Returns true when the invariant holds.
//   p2pool: height >= net.REAL_CHAIN_LENGTH or last is None
inline bool rooted_tail_invariant_holds(int32_t height,
                                        bool last_is_null,
                                        int32_t real_chain_length)
{
    return height >= real_chain_length || last_is_null;
}

// attempt_verify entry guard (data.py:695-696): a share below CHAIN_LENGTH+1
// height that is NOT on an unrooted tail is malformed and must be rejected.
// Returns true when the share is acceptable for verification at this depth.
//   p2pool: if height < CHAIN_LENGTH + 1 and last is not None: raise
inline bool verify_depth_ok(int32_t height, bool last_is_null, int32_t chain_length)
{
    return height >= chain_length + 1 || last_is_null;
}

// PPLNS / payout window depth (redistribute.hpp:453). Trailing payout walk is
// clamped to the configured real chain length.
//   c2pool: depth = min(height, real_chain_length())
inline int32_t pplns_window_depth(int32_t height, int32_t real_chain_length)
{
    return std::min(height, real_chain_length);
}

// PPLNS window activation (redistribute.hpp:454). The payout window is only live
// once at least one share is in range.
//   c2pool: if (depth < 1) return;  -> active iff depth >= 1
inline bool pplns_window_active(int32_t depth)
{
    return depth >= 1;
}

// p2pool PPLNS share-count bound (pplns_weight_walk.hpp:96): the number of
// shares actually contributing to PPLNS weight, one less than the window depth
// (the head itself is excluded), floored at zero.
//   p2pool: _pplns_max_shares = max(0, min(height, REAL_CHAIN_LENGTH) - 1)
inline int32_t pplns_max_shares(int32_t height, int32_t real_chain_length)
{
    return std::max(0, pplns_window_depth(height, real_chain_length) - 1);
}

// Pool-monitor diagnostic gate (pool_monitor.hpp:98).
//   c2pool: if (height < 10) return 0;  -> runs iff height >= 10
inline bool monitor_cycle_runs(int32_t height)
{
    return height >= MONITOR_MIN_HEIGHT;
}

} // namespace dgb