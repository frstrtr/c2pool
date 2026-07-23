// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// SSOT for the DGB TAIL-HASHRATE-SCORE chain-walk endpoints -- the pure
// arithmetic core of ShareTracker::score() (the per-tail "approximate lower
// bound on the chain's hashrate" used to rank candidate sharechain tails).
// Given a verified head share it resolves a window
//
//     end_point = get_nth_parent_hash(share_hash, CHAIN_LENGTH * 15 / 16)
//
// walks the trailing CHAIN_LENGTH/16 shares to find the most-recent resolvable
// parent block, then scores
//
//     score = get_delta(share_hash, end_point).work / (block_span * BLOCK_PERIOD)
//
// This score decides best_tail selection (data.py:767-772) and therefore which
// sharechain the pool extends -- a silent drift in the 15/16 endpoint offset, the
// /16 tail length, the short-chain guard, or the span clamp would re-rank tails
// with NO compile error, diverging operator-facing chain selection from the
// p2pool reference the V36 master-compat invariant pins.
//
// Oracle: p2pool-dgb-scrypt data.py:843-855 ShareTracker.score(share_hash,
//   block_rel_height_func):
//       head_height = self.verified.get_height(share_hash)
//       if head_height < self.net.CHAIN_LENGTH:
//           return head_height, None
//       end_point = self.verified.get_nth_parent_hash(
//           share_hash, self.net.CHAIN_LENGTH*15//16)
//       block_height = max(block_rel_height_func(share.header['previous_block'])
//           for share in self.verified.get_chain(end_point, self.net.CHAIN_LENGTH//16))
//       return self.net.CHAIN_LENGTH, \
//           self.verified.get_delta(share_hash, end_point).work \
//               / ((0 - block_height + 1) * self.net.PARENT.BLOCK_PERIOD)
//
// The chain-walk halves -- locating end_point via get_nth_parent_hash, walking
// get_chain, and summing the work delta via get_delta -- stay inside ShareTracker
// (they need the skip-list / TrackerView). This header captures ONLY the integer
// endpoint offsets, the short-chain guard, the unresolvable-block fallback, and
// the final span-clamp+divide as free functions over already-resolved inputs, so
// a KAT can pin the arithmetic with no NodeImpl / ShareTracker standup.
//
// Confirmation convention: p2pool's block_rel_height_func returns a relative
// height (0 = tip, negative = behind) and scores over (0 - block_height + 1) *
// BLOCK_PERIOD. c2pool's block_rel_height_func returns a CONFIRMATION count
// (1 = tip, 4 = three-deep), so the equivalent span is block_height *
// BLOCK_PERIOD: oracle (0 - 0 + 1) = 1 == c2pool 1 (tip), oracle (0 - -3 + 1) = 4
// == c2pool 4. The mapping is exact; this SSOT works in the c2pool confirmation
// convention to match the inline body verbatim.
//
// Per-coin isolation: dgb/ only. Header-only, additive. This slice does NOT yet
// rewire share_tracker.hpp -- that is the byte-identity delegation follow-on. The
// lifted bodies are verbatim copies of the inline arithmetic (same int32_t span
// type, same uint288 divide), so the follow-on is provably value-identical.
// Consensus-neutral: pure arithmetic, no value semantics changed.

#include <algorithm>
#include <cstdint>

#include <core/uint256.hpp>  // uint288

namespace dgb {

// Distance to the window end-point: get_nth_parent_hash(share_hash, this).
// Oracle: self.net.CHAIN_LENGTH*15//16 (Python floor division == C++ / on
// non-negative operands). CHAIN_LENGTH is a positive net constant.
inline int32_t score_endpoint_offset(int32_t chain_length)
{
    return (chain_length * 15) / 16;
}

// Number of trailing shares walked from end_point to find the most-recent
// resolvable parent block. Oracle: get_chain(end_point, self.net.CHAIN_LENGTH//16).
// The inline body additionally clamps to the end_point's accumulated height so
// the walk never over-reads past chain end (get_chain stops there anyway, but the
// clamp makes the <= 0 short-circuit below exact). end_point_acc_height is
// verified.get_acc_height(end_point).
inline int32_t score_tail_walk_count(int32_t chain_length, int32_t end_point_acc_height)
{
    return std::min(chain_length / 16, end_point_acc_height);
}

// Short-chain guard: when the head's accumulated verified height is below a full
// CHAIN_LENGTH the score is undefined (oracle returns (head_height, None)). The
// caller returns {head_acc_height, 0} in that case.
inline bool score_head_too_short(int32_t head_acc_height, int32_t chain_length)
{
    return head_acc_height < chain_length;
}

// Resolved block span in the c2pool confirmation convention. When NO parent block
// in the trailing window resolves (block_rel_height_func returned <= 0 for all, or
// the window was empty), p2pool would score work / (1e9 * BLOCK_PERIOD) -- tiny but
// non-zero so the higher-work chain still wins and selection does not oscillate.
// c2pool matches with a very large confirmation count (1,000,000) producing the
// same tiny-but-positive score. raw_block_height is the max confirmation count
// found; resolved is false when no block resolved.
inline int32_t score_resolved_block_span(bool resolved, int32_t raw_block_height)
{
    if (!resolved || raw_block_height <= 0)
        return 1000000;
    return raw_block_height;
}

// Score denominator: block_span * BLOCK_PERIOD, clamped strictly positive so the
// divide is well-defined. Oracle BLOCK_PERIOD = self.net.PARENT.BLOCK_PERIOD
// (config_coin.hpp = 75s). block_period is the make_coin_params-populated value.
inline int32_t score_time_span(int32_t block_span, int32_t block_period)
{
    int32_t time_span = block_span * block_period;
    if (time_span <= 0)
        time_span = 1;
    return time_span;
}

// Final hashrate score: cumulative-work delta over the window divided by the
// clamped time span. total_work = verified.get_delta_work(share_hash, end_point).
inline uint288 score_value(const uint288& total_work, int32_t time_span)
{
    return total_work / static_cast<uint32_t>(time_span);
}

}  // namespace dgb