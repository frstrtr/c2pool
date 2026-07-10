// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// SSOT: last_txout_nonce generation for the OP_RETURN extranonce slot.
//
// p2pool draws this value as a uniform 64-bit random number purely to make the
// coinbase OP_RETURN unique per share (work.py: last_txout_nonce =
// random.randrange(2**64)). The value is consensus-irrelevant: whatever is
// generated here is carried verbatim into the minted share and re-read on the
// verify path, so any draw satisfies uniqueness. Three ad-hoc time-XOR formulas
// had drifted across share_check.hpp; this collapses them to one oracle-faithful
// uniform draw and removes the unintended std::time() clock read (which made the
// value low-entropy and straddle-flaky across a 1-second boundary).
//
// NOT a cross-coin standardization item — coin-local, consensus-neutral hygiene.

#include <cstdint>
#include <random>

namespace dgb
{

// Oracle-faithful uniform 64-bit draw (mirrors random.randrange(2**64)).
// thread_local engine matches the per-thread mt19937_64 idiom already used in
// node.hpp / node.cpp; seeded once per thread from std::random_device.
inline uint64_t make_last_txout_nonce()
{
    static thread_local std::mt19937_64 rng(std::random_device{}());
    return rng();
}

} // namespace dgb