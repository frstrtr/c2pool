#pragma once
// V36 PPLNS exponential weight-decay parameters -- SSOT.
//
// Conforms to frstrtr/p2pool-merged-v36 p2pool/data.py
// get_decayed_cumulative_weights (the V36-native PPLNS path):
//     half_life   = max(net.CHAIN_LENGTH // 4, 1)
//     decay_per   = SCALE - (SCALE * 693147) // (1_000_000 * half_life)
//     decayed_att = (att * decay_fp) >> 40        # 40-bit fixed point
// where SCALE = 1 << 40, 693147 = ln(2) * 1e6 truncated. The fixed-point
// form is consensus-deterministic (no floating point).
//
// V36-NATIVE shared structure (3-bucket rule, bucket 2): the decayed PPLNS
// weighting is the V36 reward-distribution shape, distinct from the older
// p2pool-dgb-scrypt flat WeightsSkipList path (which has no decay and stays
// the live baseline during the crossing window). Standardize cross-coin
// toward this shape for the V37 unified migration.
//
// FENCED: header-only, share_tracker.hpp NOT yet rewired. The three open-coded
// copies of this arithmetic --
//     init_decay_table()                  (decay table precompute)
//     get_v36_decayed_cumulative_weights() (hot-path PPLNS weights)
//     the [PARENT-PPLNS] diagnostic dump  (GENTX-mismatch debug only)
// -- delegate onto this SSOT in a byte-identity follow-on PR.
#include <algorithm>
#include <cstdint>

namespace dgb::coin::weight_decay {

// 40-bit fixed-point scale (1.0 == DECAY_SCALE). Consensus-deterministic.
inline constexpr uint64_t DECAY_PRECISION = 40;
inline constexpr uint64_t DECAY_SCALE     = uint64_t(1) << DECAY_PRECISION;
// ln(2) * 1e6, truncated for integer arithmetic.
inline constexpr uint64_t LN2_MICRO       = 693147;

// half_life = max(chain_length / 4, 1)  (oracle: max(CHAIN_LENGTH // 4, 1)).
// Guard keeps the divisor non-zero for tiny chains.
inline constexpr uint32_t half_life(uint32_t chain_length) {
    return std::max(chain_length / 4u, uint32_t(1));
}

// Per-share decay multiplier in fixed point:
//   2^(-1/H) ~= 1 - ln(2)/H  ->  SCALE - SCALE*693147 / (1e6 * H)
inline constexpr uint64_t decay_per_share(uint32_t chain_length) {
    return DECAY_SCALE
         - (DECAY_SCALE * LN2_MICRO) / (uint64_t(1000000) * half_life(chain_length));
}

// Apply the accumulated depth-decay factor to a share attempts count:
//   decayed_att = (att * decay_fp) >> 40
inline constexpr uint64_t decayed_attempts(uint64_t att, uint64_t decay_fp) {
    return (att * decay_fp) >> DECAY_PRECISION;
}

} // namespace dgb::coin::weight_decay
