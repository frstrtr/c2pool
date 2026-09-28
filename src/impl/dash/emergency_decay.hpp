// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ============================================================================
// emergency_decay.hpp — the v36 emergency time-decay retarget rule, ONE copy.
//
// Used by the DASH producer retarget (share_producer.hpp compute_share_target,
// enabled only where SharechainConfig::share_profile().emergency_decay is set:
// the private/isolated DASH v36 sharechain) and by ShareTracker::
// compute_share_target's "Step 3". The public p2pool-dash oracle has no such
// rule; the public mint path never calls this.
// ============================================================================

#include <core/uint256.hpp>

#include <cstdint>

namespace dash
{

// The p2pool-v36 rule (share_tracker.hpp compute_share_target "Step 3", ltc
// share_tracker.hpp): once more than SHARE_PERIOD*20 seconds have passed since
// the previous share, the reference the ±10% band is taken around doubles every
// SHARE_PERIOD*10 seconds past that threshold, linearly interpolated inside a
// half-life, and never exceeds max_target:
//
//   time_since = desired_ts - prev_ts          (only when desired_ts > prev_ts > 0)
//   if time_since > SHARE_PERIOD*20:
//       excess   = time_since - SHARE_PERIOD*20
//       halvings = excess // (SHARE_PERIOD*10);  remainder = excess % (SHARE_PERIOD*10)
//       eased    = min(prev_max_target << halvings, max_target)
//       eased    = eased * (half_life + remainder) // half_life      (288-bit)
//       ref      = min(eased, max_target)
//   else ref = prev_max_target
//
// "Lowers the target" in the difficulty sense: the numeric target (and the
// share's max_bits) goes UP, so a stalled chain becomes easier to extend.
// The shift SATURATES at max_target (the ltc emergency_decay_shl form). A bare
// uint256 `<<=` (the pre-existing tracker copy) drops every bit shifted past
// 2^256: for prev_max_target = 0xffff * 2^200 it returns 0 from 56 halvings
// on, i.e. a stall of about 3 hours would make the reference HARDER instead of
// easier. Deliberate deviation from that copy; KAT DashShareProducerRetarget.
// EmergencyDecayShiftSaturatesNotWraps.
//
// Timestamps (deliberate, same as the ltc port, main_ltc.cpp passes the job's
// wall-clock time): `desired_timestamp` is the job's WALL-CLOCK time, while
// `prev_timestamp` is the parent's COMMITTED timestamp, which the share rules
// clip to (its parent's timestamp + 2*SHARE_PERIOD - 1). After a long stall the
// committed timestamps therefore lag wall clock by roughly the stall length,
// and since each share advances the committed time by at most
// 2*SHARE_PERIOD - 1 seconds, the lag closes slowly. So the easing
// does not stop at the first share after the stall: the next several shares
// still see time_since > SHARE_PERIOD*20 and keep easing, until the committed
// timestamps catch up; after that the ordinary retarget walks the target back
// (the band moves it by at most 10% per share). This is intended: the chain
// recovers from a stall quickly and settles back gradually. It does not skew
// payouts, because PPLNS weight is target_to_average_attempts of each share's
// own bits: an easier share carries proportionally less weight.
inline uint256 emergency_decay_clamp_ref(const uint256& prev_max_target,
                                         uint32_t prev_timestamp,
                                         uint32_t desired_timestamp,
                                         uint32_t share_period,
                                         const uint256& max_target)
{
    if (prev_timestamp == 0 || desired_timestamp <= prev_timestamp || share_period == 0)
        return prev_max_target;
    const uint64_t time_since = static_cast<uint64_t>(desired_timestamp) - prev_timestamp;
    const uint64_t threshold  = static_cast<uint64_t>(share_period) * 20;
    if (time_since <= threshold)
        return prev_max_target;

    const uint64_t half_life = static_cast<uint64_t>(share_period) * 10;
    const uint64_t excess    = time_since - threshold;
    const uint64_t halvings  = excess / half_life;
    const uint64_t remainder = excess % half_life;

    uint256 eased;
    if (halvings >= 256 || prev_max_target > (max_target >> static_cast<unsigned int>(halvings)))
        eased = max_target;
    else
    {
        eased = prev_max_target;
        eased <<= static_cast<unsigned int>(halvings);   // <= max_target: no wrap
    }

    uint288 eased_288;
    eased_288.SetHex(eased.GetHex());
    eased_288 = eased_288 * static_cast<uint32_t>(half_life + remainder);
    eased_288 = eased_288 / static_cast<uint32_t>(half_life);
    uint288 max_288;
    max_288.SetHex(max_target.GetHex());
    if (eased_288 > max_288)
        return max_target;
    uint256 out;
    out.SetHex(eased_288.GetHex());
    return out;
}

} // namespace dash
