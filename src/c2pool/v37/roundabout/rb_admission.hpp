#pragma once
// S1 — the REJECT_ROUNDABOUT admission predicate (standalone).
//
// Sibling of w2_admission.hpp Disposition::REJECT_CHAIN (:72). In the consensus
// order of spec §3.1 it is step "3d", evaluated right after 3c chain_id
// (w2_admission.hpp:178) and before 4 expiry:
//     PoW -> R-1 -> identity -> prev-own -> chain -> ROUNDABOUT -> expiry -> dedup
// so a receipt failing several checks still reports the FIRST in that order.
//
// A receipt/carrier of roundabout-validator `my_rb` under map `map` (epoch e)
// with carriage (map_epoch, rb_index, stripe, lane_tag) is REJECT_ROUNDABOUT iff
//   (a) lane_tag != lane_tag(ctx, map_epoch, rb_index, stripe)   [pool-id GAP:
//       mismatched chain/geometry/version/authority rejects EXPLICITLY]
//   (b) map_epoch != map.epoch                                   [stale/foreign map]
//   (c) rb_index >= k                                            [no such roundabout]
//   (d) stripe >= n(id)                                          [design: stripe >= n]
//   (e) assign(id, stripe, map) != rb_index                      [design: wrong home]
//   (f) rb_index != my_rb                                        [not this roundabout's work]
// The reason is diagnostic only (one disposition on the wire, like REJECT_POW
// lumping carrier failures); the FIRST failing reason in (a)..(f) is reported.
//
// Gate OFF (k = 1, the default): the check is a no-op returning OK — OFF lanes
// carry no RbCarriage (v0x01/v0x02 wire), so admission is byte-identical to
// master.

#include <cstdint>

#include "rb_gate.hpp"
#include "rb_lane_tag.hpp"
#include "rb_map.hpp"
#include "rb_params.hpp"

namespace c2pool::v37n::rb {

enum class RbDisposition : std::uint8_t {
    OK = 0,
    REJECT_ROUNDABOUT = 1,   // wiring: Disposition::REJECT_ROUNDABOUT after REJECT_CHAIN
};

enum class RbReason : std::uint8_t {
    NONE = 0,
    TAG_MISMATCH,          // (a)
    EPOCH_MISMATCH,        // (b)
    RB_OUT_OF_RANGE,       // (c)
    STRIPE_OUT_OF_RANGE,   // (d)
    WRONG_ROUNDABOUT,      // (e)
    NOT_MY_ROUNDABOUT,     // (f)
};

inline const char* rb_reason_name(RbReason r) {
    switch (r) {
        case RbReason::NONE:                return "none";
        case RbReason::TAG_MISMATCH:        return "tag-mismatch";
        case RbReason::EPOCH_MISMATCH:      return "epoch-mismatch";
        case RbReason::RB_OUT_OF_RANGE:     return "rb-out-of-range";
        case RbReason::STRIPE_OUT_OF_RANGE: return "stripe-out-of-range";
        case RbReason::WRONG_ROUNDABOUT:    return "wrong-roundabout";
        case RbReason::NOT_MY_ROUNDABOUT:   return "not-my-roundabout";
    }
    return "?";
}

struct RbCheck {
    RbDisposition disp = RbDisposition::OK;
    RbReason reason = RbReason::NONE;
    bool ok() const { return disp == RbDisposition::OK; }
};

// The pure design-of-record predicate: (d) + (e) only.
inline bool roundabout_assignment_ok(const Map& map, const bytes32& id_key,
                                     Stripe stripe, RbIndex rb_index) {
    if (u64(stripe) >= map.n_of(id_key)) return false;
    return map.assign(id_key, stripe) == rb_index;
}

// Full step-3d admission check.
inline RbCheck check_roundabout(const RoundaboutGate& g, const LaneTagContext& ctx,
                                const Map& map, RbIndex my_rb,
                                const bytes32& id_key, const RbCarriage& c) {
    auto rej = [](RbReason r) { return RbCheck{RbDisposition::REJECT_ROUNDABOUT, r}; };
    if (g.is_off()) return RbCheck{};                                  // OFF: no-op
    if (c.lane_tag != lane_tag(ctx, c.map_epoch, c.rb_index, c.stripe))
        return rej(RbReason::TAG_MISMATCH);
    if (c.map_epoch != map.epoch) return rej(RbReason::EPOCH_MISMATCH);
    if (c.rb_index >= map.k()) return rej(RbReason::RB_OUT_OF_RANGE);
    if (u64(c.stripe) >= map.n_of(id_key)) return rej(RbReason::STRIPE_OUT_OF_RANGE);
    if (map.assign(id_key, c.stripe) != c.rb_index) return rej(RbReason::WRONG_ROUNDABOUT);
    if (c.rb_index != my_rb) return rej(RbReason::NOT_MY_ROUNDABOUT);
    return RbCheck{};
}

// Miner/template side: the carriage a miner of `id_key` builds for stripe s.
inline RbCarriage make_carriage(const LaneTagContext& ctx, const Map& map,
                                const bytes32& id_key, Stripe s) {
    RbCarriage c;
    c.map_epoch = map.epoch;
    c.stripe = s;
    c.rb_index = map.assign(id_key, s);
    c.lane_tag = lane_tag(ctx, c.map_epoch, c.rb_index, c.stripe);
    return c;
}

}  // namespace c2pool::v37n::rb
