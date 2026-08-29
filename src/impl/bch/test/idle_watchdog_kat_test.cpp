// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bch_idle_watchdog_kat_test -- progress-gated block-download stall watchdog.
//
// Pins the decision predicate bch::idle_watchdog::should_drop_on_stall():
//   1. At tip / idle (in_flight == 0): NEVER drop, regardless of elapsed time.
//      This is the anti-churn guarantee -- a synced BCH node sees ~10 min
//      between blocks and must not be dropped for lack of block traffic.
//   2. Actively downloading but making progress (recent accepted body): no drop.
//   3. Actively downloading, armed, no accepted body for >= IDLE_TIMEOUT: DROP.
//   4. Boundary: exactly IDLE_TIMEOUT elapsed drops; one second short does not.
//   5. Not yet armed (DISARMED baseline while in flight): no drop this tick
//      (the caller arms the baseline, the watchdog bites on a later tick).
//   6. Clock-skew guard: now_tick < last_progress_tick never drops.

#include <cassert>
#include <iostream>

#include "../coin/idle_watchdog.hpp"

using bch::idle_watchdog::should_drop_on_stall;
using bch::idle_watchdog::DISARMED;

int main()
{
    constexpr uint64_t IDLE = 100; // mirrors NodeP2P::IDLE_TIMEOUT_SEC

    // 1. At tip: in_flight == 0 -> never drop, even after a very long silence.
    assert(!should_drop_on_stall(/*in_flight=*/0, /*now=*/100000, /*last=*/1, IDLE));
    assert(!should_drop_on_stall(0, 100000, DISARMED, IDLE));

    // 2. Downloading + recent progress -> no drop.
    assert(!should_drop_on_stall(/*in_flight=*/4, /*now=*/150, /*last=*/120, IDLE)); // 30s < 100

    // 3. Downloading, armed, stalled beyond budget -> DROP.
    assert(should_drop_on_stall(/*in_flight=*/4, /*now=*/500, /*last=*/300, IDLE)); // 200s >= 100

    // 4. Boundary: exactly IDLE drops; IDLE-1 does not.
    assert(should_drop_on_stall(1, 200, 100, IDLE));   // 100 >= 100 -> drop
    assert(!should_drop_on_stall(1, 199, 100, IDLE));  //  99 <  100 -> hold

    // 5. Not yet armed while in flight -> no drop (caller arms this tick).
    assert(!should_drop_on_stall(/*in_flight=*/8, /*now=*/9999, DISARMED, IDLE));

    // 6. Clock-skew guard: now < last -> never a positive elapsed -> no drop.
    assert(!should_drop_on_stall(4, 50, 300, IDLE));

    // 7. Steady-state soak: many quiet ticks at tip never churn.
    for (uint64_t t = 0; t < 100000; t += 5)
        assert(!should_drop_on_stall(0, t, DISARMED, IDLE));

    // 8. IBD soak: progress every 30s keeps the peer; a 100s gap drops it.
    uint64_t last = 0;
    bool dropped = false;
    for (uint64_t t = 0; t <= 300; t += 5) {
        if (should_drop_on_stall(4, t, last, IDLE)) { dropped = true; break; }
        if (t % 30 == 0) last = t; // simulate an accepted body every 30s
    }
    assert(!dropped); // steady 30s progress never trips
    // now stop making progress after t=300; must drop by t=400.
    dropped = false;
    for (uint64_t t = 305; t <= 500; t += 5)
        if (should_drop_on_stall(4, t, /*last=*/300, IDLE)) { dropped = true; break; }
    assert(dropped);

    std::cout << "bch_idle_watchdog_kat_test: PASS\n";
    return 0;
}
