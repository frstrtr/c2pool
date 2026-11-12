// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The UTXO lane's accrual and ordering suite (doge_utxo_lane_test.cpp) run
// again on LTC's parameters (#2137 S2): the lane is core::coin's, shared by
// DOGE and LTC's full set; here with LTC_MIN_BLOCKS_TO_KEEP (288),
// LTC_LIMITS and LTC's log tags. Suites named LtcRun<the DOGE suite>.
// ---------------------------------------------------------------------------

#define C2_LANE_SUITE(name) LtcRun##name
#define C2_LANE_KEEP core::coin::LTC_MIN_BLOCKS_TO_KEEP
#define C2_LANE_LIMITS core::coin::LTC_LIMITS
#define C2_LANE_CHAIN core::coin::LTC_UTXO_LANE

#include "doge_utxo_lane_test.cpp"
