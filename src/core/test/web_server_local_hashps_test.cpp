// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <nlohmann/json.hpp>

#include <core/web_server.hpp>

// ---------------------------------------------------------------------------
// KATs for core::MiningInterface::rest_local_stats -> local_hashps (#919).
//
// The /local_stats endpoint surfaces this node's OWN work rate as a series a
// local-hashrate graph polls over time. The rate is read from the real stratum
// work-rate counter (set_stratum_hashrate_fn) -- the same live per-node source
// the node-fee share at web_server.cpp trusts as local_hr -- never the empty
// m_node stub that gave us the founding poolhashps=0 lie.
//
// The honesty rule these lock, in both directions:
//   * COLD (no work-rate source wired): local_hashps is null -- an honest
//     "unknown", NOT a flat 0 that would falsely claim this node mines nothing.
//   * LIVE (source wired): local_hashps is the counter's real value. A wired
//     source that reports 0.0 is a TRUE reading and stays 0, not null.
//
// Both FAIL WITHOUT THE FIX: before it, rest_local_stats emits no local_hashps
// key at all, so the cold assertion (key present AND null) and the live
// assertion (key present AND == counter) both fail on the missing field.
// ---------------------------------------------------------------------------

// COLD: no stratum work-rate source wired -> honest-absent null, never 0.
TEST(LocalHashpsSeam, ColdCounterIsHonestNullNotZero) {
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::LITECOIN);

    auto r = mi.rest_local_stats();
    ASSERT_TRUE(r.is_object());
    ASSERT_TRUE(r.contains("local_hashps"))
        << "local_hashps must be present so a cold node reads as unknown, not 0";
    EXPECT_TRUE(r["local_hashps"].is_null())
        << "cold local work-rate counter must be honest-absent (null), not flat 0";
}

// LIVE: wired counter surfaces its real value verbatim.
TEST(LocalHashpsSeam, LiveCounterSurfacesRealValue) {
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::LITECOIN);

    const double kLocalHs = 1234567.0;  // ~1.23 MH/s of local stratum work
    mi.set_stratum_hashrate_fn([kLocalHs]() { return kLocalHs; });

    auto r = mi.rest_local_stats();
    ASSERT_TRUE(r.is_object());
    ASSERT_TRUE(r.contains("local_hashps"));
    ASSERT_TRUE(r["local_hashps"].is_number());
    EXPECT_DOUBLE_EQ(r["local_hashps"].get<double>(), kLocalHs)
        << "live local_hashps must equal the real stratum work-rate counter";
}
