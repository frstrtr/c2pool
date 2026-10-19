// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH future-timestamp bound (#1825) — the reusable free function with an
// injected clock, and the per-network profile gate.
//
//   check_share_timestamp_bound(share_timestamp, now, enabled)
//     enabled  && share_timestamp >  now + 600  -> throws std::invalid_argument
//                                                   "share timestamp is too far in the future"
//     otherwise                                  -> returns
//   future_timestamp_bound_active()
//     == SharechainConfig::share_profile().future_timestamp_bound
//     true only on the private/isolated v36 profile (custom --network-id).
//
// These symbols are new with the rule, so this file does not compile against
// the base revision ("red by absence"). The behavioural red/green through
// share_init_verify is test_dash_v36_future_timestamp.cpp.
//
// Linked into test_dash_network_id_override (process-global identity).

#include <gtest/gtest.h>

#include <impl/dash/config_pool.hpp>
#include <impl/dash/share_check.hpp>

#include <chrono>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>

namespace {

using dash::SharechainConfig;

constexpr const char* FUTURE_TS_ERR = "share timestamp is too far in the future";

struct IdentityGuard {
    IdentityGuard()  { SharechainConfig::reset_network_id(); SharechainConfig::is_testnet = false; }
    ~IdentityGuard() { SharechainConfig::reset_network_id(); SharechainConfig::is_testnet = false; }
};

bool rejects(uint32_t ts, uint32_t now, bool enabled) {
    try {
        dash::check_share_timestamp_bound(ts, now, enabled);
        return false;
    } catch (const std::invalid_argument& e) {
        EXPECT_STREQ(e.what(), FUTURE_TS_ERR);
        return true;
    }
}

} // namespace

TEST(DashV36FutureTimestamp, BoundExactBoundaryInjectedClock) {
    EXPECT_EQ(dash::SHARE_TIMESTAMP_FUTURE_BOUND_SECS, 600u);

    const uint32_t now = 1700000000u;
    // Enabled (isolated v36): the window is inclusive of now+600.
    EXPECT_FALSE(rejects(now + 600, now, true));
    EXPECT_TRUE (rejects(now + 601, now, true));
    EXPECT_TRUE (rejects(now + 10000, now, true));
    EXPECT_TRUE (rejects(std::numeric_limits<uint32_t>::max(), now, true));
    EXPECT_FALSE(rejects(now + 599, now, true));
    EXPECT_FALSE(rejects(now, now, true));
    EXPECT_FALSE(rejects(now - 1, now, true));
    EXPECT_FALSE(rejects(0, now, true));

    // Disabled (public v16): nothing is rejected, however far ahead.
    EXPECT_FALSE(rejects(now + 601, now, false));
    EXPECT_FALSE(rejects(std::numeric_limits<uint32_t>::max(), now, false));
    EXPECT_FALSE(rejects(std::numeric_limits<uint32_t>::max(), 0, false));

    // No uint32 wrap: a clock within 600 s of UINT32_MAX must not turn the
    // bound into reject-everything (now+600 would wrap to a small value).
    const uint32_t late = std::numeric_limits<uint32_t>::max() - 100;
    EXPECT_FALSE(rejects(std::numeric_limits<uint32_t>::max(), late, true));
    EXPECT_FALSE(rejects(late, late, true));
    EXPECT_FALSE(rejects(1700000000u, late, true));

    // now == 0: exactly the 600 s window.
    EXPECT_FALSE(rejects(600, 0, true));
    EXPECT_TRUE (rejects(601, 0, true));
}

TEST(DashV36FutureTimestamp, ShareClockIsWallClockSeconds) {
    const auto wall = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    const uint32_t c = dash::share_clock_now();
    // Same clock, same units: within a couple of seconds of each other.
    EXPECT_LE(c > wall ? c - wall : wall - c, 2u);
}

TEST(DashV36FutureTimestamp, ProfileSwitchIsTheOnlyGate) {
    IdentityGuard g;

    for (bool testnet : {false, true}) {
        SCOPED_TRACE(testnet ? "testnet" : "mainnet");
        SharechainConfig::reset_network_id();
        SharechainConfig::is_testnet = testnet;
        // Public network: no flag.
        EXPECT_FALSE(dash::future_timestamp_bound_active());
        EXPECT_EQ(dash::future_timestamp_bound_active(),
                  SharechainConfig::share_profile().future_timestamp_bound);

        // Every spelling of the public network id stays public => no bound.
        for (const char* v : {"", "0", "00", "0000", "0000000000000000"}) {
            SCOPED_TRACE(std::string("id=\"") + v + "\"");
            SharechainConfig::set_network_id(v, "");
            EXPECT_FALSE(dash::future_timestamp_bound_active());
            SharechainConfig::set_network_id(v, "0badc0ffee11");
            EXPECT_FALSE(dash::future_timestamp_bound_active());
        }

        // A custom network id => private/isolated v36 profile => bound on.
        SharechainConfig::reset_network_id();
        SharechainConfig::set_network_id("abcd");
        EXPECT_TRUE(SharechainConfig::v36_network());
        EXPECT_TRUE(dash::future_timestamp_bound_active());
        EXPECT_EQ(dash::future_timestamp_bound_active(),
                  SharechainConfig::share_profile().future_timestamp_bound);

        // And off again once the identity is reset.
        SharechainConfig::reset_network_id();
        EXPECT_FALSE(dash::future_timestamp_bound_active());
    }
}
