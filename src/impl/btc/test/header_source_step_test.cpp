// The standalone header-sync driver's tick decision (header_source_step.hpp).
#include <gtest/gtest.h>

#include <impl/btc/coin/header_source_step.hpp>

using btc::coin::header_source_step;
using btc::coin::kCaughtUpFailoverSec;
using btc::coin::kCaughtUpRefreshSec;
using btc::coin::kNoProgressFailoverSec;

// Catching up: unchanged from before -- getheaders on a fresh handshake or a
// tick without progress, failover after kNoProgressFailoverSec.
TEST(BtcHeaderSourceStep, CatchingUp)
{
    auto s = header_source_step(false, true, true, false, 0, 0);
    EXPECT_TRUE(s.getheaders);
    EXPECT_FALSE(s.failover);
    s = header_source_step(false, true, false, true, 5, 5);
    EXPECT_FALSE(s.getheaders);
    s = header_source_step(false, true, false, false, 12, 12);
    EXPECT_TRUE(s.getheaders);
    s = header_source_step(false, false, false, false, kNoProgressFailoverSec, 0);
    EXPECT_FALSE(s.getheaders);
    EXPECT_TRUE(s.failover);
    EXPECT_FALSE(header_source_step(false, true, false, false,
                                    kNoProgressFailoverSec - 1, 0).failover);
}

// Caught up: the 2026-11-24 stall -- one handshaked peer stopped relaying
// blocks and the tip stood for 18 hours. A quiet tip is re-asked after
// kCaughtUpRefreshSec and the peer is replaced after kCaughtUpFailoverSec.
TEST(BtcHeaderSourceStep, CaughtUpPeerThatStopsRelayingIsReplaced)
{
    // The natural gap between blocks churns nothing.
    auto s = header_source_step(true, true, false, false, kCaughtUpRefreshSec - 1,
                                kCaughtUpRefreshSec - 1);
    EXPECT_FALSE(s.getheaders);
    EXPECT_FALSE(s.failover);
    // Quiet for the refresh window: ask the peer again, once per window.
    s = header_source_step(true, true, false, false, kCaughtUpRefreshSec,
                           kCaughtUpRefreshSec);
    EXPECT_TRUE(s.getheaders);
    EXPECT_FALSE(s.failover);
    EXPECT_FALSE(header_source_step(true, true, false, false, kCaughtUpRefreshSec + 12,
                                    12).getheaders);
    // Quiet for the failover window: next candidate.
    s = header_source_step(true, true, false, false, kCaughtUpFailoverSec, 12);
    EXPECT_TRUE(s.failover);
    EXPECT_FALSE(header_source_step(true, true, false, false,
                                    kCaughtUpFailoverSec - 1, 12).failover);
    // A fresh handshake while caught up asks the new peer for its headers.
    EXPECT_TRUE(header_source_step(true, true, true, false, 0, 0).getheaders);
    // No peer: nothing to ask, but the failover still runs.
    s = header_source_step(true, false, false, false, kCaughtUpFailoverSec, 0);
    EXPECT_FALSE(s.getheaders);
    EXPECT_TRUE(s.failover);
}
