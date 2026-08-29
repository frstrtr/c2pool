// SPDX-License-Identifier: AGPL-3.0-or-later
//
// test_dash_won_block_dispatch -- KATs for dash::coin::make_on_block_found, the
// DISTRIBUTED won-block re-broadcast dispatcher (p2pool-dash node.py:268-282
// fan-out). This is the behavioral proof of the feature that DASH previously
// LACKED: before it, ShareTracker::m_on_block_found was bound to the DISPLAY-ONLY
// dashboard handler, so a block found by a PEER (a gossiped share whose X11
// header also clears the coin BLOCK target) was recorded but NEVER re-broadcast.
//
// RED->GREEN: the symbol dash::coin::make_on_block_found does not exist on
// master (only the low-level broadcast_won_block does), so this TU does not even
// compile against master -- the feature is absent. With the dispatcher wired it
// compiles and these behaviors hold.
//
// The dispatcher is driven with an INJECTED reconstruct fn + RECORDING sinks, so
// no live ShareTracker / coin-P2P peer / dashd is needed. reconstruct_won_block's
// own byte correctness is proven separately in test_dash_won_block_reconstruct.
//
// FOLDED into the already-allowlisted test_dash_broadcaster_full executable (same
// fold rationale as test_dash_won_block_dualpath): distinct suite name + anon
// namespace, gtest_main-provided main() -> no symbol clash.

#include <gtest/gtest.h>

#include <optional>
#include <string>
#include <vector>

#include <impl/dash/coin/won_block_dispatch.hpp>

namespace {

using dash::coin::ReconstructedWonBlock;
using dash::coin::make_on_block_found;

uint256 hash_from_byte(unsigned char b) {
    uint256 h;
    std::vector<unsigned char> v(32, 0);
    v[0] = b;
    h = uint256(v);
    return h;
}

ReconstructedWonBlock sample_block() {
    ReconstructedWonBlock blk;
    blk.bytes = {0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04};
    blk.hex   = "deadbeef01020304";
    return blk;
}

// A recorder for the two broadcast arms + the telemetry/dedup legs.
struct Sinks {
    int p2p_calls = 0, rpc_calls = 0, telemetry_calls = 0, mark_calls = 0;
    std::vector<unsigned char> last_p2p_bytes;
    std::string last_rpc_hex;
    uint256 last_marked;

    dash::coin::P2pRelaySink p2p() {
        return [this](const std::vector<unsigned char>& b) -> bool {
            ++p2p_calls; last_p2p_bytes = b; return true;
        };
    }
    dash::coin::RpcSubmitSink rpc() {
        return [this](const std::string& hex) -> bool {
            ++rpc_calls; last_rpc_hex = hex; return true;
        };
    }
    dash::coin::FoundBlockTelemetryFn telemetry() {
        return [this](const uint256&) { ++telemetry_calls; };
    }
    dash::coin::MarkBroadcastFn mark() {
        return [this](const uint256& h) { ++mark_calls; last_marked = h; };
    }
};

// Post inline so the broadcast is observable synchronously in the test.
dash::coin::WonBlockPostFn inline_post() {
    return [](std::function<void()> w) { w(); };
}

} // namespace

// GREEN: a reconstructable PEER won-share is re-broadcast down BOTH arms and the
// dashboard telemetry fires AFTER the broadcast. This is the fan-out the feature
// adds -- on master this path did nothing but record a dashboard row.
TEST(DashWonBlockDispatch, ReconstructablePeerShareBroadcastsBothArms) {
    Sinks s;
    const uint256 sh = hash_from_byte(0xa1);

    auto handler = make_on_block_found(
        /*reconstruct=*/[](const uint256&) { return std::optional<ReconstructedWonBlock>(sample_block()); },
        s.p2p(), s.rpc(), inline_post(),
        /*already=*/{}, s.mark(), s.telemetry());

    handler(sh);

    EXPECT_EQ(s.p2p_calls, 1);
    EXPECT_EQ(s.rpc_calls, 1);
    EXPECT_EQ(s.last_p2p_bytes, sample_block().bytes);
    EXPECT_EQ(s.last_rpc_hex, sample_block().hex);
    EXPECT_EQ(s.mark_calls, 1);
    EXPECT_EQ(s.last_marked, sh);
    EXPECT_EQ(s.telemetry_calls, 1);   // post-broadcast telemetry still fires
}

// FAIL-LOUD: a share that cannot be reconstructed (nullopt) broadcasts NOTHING
// down either arm (never a partial/malformed block) -- mirroring p2pool "GOT
// INCOMPLETE BLOCK" + dgb "NOT broadcast". The dashboard row is still recorded
// so the found block is not lost from view (no display regression).
TEST(DashWonBlockDispatch, IncompleteShareBroadcastsNothing) {
    Sinks s;
    auto handler = make_on_block_found(
        /*reconstruct=*/[](const uint256&) { return std::optional<ReconstructedWonBlock>(std::nullopt); },
        s.p2p(), s.rpc(), inline_post(),
        /*already=*/{}, s.mark(), s.telemetry());

    handler(hash_from_byte(0xb2));

    EXPECT_EQ(s.p2p_calls, 0);       // NOTHING broadcast
    EXPECT_EQ(s.rpc_calls, 0);
    EXPECT_EQ(s.mark_calls, 0);      // not marked (nothing went out)
    EXPECT_EQ(s.telemetry_calls, 1); // but the found-block row is still recorded
}

// A missing reconstructor is also fail-loud: broadcast NOTHING (telemetry still
// records the found block).
TEST(DashWonBlockDispatch, NoReconstructorBroadcastsNothing) {
    Sinks s;
    auto handler = make_on_block_found(
        /*reconstruct=*/{}, s.p2p(), s.rpc(), inline_post(),
        /*already=*/{}, s.mark(), s.telemetry());

    handler(hash_from_byte(0xc3));

    EXPECT_EQ(s.p2p_calls, 0);
    EXPECT_EQ(s.rpc_calls, 0);
    EXPECT_EQ(s.mark_calls, 0);
    EXPECT_EQ(s.telemetry_calls, 1);
}

// DEDUP: a block already broadcast by this node (the recent-won-block FIFO says
// so) is NOT re-submitted -- the reconstruct + broadcast are skipped -- but the
// dashboard row is still (idempotently) recorded.
TEST(DashWonBlockDispatch, AlreadyBroadcastSkipsReBroadcast) {
    Sinks s;
    int reconstruct_calls = 0;
    auto handler = make_on_block_found(
        /*reconstruct=*/[&](const uint256&) {
            ++reconstruct_calls;
            return std::optional<ReconstructedWonBlock>(sample_block());
        },
        s.p2p(), s.rpc(), inline_post(),
        /*already=*/[](const uint256&) { return true; }, s.mark(), s.telemetry());

    handler(hash_from_byte(0xd4));

    EXPECT_EQ(reconstruct_calls, 0); // short-circuited before reconstruct
    EXPECT_EQ(s.p2p_calls, 0);
    EXPECT_EQ(s.rpc_calls, 0);
    EXPECT_EQ(s.mark_calls, 0);
    EXPECT_EQ(s.telemetry_calls, 1);
}

// Daemonless (P2P-only) deployment: a reconstructable share still reaches the
// network on the embedded relay alone (RPC arm empty).
TEST(DashWonBlockDispatch, DaemonlessP2pOnlyStillBroadcasts) {
    Sinks s;
    auto handler = make_on_block_found(
        /*reconstruct=*/[](const uint256&) { return std::optional<ReconstructedWonBlock>(sample_block()); },
        s.p2p(), /*rpc=*/{}, inline_post(),
        /*already=*/{}, s.mark(), s.telemetry());

    handler(hash_from_byte(0xe5));

    EXPECT_EQ(s.p2p_calls, 1);
    EXPECT_EQ(s.rpc_calls, 0);
    EXPECT_EQ(s.mark_calls, 1);
    EXPECT_EQ(s.telemetry_calls, 1);
}
