// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// dgb::coin::broadcast_won_block dual-path dispatcher test (#82 broadcaster-
// gate, dispatcher half).
//
// Offline contract slice mirroring src/impl/bch/test/embedded_block_broadcast_test.cpp
// (@90a35536). Locks the dual-path rule the DGB run-loop depends on when it
// wires tracker().m_on_block_found to this dispatcher: BOTH the embedded P2P
// relay (PRIMARY) and the external digibyted submitblock (FALLBACK, fired
// ALWAYS) are attempted, each leg is guarded, landed_first records the race
// winner, and with NEITHER sink live the call is a safe no-op (any()=false,
// no throw). Uses a fake ICoinNode so the dispatch contract is verified without
// the real NodeRPC transport (deferred). p2pool-merged-v36 surface: NONE.
//
// MUST appear in BOTH test/CMakeLists.txt AND the build.yml --target allowlist
// or it becomes a #143-style NOT_BUILT sentinel that reds master.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <stdexcept>
#include <string>
#include <vector>

#include "../coin/block_broadcast.hpp"

namespace {

// Controllable external-RPC seam: lets each case set has_rpc() and the
// submit_block_hex() ack independently, and records the call so the "always
// fired" rule is observable.
class FakeSeam : public core::coin::ICoinNode {
public:
    bool rpc_present = true;
    bool submit_ack  = true;
    bool throw_on_submit = false;
    int  submit_calls = 0;
    bool last_ignore_failure = false;

    core::coin::WorkView get_work_view() override { return {}; }

    bool submit_block_hex(const std::string&, bool ignore_failure) override {
        ++submit_calls;
        last_ignore_failure = ignore_failure;
        if (throw_on_submit) throw std::runtime_error("submitblock RPC boom");
        return submit_ack;
    }

    bool is_embedded() const override { return false; }
    bool has_rpc()     const override { return rpc_present; }
};

const std::vector<unsigned char> kBytes(120, 0x42);
const std::string                kHex = "00112233";

} // namespace

// 1) NEITHER sink live -> safe no-op: any()=false, landed_first="none", no throw,
//    and a null seam is never dereferenced.
TEST(DgbBlockBroadcast, NoSinkLiveIsSafeNoOp) {
    auto r = dgb::coin::broadcast_won_block(/*p2p_relay=*/{}, /*seam=*/nullptr,
                                            kBytes, kHex);
    EXPECT_FALSE(r.p2p_sent);
    EXPECT_FALSE(r.rpc_ok);
    EXPECT_FALSE(r.any());
    EXPECT_STREQ(r.landed_first, "none");
}

// 2) P2P-only: relay sink present, no RPC -> p2p wins, fallback skipped cleanly.
TEST(DgbBlockBroadcast, P2pOnly) {
    bool relayed = false;
    std::vector<unsigned char> seen;
    auto relay = [&](const std::vector<unsigned char>& b) { relayed = true; seen = b; };

    FakeSeam seam; seam.rpc_present = false;
    auto r = dgb::coin::broadcast_won_block(relay, &seam, kBytes, kHex);

    EXPECT_TRUE(relayed);
    EXPECT_EQ(seen, kBytes);
    EXPECT_TRUE(r.p2p_sent);
    EXPECT_FALSE(r.rpc_ok);
    EXPECT_TRUE(r.any());
    EXPECT_STREQ(r.landed_first, "p2p");
    EXPECT_EQ(seam.submit_calls, 0);  // no RPC sink -> fallback not attempted
}

// 3) RPC-only: no embedded P2P sink, RPC acks -> fallback wins the race.
TEST(DgbBlockBroadcast, RpcOnly) {
    FakeSeam seam; seam.rpc_present = true; seam.submit_ack = true;
    auto r = dgb::coin::broadcast_won_block(/*p2p_relay=*/{}, &seam, kBytes, kHex);

    EXPECT_FALSE(r.p2p_sent);
    EXPECT_TRUE(r.rpc_ok);
    EXPECT_TRUE(r.any());
    EXPECT_STREQ(r.landed_first, "rpc");
    EXPECT_EQ(seam.submit_calls, 1);
    EXPECT_TRUE(seam.last_ignore_failure);  // duplicate must not mask a P2P win
}

// 4) DUAL-PATH: both sinks live -> p2p wins landed_first, but the RPC fallback
//    STILL fires (the always-fire rule), and a duplicate ack there is success.
TEST(DgbBlockBroadcast, DualPathAlwaysFiresFallback) {
    bool relayed = false;
    auto relay = [&](const std::vector<unsigned char>&) { relayed = true; };

    FakeSeam seam; seam.rpc_present = true; seam.submit_ack = true;
    auto r = dgb::coin::broadcast_won_block(relay, &seam, kBytes, kHex);

    EXPECT_TRUE(relayed);
    EXPECT_TRUE(r.p2p_sent);
    EXPECT_TRUE(r.rpc_ok);               // fallback fired even though P2P won
    EXPECT_EQ(seam.submit_calls, 1);     // ALWAYS-fired, not P2P-only catch
    EXPECT_STREQ(r.landed_first, "p2p"); // primary won the race
}

// 5) Both sinks present but RPC no-acks (rejected): p2p still carried the block,
//    rpc_ok=false, any()=true (P2P leg succeeded).
TEST(DgbBlockBroadcast, FallbackNoAckDoesNotMaskP2p) {
    auto relay = [&](const std::vector<unsigned char>&) {};
    FakeSeam seam; seam.rpc_present = true; seam.submit_ack = false;
    auto r = dgb::coin::broadcast_won_block(relay, &seam, kBytes, kHex);

    EXPECT_TRUE(r.p2p_sent);
    EXPECT_FALSE(r.rpc_ok);
    EXPECT_TRUE(r.any());
    EXPECT_STREQ(r.landed_first, "p2p");
    EXPECT_EQ(seam.submit_calls, 1);
}


// 6) GUARD (NMC #468 mirror -- throw->fallback-fires): the PRIMARY P2P relay
//    sink THROWS. The dispatcher must NOT propagate; it falls through to the
//    always-fire submitblock RPC fallback so a P2P-leg fault never silently
//    drops a won block (lost subsidy) nor removes the external-daemon fallback.
TEST(DgbBlockBroadcast, P2pThrowFallsThroughToRpcFallback) {
    auto relay = [&](const std::vector<unsigned char>&) {
        throw std::runtime_error("p2p relay boom");
    };
    FakeSeam seam; seam.rpc_present = true; seam.submit_ack = true;

    dgb::coin::BlockBroadcast r;
    ASSERT_NO_THROW({ r = dgb::coin::broadcast_won_block(relay, &seam, kBytes, kHex); });

    EXPECT_FALSE(r.p2p_sent);            // a throwing relay did not actually send
    EXPECT_TRUE(r.rpc_ok);              // fallback STILL fired despite the P2P fault
    EXPECT_TRUE(r.any());
    EXPECT_EQ(seam.submit_calls, 1);    // always-fire fallback preserved, not skipped
    EXPECT_STREQ(r.landed_first, "rpc");
}

// 7) GUARD (NMC #468 mirror -- throw->p2p-win-preserved): the FALLBACK RPC leg
//    THROWS. The dispatcher must NOT propagate and must never mask the P2P win:
//    p2p_sent stays true, rpc_ok=false (a throw is a no-ack).
TEST(DgbBlockBroadcast, RpcThrowDoesNotMaskP2pWin) {
    bool relayed = false;
    auto relay = [&](const std::vector<unsigned char>&) { relayed = true; };
    FakeSeam seam; seam.rpc_present = true; seam.throw_on_submit = true;

    dgb::coin::BlockBroadcast r;
    ASSERT_NO_THROW({ r = dgb::coin::broadcast_won_block(relay, &seam, kBytes, kHex); });

    EXPECT_TRUE(relayed);
    EXPECT_TRUE(r.p2p_sent);            // P2P win preserved through the RPC fault
    EXPECT_FALSE(r.rpc_ok);            // a throwing RPC leg = no-ack, not a mask
    EXPECT_TRUE(r.any());
    EXPECT_STREQ(r.landed_first, "p2p");
    EXPECT_EQ(seam.submit_calls, 1);   // it was attempted (then threw)
}