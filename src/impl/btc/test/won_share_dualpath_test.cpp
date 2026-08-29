// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// Gate #744 BINDING KAT: forced won share -> make_on_block_found -> BOTH arms.
//
// BTC ShareTracker::m_on_block_found fires the instant a verified sharechain
// share crosses the BTC network target, but main_btc.cpp never assigned it, so
// a peer-relayed won share was silently dropped (subsidy lost). This drives a
// forced won share through the connect-authoritative dispatch handler and
// asserts BOTH broadcast arms fire: P2P relay (best-effort bytes) + submitblock
// RPC (connect-authoritative hex), carrying the byte-identical block.
//
// The reconstructor is INJECTED as a stub here -- the faithful share->block
// reassembly (mirroring p2pool data.py Share.as_block / DGB #174/#176) is the
// next sub-slice; this KAT pins the DISPATCH contract independent of it, exactly
// as the header's "build-verifiable and run-tested NOW" contract intends.
//
// Rides the already-allowlisted btc_share_test executable, so no build.yml
// --target allowlist change is needed (no #137-style NOT_BUILT sentinel risk).
// p2pool-merged-v36 surface: NONE.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <core/uint256.hpp>

#include "../coin/won_block_dispatch.hpp"

using btc::coin::make_on_block_found;

namespace {

std::string to_hex(const std::vector<unsigned char>& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (unsigned char c : b) { s.push_back(d[c >> 4]); s.push_back(d[c & 0xf]); }
    return s;
}

using Recon = std::optional<std::pair<std::vector<unsigned char>, std::string>>;

} // namespace

// 1) THE GATE: one forced won share -> reconstruct -> BOTH arms carry the
//    byte-identical block (P2P relay bytes, submitblock RPC hex).
TEST(BtcForcedWonShareDualPath, BothArmsCarryIdenticalBlock) {
    const std::vector<unsigned char> block_bytes = {0x01, 0x02, 0x03, 0xde, 0xad, 0xbe, 0xef};
    const std::string block_hex = to_hex(block_bytes);

    std::vector<unsigned char> relayed;
    bool did_relay = false;
    std::string submitted;
    int submit_calls = 0;

    auto reconstruct = [&](const uint256&) -> Recon { return std::make_pair(block_bytes, block_hex); };
    auto relay  = [&](const std::vector<unsigned char>& b) { did_relay = true; relayed = b; return true; };
    auto submit = [&](const std::string& h) { ++submit_calls; submitted = h; return true; };

    auto handler = make_on_block_found(reconstruct, relay, submit);
    handler(uint256::ZERO);                 // FORCE the won share

    // ARM A -- embedded P2P relay fired with the block bytes.
    ASSERT_TRUE(did_relay);
    EXPECT_EQ(relayed, block_bytes);

    // ARM B -- submitblock RPC ALWAYS fired (connect-authoritative), with the hex.
    ASSERT_EQ(submit_calls, 1);
    EXPECT_EQ(submitted, block_hex);

    // CROSS-ARM IDENTITY: arm-A bytes hex-encode to exactly arm-B's hex.
    EXPECT_EQ(to_hex(relayed), submitted);
}

// 2) Unassemblable share -> reconstruct returns nullopt -> NEITHER arm fires
//    (never fabricate or relay a partial block).
TEST(BtcForcedWonShareDualPath, UnassemblableShareBroadcastsNothing) {
    bool did_relay = false;
    int submit_calls = 0;

    auto reconstruct = [&](const uint256&) -> Recon { return std::nullopt; };
    auto relay  = [&](const std::vector<unsigned char>&) { did_relay = true; return true; };
    auto submit = [&](const std::string&) { ++submit_calls; return true; };

    auto handler = make_on_block_found(reconstruct, relay, submit);
    handler(uint256::ZERO);

    EXPECT_FALSE(did_relay);
    EXPECT_EQ(submit_calls, 0);
}

// 3) Connect-authoritative: even when the P2P relay FAILS, the submitblock RPC
//    still fires and the block reaches a sink (no silent loss).
TEST(BtcForcedWonShareDualPath, P2pFailureStillConnectsViaRpc) {
    const std::vector<unsigned char> block_bytes = {0xaa, 0xbb};

    int submit_calls = 0;
    auto reconstruct = [&](const uint256&) -> Recon { return std::make_pair(block_bytes, std::string("aabb")); };
    auto relay  = [&](const std::vector<unsigned char>&) { return false; };  // P2P down
    auto submit = [&](const std::string&) { ++submit_calls; return true; };

    auto handler = make_on_block_found(reconstruct, relay, submit);
    handler(uint256::ZERO);

    EXPECT_EQ(submit_calls, 1);   // RPC fired despite P2P failure
}
