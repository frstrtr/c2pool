// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// dgb_live_node_status_test -- guards the D-DGB.LIVEADAPTER null-handle seam:
// EmbeddedCoinNode::has_live_node()/live_status() and the make_live_node_status
// SSOT that /api/spv_progress + /api/node_topology route through.
//
// The defect it pins closed: with NO live embedded coin-daemon node feeding the
// HeaderChain (every run until the M3 header ingest lands), getblockchaininfo()
// returns height 0 and is_synced() is false. Emitted raw to the operator
// dashboard that is a FAKE ZERO -- indistinguishable from a real, connected
// node parked at genesis. This test proves the absent (null) handle instead
// renders as a labelled "no live node" state with NULL height/synced, and that
// a present handle flips to real readings -- and that a THROWING probe is
// treated as not-live, never a crash.
// MUST also be in BOTH build.yml --target allowlists (#143 NOT_BUILT trap).
// ---------------------------------------------------------------------------

#include <stdexcept>

#include <gtest/gtest.h>

#include <impl/dgb/coin/embedded_coin_node.hpp>
#include <impl/dgb/coin/live_node_status.hpp>

using c2pool::dgb::HeaderChain;
using dgb::coin::EmbeddedCoinNode;
using dgb::coin::make_live_node_status;

namespace {

core::SubsidyFunc make_subsidy() {
    return [](uint32_t height) -> uint64_t { return 1000ull + height; };
}

} // namespace

// --- make_live_node_status SSOT: absent handle => labelled, null, no zero ----
TEST(DgbLiveNodeStatus, AbsentHandleIsLabelledNotFakeZero)
{
    const nlohmann::json s = make_live_node_status(/*live=*/false, 0, false);
    EXPECT_EQ(s.at("live").get<bool>(), false);
    EXPECT_EQ(s.at("state").get<std::string>(), "no live node");
    // The crux: height/synced are JSON null, NOT 0/false that read as real.
    EXPECT_TRUE(s.at("height").is_null());
    EXPECT_TRUE(s.at("synced").is_null());
}

TEST(DgbLiveNodeStatus, LiveHandleEmitsRealReadings)
{
    const nlohmann::json s = make_live_node_status(/*live=*/true, 4242, true);
    EXPECT_EQ(s.at("live").get<bool>(), true);
    EXPECT_EQ(s.at("state").get<std::string>(), "live");
    EXPECT_EQ(s.at("height").get<long long>(), 4242);
    EXPECT_EQ(s.at("synced").get<bool>(), true);
}

// --- EmbeddedCoinNode: default (no probe) is the null-handle branch ----------
TEST(DgbLiveNodeStatus, DefaultNodeHasNoLiveHandle)
{
    HeaderChain hc;
    EmbeddedCoinNode node(hc, make_subsidy());   // no probe installed => null

    EXPECT_FALSE(node.has_live_node());
    const nlohmann::json s = node.live_status();
    EXPECT_EQ(s.at("live").get<bool>(), false);
    EXPECT_EQ(s.at("state").get<std::string>(), "no live node");
    EXPECT_TRUE(s.at("height").is_null());   // never the fake 0
    EXPECT_TRUE(s.at("synced").is_null());   // never the fake false
}

// --- a probe reporting DOWN is still "no live node" --------------------------
TEST(DgbLiveNodeStatus, ProbeReportingDownIsNotLive)
{
    HeaderChain hc;
    EmbeddedCoinNode node(hc, make_subsidy());
    node.set_live_node_probe([]{ return false; });

    EXPECT_FALSE(node.has_live_node());
    EXPECT_TRUE(node.live_status().at("height").is_null());
}

// --- a probe reporting UP flips to real chain-derived readings ---------------
TEST(DgbLiveNodeStatus, ProbeReportingUpEmitsRealReadings)
{
    HeaderChain hc;
    EmbeddedCoinNode node(hc, make_subsidy());
    node.set_live_node_probe([]{ return true; });

    EXPECT_TRUE(node.has_live_node());
    const nlohmann::json s = node.live_status();
    EXPECT_EQ(s.at("live").get<bool>(), true);
    EXPECT_EQ(s.at("state").get<std::string>(), "live");
    ASSERT_FALSE(s.at("height").is_null());
    EXPECT_EQ(s.at("height").get<long long>(), 0);  // empty chain, but REAL 0
    ASSERT_FALSE(s.at("synced").is_null());
    EXPECT_EQ(s.at("synced").get<bool>(), false);   // is_synced() truthful false
}

// --- a THROWING probe must be treated as not-live, never propagate a crash ---
TEST(DgbLiveNodeStatus, ThrowingProbeIsNotLiveNeverCrashes)
{
    HeaderChain hc;
    EmbeddedCoinNode node(hc, make_subsidy());
    node.set_live_node_probe([]() -> bool { throw std::runtime_error("node down"); });

    EXPECT_NO_THROW({
        EXPECT_FALSE(node.has_live_node());
        EXPECT_EQ(node.live_status().at("state").get<std::string>(), "no live node");
    });
}
