// SPDX-License-Identifier: AGPL-3.0-or-later
//
// D-DASH.1 KATs: a daemonless c2pool-dash node reports template_source
// "embedded" only while the embedded arm actually serves.
//
// Each case attaches the REAL dash::TemplateSourceNode to a REAL
// core::MiningInterface and reads the REAL /local_stats template_source, so
// the adapter and the web_server seam are checked together.
//
//  (a) an EMBEDDED serve reports "embedded", and "embedded+rpc" when the dashd
//      NodeRPC arm is also armed (set_coin_rpc_available).
//  (b) a dashd-fallback serve clears the flag on the very next template: the
//      flag follows every sourced template and is never latched.
//  (c) none(set-gap/no-work) is not embedded, even when the embedded arm was
//      the one selected. Without dashd the node then reads template_source
//      "none" and node_role "relay".
//
// FAIL WITHOUT THE ADAPTER: c2pool-dash attached no coin node, so every case
// read template_source null.

#include <gtest/gtest.h>

#include <atomic>
#include <memory>
#include <stdexcept>
#include <thread>

#include <nlohmann/json.hpp>

#include <core/web_server.hpp>
#include <impl/dash/template_source_node.hpp>

namespace {

using Arm = dash::TemplateSourceNode::ServedArm;

std::unique_ptr<core::MiningInterface> make_mi()
{
    return std::make_unique<core::MiningInterface>(/*testnet=*/false, /*node=*/nullptr,
                                                   c2pool::address::Blockchain::DASH);
}

} // namespace

TEST(DashTemplateSource, A_EmbeddedServeReportsEmbedded)
{
    auto mi = make_mi();
    dash::TemplateSourceNode ts;
    mi->set_coin_node(&ts);
    mi->set_stratum_hashrate_fn([]() { return 0.0; });

    ts.note_sourced(dash::TemplateSourceNode::classify(/*embedded_arm_selected=*/true,
                                                       /*no_work=*/false));
    auto r = mi->rest_local_stats();
    EXPECT_EQ(r["template_source"], "embedded");
    EXPECT_EQ(r["node_role"], "mining");

    mi->set_coin_rpc_available(true);  // dashd attached as the fallback arm
    r = mi->rest_local_stats();
    EXPECT_EQ(r["template_source"], "embedded+rpc");
    mi->set_coin_node(nullptr);
}

TEST(DashTemplateSource, B_DashdFallbackClearsTheFlagOnTheNextTemplate)
{
    auto mi = make_mi();
    dash::TemplateSourceNode ts;
    mi->set_coin_node(&ts);
    mi->set_coin_rpc_available(true);
    mi->set_stratum_hashrate_fn([]() { return 0.0; });

    ts.note_sourced(dash::TemplateSourceNode::classify(true, false));
    EXPECT_EQ(mi->rest_local_stats()["template_source"], "embedded+rpc");

    ts.note_sourced(dash::TemplateSourceNode::classify(/*embedded_arm_selected=*/false,
                                                       /*no_work=*/false));
    EXPECT_EQ(ts.last_arm(), Arm::DashdFallback);
    EXPECT_FALSE(ts.is_embedded());
    EXPECT_EQ(mi->rest_local_stats()["template_source"], "rpc")
        << "a dashd-fallback serve is not an embedded serve";

    ts.note_sourced(dash::TemplateSourceNode::classify(true, false));
    EXPECT_EQ(mi->rest_local_stats()["template_source"], "embedded+rpc")
        << "the flag follows every sourced template";
    mi->set_coin_node(nullptr);
}

TEST(DashTemplateSource, C_NoWorkIsNotEmbedded)
{
    auto mi = make_mi();
    dash::TemplateSourceNode ts;
    mi->set_coin_node(&ts);
    mi->set_stratum_hashrate_fn([]() { return 0.0; });

    // Before the first sourced template nothing has been served.
    EXPECT_EQ(ts.last_arm(), Arm::None);
    EXPECT_EQ(mi->rest_local_stats()["template_source"], "none");

    ts.note_sourced(dash::TemplateSourceNode::classify(true, false));
    ASSERT_TRUE(ts.is_embedded());

    // Set-gap: the embedded arm was selected but produced no mineable work.
    ts.note_sourced(dash::TemplateSourceNode::classify(/*embedded_arm_selected=*/true,
                                                       /*no_work=*/true));
    EXPECT_EQ(ts.last_arm(), Arm::None);
    EXPECT_FALSE(ts.is_embedded());
    auto r = mi->rest_local_stats();
    EXPECT_EQ(r["template_source"], "none");
    EXPECT_EQ(r["node_role"], "relay");
    EXPECT_EQ(r["node_role_basis"], "no_template_source");
    EXPECT_EQ(dash::TemplateSourceNode::classify(false, true), Arm::None);
    mi->set_coin_node(nullptr);
}

TEST(DashTemplateSource, NeutralMembersOpenNoWorkOrSubmitPath)
{
    dash::TemplateSourceNode ts;
    ts.note_sourced(Arm::Embedded);
    EXPECT_FALSE(ts.has_rpc())
        << "true would arm WebServer's own GBT poll and submit forward";
    EXPECT_THROW(ts.get_work_view(), std::runtime_error);
    EXPECT_FALSE(ts.submit_block_hex("00", false));
}

TEST(DashTemplateSource, StratumWriterAndHttpReaderDoNotRace)
{
    dash::TemplateSourceNode ts;
    std::atomic<bool> stop{false};
    std::thread writer([&] {
        for (int i = 0; i < 200000; ++i)
            ts.note_sourced(i % 3 == 0 ? Arm::Embedded
                          : i % 3 == 1 ? Arm::DashdFallback : Arm::None);
        stop.store(true);
    });
    uint64_t reads = 0;
    while (!stop.load()) {
        const auto a = ts.last_arm();
        ASSERT_TRUE(a == Arm::None || a == Arm::Embedded || a == Arm::DashdFallback);
        (void)ts.is_embedded();
        ++reads;
    }
    writer.join();
    EXPECT_GT(reads, 0u);
}
