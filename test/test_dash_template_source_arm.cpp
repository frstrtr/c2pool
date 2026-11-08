// SPDX-License-Identifier: AGPL-3.0-or-later
//
// D-DASH.1 KATs: a daemonless c2pool-dash node reports template_source
// "embedded" only while the embedded arm actually serves. Each case publishes
// through the same dash::publish_served_arm main_dash.cpp binds and reads the
// REAL /local_stats, with NO coin node attached, as in production.

#include <gtest/gtest.h>

#include <atomic>
#include <memory>
#include <string>
#include <thread>

#include <nlohmann/json.hpp>

#include <core/web_server.hpp>
#include <impl/dash/template_source_arm.hpp>

namespace {

std::unique_ptr<core::MiningInterface> make_mi()
{
    auto mi = std::make_unique<core::MiningInterface>(/*testnet=*/false, /*node=*/nullptr,
                                                      c2pool::address::Blockchain::DASH);
    mi->set_stratum_hashrate_fn([]() { return 0.0; });
    return mi;
}

} // namespace

TEST(DashTemplateSource, A_EmbeddedServeReportsEmbedded)
{
    auto mi = make_mi();
    dash::publish_served_arm(*mi, /*embedded_arm_selected=*/true, /*no_work=*/false);
    auto r = mi->rest_local_stats();
    EXPECT_EQ(r["template_source"], "embedded");
    EXPECT_EQ(r["node_role"], "mining");

    mi->set_coin_rpc_available(true);  // dashd attached as the fallback arm
    EXPECT_EQ(mi->rest_local_stats()["template_source"], "embedded+rpc");
}

TEST(DashTemplateSource, B_DashdFallbackClearsTheFlagOnTheNextTemplate)
{
    auto mi = make_mi();
    mi->set_coin_rpc_available(true);
    dash::publish_served_arm(*mi, true, false);
    EXPECT_EQ(mi->rest_local_stats()["template_source"], "embedded+rpc");

    dash::publish_served_arm(*mi, /*embedded_arm_selected=*/false, /*no_work=*/false);
    EXPECT_EQ(mi->rest_local_stats()["template_source"], "rpc")
        << "a dashd-fallback serve is not an embedded serve";

    dash::publish_served_arm(*mi, true, false);
    EXPECT_EQ(mi->rest_local_stats()["template_source"], "embedded+rpc")
        << "the flag follows every sourced template";
}

TEST(DashTemplateSource, C_NoWorkIsNotEmbedded)
{
    auto mi = make_mi();

    // Nothing sourced yet: unknown, and an unknown must not read as a relay.
    auto before = mi->rest_local_stats();
    EXPECT_TRUE(before["template_source"].is_null());
    EXPECT_EQ(before["node_role"], "mining");
    EXPECT_EQ(before["node_role_basis"], "stratum");

    dash::publish_served_arm(*mi, true, false);
    EXPECT_EQ(mi->rest_local_stats()["template_source"], "embedded");

    // Set-gap: the embedded arm was selected but produced no mineable work.
    dash::publish_served_arm(*mi, /*embedded_arm_selected=*/true, /*no_work=*/true);
    auto r = mi->rest_local_stats();
    EXPECT_EQ(r["template_source"], "none");
    EXPECT_EQ(r["node_role"], "relay");
    EXPECT_EQ(r["node_role_basis"], "no_template_source");
    EXPECT_EQ(dash::classify_served_arm(false, true), dash::ServedArm::None);
}

// Condition (1) of the Option B pick: the tri-state unset is the old optional
// unset, and the one existing caller (BIP-110, always true) is unchanged.
TEST(DashTemplateSource, D_UnsetAndStaticCallersKeepTheirOutput)
{
    auto unset = make_mi();
    EXPECT_TRUE(unset->rest_local_stats()["template_source"].is_null());
    unset->set_coin_rpc_available(true);
    EXPECT_EQ(unset->rest_local_stats()["template_source"], "rpc");

    auto static_true = make_mi();
    static_true->set_embedded_display(true);
    EXPECT_EQ(static_true->rest_local_stats()["template_source"], "embedded");
}

TEST(DashTemplateSource, E_StratumWriterAndHttpReaderDoNotRace)
{
    auto mi = make_mi();
    std::atomic<bool> stop{false};
    std::thread writer([&] {
        for (int i = 0; !stop.load(); ++i)
            dash::publish_served_arm(*mi, i % 2 == 0, i % 3 == 0);
    });
    for (int i = 0; i < 200; ++i) {
        const auto ts = mi->rest_local_stats()["template_source"];
        ASSERT_TRUE(ts == "embedded" || ts == "none" || ts.is_null());
    }
    stop.store(true);
    writer.join();
}
