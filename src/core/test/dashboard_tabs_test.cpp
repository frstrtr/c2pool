// dashboard_tabs_test.cpp — #926 coin-switcher tab set (core/dashboard_tabs.hpp).
//
// KATs from the issue: no sibling config on a single-coin node is exactly the
// one active label we render today; a configured sibling is a tab with a
// working href; an empty/invalid entry renders nothing. Plus the integrator's
// ruling: a local secondary coin is a non-clickable label (location:null).

#include <gtest/gtest.h>

#include <core/dashboard_tabs.hpp>

using core::DashboardPeer;
using core::build_dashboard_tabs;
using core::parse_dashboard_peer;
using nlohmann::json;

namespace {

json topo(std::initializer_list<std::pair<const char*, bool>> coins) {
    json arr = json::array();
    for (const auto& c : coins) arr.push_back({{"coin", c.first}, {"primary", c.second}, {"peers", 3}});
    return json{{"node_symbol", "X"}, {"coins", arr}};
}

json tab(const char* coin, const char* sym, bool active, json location) {
    return json{{"coin", coin}, {"symbol", sym}, {"active", active}, {"location", location}};
}

}  // namespace

TEST(DashboardTabs, NoConfigSingleCoinIsTodaysSingleActiveLabel) {
    json out = build_dashboard_tabs(topo({{"LTC", true}}), {});
    json want = {{"tabs", json::array({tab("ltc", "LTC", true, "/")})}};
    EXPECT_EQ(out, want);
}

TEST(DashboardTabs, LocalSecondaryCoinIsNonClickableLabel) {
    json out = build_dashboard_tabs(topo({{"LTC", true}, {"DOGE", false}}), {});
    ASSERT_EQ(out["tabs"].size(), 2u);
    EXPECT_EQ(out["tabs"][0], tab("ltc", "LTC", true, "/"));
    EXPECT_EQ(out["tabs"][1], tab("doge", "DOGE", false, nullptr));
    EXPECT_TRUE(out["tabs"][1]["location"].is_null());
}

TEST(DashboardTabs, PrimaryFirstRegardlessOfTopologyOrder) {
    json out = build_dashboard_tabs(topo({{"DOGE", false}, {"LTC", true}}), {});
    ASSERT_EQ(out["tabs"].size(), 2u);
    EXPECT_EQ(out["tabs"][0]["symbol"], "LTC");
    EXPECT_EQ(out["tabs"][1]["symbol"], "DOGE");
}

TEST(DashboardTabs, ConfiguredSiblingIsTabWithWorkingHref) {
    auto p = parse_dashboard_peer("dash=https://dash.voidbind.com");
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(p->symbol, "DASH");
    json out = build_dashboard_tabs(topo({{"LTC", true}, {"DOGE", false}}), {*p});
    ASSERT_EQ(out["tabs"].size(), 3u);
    EXPECT_EQ(out["tabs"][2], tab("dash", "DASH", false, "https://dash.voidbind.com"));
}

TEST(DashboardTabs, InvalidPeerSpecsAreRejected) {
    for (const char* bad : {"", "DASH", "=https://x.example", "DASH=", "DASH=dash.example.com",
                            "DASH=javascript:alert(1)", "DASH=//dash.example.com", "DASH=https://",
                            "DASH=https:///path", "DA SH=https://x.example", "DASH=https://x.example/a b",
                            "DASH=https://x.example/\"onmouseover=", "DASH=https://x.example/<b>",
                            "WAYTOOLONGSYMBOL1=https://x.example"}) {
        EXPECT_FALSE(parse_dashboard_peer(bad).has_value()) << bad;
    }
    EXPECT_TRUE(parse_dashboard_peer("BTC=http://10.0.0.5:8080/").has_value());
}

TEST(DashboardTabs, InvalidPeerRendersNothingNotADeadTab) {
    // A hand-built vector bypassing parse_dashboard_peer is re-validated.
    std::vector<DashboardPeer> peers = {{"", "https://x.example"}, {"DASH", ""},
                                        {"BCH", "ftp://x.example"}, {"DGB", "https://dgb.example"}};
    json out = build_dashboard_tabs(topo({{"LTC", true}}), peers);
    ASSERT_EQ(out["tabs"].size(), 2u);
    EXPECT_EQ(out["tabs"][1], tab("dgb", "DGB", false, "https://dgb.example"));
}

TEST(DashboardTabs, PeerDuplicatingALocalCoinOrAnotherPeerIsDropped) {
    std::vector<DashboardPeer> peers = {{"DOGE", "https://doge.example"},
                                        {"DASH", "https://a.example"},
                                        {"dash", "https://b.example"}};
    json out = build_dashboard_tabs(topo({{"LTC", true}, {"DOGE", false}}), peers);
    ASSERT_EQ(out["tabs"].size(), 3u);
    EXPECT_TRUE(out["tabs"][1]["location"].is_null());  // local DOGE wins
    EXPECT_EQ(out["tabs"][2]["location"], "https://a.example");  // first DASH wins
}

TEST(DashboardTabs, AtMostOneActiveAndActiveAlwaysHasLocation) {
    json out = build_dashboard_tabs(topo({{"LTC", true}, {"DOGE", true}}),
                                    {{"DASH", "https://dash.example"}});
    int active = 0;
    for (const auto& t : out["tabs"]) {
        if (t["active"].get<bool>()) {
            ++active;
            EXPECT_TRUE(t["location"].is_string());  // v37 is_consistent()
        }
    }
    EXPECT_EQ(active, 1);
}

TEST(DashboardTabs, MalformedTopologyFabricatesNothing) {
    EXPECT_EQ(build_dashboard_tabs(json(nullptr), {})["tabs"].size(), 0u);
    EXPECT_EQ(build_dashboard_tabs(json::object(), {})["tabs"].size(), 0u);
    json t = {{"coins", json::array({json{{"coin", ""}, {"primary", true}},
                                     json{{"coin", 5}, {"primary", true}},
                                     json{{"primary", true}},
                                     json("LTC")})}};
    EXPECT_EQ(build_dashboard_tabs(t, {})["tabs"].size(), 0u);
}

TEST(DashboardTabs, NoLocalPrimaryStillListsPeersButNoActiveTab) {
    json out = build_dashboard_tabs(json::object(), {{"DASH", "https://dash.example"}});
    ASSERT_EQ(out["tabs"].size(), 1u);
    EXPECT_FALSE(out["tabs"][0]["active"].get<bool>());
}
