// SPDX-License-Identifier: AGPL-3.0-or-later
//
// graph_history_test.cpp — G4 year-scale binned graph history (#159).
//
// Ports p2pool util/graph.py's own test (test_graph.py::test_keep_largest) and
// pins the c2pool-specific invariants the design review made load-bearing:
//   * GAUGE-MEAN semantics: a bin holds the MEAN (total/count) of its samples,
//     NEVER total/bin_width — the deliberate deviation from p2pool's rate model
//     that, if wrong, silently rescales every long-view hashrate;
//   * served multivalue dicts never leak the internal 'null' sample-counter key
//     (dashboard.html sums d[1]['null'] into DOA);
//   * ascending output order with leading never-filled bins clipped;
//   * to_obj/from_obj round-trip fidelity;
//   * per-view GEOMETRY-MISMATCH -> needs_reseed (never a null view);
//   * watermark-gated replay is idempotent (no double counting).

#include <gtest/gtest.h>

#include <core/graph_history.hpp>

#include <string>
#include <vector>

using core::graph::Bin;
using core::graph::DataStreamDescription;
using core::graph::DataViewDescription;
using core::graph::HistoryDatabase;
using core::graph::keep_largest;

namespace {

// A one-view schema for focused semantics tests.
std::vector<std::pair<std::string, DataStreamDescription>>
one_view_schema(int bin_count, double total_width, bool multivalues,
                bool undefined0, int keep, bool squash)
{
    DataViewDescription v(bin_count, total_width);
    DataStreamDescription d;
    d.dataview_descriptions = {{"last_hour", v}};
    d.is_gauge = true;
    d.multivalues = multivalues;
    d.multivalue_undefined_means_0 = undefined0;
    d.multivalues_keep = keep;
    if (squash) { d.has_squash_key = true; d.multivalues_squash_key = "other"; }
    return {{"s", d}};
}

double last_scalar(const nlohmann::json& arr)
{
    EXPECT_TRUE(arr.is_array());
    EXPECT_FALSE(arr.empty());
    return arr.back()[1].get<double>();
}

}  // namespace

// ── p2pool test_graph.py::test_keep_largest, ported ──────────────────────────
TEST(GraphHistory, KeepLargestPortsP2poolTest)
{
    // b = dict(a=1, b=3, c=5, d=7, e=9); represented as (total, count=1) so the
    // gauge magnitude (total/count) equals the p2pool scalar.
    Bin b = {{"a", {1, 1}}, {"b", {3, 1}}, {"c", {5, 1}},
             {"d", {7, 1}}, {"e", {9, 1}}};

    // keep_largest(3, 'squashed')(b) == {'squashed': 9, 'd': 7, 'e': 9}
    Bin r1 = keep_largest(b, 3, /*has_squash=*/true, "squashed", /*is_gauge=*/true);
    ASSERT_EQ(r1.size(), 3u);
    EXPECT_DOUBLE_EQ(r1["e"].first, 9);
    EXPECT_DOUBLE_EQ(r1["d"].first, 7);
    ASSERT_TRUE(r1.count("squashed"));
    EXPECT_DOUBLE_EQ(r1["squashed"].first, 9);  // 5 + 3 + 1

    // keep_largest(3)(b) == {'c': 5, 'd': 7, 'e': 9}
    Bin r2 = keep_largest(b, 3, /*has_squash=*/false, "", /*is_gauge=*/true);
    ASSERT_EQ(r2.size(), 3u);
    EXPECT_DOUBLE_EQ(r2["c"].first, 5);
    EXPECT_DOUBLE_EQ(r2["d"].first, 7);
    EXPECT_DOUBLE_EQ(r2["e"].first, 9);
    EXPECT_FALSE(r2.count("a"));
    EXPECT_FALSE(r2.count("b"));
}

// ── GAUGE-MEAN: a bin is the MEAN of its samples, never total/bin_width ───────
TEST(GraphHistory, ScalarBinIsMeanNotRate)
{
    auto db = HistoryDatabase::create(
        one_view_schema(10, 10000.0 /*bin_width=1000*/, false, false, 20, false));

    // First add establishes last_bin_end=11000; subsequent adds with t < that
    // land in the SAME newest bin so we can check the mean of {100,200,300}.
    db.add_scalar("s", 10500, 100);
    db.add_scalar("s", 10600, 200);
    db.add_scalar("s", 10700, 300);

    auto data = db.stream("s")->view("last_hour")->get_data(
        db.stream("s")->desc, 10700);
    // Newest point == arithmetic mean, distinct from total/bin_width(=0.6) and
    // total/width. This is the pin that locks the is_gauge deviation.
    EXPECT_NEAR(last_scalar(data), 200.0, 1e-9);
}

// ── multivalue undefined_means_0 (pool_rates shape) mean + no 'null' leak ─────
TEST(GraphHistory, MultivalueMeanAndNoNullLeak)
{
    auto db = HistoryDatabase::create(
        one_view_schema(10, 10000.0, true, /*undefined0=*/true, 20, false));

    db.add_multi("s", 10500, {{"good", 100}, {"orphan", 10}, {"dead", 0}});
    db.add_multi("s", 10600, {{"good", 300}, {"orphan", 30}, {"dead", 0}});

    auto data = db.stream("s")->view("last_hour")->get_data(
        db.stream("s")->desc, 10600);
    ASSERT_FALSE(data.empty());
    const auto& val = data.back()[1];
    ASSERT_TRUE(val.is_object());
    // Means: good=(100+300)/2=200, orphan=(10+30)/2=20.
    EXPECT_NEAR(val["good"].get<double>(), 200.0, 1e-9);
    EXPECT_NEAR(val["orphan"].get<double>(), 20.0, 1e-9);
    // The internal sample-counter key must NOT reach the served dict, or
    // dashboard.html renderHashrateGraph would sum it into DOA.
    EXPECT_FALSE(val.contains("null"));
}

// ── ascending order + leading never-filled bins clipped ──────────────────────
TEST(GraphHistory, AscendingAndLeadingEmptyClipped)
{
    auto db = HistoryDatabase::create(
        one_view_schema(10, 10000.0, false, false, 20, false));
    db.add_scalar("s", 10500, 42);

    auto data = db.stream("s")->view("last_hour")->get_data(
        db.stream("s")->desc, 10500);
    // Only filled bins remain (the 9 older empty bins are clipped), and the
    // single point carries the value.
    ASSERT_EQ(data.size(), 1u);
    EXPECT_NEAR(data[0][1].get<double>(), 42.0, 1e-9);

    // Timestamps ascending across a multi-bin case.
    auto db2 = HistoryDatabase::create(
        one_view_schema(10, 100.0 /*bin_width=10*/, false, false, 20, false));
    db2.add_scalar("s", 1000, 1);
    db2.add_scalar("s", 1015, 2);
    db2.add_scalar("s", 1035, 3);
    auto d2 = db2.stream("s")->view("last_hour")->get_data(db2.stream("s")->desc, 1035);
    ASSERT_GE(d2.size(), 2u);
    for (size_t i = 1; i < d2.size(); ++i)
        EXPECT_LE(d2[i - 1][0].get<double>(), d2[i][0].get<double>());
}

// ── to_obj / from_obj round-trip fidelity ────────────────────────────────────
TEST(GraphHistory, PersistenceRoundTrip)
{
    auto schema = one_view_schema(10, 10000.0, true, false, 200, true);
    auto db = HistoryDatabase::create(schema);
    db.add_multi("s", 10500, {{"XaddrA", 100}, {"XaddrB", 50}});
    db.add_multi("s", 10600, {{"XaddrA", 200}, {"XaddrB", 60}});

    nlohmann::json obj = db.to_obj();
    bool needs_reseed = true;
    auto db2 = HistoryDatabase::from_obj(schema, obj, needs_reseed);
    EXPECT_FALSE(needs_reseed);
    // Same served output before and after a save/load cycle.
    auto a = db.stream("s")->view("last_hour")->get_data(db.stream("s")->desc, 10600);
    auto b = db2.stream("s")->view("last_hour")->get_data(db2.stream("s")->desc, 10600);
    EXPECT_EQ(a, b);
}

// ── per-view GEOMETRY MISMATCH -> reseed, never a null/mismatched view ────────
TEST(GraphHistory, GeometryMismatchForcesReseed)
{
    auto schema10 = one_view_schema(10, 10000.0, false, false, 20, false);
    auto db = HistoryDatabase::create(schema10);
    db.add_scalar("s", 10500, 7);
    nlohmann::json obj = db.to_obj();

    // A future config changed bin_count 10 -> 20: the stored view is valid JSON
    // but the WRONG geometry. It must be discarded (needs_reseed) and rebuilt
    // empty at the compiled geometry, never loaded as-is and never null.
    auto schema20 = one_view_schema(20, 10000.0, false, false, 20, false);
    bool needs_reseed = false;
    auto db2 = HistoryDatabase::from_obj(schema20, obj, needs_reseed);
    EXPECT_TRUE(needs_reseed);
    const auto* dv = db2.stream("s")->view("last_hour");
    ASSERT_NE(dv, nullptr);
    EXPECT_EQ(dv->bins.size(), 20u);  // compiled geometry, all empty
    for (const auto& bin : dv->bins) EXPECT_TRUE(bin.empty());
}

// ── missing stream in stored obj -> reseed ───────────────────────────────────
TEST(GraphHistory, MissingStreamForcesReseed)
{
    auto schema = one_view_schema(10, 10000.0, false, false, 20, false);
    nlohmann::json empty_obj = nlohmann::json::object();  // nothing stored
    bool needs_reseed = false;
    auto db = HistoryDatabase::from_obj(schema, empty_obj, needs_reseed);
    EXPECT_TRUE(needs_reseed);
    // Still yields a usable, correctly-shaped empty DB (never null).
    ASSERT_NE(db.stream("s"), nullptr);
    ASSERT_NE(db.stream("s")->view("last_hour"), nullptr);
    EXPECT_EQ(db.stream("s")->view("last_hour")->bins.size(), 10u);
}

// ── watermark-gated replay is idempotent (no double counting) ─────────────────
TEST(GraphHistory, WatermarkReplayIsIdempotent)
{
    auto schema = one_view_schema(10, 10000.0, false, false, 20, false);
    auto db = HistoryDatabase::create(schema);

    struct Sample { double t; double v; };
    std::vector<Sample> flat = {{10500, 100}, {10600, 200}, {10700, 300}};
    for (auto& s : flat) db.add_scalar("s", s.t, s.v);
    double watermark = flat.back().t;

    nlohmann::json obj = db.to_obj();
    bool needs_reseed = true;
    auto reloaded = HistoryDatabase::from_obj(schema, obj, needs_reseed);
    ASSERT_FALSE(needs_reseed);

    // Simulate the load-time incremental replay: only entries strictly newer
    // than the watermark are re-added. With watermark == last, nothing replays,
    // so the served output is byte-identical to the pre-save output.
    for (auto& s : flat)
        if (s.t > watermark) reloaded.add_scalar("s", s.t, s.v);

    auto a = db.stream("s")->view("last_hour")->get_data(db.stream("s")->desc, 10700);
    auto b = reloaded.stream("s")->view("last_hour")->get_data(
        reloaded.stream("s")->desc, 10700);
    EXPECT_EQ(a, b);
    // And the mean at the newest bin is unchanged (200 == mean of 100/200/300
    // when all three share the newest bin window).
    EXPECT_NEAR(last_scalar(b), 200.0, 1e-9);
}
