// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

#include <nlohmann/json.hpp>

#include <core/web_server.hpp>
#include <core/address_validator.hpp>

// ---------------------------------------------------------------------------
// KATs for core::MiningInterface::rest_current_payouts — the /current_payouts
// JSON endpoint. Regression lock for #939: on a live DASH node with a full
// share window and real balances the endpoint returned {}. Root cause: DASH
// has no coinbase-builder PPLNS cache feeding this endpoint and wires no
// PayoutManager (unlike LTC's set_payout_manager), so BOTH web-layer sources
// are empty and the endpoint faithfully reports {} — the data is absent at the
// boundary. Fix: a direct-source injection seam (set_current_payouts_fn) so a
// coin whose payout set lives outside the web coinbase builder can feed it.
//
// A dashboard must not report "no payouts" when a source exists; equally it
// must not fabricate one when none does. These KATs lock both directions.
// ---------------------------------------------------------------------------

// The injected direct source is authoritative when present and non-empty.
// FAILS WITHOUT THE SEAM (endpoint has no way to see the DASH payout set -> {}).
TEST(CurrentPayoutsSeam, DirectSourceIsAuthoritative) {
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::DASH);

    nlohmann::json feed = {
        {"XmR5w1yQ8oExampleDashAddr0000000000", 1.25},
        {"XpQ7z2aB9nExampleDashAddr1111111111", 0.50},
    };
    mi.set_current_payouts_fn([feed]() { return feed; });

    auto r = mi.rest_current_payouts();
    ASSERT_TRUE(r.is_object());
    EXPECT_EQ(r, feed) << "direct current-payouts source was not surfaced";
}

// An empty/absent feed must NOT mask the ordinary path — with no cache and no
// PayoutManager data the endpoint honestly returns {} rather than a stale or
// fabricated set. Guards against the seam swallowing the fallthrough.
TEST(CurrentPayoutsSeam, EmptyFeedFallsThroughToHonestEmpty) {
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::DASH);

    mi.set_current_payouts_fn([]() { return nlohmann::json::object(); });  // absent

    auto r = mi.rest_current_payouts();
    ASSERT_TRUE(r.is_object());
    EXPECT_TRUE(r.empty()) << "empty feed must fall through to honest {}";
}

// With no seam wired at all, behaviour is unchanged: honest {} when no source.
TEST(CurrentPayoutsSeam, NoSeamUnchangedHonestEmpty) {
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::DASH);
    auto r = mi.rest_current_payouts();
    ASSERT_TRUE(r.is_object());
    EXPECT_TRUE(r.empty());
}

// ---------------------------------------------------------------------------
// /current_merged_payouts cold-cache fallback. The "Current Payouts" card
// (loadPayouts) fetches /current_merged_payouts, NOT /current_payouts. On lanes
// that never run the per-tip cache pump (bip110: MI stratum off, no
// fire_share_tip_refresh), m_cached_merged_payouts stays {} even though the
// /current_payouts seam is populated — so the card stayed EMPTY. rest_current_
// merged_payouts now falls back to the primary seam wrapped in the merged shape.
// ---------------------------------------------------------------------------

// Cold merged cache but a live /current_payouts seam -> merged reflects the
// primary payouts as {addr:{amount,merged:[]}}. FAILS WITHOUT THE FALLBACK ({}).
TEST(CurrentMergedPayoutsColdCache, ReflectsPrimarySeam) {
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::DASH);

    nlohmann::json feed = {
        {"XmR5w1yQ8oExampleDashAddr0000000000", 1.25},
        {"XpQ7z2aB9nExampleDashAddr1111111111", 0.50},
    };
    mi.set_current_payouts_fn([feed]() { return feed; });

    auto merged = mi.rest_current_merged_payouts();
    ASSERT_TRUE(merged.is_object());
    ASSERT_FALSE(merged.empty()) << "cold merged cache must fall back to the primary seam";
    ASSERT_EQ(merged.size(), feed.size());
    for (auto it = feed.begin(); it != feed.end(); ++it) {
        ASSERT_TRUE(merged.contains(it.key()));
        EXPECT_DOUBLE_EQ(merged[it.key()]["amount"].get<double>(), it.value().get<double>());
        ASSERT_TRUE(merged[it.key()]["merged"].is_array());
        EXPECT_TRUE(merged[it.key()]["merged"].empty());
    }
}

// No primary seam either -> honest {} (fallback never fabricates).
TEST(CurrentMergedPayoutsColdCache, HonestEmptyWithoutSource) {
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::DASH);
    auto merged = mi.rest_current_merged_payouts();
    ASSERT_TRUE(merged.is_object());
    EXPECT_TRUE(merged.empty());
}

// The donation output is emitted even at --give-author 0 as a 1-duff dust
// marker, so /current_payouts lists the donation address at 1e-8. The merged
// view behind the "Current Payouts" card must keep it too; only an exact-zero
// entry with no merged payouts is dropped.
TEST(CurrentMergedPayoutsCompute, KeepsDustDonationMarker) {
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::DASH);

    nlohmann::json feed = {
        {"XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u", 1e-08},   // dust marker
        {"XmR5w1yQ8oExampleDashAddr0000000000", 0.41},
        {"XpQ7z2aB9nExampleDashAddr1111111111", 0.0},    // zero: dropped
    };
    mi.set_current_payouts_fn([feed]() { return feed; });

    auto merged = mi.compute_current_merged_payouts();
    ASSERT_TRUE(merged.is_object());
    ASSERT_TRUE(merged.contains("XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u"))
        << "the 1e-8 donation marker must reach the Current Payouts card";
    EXPECT_DOUBLE_EQ(merged["XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u"]["amount"].get<double>(), 1e-08);
    EXPECT_TRUE(merged.contains("XmR5w1yQ8oExampleDashAddr0000000000"));
    EXPECT_FALSE(merged.contains("XpQ7z2aB9nExampleDashAddr1111111111"));
}

// ---------------------------------------------------------------------------
// "Predicted Payout History" (miner page) is the stat log's current_payouts
// series ("cps"). The sampler (update_stat_log) read only the coinbase-builder
// PPLNS cache, which the coins wiring set_current_payouts_fn (DASH, BTC,
// BIP-110) never fill, so their series stayed {} on every tick while
// /current_payouts showed live balances. The sampler now takes the same direct
// source when the cache gives nothing.
// ---------------------------------------------------------------------------
namespace {

struct PayoutHistDir {
    std::filesystem::path dir;
    explicit PayoutHistDir(const char* name) {
        dir = std::filesystem::temp_directory_path() / name;
        std::filesystem::remove_all(dir);
        std::filesystem::create_directories(dir);
    }
    ~PayoutHistDir() { std::filesystem::remove_all(dir); }
    std::string path(const char* leaf) const { return (dir / leaf).string(); }
};

nlohmann::json read_payout_hist_log(const std::string& path) {
    std::ifstream f(path);
    EXPECT_TRUE(static_cast<bool>(f)) << "stat-log file must exist: " << path;
    std::string content((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
    auto arr = nlohmann::json::parse(content);
    EXPECT_TRUE(arr.is_array());
    return arr;
}

} // namespace

// FAILS WITHOUT THE FIX: "cps" is {} although the direct source has payouts.
TEST(CurrentPayoutsHistory, SamplerRecordsTheDirectSource) {
    PayoutHistDir tmp("core_payout_history_direct_kat");
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::DASH);
    mi.set_stat_log_path(tmp.path("graph_db"));

    const nlohmann::json feed = {
        {"XmR5w1yQ8oExampleDashAddr0000000000", 0.37003781},
        {"XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u", 0.04097709},
    };
    mi.set_current_payouts_fn([feed]() { return feed; });

    mi.update_stat_log();
    mi.save_stat_log();

    auto arr = read_payout_hist_log(tmp.path("graph_db"));
    ASSERT_EQ(arr.size(), static_cast<std::size_t>(1));
    ASSERT_TRUE(arr[0].contains("cps"));
    EXPECT_EQ(arr[0]["cps"], feed)
        << "the payout-history sample must carry the same split /current_payouts serves";

    // What the miner page's chart fetches.
    auto series = mi.rest_web_graph_data("current_payouts", "last_hour");
    bool seen = false;
    for (const auto& p : series)
        if (p.is_array() && p.size() > 1 && p[1].is_object()
            && p[1].contains("XmR5w1yQ8oExampleDashAddr0000000000"))
            seen = true;
    EXPECT_TRUE(seen) << "/web/graph_data/current_payouts must show the miner's predicted payout";
}

// The cache path (LTC) is unchanged: when the coinbase-builder cache has the
// split, the direct source is not sampled too (no doubled or mixed series).
TEST(CurrentPayoutsHistory, CachePathIsNotMixedWithTheDirectSource) {
    PayoutHistDir tmp("core_payout_history_cache_kat");
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::LITECOIN);
    mi.set_stat_log_path(tmp.path("graph_db"));

    // One P2PKH output of 1.5 coins in the cache.
    mi.set_cached_pplns_outputs({{"76a914" + std::string(40, '1') + "88ac", 150000000ULL}});
    int direct_calls = 0;
    mi.set_current_payouts_fn([&direct_calls]() {
        ++direct_calls;
        return nlohmann::json{{"LdirectSourceMustNotAppear000000000", 9.0}};
    });

    mi.update_stat_log();
    mi.save_stat_log();

    auto arr = read_payout_hist_log(tmp.path("graph_db"));
    ASSERT_EQ(arr.size(), static_cast<std::size_t>(1));
    ASSERT_TRUE(arr[0].contains("cps"));
    const auto& cps = arr[0]["cps"];
    ASSERT_EQ(cps.size(), static_cast<std::size_t>(1)) << cps.dump();
    EXPECT_FALSE(cps.contains("LdirectSourceMustNotAppear000000000"));
    EXPECT_DOUBLE_EQ(cps.begin().value().get<double>(), 1.5);
    EXPECT_EQ(direct_calls, 0) << "with the cache populated the direct source is not consulted";
}

// No source at all: the sample stays honestly empty (no fabricated payouts).
TEST(CurrentPayoutsHistory, NoSourceRecordsNothing) {
    PayoutHistDir tmp("core_payout_history_none_kat");
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::DASH);
    mi.set_stat_log_path(tmp.path("graph_db"));
    mi.set_current_payouts_fn([]() { return nlohmann::json::object(); });

    mi.update_stat_log();
    mi.save_stat_log();

    auto arr = read_payout_hist_log(tmp.path("graph_db"));
    ASSERT_EQ(arr.size(), static_cast<std::size_t>(1));
    ASSERT_TRUE(arr[0].contains("cps"));
    EXPECT_TRUE(arr[0]["cps"].empty());
}
