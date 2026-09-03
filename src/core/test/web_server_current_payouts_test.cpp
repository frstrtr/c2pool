// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

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
