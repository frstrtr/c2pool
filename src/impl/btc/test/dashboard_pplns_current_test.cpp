// SPDX-License-Identifier: AGPL-3.0-or-later
// BTC pool-wide "Current Payouts" read-model KAT — exercised through the REAL
// btc::ShareTracker API and the REAL btc::dashboard::pplns_payouts_current
// (main_btc.cpp §3b feeds this to /current_payouts and the window's
// `pplns_current`).
//
// Regression witness for the empty-"Current Payouts" defect: BTC served an
// 8640-share window with 12 miners but NO `pplns` key, because the web MI's own
// PPLNS cache never fills on a NULL-IMiningNode dashboard. This pins that a
// POPULATED sharechain now yields a NON-EMPTY, address-keyed, value-conserving
// split — and that every honest-empty precondition still returns {}.
//
// FENCED, additive: touches no production code. Joins the EXISTING allowlisted
// `btc_share_test` target (see CMakeLists.txt) so it can never become a #143
// NOT_BUILT sentinel.

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <core/uint256.hpp>
#include <impl/btc/share.hpp>
#include <impl/btc/share_tracker.hpp>
#include <impl/btc/dashboard_pplns.hpp>

namespace {

// A short hex tail -> uint256 (zero-padded to 64 nibbles).
uint256 hx(const std::string& tail) {
    uint256 v;
    v.SetHex(std::string(64 - tail.size(), '0') + tail);
    return v;
}

// Build a resolved btc::ShareTracker of `count` v36 MergedMiningShares (share i's
// parent is i-1; share 0 has a null parent = resolved chain genesis). Each share
// carries a DISTINCT 20-byte P2PKH pubkey hash, so the PPLNS split has `count`
// worker rows plus the donation. m_donation == 0 routes all decayed weight to the
// worker script; the donation output absorbs the (>=1 sat consensus-floored)
// remainder. Returns the tip hash.
uint256 build_chain(btc::ShareTracker& tracker, int count, uint32_t bits) {
    uint256 prev;
    prev.SetNull();
    uint256 tip;
    tip.SetNull();
    for (int i = 0; i < count; ++i) {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "%x", 0x5a1e + i);
        uint256 h = hx(buf);

        auto* s = new btc::MergedMiningShare(h, (i == 0) ? uint256::ZERO : prev);
        s->m_bits       = bits;
        s->m_max_bits   = bits;
        s->m_donation   = 0;
        s->m_pubkey_type = 0;                       // P2PKH
        // Distinct pubkey hash per miner: byte 0 = miner index (all else zero).
        s->m_pubkey_hash.SetNull();
        s->m_pubkey_hash.begin()[0] = static_cast<unsigned char>(0x10 + i);
        s->m_min_header.m_bits = bits;
        s->m_timestamp  = 1700000000u + i;
        s->m_absheight  = i;

        tracker.add(s);
        prev = h;
        tip = h;
    }
    return tip;
}

double sum_values(const nlohmann::json& obj) {
    double total = 0.0;
    for (auto it = obj.begin(); it != obj.end(); ++it)
        total += it.value().get<double>();
    return total;
}

constexpr uint32_t kBits    = 0x1d00ffffu;      // standard difficulty-1 nBits
constexpr uint64_t kSubsidy = 5000000000ull;    // 50 BTC in satoshi

} // namespace

// Populated chain -> a non-empty, address-keyed, value-conserving split.
TEST(BtcDashboardPplnsCurrent, PopulatedChainYieldsNonEmptyAddressKeyedSplit)
{
    btc::ShareTracker tracker;
    const int n_miners = 4;
    uint256 tip = build_chain(tracker, n_miners, kBits);

    nlohmann::json out = btc::dashboard::pplns_payouts_current(
        tracker, tip, /*share_version=*/36, kBits, kSubsidy, /*testnet=*/false);

    ASSERT_TRUE(out.is_object());
    ASSERT_FALSE(out.empty()) << "populated window must not render an empty split";

    // Every key must be a decoded address (never raw hex / empty). Mainnet BTC:
    // worker P2PKH -> '1...', the v36 P2SH donation -> '3...'. Count the workers.
    int worker_rows = 0;
    for (auto it = out.begin(); it != out.end(); ++it) {
        const std::string& addr = it.key();
        ASSERT_FALSE(addr.empty());
        ASSERT_TRUE(addr[0] == '1' || addr[0] == '3')
            << "unexpected non-base58 key: " << addr;
        ASSERT_GT(it.value().get<double>(), 0.0);
        if (addr[0] == '1') ++worker_rows;
    }
    EXPECT_EQ(worker_rows, n_miners) << "each distinct miner must render one payout row";
    EXPECT_GE(static_cast<int>(out.size()), n_miners + 1) << "workers + donation output";

    // Value conservation: the whole subsidy is distributed (donation absorbs the
    // remainder), so the rendered BTC total equals subsidy/1e8 to the satoshi.
    EXPECT_NEAR(sum_values(out), static_cast<double>(kSubsidy) / 1e8, 1e-6);
}

// The window feeder attaches pplns_current + pplns[tip16] from the SAME split.
TEST(BtcDashboardPplnsCurrent, WindowKeysMirrorTheCurrentSplit)
{
    btc::ShareTracker tracker;
    uint256 tip = build_chain(tracker, 3, kBits);

    nlohmann::json cur = btc::dashboard::pplns_payouts_current(
        tracker, tip, 36, kBits, kSubsidy, false);
    ASSERT_TRUE(cur.is_object() && !cur.empty());

    // Reproduce exactly what main_btc.cpp §4 writes into the window JSON.
    nlohmann::json window = nlohmann::json::object();
    window["shares"] = nlohmann::json::array();
    window["shares"].push_back({{"h", tip.GetHex().substr(0, 16)}});
    if (cur.is_object() && !cur.empty()) {
        window["pplns"] = {{ tip.GetHex().substr(0, 16), cur }};
        window["pplns_current"] = cur;
    }

    ASSERT_TRUE(window.contains("pplns_current"));
    ASSERT_TRUE(window.contains("pplns"));
    const std::string tip16 = tip.GetHex().substr(0, 16);
    ASSERT_TRUE(window["pplns"].contains(tip16))
        << "the tip's own window must be keyed by its 16-hex short hash";
    EXPECT_EQ(window["pplns"][tip16], window["pplns_current"]);
    // The keyed split matches the tip row the frontend nearest-newer walk lands on.
    EXPECT_EQ(window["shares"][0]["h"].get<std::string>(), tip16);
}

// Honest-empty guards: every failure precondition returns {} with NO keys.
TEST(BtcDashboardPplnsCurrent, EmptyGuardsReturnEmptyObject)
{
    btc::ShareTracker empty_tracker;

    // Null best share (empty sharechain) -> {}.
    nlohmann::json a = btc::dashboard::pplns_payouts_current(
        empty_tracker, uint256::ZERO, 36, kBits, kSubsidy, false);
    EXPECT_TRUE(a.is_object());
    EXPECT_TRUE(a.empty());

    // A real tip but zero subsidy -> {} (no honest reward to split).
    btc::ShareTracker tracker;
    uint256 tip = build_chain(tracker, 3, kBits);
    nlohmann::json b = btc::dashboard::pplns_payouts_current(
        tracker, tip, 36, kBits, /*subsidy=*/0, false);
    EXPECT_TRUE(b.is_object());
    EXPECT_TRUE(b.empty());

    // A real tip but zero block bits -> {} (no difficulty epoch to anchor to).
    nlohmann::json c = btc::dashboard::pplns_payouts_current(
        tracker, tip, 36, /*block_bits=*/0, kSubsidy, false);
    EXPECT_TRUE(c.is_object());
    EXPECT_TRUE(c.empty());
}
