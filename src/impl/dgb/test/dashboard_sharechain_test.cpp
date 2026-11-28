// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The DGB dashboard documents built with core::sharechain_views (rides
// dgb_work_source_test): the addresses are DGB's (D... / S... / dgb1...,
// the P2PK donation as DQ8A...), never the bitcoin rendering the core views
// use, and main_dgb wires the four hooks DASHBOARD-GAPS-DGB.md listed.
// ---------------------------------------------------------------------------

#include <impl/dgb/dashboard_sharechain.hpp>
#include <impl/dgb/share.hpp>
#include <impl/dgb/share_tracker.hpp>

#include <btclibs/util/strencodings.h>
#include <core/uint256.hpp>

#include <gtest/gtest.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#ifndef DGB_MAIN_SRC
#error "DGB_MAIN_SRC must name src/c2pool/main_dgb.cpp"
#endif

namespace {

using Bytes = std::vector<unsigned char>;

const std::string kD = "DB68diZto76gixVajwyoMjcEXsSdyEhnS9";
const std::string kLower = "dgb1q24242424242424242424242424242424swqgq4";

uint256 add_share(dgb::ShareTracker& t, int n, const uint256& prev, const std::string& addr)
{
    auto* s = new dgb::PaddingBugfixShare();
    uint256 h;
    h.SetHex(std::to_string(8200000 + n));
    s->m_hash = h;
    s->m_prev_hash = prev;
    s->m_bits = 0x1e0fffff;
    s->m_max_bits = 0x1e0fffff;
    s->m_timestamp = 1790000000u + 15u * static_cast<uint32_t>(n);
    s->m_absheight = static_cast<uint32_t>(n);
    s->m_desired_version = 35;
    s->m_address.m_data.assign(addr.begin(), addr.end());
    dgb::ShareType st;
    st = s;
    t.add(st);
    return h;
}

} // namespace

TEST(DgbDashboardViews, AddressesAreDgbs)
{
    EXPECT_EQ(dgb::dashboard::dgb_address_of(ParseHex("76a914414141414141414141414141414141414141414188ac")), kD);
    EXPECT_EQ(dgb::dashboard::dgb_address_of(ParseHex("00145555555555555555555555555555555555555555")), kLower);
    const auto& ds = dgb::PoolConfig::DONATION_SCRIPT;
    EXPECT_EQ(dgb::dashboard::dgb_address_of(Bytes(ds.begin(), ds.end())), "DQ8AwqR2XJE9G5dSEfspJYH7Spre85dj6L");
    EXPECT_EQ(dgb::dashboard::dgb_address_of(Bytes{0x6a, 0x01}), "6a01") << "an undecodable script is raw hex";
    const std::string s = dgb::dashboard::dgb_address_of(ParseHex("a914414141414141414141414141414141414141414187"));
    EXPECT_EQ(s.front(), 'S') << s;
}

TEST(DgbDashboardViews, TheDeltaAndTheSharePageCarryDgbAddresses)
{
    dgb::ShareTracker t;
    uint256 prev;
    std::vector<uint256> hs;
    for (int i = 0; i < 3; ++i) {
        prev = add_share(t, i, prev, i == 1 ? kLower : kD);
        hs.push_back(prev);
    }
    const auto snap = dgb::dashboard::delta_snapshot(t, "");
    ASSERT_EQ(snap.rows.size(), 3u);
    const auto doc = dgb::dashboard::delta_json(snap, "", {});
    ASSERT_EQ(doc["shares"].size(), 3u);
    for (size_t i = 0; i < 3; ++i) {
        const std::string want = snap.rows[i].hash == hs[1] ? kLower : kD;
        EXPECT_EQ(doc["shares"][i]["m"], want) << i;
    }
    // The cursor: only the shares newer than it.
    const auto since = dgb::dashboard::delta_snapshot(t, hs[1].GetHex());
    EXPECT_EQ(since.rows.size(), 1u);

    const auto detail = dgb::dashboard::share_detail(t, hs[1].GetHex());
    ASSERT_FALSE(detail.contains("error")) << detail.dump();
    EXPECT_EQ(detail["share_data"]["payout_address"], kLower);
    EXPECT_EQ(dgb::dashboard::share_detail(t, std::string(64, 'e'))["error"], "share not found");
    // Nothing to split at an unknown best or without a template.
    EXPECT_TRUE(dgb::dashboard::current_payouts(t, uint256(), 0x1b0404cb, 1000).empty());
    EXPECT_TRUE(dgb::dashboard::current_payouts(t, hs[2], 0, 1000).empty());
}

TEST(DgbDashboardViews, MainDgbWiresTheFourHooks)
{
    std::ifstream f(DGB_MAIN_SRC);
    ASSERT_TRUE(f.good());
    std::stringstream ss;
    ss << f.rdbuf();
    const std::string s = ss.str();
    for (const char* line : {"mi->set_sharechain_delta_fn(", "dgb::dashboard::delta_json(snap, fee_hash160, found);",
                             "mi->set_share_lookup_fn(", "dgb::dashboard::share_detail(*guard, hash_hex);",
                             "mi->set_current_payouts_fn(",
                             "dgb::dashboard::current_payouts(*guard, best, t->bits, t->coinbase_value);",
                             "mi->set_stratum_workers_fn([ws = work_source.get()]() { return ws->snapshot_stratum_workers(); });"})
        EXPECT_NE(s.find(line), std::string::npos) << line;
}
