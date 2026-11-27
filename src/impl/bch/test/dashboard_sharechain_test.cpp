// SPDX-License-Identifier: AGPL-3.0-or-later
// BCH sharechain dashboard views, over a real bch::ShareTracker and the
// bch::dashboard functions bch::standup_pool_run serves:
//   /web/share/<hash>   share_detail: the share.html document for a known
//                       share, {"error":"share not found"} for an unknown one
//   /sharechain/window  window_json(window_snapshot): rows carry V (share
//                       version), s, dv and the payout address
//   /sharechain/delta   delta_json(delta_snapshot): the shares after a cursor
//   /sharechain/tip     tip_of
//   sharechain stats    chain_stats: the keys /global_stats, /version_signaling
//                       and /web/sync_status read
//
// Built into bch_dashboard_pplns_current_test (that test's main runs these
// checks), in the BCH tree's plain-main CHECK form.

#include <cstdint>
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

#include <core/uint256.hpp>
#include <impl/bch/share.hpp>
#include <impl/bch/share_tracker.hpp>
#include <impl/bch/dashboard_sharechain.hpp>

namespace {

namespace views = core::sharechain_views;

int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ dashboard_sharechain_test.cpp:" << __LINE__ << "\n"; ++failures; } } while (0)

// A hash whose display hex starts with `head` (zero-padded on the right), so
// test shares have distinct 16-hex short hashes, the delta cursor's key.
uint256 hx(const std::string& head) {
    uint256 v;
    v.SetHex(head + std::string(64 - head.size(), '0'));
    return v;
}

constexpr uint32_t kBits    = 0x1d00ffffu;
constexpr uint64_t kSubsidy = 312500000ull;

std::vector<uint256> build_v36_chain(bch::ShareTracker& tracker, int count) {
    std::vector<uint256> hashes;
    uint256 prev;
    for (int i = 0; i < count; ++i) {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "bc4%x", 0x100 + i);
        const uint256 h = hx(buf);
        auto* s = new bch::MergedMiningShare(h, i == 0 ? uint256::ZERO : prev);
        s->m_bits            = kBits;
        s->m_max_bits        = kBits;
        s->m_donation        = 655;
        s->m_desired_version = 36;
        s->m_stale_info      = bch::StaleInfo::none;
        s->m_pubkey_type     = 0;
        s->m_pubkey_hash.SetNull();
        s->m_pubkey_hash.begin()[0] = static_cast<unsigned char>(0x30 + i);
        s->m_min_header.m_version   = 0x20000000;
        s->m_min_header.m_bits      = 0x18034219u;
        s->m_min_header.m_timestamp = 1790000000u + i;
        s->m_min_header.m_nonce     = 55u + i;
        s->m_timestamp  = 1790000000u + i;
        s->m_absheight  = 300 + i;
        s->m_nonce      = 7000u + i;
        s->m_subsidy    = kSubsidy;
        s->m_last_txout_nonce = 0x1122334455667788ull;
        const std::string tag = "/c2pool-bch-test/";
        s->m_coinbase.m_data = {0x03, 0x01, 0x02, 0x03};
        s->m_coinbase.m_data.insert(s->m_coinbase.m_data.end(), tag.begin(), tag.end());
        s->m_far_share_hash = (i >= 2) ? hashes[i - 2] : uint256::ZERO;
        tracker.add(s);
        hashes.push_back(h);
        prev = h;
    }
    return hashes;
}

uint256 add_v35_share(bch::ShareTracker& tracker, const uint256& prev) {
    const uint256 h = hx("bc4fff");
    auto* s = new bch::PaddingBugfixShare(h, prev);
    s->m_bits            = kBits;
    s->m_max_bits        = kBits;
    s->m_desired_version = 36;
    s->m_stale_info      = bch::StaleInfo::doa;
    s->m_donation        = 0;
    s->m_nonce           = 1;
    s->m_last_txout_nonce = 0;
    s->m_min_header.m_version   = 0x20000000;
    s->m_min_header.m_bits      = kBits;
    s->m_min_header.m_timestamp = 1790001000u;
    s->m_min_header.m_nonce     = 2;
    const std::string addr = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT";
    s->m_address.m_data.assign(addr.begin(), addr.end());
    s->m_timestamp = 1790001000u;
    s->m_absheight = 900;
    s->m_subsidy   = kSubsidy;
    tracker.add(s);
    return h;
}

void share_detail_checks()
{
    bch::ShareTracker tracker;
    const auto hashes = build_v36_chain(tracker, 4);
    const uint256 mid = hashes[2];

    const nlohmann::json d = bch::dashboard::share_detail(tracker, mid.GetHex(), false);
    CHECK(!d.contains("error"));
    CHECK(d.value("hash", "") == mid.GetHex());
    CHECK(d.value("parent", "") == hashes[1].GetHex());
    CHECK(d.value("far_parent", "") == hashes[0].GetHex());
    CHECK(d.value("type_name", "") == "V36");
    CHECK(d.value("version", 0) == 36);
    CHECK(d.value("is_block_solution", true) == false);
    CHECK(d["children"].is_array() && d["children"].size() == 1
          && d["children"][0] == hashes[3].GetHex());
    CHECK(d["local"].is_object() && d["local"].contains("verified")
          && d["local"].contains("time_first_seen")
          && d["local"].contains("peer_first_received_from"));

    const auto& sd = d["share_data"];
    CHECK(sd.is_object());
    CHECK(sd.value("timestamp", 0u) == 1790000002u);
    CHECK(sd.value("target", 0u) == kBits);
    CHECK(sd.value("max_target", 0u) == kBits);
    CHECK(sd.value("nonce", 0u) == 7002u);
    CHECK(sd.value("desired_version", 0) == 36);
    CHECK(sd.value("absheight", 0) == 302);
    CHECK(sd.value("stale_info", -1) == 0);
    CHECK(sd.contains("abswork") && sd.contains("difficulty") && sd.contains("min_difficulty"));
    const std::string payout = sd.value("payout_address", "");
    CHECK(!payout.empty() && payout[0] == '1');

    const auto& block = d["block"];
    CHECK(block.value("hash", "") == mid.GetHex());
    CHECK(block["header"].value("nonce", 0u) == 57u);
    CHECK(block["header"].value("target", 0u) == 0x18034219u);
    CHECK(block["header"]["merkle_root"].is_null());
    CHECK(block["gentx"]["hash"].is_null());
    CHECK(block["gentx"].value("coinbase", "").find("2f6332706f6f6c") != std::string::npos);
    CHECK(d.contains("v36_metadata"));

    // Unknown hashes: the not-found error rest_web_share keeps.
    CHECK(bch::dashboard::share_detail(tracker, hx("dead").GetHex(), false)
          == (nlohmann::json{{"error", "share not found"}}));
    CHECK(bch::dashboard::share_detail(tracker, std::string(64, '0'), false)
          == (nlohmann::json{{"error", "share not found"}}));
}

void window_checks()
{
    bch::ShareTracker tracker;
    const auto hashes = build_v36_chain(tracker, 5);
    const uint256 v35 = add_v35_share(tracker, hashes.back());

    const auto snap = bch::dashboard::window_snapshot(tracker);
    const std::vector<std::string> found = {hashes[2].GetHex()};
    const nlohmann::json w = views::window_json(snap, bch::PoolConfig::chain_length(),
                                                "", "", found, false);
    CHECK(w.value("best_hash", "") == v35.GetHex());
    CHECK(w["shares"].is_array() && w["shares"].size() == 6);
    for (const auto& s : w["shares"]) {
        CHECK(s.contains("V"));
        CHECK(s.contains("s") && s.contains("dv") && s.contains("H") && s.contains("h"));
        const std::string m = s.value("m", "");
        CHECK(!m.empty() && m[0] == '1');
    }
    CHECK(w["shares"][0].value("V", 0) == 35);
    CHECK(w["shares"][0].value("s", 0) == 254);
    CHECK(w["shares"][0].value("m", "") == "1BoatSLRHtKNngkdXEeobR76b53LETtpyT");
    CHECK(w["shares"][1].value("V", 0) == 36);
    CHECK(w["shares"][1].value("cb", "") == "/c2pool-bch-test/");
    CHECK(w["heads"].size() == 1 && w["heads"][0] == v35.GetHex().substr(0, 16));
    CHECK(w["block_hashes"].size() == 1 && w["block_hashes"][0] == hashes[2].GetHex());

    const auto dsnap = bch::dashboard::delta_snapshot(tracker, hashes[3].GetHex().substr(0, 16));
    const nlohmann::json delta = views::delta_json(dsnap, "", found, false);
    CHECK(delta.value("count", 0) == 2);
    CHECK(delta["shares"].size() == 2 && delta["shares"][0].value("H", "") == v35.GetHex());
    CHECK(delta.value("tip", "") == v35.GetHex().substr(0, 16));
    CHECK(!delta.contains("block_hashes"));

    const auto tip = views::tip_of(tracker);
    CHECK(tip.has_value() && tip->hash == v35.GetHex().substr(0, 16) && tip->total == 6);
    bch::ShareTracker empty;
    CHECK(!views::tip_of(empty).has_value());
}

void stats_checks()
{
    bch::ShareTracker tracker;
    const auto hashes = build_v36_chain(tracker, 5);
    add_v35_share(tracker, hashes.back());
    const nlohmann::json st = bch::dashboard::chain_stats(tracker);
    CHECK(st.value("chain_height", 0) == 6);
    CHECK(st.value("total_shares", 0) == 6);
    CHECK(st.value("dead_shares", -1) == 1);
    CHECK(st.value("orphan_shares", -1) == 0);
    CHECK(st["shares_by_version"].value("36", 0) == 5);
    CHECK(st["shares_by_version"].value("35", 0) == 1);
    CHECK(st["shares_by_desired_version"].value("36", 0) == 6);
    CHECK(st["shares_by_miner"].size() == 6);
    CHECK(st.value("chain_length", 0) == static_cast<int>(bch::PoolConfig::chain_length()));
    CHECK(st["heads"].size() == 1 && st["tails"].size() == 1);

    bch::ShareTracker empty;
    const nlohmann::json e = bch::dashboard::chain_stats(empty);
    CHECK(e.value("chain_height", -1) == 0 && e.value("total_shares", -1) == 0);
}

} // namespace

int run_dashboard_sharechain_checks()
{
    share_detail_checks();
    window_checks();
    stats_checks();
    if (failures == 0)
        std::cout << "bch dashboard sharechain views: ALL PASS\n";
    else
        std::cerr << "bch dashboard sharechain views: " << failures << " FAILURE(S)\n";
    return failures;
}
