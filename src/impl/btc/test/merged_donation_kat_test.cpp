// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The donation of the aux-chain coinbase (c2pool/merged/merged_donation.hpp),
// BTC side (NMC under BTC). Folded into the allowlisted btc_share_test target
// (no new executable: #769).
//
//   BtcAuxDonation.NmcSplitRemainderIsTheBuilderLastOutput: the REAL
//     btc::ShareTracker merged split, called as the BTC merged payout
//     provider calls it (main_btc.cpp: get_merged_expected_payouts with the
//     accessor's script, outputs of at least 1 satoshi, sorted), puts the
//     remainder on merged_donation_script(); the NMC coinbase
//     build_pplns_coinbase_hex makes of it pays that script as its
//     always-last output, with a share paid to the old combined P2SH folded
//     in.
//   BtcAuxDonation.ProviderPassesTheAccessor: main_btc.cpp's merged payout
//     provider gives the split the accessor, not the BTC share donation.
//   BtcAuxDonation.ParentShareDonationIsUnchanged: the BTC share donation
//     (PoolConfig::get_donation_script, the parent gentx's) is still the
//     combined P2SH for V36 and the P2PK for V35.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <span>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <btclibs/util/strencodings.h>
#include <c2pool/merged/merged_donation.hpp>
#include <c2pool/merged/merged_mining.hpp>
#include <core/donation.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>
#include <impl/btc/config_pool.hpp>
#include <impl/btc/share.hpp>
#include <impl/btc/share_tracker.hpp>

#ifndef BTC_MAIN_SRC
#error "BTC_MAIN_SRC must point at main_btc.cpp (btc_share_test target_compile_definitions)"
#endif

namespace {

using Script = std::vector<unsigned char>;

constexpr const char* kSingleHex   = "76a91420cb5c22b1e4d5947e5c112c7696b51ad9af3c6188ac";
constexpr const char* kCombinedHex = "a9148c6272621d89e8fa526dd86acff60c7136be8e8587";
constexpr const char* kP2pkHex =
    "4104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b532"
    "56786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac";
constexpr uint32_t kBits = 0x1d00ffffu;
constexpr uint32_t kNmc = 1;

std::string hex(const Script& s) { return HexStr(std::span<const unsigned char>(s.data(), s.size())); }

uint256 hx(const std::string& tail)
{
    uint256 v;
    v.SetHex(std::string(64 - tail.size(), '0') + tail);
    return v;
}

// `count` V36 shares, share i paying P2PKH key 0x10+i with a 1% donation;
// the last one pays the combined P2SH (a "donate"-mode share). Returns the tip.
uint256 build_chain(btc::ShareTracker& tracker, int count)
{
    const Script combined = ParseHex(kCombinedHex);
    uint256 prev, tip;
    prev.SetNull();
    tip.SetNull();
    for (int i = 0; i < count; ++i) {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "%x", 0xd0e0 + i);
        const uint256 h = hx(buf);
        auto* s = new btc::MergedMiningShare(h, i == 0 ? uint256::ZERO : prev);
        s->m_bits = kBits;
        s->m_max_bits = kBits;
        s->m_min_header.m_bits = kBits;
        s->m_donation = 655;
        s->m_desired_version = 36;   // the merged walk counts V36-voting shares only
        s->m_pubkey_hash.SetNull();
        if (i + 1 == count) {
            s->m_pubkey_type = 2;   // P2SH
            std::memcpy(s->m_pubkey_hash.begin(), combined.data() + 2, 20);
        } else {
            s->m_pubkey_type = 0;   // P2PKH
            s->m_pubkey_hash.begin()[0] = static_cast<unsigned char>(0x10 + i);
        }
        s->m_timestamp = 1700000000u + i;
        s->m_absheight = i;
        tracker.add(s);
        prev = h;
        tip = h;
    }
    return tip;
}

struct Out {
    Script script;
    uint64_t value;
};

std::vector<Out> outputs_of(const std::string& tx_hex)
{
    const auto b = ParseHex(tx_hex);
    size_t p = 4;   // version
    auto varint = [&]() -> uint64_t {
        const uint8_t f = b.at(p++);
        if (f < 0xfd) return f;
        const size_t n = f == 0xfd ? 2 : f == 0xfe ? 4 : 8;
        uint64_t v = 0;
        for (size_t i = 0; i < n; ++i) v |= static_cast<uint64_t>(b.at(p++)) << (8 * i);
        return v;
    };
    const uint64_t nin = varint();
    for (uint64_t i = 0; i < nin; ++i) {
        p += 36;
        const uint64_t sig = varint();
        p += sig + 4;
    }
    std::vector<Out> outs;
    const uint64_t nout = varint();
    for (uint64_t i = 0; i < nout; ++i) {
        uint64_t v = 0;
        for (int k = 0; k < 8; ++k) v |= static_cast<uint64_t>(b.at(p++)) << (8 * k);
        const uint64_t n = varint();
        outs.push_back({Script(b.begin() + p, b.begin() + p + n), v});
        p += n;
    }
    EXPECT_EQ(p + 4, b.size()) << "locktime ends the transaction";
    return outs;
}

std::string read_file(const std::string& path)
{
    std::ifstream f(path);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

} // namespace

TEST(BtcAuxDonation, NmcSplitRemainderIsTheBuilderLastOutput)
{
    btc::ShareTracker tracker;
    const uint256 tip = build_chain(tracker, 5);
    const auto& don = c2pool::merged::merged_donation_script();
    const Script combined = ParseHex(kCombinedHex);
    const uint64_t value = 50'0000'0000ULL + 12345;

    // As the provider: the split with the accessor, outputs >= 1, sorted.
    const auto map = tracker.get_merged_expected_payouts(tip, chain::bits_to_target(kBits), value, kNmc,
                                                         don, {}, {});
    ASSERT_TRUE(map.contains(don)) << "the remainder goes to the accessor's script";
    ASSERT_TRUE(map.contains(combined)) << "the donate-mode share is paid to its P2SH";
    std::vector<std::pair<Script, uint64_t>> payouts;
    uint64_t split_total = 0;
    for (const auto& [script, amount] : map) {
        split_total += amount;
        if (amount >= 1) payouts.emplace_back(script, amount);
    }
    std::sort(payouts.begin(), payouts.end());
    EXPECT_EQ(split_total, value);
    EXPECT_GE(map.at(don), 1u);

    const auto outs = outputs_of(
        c2pool::merged::MergedMiningManager::build_pplns_coinbase_hex(700'000, payouts, uint256()));
    // Four P2PKH miners, OP_RETURN, donation.
    ASSERT_EQ(outs.size(), 6u);
    for (size_t i = 0; i < 4; ++i) {
        ASSERT_EQ(outs[i].script.size(), 25u);
        EXPECT_EQ(static_cast<unsigned>(outs[i].script[3]), static_cast<unsigned>(0x10 + i));
        EXPECT_EQ(outs[i].value, map.at(outs[i].script));
    }
    EXPECT_EQ(outs[4].script.at(0), 0x6a);
    // The provider's script == the accessor == the builder's last output.
    EXPECT_EQ(hex(outs.back().script), kSingleHex);
    EXPECT_EQ(outs.back().script, don);
    EXPECT_EQ(outs.back().value, map.at(don) + map.at(combined));
    uint64_t total = 0;
    for (const auto& o : outs) {
        total += o.value;
        EXPECT_NE(o.script, combined);
    }
    EXPECT_EQ(total, value);
}

TEST(BtcAuxDonation, ProviderPassesTheAccessor)
{
    const std::string src = read_file(BTC_MAIN_SRC);
    ASSERT_FALSE(src.empty()) << "main_btc.cpp not found";
    const auto begin = src.find("Merged-mining (NMC AuxPoW) payout provider");
    const auto end = src.find("mm_manager->set_on_work_changed(", begin);
    ASSERT_NE(begin, std::string::npos);
    ASSERT_NE(end, std::string::npos);
    const std::string region = src.substr(begin, end - begin);
    EXPECT_NE(region.find("const auto& donation_script = c2pool::merged::merged_donation_script();"),
              std::string::npos);
    EXPECT_NE(region.find("get_merged_expected_payouts("), std::string::npos);
    EXPECT_EQ(region.find("get_donation_script("), std::string::npos)
        << "the BTC share donation never reaches the aux split";
    EXPECT_EQ(region.find("COMBINED_DONATION_SCRIPT"), std::string::npos);
}

TEST(BtcAuxDonation, ParentShareDonationIsUnchanged)
{
    EXPECT_EQ(hex(btc::PoolConfig::get_donation_script(36)), kCombinedHex);
    EXPECT_EQ(hex(btc::PoolConfig::get_donation_script(35)), kP2pkHex);
    EXPECT_EQ(hex(btc::PoolConfig::get_donation_script(36)),
              hex(Script(core::donation::COMBINED_DONATION_SCRIPT.begin(),
                         core::donation::COMBINED_DONATION_SCRIPT.end())));
    EXPECT_NE(btc::PoolConfig::get_donation_script(36), c2pool::merged::merged_donation_script());
}
