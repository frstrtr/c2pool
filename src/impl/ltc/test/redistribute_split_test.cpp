// SPDX-License-Identifier: AGPL-3.0-or-later
//
// --redistribute split: a share minted for work the node cannot attribute to a
// payout address pays the node owner, with donation core::kSplitShareDonation
// (32768 of 65535) in place of --give-author's. PPLNS splits every share's
// weight by its own donation field: (65535 - donation)/65535 to the share's
// address and donation/65535 to the donation script. So such a share gives the
// owner and the donation half of its weight each:
//   - on the parent chain (V36 decayed weights, share_tracker.hpp
//     get_v36_decayed_cumulative_weights; amounts as generate_share_transaction:
//     subsidy * weight / total, the donation the remainder);
//   - on a merged chain (flat merged weights, merged_weights_delta: the share's
//     explicit merged address, Tier 1; amounts merged_payouts_from_weights);
// for a V36 and for a 3601 share. A miner's share beside it keeps its own
// donation. No consensus change: the donation is the share's own uint16 field.

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <core/author_fee.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>
#include <impl/ltc/share.hpp>
#include <impl/ltc/share_check.hpp>
#include <impl/ltc/share_tracker.hpp>

namespace {

constexpr uint32_t kBits = 0x1e0fffff;
constexpr uint32_t kTs = 1800000000;
constexpr uint32_t kDoge = 98;
constexpr uint16_t kNodeDonation = 66;   // --give-author 0.1%

uint256 hx(uint64_t n)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llx", static_cast<unsigned long long>(n));
    const std::string t(buf);
    uint256 v;
    v.SetHex(std::string(64 - t.size(), '0') + t);
    return v;
}

uint160 key(unsigned char b)
{
    uint160 h;
    for (int i = 0; i < 20; ++i)
        h.data()[i] = b;
    return h;
}

std::vector<unsigned char> p2pkh(unsigned char b)
{
    std::vector<unsigned char> s{0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, b);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

template <class S>
uint256 add(ltc::ShareTracker& tr, uint64_t id, const uint256& prev, const uint160& pkh, uint16_t donation,
            const std::vector<unsigned char>& doge_script)
{
    auto* sh = new S();
    sh->m_hash = hx(id);
    sh->m_prev_hash = prev;
    sh->m_desired_version = 36;
    sh->m_bits = kBits;
    sh->m_max_bits = kBits;
    sh->m_timestamp = kTs + static_cast<uint32_t>(id);
    sh->m_donation = donation;
    sh->m_pubkey_hash = pkh;
    sh->m_pubkey_type = 0;
    ltc::MergedAddressEntry e;
    e.m_chain_id = kDoge;
    e.m_script.m_data = doge_script;
    sh->m_merged_addresses.push_back(e);
    sh->m_hash_link.m_state.m_data.assign(32, 0x4c);
    sh->m_hash_link.m_length = 64;
    const uint256 h = sh->m_hash;
    ltc::ShareType st;
    st = sh;
    tr.add(st);
    return h;
}

uint288 unlimited()
{
    uint288 u;
    u.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    return u;
}

// generate_share_transaction's V36 amounts: subsidy * weight / total for the
// share's address, the remainder to the donation.
std::pair<uint64_t, uint64_t> parent_amounts(const uint288& weight, const uint288& total, uint64_t subsidy)
{
    const uint64_t addr = (uint288(subsidy) * weight / total).GetLow64();
    return {addr, subsidy - addr};
}

template <class S>
void split_share_pays_owner_and_donation_half_and_half(const char* what)
{
    SCOPED_TRACE(what);
    const uint160 owner = key(0x0a), miner = key(0x22);
    const auto owner_script = ltc::pubkey_hash_to_script(owner, 0);
    const auto miner_script = ltc::pubkey_hash_to_script(miner, 0);
    ASSERT_EQ(owner_script, p2pkh(0x0a));
    const auto owner_doge = p2pkh(0x0c), miner_doge = p2pkh(0x21);
    const std::vector<unsigned char> doge_donation{0xa9, 0x14, 1, 2, 3};
    const uint288 att = chain::target_to_average_attempts(chain::bits_to_target(kBits));
    const uint64_t subsidy = 625000000;            // the parent's coinbase value
    const uint64_t doge_subsidy = 1000000000000;   // the DOGE coinbase value

    // The split share alone: half and half (32767 / 32768 of 65535).
    {
        ltc::ShareTracker tr;
        const uint256 s = add<S>(tr, 1, uint256(), owner, core::kSplitShareDonation, owner_doge);
        const auto w = tr.get_v36_decayed_cumulative_weights(s, 1, unlimited());
        EXPECT_EQ(w.total_weight, att * 65535u);
        ASSERT_EQ(w.weights.size(), 1u);
        EXPECT_EQ(w.weights.at(owner_script), att * 32767u);
        EXPECT_EQ(w.total_donation_weight, att * 32768u);
        // owner = floor(subsidy * 32767 / 65535), the donation the rest: they
        // differ by subsidy/65535 (the odd denominator) plus the floor's
        // remainder, at most 2 satoshi more.
        const auto [owner_amt, don_amt] = parent_amounts(w.weights.at(owner_script), w.total_weight, subsidy);
        EXPECT_EQ(owner_amt, subsidy * 32767 / 65535);
        EXPECT_EQ(owner_amt, 312495231u);
        EXPECT_EQ(don_amt, 312504769u);
        EXPECT_EQ(owner_amt + don_amt, subsidy);
        EXPECT_GE(don_amt, owner_amt);
        EXPECT_LE(don_amt - owner_amt, subsidy / 65535 + 2) << owner_amt << " / " << don_amt;

        const auto mw = tr.get_merged_payout_weights(s, kDoge);
        EXPECT_EQ(mw.total_weight, att * 65535u);
        EXPECT_EQ(mw.donation_weight, att * 32768u);
        ASSERT_EQ(mw.resolved.size(), 1u);
        EXPECT_EQ(mw.resolved[0].first, owner_doge) << "the DOGE side pays the owner's DOGE script";
        EXPECT_EQ(mw.resolved[0].second, att * 32767u);
        const auto m = ltc::ShareTracker::merged_payouts_from_weights(mw, doge_subsidy, doge_donation);
        ASSERT_EQ(m.size(), 2u);
        // donation = floor(subsidy * 32768 / 65535), the owner the rest.
        const uint64_t mo = m.at(owner_doge), md = m.at(doge_donation);
        EXPECT_EQ(md, doge_subsidy * 32768 / 65535);
        EXPECT_EQ(mo + md, doge_subsidy);
        EXPECT_GE(md, mo);
        EXPECT_LE(md - mo, doge_subsidy / 65535 + 2) << mo << " / " << md;
    }

    // Under a miner's share: the split share's weight still goes half to the
    // owner, half to the donation; the miner's share keeps its own donation.
    {
        ltc::ShareTracker tr;
        const uint256 a = add<S>(tr, 1, uint256(), miner, kNodeDonation, miner_doge);
        const uint256 b = add<S>(tr, 2, a, owner, core::kSplitShareDonation, owner_doge);
        const auto w = tr.get_v36_decayed_cumulative_weights(b, 2, unlimited());
        ASSERT_EQ(w.weights.size(), 2u);
        EXPECT_EQ(w.weights.at(owner_script), att * 32767u) << "the split share, at the tip (no decay)";
        const uint288 miner_w = w.weights.at(miner_script);   // decayed * (65535 - 66)
        const uint288 split_don = att * 32768u;
        EXPECT_EQ((w.total_donation_weight - split_don) * uint288(65535 - kNodeDonation), miner_w * uint288(kNodeDonation))
            << "the miner's share: its own donation";

        const auto mw = tr.get_merged_payout_weights(b, kDoge);
        EXPECT_EQ(mw.total_weight, att * 131070u);
        EXPECT_EQ(mw.donation_weight, att * (32768u + kNodeDonation));
        ASSERT_EQ(mw.resolved.size(), 2u);
        for (const auto& [script, weight] : mw.resolved) {
            if (script == owner_doge)
                EXPECT_EQ(weight, att * 32767u);
            else if (script == miner_doge)
                EXPECT_EQ(weight, att * (65535u - kNodeDonation));
            else
                ADD_FAILURE() << "an unexpected merged payee";
        }
    }
}

} // namespace

TEST(RedistributeSplit, PplnsGivesTheOwnerAndTheDonationHalfOfTheShareV36)
{
    split_share_pays_owner_and_donation_half_and_half<ltc::MergedMiningShare>("V36 share");
}

TEST(RedistributeSplit, PplnsGivesTheOwnerAndTheDonationHalfOfTheShare3601)
{
    split_share_pays_owner_and_donation_half_and_half<ltc::MergedMiningShareV3601>("3601 share");
}
