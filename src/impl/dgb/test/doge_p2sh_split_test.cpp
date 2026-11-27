// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The operator's DOGE rule for P2SH parent keys (rides dgb_work_source_test).
//
// A share whose DGB payout key is a P2SH ("S...", e.g. DigiByte Core's
// p2sh-segwit default) and that names no DOGE address is not paid as the same
// P2SH on DOGE (P2SH(0014<keyhash>) is anyone-can-spend on DOGE once the
// redeem script is public). Its DOGE amount a is split:
//   owner = floor(a/2) to the node owner's DOGE script,
//   donation = a - owner (the odd satoshi),
//   all to the donation without an owner script, or when owner rounds to 0.
// Pinned: the exact two outputs; no owner -> all to the donation; an explicit
// DOGE address wins; P2PKH/P2WPKH miners unchanged; the sum is the value;
// amount 0 and 1; merging into existing outputs; the owner script rule.
// ---------------------------------------------------------------------------

#include <impl/dgb/coin/aux_doge_payout_provider.hpp>

#include <impl/dgb/config_pool.hpp>
#include <impl/dgb/share.hpp>
#include <impl/dgb/share_tracker.hpp>

#include <c2pool/merged/aux_chain_params.hpp>
#include <core/address_utils.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <c2pool/merged/merged_donation.hpp>
#include <gtest/gtest.h>

#include <memory>
#include <mutex>
#include <shared_mutex>

#include <cstdint>
#include <map>
#include <string>
#include <tuple>
#include <vector>

namespace {

using Bytes = std::vector<unsigned char>;
constexpr uint32_t kDoge = 98;

Bytes h(unsigned char f) { return Bytes(20, f); }
Bytes p2pkh(const Bytes& k) { Bytes s{0x76, 0xa9, 0x14}; s.insert(s.end(), k.begin(), k.end()); s.push_back(0x88); s.push_back(0xac); return s; }
Bytes p2sh(const Bytes& k) { Bytes s{0xa9, 0x14}; s.insert(s.end(), k.begin(), k.end()); s.push_back(0x87); return s; }
Bytes wpkh(const Bytes& k) { Bytes s{0x00, 0x14}; s.insert(s.end(), k.begin(), k.end()); return s; }

const Bytes kOwner = p2pkh(h(0x0e));
const Bytes kExplicitX = p2pkh(h(0x5c));

// The aux donation (#2346): the single P2PKH key, as the manager's builder pays.
const Bytes& donation() { return c2pool::merged::merged_donation_script(); }
const Bytes& combined_p2sh() { static const Bytes d = dgb::PoolConfig::get_donation_script(36); return d; }

// Four V36 shares of equal work, donation 0:
//   S: P2SH key 0x51, no merged address        -> split
//   A: P2PKH key 0xa1                           -> unchanged
//   C: P2WPKH key 0xc3                          -> unchanged (as P2PKH)
//   E: P2SH key 0xe5 WITH an explicit DOGE X    -> X, no split
struct SplitChain {
    dgb::ShareTracker tracker;
    uint256 tip;
    SplitChain()
    {
        struct Spec { Bytes key; uint8_t type; const Bytes* merged; };
        const std::vector<Spec> specs = {
            {h(0x51), 2, nullptr}, {h(0xa1), 0, nullptr}, {h(0xc3), 1, nullptr}, {h(0xe5), 2, &kExplicitX}};
        for (size_t i = 0; i < specs.size(); ++i) {
            auto* s = new dgb::MergedMiningShare();
            s->m_hash = uint256(std::vector<unsigned char>(32, static_cast<unsigned char>(0x70 + i)));
            if (i == 0) s->m_prev_hash.SetNull(); else s->m_prev_hash = tip;
            s->m_pubkey_hash = uint160(base_uint<160>(specs[i].key));
            s->m_pubkey_type = specs[i].type;
            s->m_donation = 0;
            s->m_desired_version = 36;
            s->m_bits = 0x1e0fffff;
            s->m_max_bits = 0x1e0fffff;
            s->m_min_header.m_bits = 0x1b0404cb;
            if (specs[i].merged) {
                dgb::MergedAddressEntry e;
                e.m_chain_id = kDoge;
                e.m_script.m_data = *specs[i].merged;
                s->m_merged_addresses.push_back(e);
            }
            tip = s->m_hash;
            dgb::ShareType st;
            st = s;
            tracker.add(st);
        }
    }
};

std::map<Bytes, uint64_t> as_map(const dgb::coin::DogePayouts& p) { return {p.begin(), p.end()}; }

uint64_t sum(const std::map<Bytes, uint64_t>& m)
{
    uint64_t s = 0;
    for (const auto& [_, v] : m) s += v;
    return s;
}

} // namespace

TEST(DgbDogeP2shSplit, P2shKeyIsSplitOwnerDonationOthersUnchanged)
{
    SplitChain sc;
    const uint64_t value = 4'000'000'000ULL;
    // Oracle: the proven split with the pass-through resolution.
    const auto base = sc.tracker.get_merged_expected_payouts(
        sc.tip, chain::bits_to_target(0x1b0404cb), value, kDoge, donation(), {}, {});
    ASSERT_TRUE(base.count(p2sh(h(0x51))));
    const uint64_t a = base.at(p2sh(h(0x51)));

    dgb::coin::DogeP2shSplit rule{kOwner};
    std::string miss;
    const auto got = as_map(dgb::coin::doge_merged_payouts(sc.tracker, sc.tip, kDoge, value, miss, &rule));

    EXPECT_EQ(got.count(p2sh(h(0x51))), 0u) << "the P2SH key is not paid as a DOGE P2SH";
    // The split sees the whole amount: the core's >= 1 sat rule (which took
    // 1 sat from the P2SH entry in `base`) is left to the split.
    EXPECT_EQ(a + 1, 1'000'000'000ULL);
    EXPECT_EQ(got.at(kOwner), (a + 1) / 2);
    EXPECT_EQ(got.at(donation()), (a + 1) - (a + 1) / 2) << "odd satoshi to the donation";
    // Unchanged: P2PKH, P2WPKH (as P2PKH), and the explicit DOGE address of a P2SH key.
    EXPECT_EQ(got.at(p2pkh(h(0xa1))), base.at(p2pkh(h(0xa1))));
    EXPECT_EQ(got.at(p2pkh(h(0xc3))), base.at(p2pkh(h(0xc3))));
    EXPECT_EQ(got.at(kExplicitX), base.at(kExplicitX)) << "an explicit DOGE address wins";
    EXPECT_EQ(got.count(p2sh(h(0xe5))), 0u);
    EXPECT_EQ(sum(got), value);
    EXPECT_EQ(sum(base), value);
    // The known numbers (four equal shares, no donation weight): exactly 50/50.
    EXPECT_EQ(got.at(kOwner), 500'000'000ULL);
    EXPECT_EQ(got.at(donation()), 500'000'000ULL);
}

TEST(DgbDogeP2shSplit, NoOwnerScriptSendsAllToTheDonation)
{
    SplitChain sc;
    const uint64_t value = 4'000'000'001ULL;
    const auto base = sc.tracker.get_merged_expected_payouts(
        sc.tip, chain::bits_to_target(0x1b0404cb), value, kDoge, donation(), {}, {});
    const uint64_t a = base.at(p2sh(h(0x51)));
    dgb::coin::DogeP2shSplit rule{};
    std::string miss;
    const auto got = as_map(dgb::coin::doge_merged_payouts(sc.tracker, sc.tip, kDoge, value, miss, &rule));
    EXPECT_EQ(got.count(p2sh(h(0x51))), 0u);
    EXPECT_EQ(got.at(donation()), base.at(donation()) + a);
    EXPECT_EQ(sum(got), value);
}

TEST(DgbDogeP2shSplit, RoundingAndMergingRules)
{
    const Bytes tag_key = [] {
        Bytes t{0xff, 'p', '2', 's', 'h', '-', 's', 'p', 'l', 'i', 't'};
        const Bytes k = p2sh(h(0x51));
        t.insert(t.end(), k.begin(), k.end());
        return t;
    }();
    const dgb::coin::DogeP2shSplit rule{kOwner};
    for (uint64_t a : {uint64_t(0), uint64_t(1), uint64_t(2), uint64_t(7), uint64_t(1'000'000'001ULL)}) {
        SCOPED_TRACE(a);
        // Existing outputs for the owner and the donation: the parts merge in.
        std::map<Bytes, uint64_t> m{{tag_key, a}, {kOwner, 10}, {donation(), 3}};
        dgb::coin::apply_doge_p2sh_split(m, rule, donation());
        EXPECT_EQ(m.count(tag_key), 0u);
        const uint64_t owner = a / 2;
        EXPECT_EQ(m.at(kOwner), 10 + owner);
        EXPECT_EQ(m.at(donation()), 3 + (a - owner));
        EXPECT_EQ(sum(m), 13 + a);
    }
    // amount 1: no owner output is created (never a 0-value output).
    std::map<Bytes, uint64_t> one{{tag_key, 1}};
    dgb::coin::apply_doge_p2sh_split(one, rule, donation());
    EXPECT_EQ(one.count(kOwner), 0u);
    EXPECT_EQ(one.at(donation()), 1u);
    // amount 0: nothing at all.
    std::map<Bytes, uint64_t> zero{{tag_key, 0}};
    dgb::coin::apply_doge_p2sh_split(zero, rule, donation());
    EXPECT_TRUE(zero.empty());
}

TEST(DgbDogeP2shSplit, OwnerDogeScriptRule)
{
    std::string src;
    const std::string d_owner = core::script_to_address(p2pkh(h(0x0e)), "", 30, 63);
    const std::string w_owner = core::script_to_address(wpkh(h(0x0e)), "dgb", 30, 63);
    const std::string s_owner = core::script_to_address(p2sh(h(0x0e)), "", 30, 63);
    const std::string doge_owner = core::script_to_address(p2sh(h(0x2d)), "", 30, 22);   // DOGE "A..."

    EXPECT_EQ(dgb::coin::doge_owner_script(d_owner, "", false, false, src), p2pkh(h(0x0e)));
    EXPECT_EQ(dgb::coin::doge_owner_script(w_owner, "", false, false, src), p2pkh(h(0x0e)));
    EXPECT_TRUE(dgb::coin::doge_owner_script(s_owner, "", false, false, src).empty()) << "P2SH owner -> donation";
    EXPECT_TRUE(dgb::coin::doge_owner_script("", "", false, false, src).empty());
    // An explicit owner DOGE address wins, also for a P2SH owner.
    EXPECT_EQ(dgb::coin::doge_owner_script(s_owner, doge_owner, false, false, src), p2sh(h(0x2d)));
    EXPECT_EQ(dgb::coin::doge_owner_script(d_owner, doge_owner, false, false, src), p2sh(h(0x2d)));
    // Not a DOGE address of this network: donation, not the DGB key.
    EXPECT_TRUE(dgb::coin::doge_owner_script(d_owner, "notanaddress", false, false, src).empty());
}

namespace {
struct SplitNode {
    dgb::ShareTracker& tracker;
    uint256 best;
    std::shared_mutex mtx;
    struct Guard {
        std::shared_lock<std::shared_mutex> lk;
        dgb::ShareTracker* t;
        explicit operator bool() const { return lk.owns_lock(); }
        dgb::ShareTracker& operator*() { return *t; }
    };
    Guard read_tracker() { return Guard{std::shared_lock<std::shared_mutex>(mtx, std::try_to_lock), &tracker}; }
    uint256 best_share_hash() { return best; }
};
} // namespace

// The registered provider applies the rule: with main_dgb's owner script, and
// by default (no owner configured) all to the donation.
TEST(DgbDogeP2shSplit, ProviderAppliesTheRule)
{
    SplitChain sc;
    SplitNode node{sc.tracker, sc.tip};
    const uint64_t value = 4'000'000'000ULL;
    auto with_owner = as_map(dgb::coin::make_doge_payout_provider(
        &node, std::make_shared<const dgb::coin::DogeP2shSplit>(dgb::coin::DogeP2shSplit{kOwner}))(kDoge, value));
    EXPECT_EQ(with_owner.at(kOwner), 500'000'000ULL);
    EXPECT_EQ(with_owner.count(p2sh(h(0x51))), 0u);
    auto by_default = as_map(dgb::coin::make_doge_payout_provider(&node)(kDoge, value));
    EXPECT_EQ(by_default.count(kOwner), 0u);
    EXPECT_EQ(by_default.count(p2sh(h(0x51))), 0u);
    EXPECT_EQ(by_default.at(donation()), 1'000'000'000ULL);
    EXPECT_EQ(sum(by_default), value);
}

// A window of P2SH keys only, no donation weight: the split is exactly 50/50
// (the core's >= 1 sat rule would have taken 1 sat first: 49/51), and the
// donation is still >= 1. Without the split rule the core rule is unchanged.
TEST(DgbDogeP2shSplit, OnlyP2shKeysNoDonationIsExactlyFiftyFifty)
{
    dgb::ShareTracker tracker;
    uint256 tip;
    for (int i = 0; i < 3; ++i) {
        auto* s = new dgb::MergedMiningShare();
        s->m_hash = uint256(std::vector<unsigned char>(32, static_cast<unsigned char>(0x60 + i)));
        if (i == 0) s->m_prev_hash.SetNull(); else s->m_prev_hash = tip;
        s->m_pubkey_hash = uint160(base_uint<160>(h(0x51)));
        s->m_pubkey_type = 2;   // P2SH
        s->m_donation = 0;
        s->m_desired_version = 36;
        s->m_bits = 0x1e0fffff;
        s->m_max_bits = 0x1e0fffff;
        s->m_min_header.m_bits = 0x1b0404cb;
        tip = s->m_hash;
        dgb::ShareType st;
        st = s;
        tracker.add(st);
    }
    const dgb::coin::DogeP2shSplit with_owner{kOwner};
    const dgb::coin::DogeP2shSplit no_owner{};
    std::string miss;
    for (const auto& [value, owner, don] : std::vector<std::tuple<uint64_t, uint64_t, uint64_t>>{
             {100, 50, 50}, {101, 50, 51}, {1, 0, 1}, {1'000'000'000'000ULL, 500'000'000'000ULL, 500'000'000'000ULL}}) {
        SCOPED_TRACE(value);
        const auto got = as_map(dgb::coin::doge_merged_payouts(tracker, tip, kDoge, value, miss, &with_owner));
        EXPECT_EQ(got.count(p2sh(h(0x51))), 0u);
        EXPECT_EQ(owner == 0 ? 0u : got.at(kOwner), owner) << "not floor(a/2) to the owner";
        if (owner == 0)
            EXPECT_EQ(got.count(kOwner), 0u) << "a 0-value owner output";
        EXPECT_EQ(got.at(donation()), don);
        EXPECT_GE(got.at(donation()), 1u);
        EXPECT_EQ(sum(got), value);
        const auto all = as_map(dgb::coin::doge_merged_payouts(tracker, tip, kDoge, value, miss, &no_owner));
        EXPECT_EQ(all.at(donation()), value) << "no owner: all to the donation";
        EXPECT_EQ(all.size(), 1u);
        EXPECT_EQ(got.count(combined_p2sh()), 0u) << "the donation is still the combined P2SH";
    }
    // Without the split rule the core's >= 1 sat rule applies as before.
    const auto base = tracker.get_merged_expected_payouts(tip, chain::bits_to_target(0x1b0404cb), 100, kDoge,
                                                          donation(), {}, {});
    EXPECT_EQ(base.at(p2sh(h(0x51))), 99u);
    EXPECT_EQ(base.at(donation()), 1u);
}
