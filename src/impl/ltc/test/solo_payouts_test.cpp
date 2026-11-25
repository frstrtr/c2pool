// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// --solo pays each miner to its login's own script (rides share_test).
//
// The solo split read the hashrate by pubkey hash and paid every miner
// P2PKH(<hash>): a P2SH login was paid P2PKH(<script hash>) (unspendable), a
// P2WSH / P2TR login (no 20-byte hash) the zero key. ltc::solo_payouts pays
// the login scripts; the outputs add up to the subsidy exactly.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include <impl/ltc/solo_payouts.hpp>

namespace {

std::vector<unsigned char> script(std::vector<unsigned char> head, unsigned char b, size_t n,
                                  std::vector<unsigned char> tail = {})
{
    head.insert(head.end(), n, b);
    head.insert(head.end(), tail.begin(), tail.end());
    return head;
}

const auto kP2pkh = script({0x76, 0xa9, 0x14}, 0x11, 20, {0x88, 0xac});
const auto kP2sh = script({0xa9, 0x14}, 0x22, 20, {0x87});
const auto kP2wpkh = script({0x00, 0x14}, 0x33, 20);
const auto kP2wsh = script({0x00, 0x20}, 0x44, 32);
const auto kP2tr = script({0x51, 0x20}, 0x55, 32);
const auto kOwner = script({0x76, 0xa9, 0x14}, 0x0e, 20, {0x88, 0xac});
const auto kDonation = script({0xa9, 0x14}, 0xdd, 20, {0x87});
const std::vector<unsigned char> kZeroKey = script({0x76, 0xa9, 0x14}, 0x00, 20, {0x88, 0xac});

uint64_t sum(const std::map<std::vector<unsigned char>, double>& m)
{
    uint64_t s = 0;
    for (const auto& [_, v] : m) s += static_cast<uint64_t>(v);
    return s;
}

} // namespace

TEST(SoloPayouts, EveryMinerIsPaidToItsLoginsOwnScript)
{
    const uint64_t subsidy = 5000003333ULL;
    ltc::SoloMinerRates miners = {{kP2pkh, 1.0}, {kP2sh, 2.0}, {kP2wpkh, 3.0}, {kP2wsh, 4.0}, {kP2tr, 5.0}};
    auto out = ltc::solo_payouts(subsidy, miners, kOwner, /*node_owner_fee=*/1.0, kDonation, /*dev_donation=*/0.0);
    for (const auto& s : {kP2pkh, kP2sh, kP2wpkh, kP2wsh, kP2tr})
        EXPECT_GT(out.count(s) ? out.at(s) : 0.0, 0.0) << "each login's own script is paid";
    EXPECT_EQ(out.count(kZeroKey), 0u) << "never the zero key";
    EXPECT_EQ(out.size(), 7u) << "five miners, the owner, the donation marker";
    EXPECT_EQ(sum(out), subsidy) << "the outputs add up to the subsidy";
    EXPECT_EQ(out.at(kDonation), 1.0) << "the 1-satoshi marker";
    EXPECT_NEAR(out.at(kP2tr) / out.at(kP2pkh), 5.0, 1e-6) << "by hashrate";
}

TEST(SoloPayouts, NoMinerPaysTheOwnerElseTheDonation)
{
    auto out = ltc::solo_payouts(1000000ULL, {}, kOwner, 0.0, kDonation, 0.0);
    EXPECT_EQ(out.at(kOwner), 999999.0);
    EXPECT_EQ(out.at(kDonation), 1.0);
    auto out2 = ltc::solo_payouts(1000000ULL, {}, {}, 2.0, kDonation, 0.0);
    EXPECT_EQ(out2.size(), 1u) << "no owner script: no owner fee, the rest to the donation";
    EXPECT_EQ(out2.at(kDonation), 1000000.0);
}

TEST(SoloPayouts, FeesAndRoundingStillAddUpToTheSubsidy)
{
    const uint64_t subsidy = 2500004350ULL;
    ltc::SoloMinerRates miners = {{kP2pkh, 1.0}, {kP2sh, 1.0}, {kP2wsh, 1.0}};
    auto out = ltc::solo_payouts(subsidy, miners, kOwner, 2.5, kDonation, 1.0);
    EXPECT_EQ(sum(out), subsidy);
    EXPECT_EQ(out.at(kDonation), static_cast<double>(static_cast<uint64_t>(subsidy * 1.0 / 100.0)));
    // the miners' rounding remainder went to the owner
    EXPECT_GE(out.at(kOwner), static_cast<double>(static_cast<uint64_t>(subsidy * 2.5 / 100.0)));
}
