// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The output order of a V35 generation transaction (rides dgb_work_source_test).
//
// The python V35 network sorts the dests by (is_donation, amount, ADDRESS
// STRING) and keeps the last 4000, the donation among them (p2pool-dgb-scrypt
// data.py generate_transaction). c2pool sorted equal amounts by the script,
// where a P2WPKH (0x00...) came before every P2PKH (0x76) and P2SH (0xa9), and
// bech32 strings do not follow their programs' byte order: equal amounts
// (common after a revive) gave a different generation transaction.
// The expected order is the oracle's: the strings were produced by the
// oracle's util/segwit_addr.py and a standalone base58check, then sorted:
//   D... "DB68diZto76gixVajwyoMjcEXsSdyEhnS9"  (P2PKH, hash 0x41*20)
//   S... "STF38JQQE4PbiG6SYnyKMsbCJWwmTBgAFy"  (P2SH,  hash 0x41*20)
//   W2   "dgb1qrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcwyep8g" (P2WPKH 0x18*20)
//   W1   "dgb1qzqgpqyqszqgpqyqszqgpqyqszqgpqyqspvvsyd" (P2WPKH 0x10*20)
// V36 keeps the script order.
// ---------------------------------------------------------------------------

#include <impl/dgb/coin/pplns_payout_split.hpp>

#include <gtest/gtest.h>

#include <map>
#include <vector>

namespace {

using Bytes = std::vector<unsigned char>;

Bytes p2pkh(unsigned char b)
{
    Bytes s{0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, b);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}
Bytes p2sh(unsigned char b)
{
    Bytes s{0xa9, 0x14};
    s.insert(s.end(), 20, b);
    s.push_back(0x87);
    return s;
}
Bytes p2wpkh(unsigned char b)
{
    Bytes s{0x00, 0x14};
    s.insert(s.end(), 20, b);
    return s;
}

std::vector<Bytes> order(const dgb::coin::PplnsPayoutSplit& s)
{
    std::vector<Bytes> o;
    for (const auto& [script, amount] : s.payout_outputs)
        o.push_back(script);
    return o;
}

} // namespace

TEST(DgbPplnsV35Order, EqualAmountsSortByAddressString)
{
    const Bytes D = p2pkh(0x41), S = p2sh(0x41), W1 = p2wpkh(0x10), W2 = p2wpkh(0x18), F = p2pkh(0x99);
    std::map<Bytes, uint288> w{{D, uint288(1)}, {S, uint288(1)}, {W1, uint288(1)}, {W2, uint288(1)}};
    const auto v35 = dgb::coin::compute_pplns_payout_split(w, uint288(4), 1000000000ULL, /*use_v36=*/false, F);
    // The finder's 0.5% alone is the lowest; then the four equal amounts.
    ASSERT_EQ(v35.payout_outputs.size(), 5u);
    EXPECT_EQ(v35.payout_outputs[1].second, v35.payout_outputs[4].second) << "not a tie: the KAT premise";
    EXPECT_EQ(order(v35), (std::vector<Bytes>{F, D, S, W2, W1}))
        << "a V35 tie is not in the python order (amount, address string)";

    // (A fifth weight unit is the donation's, so no >=1-sat deduction breaks the tie.)
    const auto v36 = dgb::coin::compute_pplns_payout_split(w, uint288(5), 1000000000ULL, /*use_v36=*/true, F);
    EXPECT_EQ(order(v36), (std::vector<Bytes>{W1, W2, D, S})) << "V36 keeps the script order";
}

// The donation takes one of python's 4000 places: a V35 transaction keeps the
// 3999 highest payouts; V36 keeps 4000.
TEST(DgbPplnsV35Order, DonationCountsInTheFourThousand)
{
    std::map<Bytes, uint288> w;
    for (uint32_t i = 0; i < 4100; ++i) {
        Bytes s{0x76, 0xa9, 0x14};
        for (int k = 0; k < 4; ++k)
            s.push_back(static_cast<unsigned char>(i >> (8 * k)));
        s.insert(s.end(), 16, 0x07);
        s.push_back(0x88);
        s.push_back(0xac);
        w[s] = uint288(i + 1);   // distinct amounts
    }
    uint288 total;
    for (const auto& [s, x] : w)
        total = total + x;
    const auto v35 = dgb::coin::compute_pplns_payout_split(w, total, 100000000000ULL, false, w.begin()->first);
    EXPECT_EQ(v35.payout_outputs.size(), dgb::coin::PPLNS_MAX_OUTPUTS - 1);
    const auto v36 = dgb::coin::compute_pplns_payout_split(w, total, 100000000000ULL, true, w.begin()->first);
    EXPECT_EQ(v36.payout_outputs.size(), dgb::coin::PPLNS_MAX_OUTPUTS);
}
