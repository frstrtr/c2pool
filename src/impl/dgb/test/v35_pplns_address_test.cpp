// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// V35 PPLNS keyed by ADDRESS STRING, as the python DGB network (rides
// dgb_work_source_test).
//
// Python (p2pool-dgb-scrypt data.py) keys a share's weight by share.address,
// sums amounts per string, merges the donation's own P2PKH address into the
// donation, sorts dests by (is_donation, amount, string) and derives each
// output's script from its own string. Distinct strings with one script stay
// distinct outputs: an UPPERCASE bech32, a witness-v1 BIP173 address with the
// same 20-byte program (opcode 0 there), a 32-byte program with a leading 0x00
// and a 31-byte v1 program. c2pool keyed by script and made one output of each
// group, so every python share whose window held one of them was rejected
// here, and the reverse.
// The expected outputs below were computed by data.py's rules re-stated in
// python, with the addresses from the oracle's own util/segwit_addr.py.
// ---------------------------------------------------------------------------

#include <impl/dgb/coin/pplns_payout_split.hpp>
#include <impl/dgb/config_pool.hpp>
#include <impl/dgb/share.hpp>
#include <impl/dgb/share_check.hpp>
#include <impl/dgb/share_tracker.hpp>
#include <impl/dgb/v35_address.hpp>

#include <btclibs/util/strencodings.h>
#include <core/uint256.hpp>

#include <gtest/gtest.h>

#include <map>
#include <string>
#include <utility>
#include <vector>

namespace {

using Bytes = std::vector<unsigned char>;

const char* kLower = "dgb1q24242424242424242424242424242424swqgq4";
const char* kUpper = "DGB1Q24242424242424242424242424242424SWQGQ4";
const char* kV1 = "dgb1p24242424242424242424242424242424mshrd7";
const char* kWsh = "dgb1qqpnxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenqtstmfg";
const char* kV1_31 = "dgb1pvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvc5glslh";
const char* kD = "DB68diZto76gixVajwyoMjcEXsSdyEhnS9";
const char* kDonationAddress = "DQ8AwqR2XJE9G5dSEfspJYH7Spre85dj6L";   // P2PKH of the forrestv donation pubkey

std::string hex(const Bytes& b) { return HexStr(Span<const unsigned char>(b.data(), b.size())); }

} // namespace

TEST(DgbV35PplnsByAddress, DonationAddressIsPythons)
{
    const auto& ds = dgb::PoolConfig::DONATION_SCRIPT;
    EXPECT_EQ(dgb::v35_donation_address(Bytes(ds.begin(), ds.end()), dgb::v35_address_net(false)), kDonationAddress);
}

TEST(DgbV35PplnsByAddress, DistinctStringsAreDistinctOutputsInPythonOrder)
{
    std::map<Bytes, uint288> w;
    for (const char* a : {kLower, kUpper, kV1, kWsh, kV1_31, kD, kDonationAddress})
        w[dgb::v35_weight_key(a)] = uint288(1);
    const auto split = dgb::coin::compute_pplns_payout_split(w, uint288(8), 100000000000ULL, /*use_v36=*/false,
                                                             dgb::v35_weight_key(kD));
    const std::vector<std::pair<std::string, uint64_t>> want = {
        {"00145555555555555555555555555555555555555555", 12437500000ULL},                 // DGB1Q... (UPPER)
        {"00145555555555555555555555555555555555555555", 12437500000ULL},                 // dgb1p (v1, same program)
        {"001f66666666666666666666666666666666666666666666666666666666666666", 12437500000ULL},  // dgb1p 31-byte
        {"00145555555555555555555555555555555555555555", 12437500000ULL},                 // dgb1q (lower)
        {"001f66666666666666666666666666666666666666666666666666666666666666", 12437500000ULL},  // dgb1q 32-byte 0x00...
        {"76a914414141414141414141414141414141414141414188ac", 12937500000ULL},            // D... (the finder)
    };
    ASSERT_EQ(split.payout_outputs.size(), want.size());
    for (size_t i = 0; i < want.size(); ++i) {
        SCOPED_TRACE(i);
        EXPECT_EQ(hex(split.payout_outputs[i].first), want[i].first);
        EXPECT_EQ(split.payout_outputs[i].second, want[i].second);
    }
    EXPECT_EQ(split.donation_amount, 24875000000ULL) << "the donation address is merged into the donation";
}

TEST(DgbV35PplnsByAddress, ScriptKeyedCallersReadTheCanonicalAddress)
{
    // A script key (the job producer's finder, a script-keyed caller) is read
    // as its canonical address, so it merges with the same string.
    const Bytes d_script = ParseHex("76a914414141414141414141414141414141414141414188ac");
    std::map<Bytes, uint288> by_key{{dgb::v35_weight_key(kD), uint288(3)}};
    std::map<Bytes, uint288> by_script{{d_script, uint288(3)}};
    const auto a = dgb::coin::compute_pplns_payout_split(by_key, uint288(4), 1000000000ULL, false, d_script);
    const auto b = dgb::coin::compute_pplns_payout_split(by_script, uint288(4), 1000000000ULL, false,
                                                         dgb::v35_weight_key(kD));
    ASSERT_EQ(a.payout_outputs.size(), 1u);
    EXPECT_EQ(a.payout_outputs, b.payout_outputs);
    EXPECT_EQ(a.donation_amount, b.donation_amount);
    EXPECT_EQ(a.payout_outputs[0].first, d_script);
}

// The V35 weights walk keys each share by the address string it carries.
TEST(DgbV35PplnsByAddress, WeightsWalkKeysByTheSharesString)
{
    dgb::ShareTracker tracker;
    uint256 prev;
    uint256 tip;
    int i = 0;
    for (const char* a : {kLower, kUpper, kLower}) {
        auto* s = new dgb::PaddingBugfixShare();
        uint256 h;
        h.SetHex(std::to_string(7000000 + i++));
        s->m_hash = h;
        s->m_prev_hash = prev;
        s->m_bits = 0x1e0fffff;
        s->m_max_bits = 0x1e0fffff;
        s->m_donation = 0;   // equal weights per share
        s->m_timestamp = 1790000000u + 15u * static_cast<uint32_t>(i);
        s->m_absheight = static_cast<uint32_t>(i);
        const std::string addr = a;
        s->m_address.m_data.assign(addr.begin(), addr.end());
        prev = h;
        tip = h;
        dgb::ShareType st;
        st = s;
        tracker.add(st);
    }
    // The weights walk runs over verified shares (as attempt_verify adds them).
    {
        std::vector<uint256> chainward;
        for (uint256 cur = tip; !cur.IsNull() && tracker.chain.contains(cur);) {
            chainward.push_back(cur);
            auto* idx = tracker.chain.get_index(cur);
            cur = idx ? idx->tail : uint256();
        }
        for (auto it = chainward.rbegin(); it != chainward.rend(); ++it)
            tracker.verified.add(tracker.chain.get_share(*it));
    }
    uint288 big;
    big.SetHex(std::string(72, 'f'));
    const auto cw = tracker.get_cumulative_weights(tip, 3, big);
    ASSERT_EQ(cw.weights.size(), 2u) << "UPPER and lower merged into one key";
    EXPECT_TRUE(cw.weights.count(dgb::v35_weight_key(kLower)));
    EXPECT_TRUE(cw.weights.count(dgb::v35_weight_key(kUpper)));
    EXPECT_EQ(cw.weights.at(dgb::v35_weight_key(kLower)), cw.weights.at(dgb::v35_weight_key(kUpper)) * 2);
}
