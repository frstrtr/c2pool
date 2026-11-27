// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The donation of the aux-chain coinbase (c2pool/merged/merged_donation.hpp),
// LTC side. Folded into the allowlisted share_test target (no new
// executable: #769).
//
//   AuxDonation.IsTheSingleP2pkhKeyOnEveryChain: merged_donation_script() is
//     76a914 20cb5c22b1e4d5947e5c112c7696b51ad9af3c61 88ac, the bytes of
//     core::donation::SINGLE_P2PKH_DONATION_SCRIPT; rendered from those bytes
//     with each chain's versions (aux_chain_params) it is
//     D88Vn6Dyct7DKfVCfR3syHkjyNx9gEyyiv on DOGE mainnet and
//     nXBZW6xtYrZwCe4PhEhLDhM3DFLSd1pa1R on DOGE testnet (Base58Check
//     computed independently).
//   AuxDonation.LtcSplitRemainderIsTheBuilderLastOutput: the LTC merged split
//     (ShareTracker::merged_payout_outputs, what the P2P provider derives)
//     with the accessor's script puts the PPLNS remainder on it, and the DOGE
//     coinbase build_pplns_coinbase_hex makes of those payouts pays it as its
//     always-last output, an old combined P2SH entry folded in.
//   AuxDonation.OldCombinedEntryIsFoldedNeverPaidAsAMiner: a payout entry
//     with the combined P2SH goes into the donation output, alone or with the
//     accessor's entry; with neither, the >= 1 satoshi donation is still paid
//     to the single key.
//   AuxDonation.LtcProvidersPassTheAccessor: both merged payout providers of
//     main_ltc.cpp (solo/custodial and P2P) give the split the accessor, and
//     neither the combined P2SH nor the parent coinbase's donation script.
//   AuxDonation.ParentShareDonationIsUnchanged: the LTC share donation
//     (PoolConfig::get_donation_script, the parent gentx's) is still the
//     combined P2SH for V36 and the P2PK for V35. The parent gentx bytes
//     themselves: LTC_T5_GentxGolden (ltc_gentx_golden_kat_test.cpp, the same
//     target), byte-equal to the frozen p2pool fixtures.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <fstream>
#include <span>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <btclibs/util/strencodings.h>
#include <c2pool/merged/aux_chain_params.hpp>
#include <c2pool/merged/merged_donation.hpp>
#include <c2pool/merged/merged_mining.hpp>
#include <core/address_utils.hpp>
#include <core/donation.hpp>
#include <core/uint256.hpp>
#include <impl/ltc/config_pool.hpp>
#include <impl/ltc/share_tracker.hpp>

#ifndef C2POOL_IMPL_DIR
#error "C2POOL_IMPL_DIR must point at src/impl (share_test target_compile_definitions)"
#endif

namespace {

using Script = std::vector<unsigned char>;
using Payouts = std::vector<std::pair<Script, uint64_t>>;

constexpr const char* kSingleHex   = "76a91420cb5c22b1e4d5947e5c112c7696b51ad9af3c6188ac";
constexpr const char* kCombinedHex = "a9148c6272621d89e8fa526dd86acff60c7136be8e8587";
constexpr const char* kP2pkHex =
    "4104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b532"
    "56786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac";

std::string hex(const Script& s) { return HexStr(std::span<const unsigned char>(s.data(), s.size())); }

Script p2pkh(unsigned char fill)
{
    Script s{0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, fill);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

Script combined() { return ParseHex(kCombinedHex); }

struct Out {
    Script script;
    uint64_t value;
};

// The outputs of a serialized (non-witness) transaction, given as hex.
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

std::string build(const Payouts& payouts)
{
    return c2pool::merged::MergedMiningManager::build_pplns_coinbase_hex(5'000'001, payouts, uint256());
}

std::string read_file(const std::string& path)
{
    std::ifstream f(path);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

size_t count(const std::string& hay, const std::string& needle)
{
    size_t n = 0;
    for (size_t at = hay.find(needle); at != std::string::npos; at = hay.find(needle, at + needle.size()))
        ++n;
    return n;
}

} // namespace

TEST(AuxDonation, IsTheSingleP2pkhKeyOnEveryChain)
{
    const auto& s = c2pool::merged::merged_donation_script();
    EXPECT_EQ(hex(s), kSingleHex);
    EXPECT_EQ(s, Script(core::donation::SINGLE_P2PKH_DONATION_SCRIPT.begin(),
                        core::donation::SINGLE_P2PKH_DONATION_SCRIPT.end()));
    EXPECT_TRUE(c2pool::merged::is_merged_donation_output(s));
    EXPECT_TRUE(c2pool::merged::is_merged_donation_output(combined()));
    EXPECT_FALSE(c2pool::merged::is_merged_donation_output(p2pkh(0x20)));
    EXPECT_FALSE(c2pool::merged::is_merged_donation_output(ParseHex(kP2pkHex)));

    // The addresses, from the bytes and each chain's own versions.
    const auto* doge = c2pool::merged::find_aux_chain_params("DOGE");
    ASSERT_NE(doge, nullptr);
    EXPECT_EQ(core::script_to_address(s, "", doge->main.p2pkh.front(), doge->main.p2sh.front()),
              "D88Vn6Dyct7DKfVCfR3syHkjyNx9gEyyiv");
    EXPECT_EQ(core::script_to_address(s, "", doge->test.p2pkh.front(), doge->test.p2sh.front()),
              "nXBZW6xtYrZwCe4PhEhLDhM3DFLSd1pa1R");
    // The same bytes on the other aux chains (only the rendering differs).
    const auto* pep = c2pool::merged::find_aux_chain_params("PEP");
    ASSERT_NE(pep, nullptr);
    EXPECT_EQ(core::script_to_address(s, "", pep->main.p2pkh.front(), pep->main.p2sh.front()),
              "PavBNuyU5a9zaw7TJKiAaYqCLVeg8HCpgk");
    const auto* nmc = c2pool::merged::find_aux_chain_params("NMC");
    ASSERT_NE(nmc, nullptr);
    EXPECT_EQ(core::script_to_address(s, "", nmc->main.p2pkh.front(), nmc->main.p2sh.front()),
              "MyZmSUnKErJVKCZ7CeNte3k3pUcuLp989K");
}

TEST(AuxDonation, LtcSplitRemainderIsTheBuilderLastOutput)
{
    const auto& don = c2pool::merged::merged_donation_script();
    const Script a = p2pkh(0x11), b = p2pkh(0x22);

    // Two miners and a share whose DOGE payout is the old combined P2SH (a
    // "donate"-mode share), with a donation weight.
    ltc::MergedPayoutWeights w;
    w.chain_id = 98;
    w.resolved = {{a, uint288(3000)}, {b, uint288(5000)}, {combined(), uint288(2000)}};
    w.accepted_total = uint288(10000);
    w.donation_weight = uint288(77);
    w.total_weight = uint288(10077);
    const uint64_t value = 1000000012345ULL;

    const Payouts payouts = ltc::ShareTracker::merged_payout_outputs(w, value, don);
    // donation = value * 77 // 10077 = 7641163138; the miners split the rest
    // (992358849207) by weight, rounding down; the remainder (1) is added to
    // the donation. Sorted by script: 76a914 11.., 76a914 20cb.. (the single
    // key), 76a914 22.., a914 8c.. (the combined P2SH).
    const Payouts want = {{a, 297707654762ULL}, {don, 7641163139ULL}, {b, 496179424603ULL},
                          {combined(), 198471769841ULL}};
    EXPECT_EQ(payouts, want);

    const auto outs = outputs_of(build(payouts));
    ASSERT_EQ(outs.size(), 4u);   // a, b, OP_RETURN, donation
    EXPECT_EQ(outs[0].script, a);
    EXPECT_EQ(outs[0].value, 297707654762ULL);
    EXPECT_EQ(outs[1].script, b);
    EXPECT_EQ(outs[1].value, 496179424603ULL);
    EXPECT_EQ(outs[2].script.at(0), 0x6a);
    EXPECT_EQ(outs[2].value, 0u);
    // The provider's donation script == the accessor == the last output.
    EXPECT_EQ(hex(outs.back().script), kSingleHex);
    EXPECT_EQ(outs.back().script, don);
    EXPECT_EQ(outs.back().value, 7641163139ULL + 198471769841ULL);
    uint64_t total = 0;
    for (const auto& o : outs) {
        total += o.value;
        EXPECT_NE(o.script, combined()) << "the combined P2SH is never an output";
    }
    EXPECT_EQ(total, value);
}

TEST(AuxDonation, OldCombinedEntryIsFoldedNeverPaidAsAMiner)
{
    const auto& don = c2pool::merged::merged_donation_script();
    const Script a = p2pkh(0x11);

    // Only the old script: all of it to the single key.
    {
        const auto outs = outputs_of(build({{a, 900}, {combined(), 100}}));
        ASSERT_EQ(outs.size(), 3u);
        EXPECT_EQ(outs[0].script, a);
        EXPECT_EQ(outs[0].value, 900u);
        EXPECT_EQ(outs[2].script, don);
        EXPECT_EQ(outs[2].value, 100u);
    }
    // Both: summed.
    {
        const auto outs = outputs_of(build({{a, 900}, {don, 30}, {combined(), 70}}));
        ASSERT_EQ(outs.size(), 3u);
        EXPECT_EQ(outs[2].script, don);
        EXPECT_EQ(outs[2].value, 100u);
    }
    // Neither: the >= 1 satoshi donation, taken from the largest miner.
    {
        const auto outs = outputs_of(build({{a, 1000}}));
        ASSERT_EQ(outs.size(), 3u);
        EXPECT_EQ(outs[0].value, 999u);
        EXPECT_EQ(outs[2].script, don);
        EXPECT_EQ(outs[2].value, 1u);
    }
}

TEST(AuxDonation, LtcProvidersPassTheAccessor)
{
    const std::string src = read_file(std::string(C2POOL_IMPL_DIR) + "/../c2pool/main_ltc.cpp");
    ASSERT_FALSE(src.empty()) << "main_ltc.cpp not found";
    const auto begin = src.find("// Wire the merged payout provider so that aux chain block");
    const auto end = src.find("} // end MM payout provider", begin);
    ASSERT_NE(begin, std::string::npos);
    ASSERT_NE(end, std::string::npos);
    const std::string region = src.substr(begin, end - begin);

    // Solo/custodial and P2P: the accessor, each once.
    EXPECT_EQ(count(region, "c2pool::merged::merged_donation_script()"), 2u);
    EXPECT_EQ(count(region, "mm_manager->set_payout_provider("), 2u);
    EXPECT_EQ(region.find("COMBINED_DONATION_SCRIPT"), std::string::npos);
    EXPECT_EQ(region.find("get_donation_script("), std::string::npos)
        << "the parent coinbase's donation script never reaches the aux split";
    // The P2P split is the one tested above.
    EXPECT_NE(region.find("ltc::ShareTracker::merged_payout_outputs(*w, coinbase_value,"), std::string::npos);
}

TEST(AuxDonation, ParentShareDonationIsUnchanged)
{
    EXPECT_EQ(hex(ltc::PoolConfig::get_donation_script(36)), kCombinedHex);
    EXPECT_EQ(hex(ltc::PoolConfig::get_donation_script(3601)), kCombinedHex);
    EXPECT_EQ(hex(ltc::PoolConfig::get_donation_script(35)), kP2pkHex);
    EXPECT_EQ(hex(Script(ltc::PoolConfig::COMBINED_DONATION_SCRIPT.begin(),
                         ltc::PoolConfig::COMBINED_DONATION_SCRIPT.end())),
              kCombinedHex);
    EXPECT_NE(ltc::PoolConfig::get_donation_script(36), c2pool::merged::merged_donation_script());
}
