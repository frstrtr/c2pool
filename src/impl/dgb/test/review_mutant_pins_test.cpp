// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// Pins for the mutants review dd1248abd #8 found no KAT killed (rides
// dgb_work_source_test). The tip check, the store epoch and its failure
// branches are pinned in work_source_test / store_rules_epoch_test.
// ---------------------------------------------------------------------------

#include <impl/dgb/coin/pplns_payout_split.hpp>
#include <impl/dgb/config_coin.hpp>
#include <impl/dgb/params.hpp>
#include <impl/dgb/share.hpp>
#include <impl/dgb/share_check.hpp>
#include <impl/dgb/v35_address.hpp>

#include <btclibs/util/strencodings.h>
#include <core/coin_params.hpp>
#include <core/uint256.hpp>

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#ifndef DGB_MAIN_SRC
#error "DGB_MAIN_SRC must name src/c2pool/main_dgb.cpp"
#endif

namespace {

using Bytes = std::vector<unsigned char>;

std::string slurp(const std::filesystem::path& f)
{
    std::ifstream in(f);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

std::filesystem::path src_root() { return std::filesystem::path(DGB_MAIN_SRC).parent_path().parent_path(); }

std::string hex(const Bytes& b) { return HexStr(Span<const unsigned char>(b.data(), b.size())); }

} // namespace

// The finder IS the donation address: python adds the finder fee to
// amounts[donation_address], which is then the DONATION output (data.py
// 266-276, 334-337), never a P2PKH of its own. A split that erased the
// donation key before adding the finder fee would pay it as a separate output.
// Expected values: data.py's rules re-stated in python3 (weights 1:1:1 of 4).
TEST(DgbReviewMutantPins, FinderIsTheDonationAddress)
{
    const char* kLower = "dgb1q24242424242424242424242424242424swqgq4";
    const char* kD = "DB68diZto76gixVajwyoMjcEXsSdyEhnS9";
    const char* kDonation = "DQ8AwqR2XJE9G5dSEfspJYH7Spre85dj6L";
    std::map<Bytes, uint288> w;
    for (const char* a : {kLower, kD, kDonation})
        w[dgb::v35_weight_key(a)] = uint288(1);
    const auto split = dgb::coin::compute_pplns_payout_split(w, uint288(4), 100000000000ULL, /*use_v36=*/false,
                                                             dgb::v35_weight_key(kDonation));
    ASSERT_EQ(split.payout_outputs.size(), 2u) << "the finder fee became an output of its own";
    EXPECT_EQ(hex(split.payout_outputs[0].first), "76a914414141414141414141414141414141414141414188ac");
    EXPECT_EQ(split.payout_outputs[0].second, 24875000000ULL);
    EXPECT_EQ(hex(split.payout_outputs[1].first), "00145555555555555555555555555555555555555555");
    EXPECT_EQ(split.payout_outputs[1].second, 24875000000ULL);
    EXPECT_EQ(split.donation_amount, 50250000000ULL) << "the finder fee is the donation's";
}

// Only the exact none-value {[], root 2**256-1} is python's None; a non-empty
// branch with that root is a present segwit_data python accepts. The share
// carries an undecodable address, so share_init_verify stops at the address
// check right after the segwit_data one (a bare share must not run further).
TEST(DgbReviewMutantPins, SegwitDataWithABranchIsNotTheNoneValue)
{
    const auto params = dgb::make_coin_params(/*testnet=*/false);
    auto refusal = [&](bool with_branch) -> std::string {
        dgb::PaddingBugfixShare share;
        share.m_coinbase.m_data = {0x03, 0x01, 0x02, 0x03};
        const std::string a = "not-an-address";
        share.m_address.m_data.assign(a.begin(), a.end());
        dgb::SegwitData sd = dgb::SegwitDataDefaultV35::get();
        if (with_branch)
            sd.m_txid_merkle_link.m_branch.push_back(uint256(std::vector<unsigned char>(32, 0x11)));
        share.m_segwit_data = sd;
        try {
            dgb::share_init_verify(share, params, /*check_pow=*/false);
        } catch (const std::exception& e) {
            return e.what();
        }
        return {};
    };
    EXPECT_NE(refusal(false).find("without segwit_data"), std::string::npos) << refusal(false);
    const std::string with_branch = refusal(true);
    EXPECT_EQ(with_branch.find("without segwit_data"), std::string::npos) << with_branch;
    EXPECT_FALSE(with_branch.empty()) << "the undecodable address passed";
}

// Source pins: the share_info height is the accumulated one (attempt_verify's
// source), and the won-block relay requires the share hash outside the
// regtest forced-won seam.
TEST(DgbReviewMutantPins, OneHeightSourceAndTheRelayGate)
{
    const std::string check = slurp(src_root() / "impl" / "dgb" / "share_check.hpp");
    ASSERT_FALSE(check.empty());
    const auto fn = check.find("void check_v35_share_info(");
    ASSERT_NE(fn, std::string::npos);
    const auto ph = check.find("const int32_t prev_height = tracker.chain.get_acc_height(share.m_prev_hash);", fn);
    EXPECT_NE(ph, std::string::npos) << "check_v35_share_info reads another height";
    EXPECT_NE(check.find("|| (share.m_segwit_data->m_txid_merkle_link.m_branch.empty()"), std::string::npos);

    const std::string main = slurp(DGB_MAIN_SRC);
    EXPECT_NE(main.find("/*require_share_hash=*/!(regtest && force_won_share));"), std::string::npos)
        << "the won-block relay no longer requires the share hash";
}
