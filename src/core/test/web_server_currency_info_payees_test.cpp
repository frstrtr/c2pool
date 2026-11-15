// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// /web/currency_info payee identities for the PPLNS treemap: the node-owner
// fee payee (node_owner_address, node_owner_merged_addresses) and the
// donation outputs (donation_address, merged_donation_addresses), so the
// dashboard draws the fee and donation tiles from explicit fields instead of
// guessing from address prefixes.
//   * each is rendered from the script the node pays, in the form
//     /current_payouts (parent) and /current_merged_payouts (merged) key
//     their rows by, on the node's network;
//   * "" / {} when the node pays no such output: no --fee, no merged chain,
//     a createauxblock-mode chain (the daemon's coinbase has no donation);
//   * a coin core has no address form for (DGB, BCH CashAddr) stays empty,
//     never a Bitcoin-format address.
// Folded into the allowlisted core_test target (no new executable: #769).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>

#include <c2pool/merged/aux_chain_params.hpp>
#include <c2pool/merged/merged_mining.hpp>
#include <core/address_utils.hpp>
#include <core/address_validator.hpp>
#include <core/donation.hpp>
#include <core/web_server.hpp>

namespace {

using c2pool::address::Blockchain;
using c2pool::merged::MergedMiningManager;
using Script = std::vector<unsigned char>;

Script p2pkh(unsigned char fill)
{
    Script s{0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, fill);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

// Base58Check of hash160 = 20 x fill (computed independently, Python hashlib).
const char* kOwnerLtc      = "LLnCCHbSzfwWquEdaS5TF2Yt7uz5Qb1SZ1";   // LTC main P2PKH, 0x11
const char* kOwnerLtcTest  = "mh5CE8Nbj38iND267s4XnvhSmhDW7yWc6Q";   // LTC test P2PKH, 0x11
const char* kOwnerDogeKey  = "D6hLULEGDRbk86j58t5iWmeinqM6acA16V";   // DOGE main P2PKH, 0x11
const char* kOwnerDogeKeyT = "nVkQCLyB9Q4U15JGAhjAmBF22hjPYUwj3w";   // DOGE test P2PKH, 0x11
const char* kOwnerDoge     = "DBN4GZ67xTh7tPMVLmMBQo75WwCV7ppTgD";   // DOGE main P2PKH, 0x44
const char* kOwnerDash     = "XcF5mKwWsiv3k394GBQNpYAuk3CVJ48Xnp";   // DASH main P2PKH, 0x11
// The donation scripts (core/donation.hpp) on each chain.
const char* kDonationLtc       = "MLhSmVQxMusLE3pjGFvp4unFckgjeD8LUA";   // V36 P2SH, LTC main
const char* kDonationLtcV35    = "LeD2fnnDJYZuyt8zgDsZ2oBGmuVcxGKCLd";   // pre-V36 P2PK, its key's P2PKH
const char* kDonationDoge      = "A5EZCT4tUrtoKuvJaWbtVQADzdUKdtsqpr";   // V36 P2SH, DOGE main
const char* kDonationTestnet   = "2N63WXLw22FXFdLBNqWZLsDX7WQJTPXus7f";  // V36 P2SH, LTC/DOGE testnet (0xc4)

struct DogeBackend : c2pool::merged::IAuxChainBackend {
    c2pool::merged::AuxChainConfig cfg;
    std::string tip = std::string(62, '0') + "c1";
    explicit DogeBackend(bool multiaddress)
    {
        cfg.symbol = "DOGE";
        cfg.chain_id = 98;
        cfg.multiaddress = multiaddress;
    }
    c2pool::merged::AuxWork get_work_template() override
    {
        c2pool::merged::AuxWork w;
        w.chain_id = 98;
        w.height = 5'000'001;
        w.coinbase_value = 1000000000000ULL;
        w.block_hash.SetHex(tip);
        w.target.SetHex(std::string(8, '0') + std::string(56, 'f'));
        w.prev_block_hash = tip;
        return w;
    }
    c2pool::merged::AuxWork create_aux_block(const std::string&) override { return get_work_template(); }
    bool connect() override { return true; }
    bool submit_block(const std::string&) override { return true; }
    bool submit_aux_block(const uint256&, const std::string&) override { return true; }
    std::string get_block_hex(const std::string&) override { return {}; }
    std::string get_best_block_hash() override { return tip; }
    std::vector<NetService> getpeerinfo() override { return {}; }
    const c2pool::merged::AuxChainConfig& config() const override { return cfg; }
};

// An LTC node merge-mining DOGE, wired as main_ltc.cpp wires it: the fee via
// set_node_fee_from_address, the DOGE operator script from
// resolve_operator_merged_script (only with a fee, as main_ltc does), the
// donation script of the share version.
struct LtcRig {
    boost::asio::io_context ioc;
    MergedMiningManager mm{ioc};
    core::MiningInterface mi;

    LtcRig(bool testnet, double fee, const std::string& owner, const std::string& owner_doge,
           bool merged = true, bool multiaddress = true, int64_t share_version = 36)
        : mi(testnet, /*node=*/nullptr, Blockchain::LITECOIN)
    {
        if (merged) {
            auto backend = std::make_unique<DogeBackend>(multiaddress);
            auto cfg = backend->cfg;
            mm.add_chain(cfg, std::move(backend));
            mi.set_merged_mining_manager(&mm);
        }
        if (fee > 0.0 && !owner.empty()) {
            mi.set_node_fee_from_address(fee, owner);
            if (merged) {
                const auto o = c2pool::merged::resolve_operator_merged_script(
                    "DOGE", testnet ? c2pool::merged::AuxNetwork::testnet : c2pool::merged::AuxNetwork::mainnet,
                    owner, owner_doge, "", core::donation::get_donation_script(36));
                mi.set_operator_merged_scripts({{98u, o.script}});
            }
        }
        mi.set_donation_script(core::donation::get_donation_script(share_version));
    }
};

void expect_payee_fields_present(const nlohmann::json& r)
{
    ASSERT_TRUE(r.contains("node_owner_address"));
    ASSERT_TRUE(r.contains("node_owner_merged_addresses"));
    ASSERT_TRUE(r.contains("donation_address"));
    ASSERT_TRUE(r.contains("merged_donation_addresses"));
    EXPECT_TRUE(r.at("node_owner_address").is_string());
    EXPECT_TRUE(r.at("node_owner_merged_addresses").is_object());
    EXPECT_TRUE(r.at("donation_address").is_string());
    EXPECT_TRUE(r.at("merged_donation_addresses").is_object());
}

} // namespace

TEST(CurrencyInfoPayees, LtcWithFeeNamesTheOwnerAndTheDonationOnBothChains)
{
    LtcRig rig(/*testnet=*/false, /*fee=*/1.0, kOwnerLtc, kOwnerDoge);
    const auto r = rig.mi.rest_web_currency_info();
    expect_payee_fields_present(r);

    EXPECT_EQ(r.at("node_owner_address"), kOwnerLtc);
    // The --node-owner-merged-address the DOGE side of the fee shares carries.
    EXPECT_EQ(r.at("node_owner_merged_addresses"), (nlohmann::json{{"DOGE", kOwnerDoge}}));
    EXPECT_EQ(r.at("donation_address"), kDonationLtc);
    EXPECT_EQ(r.at("merged_donation_addresses"), (nlohmann::json{{"DOGE", kDonationDoge}}));

    // The tiles' keys: the parent form is /current_payouts', the merged one
    // /current_merged_payouts' (DOGE 0x1e / 0x16).
    EXPECT_EQ(r.at("node_owner_address"), core::script_to_address(p2pkh(0x11), /*is_litecoin=*/true, false));
    const Script don(core::donation::COMBINED_DONATION_SCRIPT.begin(), core::donation::COMBINED_DONATION_SCRIPT.end());
    EXPECT_EQ(r.at("merged_donation_addresses").at("DOGE"), core::script_to_address(don, "", 0x1e, 0x16));

    // Existing fields are untouched.
    EXPECT_EQ(r.value("symbol", std::string()), "LTC");
    EXPECT_EQ(r.value("merged_child_symbol", std::string()), "DOGE");
    EXPECT_EQ(r.value("block_period", 0), 150);
}

TEST(CurrencyInfoPayees, LtcOwnerMergedAddressIsTheEffectiveOneWhenNoneIsSet)
{
    // No --node-owner-merged-address: the fee shares carry the DOGE P2PKH of
    // the owner's own key (resolve_operator_merged_script P2), and that is
    // what the field says.
    LtcRig rig(false, 1.0, kOwnerLtc, /*owner_doge=*/"");
    const auto r = rig.mi.rest_web_currency_info();
    EXPECT_EQ(r.at("node_owner_address"), kOwnerLtc);
    EXPECT_EQ(r.at("node_owner_merged_addresses"), (nlohmann::json{{"DOGE", kOwnerDogeKey}}));
}

TEST(CurrencyInfoPayees, LtcWithoutFeeHasNoOwnerButKeepsTheDonation)
{
    LtcRig rig(false, /*fee=*/0.0, kOwnerLtc, kOwnerDoge);
    auto r = rig.mi.rest_web_currency_info();
    expect_payee_fields_present(r);
    EXPECT_EQ(r.at("node_owner_address"), "");
    EXPECT_EQ(r.at("node_owner_merged_addresses"), nlohmann::json::object());
    EXPECT_EQ(r.at("donation_address"), kDonationLtc);
    EXPECT_EQ(r.at("merged_donation_addresses"), (nlohmann::json{{"DOGE", kDonationDoge}}));

    // --fee 0 with an owner script and operator scripts still installed: no
    // fee share is minted to them, so no owner is named.
    rig.mi.set_node_fee(0.0, p2pkh(0x11));
    rig.mi.set_operator_merged_scripts({{98u, p2pkh(0x44)}});
    r = rig.mi.rest_web_currency_info();
    EXPECT_EQ(r.at("node_owner_address"), "");
    EXPECT_EQ(r.at("node_owner_merged_addresses"), nlohmann::json::object());
}

TEST(CurrencyInfoPayees, LtcTestnetRendersOnTheTestNetworks)
{
    LtcRig rig(/*testnet=*/true, 1.0, kOwnerLtcTest, "");
    const auto r = rig.mi.rest_web_currency_info();
    EXPECT_EQ(r.at("node_owner_address"), kOwnerLtcTest);
    EXPECT_EQ(r.at("node_owner_merged_addresses"), (nlohmann::json{{"DOGE", kOwnerDogeKeyT}}));
    EXPECT_EQ(r.at("donation_address"), kDonationTestnet);
    EXPECT_EQ(r.at("merged_donation_addresses"), (nlohmann::json{{"DOGE", kDonationTestnet}}));
}

TEST(CurrencyInfoPayees, PreV36DonationIsShownByItsKeysP2pkhAddress)
{
    // The V35 donation is P2PK: /current_payouts keys it by the key's P2PKH
    // address, and so does the field.
    LtcRig rig(false, 1.0, kOwnerLtc, "", /*merged=*/false, true, /*share_version=*/35);
    const auto r = rig.mi.rest_web_currency_info();
    EXPECT_EQ(r.at("donation_address"), kDonationLtcV35);
}

TEST(CurrencyInfoPayees, NoMergedChainOrACreateauxblockChainHasNoMergedPayees)
{
    {
        LtcRig rig(false, 1.0, kOwnerLtc, kOwnerDoge, /*merged=*/false);
        auto r = rig.mi.rest_web_currency_info();
        EXPECT_EQ(r.at("node_owner_address"), kOwnerLtc);
        EXPECT_EQ(r.at("node_owner_merged_addresses"), nlohmann::json::object());
        EXPECT_EQ(r.at("merged_donation_addresses"), nlohmann::json::object());
        // An operator script for a chain the node does not mine: not named.
        rig.mi.set_operator_merged_scripts({{98u, p2pkh(0x44)}});
        r = rig.mi.rest_web_currency_info();
        EXPECT_EQ(r.at("node_owner_merged_addresses"), nlohmann::json::object());
    }
    {
        // createauxblock mode: the DOGE daemon builds the coinbase (no
        // donation output); the fee shares still carry the DOGE owner address.
        LtcRig rig(false, 1.0, kOwnerLtc, kOwnerDoge, /*merged=*/true, /*multiaddress=*/false);
        const auto r = rig.mi.rest_web_currency_info();
        EXPECT_EQ(r.at("node_owner_merged_addresses"), (nlohmann::json{{"DOGE", kOwnerDoge}}));
        EXPECT_EQ(r.at("merged_donation_addresses"), nlohmann::json::object());
    }
}

TEST(CurrencyInfoPayees, DashOwnerComesFromTheSameCoreAccessor)
{
    // main_dash.cpp sets the real fee through set_node_fee_from_address and no
    // donation script / merged chain on the MiningInterface.
    core::MiningInterface mi(false, nullptr, Blockchain::DASH);
    mi.set_node_fee_from_address(1.0, kOwnerDash);
    const auto r = mi.rest_web_currency_info();
    expect_payee_fields_present(r);
    EXPECT_EQ(r.at("node_owner_address"), kOwnerDash);
    EXPECT_EQ(r.at("node_owner_merged_addresses"), nlohmann::json::object());
    EXPECT_EQ(r.at("donation_address"), "");
    EXPECT_EQ(r.at("merged_donation_addresses"), nlohmann::json::object());
}

TEST(CurrencyInfoPayees, CoinsWithoutAnAddressFormHereStayEmpty)
{
    // Nothing configured: present and empty.
    {
        core::MiningInterface mi(false, nullptr, Blockchain::BITCOIN);
        const auto r = mi.rest_web_currency_info();
        expect_payee_fields_present(r);
        EXPECT_EQ(r.at("node_owner_address"), "");
        EXPECT_EQ(r.at("donation_address"), "");
    }
    // DGB and BCH (CashAddr, on Blockchain::BITCOIN) would render as Bitcoin
    // addresses: empty instead.
    {
        core::MiningInterface mi(false, nullptr, Blockchain::DIGIBYTE);
        mi.set_node_fee(1.0, p2pkh(0x11));
        mi.set_donation_script(core::donation::get_donation_script(36));
        const auto r = mi.rest_web_currency_info();
        EXPECT_EQ(r.at("node_owner_address"), "");
        EXPECT_EQ(r.at("donation_address"), "");
    }
    {
        core::MiningInterface mi(false, nullptr, Blockchain::BITCOIN);
        mi.set_coin_label("BCH");
        mi.set_node_fee(1.0, p2pkh(0x11));
        mi.set_donation_script(core::donation::get_donation_script(36));
        const auto r = mi.rest_web_currency_info();
        EXPECT_EQ(r.at("node_owner_address"), "");
        EXPECT_EQ(r.at("donation_address"), "");
    }
}
