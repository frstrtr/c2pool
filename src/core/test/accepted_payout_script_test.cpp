// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The job payout script of an accepted login (rides core_test).
//
// core::StratumSession::send_notify_work built every accepted payout with the
// chain-agnostic address_to_script. Its P2SH whitelist and HRP list do not
// know every coin: a DigiByte P2SH "S..." (0x3f) became a P2PKH of the
// redeem-script hash (nobody can spend it) and "dgb1..." became nothing, while
// the DGB mint (classify_address_for_coin with DGB's own versions) built the
// right script, so the share's ref never matched the job's and such miners
// were never credited. accepted_payout_script uses the coin's own
// classification for its own addresses when the coin published its
// acceptance, and address_to_script otherwise.
// Pinned: every LTC address form gives byte-for-byte the same script as
// before; a coin with no acceptance (BTC/BCH/DASH/BIP110) takes exactly
// address_to_script; DGB P2SH and bech32 get their own script type; a
// configured merged chain's address keeps address_to_script.
// ---------------------------------------------------------------------------

#include <core/address_utils.hpp>

#include <btclibs/bech32.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

namespace {

using Bytes = std::vector<unsigned char>;

Bytes h(unsigned char fill, size_t n = 20) { return Bytes(n, fill); }
Bytes p2pkh(const Bytes& k) { Bytes s{0x76, 0xa9, 0x14}; s.insert(s.end(), k.begin(), k.end()); s.push_back(0x88); s.push_back(0xac); return s; }
Bytes p2sh(const Bytes& k) { Bytes s{0xa9, 0x14}; s.insert(s.end(), k.begin(), k.end()); s.push_back(0x87); return s; }
Bytes witness(int ver, const Bytes& prog)
{
    Bytes s{static_cast<unsigned char>(ver == 0 ? 0x00 : 0x50 + ver), static_cast<unsigned char>(prog.size())};
    s.insert(s.end(), prog.begin(), prog.end());
    return s;
}

// LTC's acceptance (impl/ltc/address_encoding.hpp): mainnet P2PKH 48, P2SH
// {50, 5}, "ltc"; testnet P2PKH 111, P2SH {196, 58}, "tltc".
core::CoinAddressAcceptance ltc(bool testnet)
{
    core::CoinAddressAcceptance a;
    a.p2pkh_versions = {static_cast<uint8_t>(testnet ? 111 : 48)};
    a.p2sh_versions = testnet ? std::vector<uint8_t>{196, 58} : std::vector<uint8_t>{50, 5};
    a.bech32_hrps = {testnet ? "tltc" : "ltc"};
    return a;
}

// DGB's acceptance (impl/dgb/address_encoding.hpp): mainnet 30 / 63 / "dgb".
core::CoinAddressAcceptance dgb_main()
{
    core::CoinAddressAcceptance a;
    a.p2pkh_versions = {30};
    a.p2sh_versions = {63};
    a.bech32_hrps = {"dgb"};
    return a;
}

std::vector<std::string> ltc_addresses(bool testnet)
{
    const auto acc = ltc(testnet);
    const std::string hrp = acc.bech32_hrps.front();
    std::vector<std::string> out;
    out.push_back(core::script_to_address(p2pkh(h(0x11)), "", acc.p2pkh_versions[0], acc.p2sh_versions[0]));
    for (auto v : acc.p2sh_versions)
        out.push_back(core::script_to_address(p2sh(h(0x22)), "", acc.p2pkh_versions[0], v));
    out.push_back(core::script_to_address(witness(0, h(0x33)), hrp, acc.p2pkh_versions[0], acc.p2sh_versions[0]));
    out.push_back(core::script_to_address(witness(0, h(0x44, 32)), hrp, acc.p2pkh_versions[0], acc.p2sh_versions[0]));
    const auto p2tr = bech32::encode_segwit(hrp, 1, std::vector<uint8_t>(32, 0x55));
    if (!p2tr.empty())
        out.push_back(p2tr);
    return out;
}

} // namespace

TEST(AcceptedPayoutScript, LtcAddressesAreByteIdentical)
{
    for (bool testnet : {false, true}) {
        const auto acc = ltc(testnet);
        const auto addrs = ltc_addresses(testnet);
        ASSERT_GE(addrs.size(), 5u);
        for (const auto& a : addrs) {
            ASSERT_FALSE(a.empty());
            Bytes own;
            ASSERT_EQ(core::classify_address_for_coin(a, acc, own), core::AddressCoinMatch::Own) << a;
            EXPECT_EQ(core::accepted_payout_script(a, acc), core::address_to_script(a)) << a;
            EXPECT_FALSE(core::address_to_script(a).empty()) << a;
        }
    }
}

TEST(AcceptedPayoutScript, NoPublishedAcceptanceTakesAddressToScript)
{
    // BTC/BCH/DASH/BIP110 publish no acceptance: exactly address_to_script,
    // for any address (including ones address_to_script mis-types).
    const core::CoinAddressAcceptance none;
    const std::vector<std::string> addrs = {
        core::script_to_address(p2pkh(h(0x11)), "", 0, 5),
        core::script_to_address(p2sh(h(0x22)), "", 0, 5),
        core::script_to_address(witness(0, h(0x33)), "bc", 0, 5),
        core::script_to_address(p2sh(h(0x66)), "", 30, 63),       // a DGB "S..."
        core::script_to_address(witness(0, h(0x77)), "dgb", 30, 63),
        "not-an-address",
    };
    for (const auto& a : addrs)
        EXPECT_EQ(core::accepted_payout_script(a, none), core::address_to_script(a)) << a;
}

TEST(AcceptedPayoutScript, DgbP2shAndBech32PayTheirOwnScript)
{
    const auto acc = dgb_main();
    const std::string s_addr = core::script_to_address(p2sh(h(0x66)), "", 30, 63);
    const std::string bech = core::script_to_address(witness(0, h(0x77)), "dgb", 30, 63);
    const std::string d_addr = core::script_to_address(p2pkh(h(0x88)), "", 30, 63);
    ASSERT_EQ(s_addr.front(), 'S');
    ASSERT_EQ(bech.rfind("dgb1", 0), 0u);
    ASSERT_EQ(d_addr.front(), 'D');

    // Before: the chain-agnostic decoder mis-typed / lost them.
    EXPECT_EQ(core::address_to_script(s_addr), p2pkh(h(0x66))) << "the old job script (unspendable)";
    EXPECT_TRUE(core::address_to_script(bech).empty()) << "the old job script (none)";
    // Now: the coin's own script type.
    EXPECT_EQ(core::accepted_payout_script(s_addr, acc), p2sh(h(0x66)));
    EXPECT_EQ(core::accepted_payout_script(bech, acc), witness(0, h(0x77)));
    // A DGB P2PKH was already right and stays the same.
    EXPECT_EQ(core::accepted_payout_script(d_addr, acc), p2pkh(h(0x88)));
    EXPECT_EQ(core::accepted_payout_script(d_addr, acc), core::address_to_script(d_addr));
}

TEST(AcceptedPayoutScript, ConfiguredMergedChainAddressKeepsAddressToScript)
{
    // A DOGE P2SH "A..." (22) accepted on a DGB node because DOGE is a
    // configured merged chain: Foreign to DGB's own classification, so the job
    // script is address_to_script's, unchanged.
    const auto acc = dgb_main();
    const std::string doge_a = core::script_to_address(p2sh(h(0x99)), "", 30, 22);
    Bytes own;
    ASSERT_EQ(core::classify_address_for_coin(doge_a, acc, own), core::AddressCoinMatch::Foreign);
    EXPECT_EQ(core::accepted_payout_script(doge_a, acc), core::address_to_script(doge_a));
}
