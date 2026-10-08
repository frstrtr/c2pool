// SPDX-License-Identifier: AGPL-3.0-or-later
#include "ConvertCoins.hpp"

namespace c2w::convert {

const std::vector<ConvertCoin>& convert_coins()
{
    // Mirrors docs/design/c2wallet-qt.md §4.1 convertibility table.
    //  ticker  p2pkh p2sh  p2pkh_accept   p2sh_accept        hrp     tr     bch   cashaddr        testnet
    static const std::vector<ConvertCoin> kCoins = {
        {"BTC",  0x00, 0x05, {0x00},        {0x05},            "bc",   true,  false, "",            false},
        {"LTC",  0x30, 0x32, {0x30},        {0x32, 0x05},      "ltc",  true,  false, "",            false},
        {"DOGE", 0x1e, 0x16, {0x1e},        {0x16},            "",     false, false, "",            false},
        {"DASH", 0x4c, 0x10, {0x4c},        {0x10},            "",     false, false, "",            false},
        {"DGB",  0x1e, 0x3f, {0x1e},        {0x3f},            "dgb",  true,  false, "",            false},
        {"BCH",  0x00, 0x05, {0x00},        {0x05},            "",     false, true,  "bitcoincash", false},
        {"NMC",  0x34, 0x0d, {0x34},        {0x0d},            "",     false, false, "",            false},
        // Testnet entries (network-mismatch refuse KAT). BTC/LTC testnet share
        // P2PKH 0x6f and P2SH 0xc4; LTC testnet segwit HRP is "tltc".
        {"BTC-t", 0x6f, 0xc4, {0x6f},       {0xc4},            "tb",   true,  false, "",            true},
        {"LTC-t", 0x6f, 0x3a, {0x6f},       {0x3a, 0xc4},      "tltc", true,  false, "",            true},
    };
    return kCoins;
}

const ConvertCoin* convert_coin(const std::string& ticker)
{
    for (const auto& c : convert_coins())
        if (c.ticker == ticker) return &c;
    return nullptr;
}

core::CoinAddressAcceptance acceptance_of(const ConvertCoin& c)
{
    core::CoinAddressAcceptance acc;
    acc.p2pkh_versions = c.p2pkh_accept;
    acc.p2sh_versions  = c.p2sh_accept;
    if (!c.segwit_hrp.empty())
        acc.bech32_hrps.push_back(c.segwit_hrp);   // already BARE (no trailing '1')
    return acc;
}

} // namespace c2w::convert
