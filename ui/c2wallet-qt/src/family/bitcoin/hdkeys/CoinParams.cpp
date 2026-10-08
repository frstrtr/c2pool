// SPDX-License-Identifier: AGPL-3.0-or-later
#include "CoinParams.hpp"

namespace c2w::hdkeys {

// Standard Bitcoin xprv/xpub pair, reused verbatim by DASH/DGB/BCH.
static constexpr Bip32Versions kStd{0x0488ADE4u, 0x0488B21Eu};

const std::vector<CoinParams>& all_coins()
{
    static const std::vector<CoinParams> C = {
        // name        ticker  slip44 p2pkh p2sh  wif   hrp     testnet  std_bip32
        {"Bitcoin",     "BTC",   0,   0x00, 0x05, 0x80, "bc",   false, kStd},
        {"Bitcoin test","BTC-t", 1,   0x6f, 0xc4, 0xef, "tb",   true,  {0x04358394u, 0x043587CFu}},
        {"Litecoin",    "LTC",   2,   0x30, 0x32, 0xb0, "ltc",  false, {0x019D9CFEu, 0x019DA462u}},
        {"Dogecoin",    "DOGE",  3,   0x1e, 0x16, 0x9e, "",     false, {0x02FAC398u, 0x02FACAFDu}},
        {"Dash",        "DASH",  5,   0x4c, 0x10, 0xcc, "",     false, kStd},
        {"DigiByte",    "DGB",   20,  0x1e, 0x3f, 0x80, "dgb",  false, kStd},
        {"Bitcoin Cash","BCH",   145, 0x00, 0x05, 0x80, "",     false, kStd},
    };
    return C;
}

const CoinParams* coin_by_ticker(const std::string& ticker)
{
    for (const auto& c : all_coins())
        if (ticker == c.ticker) return &c;
    return nullptr;
}

std::vector<const CoinParams*> coins_by_wif_version(uint8_t version)
{
    std::vector<const CoinParams*> out;
    for (const auto& c : all_coins())
        if (c.wif_version == version) out.push_back(&c);
    return out;
}

// SLIP-132 + per-coin BIP32 prefix registry. Each (priv,pub) pair yields two
// entries so parse() can resolve either half. Single-key hints only (M1-A core;
// multisig Yprv/Zprv land with the constructor phases).
const Slip132Entry* lookup_bip32_version(uint32_t version)
{
    static const std::vector<Slip132Entry> R = {
        // Bitcoin mainnet
        {0x0488ADE4u, true,  {0x0488ADE4u, 0x0488B21Eu}, ScriptHint::P2PKH,       "BTC", "xprv"},
        {0x0488B21Eu, false, {0x0488ADE4u, 0x0488B21Eu}, ScriptHint::P2PKH,       "BTC", "xpub"},
        {0x049D7878u, true,  {0x049D7878u, 0x049D7CB2u}, ScriptHint::P2SH_P2WPKH, "BTC", "yprv"},
        {0x049D7CB2u, false, {0x049D7878u, 0x049D7CB2u}, ScriptHint::P2SH_P2WPKH, "BTC", "ypub"},
        {0x04B2430Cu, true,  {0x04B2430Cu, 0x04B24746u}, ScriptHint::P2WPKH,      "BTC", "zprv"},
        {0x04B24746u, false, {0x04B2430Cu, 0x04B24746u}, ScriptHint::P2WPKH,      "BTC", "zpub"},
        // Bitcoin testnet
        {0x04358394u, true,  {0x04358394u, 0x043587CFu}, ScriptHint::P2PKH,       "BTC-t", "tprv"},
        {0x043587CFu, false, {0x04358394u, 0x043587CFu}, ScriptHint::P2PKH,       "BTC-t", "tpub"},
        {0x044A4E28u, true,  {0x044A4E28u, 0x044A5262u}, ScriptHint::P2SH_P2WPKH, "BTC-t", "uprv"},
        {0x044A5262u, false, {0x044A4E28u, 0x044A5262u}, ScriptHint::P2SH_P2WPKH, "BTC-t", "upub"},
        {0x045F18BCu, true,  {0x045F18BCu, 0x045F1CF6u}, ScriptHint::P2WPKH,      "BTC-t", "vprv"},
        {0x045F1CF6u, false, {0x045F18BCu, 0x045F1CF6u}, ScriptHint::P2WPKH,      "BTC-t", "vpub"},
        // Litecoin
        {0x019D9CFEu, true,  {0x019D9CFEu, 0x019DA462u}, ScriptHint::P2PKH,       "LTC", "Ltpv"},
        {0x019DA462u, false, {0x019D9CFEu, 0x019DA462u}, ScriptHint::P2PKH,       "LTC", "Ltub"},
        {0x01B26792u, true,  {0x01B26792u, 0x01B26EF6u}, ScriptHint::P2SH_P2WPKH, "LTC", "Mtpv"},
        {0x01B26EF6u, false, {0x01B26792u, 0x01B26EF6u}, ScriptHint::P2SH_P2WPKH, "LTC", "Mtub"},
        // Dogecoin
        {0x02FAC398u, true,  {0x02FAC398u, 0x02FACAFDu}, ScriptHint::P2PKH,       "DOGE", "dgpv"},
        {0x02FACAFDu, false, {0x02FAC398u, 0x02FACAFDu}, ScriptHint::P2PKH,       "DOGE", "dgub"},
    };
    for (const auto& e : R)
        if (e.version == version) return &e;
    return nullptr;
}

} // namespace c2w::hdkeys
