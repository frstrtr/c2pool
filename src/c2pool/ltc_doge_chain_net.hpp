// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// LTC / DOGE coin-daemon network identity: P2P magic + default P2P port.
//
// Pure policy, standard library only. main_ltc.cpp delegates LTC and DOGE to
// these helpers; the other coins stay in its lambdas.
//
// Why regtest is here: the embedded LTC/DOGE P2P sink has to handshake with a
// regtest litecoind/dogecoind for the G3a node-in-the-loop block test. Before
// this, the table knew only main/testnet(/t4a). Regtest magic is fabfb5da for
// BOTH coins (Litecoin Core and Dogecoin Core CRegTestParams pchMessageStart);
// default ports are 19444 (litecoind) and 18444 (dogecoind).
//
// Precedence: regtest > doge_testnet4alpha > testnet > mainnet.
#include <string>

namespace c2pool::ltc_doge {

inline bool is_ltc(const std::string& s)  { return s == "LTC"  || s == "ltc"; }
inline bool is_doge(const std::string& s) { return s == "DOGE" || s == "doge"; }

// Hex of the 4-byte pchMessageStart, or "" if the symbol is not LTC/DOGE.
inline std::string p2p_magic_hex(const std::string& symbol, bool testnet,
                                 bool doge_testnet4alpha, bool regtest)
{
    if (is_ltc(symbol)) {
        if (regtest) return "fabfb5da";
        return testnet ? "fdd2c8f1" : "fbc0b6db";
    }
    if (is_doge(symbol)) {
        if (regtest) return "fabfb5da";
        if (!testnet) return "c0c0c0c0";
        return doge_testnet4alpha ? "d4a1f4a1" : "fcc1b7dc";
    }
    return "";
}

// Default daemon P2P port, or 0 if the symbol is not LTC/DOGE.
inline int p2p_port(const std::string& symbol, bool testnet,
                    bool doge_testnet4alpha, bool regtest)
{
    if (is_ltc(symbol)) {
        if (regtest) return 19444;
        return testnet ? 19335 : 9333;
    }
    if (is_doge(symbol)) {
        if (regtest) return 18444;
        // t4a uses mainnet-style 22556
        return (testnet && !doge_testnet4alpha) ? 44556 : 22556;
    }
    return 0;
}

} // namespace c2pool::ltc_doge
