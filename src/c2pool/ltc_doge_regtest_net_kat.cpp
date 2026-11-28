// SPDX-License-Identifier: AGPL-3.0-or-later
// KAT: LTC/DOGE daemon network identity (P2P magic + default port), incl. regtest.
// FAILS on master: ltc_doge_chain_net.hpp does not exist there (compile red),
// and the main_ltc.cpp table had no regtest row at all.
#include <c2pool/ltc_doge_chain_net.hpp>
#include <impl/ltc/address_encoding.hpp>
#include <cstdio>
#include <string>
#include <vector>

using namespace c2pool::ltc_doge;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

int main()
{
    // Pre-existing rows: byte-identical to the old main_ltc.cpp lambdas.
    CHECK(p2p_magic_hex("LTC",  false, false, false) == "fbc0b6db");
    CHECK(p2p_magic_hex("ltc",  true,  false, false) == "fdd2c8f1");
    CHECK(p2p_magic_hex("DOGE", false, false, false) == "c0c0c0c0");
    CHECK(p2p_magic_hex("doge", true,  false, false) == "fcc1b7dc");
    CHECK(p2p_magic_hex("DOGE", true,  true,  false) == "d4a1f4a1");
    CHECK(p2p_magic_hex("DOGE", false, true,  false) == "c0c0c0c0"); // t4a needs --testnet
    CHECK(p2p_port("LTC",  false, false, false) == 9333);
    CHECK(p2p_port("LTC",  true,  false, false) == 19335);
    CHECK(p2p_port("DOGE", false, false, false) == 22556);
    CHECK(p2p_port("DOGE", true,  false, false) == 44556);
    CHECK(p2p_port("DOGE", true,  true,  false) == 22556);

    // New regtest rows: fabfb5da for both coins; regtest beats testnet and t4a.
    for (bool tn : {false, true})
        for (bool t4a : {false, true}) {
            CHECK(p2p_magic_hex("LTC",  tn, t4a, true) == "fabfb5da");
            CHECK(p2p_magic_hex("DOGE", tn, t4a, true) == "fabfb5da");
            CHECK(p2p_port("LTC",  tn, t4a, true) == 19444);
            CHECK(p2p_port("DOGE", tn, t4a, true) == 18444);
        }

    // Non-LTC/DOGE symbols are not ours: caller falls through to its own table.
    CHECK(p2p_magic_hex("BTC", false, false, true).empty());
    CHECK(p2p_port("DGB", true, false, true) == 0);

    // LTC stratum payout acceptance (#961 door). Mainnet/testnet unchanged;
    // --regtest publishes litecoind regtest bech32 "rltc" (was "tltc" -> every
    // rltc1 payout door-rejected), same version bytes as testnet.
    {
        using V8 = std::vector<uint8_t>;
        using VS = std::vector<std::string>;
        auto m = ltc::address_acceptance(false);
        CHECK(m.p2pkh_versions == V8{48} && m.p2sh_versions == (V8{50, 5}) && m.bech32_hrps == VS{"ltc"});
        auto t = ltc::address_acceptance(true);
        CHECK(t.p2pkh_versions == V8{111} && t.p2sh_versions == (V8{196, 58}) && t.bech32_hrps == VS{"tltc"});
        CHECK(ltc::address_acceptance(true, false).bech32_hrps == VS{"tltc"});
        for (bool tn : {false, true}) {
            auto r = ltc::address_acceptance(tn, true);
            CHECK(r.p2pkh_versions == V8{111});
            CHECK(r.p2sh_versions == (V8{196, 58}));
            CHECK(r.bech32_hrps == VS{"rltc"});
        }
        CHECK(std::string(ltc::address_encoding(true, true).hrp_bare) == "rltc");
        CHECK(std::string(ltc::address_encoding(true).hrp_bare) == "tltc");
    }

    if (g_fail) { std::printf("ltc_doge_regtest_net_kat: %d FAIL\n", g_fail); return 1; }
    std::printf("ltc_doge_regtest_net_kat: ALL PASS\n");
    return 0;
}
