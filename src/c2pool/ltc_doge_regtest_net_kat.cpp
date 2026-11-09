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

    // DOGE createauxblock fallback address: mainnet/testnet unchanged, regtest
    // gets the version-111 encoding of the same zero hash160 (validateaddress
    // isvalid=true on dogecoind 1.14.9 -regtest; the testnet one is invalid there).
    CHECK(std::string(doge_aux_fallback_address(false, false)) == "DDogepartyxxxxxxxxxxxxxxxxxxw1dfzr");
    CHECK(std::string(doge_aux_fallback_address(true,  false)) == "nUCAGGgZEPN1QyknmQe1oAku817bQAFKFt");
    CHECK(std::string(doge_aux_fallback_address(true,  true))  == "mfWxJ45yp2SFn7UciZyNpvDKrzbhyfKrY8");
    CHECK(std::string(doge_aux_fallback_address(false, true))  == "mfWxJ45yp2SFn7UciZyNpvDKrzbhyfKrY8");

    // DOGE aux P2P port policy (--merged DOGE spec).
    // Embedded on (the default): unchanged, the network default is used.
    CHECK(doge_aux_p2p_port(0, -1, 22556, true) == 22556);
    CHECK(doge_aux_p2p_port(0, -1, 18444, true) == 18444);
    // THE FIX: embedded off + no explicit port -> 0 (was the default port).
    CHECK(doge_aux_p2p_port(0, -1, 44556, false) == 0);
    CHECK(doge_aux_p2p_port(0, -1, 18444, false) == 0);
    // Explicit ports still win, embedded on or off.
    for (bool emb : {false, true}) {
        CHECK(doge_aux_p2p_port(0, 18444, 44556, emb) == 18444);  // 7th field
        CHECK(doge_aux_p2p_port(0, 0, 44556, emb) == 0);          // 7th field ":0" = off
        CHECK(doge_aux_p2p_port(22556, -1, 44556, emb) == 22556); // --doge-p2p-port
        CHECK(doge_aux_p2p_port(22556, 0, 44556, emb) == 22556);  // flag beats ":0"
        CHECK(doge_aux_p2p_port(22556, 18444, 44556, emb) == 22556);
    }

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
