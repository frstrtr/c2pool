// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KAT for issue #961: cross-coin address pay-misdirection.
//
// core::classify_address_for_coin() is the money-path gate that decides whether
// a miner-supplied payout address belongs to the RUNNING coin. Before it, the
// chain-agnostic address_to_script() would decode ANY supported coin's version
// byte / bech32 HRP and build a scriptPubKey for whatever coin the node runs —
// so a foreign address (valid on another chain) was silently repurposed into a
// wrong-coin script and the miner's funds were MISDIRECTED.
//
// This KAT proves, for BTC / LTC / DOGE / DASH / BCH / DGB:
//   • ACCEPT-OWN   : each coin's own P2PKH / P2SH (and bech32 where it exists)
//                    address classifies as Own and yields the correct script.
//   • REJECT-FOREIGN: an address whose version byte / HRP is NOT in the running
//                     coin's accepted set classifies as Foreign and yields an
//                     EMPTY script (never a repurposed wrong-coin payment).
//
// Addresses are CONSTRUCTED in-test from a fixed hash160 with each coin's real
// chainparams version byte (via EncodeBase58Check / bech32::encode_segwit), so
// the checksums are always valid and the version constants are pinned by the
// assertions themselves — a wrong constant in the wiring makes the matching
// coin's own address classify as Foreign and fails the test.

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include <core/address_utils.hpp>

#include <btclibs/base58.h>
#include <btclibs/bech32.h>
#include <btclibs/span.h>

using core::AddressCoinMatch;
using core::classify_address_for_coin;

namespace {

// A fixed, arbitrary 20-byte hash160 used for every constructed address.
const std::vector<uint8_t> kH160 = {
    0x62, 0xe9, 0x07, 0xb1, 0x5c, 0xbf, 0x27, 0xd5, 0x42, 0x53,
    0x99, 0xeb, 0xf6, 0xf0, 0xfb, 0x50, 0xeb, 0xb8, 0x8f, 0x18};

// Encode a Base58Check address: 1 version byte || 20-byte hash160.
std::string b58(uint8_t version)
{
    std::vector<unsigned char> payload;
    payload.reserve(21);
    payload.push_back(version);
    payload.insert(payload.end(), kH160.begin(), kH160.end());
    return EncodeBase58Check(Span<const unsigned char>(payload.data(), payload.size()));
}

// Encode a native-segwit v0 P2WPKH address for the given bech32 HRP.
std::string bech32_v0(const std::string& hrp)
{
    return bech32::encode_segwit(hrp, 0, kH160);
}

// Expected scripts for kH160.
std::vector<unsigned char> p2pkh_script()
{
    std::vector<unsigned char> s{0x76, 0xa9, 0x14};
    s.insert(s.end(), kH160.begin(), kH160.end());
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}
std::vector<unsigned char> p2sh_script()
{
    std::vector<unsigned char> s{0xa9, 0x14};
    s.insert(s.end(), kH160.begin(), kH160.end());
    s.push_back(0x87);
    return s;
}
std::vector<unsigned char> p2wpkh_script()
{
    std::vector<unsigned char> s{0x00, 0x14};
    s.insert(s.end(), kH160.begin(), kH160.end());
    return s;
}

// One running coin's accepted set (mainnet), mirroring each chain's chainparams.
struct Coin {
    std::string name;
    std::vector<uint8_t> p2pkh;   // accepted P2PKH version bytes
    std::vector<uint8_t> p2sh;    // accepted P2SH version bytes
    std::vector<std::string> hrps; // accepted bech32 HRPs (bare, no trailing '1')
};

// Mainnet chainparams (verified against each coin's chainparams.cpp):
//   BTC : P2PKH 0x00, P2SH 0x05, hrp "bc"
//   LTC : P2PKH 0x30, P2SH 0x32 (+ legacy 0x05), hrp "ltc"
//   DOGE: P2PKH 0x1e, P2SH 0x16, no bech32
//   DASH: P2PKH 0x4c, P2SH 0x10, no bech32
//   BCH : P2PKH 0x00, P2SH 0x05 (legacy base58 == BTC), CashAddr via decoder
//   DGB : P2PKH 0x1e, P2SH 0x3f, hrp "dgb"
const std::vector<Coin> kCoins = {
    {"BTC",  {0x00},       {0x05},        {"bc"}},
    {"LTC",  {0x30},       {0x32, 0x05},  {"ltc"}},
    {"DOGE", {0x1e},       {0x16},        {}},
    {"DASH", {0x4c},       {0x10},        {}},
    {"BCH",  {0x00},       {0x05},        {}},
    {"DGB",  {0x1e},       {0x3f},        {"dgb"}},
};

const Coin& coin(const std::string& name)
{
    for (const auto& c : kCoins) if (c.name == name) return c;
    ADD_FAILURE() << "unknown coin " << name;
    return kCoins[0];
}

AddressCoinMatch run(const Coin& c, const std::string& addr, std::vector<unsigned char>& script)
{
    return classify_address_for_coin(addr, c.p2pkh, c.p2sh, c.hrps, script);
}

bool set_has(const std::vector<uint8_t>& v, uint8_t x)
{
    for (uint8_t e : v) if (e == x) return true;
    return false;
}
bool set_has(const std::vector<std::string>& v, const std::string& x)
{
    for (const auto& e : v) if (e == x) return true;
    return false;
}

} // namespace

// ── ACCEPT-OWN: each coin accepts its own P2PKH / P2SH address ───────────────
TEST(AddressCoinValidation, AcceptsOwnP2PKH)
{
    for (const auto& c : kCoins) {
        const std::string addr = b58(c.p2pkh.front());
        std::vector<unsigned char> script;
        EXPECT_EQ(run(c, addr, script), AddressCoinMatch::Own)
            << c.name << " must accept its own P2PKH address " << addr;
        EXPECT_EQ(script, p2pkh_script()) << c.name << " P2PKH script mismatch";
    }
}

TEST(AddressCoinValidation, AcceptsOwnP2SH)
{
    for (const auto& c : kCoins) {
        const std::string addr = b58(c.p2sh.front());
        std::vector<unsigned char> script;
        EXPECT_EQ(run(c, addr, script), AddressCoinMatch::Own)
            << c.name << " must accept its own P2SH address " << addr;
        EXPECT_EQ(script, p2sh_script()) << c.name << " P2SH script mismatch";
    }
}

TEST(AddressCoinValidation, AcceptsOwnBech32)
{
    for (const auto& c : kCoins) {
        if (c.hrps.empty()) continue;  // DOGE/DASH/BCH have no segwit
        const std::string addr = bech32_v0(c.hrps.front());
        std::vector<unsigned char> script;
        EXPECT_EQ(run(c, addr, script), AddressCoinMatch::Own)
            << c.name << " must accept its own bech32 address " << addr;
        EXPECT_EQ(script, p2wpkh_script()) << c.name << " P2WPKH script mismatch";
    }
}

// ── REJECT-FOREIGN: full cross product of base58 addresses ───────────────────
// Every coin's own P2PKH and P2SH address is offered to every OTHER coin. The
// expected verdict is derived from the running coin's accepted set: Own iff the
// version byte is in the set (handles the inherent BTC/BCH 0x00,0x05 and
// DOGE/DGB 0x1e collisions), Foreign otherwise — and Foreign MUST yield an
// empty script so the money path can never emit a wrong-coin payment.
TEST(AddressCoinValidation, RejectsForeignBase58)
{
    struct Sample { std::string owner; uint8_t version; };
    std::vector<Sample> samples;
    for (const auto& c : kCoins) {
        for (uint8_t v : c.p2pkh) samples.push_back({c.name, v});
        for (uint8_t v : c.p2sh)  samples.push_back({c.name, v});
    }

    for (const auto& running : kCoins) {
        for (const auto& s : samples) {
            const std::string addr = b58(s.version);
            std::vector<unsigned char> script;
            auto verdict = run(running, addr, script);
            const bool own = set_has(running.p2pkh, s.version) ||
                             set_has(running.p2sh,  s.version);
            if (own) {
                EXPECT_EQ(verdict, AddressCoinMatch::Own)
                    << running.name << " should accept version 0x"
                    << std::hex << int(s.version) << " (from " << s.owner << ")";
                EXPECT_FALSE(script.empty());
            } else {
                EXPECT_EQ(verdict, AddressCoinMatch::Foreign)
                    << running.name << " must REJECT foreign version 0x"
                    << std::hex << int(s.version) << " (from " << s.owner << ")";
                EXPECT_TRUE(script.empty())
                    << running.name << " emitted a script for a foreign address "
                    << "— MISDIRECTION (issue #961)";
            }
        }
    }
}

// ── REJECT-FOREIGN: a bech32 address for another chain ───────────────────────
// A well-formed segwit address under a HRP the running coin does not accept is
// Foreign (never repurposed), and a coin with no segwit at all rejects every
// bech32 address it is offered.
TEST(AddressCoinValidation, RejectsForeignBech32)
{
    const std::vector<std::string> all_hrps = {"bc", "ltc", "dgb", "tb"};
    for (const auto& running : kCoins) {
        for (const auto& hrp : all_hrps) {
            const std::string addr = bech32_v0(hrp);
            std::vector<unsigned char> script;
            auto verdict = run(running, addr, script);
            if (set_has(running.hrps, hrp)) {
                EXPECT_EQ(verdict, AddressCoinMatch::Own)
                    << running.name << " should accept its own hrp " << hrp;
            } else {
                EXPECT_EQ(verdict, AddressCoinMatch::Foreign)
                    << running.name << " must REJECT foreign bech32 hrp " << hrp;
                EXPECT_TRUE(script.empty())
                    << running.name << " emitted a script for a foreign bech32 "
                    << "address — MISDIRECTION (issue #961)";
            }
        }
    }
}

// ── Concrete money-leak cases with real, checksum-valid mainnet addresses ────
// These pin the exact behaviour the issue describes, independent of the
// constructed-address matrix above.
TEST(AddressCoinValidation, ConcreteMisdirectionCases)
{
    std::vector<unsigned char> script;

    // Genesis BTC P2PKH — Own on BTC, Foreign on DASH / DGB / LTC.
    const std::string btc_p2pkh = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    EXPECT_EQ(run(coin("BTC"), btc_p2pkh, script), AddressCoinMatch::Own);
    EXPECT_EQ(run(coin("DASH"), btc_p2pkh, script), AddressCoinMatch::Foreign);
    EXPECT_TRUE(script.empty());
    EXPECT_EQ(run(coin("DGB"), btc_p2pkh, script), AddressCoinMatch::Foreign);
    EXPECT_TRUE(script.empty());
    EXPECT_EQ(run(coin("LTC"), btc_p2pkh, script), AddressCoinMatch::Foreign);
    EXPECT_TRUE(script.empty());

    // BIP173 canonical BTC bech32 — Own on BTC, Foreign on DGB (has segwit) and
    // DASH (no segwit).
    const std::string btc_bech32 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    EXPECT_EQ(run(coin("BTC"), btc_bech32, script), AddressCoinMatch::Own);
    EXPECT_FALSE(script.empty());
    EXPECT_EQ(run(coin("DGB"), btc_bech32, script), AddressCoinMatch::Foreign);
    EXPECT_TRUE(script.empty());
    EXPECT_EQ(run(coin("DASH"), btc_bech32, script), AddressCoinMatch::Foreign);
    EXPECT_TRUE(script.empty());

    // A CashAddr-shaped string (BCH's own format) is not Base58Check/segwit, so
    // it classifies as Invalid — the caller falls through to the coin-specific
    // CashAddr decoder. It must NEVER classify as Own on a non-BCH coin.
    const std::string cashaddr = "qqg8m40vjdvxfp6yj6f6f0f0jh9c0f4y8q0q0q0q0q";
    EXPECT_EQ(run(coin("BTC"), cashaddr, script), AddressCoinMatch::Invalid);
    EXPECT_TRUE(script.empty());
    EXPECT_EQ(run(coin("DASH"), cashaddr, script), AddressCoinMatch::Invalid);
    EXPECT_TRUE(script.empty());

    // Garbage / empty → Invalid, empty script.
    EXPECT_EQ(run(coin("BTC"), "", script), AddressCoinMatch::Invalid);
    EXPECT_TRUE(script.empty());
    EXPECT_EQ(run(coin("BTC"), "not an address", script), AddressCoinMatch::Invalid);
    EXPECT_TRUE(script.empty());
}

// ── LTC lane: an UNCONFIGURED foreign address is rejected (issue #961 blocker 1)
// The production LTC/DOGE merged-mining server built its per-job coinbase payout
// with the chain-agnostic address_to_script(), so a foreign-coin address whose
// coin is NOT a configured merged chain was repurposed into an LTC script from a
// hash160 the miner does not control on Litecoin — the money leak. At the
// classify gate (what send_notify_work now consults before building the script),
// LTC must classify every non-LTC address as Foreign and yield an EMPTY script.
// (The stratum server then additionally honours a CONFIGURED merged chain's
// address via the shared merged-chain table; the classify gate itself, tested
// here, is the reject-unconfigured-foreign half.)
TEST(AddressCoinValidation, LtcRejectsUnconfiguredForeign)
{
    const Coin& ltc = coin("LTC");
    std::vector<unsigned char> script;

    // A DOGE address (0x1e) — the classic "unconfigured merged coin" case. When
    // DOGE is NOT a configured merged chain, LTC must NOT pay it.
    EXPECT_EQ(run(ltc, b58(0x1e), script), AddressCoinMatch::Foreign);
    EXPECT_TRUE(script.empty())
        << "LTC repurposed a DOGE address into an LTC script — MISDIRECTION (#961)";

    // A DASH address (0x4c) — a coin LTC can never merge-mine.
    EXPECT_EQ(run(ltc, b58(0x4c), script), AddressCoinMatch::Foreign);
    EXPECT_TRUE(script.empty());

    // A real BTC mainnet bech32 — Foreign to LTC (HRP "bc" ∉ {"ltc"}), empty.
    EXPECT_EQ(run(ltc, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", script),
              AddressCoinMatch::Foreign);
    EXPECT_TRUE(script.empty());

    // LTC's OWN addresses (incl. the legacy 0x05 P2SH collision) stay Own — the
    // reject must not become a false-reject of a real LTC payout.
    EXPECT_EQ(run(ltc, b58(0x30), script), AddressCoinMatch::Own);       // L... P2PKH
    EXPECT_FALSE(script.empty());
    EXPECT_EQ(run(ltc, b58(0x32), script), AddressCoinMatch::Own);       // M... P2SH
    EXPECT_FALSE(script.empty());
    EXPECT_EQ(run(ltc, b58(0x05), script), AddressCoinMatch::Own);       // legacy 3... P2SH
    EXPECT_FALSE(script.empty());
    EXPECT_EQ(run(ltc, bech32_v0("ltc"), script), AddressCoinMatch::Own);
    EXPECT_FALSE(script.empty());
}

// ── Regtest addresses are ACCEPTED (issue #961 blocker 2, FALSE-REJECT fix) ───
// The wirings previously keyed the accepted set on a single is_testnet_ bool, so
// a --regtest node (testnet=false) resolved to the MAINNET set and rejected a
// legitimate regtest payout address as Foreign. The registry helpers now derive
// the set from the TRUE network. These sets mirror what
// {btc,dgb,ltc}::address_acceptance(testnet,regtest) returns for regtest:
// bitcoin-family regtest reuses the TESTNET base58 version bytes and swaps the
// bech32 HRP (BTC "bcrt", DGB "dgbrt", LTC "rltc"). A regtest own address must
// classify as Own; a MAINNET address must be Foreign under the regtest set
// (proving the set is network-derived, not mainnet-or-not).
TEST(AddressCoinValidation, AcceptsRegtestAddresses)
{
    struct RegtestSet { std::string name; Coin set; uint8_t mainnet_p2pkh; };
    const std::vector<RegtestSet> regtests = {
        // BTC regtest: testnet 0x6f/0xc4 + hrp "bcrt"; mainnet P2PKH 0x00.
        {"BTC",  {"BTCrt",  {0x6f}, {0xc4}, {"bcrt"}},  0x00},
        // DGB regtest: testnet 0x7e/0x8c + hrp "dgbrt"; mainnet P2PKH 0x1e.
        {"DGB",  {"DGBrt",  {0x7e}, {0x8c}, {"dgbrt"}}, 0x1e},
        // LTC regtest: testnet 111/196(+58) + hrp "rltc"; mainnet P2PKH 0x30.
        {"LTC",  {"LTCrt",  {0x6f}, {0xc4, 0x3a}, {"rltc"}}, 0x30},
    };

    for (const auto& r : regtests) {
        std::vector<unsigned char> script;

        // Regtest own P2PKH / P2SH / bech32 all classify Own with correct scripts.
        EXPECT_EQ(run(r.set, b58(r.set.p2pkh.front()), script), AddressCoinMatch::Own)
            << r.name << " regtest must accept its own P2PKH address";
        EXPECT_EQ(script, p2pkh_script());
        EXPECT_EQ(run(r.set, b58(r.set.p2sh.front()), script), AddressCoinMatch::Own)
            << r.name << " regtest must accept its own P2SH address";
        EXPECT_EQ(script, p2sh_script());
        EXPECT_EQ(run(r.set, bech32_v0(r.set.hrps.front()), script), AddressCoinMatch::Own)
            << r.name << " regtest must accept its own bech32 address";
        EXPECT_EQ(script, p2wpkh_script());

        // A MAINNET address of the same coin is Foreign under the regtest set —
        // the network-derived set is what closes the FALSE-REJECT without
        // silently widening acceptance back to mainnet.
        EXPECT_EQ(run(r.set, b58(r.mainnet_p2pkh), script), AddressCoinMatch::Foreign)
            << r.name << " regtest set must not accept a mainnet address";
        EXPECT_TRUE(script.empty());
    }
}
