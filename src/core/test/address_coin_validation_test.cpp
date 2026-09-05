// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KAT for issue #961: cross-coin address pay-misdirection (the LTC-lane money
// leak) and its remediation. This test is RED on the parent commit (208ba2f7):
// every acceptance set it checks comes from a REAL registry helper
//   ltc::address_acceptance / btc::address_acceptance / bch::address_acceptance /
//   dgb::address_acceptance / bip110::address_acceptance / dash::address_acceptance
// and the payout decision it exercises is core::decide_payout_address() — NONE of
// which exist on the parent. The earlier revision of this file supplied its own
// hardcoded coin tables and called only the pre-existing classify_address_for_coin(),
// so it passed on the parent and proved nothing about the fix (a blind KAT). This
// revision instead:
//   1. Pins each coin's registry-sourced acceptance to its real chainparams
//      (catches a re-typed / drifted version byte — blocker #3), calling the
//      helper, never a literal in the test.
//   2. Exercises the stratum money-path decision core::decide_payout_address()
//      that handle_authorize() (door reject) and send_notify_work() (no-empty-
//      payout guard) both consult (blocker #1): own-coin → AcceptOwn, a
//      CONFIGURED merged chain → AcceptMerged, foreign-and-unconfigured or
//      unparseable → Reject (never a burned / misdirected payout).
//   3. Runs the cross-coin ACCEPT-OWN / REJECT-FOREIGN matrix against those real
//      registry sets, incl. network-derived regtest sets (blocker #2).
//
// Addresses are CONSTRUCTED in-test from a fixed hash160 with each coin's real
// chainparams version byte (via EncodeBase58Check / bech32::encode_segwit), so
// the checksums are always valid and a wrong registry constant makes the matching
// coin's own address classify as Foreign and fails the test.

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include <core/address_utils.hpp>

// The REAL per-coin registry helpers under test (issue #961). Including these and
// calling address_acceptance() is what makes this KAT non-blind and red on parent.
#include <impl/ltc/params.hpp>
#include <impl/btc/config_coin.hpp>
#include <impl/bch/config_coin.hpp>
#include <impl/dgb/params.hpp>
#include <impl/bip110/params.hpp>
#include <impl/dash/params.hpp>

#include <btclibs/base58.h>
#include <btclibs/bech32.h>
#include <btclibs/span.h>

using core::AddressCoinMatch;
using core::CoinAddressAcceptance;
using core::classify_address_for_coin;
using core::decide_payout_address;
using core::MergedChainAddr;
using core::PayoutAddressDecision;

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

// One running coin, its accepted set sourced from the REAL registry helper.
struct Coin {
    std::string name;
    CoinAddressAcceptance acc;
};

// Every set here is REGISTRY-SOURCED (mainnet) — no literals in the test.
const std::vector<Coin> kCoins = {
    {"BTC",    btc::address_acceptance(/*testnet=*/false, /*regtest=*/false)},
    {"LTC",    ltc::address_acceptance(/*testnet=*/false)},
    {"DASH",   dash::address_acceptance(/*testnet=*/false, /*regtest=*/false)},
    {"BCH",    bch::address_acceptance(/*testnet=*/false, /*regtest=*/false)},
    {"DGB",    dgb::address_acceptance(/*testnet=*/false, /*regtest=*/false)},
    {"BIP110", bip110::address_acceptance(/*testnet=*/false, /*regtest=*/false)},
};

const Coin& coin(const std::string& name)
{
    for (const auto& c : kCoins) if (c.name == name) return c;
    ADD_FAILURE() << "unknown coin " << name;
    return kCoins[0];
}

AddressCoinMatch run(const Coin& c, const std::string& addr, std::vector<unsigned char>& script)
{
    return classify_address_for_coin(addr, c.acc, script);
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

// ── Registry values match chainparams (blocker #3: derived, not re-typed) ─────
// The version bytes / HRPs come from make_coin_params()/params SSOT via the
// address_acceptance() helper. Pinning them here catches a drifted constant AND
// makes the file fail to compile on the parent (the helpers do not exist there).
TEST(AddressCoinValidation, RegistryValuesMatchChainparams)
{
    // LTC: mainnet 48 / {50,5} / "ltc"; testnet 111 / {196,58} / "tltc".
    EXPECT_EQ(ltc::address_acceptance(false).p2pkh_versions, (std::vector<uint8_t>{48}));
    EXPECT_EQ(ltc::address_acceptance(false).p2sh_versions,  (std::vector<uint8_t>{50, 5}));
    EXPECT_EQ(ltc::address_acceptance(false).bech32_hrps,    (std::vector<std::string>{"ltc"}));
    EXPECT_EQ(ltc::address_acceptance(true).p2pkh_versions,  (std::vector<uint8_t>{111}));
    EXPECT_EQ(ltc::address_acceptance(true).p2sh_versions,   (std::vector<uint8_t>{196, 58}));
    EXPECT_EQ(ltc::address_acceptance(true).bech32_hrps,     (std::vector<std::string>{"tltc"}));

    // BTC: mainnet 0 / 5 / "bc"; testnet 0x6f / 0xc4 / "tb"; regtest hrp "bcrt".
    EXPECT_EQ(btc::address_acceptance(false, false).p2pkh_versions, (std::vector<uint8_t>{0x00}));
    EXPECT_EQ(btc::address_acceptance(false, false).p2sh_versions,  (std::vector<uint8_t>{0x05}));
    EXPECT_EQ(btc::address_acceptance(false, false).bech32_hrps,    (std::vector<std::string>{"bc"}));
    EXPECT_EQ(btc::address_acceptance(true,  false).bech32_hrps,    (std::vector<std::string>{"tb"}));
    EXPECT_EQ(btc::address_acceptance(false, true ).bech32_hrps,    (std::vector<std::string>{"bcrt"}));

    // BCH: legacy base58 == BTC bytes; NO bech32 (CashAddr is a distinct format).
    EXPECT_EQ(bch::address_acceptance(false, false).p2pkh_versions, (std::vector<uint8_t>{0x00}));
    EXPECT_EQ(bch::address_acceptance(false, false).p2sh_versions,  (std::vector<uint8_t>{0x05}));
    EXPECT_TRUE(bch::address_acceptance(false, false).bech32_hrps.empty());

    // DGB: mainnet 0x1e / 0x3f / "dgb"; regtest hrp "dgbrt".
    EXPECT_EQ(dgb::address_acceptance(false, false).p2pkh_versions, (std::vector<uint8_t>{0x1e}));
    EXPECT_EQ(dgb::address_acceptance(false, false).p2sh_versions,  (std::vector<uint8_t>{0x3f}));
    EXPECT_EQ(dgb::address_acceptance(false, false).bech32_hrps,    (std::vector<std::string>{"dgb"}));
    EXPECT_EQ(dgb::address_acceptance(false, true ).bech32_hrps,    (std::vector<std::string>{"dgbrt"}));

    // BIP-110: Bitcoin address formats unchanged; mainnet 0/5/"bc".
    EXPECT_EQ(bip110::address_acceptance(false, false).p2pkh_versions, (std::vector<uint8_t>{0x00}));
    EXPECT_EQ(bip110::address_acceptance(false, false).p2sh_versions,  (std::vector<uint8_t>{0x05}));
    EXPECT_EQ(bip110::address_acceptance(false, false).bech32_hrps,    (std::vector<std::string>{"bc"}));
    EXPECT_EQ(bip110::address_acceptance(false, true ).bech32_hrps,    (std::vector<std::string>{"bcrt"}));

    // DASH: mainnet 76 / 16; testnet 140 / 19; regtest == testnet; no bech32.
    EXPECT_EQ(dash::address_acceptance(false, false).p2pkh_versions, (std::vector<uint8_t>{76}));
    EXPECT_EQ(dash::address_acceptance(false, false).p2sh_versions,  (std::vector<uint8_t>{16}));
    EXPECT_TRUE(dash::address_acceptance(false, false).bech32_hrps.empty());
    EXPECT_EQ(dash::address_acceptance(false, true ).p2pkh_versions, (std::vector<uint8_t>{140}));
    EXPECT_EQ(dash::address_acceptance(true,  false).p2sh_versions,  (std::vector<uint8_t>{19}));
}

// ── The stratum payout decision (blocker #1: reject / guard, not accept-burn) ──
// core::decide_payout_address() is the SSOT that handle_authorize() consults to
// reject a foreign-unconfigured address at the door, and that send_notify_work()
// consults to refuse building a zero-payout share. Prove: own-coin → AcceptOwn;
// a CONFIGURED merged chain → AcceptMerged (legit reuse, same hash160 pays the
// parent P2PKH); foreign-unconfigured OR unparseable → Reject.
TEST(AddressCoinValidation, StratumPayoutDecision)
{
    const CoinAddressAcceptance ltc_acc = ltc::address_acceptance(false);

    // DOGE identification triple, exactly as the stratum server's merged-chain
    // table records it (D... 0x1e, 9/A... 0x16, testnet n... 0x71; no bech32).
    const MergedChainAddr doge{{}, {0x1e, 0x16, 0x71}};
    const std::vector<MergedChainAddr> no_merged{};
    const std::vector<MergedChainAddr> with_doge{doge};

    // Own LTC addresses → AcceptOwn regardless of merged config.
    EXPECT_EQ(decide_payout_address(b58(48), ltc_acc, no_merged),
              PayoutAddressDecision::AcceptOwn);          // L... P2PKH
    EXPECT_EQ(decide_payout_address(b58(50), ltc_acc, no_merged),
              PayoutAddressDecision::AcceptOwn);          // M... P2SH
    EXPECT_EQ(decide_payout_address(b58(5),  ltc_acc, no_merged),
              PayoutAddressDecision::AcceptOwn);          // legacy 3... P2SH
    EXPECT_EQ(decide_payout_address(bech32_v0("ltc"), ltc_acc, with_doge),
              PayoutAddressDecision::AcceptOwn);

    // A DOGE address (0x1e): the ACCEPT-AND-BURN case. Rejected when DOGE is NOT
    // a configured merged chain (the #961 money leak — previously repurposed into
    // an LTC script from a hash160 the miner does not control), but AcceptMerged
    // once DOGE IS configured (the intended merged-mining reuse).
    EXPECT_EQ(decide_payout_address(b58(0x1e), ltc_acc, no_merged),
              PayoutAddressDecision::Reject);
    EXPECT_EQ(decide_payout_address(b58(0x1e), ltc_acc, with_doge),
              PayoutAddressDecision::AcceptMerged);

    // A DASH address (0x4c) LTC can never merge-mine → Reject even with DOGE cfg.
    EXPECT_EQ(decide_payout_address(b58(0x4c), ltc_acc, with_doge),
              PayoutAddressDecision::Reject);

    // A real BTC mainnet bech32 (HRP "bc" ∉ {"ltc"}) → Reject.
    EXPECT_EQ(decide_payout_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                                    ltc_acc, with_doge),
              PayoutAddressDecision::Reject);

    // Unparseable → Reject (an Invalid address is never payable, even if a merged
    // chain is configured — the merged check only runs for a well-formed Foreign).
    EXPECT_EQ(decide_payout_address("not an address", ltc_acc, with_doge),
              PayoutAddressDecision::Reject);
    EXPECT_EQ(decide_payout_address("", ltc_acc, with_doge),
              PayoutAddressDecision::Reject);
}

// ── ACCEPT-OWN: each coin accepts its own P2PKH / P2SH / bech32 address ───────
TEST(AddressCoinValidation, AcceptsOwnP2PKH)
{
    for (const auto& c : kCoins) {
        const std::string addr = b58(c.acc.p2pkh_versions.front());
        std::vector<unsigned char> script;
        EXPECT_EQ(run(c, addr, script), AddressCoinMatch::Own)
            << c.name << " must accept its own P2PKH address " << addr;
        EXPECT_EQ(script, p2pkh_script()) << c.name << " P2PKH script mismatch";
    }
}

TEST(AddressCoinValidation, AcceptsOwnP2SH)
{
    for (const auto& c : kCoins) {
        const std::string addr = b58(c.acc.p2sh_versions.front());
        std::vector<unsigned char> script;
        EXPECT_EQ(run(c, addr, script), AddressCoinMatch::Own)
            << c.name << " must accept its own P2SH address " << addr;
        EXPECT_EQ(script, p2sh_script()) << c.name << " P2SH script mismatch";
    }
}

TEST(AddressCoinValidation, AcceptsOwnBech32)
{
    for (const auto& c : kCoins) {
        if (c.acc.bech32_hrps.empty()) continue;  // DOGE/DASH/BCH have no segwit
        const std::string addr = bech32_v0(c.acc.bech32_hrps.front());
        std::vector<unsigned char> script;
        EXPECT_EQ(run(c, addr, script), AddressCoinMatch::Own)
            << c.name << " must accept its own bech32 address " << addr;
        EXPECT_EQ(script, p2wpkh_script()) << c.name << " P2WPKH script mismatch";
    }
}

// ── REJECT-FOREIGN: full cross product of base58 addresses ───────────────────
// Every coin's own P2PKH and P2SH version is offered to every OTHER coin. The
// expected verdict is derived from the running coin's REGISTRY set: Own iff the
// version byte is in the set (handles the inherent BTC/BCH 0x00,0x05 and
// DOGE/DGB 0x1e collisions), Foreign otherwise — and Foreign MUST yield an empty
// script so the money path can never emit a wrong-coin payment.
TEST(AddressCoinValidation, RejectsForeignBase58)
{
    std::vector<uint8_t> versions;
    for (const auto& c : kCoins) {
        for (uint8_t v : c.acc.p2pkh_versions) versions.push_back(v);
        for (uint8_t v : c.acc.p2sh_versions)  versions.push_back(v);
    }

    for (const auto& running : kCoins) {
        for (uint8_t v : versions) {
            const std::string addr = b58(v);
            std::vector<unsigned char> script;
            auto verdict = run(running, addr, script);
            const bool own = set_has(running.acc.p2pkh_versions, v) ||
                             set_has(running.acc.p2sh_versions,  v);
            if (own) {
                EXPECT_EQ(verdict, AddressCoinMatch::Own)
                    << running.name << " should accept version 0x" << std::hex << int(v);
                EXPECT_FALSE(script.empty());
            } else {
                EXPECT_EQ(verdict, AddressCoinMatch::Foreign)
                    << running.name << " must REJECT foreign version 0x" << std::hex << int(v);
                EXPECT_TRUE(script.empty())
                    << running.name << " emitted a script for a foreign address "
                    << "— MISDIRECTION (issue #961)";
            }
        }
    }
}

// ── REJECT-FOREIGN: a bech32 address for another chain ───────────────────────
TEST(AddressCoinValidation, RejectsForeignBech32)
{
    const std::vector<std::string> all_hrps = {"bc", "ltc", "dgb", "tb"};
    for (const auto& running : kCoins) {
        for (const auto& hrp : all_hrps) {
            const std::string addr = bech32_v0(hrp);
            std::vector<unsigned char> script;
            auto verdict = run(running, addr, script);
            if (set_has(running.acc.bech32_hrps, hrp)) {
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
// hash160 the miner does not control on Litecoin — the money leak. At the classify
// gate (what send_notify_work now consults before building the script), LTC must
// classify every non-LTC address as Foreign and yield an EMPTY script. The
// running set is the REAL ltc::address_acceptance(false).
TEST(AddressCoinValidation, LtcRejectsUnconfiguredForeign)
{
    const Coin& ltc = coin("LTC");
    std::vector<unsigned char> script;

    // A DOGE address (0x1e) — the classic "unconfigured merged coin" case.
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

    // LTC's OWN addresses (incl. the legacy 0x05 P2SH collision) stay Own.
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
// the set from the TRUE network (testnet, regtest). These come from the REAL
// address_acceptance(testnet=false, regtest=true): a regtest own address must
// classify as Own; a MAINNET address must be Foreign under the regtest set.
TEST(AddressCoinValidation, AcceptsRegtestAddresses)
{
    struct RegtestSet { std::string name; CoinAddressAcceptance set; uint8_t mainnet_p2pkh; bool has_bech32; };
    const std::vector<RegtestSet> regtests = {
        {"BTC",    btc::address_acceptance(false, true),    0x00, true},
        {"DGB",    dgb::address_acceptance(false, true),    0x1e, true},
        {"BIP110", bip110::address_acceptance(false, true), 0x00, true},
        {"DASH",   dash::address_acceptance(false, true),   76,   false},
    };

    for (const auto& r : regtests) {
        const Coin c{r.name, r.set};
        std::vector<unsigned char> script;

        EXPECT_EQ(run(c, b58(r.set.p2pkh_versions.front()), script), AddressCoinMatch::Own)
            << r.name << " regtest must accept its own P2PKH address";
        EXPECT_EQ(script, p2pkh_script());
        EXPECT_EQ(run(c, b58(r.set.p2sh_versions.front()), script), AddressCoinMatch::Own)
            << r.name << " regtest must accept its own P2SH address";
        EXPECT_EQ(script, p2sh_script());
        if (r.has_bech32) {
            EXPECT_EQ(run(c, bech32_v0(r.set.bech32_hrps.front()), script), AddressCoinMatch::Own)
                << r.name << " regtest must accept its own bech32 address";
            EXPECT_EQ(script, p2wpkh_script());
        }

        // A MAINNET address of the same coin is Foreign under the regtest set —
        // proving the set is network-derived, not mainnet-or-not.
        EXPECT_EQ(run(c, b58(r.mainnet_p2pkh), script), AddressCoinMatch::Foreign)
            << r.name << " regtest set must not accept a mainnet address";
        EXPECT_TRUE(script.empty());
    }
}

// ── #961 B4 cross-lane: the payout DOOR-REJECT decision applies on EVERY lane ─
// Cycle-1 published the acceptance set (StratumConfig.payout_*) on the LTC lane
// only, so the core stratum door-reject + no-empty-payout guard ran on LTC alone.
// The other five mains (BTC/BCH/DGB/DASH/BIP-110) authorized a foreign-
// unconfigured address — and the fresh BCH lane then BURNED it to a zero-hash160
// coinbase. B4 publishes each coin's OWN registry-sourced acceptance from its main
// so decide_payout_address() — the SSOT the door consults — runs identically on
// every lane. Prove the decision each published set now feeds: own → AcceptOwn;
// a foreign coin's address that is NOT a configured merged chain → Reject.
TEST(AddressCoinValidation, CrossLaneDoorRejectsForeignEveryLane)
{
    const std::vector<MergedChainAddr> no_merged{};
    for (const auto& running : kCoins) {
        const CoinAddressAcceptance& acc = running.acc;

        // Own P2PKH / P2SH → AcceptOwn (reward-safe: still built byte-identically).
        EXPECT_EQ(decide_payout_address(b58(acc.p2pkh_versions.front()), acc, no_merged),
                  PayoutAddressDecision::AcceptOwn)
            << running.name << " must AcceptOwn its own P2PKH at the door";
        EXPECT_EQ(decide_payout_address(b58(acc.p2sh_versions.front()), acc, no_merged),
                  PayoutAddressDecision::AcceptOwn)
            << running.name << " must AcceptOwn its own P2SH at the door";
        if (!acc.bech32_hrps.empty())
            EXPECT_EQ(decide_payout_address(bech32_v0(acc.bech32_hrps.front()), acc, no_merged),
                      PayoutAddressDecision::AcceptOwn)
                << running.name << " must AcceptOwn its own bech32 at the door";

        // A DASH mainnet P2PKH (version 0x4c) is foreign to every non-DASH lane and
        // is not a configured merged chain of any lane → the door MUST Reject it
        // (the cross-lane fix: previously these lanes authorized-and-redirected/
        // burned it). DASH itself accepts its own address.
        const auto verdict = decide_payout_address(b58(0x4c), acc, no_merged);
        const bool dash_own = set_has(acc.p2pkh_versions, uint8_t(0x4c)) ||
                              set_has(acc.p2sh_versions,  uint8_t(0x4c));
        if (dash_own)
            EXPECT_EQ(verdict, PayoutAddressDecision::AcceptOwn) << running.name;
        else
            EXPECT_EQ(verdict, PayoutAddressDecision::Reject)
                << running.name << " must door-reject a foreign DASH address, "
                << "never authorize-and-redirect/burn it (#961 B4)";
    }
}

// ── #961 B4: a coin's NATIVE-format own address is AcceptOwn at the door ───────
// BCH's native CashAddr is not Base58Check/bech32, so classify_address_for_coin()
// returns Invalid for it. On the PARENT tree (4a9dd316) decide_payout_address()
// returned Reject for any Invalid classification — so once BCH publishes its
// acceptance set (B4), the door would REJECT a legitimate BCH CashAddr miner and
// the guard would refuse to build their work: a reward-UNSAFE regression. B4 makes
// the SSOT consult the coin-registered native decoder (address_to_script): an
// address the running node CAN pay is AcceptOwn. This test is RED on 4a9dd316
// (parent returns Reject for the native address) and green here.
TEST(AddressCoinValidation, NativeDecoderOwnAddressAcceptedAtDoor)
{
    // A sentinel that only the registered decoder below understands. It matches
    // exactly ONE fixed string (empty for everything else), so no other test's
    // addresses are affected by this process-global registration.
    const std::string kNative = "cashaddr:sentinel-b4-961-own";
    core::register_address_decoder(
        [kNative](const std::string& a) -> std::vector<unsigned char> {
            if (a == kNative) return p2pkh_script();  // a real, spendable scriptPubKey
            return {};
        });

    const CoinAddressAcceptance bch_acc = bch::address_acceptance(false, false);
    const std::vector<MergedChainAddr> no_merged{};

    // The native-format own address the node CAN build a script for → AcceptOwn.
    // RED on parent 4a9dd316: there the Invalid classification short-circuits to
    // Reject without consulting the registered decoder.
    EXPECT_EQ(decide_payout_address(kNative, bch_acc, no_merged),
              PayoutAddressDecision::AcceptOwn)
        << "a coin's own native (CashAddr) address must be accepted at the door — "
        << "rejecting it would refuse legitimate BCH miners (reward-unsafe)";

    // The fix opens NO hole: a truly-undecodable Invalid address (no decoder
    // matches) still Rejects, so a foreign/garbage username can never slip through.
    EXPECT_EQ(decide_payout_address("still not any address at all", bch_acc, no_merged),
              PayoutAddressDecision::Reject);
    EXPECT_EQ(decide_payout_address("", bch_acc, no_merged),
              PayoutAddressDecision::Reject);

    // And a well-formed FOREIGN base58 address (BTC genesis P2PKH, version 0x00 —
    // not in BCH's set? it IS: BCH shares BTC's 0x00) — use a DASH address instead,
    // foreign to BCH and not a merged chain → Reject even with the decoder armed.
    EXPECT_EQ(decide_payout_address(b58(0x4c), bch_acc, no_merged),
              PayoutAddressDecision::Reject);
}
