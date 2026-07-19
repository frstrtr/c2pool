// SPDX-License-Identifier: AGPL-3.0-or-later
/// Phase G1 byte-parity — DASH coinbase/payee serialization conformance vs the
/// canonical oracle frstrtr/p2pool-dash (older-than-v35).
///
/// Integrator-assigned (2026-06-26): prove the payee-assembly path
/// (coin/embedded_gbt.hpp + coin/rpc.hpp m_packed_payments ->
/// coinbase_builder.hpp::compute_dash_payouts) emits a byte-identical coinbase
/// to p2pool-dash data.py generate_transaction() for the same input -- pure
/// conformance, no masternode tracking. Directly advances G1 and feeds G3
/// ASSEMBLED.
///
/// GOLDEN VECTORS captured from the REAL oracle (NOT synthesized) by driving
/// p2pool/dash/data.py under python2.7.18 + pycryptodome, testnet params
/// (ADDRESS_VERSION=140, SCRIPT_ADDRESS_VERSION=19):
///
///   pubkey_hash int 0x20cb5c22b1e4d5947e5c112c7696b51ad9af3c61
///     pubkey_hash_to_script2        -> 76a914 613cafd9..cb20 88ac   (P2PKH)
///     pubkey_hash_script_to_script2 -> a914   613cafd9..cb20 87     (P2SH)
///     script2_to_address (P2PKH)    -> yVBb6QnAEZWfKomEwkEqRMUF5zFvFgerom
///     script2_to_address (P2SH)     -> 8oHbxGiJKjSeNMtkyywGkBY3vx5nCaDExZ
///     address_to_script2 round-trips both byte-identically
///     txout pack (val 123456789)    -> 15cd5b0700000000 19 76a914..88ac
///
/// CONFORMANCE TRAP this pins: p2pool packs pubkey_hash LITTLE-ENDIAN
/// (pack.IntType(160)), so the script carries 613cafd9..cb20 -- the byte
/// reversal of the 0x20cb..3c61 integer. c2pool pubkey_hash_to_script2 reads
/// uint160::GetChars() (storage order); feeding the same 20 raw bytes must
/// reproduce the oracle script exactly.

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include <impl/dash/share_check.hpp>       // decode_payee_script, pubkey_hash_to_script2, DONATION_SCRIPT
#include <impl/dash/coinbase_builder.hpp>  // compute_dash_payouts, MinerPayout
#include <impl/dash/params.hpp>            // make_coin_params
#include <impl/dash/coin/rpc_data.hpp>     // dash::coin::PackedPayment
#include <core/uint256.hpp>

namespace {

// hash160 in oracle on-wire (little-endian-of-the-int) order -- the 20 bytes
// that actually land in the scriptPubKey.
const std::vector<unsigned char> kH160 = {
    0x61, 0x3c, 0xaf, 0xd9, 0x1a, 0xb5, 0x96, 0x76, 0x2c, 0x11,
    0x5c, 0x7e, 0x94, 0xd5, 0xe4, 0xb1, 0x22, 0x5c, 0xcb, 0x20,
};

std::vector<unsigned char> p2pkh(const std::vector<unsigned char>& h) {
    std::vector<unsigned char> s = {0x76, 0xa9, 0x14};
    s.insert(s.end(), h.begin(), h.end());
    s.push_back(0x88); s.push_back(0xac);
    return s;
}
std::vector<unsigned char> p2sh(const std::vector<unsigned char>& h) {
    std::vector<unsigned char> s = {0xa9, 0x14};
    s.insert(s.end(), h.begin(), h.end());
    s.push_back(0x87);
    return s;
}

// Canonical testnet base58 forms emitted by the oracle for kH160.
const std::string kAddrP2PKH = "yVBb6QnAEZWfKomEwkEqRMUF5zFvFgerom";
const std::string kAddrP2SH  = "8oHbxGiJKjSeNMtkyywGkBY3vx5nCaDExZ";

// Mirror of pack.IntType(64) + pack.VarStrType() used by data.py for each tx_out.
std::vector<unsigned char> pack_txout(uint64_t value,
                                      const std::vector<unsigned char>& script) {
    std::vector<unsigned char> out;
    for (int i = 0; i < 8; ++i) out.push_back((value >> (8 * i)) & 0xff); // i64 LE
    out.push_back(static_cast<unsigned char>(script.size()));             // compactsize (<0xfd)
    out.insert(out.end(), script.begin(), script.end());
    return out;
}

std::string hex(const std::vector<unsigned char>& v) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(v.size() * 2);
    for (auto b : v) { s.push_back(d[b >> 4]); s.push_back(d[b & 0xf]); }
    return s;
}

} // namespace

// (1) "!"-prefix raw hex script -> identity hex decode (data.py payee[1:].decode("hex")).
TEST(DashCoinbaseParity, PayeeBangHexDirectScript) {
    auto s = dash::decode_payee_script("!6a04deadbeef", 140, 19);
    EXPECT_EQ(hex(s), "6a04deadbeef");
}

// (2) base58 P2PKH address -> oracle P2PKH script, byte-identical.
TEST(DashCoinbaseParity, PayeeBase58P2PKHMatchesOracle) {
    auto s = dash::decode_payee_script(kAddrP2PKH, 140, 19);
    EXPECT_EQ(s, p2pkh(kH160));
    EXPECT_EQ(hex(s), "76a914613cafd91ab596762c115c7e94d5e4b1225ccb2088ac");
}

// (3) base58 P2SH address -> oracle P2SH script, byte-identical.
TEST(DashCoinbaseParity, PayeeBase58P2SHMatchesOracle) {
    auto s = dash::decode_payee_script(kAddrP2SH, 140, 19);
    EXPECT_EQ(s, p2sh(kH160));
    EXPECT_EQ(hex(s), "a914613cafd91ab596762c115c7e94d5e4b1225ccb2087");
}

// (4) "script:"-prefix legacy form -> dropped (data.py `continue`; c2pool falls
//     through base58 decode -> empty -> caller skips). Same observable result.
TEST(DashCoinbaseParity, PayeeScriptPrefixDropped) {
    EXPECT_TRUE(dash::decode_payee_script("script:76a914aa88ac", 140, 19).empty());
}

// (5) empty / malformed payee -> dropped.
TEST(DashCoinbaseParity, PayeeEmptyDropped) {
    EXPECT_TRUE(dash::decode_payee_script("", 140, 19).empty());
    EXPECT_TRUE(dash::decode_payee_script("not_an_address!!!", 140, 19).empty());
}

// (6) pubkey_hash_to_script2 reproduces the oracle little-endian packing, and is
//     consistent with the base58 path for the same hash160.
TEST(DashCoinbaseParity, PubkeyHashToScriptLittleEndianPacking) {
    uint160 h(kH160);
    auto s = dash::pubkey_hash_to_script2(h);
    EXPECT_EQ(s, p2pkh(kH160));
    EXPECT_EQ(s, dash::decode_payee_script(kAddrP2PKH, 140, 19));
}

// (7) on-wire tx_out bytes (value i64 LE + VarStr script) match the oracle.
TEST(DashCoinbaseParity, TxOutOnWireBytesMatchOracle) {
    auto out = pack_txout(123456789ull, p2pkh(kH160));
    EXPECT_EQ(hex(out),
              "15cd5b07000000001976a914613cafd91ab596762c115c7e94d5e4b1225ccb2088ac");
}

// (8) compute_dash_payouts tx_out ORDER == oracle generate_transaction:
//     worker_tx (finder) || payments_tx (GBT order, nonzero only) ||
//     donation_tx (always last). Drops zero-amount entries ONLY — a non-zero
//     undecodable payee now THROWS instead of being silently dropped
//     (bad-cb-payee hard rule, 2026-07-19; see test (8b) below): a coinbase
//     missing a consensus-required payment is guaranteed-rejected by dashd,
//     so the builder must refuse rather than build a doomed coinbase.
TEST(DashCoinbaseParity, TxOutOrderingWorkerPaymentsDonation) {
    auto params = dash::make_coin_params(true); // testnet: ver 140 / p2sh 19

    std::vector<dash::coin::PackedPayment> payments;
    payments.push_back({kAddrP2PKH,          5000}); // valid base58 P2PKH -> kept
    payments.push_back({"!6a04deadbeef",        1}); // valid raw script   -> kept
    payments.push_back({kAddrP2SH,              0}); // zero amount        -> dropped

    // Distinct finder hash so its script never coalesces with a payee script.
    std::vector<unsigned char> finder_h(20, 0x07);
    uint160 finder(finder_h);

    const uint64_t subsidy = 5000000000ull;
    auto outs = dash::coinbase::compute_dash_payouts(
        subsidy, payments, finder, /*weights=*/{}, /*total_weight=*/0, params);

    // finder + 2 kept payments + donation
    ASSERT_EQ(outs.size(), 4u);
    EXPECT_EQ(outs[0].script, dash::pubkey_hash_to_script2(finder)); // worker_tx
    EXPECT_EQ(outs[1].script, p2pkh(kH160));                         // payment 1 (GBT order)
    EXPECT_EQ(outs[1].amount, 5000u);
    EXPECT_EQ(hex(outs[2].script), "6a04deadbeef");                  // payment 2 (raw)
    EXPECT_EQ(outs[2].amount, 1u);
    EXPECT_EQ(outs[3].script, dash::DONATION_SCRIPT);               // donation last
    EXPECT_GT(outs[0].amount, 0u);
    EXPECT_GT(outs[3].amount, 0u);

    // sum(outs) == subsidy (data.py worker_payout invariant).
    uint64_t sum = 0; for (auto& o : outs) sum += o.amount;
    EXPECT_EQ(sum, subsidy);
}

// (8b) bad-cb-payee hard rule: a NON-ZERO payment whose payee cannot be
//      decoded (legacy "script:" form, corrupt string) and which carries no
//      raw GBT script bytes must THROW — never be silently dropped. The
//      pre-fix silent drop built a coinbase missing a consensus-required
//      output; dashd rejected the won block with bad-cb-payee (hex-confirmed
//      live on testnet 2026-07-19).
TEST(DashCoinbaseParity, UndecodablePayeeThrowsNeverDrops) {
    auto params = dash::make_coin_params(true);

    std::vector<dash::coin::PackedPayment> payments;
    payments.push_back({"script:76a914aa88ac", 9}); // legacy form, no raw script

    std::vector<unsigned char> finder_h(20, 0x07);
    uint160 finder(finder_h);

    EXPECT_THROW(
        dash::coinbase::compute_dash_payouts(
            5000000000ull, payments, finder, /*weights=*/{},
            /*total_weight=*/0, params),
        std::runtime_error);
}

// (9) v36 ARM: full-weight split, NO 2% block-finder fee, donation = remainder.
//     Gated on params.current_share_version >= 36 (core::version_gate SSOT).
//     Mirrors DGB share_tracker::get_expected_payouts; total_weight is the
//     GRAND total (incl. donation_weight) so the donation absorbs its slice
//     via the step-5 remainder.
TEST(DashCoinbaseParity, V36FullWeightNoFinder) {
    auto params = dash::make_coin_params(true);
    params.current_share_version = 36;  // activate v36 arm

    // Two distinct weighted miners. total_weight=50 > sum(miner weights)=40,
    // i.e. donation_weight=10 -> donation gets 10/50 of worker_payout.
    std::vector<unsigned char> hA(20, 0x11), hB(20, 0x22);
    auto scriptA = dash::pubkey_hash_to_script2(uint160(hA));
    auto scriptB = dash::pubkey_hash_to_script2(uint160(hB));
    std::map<std::vector<unsigned char>, uint64_t> weights;
    weights[scriptA] = 30;
    weights[scriptB] = 10;

    // Finder hash NOT in the weight set -> in v36 it must produce NO output.
    std::vector<unsigned char> finder_h(20, 0x07);
    uint160 finder(finder_h);

    const uint64_t subsidy = 5000000000ull;  // no payments -> worker_payout=subsidy
    auto outs = dash::coinbase::compute_dash_payouts(
        subsidy, /*payments=*/{}, finder, weights, /*total_weight=*/50, params);

    std::map<std::vector<unsigned char>, uint64_t> got;
    for (auto& o : outs) got[o.script] += o.amount;

    EXPECT_EQ(got[scriptA], 3000000000ull);           // 5e9 * 30/50  (FULL weight)
    EXPECT_EQ(got[scriptB], 1000000000ull);           // 5e9 * 10/50
    EXPECT_EQ(got[std::vector<unsigned char>(
                  dash::DONATION_SCRIPT.begin(), dash::DONATION_SCRIPT.end())],
              1000000000ull);                          // remainder = 5e9 - 4e9
    // finder dropped entirely in v36 (no 2% fee).
    EXPECT_EQ(got.count(dash::pubkey_hash_to_script2(finder)), 0u);

    uint64_t sum = 0; for (auto& o : outs) sum += o.amount;
    EXPECT_EQ(sum, subsidy);
}

// (10) v36 a60f7f7f floor: when the donation remainder rounds to 0, exactly
//      1 satoshi is deducted from the largest miner (tiebreak: (amount,script)).
TEST(DashCoinbaseParity, V36DonationFloorOneSat) {
    auto params = dash::make_coin_params(true);
    params.current_share_version = 36;

    std::vector<unsigned char> hA(20, 0x11), hB(20, 0x22);
    auto scriptA = dash::pubkey_hash_to_script2(uint160(hA));
    auto scriptB = dash::pubkey_hash_to_script2(uint160(hB));
    std::map<std::vector<unsigned char>, uint64_t> weights;
    weights[scriptA] = 1;
    weights[scriptB] = 1;  // total_weight=2 -> donation_weight=0, remainder rounds to 0

    std::vector<unsigned char> finder_h(20, 0x07);
    uint160 finder(finder_h);

    const uint64_t subsidy = 1000ull;  // worker_payout=1000 -> A=500,B=500, donation 0
    auto outs = dash::coinbase::compute_dash_payouts(
        subsidy, /*payments=*/{}, finder, weights, /*total_weight=*/2, params);

    std::map<std::vector<unsigned char>, uint64_t> got;
    for (auto& o : outs) got[o.script] += o.amount;

    auto don = std::vector<unsigned char>(
        dash::DONATION_SCRIPT.begin(), dash::DONATION_SCRIPT.end());
    EXPECT_EQ(got[don], 1u);                           // floor forced donation >= 1
    // Tiebreak (amount,script): equal 500/500 -> larger script bytes loses 1 sat.
    auto& loser  = (scriptA < scriptB) ? scriptB : scriptA;
    auto& other  = (scriptA < scriptB) ? scriptA : scriptB;
    EXPECT_EQ(got[loser], 499u);
    EXPECT_EQ(got[other], 500u);

    uint64_t sum = 0; for (auto& o : outs) sum += o.amount;
    EXPECT_EQ(sum, subsidy);                            // invariant preserved
}