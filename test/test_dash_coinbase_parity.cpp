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

#include <algorithm>
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
//     worker_tx (finder) || payments_tx (GBT order, nonzero+decodable only) ||
//     donation_tx (always last). Drops zero-amount + "script:"/undecodable payees.
TEST(DashCoinbaseParity, TxOutOrderingWorkerPaymentsDonation) {
    auto params = dash::make_coin_params(true); // testnet: ver 140 / p2sh 19

    std::vector<dash::coin::PackedPayment> payments;
    payments.push_back({kAddrP2PKH,          5000}); // valid base58 P2PKH -> kept
    payments.push_back({"!6a04deadbeef",        1}); // valid raw script   -> kept
    payments.push_back({"script:76a914aa88ac",  9}); // legacy form        -> dropped
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


// ─────────────────────────────────────────────────────────────────────────────
// (11)-(19) Coinbase text — the canonical p2pool marker + --coinbase-text.
//
// Block explorers attribute blocks to a pool BY COINBASE TEXT.
// chainz.cryptoid.info/dash/extraction.dws?30.htm registers the pool as
// "P2Pool-DASH"; it has no knowledge of the string "c2pool". Before this,
// c2pool's DASH coinbase read `03c751266332706f6f6c` = BIP34 height + "c2pool",
// so blocks the pool won through c2pool (2511241, 2511303) were attributed to
// nobody. The default coinbase text is now the oracle COINBASEEXT payload
// ("/P2Pool-DASH/", networks/dash.py:11) plus a "c2pool/" implementation tag,
// sourced from the coin SSOT (config_pool.hpp) and overridable per-pool with
// --coinbase-text.
//
// NOT consensus-bearing: the coinbase text is a customizable parameter.
// COINBASEEXT appears nowhere in the oracle's data.py; the scriptSig travels as
// share_info.share_data.coinbase and Share.check() re-derives the gentx from the
// RECEIVED share's own coinbase field. What these tests DO guard is FRAMING —
// the BIP34 height push must stay first, the 100-byte bound must hold, and the
// stratum extranonce2 slot must not move.
// ─────────────────────────────────────────────────────────────────────────────

namespace {

// Oracle marker payloads, transcribed independently of config_pool.hpp so a
// silent edit to the SSOT cannot silently move these KATs with it.
//   networks/dash.py:11          '0D2F5032506F6F6C2D444153482F' = 0x0D "/P2Pool-DASH/"
//   networks/dash_testnet.py:11  '0E2F5032506F6F6C2D74444153482F' = 0x0E "/P2Pool-tDASH/"
const std::string kOracleMarkerMain = "/P2Pool-DASH/";
const std::string kOracleMarkerTest = "/P2Pool-tDASH/";

std::string ascii(const std::vector<unsigned char>& v) {
    return std::string(v.begin(), v.end());
}

// RAII for the pool-level --coinbase-text override: it is a process global, so
// one test must not leak into the next.
struct ScopedCoinbaseText {
    std::string saved;
    explicit ScopedCoinbaseText(const std::string& v)
        : saved(dash::SharechainConfig::coinbase_text_override) {
        dash::SharechainConfig::coinbase_text_override = v;
    }
    ~ScopedCoinbaseText() {
        dash::SharechainConfig::coinbase_text_override = saved;
    }
};

} // namespace

// (11) MAINNET KAT — exact scriptSig bytes at the real height of the block the
//      pool won on 2026-07-24 (2511303 = 0x2651c7 -> BIP34 push `03 c7 51 26`).
TEST(DashCoinbaseMarker, MainnetScriptSigKAT) {
    ScopedCoinbaseText no_override("");
    auto s = dash::coinbase::build_coinbase_scriptsig(
        /*height=*/2511303, /*coinbase_text=*/"", /*testnet=*/false);

    EXPECT_EQ(hex(s),
              "03c75126"                                    // BIP34 push3, height 2511303 LE
              "2f5032506f6f6c2d444153482f6332706f6f6c2f");  // "/P2Pool-DASH/c2pool/"
    EXPECT_EQ(s.size(), 24u);
    EXPECT_EQ(ascii(s).substr(4), "/P2Pool-DASH/c2pool/");
    // The marker an explorer matches on is present verbatim.
    EXPECT_NE(ascii(s).find(kOracleMarkerMain), std::string::npos);
}

// (12) TESTNET KAT — the tDASH variant, never the mainnet string. (c2pool has
//      no separate regtest sharechain profile: main_dash.cpp maps --regtest
//      onto testnet=true, so regtest emits these same bytes.)
TEST(DashCoinbaseMarker, TestnetScriptSigKAT) {
    ScopedCoinbaseText no_override("");
    auto s = dash::coinbase::build_coinbase_scriptsig(
        /*height=*/950000, /*coinbase_text=*/"", /*testnet=*/true);

    EXPECT_EQ(hex(s),
              "03f07e0e"                                      // BIP34 push3, height 950000 LE
              "2f5032506f6f6c2d74444153482f6332706f6f6c2f");  // "/P2Pool-tDASH/c2pool/"
    EXPECT_EQ(s.size(), 25u);
    EXPECT_EQ(ascii(s).substr(4), "/P2Pool-tDASH/c2pool/");
    EXPECT_NE(ascii(s).find(kOracleMarkerTest), std::string::npos);
    // Testnet must NOT carry the mainnet marker.
    EXPECT_EQ(ascii(s).find(kOracleMarkerMain), std::string::npos);
}

// (13) NEGATIVE CONTROL — the bytes c2pool used to emit. This is the exact
//      scriptSig observed on live mainnet block 2511303 before the change; it
//      must satisfy none of the assertions above, proving they discriminate.
TEST(DashCoinbaseMarker, LegacyBareTagIsNotAttributable) {
    ScopedCoinbaseText no_override("");

    // Reconstruct the pre-change form: BIP34 height + raw "c2pool", no marker.
    std::vector<unsigned char> legacy = dash::coinbase::push_bip34_height(2511303);
    for (char c : std::string("c2pool"))
        legacy.push_back(static_cast<unsigned char>(c));

    EXPECT_EQ(hex(legacy), "03c751266332706f6f6c");     // as seen on-chain
    EXPECT_EQ(ascii(legacy).find("P2Pool"), std::string::npos);
    EXPECT_EQ(ascii(legacy).find(kOracleMarkerMain), std::string::npos);

    auto now = dash::coinbase::build_coinbase_scriptsig(2511303, "", false);
    EXPECT_NE(hex(now), hex(legacy));
    // The BIP34 height push is byte-identical across old and new — the text is
    // appended, never displacing dashd's ContextualCheckBlock prefix.
    EXPECT_EQ(hex(now).substr(0, 8), hex(legacy).substr(0, 8));
}

// (14) SSOT wiring — config_pool.hpp carries the oracle hex verbatim (push
//      opcode included) and coinbaseext_text() strips exactly that opcode.
TEST(DashCoinbaseMarker, ConfigPoolCarriesOracleConstant) {
    EXPECT_EQ(dash::SharechainConfig::COINBASEEXT_HEX,
              "0D2F5032506F6F6C2D444153482F");
    EXPECT_EQ(dash::SharechainConfig::TESTNET_COINBASEEXT_HEX,
              "0E2F5032506F6F6C2D74444153482F");

    // Raw oracle bytes: leading push opcode == payload length.
    const std::string m = dash::SharechainConfig::coinbaseext_bytes(false);
    ASSERT_EQ(m.size(), 14u);
    EXPECT_EQ(static_cast<unsigned char>(m[0]), 0x0D);
    EXPECT_EQ(m.size() - 1, static_cast<size_t>(static_cast<unsigned char>(m[0])));
    const std::string t = dash::SharechainConfig::coinbaseext_bytes(true);
    ASSERT_EQ(t.size(), 15u);
    EXPECT_EQ(static_cast<unsigned char>(t[0]), 0x0E);
    EXPECT_EQ(t.size() - 1, static_cast<size_t>(static_cast<unsigned char>(t[0])));

    // Text form == the ASCII an explorer reads.
    EXPECT_EQ(dash::SharechainConfig::coinbaseext_text(false), kOracleMarkerMain);
    EXPECT_EQ(dash::SharechainConfig::coinbaseext_text(true),  kOracleMarkerTest);

    EXPECT_EQ(dash::SharechainConfig::default_coinbase_text(false),
              "/P2Pool-DASH/c2pool/");
    EXPECT_EQ(dash::SharechainConfig::default_coinbase_text(true),
              "/P2Pool-tDASH/c2pool/");
}

// (15) --coinbase-text override: the operator value replaces the default on
//      BOTH the explicit-argument path and the SSOT-resolved path, and the
//      default returns once the override is cleared.
TEST(DashCoinbaseMarker, OperatorOverrideReplacesDefault) {
    {
        ScopedCoinbaseText ov("/my-pool/");
        EXPECT_EQ(dash::SharechainConfig::coinbase_text(false), "/my-pool/");
        auto s = dash::coinbase::build_coinbase_scriptsig(2511303, "", false);
        EXPECT_EQ(hex(s), "03c75126" "2f6d792d706f6f6c2f");   // "/my-pool/"
        EXPECT_EQ(ascii(s).find(kOracleMarkerMain), std::string::npos);

        // An explicit non-empty argument still wins over the pool setting —
        // that is what the E5/--mine-block call sites pass.
        auto e = dash::coinbase::build_coinbase_scriptsig(2511303, "/other/", false);
        EXPECT_EQ(ascii(e).substr(4), "/other/");
    }
    // Override scope ended -> default restored.
    ScopedCoinbaseText no_override("");
    EXPECT_EQ(dash::SharechainConfig::coinbase_text(false), "/P2Pool-DASH/c2pool/");
}

// (16) 100-byte bound + BIP34 integrity under an absurd text. The oracle rejects
//      share_data['coinbase'] outside 2..100 bytes (data.py:315) and work.py
//      slices [:100]; the height push must survive both.
TEST(DashCoinbaseMarker, TruncationRespectsBoundAndKeepsHeightPush) {
    ScopedCoinbaseText no_override("");
    const std::string absurd(400, 'X');
    auto s = dash::coinbase::build_coinbase_scriptsig(2511303, absurd, false);

    EXPECT_EQ(s.size(), dash::coinbase::MAX_SCRIPTSIG_LEN);   // exactly 100, never more
    EXPECT_GE(s.size(), 2u);
    // BIP34 height push intact and still FIRST.
    auto h = dash::coinbase::push_bip34_height(2511303);
    ASSERT_GE(s.size(), h.size());
    EXPECT_TRUE(std::equal(h.begin(), h.end(), s.begin()));

    // Worst-case BIP34 push is 5 bytes (4-byte CScriptNum + length); even then
    // the default text is nowhere near the cap, and --coinbase-text is bounded
    // at c2pool::MAX_OPERATOR_TEXT_SOLO (64) by main_dash.cpp.
    auto tall = dash::coinbase::push_bip34_height(0x7FFFFFFFu);
    EXPECT_EQ(tall.size(), 5u);
    auto s2 = dash::coinbase::build_coinbase_scriptsig(0x7FFFFFFFu, "", false);
    EXPECT_EQ(s2.size(), 5u + 20u);
    EXPECT_LT(5u + 64u, dash::coinbase::MAX_SCRIPTSIG_LEN);
    EXPECT_NE(ascii(s2).find(kOracleMarkerMain), std::string::npos);
}

// (17) END-TO-END: the text actually lands in the coinbase TX that
//      coinbase::build() serializes (this is the tx a winning miner submits).
//      Fixed tx prefix: [version 4][vin count 1][prev_hash 32][prev_n 4] = 41
//      bytes, so the scriptSig VarStr length byte sits at offset 41.
TEST(DashCoinbaseMarker, BuildEmitsMarkerInSerializedCoinbase) {
    ScopedCoinbaseText no_override("");
    auto params = dash::make_coin_params(/*testnet=*/false);
    ASSERT_FALSE(params.is_testnet);

    dash::coin::DashWorkData work;
    work.m_height         = 2511303;
    work.m_coinbase_value = 5000000000ull;
    work.m_bits           = 0x1b0404cb;

    std::vector<unsigned char> finder_h(20, 0x07);
    auto tx_outs = dash::coinbase::compute_dash_payouts(
        work.m_coinbase_value, /*payments=*/{}, uint160(finder_h),
        /*weights=*/{}, /*total_weight=*/0, params);

    auto layout = dash::coinbase::build(
        work, tx_outs,
        dash::SharechainConfig::coinbase_text(params.is_testnet),
        params, uint256::ZERO);

    const auto expected = dash::coinbase::build_coinbase_scriptsig(
        work.m_height, /*coinbase_text=*/"", params.is_testnet);

    ASSERT_GT(layout.bytes.size(), 41u + 1u + expected.size());
    EXPECT_EQ(layout.bytes[41], static_cast<unsigned char>(expected.size()));
    std::vector<unsigned char> on_wire(layout.bytes.begin() + 42,
                                       layout.bytes.begin() + 42 + expected.size());
    EXPECT_EQ(hex(on_wire), hex(expected));
    EXPECT_EQ(hex(on_wire),
              "03c751262f5032506f6f6c2d444153482f6332706f6f6c2f");

    // FRAMING: the split point is derived from the tx TAIL, so a longer
    // scriptSig cannot move the 8-byte extranonce2 slot — coinb2 stays
    // [locktime||payload] and the advertised extranonce2_size is unchanged.
    auto split = dash::coinbase::split_coinb(layout);
    EXPECT_EQ(dash::coinbase::EXTRANONCE2_SIZE, 8u);
    EXPECT_EQ(split.coinb1_hex.size(), layout.nonce64_offset * 2);
    EXPECT_EQ(split.coinb2_hex.size(),
              (layout.bytes.size() - layout.nonce64_offset - 8) * 2);
    EXPECT_EQ(split.coinb2_hex, "00000000");            // locktime only, no payload
    EXPECT_EQ(layout.nonce64_offset, layout.ref_hash_offset + 32);
}

// (18) Testnet params select the testnet text end-to-end (build() reads
//      params.is_testnet, not the mutable process-global).
TEST(DashCoinbaseMarker, BuildHonoursTestnetParams) {
    ScopedCoinbaseText no_override("");
    auto params = dash::make_coin_params(/*testnet=*/true);
    ASSERT_TRUE(params.is_testnet);

    dash::coin::DashWorkData work;
    work.m_height         = 950000;
    work.m_coinbase_value = 5000000000ull;

    std::vector<unsigned char> finder_h(20, 0x07);
    auto tx_outs = dash::coinbase::compute_dash_payouts(
        work.m_coinbase_value, /*payments=*/{}, uint160(finder_h),
        /*weights=*/{}, /*total_weight=*/0, params);
    auto layout = dash::coinbase::build(
        work, tx_outs,
        dash::SharechainConfig::coinbase_text(params.is_testnet),
        params, uint256::ZERO);

    const size_t len = layout.bytes[41];
    std::vector<unsigned char> on_wire(layout.bytes.begin() + 42,
                                       layout.bytes.begin() + 42 + len);
    EXPECT_EQ(hex(on_wire),
              "03f07e0e2f5032506f6f6c2d74444153482f6332706f6f6c2f");
    EXPECT_EQ(ascii(on_wire).find(kOracleMarkerMain), std::string::npos);
}

// (19) The SHARE-MINT path and the BLOCK-COINBASE path derive their scriptSig
//      from the same helper. If they ever disagree by one byte the minted
//      share's gentx stops matching the block coinbase and the node
//      self-rejects, so pin the equality explicitly: what mint_runloop.hpp
//      writes into share_data['coinbase'] is exactly what build() serializes.
TEST(DashCoinbaseMarker, MintAndBlockCoinbaseScriptSigsAgree) {
    ScopedCoinbaseText no_override("");
    for (bool testnet : {false, true}) {
        auto params = dash::make_coin_params(testnet);
        dash::coin::DashWorkData work;
        work.m_height         = testnet ? 950000u : 2511303u;
        work.m_coinbase_value = 5000000000ull;

        const std::string resolved =
            dash::SharechainConfig::coinbase_text(params.is_testnet);

        // mint_runloop.hpp::build_producer_job body, verbatim.
        auto mint_sig = dash::coinbase::build_coinbase_scriptsig(
            work.m_height, resolved, params.is_testnet);
        ASSERT_GE(mint_sig.size(), 2u);
        ASSERT_LE(mint_sig.size(), dash::coinbase::MAX_SCRIPTSIG_LEN);

        std::vector<unsigned char> finder_h(20, 0x07);
        auto tx_outs = dash::coinbase::compute_dash_payouts(
            work.m_coinbase_value, /*payments=*/{}, uint160(finder_h),
            /*weights=*/{}, /*total_weight=*/0, params);
        auto layout = dash::coinbase::build(
            work, tx_outs, resolved, params, uint256::ZERO);

        const size_t len = layout.bytes[41];
        std::vector<unsigned char> block_sig(
            layout.bytes.begin() + 42, layout.bytes.begin() + 42 + len);
        EXPECT_EQ(hex(block_sig), hex(mint_sig)) << "testnet=" << testnet;
    }
}
