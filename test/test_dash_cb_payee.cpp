// SPDX-License-Identifier: AGPL-3.0-or-later
/// Phase G3b regression KAT — bad-cb-payee / empty-payee normalization.
///
/// Root cause (2026-06-27): on REAL testnet3 (fork-active) dashd surfaces the
/// platform credit-pool OP_RETURN burn INSIDE the getblocktemplate "masternode"
/// array as an entry shaped {"payee":"", "script":"6a", "amount":N}. The payee
/// field is PRESENT but an EMPTY string. The pre-fix getwork parser took the
/// "payee is a string" branch unconditionally, set payee="", and that empty
/// address later failed base58 decode -> the burn output was silently dropped ->
/// the assembled coinbase was missing a required output -> dashd rejected the
/// submitted block with bad-cb-payee.
///
/// Fix (rpc_data.hpp::normalize_payment): require a NON-EMPTY payee before
/// treating it as a base58 address; otherwise fall through to the raw
/// "!"+script form so the burn output is preserved. This KAT pins that
/// normalization directly (no live node required).

#include <gtest/gtest.h>

#include <cstdint>
#include <string>

#include <nlohmann/json.hpp>
#include <impl/dash/coin/rpc_data.hpp>   // dash::coin::normalize_payment, PackedPayment

using dash::coin::normalize_payment;
using dash::coin::PackedPayment;
using nlohmann::json;

// THE bug: empty payee + script "6a" must normalize to the raw "!6a" burn form,
// NOT to an empty base58 address that gets dropped downstream.
TEST(DashCbPayee, EmptyPayeeWithScriptNormalizesToRawScript) {
    json entry = {{"payee", ""}, {"script", "6a"}, {"amount", 1234}};
    PackedPayment pp = normalize_payment(entry);
    EXPECT_EQ(pp.payee, "!6a");
    EXPECT_EQ(pp.amount, 1234u);
}

// A real (non-empty) base58 masternode payee is kept verbatim as an address.
TEST(DashCbPayee, NonEmptyBase58PayeeKeptAsAddress) {
    json entry = {{"payee", "yVBb6QnAEZWfKomEwkEqRMUF5zFvFgerom"},
                  {"script", "76a914613cafd91ab596762c115c7e94d5e4b1225ccb2088ac"},
                  {"amount", 500}};
    PackedPayment pp = normalize_payment(entry);
    EXPECT_EQ(pp.payee, "yVBb6QnAEZWfKomEwkEqRMUF5zFvFgerom");
    EXPECT_EQ(pp.amount, 500u);
}

// payee key absent entirely, script present -> raw "!"+script form.
TEST(DashCbPayee, AbsentPayeeFallsToScript) {
    json entry = {{"script", "76a914deadbeef88ac"}, {"amount", 7}};
    PackedPayment pp = normalize_payment(entry);
    EXPECT_EQ(pp.payee, "!76a914deadbeef88ac");
    EXPECT_EQ(pp.amount, 7u);
}

// Non-empty payee wins even when a script is also present (address shape).
TEST(DashCbPayee, NonEmptyPayeeWinsOverScript) {
    json entry = {{"payee", "yMjcVgN3UM7X8UWZQPvx6UeXTXKeR7h8dx"},
                  {"script", "6a"}, {"amount", 9}};
    PackedPayment pp = normalize_payment(entry);
    EXPECT_EQ(pp.payee, "yMjcVgN3UM7X8UWZQPvx6UeXTXKeR7h8dx");
    EXPECT_EQ(pp.amount, 9u);
}

// Empty payee with NO script -> nothing assignable; payee stays empty and the
// getwork caller drops it only when amount==0. Here amount is carried through.
TEST(DashCbPayee, EmptyPayeeNoScriptLeavesPayeeEmpty) {
    json entry = {{"payee", ""}, {"amount", 42}};
    PackedPayment pp = normalize_payment(entry);
    EXPECT_TRUE(pp.payee.empty());
    EXPECT_EQ(pp.amount, 42u);
}

// Amount is parsed as an unsigned 64-bit value (no precision loss near 2^53).
TEST(DashCbPayee, LargeAmountParsedAsUint64) {
    json entry = {{"payee", ""}, {"script", "6a"}, {"amount", 9007199254740993ULL}};
    PackedPayment pp = normalize_payment(entry);
    EXPECT_EQ(pp.payee, "!6a");
    EXPECT_EQ(pp.amount, 9007199254740993ULL);
}

// A non-object entry (defensive) yields a default-empty PackedPayment, which the
// caller drops via the amount==0 guard.
TEST(DashCbPayee, NonObjectEntryYieldsEmptyPayment) {
    json entry = "not-an-object";
    PackedPayment pp = normalize_payment(entry);
    EXPECT_TRUE(pp.payee.empty());
    EXPECT_EQ(pp.amount, 0u);
}
// ═══════════════════════════════════════════════════════════════════════════
// bad-cb-payee round 2 (2026-07-19): the stratum-served coinbase LOST the
// masternode payee output whenever the GBT payee string failed base58 decode
// under the active net params — compute_dash_payouts silently `continue`d on
// an undecodable payee, and normalize_payment had discarded the GBT "script"
// bytes whenever a non-empty base58 payee was present, so there was no
// byte-faithful fallback. Reproduced live against testnet dashd
// (getblocktemplate proposal mode): a MAINNET-mode binary against the testnet
// daemon served a coinbase missing the 'y...' masternode output -> verdict
// "bad-cb-payee"; the same template under testnet params -> verdict null
// (valid). Fix: (a) normalize_payment ALWAYS preserves the raw GBT
// scriptPubKey bytes, (b) compute_dash_payouts falls back to them verbatim
// when the payee string does not decode, and (c) THROWS (never silently
// drops) when neither form is usable. These KATs pin all three arms plus a
// golden full-coinbase vector dashd accepted on live testnet.
// ═══════════════════════════════════════════════════════════════════════════

#include <impl/dash/coinbase_builder.hpp>   // compute_dash_payouts, build
#include <impl/dash/params.hpp>             // dash::make_coin_params
#include <btclibs/util/strencodings.h>      // ParseHex, HexStr

#include <map>
#include <span>
#include <stdexcept>
#include <vector>

namespace {

// The REAL dashd testnet GBT masternode array captured 2026-07-19 from
// 192.168.86.52:19998 (height 1517409 template): platform credit-pool burn +
// the round's masternode payee, exactly as dashd serialized them.
json real_testnet_masternode_entries()
{
    return json::array({
        {{"payee", ""},
         {"script", "6a"},
         {"amount", 66966830}},
        {{"payee", "yVXDAM73Tg6A44Bm3qduXsMCYxzuqBCT48"},
         {"script", "76a91464f2b2b84f62d68a2cd7f7f5fb2b5aa75ef716d788ac"},
         {"amount", 111611384}},
    });
}

std::vector<dash::coin::PackedPayment> normalized_real_payments()
{
    std::vector<dash::coin::PackedPayment> out;
    for (const auto& e : real_testnet_masternode_entries())
        out.push_back(normalize_payment(e));
    return out;
}

bool payments_contain(const std::vector<dash::coinbase::MinerPayout>& outs,
                      const std::string& script_hex, uint64_t amount)
{
    const auto want = ParseHex(script_hex);
    for (const auto& o : outs)
        if (o.amount == amount
            && o.script == std::vector<unsigned char>(want.begin(), want.end()))
            return true;
    return false;
}

} // namespace

// (a) The raw GBT scriptPubKey bytes survive normalization ALONGSIDE a
// non-empty base58 payee (previously they were discarded on that branch).
TEST(DashCbPayee, NormalizePreservesRawScriptAlongsideBase58Payee) {
    auto pp = normalize_payment(real_testnet_masternode_entries()[1]);
    EXPECT_EQ(pp.payee, "yVXDAM73Tg6A44Bm3qduXsMCYxzuqBCT48");
    EXPECT_EQ(pp.amount, 111611384u);
    const auto want = ParseHex("76a91464f2b2b84f62d68a2cd7f7f5fb2b5aa75ef716d788ac");
    EXPECT_EQ(pp.script, std::vector<unsigned char>(want.begin(), want.end()));
}

// Right-net (testnet) params: both consensus-required payments present, payee
// decoded from the base58 string (share-wire form), byte-identical to the GBT
// script.
TEST(DashCbPayee, ComputePayoutsKeepsMasternodeOutputsOnRightNet) {
    const auto params = dash::make_coin_params(/*testnet=*/true);
    std::map<std::vector<unsigned char>, uint64_t> no_weights;
    auto outs = dash::coinbase::compute_dash_payouts(
        /*subsidy=*/238104286ULL, normalized_real_payments(),
        /*miner_pubkey_hash=*/uint160(), no_weights, /*total_weight=*/0, params);
    EXPECT_TRUE(payments_contain(outs, "6a", 66966830u));
    EXPECT_TRUE(payments_contain(
        outs, "76a91464f2b2b84f62d68a2cd7f7f5fb2b5aa75ef716d788ac", 111611384u));
}

// (b) THE regression: wrong-net (mainnet) params make the 'y...' testnet payee
// undecodable — pre-fix the masternode output silently vanished from the
// coinbase (live dashd verdict: bad-cb-payee). Post-fix the GBT-provided raw
// scriptPubKey is emitted VERBATIM, so the consensus-required output survives.
TEST(DashCbPayee, ComputePayoutsFallsBackToGbtScriptOnWrongNetParams) {
    const auto params = dash::make_coin_params(/*testnet=*/false);
    std::map<std::vector<unsigned char>, uint64_t> no_weights;
    auto outs = dash::coinbase::compute_dash_payouts(
        /*subsidy=*/238104286ULL, normalized_real_payments(),
        /*miner_pubkey_hash=*/uint160(), no_weights, /*total_weight=*/0, params);
    EXPECT_TRUE(payments_contain(outs, "6a", 66966830u));
    EXPECT_TRUE(payments_contain(
        outs, "76a91464f2b2b84f62d68a2cd7f7f5fb2b5aa75ef716d788ac", 111611384u))
        << "masternode payee output missing under wrong-net params -- "
           "bad-cb-payee regression";
}

// (c) Neither form usable -> THROW. A silently-dropped required payment is a
// guaranteed bad-cb-payee reject (lost block); the builder must refuse.
TEST(DashCbPayee, ComputePayoutsThrowsOnUndecodablePayeeWithoutScript) {
    dash::coin::PackedPayment broken;
    broken.payee  = "not-a-decodable-payee";
    broken.amount = 12345;
    const auto params = dash::make_coin_params(/*testnet=*/true);
    std::map<std::vector<unsigned char>, uint64_t> no_weights;
    EXPECT_THROW(
        dash::coinbase::compute_dash_payouts(
            /*subsidy=*/238104286ULL, {broken}, uint160(), no_weights, 0, params),
        std::runtime_error);
}

// GOLDEN (live-accepted): the full coinbase c2pool-dash served for the real
// height-1517409 testnet template, byte-for-byte. This exact serialization
// (zeroed nonce64 slot) was submitted to dashd 192.168.86.52 via
// getblocktemplate proposal mode on 2026-07-19 and ACCEPTED (verdict null):
// worker/finder output, platform OP_RETURN burn, masternode payee, donation
// tail, c2pool OP_RETURN ref+nonce64 slot, and the DIP4 CbTx extra_payload.
TEST(DashCbPayee, GoldenLiveAcceptedTestnetCoinbase) {
    dash::coin::DashWorkData work;
    work.m_height         = 1517409;
    work.m_coinbase_value = 238104286ULL;
    work.m_packed_payments = normalized_real_payments();
    const auto payload = ParseHex(
        "0300612717008fd43916c4062570542a746a18808d00bb47107d541c0eeb0defc107fd"
        "07bc6b7f6665a24049a71e2a3460ab19a23b3169d71f4eb42448b4589ccf138be493ec"
        "01b8c52ecdcb1f335749e9974eef630753dd0496c3e59b3e0362c5776284f0b5190cb9"
        "37134903a9fce51754bda7dd04da09022ef0b6abe378260d5982f4048cb9344dbac1d6"
        "a82866ec2f679f243ce8e65268e2711f4026bef8034dfb6d264afbb70b659cd21e0000");
    work.m_coinbase_payload.assign(payload.begin(), payload.end());

    const auto params = dash::make_coin_params(/*testnet=*/true);
    std::map<std::vector<unsigned char>, uint64_t> no_weights;
    auto outs = dash::coinbase::compute_dash_payouts(
        work.m_coinbase_value, work.m_packed_payments,
        /*miner_pubkey_hash=*/uint160(), no_weights, /*total_weight=*/0, params);
    auto layout = dash::coinbase::build(work, outs, /*pool_tag=*/"c2pool",
                                        params, /*ref_hash=*/uint256::ZERO);

    const std::string expected =
        "03000500010000000000000000000000000000000000000000000000000000000000"
        "000000ffffffff0a036127176332706f6f6cffffffff05792a1200000000001976a9"
        "14000000000000000000000000000000000000000088ac2ed5fd0300000000016af8"
        "0da706000000001976a91464f2b2b84f62d68a2cd7f7f5fb2b5aa75ef716d788ac3f"
        "217a03000000001976a91420cb5c22b1e4d5947e5c112c7696b51ad9af3c6188ac00"
        "000000000000002a6a28000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000af0300612717008fd43916c40625"
        "70542a746a18808d00bb47107d541c0eeb0defc107fd07bc6b7f6665a24049a71e2a"
        "3460ab19a23b3169d71f4eb42448b4589ccf138be493ec01b8c52ecdcb1f335749e9"
        "974eef630753dd0496c3e59b3e0362c5776284f0b5190cb937134903a9fce51754bd"
        "a7dd04da09022ef0b6abe378260d5982f4048cb9344dbac1d6a82866ec2f679f243c"
        "e8e65268e2711f4026bef8034dfb6d264afbb70b659cd21e0000";
    EXPECT_EQ(HexStr(std::span<const unsigned char>(
                  layout.bytes.data(), layout.bytes.size())),
              expected);
}
