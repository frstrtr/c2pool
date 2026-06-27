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
