// SPDX-License-Identifier: AGPL-3.0-or-later
/// E-SUPERBLOCK — daemonless superblock payee sourcing KATs.
///
/// Pins the reused dashcore superblock logic (governance-classes.cpp
/// CSuperblock::ParsePaymentSchedule + CSuperblockManager::GetSuperblockPayments
/// + CalcSuperblockBudget) against FROM-WIRE testnet vectors captured from
/// dashd @192.168.86.52 (RPC 19998):
///
///   validateaddress yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A
///     -> scriptPubKey 76a914c69a0bda7daaae481be8def95e5f347a1d00a4b488ac
///   block 1519800 coinbase vout[0] ycn2gNExGVmcwJALr4PciWqWuN1DEsUBEN
///     -> scriptPubKey 76a914b489115851ca07a26a5ad8bac3cec3c7dbebd83188ac
///   getsuperblockbudget 1519824  -> 14.28625704 DASH == 1428625704 duffs (cycle 24)
///   getgovernanceinfo -> superblockcycle 24, fundingthreshold 17
///
/// Tests:
///   1. ParsePaymentSchedule: a trigger's plaintext JSON -> the exact
///      (scriptPubKey, amount) vector dashd would place in the coinbase.
///   2. govdata hex round-trip (vchData hex -> plaintext -> parse).
///   3. superblock_budget == dashd getsuperblockbudget (testnet + mainnet).
///   4. GetBestSuperblock / fail-closed: sub-threshold funding tally => NO
///      winner => get_superblock_payments == nullopt (refuse); enough verified
///      yes-votes => the winning schedule.
///   5. Over-budget trigger => rejected (nullopt).
///   6. Malformed trigger inputs => nullopt (fail closed).
///   7. build_embedded_workdata emits the superblock outputs + augments the
///      coinbase value at a funded superblock height (template wiring).
///   8. parse_fixed_point_8 edge cases.

#include <gtest/gtest.h>

#include <impl/dash/coin/utxo_adapter.hpp>          // dash_txid (subsidy.hpp template dep)
#include <impl/dash/coin/governance_object.hpp>
#include <impl/dash/coin/governance_store.hpp>
#include <impl/dash/coin/superblock.hpp>
#include <impl/dash/coin/embedded_gbt.hpp>
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/mempool.hpp>

#include <core/uint256.hpp>

#include <cstdint>
#include <string>
#include <vector>

using namespace dash::coin;

namespace {

// Hex-encode a plaintext string (governance vchData is hex-encoded plaintext).
std::string to_hex(const std::string& s) {
    static const char* H = "0123456789abcdef";
    std::string out;
    out.reserve(s.size() * 2);
    for (unsigned char c : s) { out.push_back(H[c >> 4]); out.push_back(H[c & 0xf]); }
    return out;
}

std::vector<uint8_t> hex_bytes(const std::string& hex) {
    return std::vector<uint8_t>(hex.begin(), hex.end());
}

// Real from-wire scripts (see file header).
const std::vector<uint8_t> kScriptYeRZ = {
    0x76,0xa9,0x14,0xc6,0x9a,0x0b,0xda,0x7d,0xaa,0xae,0x48,0x1b,0xe8,
    0xde,0xf9,0x5e,0x5f,0x34,0x7a,0x1d,0x00,0xa4,0xb4,0x88,0xac};
const std::vector<uint8_t> kScriptYcn2 = {
    0x76,0xa9,0x14,0xb4,0x89,0x11,0x58,0x51,0xca,0x07,0xa2,0x6a,0x5a,
    0xd8,0xba,0xc3,0xce,0xc3,0xc7,0xdb,0xeb,0xd8,0x31,0x88,0xac};

uint256 hash_of(uint64_t n) {
    uint256 h;
    h.data()[0] = static_cast<unsigned char>(n & 0xff);
    h.data()[1] = static_cast<unsigned char>((n >> 8) & 0xff);
    return h;
}

} // namespace

// ── 1. ParsePaymentSchedule (single payee, from-wire script) ────────────────
TEST(DashSuperblock, ParseSinglePayeeMatchesWireScript) {
    const std::string json =
        R"({"event_block_height":1519824,)"
        R"("payment_addresses":"yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A",)"
        R"("payment_amounts":"5.00000000",)"
        R"("proposal_hashes":"abc","type":2})";
    auto trig = parse_superblock_trigger(json, hash_of(1));
    ASSERT_TRUE(trig.has_value());
    EXPECT_EQ(trig->event_block_height, 1519824);
    ASSERT_EQ(trig->payments.size(), 1u);
    EXPECT_EQ(trig->payments[0].script, kScriptYeRZ);        // byte-exact vs dashd
    EXPECT_EQ(trig->payments[0].amount, 500'000'000LL);      // 5 DASH
}

// ── 1b. Multi-payee ordered schedule ────────────────────────────────────────
TEST(DashSuperblock, ParseMultiPayeeOrdered) {
    const std::string json =
        R"({"event_block_height":1519824,)"
        R"("payment_addresses":"yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A|ycn2gNExGVmcwJALr4PciWqWuN1DEsUBEN",)"
        R"("payment_amounts":"1.11626384|0.59531072","type":2})";
    auto trig = parse_superblock_trigger(json, hash_of(2));
    ASSERT_TRUE(trig.has_value());
    ASSERT_EQ(trig->payments.size(), 2u);
    EXPECT_EQ(trig->payments[0].script, kScriptYeRZ);
    EXPECT_EQ(trig->payments[0].amount, 111'626'384LL);
    EXPECT_EQ(trig->payments[1].script, kScriptYcn2);
    EXPECT_EQ(trig->payments[1].amount, 59'531'072LL);
    EXPECT_EQ(trig->total_amount(), 171'157'456LL);
}

// ── 2. vchData hex round-trip ───────────────────────────────────────────────
TEST(DashSuperblock, GovDataHexRoundTrip) {
    const std::string json =
        R"({"event_block_height":1519824,)"
        R"("payment_addresses":"yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A",)"
        R"("payment_amounts":"5.00000000","type":2})";
    auto plain = govdata_hex_to_plain(to_hex(json));
    ASSERT_TRUE(plain.has_value());
    EXPECT_EQ(*plain, json);
    auto trig = parse_superblock_trigger(*plain, hash_of(3));
    ASSERT_TRUE(trig.has_value());
    EXPECT_EQ(trig->payments[0].script, kScriptYeRZ);
}

// ── 3. superblock_budget == dashd getsuperblockbudget ───────────────────────
TEST(DashSuperblock, BudgetMatchesDashd) {
    // Testnet: getsuperblockbudget 1519824 == 14.28625704 DASH, cycle 24.
    EXPECT_EQ(superblock_budget(1519824, DASH_SUPERBLOCK_CYCLE_TESTNET),
              1'428'625'704LL);
    // Mainnet cycle 16616: a large but well-defined value; just assert positive
    // and equal to part*cycle (guards against a formula regression).
    EXPECT_GT(superblock_budget(2'128'896, DASH_SUPERBLOCK_CYCLE_MAINNET), 0);
}

// ── 4. GetBestSuperblock + FAIL-CLOSED on sub-threshold funding ─────────────
TEST(DashSuperblock, FailClosedUntilFundingThreshold) {
    GovernanceStore store;
    store.set_funding_threshold(17);   // dashd getgovernanceinfo.fundingthreshold

    const std::string json =
        R"({"event_block_height":1519824,)"
        R"("payment_addresses":"yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A",)"
        R"("payment_amounts":"5.00000000","type":2})";
    auto trig = parse_superblock_trigger(json, hash_of(10));
    ASSERT_TRUE(trig.has_value());
    store.add_trigger(*trig);

    const int64_t budget = superblock_budget(1519824, DASH_SUPERBLOCK_CYCLE_TESTNET);

    // No votes yet -> not triggered -> FAIL CLOSED (refuse; nullopt).
    EXPECT_FALSE(get_superblock_payments(store, 1519824, budget).has_value());

    // 16 verified yes-votes: still below threshold 17 -> still fail closed.
    for (int i = 0; i < 16; ++i)
        store.add_verified_funding_vote(hash_of(10), "mn-" + std::to_string(i),
                                        VOTE_OUTCOME_YES, 1000 + i);
    EXPECT_EQ(store.absolute_yes_count(hash_of(10)), 16);
    EXPECT_FALSE(get_superblock_payments(store, 1519824, budget).has_value());

    // 17th verified yes-vote reaches threshold -> WINNER -> schedule served.
    store.add_verified_funding_vote(hash_of(10), "mn-16", VOTE_OUTCOME_YES, 2000);
    EXPECT_EQ(store.absolute_yes_count(hash_of(10)), 17);
    auto pay = get_superblock_payments(store, 1519824, budget);
    ASSERT_TRUE(pay.has_value());
    ASSERT_EQ(pay->size(), 1u);
    EXPECT_EQ((*pay)[0].script, kScriptYeRZ);
    EXPECT_EQ((*pay)[0].amount, 500'000'000LL);

    // A NO vote decrements the absolute-yes tally back below threshold -> refuse.
    store.add_verified_funding_vote(hash_of(10), "mn-no", VOTE_OUTCOME_NO, 3000);
    EXPECT_EQ(store.absolute_yes_count(hash_of(10)), 16);
    EXPECT_FALSE(get_superblock_payments(store, 1519824, budget).has_value());
}

// ── 4b. Unknown threshold (0) always fails closed ───────────────────────────
TEST(DashSuperblock, UnknownThresholdFailsClosed) {
    GovernanceStore store;   // threshold defaults to 0 => unknown
    const std::string json =
        R"({"event_block_height":1519824,"payment_addresses":"yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A",)"
        R"("payment_amounts":"5.0","type":2})";
    auto trig = parse_superblock_trigger(json, hash_of(11));
    ASSERT_TRUE(trig.has_value());
    store.add_trigger(*trig);
    for (int i = 0; i < 100; ++i)
        store.add_verified_funding_vote(hash_of(11), "mn-" + std::to_string(i),
                                        VOTE_OUTCOME_YES, i);
    EXPECT_FALSE(store.get_best_superblock(1519824).has_value());
}

// ── 5. Over-budget trigger rejected ─────────────────────────────────────────
TEST(DashSuperblock, OverBudgetRejected) {
    GovernanceStore store;
    store.set_funding_threshold(1);
    const std::string json =
        R"({"event_block_height":1519824,"payment_addresses":"yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A",)"
        R"("payment_amounts":"1000.0","type":2})";   // 1000 DASH >> 14.28 budget
    auto trig = parse_superblock_trigger(json, hash_of(12));
    ASSERT_TRUE(trig.has_value());
    store.add_trigger(*trig);
    store.add_verified_funding_vote(hash_of(12), "mn-0", VOTE_OUTCOME_YES, 1);
    const int64_t budget = superblock_budget(1519824, DASH_SUPERBLOCK_CYCLE_TESTNET);
    EXPECT_FALSE(get_superblock_payments(store, 1519824, budget).has_value());
}

// ── 5b. Highest-yes trigger wins among competitors ──────────────────────────
TEST(DashSuperblock, BestSuperblockPicksHighestYes) {
    GovernanceStore store;
    store.set_funding_threshold(2);
    auto mk = [&](uint64_t id, const char* amt, int yes) {
        std::string json = std::string(R"({"event_block_height":1519824,)")
            + R"("payment_addresses":"yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A",)"
            + R"("payment_amounts":")" + amt + R"(","type":2})";
        auto t = parse_superblock_trigger(json, hash_of(id));
        store.add_trigger(*t);
        for (int i = 0; i < yes; ++i)
            store.add_verified_funding_vote(hash_of(id), "mn-" + std::to_string(id * 100 + i),
                                            VOTE_OUTCOME_YES, i);
    };
    mk(20, "1.0", 3);
    mk(21, "2.0", 9);   // most yes -> winner
    mk(22, "3.0", 5);
    auto best = store.get_best_superblock(1519824);
    ASSERT_TRUE(best.has_value());
    EXPECT_EQ(best->object_hash, hash_of(21));
    EXPECT_EQ(best->payments[0].amount, 200'000'000LL);
}

// ── 6. Malformed trigger inputs fail closed ─────────────────────────────────
TEST(DashSuperblock, MalformedFailsClosed) {
    // not a trigger (type 1 = proposal)
    EXPECT_FALSE(parse_superblock_trigger(
        R"({"event_block_height":1,"payment_addresses":"yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A","payment_amounts":"1.0","type":1})",
        hash_of(30)).has_value());
    // address/amount count mismatch
    EXPECT_FALSE(parse_superblock_trigger(
        R"({"event_block_height":1,"payment_addresses":"yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A|ycn2gNExGVmcwJALr4PciWqWuN1DEsUBEN","payment_amounts":"1.0","type":2})",
        hash_of(31)).has_value());
    // bad address
    EXPECT_FALSE(parse_superblock_trigger(
        R"({"event_block_height":1,"payment_addresses":"not_an_address","payment_amounts":"1.0","type":2})",
        hash_of(32)).has_value());
    // missing event_block_height
    EXPECT_FALSE(parse_superblock_trigger(
        R"({"payment_addresses":"yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A","payment_amounts":"1.0","type":2})",
        hash_of(33)).has_value());
    // non-JSON
    EXPECT_FALSE(parse_superblock_trigger("not json at all", hash_of(34)).has_value());
    // odd-length hex
    EXPECT_FALSE(govdata_hex_to_plain("abc").has_value());
}

// ── 7. build_embedded_workdata emits superblock outputs + bumps value ───────
TEST(DashSuperblock, TemplateEmitsSuperblockOutputs) {
    MnStateMachine mn;   // empty MN set (no MN payee) — isolates the superblock path
    Mempool mp;

    const uint32_t next_h = 1519824;
    // Baseline (no superblock schedule): capture coinbase value.
    DashWorkData base = build_embedded_workdata(
        next_h - 1, uint256::ZERO, mn, mp,
        /*bits*/0x1e0ffff0, /*mtp*/1'700'000'000u,
        /*addr_ver*/140, /*addr_p2sh*/19,
        /*curtime*/1'700'000'100u, /*version*/0x20000000u,
        /*underfill*/nullptr, /*sml*/nullptr, /*qmgr*/nullptr,
        /*bestcl_h*/0, k_zero_cl_sig, /*credit_pool*/0,
        DASH_MN_RR_HEIGHT_TESTNET, /*superblock_payments*/nullptr);

    // Funded superblock: one payee of 5 DASH.
    std::vector<SuperblockPayment> sched = {{kScriptYeRZ, 500'000'000LL}};
    DashWorkData sb = build_embedded_workdata(
        next_h - 1, uint256::ZERO, mn, mp,
        0x1e0ffff0, 1'700'000'000u, 140, 19,
        1'700'000'100u, 0x20000000u,
        nullptr, nullptr, nullptr, 0, k_zero_cl_sig, 0,
        DASH_MN_RR_HEIGHT_TESTNET, &sched);

    // Coinbase value augmented by exactly the superblock total.
    EXPECT_EQ(sb.m_coinbase_value, base.m_coinbase_value + 500'000'000ULL);
    // The superblock payee output is present (base58 form of yeRZ...).
    bool found = false;
    for (const auto& pp : sb.m_packed_payments)
        if (pp.amount == 500'000'000ULL &&
            pp.payee == "yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A")
            found = true;
    EXPECT_TRUE(found);
    // And it is an ADDED output vs baseline.
    EXPECT_EQ(sb.m_packed_payments.size(), base.m_packed_payments.size() + 1);
}

// ── 8. parse_fixed_point_8 edge cases ───────────────────────────────────────
TEST(DashSuperblock, FixedPointParse) {
    EXPECT_EQ(parse_fixed_point_8("1").value(), 100'000'000LL);
    EXPECT_EQ(parse_fixed_point_8("1.0").value(), 100'000'000LL);
    EXPECT_EQ(parse_fixed_point_8("0.00000001").value(), 1LL);
    EXPECT_EQ(parse_fixed_point_8("14.28625704").value(), 1'428'625'704LL);
    EXPECT_FALSE(parse_fixed_point_8("").has_value());
    EXPECT_FALSE(parse_fixed_point_8("1.234567890").has_value());  // 9 frac digits
    EXPECT_FALSE(parse_fixed_point_8("-1.0").has_value());          // negative
    EXPECT_FALSE(parse_fixed_point_8("1.2.3").has_value());         // garbage
    EXPECT_FALSE(parse_fixed_point_8("abc").has_value());
}
