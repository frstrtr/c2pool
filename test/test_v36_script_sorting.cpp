// test_v36_script_sorting.cpp — Cross-implementation V36 output sorting tests.
//
// V36 consensus: PPLNS outputs are sorted by (amount, script_bytes) ascending.
// This replaces the pre-V36 sort by (amount, address_string).
//
// These tests verify that C++ sorting produces the exact same order as the
// Python reference implementation (p2pool/test/test_v36_script_sorting.py).

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace {

// Helper: build P2PKH scriptPubKey from 20-byte hash160
std::vector<unsigned char> make_p2pkh_script(const std::vector<unsigned char>& hash160)
{
    // OP_DUP OP_HASH160 PUSH20 <hash160> OP_EQUALVERIFY OP_CHECKSIG
    std::vector<unsigned char> script;
    script.push_back(0x76);
    script.push_back(0xa9);
    script.push_back(0x14);
    script.insert(script.end(), hash160.begin(), hash160.end());
    script.push_back(0x88);
    script.push_back(0xac);
    return script;
}

// Helper: build P2WPKH scriptPubKey from 20-byte hash160
std::vector<unsigned char> make_p2wpkh_script(const std::vector<unsigned char>& hash160)
{
    // OP_0 PUSH20 <hash160>
    std::vector<unsigned char> script;
    script.push_back(0x00);
    script.push_back(0x14);
    script.insert(script.end(), hash160.begin(), hash160.end());
    return script;
}

// Helper: build P2SH scriptPubKey from 20-byte hash160
std::vector<unsigned char> make_p2sh_script(const std::vector<unsigned char>& hash160)
{
    // OP_HASH160 PUSH20 <hash160> OP_EQUAL
    std::vector<unsigned char> script;
    script.push_back(0xa9);
    script.push_back(0x14);
    script.insert(script.end(), hash160.begin(), hash160.end());
    script.push_back(0x87);
    return script;
}

// Helper: create hash160 filled with a repeated byte
std::vector<unsigned char> fill_hash160(unsigned char byte)
{
    return std::vector<unsigned char>(20, byte);
}

// V36 output sorting: matches p2pool's generate_transaction (V36 path)
using ScriptAmount = std::pair<std::vector<unsigned char>, uint64_t>;

std::vector<ScriptAmount> v36_sort_outputs(
    const std::map<std::vector<unsigned char>, uint64_t>& amounts,
    const std::set<std::vector<unsigned char>>& excluded)
{
    std::vector<ScriptAmount> outputs;
    for (const auto& [script, amount] : amounts) {
        if (excluded.count(script) == 0 && amount > 0)
            outputs.push_back({script, amount});
    }

    std::sort(outputs.begin(), outputs.end(),
        [](const ScriptAmount& a, const ScriptAmount& b) {
            if (a.second != b.second) return a.second < b.second;
            return a.first < b.first;
        });

    // Keep last 4000 (highest amounts)
    if (outputs.size() > 4000)
        outputs.erase(outputs.begin(), outputs.end() - 4000);

    return outputs;
}

} // namespace

// ============================================================================
// Same-type sorting tests
// ============================================================================

TEST(V36ScriptSorting, SameTypeP2PKH_DifferentAmounts)
{
    auto script_a = make_p2pkh_script(fill_hash160(0xaa));
    auto script_b = make_p2pkh_script(fill_hash160(0xbb));
    std::map<std::vector<unsigned char>, uint64_t> amounts = {
        {script_a, 3000}, {script_b, 1000}
    };
    auto result = v36_sort_outputs(amounts, {});
    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0].second, 1000u);  // lower amount first
    EXPECT_EQ(result[1].second, 3000u);
}

TEST(V36ScriptSorting, EqualAmountsP2PKH_TiebreakByScript)
{
    auto script_a = make_p2pkh_script(fill_hash160(0xaa));
    auto script_b = make_p2pkh_script(fill_hash160(0xbb));
    std::map<std::vector<unsigned char>, uint64_t> amounts = {
        {script_a, 5000}, {script_b, 5000}
    };
    auto result = v36_sort_outputs(amounts, {});
    ASSERT_EQ(result.size(), 2u);
    // 0xaa < 0xbb in script bytes
    EXPECT_EQ(result[0].first, script_a);
    EXPECT_EQ(result[1].first, script_b);
}

// ============================================================================
// Mixed address type tests — THE critical consensus test
// ============================================================================

TEST(V36ScriptSorting, MixedTypes_EqualAmounts_ScriptOrder)
{
    // This is the KEY test: P2WPKH vs P2PKH with equal amounts.
    // Address-based sort: P2PKH "m..." < P2WPKH "tltc1q..." (pre-V36)
    // Script-based sort:  P2WPKH 0x0014 < P2PKH 0x76a9   (V36)
    // These are OPPOSITE orders.

    auto hash160 = fill_hash160(0xab);
    auto p2pkh  = make_p2pkh_script(hash160);   // 76 a9 14 ... 88 ac
    auto p2wpkh = make_p2wpkh_script(hash160);  // 00 14 ...

    std::map<std::vector<unsigned char>, uint64_t> amounts = {
        {p2pkh, 5000}, {p2wpkh, 5000}
    };
    auto result = v36_sort_outputs(amounts, {});

    ASSERT_EQ(result.size(), 2u);
    // V36: P2WPKH (0x00) sorts before P2PKH (0x76)
    EXPECT_EQ(result[0].first, p2wpkh) << "P2WPKH (0x0014) must sort before P2PKH (0x76a9)";
    EXPECT_EQ(result[1].first, p2pkh);
}

TEST(V36ScriptSorting, AllThreeTypes_EqualAmounts)
{
    auto hash160 = fill_hash160(0xdd);
    auto p2wpkh = make_p2wpkh_script(hash160);  // 00 14 ...
    auto p2pkh  = make_p2pkh_script(hash160);    // 76 a9 14 ... 88 ac
    auto p2sh   = make_p2sh_script(hash160);     // a9 14 ... 87

    std::map<std::vector<unsigned char>, uint64_t> amounts = {
        {p2pkh, 5000}, {p2wpkh, 5000}, {p2sh, 5000}
    };
    auto result = v36_sort_outputs(amounts, {});

    ASSERT_EQ(result.size(), 3u);
    // Script byte order: 0x00 < 0x76 < 0xa9
    EXPECT_EQ(result[0].first, p2wpkh) << "P2WPKH (0x00) first";
    EXPECT_EQ(result[1].first, p2pkh)  << "P2PKH (0x76) second";
    EXPECT_EQ(result[2].first, p2sh)   << "P2SH (0xa9) third";
}

TEST(V36ScriptSorting, MixedTypes_DifferentAmounts_PrimarySort)
{
    auto p2pkh  = make_p2pkh_script(fill_hash160(0xaa));
    auto p2wpkh = make_p2wpkh_script(fill_hash160(0xbb));
    auto p2sh   = make_p2sh_script(fill_hash160(0xcc));

    std::map<std::vector<unsigned char>, uint64_t> amounts = {
        {p2pkh, 3000}, {p2wpkh, 1000}, {p2sh, 2000}
    };
    auto result = v36_sort_outputs(amounts, {});

    ASSERT_EQ(result.size(), 3u);
    EXPECT_EQ(result[0].second, 1000u);
    EXPECT_EQ(result[1].second, 2000u);
    EXPECT_EQ(result[2].second, 3000u);
}

// ============================================================================
// Edge cases
// ============================================================================

TEST(V36ScriptSorting, ExcludedScripts)
{
    auto donation = make_p2sh_script(fill_hash160(0x8c));
    auto miner_a  = make_p2pkh_script(fill_hash160(0x11));
    auto miner_b  = make_p2pkh_script(fill_hash160(0x22));

    std::map<std::vector<unsigned char>, uint64_t> amounts = {
        {miner_a, 3000}, {miner_b, 2000}, {donation, 500}
    };
    auto result = v36_sort_outputs(amounts, {donation});

    ASSERT_EQ(result.size(), 2u);
    for (const auto& [s, a] : result)
        EXPECT_NE(s, donation) << "Donation script must be excluded";
}

TEST(V36ScriptSorting, SingleMiner)
{
    auto script = make_p2pkh_script(fill_hash160(0xff));
    std::map<std::vector<unsigned char>, uint64_t> amounts = {{script, 10000}};
    auto result = v36_sort_outputs(amounts, {});
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].second, 10000u);
}

TEST(V36ScriptSorting, ZeroAmountExcluded)
{
    auto script_a = make_p2pkh_script(fill_hash160(0xaa));
    auto script_b = make_p2pkh_script(fill_hash160(0xbb));
    std::map<std::vector<unsigned char>, uint64_t> amounts = {
        {script_a, 5000}, {script_b, 0}
    };
    auto result = v36_sort_outputs(amounts, {});
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].first, script_a);
}

TEST(V36ScriptSorting, MaxOutputsTruncation)
{
    std::map<std::vector<unsigned char>, uint64_t> amounts;
    for (int i = 0; i < 4100; ++i) {
        std::vector<unsigned char> hash160(20, 0);
        hash160[0] = static_cast<unsigned char>((i >> 8) & 0xff);
        hash160[1] = static_cast<unsigned char>(i & 0xff);
        amounts[make_p2pkh_script(hash160)] = static_cast<uint64_t>(i + 1);
    }
    auto result = v36_sort_outputs(amounts, {});
    ASSERT_EQ(result.size(), 4000u);
    // Lowest 100 amounts (1..100) should be dropped
    EXPECT_EQ(result[0].second, 101u);
    EXPECT_EQ(result[3999].second, 4100u);
}

// ============================================================================
// Cross-implementation test vector
// ============================================================================

TEST(V36ScriptSorting, CrossImplementationTestVector)
{
    // These EXACT scripts and amounts must produce the same order in
    // both C++ (this test) and Python (test_v36_script_sorting.py).

    // P2WPKH: 00 14 a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
    std::vector<unsigned char> h1 = {
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0xa1, 0xb2, 0xc3, 0xd4,
        0xe5, 0xf6, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0xa1, 0xb2
    };
    auto p2wpkh = make_p2wpkh_script(h1);

    // P2PKH: 76 a9 14 1234567890abcdef1234567890abcdef12345678 88 ac
    std::vector<unsigned char> h2 = {
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34,
        0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78
    };
    auto p2pkh = make_p2pkh_script(h2);

    // P2SH: a9 14 fedcba9876543210fedcba9876543210fedcba98 87
    std::vector<unsigned char> h3 = {
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc,
        0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98
    };
    auto p2sh = make_p2sh_script(h3);

    std::map<std::vector<unsigned char>, uint64_t> amounts = {
        {p2wpkh, 12345678},  // Same amount as P2PKH — tiebreak by script
        {p2pkh,  12345678},
        {p2sh,   87654321},
    };

    auto result = v36_sort_outputs(amounts, {});

    ASSERT_EQ(result.size(), 3u);
    // 1. P2WPKH (amount=12345678, script=0x0014...) — lowest script for tied amount
    EXPECT_EQ(result[0].second, 12345678u);
    EXPECT_EQ(result[0].first[0], 0x00) << "First should be P2WPKH";
    EXPECT_EQ(result[0].first[1], 0x14);
    // 2. P2PKH (amount=12345678, script=0x76a914...)
    EXPECT_EQ(result[1].second, 12345678u);
    EXPECT_EQ(result[1].first[0], 0x76) << "Second should be P2PKH";
    // 3. P2SH (amount=87654321)
    EXPECT_EQ(result[2].second, 87654321u);
    EXPECT_EQ(result[2].first[0], 0xa9) << "Third should be P2SH";
}

// ============================================================================
// Merged payout hash serialization format
// ============================================================================

TEST(V36ScriptSorting, MergedPayoutHashFormat)
{
    // Verify that script-hex serialization produces deterministic output.
    // Keys sorted by raw script bytes → hex encoding preserves order.
    auto script_a = make_p2pkh_script(fill_hash160(0xaa));
    auto script_b = make_p2pkh_script(fill_hash160(0xbb));

    // Sort by script bytes
    std::map<std::vector<unsigned char>, uint64_t> weights = {
        {script_b, 2000}, {script_a, 3000}
    };

    std::string payload;
    auto to_hex = [](const std::vector<unsigned char>& v) {
        static const char digits[] = "0123456789abcdef";
        std::string hex;
        hex.reserve(v.size() * 2);
        for (unsigned char c : v) {
            hex.push_back(digits[c >> 4]);
            hex.push_back(digits[c & 0xf]);
        }
        return hex;
    };

    for (const auto& [script, w] : weights) {
        if (!payload.empty()) payload.push_back('|');
        payload += to_hex(script);
        payload.push_back(':');
        payload += std::to_string(w);
    }
    payload += "|T:5500|D:500";

    // Verify hex of 0xaa script comes before 0xbb script
    auto pos_aa = payload.find("76a914" + std::string(40, 'a') + "88ac");
    auto pos_bb = payload.find("76a914" + std::string(40, 'b') + "88ac");
    EXPECT_LT(pos_aa, pos_bb) << "0xaa script hex must appear before 0xbb";
    EXPECT_NE(payload.find("T:5500"), std::string::npos);
    EXPECT_NE(payload.find("D:500"), std::string::npos);
}
