// SPDX-License-Identifier: AGPL-3.0-or-later
// B6 template parity check: c2pool-btc algorithmic functions vs Bitcoin
// Core consensus oracles. This is a standalone smoke-style harness — not
// a full gtest fixture — so it can be built and run without restoring the
// btc/test subdir's CMake plumbing.
//
// Build (from repo root):
//   g++ -std=gnu++20 -I src -I src/btclibs -I /usr/include \
//       src/impl/btc/test/template_parity_test.cpp \
//       -o /tmp/btc_template_parity
// Run:
//   /tmp/btc_template_parity
//
// Failing cases print PASS/FAIL with computed vs expected, return non-zero
// exit on any failure.

#include <impl/btc/coin/template_builder.hpp>
#include <impl/btc/coin/header_chain.hpp>

#include <cstdio>
#include <cstdint>
#include <vector>
#include <string>

using btc::coin::get_block_subsidy;
using btc::coin::compute_merkle_root;
using btc::coin::calculate_next_work_required;
using btc::coin::BTCChainParams;

static int g_fails = 0;

static void check(bool ok, const char* label) {
    std::printf("  %s %s\n", ok ? "PASS" : "FAIL", label);
    if (!ok) ++g_fails;
}

// ─────────────────────────────────────────────────────────────────────────────
// Subsidy parity — oracle values are well-known consensus constants from
// Bitcoin Core's GetBlockSubsidy() across each halving boundary.
// ─────────────────────────────────────────────────────────────────────────────
static void test_subsidy()
{
    constexpr uint64_t COIN = 100'000'000ULL;
    struct Case { uint32_t h; uint64_t expected; const char* note; };
    Case cases[] = {
        {       0, 50    * COIN,        "genesis: 50 BTC"           },
        {       1, 50    * COIN,        "block 1: 50 BTC"           },
        { 209'999, 50    * COIN,        "last of epoch 0: 50 BTC"   },
        { 210'000, 25    * COIN,        "first of epoch 1: 25 BTC"  },
        { 419'999, 25    * COIN,        "last of epoch 1: 25 BTC"   },
        { 420'000, 1'250'000'000ULL,    "first of epoch 2: 12.5 BTC"},
        { 629'999, 1'250'000'000ULL,    "last of epoch 2: 12.5 BTC" },
        { 630'000,   625'000'000ULL,    "first of epoch 3: 6.25 BTC"},
        { 839'999,   625'000'000ULL,    "last of epoch 3: 6.25 BTC" },
        { 840'000,   312'500'000ULL,    "first of epoch 4: 3.125 BTC (current)"},
        {1'050'000,  156'250'000ULL,    "epoch 5: 1.5625 BTC"       },
        {13'440'000, 0,                 "post-64th halving: 0 BTC"  },
    };

    std::printf("== subsidy parity ==\n");
    for (auto& c : cases) {
        uint64_t got = get_block_subsidy(c.h);
        char label[256];
        std::snprintf(label, sizeof(label),
            "h=%u get=%llu exp=%llu (%s)",
            c.h, (unsigned long long)got, (unsigned long long)c.expected, c.note);
        check(got == c.expected, label);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Merkle root parity. Oracle: Bitcoin mainnet genesis block has exactly
// 1 transaction (coinbase txid 4a5e1e4baab89f3a32518a88c31bc87f618f76673e
// 2cc77ab2127b7afdeda33b). The Merkle root of a 1-tx tree is the txid
// itself. Block header's merkle_root field for genesis matches.
//
// Reference: Bitcoin Core src/kernel/chainparams.cpp CMainParams genesis.
// ─────────────────────────────────────────────────────────────────────────────
static void test_merkle_root()
{
    std::printf("== merkle root parity ==\n");

    // 1-tx tree (genesis case)
    {
        uint256 coinbase_txid;
        coinbase_txid.SetHex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
        std::vector<uint256> txids = {coinbase_txid};
        uint256 root = compute_merkle_root(txids);
        check(root == coinbase_txid, "1-tx tree (genesis): root == txid");
    }

    // 2-tx tree: root = SHA256d(txid1 || txid2)
    {
        uint256 t1, t2;
        t1.SetHex("aa11111111111111111111111111111111111111111111111111111111111111");
        t2.SetHex("bb22222222222222222222222222222222222222222222222222222222222222");
        std::vector<uint256> v = {t1, t2};
        uint256 got = compute_merkle_root(v);
        // Hand-computed expected:
        // concat 32+32, SHA256d, see Bitcoin Core consensus/merkle.cpp
        // For this test we just verify it's NOT one of the inputs (sanity)
        // and matches itself across two calls (deterministic).
        std::vector<uint256> v2 = {t1, t2};
        uint256 got2 = compute_merkle_root(v2);
        check(got == got2,                 "2-tx: deterministic");
        check(got != t1 && got != t2,      "2-tx: not pass-through");
    }

    // 3-tx tree: must duplicate last (Bitcoin Core's
    // ComputeMerkleRoot(): if odd count, duplicate last element)
    // This means root(3-tx) = root(4-tx with last duplicated).
    {
        uint256 a, b, c;
        a.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
        b.SetHex("2222222222222222222222222222222222222222222222222222222222222222");
        c.SetHex("3333333333333333333333333333333333333333333333333333333333333333");
        std::vector<uint256> v3 = {a, b, c};
        std::vector<uint256> v4 = {a, b, c, c};
        uint256 r3 = compute_merkle_root(v3);
        uint256 r4 = compute_merkle_root(v4);
        check(r3 == r4, "3-tx: duplicates last → root(3) == root(4-with-dup)");
    }

    // Empty input → uint256::ZERO (per our docstring)
    {
        std::vector<uint256> empty;
        uint256 r = compute_merkle_root(empty);
        check(r == uint256::ZERO, "empty tree: root == 0");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DAA parity — calculate_next_work_required() vs Bitcoin Core's actual on-
// chain retarget result. Oracle data captured live from bitcoind 28.1.0
// on .40 (BTC mainnet) on 2026-04-29.
//
// For a retarget at height B (where B % 2016 == 0):
//   tip_bits     = bits at block B-1     (last of prev period)
//   tip_time     = time at block B-1
//   first_time   = time at block B-2016  (BTC uses interval-1 = 2015 back-step,
//                                         and block B-2016 == block (B-1)-2015)
//   expected     = bits at block B       (the retarget result we're verifying)
// ─────────────────────────────────────────────────────────────────────────────
static void test_daa()
{
    std::printf("== DAA parity (live mainnet retargets) ==\n");

    auto params = BTCChainParams::mainnet();

    struct Case {
        uint32_t boundary_height;
        uint32_t tip_bits;          // block (boundary-1)
        int64_t  tip_time;
        int64_t  first_time;        // block (boundary-2016)
        uint32_t expected_bits;     // block boundary itself
    };

    Case cases[] = {
        // Most recent retarget (height 945504): captured 2026-04-29 from
        // bitcoind on .40. Difficulty crept up — actual_timespan slightly
        // shorter than target (2 weeks = 1209600 s), so bits dropped from
        // 0x17020684 → 0x17021369 (smaller target = harder).
        // Wait — 21369 > 20684 in numeric, but in compact-target encoding,
        // bits with same exponent (0x17) are compared by mantissa.
        // 0x21369 (135529) > 0x20684 (132996) means the new TARGET is
        // LARGER, so EASIER. Let's verify our impl agrees with bitcoind.
        { 945504, 0x17020684, 1776448209, 1775208520, 0x17021369 },
        // One retarget earlier (height 943488):
        // 0x17021a91 → 0x17020684 (slightly easier)
        { 943488, 0x17021a91, 1775208233, 1774043659, 0x17020684 },
    };

    for (auto& c : cases) {
        uint32_t got = calculate_next_work_required(
            c.tip_bits, c.tip_time, c.first_time, params);
        char label[256];
        std::snprintf(label, sizeof(label),
            "retarget@%u: tip_bits=0x%08x get=0x%08x exp=0x%08x dt=%lld",
            c.boundary_height, c.tip_bits, got, c.expected_bits,
            (long long)(c.tip_time - c.first_time));
        check(got == c.expected_bits, label);
    }
}

int main()
{
    test_subsidy();
    test_merkle_root();
    test_daa();

    std::printf("\n");
    if (g_fails == 0)
        std::printf("ALL PARITY CHECKS PASSED.\n");
    else
        std::printf("FAILED %d parity check(s).\n", g_fails);
    return g_fails;
}