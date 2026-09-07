// SPDX-License-Identifier: AGPL-3.0-or-later
// B6 template parity gate (§4.7): c2pool-btc algorithmic functions vs
// Bitcoin Core consensus oracles. Converted from the earlier standalone
// smoke harness into gtest cases so it executes as a REGISTERED, running
// check inside the btc_share_test target (which already links core/btc/
// btclibs/secp256k1). Folding into the existing allowlisted target rather
// than a new add_executable avoids the silent "Not Run" fake-green class
// (see merged PR #868 note in this dir's CMakeLists.txt).
//
// SCOPE: this is the STATIC-oracle subset of §4.7 B6 — B6.1 (bit-exact
// against Core consensus constants) and the static half of B6.4 (subsidy /
// merkle / DAA retarget field parity). The LIVE rolling-1000 RPC-oracle
// soak (B6.2 header-tip parity, B6.3 gettxoutsetinfo every 144, and the
// "green for 24h" exit) still requires the bitcoind snapshot rig
// (reference_btc_snapshot.md) and is tracked separately.

#include <impl/btc/coin/template_builder.hpp>
#include <impl/btc/coin/header_chain.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

using btc::coin::get_block_subsidy;
using btc::coin::compute_merkle_root;
using btc::coin::calculate_next_work_required;
using btc::coin::BTCChainParams;

// ─────────────────────────────────────────────────────────────────────────────
// Subsidy parity — oracle values are well-known consensus constants from
// Bitcoin Core's GetBlockSubsidy() across each halving boundary.
// ─────────────────────────────────────────────────────────────────────────────
TEST(BtcTemplateParityB6, Subsidy)
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

    for (auto& c : cases) {
        uint64_t got = get_block_subsidy(c.h);
        EXPECT_EQ(got, c.expected)
            << "h=" << c.h << " (" << c.note << ")";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Merkle root parity. Oracle: Bitcoin mainnet genesis block has exactly
// 1 transaction (coinbase txid 4a5e1e4baab89f3a32518a88c31bc87f618f76673e
// 2cc77ab2127b7afdeda33b). The Merkle root of a 1-tx tree is the txid
// itself. Reference: Bitcoin Core src/kernel/chainparams.cpp CMainParams.
// ─────────────────────────────────────────────────────────────────────────────
TEST(BtcTemplateParityB6, MerkleRoot)
{
    // 1-tx tree (genesis case)
    {
        uint256 coinbase_txid;
        coinbase_txid.SetHex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
        std::vector<uint256> txids = {coinbase_txid};
        uint256 root = compute_merkle_root(txids);
        EXPECT_EQ(root, coinbase_txid) << "1-tx tree (genesis): root == txid";
    }

    // 2-tx tree: deterministic, and not a pass-through of either input.
    {
        uint256 t1, t2;
        t1.SetHex("aa11111111111111111111111111111111111111111111111111111111111111");
        t2.SetHex("bb22222222222222222222222222222222222222222222222222222222222222");
        std::vector<uint256> v = {t1, t2};
        uint256 got = compute_merkle_root(v);
        std::vector<uint256> v2 = {t1, t2};
        uint256 got2 = compute_merkle_root(v2);
        EXPECT_EQ(got, got2)                    << "2-tx: deterministic";
        EXPECT_TRUE(got != t1 && got != t2)     << "2-tx: not pass-through";
    }

    // 3-tx tree: Bitcoin Core's ComputeMerkleRoot() duplicates the last
    // element on an odd count, so root(3-tx) == root(4-tx with last dup).
    {
        uint256 a, b, c;
        a.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
        b.SetHex("2222222222222222222222222222222222222222222222222222222222222222");
        c.SetHex("3333333333333333333333333333333333333333333333333333333333333333");
        std::vector<uint256> v3 = {a, b, c};
        std::vector<uint256> v4 = {a, b, c, c};
        EXPECT_EQ(compute_merkle_root(v3), compute_merkle_root(v4))
            << "3-tx: duplicates last -> root(3) == root(4-with-dup)";
    }

    // Empty input -> uint256::ZERO
    {
        std::vector<uint256> empty;
        EXPECT_EQ(compute_merkle_root(empty), uint256::ZERO)
            << "empty tree: root == 0";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DAA parity — calculate_next_work_required() vs Bitcoin Core's actual on-
// chain retarget result. Oracle data captured live from bitcoind 28.1.0
// on .40 (BTC mainnet) on 2026-04-29.
// ─────────────────────────────────────────────────────────────────────────────
TEST(BtcTemplateParityB6, DAARetarget)
{
    auto params = BTCChainParams::mainnet();

    struct Case {
        uint32_t boundary_height;
        uint32_t tip_bits;          // block (boundary-1)
        int64_t  tip_time;
        int64_t  first_time;        // block (boundary-2016)
        uint32_t expected_bits;     // block boundary itself
    };

    Case cases[] = {
        { 945504, 0x17020684, 1776448209, 1775208520, 0x17021369 },
        { 943488, 0x17021a91, 1775208233, 1774043659, 0x17020684 },
    };

    for (auto& c : cases) {
        uint32_t got = calculate_next_work_required(
            c.tip_bits, c.tip_time, c.first_time, params);
        EXPECT_EQ(got, c.expected_bits)
            << "retarget@" << c.boundary_height
            << ": tip_bits=" << std::hex << c.tip_bits
            << " dt=" << std::dec << (c.tip_time - c.first_time);
    }
}
