// KAT: BIP141 witness-commitment merkle-root leaf-0 contract.
//
// The coinbase transaction's wtxid is DEFINED as 32 zero bytes and MUST occupy
// leaf 0 of the witness merkle tree; the block's other tx wtxids follow IN
// ORDER. A populated segwit block that drops the first tx's wtxid (or omits the
// coinbase placeholder) computes the wrong commitment and bitcoind rejects it
// `bad-witness-merkle-match` -- the witness-tree analogue of the stratum
// txid-merkle leaf-0 bug fixed in PR #570. This pins the contract via the
// shared btc::coin::witness_merkle_root() SSOT helper that work_source.cpp uses.

#include <gtest/gtest.h>

#include <cstring>
#include <vector>

#include <impl/btc/coin/template_builder.hpp>

using btc::coin::compute_merkle_root;
using btc::coin::witness_merkle_root;

namespace {

// A wtxid filled with the given byte (distinct, deterministic test vectors).
uint256 wt(uint8_t b) {
    uint256 h;
    std::memset(h.data(), b, 32);
    return h;
}

}  // namespace

// Coinbase-only block: the only leaf is the coinbase ZERO placeholder, so the
// witness root is that single leaf (compute_merkle_root of one element).
TEST(BTC_witness_commitment, CoinbaseOnlyRootIsPlaceholder) {
    EXPECT_EQ(witness_merkle_root({}).GetHex(), uint256::ZERO.GetHex());
}

// Leaf 0 is the coinbase ZERO placeholder, NOT the first real tx: the root must
// equal the merkle over [ZERO, a, b] (3 leaves -> odd level duplicates last).
TEST(BTC_witness_commitment, Leaf0IsCoinbasePlaceholder) {
    uint256 a = wt(0x11), b = wt(0x22);
    std::vector<uint256> expect_leaves = {uint256::ZERO, a, b};
    EXPECT_EQ(witness_merkle_root({a, b}).GetHex(),
              compute_merkle_root(expect_leaves).GetHex());
}

// flip-RED guard: dropping the FIRST real tx's wtxid changes the root, and a
// tree built WITHOUT the coinbase placeholder also diverges. Either regression
// (the #570 bug class on the witness tree) would flip these to RED.
TEST(BTC_witness_commitment, DropFirstTxOrMissingPlaceholderDiverges) {
    uint256 a = wt(0x11), b = wt(0x22);
    const std::string correct = witness_merkle_root({a, b}).GetHex();

    // Bug 1: first real tx (a) silently lost.
    EXPECT_NE(correct, witness_merkle_root({b}).GetHex());

    // Bug 2: coinbase leaf-0 placeholder omitted entirely.
    EXPECT_NE(correct, compute_merkle_root({a, b}).GetHex());
}

// Order matters: swapping tx order changes the witness root (no accidental sort).
TEST(BTC_witness_commitment, OrderSensitive) {
    uint256 a = wt(0x11), b = wt(0x22);
    EXPECT_NE(witness_merkle_root({a, b}).GetHex(),
              witness_merkle_root({b, a}).GetHex());
}
