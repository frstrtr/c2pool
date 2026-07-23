// SPDX-License-Identifier: AGPL-3.0-or-later
// Producer/consumer merkle-branch contract KAT for the BTC stratum work source.
//
// Regression guard for the latent bad-txnmrklroot defect fixed in PR #570.
// BTCWorkSource::get_stratum_merkle_branches() folds wd->m_hashes (the pure
// [tx1..txN] list, with NO coinbase slot) into stratum coinbase branches. The
// miner rebuilds the header merkle root by folding ITS coinbase txid against
// those branches; that reconstruction MUST equal
// compute_merkle_root([coinbase, tx1..txN]) — the exact root the serialized
// block body commits to. Pre-#570 the branch builder omitted the leaf-0
// coinbase placeholder, so tx1 was dropped and every populated (>=1 tx) won
// block was rejected bad-txnmrklroot.
//
// SSOT under test: btc::coin::stratum_merkle_siblings (template_builder.hpp),
// which get_stratum_merkle_branches() now delegates to. Revert the leaf-0
// prepend there and FoldReconstructsBodyRoot goes RED.

#include <gtest/gtest.h>

#include <impl/btc/coin/template_builder.hpp>
#include <core/uint256.hpp>

#include <vector>

using btc::coin::compute_merkle_root;
using btc::coin::merkle_hash_pair;
using btc::coin::stratum_merkle_siblings;

namespace {

// Miner-side reconstruction: fold the coinbase txid against the branch siblings.
uint256 fold_branches(const uint256& coinbase, const std::vector<uint256>& sibs) {
    uint256 acc = coinbase;
    for (const auto& s : sibs) acc = merkle_hash_pair(acc, s);
    return acc;
}

// Body-side truth: the full merkle root committed by the serialized block over
// [coinbase, tx1..txN].
uint256 body_root(const uint256& coinbase, const std::vector<uint256>& txs) {
    std::vector<uint256> leaves;
    leaves.reserve(txs.size() + 1);
    leaves.push_back(coinbase);
    leaves.insert(leaves.end(), txs.begin(), txs.end());
    return compute_merkle_root(leaves);
}

std::vector<uint256> make_txs(unsigned n) {
    std::vector<uint256> v;
    v.reserve(n);
    for (unsigned i = 0; i < n; ++i) v.push_back(uint256((uint64_t)(0x1000u + i)));
    return v;
}

// The pre-#570 BUGGY branch builder: folds tx_hashes with NO coinbase leaf-0
// placeholder. Replicated here only to PROVE this KAT catches the regression.
std::vector<uint256> buggy_siblings(const std::vector<uint256>& tx_hashes) {
    if (tx_hashes.empty()) return {};
    std::vector<uint256> level = tx_hashes;  // BUG: missing coinbase leaf-0
    std::vector<uint256> sibs;
    while (level.size() > 1) {
        sibs.push_back(level[1]);
        std::vector<uint256> next;
        next.push_back(uint256::ZERO);
        for (size_t i = 2; i < level.size(); i += 2) {
            const uint256& l = level[i];
            const uint256& r = (i + 1 < level.size()) ? level[i + 1] : level[i];
            next.push_back(merkle_hash_pair(l, r));
        }
        level = std::move(next);
    }
    return sibs;
}

const uint256 COINBASE((uint64_t)0xC0FFEEull);

}  // namespace

// Positive contract: production siblings reconstruct the body root for every
// template size — including the single-tx (N=1) case the pre-#570 bug silently
// corrupted, and odd counts (last-element duplication path).
TEST(StratumMerkleBranch, FoldReconstructsBodyRoot) {
    for (unsigned n : {0u, 1u, 2u, 3u, 4u, 5u, 7u, 16u}) {
        auto txs = make_txs(n);
        auto sibs = stratum_merkle_siblings(txs);
        EXPECT_EQ(fold_branches(COINBASE, sibs), body_root(COINBASE, txs))
            << "N=" << n << " branch fold diverged from body merkle root";
    }
}

// Coinbase-only template yields zero branches and the coinbase IS the root.
TEST(StratumMerkleBranch, CoinbaseOnlyHasNoBranches) {
    auto sibs = stratum_merkle_siblings(make_txs(0));
    EXPECT_TRUE(sibs.empty());
    EXPECT_EQ(fold_branches(COINBASE, sibs), COINBASE);
}

// flip-RED proof: the pre-#570 builder (no leaf-0 placeholder) diverges from
// the body root on EVERY populated template — i.e. this KAT would have caught
// the bad-txnmrklroot defect.
TEST(StratumMerkleBranch, PreFixBuilderDivergesOnPopulated) {
    for (unsigned n : {1u, 2u, 3u, 5u}) {
        auto txs = make_txs(n);
        EXPECT_NE(fold_branches(COINBASE, buggy_siblings(txs)), body_root(COINBASE, txs))
            << "N=" << n << " buggy builder unexpectedly matched — guard is blind";
    }
}