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

#include <impl/btc/coin/header_chain.hpp>
#include <impl/btc/coin/mempool.hpp>
#include <impl/btc/coin/template_builder.hpp>
#include <impl/btc/stratum/work_source.hpp>
#include <core/hash.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>

#include <cstring>
#include <memory>
#include <set>
#include <span>
#include <string>
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
// ── Fold KAT over the real wire builder ─────────────────────────────────────
//
// fold(coinbase_txid, branches) == merkle_root([coinbase_txid, tx1..txN]) for
// N = 0..9 and 33, with the merkle root computed by a reference written here
// (SHA256d pairwise, odd row duplicates its last element), over:
//   * stratum_merkle_siblings on synthetic txids, and
//   * BTCWorkSource::get_stratum_merkle_branches() on a real embedded template
//     (HeaderChain + Mempool -> TemplateBuilder), decoded from the wire hex.
// The template's body txs carry witness data, so txid != wtxid. WorkData
// m_hashes and the stratum tree are the TXID tree; the wtxids feed only the
// witness commitment.

namespace {

uint256 ref_pair(const uint256& l, const uint256& r) {
    unsigned char buf[64];
    std::memcpy(buf, l.data(), 32);
    std::memcpy(buf + 32, r.data(), 32);
    return Hash(std::span<const unsigned char>(buf, sizeof(buf)));
}

uint256 ref_block_root(const uint256& coinbase, const std::vector<uint256>& body) {
    std::vector<uint256> level{coinbase};
    level.insert(level.end(), body.begin(), body.end());
    while (level.size() > 1) {
        std::vector<uint256> next;
        for (size_t i = 0; i < level.size(); i += 2)
            next.push_back(ref_pair(level[i], i + 1 < level.size() ? level[i + 1] : level[i]));
        level.swap(next);
    }
    return level[0];
}

uint256 ref_fold(const uint256& coinbase, const std::vector<uint256>& branches) {
    uint256 acc = coinbase;
    for (const auto& b : branches) acc = ref_pair(acc, b);
    return acc;
}

// Wire branch hex (LE-internal bytes) -> uint256, as mining_submit decodes it.
std::vector<uint256> decode_branches(const std::vector<std::string>& hexes) {
    std::vector<uint256> out;
    for (const auto& h : hexes) {
        uint256 b = uint256::ONE;  // a malformed branch must not fold right
        auto bytes = ParseHex(h);
        if (bytes.size() == 32) std::memcpy(b.begin(), bytes.data(), 32);
        out.push_back(b);
    }
    return out;
}

uint256 tag_hash(uint32_t i) {
    unsigned char b[4] = {uint8_t(i), uint8_t(i >> 8), uint8_t(i >> 16), uint8_t(i >> 24)};
    return Hash(std::span<const unsigned char>(b, sizeof(b)));
}

const std::vector<unsigned> kFoldSizes = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 33};

// P2WPKH-shaped spend: one input with a two-item witness, one P2WPKH output.
btc::coin::MutableTransaction witness_tx(uint32_t i) {
    btc::coin::MutableTransaction tx;
    tx.version = 2;
    tx.locktime = 0;
    btc::coin::TxIn in;
    in.prevout.hash = tag_hash(0xF0000 + i);
    in.prevout.index = 0;
    in.sequence = 0xffffffff;
    in.scriptWitness.stack = {std::vector<unsigned char>(72, uint8_t(0x30 + i)),
                              std::vector<unsigned char>(33, 0x02)};
    tx.vin.push_back(in);
    btc::coin::TxOut out;
    out.value = 50000 + i;
    out.scriptPubKey.m_data = {0x00, 0x14};
    out.scriptPubKey.m_data.insert(out.scriptPubKey.m_data.end(), 20, uint8_t(i));
    tx.vout.push_back(out);
    return tx;
}

struct WsRig {
    btc::coin::BTCChainParams params = btc::coin::BTCChainParams::mainnet();
    btc::coin::HeaderChain    chain{params};
    btc::coin::Mempool        mempool;
    std::set<uint256>         txids;
    std::unique_ptr<btc::stratum::BTCWorkSource> ws;

    explicit WsRig(unsigned n) {
        EXPECT_TRUE(chain.init());
        for (unsigned i = 0; i < n; ++i) {
            auto tx = witness_tx(i);
            const uint256 id = btc::coin::compute_txid(tx);
            EXPECT_TRUE(mempool.add_tx(tx));
            mempool.set_tx_fee(id, 1000 + 37 * i);
            txids.insert(id);
        }
        ws = std::make_unique<btc::stratum::BTCWorkSource>(
            chain, mempool, /*is_testnet=*/false,
            [](const std::vector<unsigned char>&, uint32_t) { return true; });
    }
};

}  // namespace

TEST(StratumMerkleBranch, SiblingsFoldToReferenceRootZeroToNineAnd33) {
    const uint256 cb = tag_hash(0xC0FFEE);
    for (unsigned n : kFoldSizes) {
        std::vector<uint256> txs;
        for (unsigned i = 0; i < n; ++i) txs.push_back(tag_hash(0x1000 + i));
        const auto sibs = stratum_merkle_siblings(txs);
        EXPECT_EQ(ref_fold(cb, sibs), ref_block_root(cb, txs)) << "N=" << n;
        EXPECT_EQ(body_root(cb, txs), ref_block_root(cb, txs)) << "N=" << n;
        if (n == 0) {
            EXPECT_TRUE(sibs.empty());
            EXPECT_EQ(ref_block_root(cb, txs), cb);
        } else {
            ASSERT_FALSE(sibs.empty()) << "N=" << n;
            EXPECT_EQ(sibs[0], txs[0]) << "N=" << n << " level-0 sibling must be tx1";
        }
    }
}

TEST(StratumMerkleBranch, WorkSourceBranchesFoldToTxidRoot) {
    const uint256 cb = tag_hash(0xCB);
    for (unsigned n : kFoldSizes) {
        SCOPED_TRACE("N=" + std::to_string(n));
        WsRig rig(n);

        // Producer: m_hashes is the body txid list, no coinbase slot, aligned
        // with transactions[].txid; transactions[].hash is the wtxid.
        auto wd = btc::coin::TemplateBuilder::build_template(rig.chain, rig.mempool, false);
        ASSERT_TRUE(wd.has_value());
        const auto& entries = wd->m_data["transactions"];
        ASSERT_EQ(entries.size(), n);
        ASSERT_EQ(wd->m_hashes.size(), n);
        std::vector<uint256> body_txids, body_wtxids;
        for (const auto& e : entries) {
            uint256 t, w;
            t.SetHex(e["txid"].get<std::string>());
            w.SetHex(e["hash"].get<std::string>());
            body_txids.push_back(t);
            body_wtxids.push_back(w);
        }
        EXPECT_EQ(wd->m_hashes, body_txids);
        EXPECT_EQ(std::set<uint256>(body_txids.begin(), body_txids.end()), rig.txids);

        // Consumer: the real stratum branch builder, decoded from the wire.
        const auto tmpl = rig.ws->get_current_work_template();
        ASSERT_EQ(tmpl["transactions"].size(), n);
        for (size_t i = 0; i < n; ++i)
            EXPECT_EQ(tmpl["transactions"][i]["txid"].get<std::string>(), body_txids[i].GetHex());
        const auto branches = decode_branches(rig.ws->get_stratum_merkle_branches());
        EXPECT_EQ(ref_fold(cb, branches), ref_block_root(cb, body_txids));
        if (n == 0) {
            EXPECT_TRUE(branches.empty());
        } else {
            EXPECT_NE(body_txids, body_wtxids);
            EXPECT_NE(ref_fold(cb, branches), ref_block_root(cb, body_wtxids));
        }
    }
}
