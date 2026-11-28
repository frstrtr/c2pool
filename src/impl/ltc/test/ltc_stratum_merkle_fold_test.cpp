// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// LTC stratum merkle branch fold KAT (rides share_test).
//
// The LTC lane (and DOGE merged under it) builds job branches with
// core::MiningInterface::compute_merkle_branches over WorkData::m_hashes --
// refresh_work hands it each m_hashes entry as GetHex(); m_hashes is the body
// txid list [tx1..txN] with NO coinbase slot -- and rebuilds the won-block
// header root with MiningInterface::reconstruct_merkle_root(coinbase_hex,
// branches). For N = 0..9 and 33:
//
//     reconstruct_merkle_root(coinbase, compute_merkle_branches(m_hashes))
//         == merkle_root([SHA256d(coinbase), tx1..txN])
//
// with the merkle root computed by a reference written here (SHA256d pairwise,
// odd row duplicates its last element). N == 0 gives no branches and the
// coinbase txid as root. The embedded template's body txs carry witness data,
// so txid != wtxid: m_hashes and the stratum tree are the TXID tree; the
// wtxids feed only the witness commitment.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include <core/hash.hpp>
#include <core/uint256.hpp>
#include <core/web_server.hpp>
#include <btclibs/util/strencodings.h>

#include <impl/ltc/coin/header_chain.hpp>
#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/template_builder.hpp>
#include <impl/ltc/test/mempool_test_view.hpp>

namespace {

using core::MiningInterface;

uint256 ref_pair(const uint256& l, const uint256& r)
{
    unsigned char buf[64];
    std::memcpy(buf, l.data(), 32);
    std::memcpy(buf + 32, r.data(), 32);
    return Hash(std::span<const unsigned char>(buf, sizeof(buf)));
}

uint256 ref_block_root(const uint256& coinbase_txid, const std::vector<uint256>& body)
{
    std::vector<uint256> level{coinbase_txid};
    level.insert(level.end(), body.begin(), body.end());
    while (level.size() > 1) {
        std::vector<uint256> next;
        for (size_t i = 0; i < level.size(); i += 2)
            next.push_back(ref_pair(level[i], i + 1 < level.size() ? level[i + 1] : level[i]));
        level.swap(next);
    }
    return level[0];
}

uint256 tag_hash(uint32_t i)
{
    unsigned char b[4] = {uint8_t(i), uint8_t(i >> 8), uint8_t(i >> 16), uint8_t(i >> 24)};
    return Hash(std::span<const unsigned char>(b, sizeof(b)));
}

// Any coinbase bytes: the fold only needs SHA256d(coinbase) as leaf 0.
const std::string kCoinbaseHex =
    "01000000010000000000000000000000000000000000000000000000000000000000000000"
    "ffffffff0503a0860100ffffffff0100f2052a01000000015100000000";

uint256 coinbase_txid()
{
    auto bytes = ParseHex(kCoinbaseHex);
    return Hash(std::span<const unsigned char>(bytes.data(), bytes.size()));
}

// refresh_work's conversion: m_hashes -> GetHex() -> compute_merkle_branches.
std::vector<std::string> branches_from_hashes(const std::vector<uint256>& hashes)
{
    std::vector<std::string> hexes;
    for (const auto& h : hashes) hexes.push_back(h.GetHex());
    return MiningInterface::compute_merkle_branches(hexes);
}

const std::vector<unsigned> kSizes = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 33};

// One input with a two-item witness, one P2WPKH output.
ltc::coin::MutableTransaction witness_tx(uint32_t i)
{
    ltc::coin::MutableTransaction tx;
    tx.version = 2;
    tx.locktime = 0;
    ltc::coin::TxIn in;
    in.prevout.hash = tag_hash(0xF0000 + i);
    in.prevout.index = 0;
    in.sequence = 0xffffffff;
    in.scriptWitness.stack = {std::vector<unsigned char>(72, uint8_t(0x30 + i)),
                              std::vector<unsigned char>(33, 0x02)};
    tx.vin.push_back(in);
    ltc::coin::TxOut out;
    out.value = 50000 + i;
    out.scriptPubKey.m_data = {0x00, 0x14};
    out.scriptPubKey.m_data.insert(out.scriptPubKey.m_data.end(), 20, uint8_t(i));
    tx.vout.push_back(out);
    return tx;
}

ltc::coin::BlockHeaderType testnet_genesis()
{
    ltc::coin::BlockHeaderType g;
    g.m_version = 1;
    g.m_previous_block.SetNull();
    g.m_merkle_root.SetHex("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9");
    g.m_timestamp = 1486949366;
    g.m_bits = 0x1e0ffff0;
    g.m_nonce = 293345;
    return g;
}

} // namespace

TEST(LtcStratumMerkleFold, CoreBranchesFoldToReferenceRoot)
{
    const uint256 cb = coinbase_txid();
    for (unsigned n : kSizes) {
        std::vector<uint256> txs;
        for (unsigned i = 0; i < n; ++i) txs.push_back(tag_hash(0x1000 + i));
        const auto branches = branches_from_hashes(txs);
        EXPECT_EQ(MiningInterface::reconstruct_merkle_root(kCoinbaseHex, branches),
                  ref_block_root(cb, txs)) << "N=" << n;
        if (n == 0) {
            EXPECT_TRUE(branches.empty());
            EXPECT_EQ(MiningInterface::reconstruct_merkle_root(kCoinbaseHex, branches), cb);
        }
    }
}

TEST(LtcStratumMerkleFold, EmbeddedTemplateFoldsToTxidRoot)
{
    const uint256 cb = coinbase_txid();
    for (unsigned n : kSizes) {
        SCOPED_TRACE("N=" + std::to_string(n));
        ltc::coin::HeaderChain chain(ltc::coin::make_ltc_chain_params_testnet());
        ASSERT_TRUE(chain.init());
        ASSERT_TRUE(chain.add_header(testnet_genesis()));

        ltc::coin::Mempool pool;
        for (unsigned i = 0; i < n; ++i) {
            auto tx = witness_tx(i);
            ASSERT_TRUE(pool.add_tx_unchecked(tx));
            pool.set_tx_fee(ltc::coin::compute_txid(tx), 1000 + 37 * i);
        }
        ltc_test::CoveringView view;
        view.cover(pool);
        {
            // The pool is cleaned for the tip (template_pool_gate).
            ltc::coin::BlockType tip_block;
            static_cast<ltc::coin::BlockHeaderType&>(tip_block) = testnet_genesis();
            pool.remove_for_block(tip_block);
        }

        auto wd = ltc::coin::TemplateBuilder::build_template(chain, pool, true);
        ASSERT_TRUE(wd.has_value());

        // Producer: m_hashes is the body txid list, no coinbase slot, aligned
        // with transactions[].txid; transactions[].hash is the wtxid.
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

        // Consumer: the core branch builder and header-root rebuild.
        const auto branches = branches_from_hashes(wd->m_hashes);
        const uint256 root = MiningInterface::reconstruct_merkle_root(kCoinbaseHex, branches);
        EXPECT_EQ(root, ref_block_root(cb, body_txids));
        if (n == 0) {
            EXPECT_TRUE(branches.empty());
        } else {
            EXPECT_NE(body_txids, body_wtxids);
            EXPECT_NE(root, ref_block_root(cb, body_wtxids));
        }
    }
}
