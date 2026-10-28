// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// Embedded DOGE templates dogecoind can accept (rides share_test).
//
//   DogeTemplateBudget.FullTemplateWithAuxPowStaysUnder1MB: dogecoind's
//     CheckBlock limits the serialized block, the AuxPoW in its header
//     included, to MAX_BLOCK_BASE_SIZE = 1,000,000 bytes (bad-blk-length,
//     validation.cpp:2972). The AuxPoW carries the whole parent (LTC)
//     coinbase. With PPLNS coinbases of 4,000 outputs on both chains and a
//     DOGE mempool above 1 MB, the REAL doge::coin::TemplateBuilder,
//     selecting within the budget MergedMiningManager passes
//     (aux_block_reserve_bytes), yields a block that the REAL producers
//     (build_auxpow_proof, build_pplns_coinbase_hex) assemble to at most
//     1,000,000 bytes, still full.
//   DogeTemplateTime.CurtimeNeverAtOrBelowMtp: dogecoind refuses a block at
//     or below the median time past of its parent (time-too-old,
//     validation.cpp:3103) and puts max(MTP + 1, now) in its own templates
//     (miner.cpp:65). With the last 11 headers ahead of the local clock the
//     template's curtime and mintime are above the MTP.
// Folded into the allowlisted share_test target (no new executable: #769).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdio>
#include <ctime>
#include <string>
#include <vector>

#include <core/uint256.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/coin/utxo.hpp>
#include <btclibs/util/strencodings.h>

#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/transaction.hpp>
#include <impl/doge/coin/chain_params.hpp>
#include <impl/doge/coin/header_chain.hpp>
#include <impl/doge/coin/template_builder.hpp>
#include <c2pool/merged/merged_mining.hpp>

namespace {

using ltc::coin::MutableTransaction;

/// A DOGE header chain in memory: a checkpoint root at `root_height`, then
/// one header per timestamp (AuxPoW heights: structural checks only).
struct DogeChain {
    doge::coin::DOGEChainParams params = doge::coin::DOGEChainParams::mainnet();
    doge::coin::HeaderChain chain{params};

    DogeChain(uint32_t root_height, const std::vector<uint32_t>& timestamps)
    {
        uint256 root;
        root.SetHex("00000000000000000000000000000000000000000000000000000000000d0e01");
        chain.set_dynamic_checkpoint(root_height, root);
        uint256 prev = root;
        for (size_t i = 0; i < timestamps.size(); ++i) {
            ltc::coin::BlockHeaderType h;
            h.m_version = 0x00620104;
            h.m_previous_block = prev;
            h.m_merkle_root.SetHex(std::to_string(1000 + i));
            h.m_timestamp = timestamps[i];
            h.m_bits = 0x1a01d2c3;
            h.m_nonce = static_cast<uint32_t>(i);
            EXPECT_TRUE(chain.add_header(h)) << "header " << i;
            prev = Hash(pack(h).get_span());
        }
    }
};

MutableTransaction big_tx(uint8_t tag, uint32_t index, size_t outputs)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    ltc::coin::TxIn in;
    for (int i = 0; i < 32; ++i)
        in.prevout.hash.data()[i] = static_cast<uint8_t>(tag + i);
    in.prevout.index = index;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    for (size_t k = 0; k < outputs; ++k) {
        ltc::coin::TxOut out;
        out.value = 100000000 + static_cast<int64_t>(k);
        out.scriptPubKey.m_data = {0x76, 0xa9, 0x14};
        for (int i = 0; i < 20; ++i)
            out.scriptPubKey.m_data.push_back(static_cast<unsigned char>(k + i));
        out.scriptPubKey.m_data.push_back(0x88);
        out.scriptPubKey.m_data.push_back(0xac);
        tx.vout.push_back(out);
    }
    return tx;
}

/// A PPLNS coinbase of `n` P2PKH payees, as MergedMiningManager builds the
/// aux one (also the size of the parent's for the same payees).
std::string pplns_coinbase_hex(size_t n, int height)
{
    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> payouts;
    for (size_t i = 0; i < n; ++i) {
        std::vector<unsigned char> s{0x76, 0xa9, 0x14};
        for (int k = 0; k < 20; ++k)
            s.push_back(static_cast<unsigned char>((i >> (8 * (k % 4))) + k));
        s.push_back(0x88);
        s.push_back(0xac);
        payouts.emplace_back(std::move(s), 250000000);
    }
    return c2pool::merged::MergedMiningManager::build_pplns_coinbase_hex(height, payouts, uint256());
}

std::string varint_hex(uint64_t n)
{
    char buf[19];
    if (n < 0xfd) {
        std::snprintf(buf, sizeof(buf), "%02x", static_cast<unsigned>(n));
    } else {
        std::snprintf(buf, sizeof(buf), "fd%02x%02x", static_cast<unsigned>(n & 0xff),
                      static_cast<unsigned>((n >> 8) & 0xff));
    }
    return buf;
}

} // namespace

TEST(DogeTemplateBudget, FullTemplateWithAuxPowStaysUnder1MB)
{
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    DogeChain c(5'000'000, {now - 60});

    ltc::coin::Mempool pool(core::coin::DOGE_LIMITS);
    for (uint32_t i = 0; i < 120; ++i) {   // ~1.19 MB
        auto tx = big_tx(static_cast<uint8_t>(i), i, 290);
        ASSERT_TRUE(pool.add_tx_unchecked(tx));
        pool.set_tx_fee(ltc::coin::compute_txid(tx), 1000000 + i);
    }

    // Both coinbases carry 4,000 payees; the parent's is about as large plus
    // its own extra outputs (witness commitment, share reference).
    const std::string doge_cb = pplns_coinbase_hex(4000, 5'000'002);
    const std::string parent_cb = pplns_coinbase_hex(4000, 3'200'000);
    const uint32_t parent_cb_bytes = static_cast<uint32_t>(parent_cb.size() / 2 + 200);
    const uint32_t parent_branch_len = 12;  // a 4,000-tx parent block
    const uint32_t reserve = c2pool::merged::aux_block_reserve_bytes(
        parent_cb_bytes, parent_branch_len, /*aux_branch_len=*/0,
        static_cast<uint32_t>(doge_cb.size() / 2));

    auto wd = doge::coin::TemplateBuilder::build_template(
        c.chain, pool, c.params, doge::coin::TemplateBuilder::tx_weight_budget(reserve));
    ASSERT_TRUE(wd.has_value());
    const auto& txs = wd->m_data["transactions"];
    ASSERT_GT(txs.size(), 10u);

    // The block as try_submit_merged_blocks assembles it: header, AuxPoW,
    // tx count, coinbase, transactions.
    std::vector<std::string> branch(parent_branch_len, std::string(64, 'a'));
    uint256 parent_hash;
    parent_hash.SetHex(std::string(64, 'b'));
    const std::string auxpow = c2pool::merged::build_auxpow_proof(
        parent_cb + std::string(400, 'c'), parent_hash, branch, 0, {}, 0, std::string(160, 'd'));
    std::string block = std::string(160, 'e') + auxpow + varint_hex(1 + txs.size()) + doge_cb;
    for (const auto& t : txs)
        block += t["data"].get<std::string>();
    const size_t bytes = block.size() / 2;
    EXPECT_LE(bytes, 1'000'000u) << "bad-blk-length (auxpow " << auxpow.size() / 2 << " B, coinbase "
                                 << doge_cb.size() / 2 << " B, " << txs.size() << " txs)";
    EXPECT_GT(bytes, 980'000u) << "the template is still full";
}

TEST(DogeTemplateTime, CurtimeNeverAtOrBelowMtp)
{
    // The last 11 headers two hours ahead of the local clock (the network's
    // time, or a local clock behind it): MTP = the 6th of them.
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    std::vector<uint32_t> ts;
    for (uint32_t i = 0; i < 11; ++i)
        ts.push_back(now + 7200 + i * 60);
    DogeChain c(5'000'000, ts);
    const int64_t mtp = now + 7200 + 5 * 60;

    ltc::coin::Mempool pool(core::coin::DOGE_LIMITS);
    auto wd = doge::coin::TemplateBuilder::build_template(c.chain, pool, c.params);
    ASSERT_TRUE(wd.has_value());
    const int64_t curtime = wd->m_data["curtime"].get<int64_t>();
    EXPECT_GT(curtime, mtp) << "time-too-old: curtime " << curtime << " <= MTP " << mtp;
    EXPECT_EQ(wd->m_data["mintime"].get<int64_t>(), mtp + 1);

    // A clock ahead of the MTP is used as is.
    DogeChain past(5'000'000, {now - 3000, now - 2000, now - 1000});
    auto wd2 = doge::coin::TemplateBuilder::build_template(past.chain, pool, past.params);
    ASSERT_TRUE(wd2.has_value());
    EXPECT_GE(wd2->m_data["curtime"].get<int64_t>(), static_cast<int64_t>(now));
    EXPECT_LE(wd2->m_data["curtime"].get<int64_t>(), static_cast<int64_t>(now) + 5);
}
