// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// LTC MWEB state <-> chain tip hash binding KAT (rides share_test).
//
// A template's HogEx spends the HogEx of the block the MWEB state came from,
// so the state is usable only when that block IS the tip. MWEBTracker::update
// accepts a block at the same height as the current state (a sibling), so a
// late sibling could overwrite the tip's state; the template builder must then
// HOLD instead of spending the sibling's HogEx. Driven over the REAL mainnet
// block 3200424 (tip) and a sibling of it (same txs, different header nonce).
// Pattern: template_hogex_survives_truncation_test.cpp.
// Folded into the allowlisted share_test target (no new executable: #769).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <memory>
#include <optional>
#include <string>

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/coin/mweb_shape.hpp>
#include <btclibs/util/strencodings.h>

#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/rpc_data.hpp>
#include <impl/ltc/coin/transaction.hpp>
#include <impl/ltc/coin/template_builder.hpp>

#include "ltc_mweb_cmpct_fixtures.hpp"

namespace {

using namespace ltc::coin;
namespace fx = ltc_mweb_cmpct_fixture;

BlockType vector_block()
{
    auto bytes = ParseHex(fx::kBlockWithMwebHex);
    PackStream ps(bytes);
    BlockType b;
    ps >> b;
    return b;
}

uint256 hash_of(const BlockHeaderType& h)
{
    auto packed = pack(h);
    return Hash(packed.get_span());
}

// Mainnet chain whose tip is the real block 3200424: a fast-start checkpoint
// at its parent, then the real header (real PoW).
std::unique_ptr<HeaderChain> chain_at_vector_tip(const BlockType& b)
{
    auto p = make_ltc_chain_params_mainnet();
    LTCChainParams::Checkpoint cp;
    cp.height = fx::kHeight - 1;
    cp.hash.SetHex(fx::kPrevBlockHash);
    p.fast_start_checkpoint = cp;
    auto chain = std::make_unique<HeaderChain>(p);
    EXPECT_TRUE(chain->init());
    EXPECT_TRUE(chain->add_header(static_cast<const BlockHeaderType&>(b)));
    EXPECT_EQ(chain->height(), fx::kHeight);
    return chain;
}

std::string last_tx_hex(const rpc::WorkData& wd)
{
    return wd.m_data["transactions"].back()["data"].get<std::string>();
}

} // namespace

TEST(LtcMwebStateHashBinding, SiblingStateHoldsTipStateBuilds)
{
    const BlockType tip_block = vector_block();
    auto chain = chain_at_vector_tip(tip_block);
    const uint256 tip_hash = chain->tip()->block_hash;
    ASSERT_EQ(tip_hash.GetHex(), fx::kBlockHash);

    // A sibling at the same height: same txs and mw::Block, another nonce.
    BlockType sibling = tip_block;
    sibling.m_nonce ^= 0x5a5a5a5a;
    const uint256 sibling_hash = hash_of(sibling);
    ASSERT_NE(sibling_hash, tip_hash);

    Mempool pool;
    MWEBTracker tracker;

    // The sibling's state lands (passes every commitment check: same HogEx).
    ASSERT_TRUE(tracker.update(sibling, fx::kHeight, sibling.m_mweb_raw));
    EXPECT_EQ(tracker.state_hash(), sibling_hash);

    std::optional<rpc::WorkData> refused;
    auto held = TemplateBuilder::build_template(
        *chain, pool, false, &tracker,
        TemplateBuilder::MAX_BLOCK_WEIGHT - TemplateBuilder::COINBASE_RESERVE, &refused);
    EXPECT_FALSE(held) << "state for a block that is not the tip: HOLD";
    ASSERT_TRUE(refused);
    EXPECT_TRUE(refused->m_data["mweb"].get<std::string>().empty());
    EXPECT_TRUE(core::coin::check_template_shape(refused->m_data))
        << "the refused template can never become an LTC block";

    // The tip's own state (same height -> accepted) builds the HogEx template.
    ASSERT_TRUE(tracker.update(tip_block, fx::kHeight, tip_block.m_mweb_raw));
    EXPECT_EQ(tracker.state_hash(), tip_hash);
    auto wd = TemplateBuilder::build_template(*chain, pool, false, &tracker);
    ASSERT_TRUE(wd);
    EXPECT_EQ(wd->m_data["height"].get<int>(), static_cast<int>(fx::kHeight + 1));
    EXPECT_EQ(wd->m_data["previousblockhash"].get<std::string>(), fx::kBlockHash);
    EXPECT_TRUE(core::coin::tx_hex_is_hogex(last_tx_hex(*wd)));
    EXPECT_FALSE(core::coin::check_template_shape(wd->m_data));
    ASSERT_FALSE(wd->m_txs.empty());
    const auto& hogex = wd->m_txs.back();
    ASSERT_TRUE(hogex.m_hogEx);
    ASSERT_EQ(hogex.vin.size(), 1u);
    EXPECT_EQ(hogex.vin[0].prevout.hash.GetHex(), fx::kHogexTxid)
        << "spends the tip's HogEx (what block 3200425 did)";
    EXPECT_EQ(hogex.vin[0].prevout.index, 0u);
    ASSERT_FALSE(hogex.vout.empty());
    EXPECT_EQ(hogex.vout[0].value, fx::kHogaddrValue);
}

TEST(LtcMwebStateHashBinding, InvalidateUnlessKeepsOnlyTheTipsState)
{
    const BlockType b = vector_block();
    const uint256 b_hash = hash_of(b);
    uint256 other;
    other.SetHex("00000000000000000000000000000000000000000000000000000000000000ee");

    MWEBTracker tracker;
    ASSERT_TRUE(tracker.update(b, fx::kHeight, b.m_mweb_raw));

    EXPECT_TRUE(tracker.invalidate_unless(b_hash)) << "state for the new tip survives";
    EXPECT_TRUE(tracker.has_state());
    EXPECT_EQ(tracker.state_hash(), b_hash);

    EXPECT_FALSE(tracker.invalidate_unless(other)) << "a tip change elsewhere drops it";
    EXPECT_FALSE(tracker.has_state());
    EXPECT_TRUE(tracker.state_hash().IsNull());
    EXPECT_EQ(tracker.mweb_seen_height(), fx::kHeight) << "the chain stays known MWEB-active";

    // After the drop any height is accepted again (a reorg to a shorter tip).
    BlockType older = b;
    EXPECT_FALSE(tracker.update(older, fx::kHeight - 1, older.m_mweb_raw))
        << "...but the commitment still has to hold (mweb height != block height)";
    ASSERT_TRUE(tracker.update(b, fx::kHeight, b.m_mweb_raw));
    EXPECT_EQ(tracker.state_hash(), b_hash);
}
