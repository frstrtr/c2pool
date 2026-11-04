// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The embedded LTC template waits for the mempool cleanup of every block
// between the UTXO view and the tip (#2136, #2137 S0; rides share_test).
//
// The selection prices against the UTXO view. When the tip's body arrives
// before its parent's, the pool is cleaned for the tip at once but the
// parent's confirmed txs stay priced against the older view until the fill
// connects the parent; a template carrying one is a block litecoind rejects
// (bad-txns-inputs-missingorspent). Both observed events are pinned here over
// a REAL HeaderChain, Mempool and UTXOViewCache/UTXOViewDB:
//   - back to back: tip T2 (parent T1), view at T0, pool cleaned for T2
//     only -> refused mempool-not-cleaned-for-ancestor (the ingress HOLDs
//     it); cleaned for T1 too -> built;
//   - a reorg across a same-height sibling: view on S1 (a sibling of T1) ->
//     refused even with T1 and T2 cleaned, until the view rewinds onto the
//     tip's ancestry;
//   - a view above the tip is a reorg in progress: refused;
//   - core::coin::segment_cleaned itself: the failing height, a missing
//     header, the segment bound;
//   - the cleaned_for semantics the tip check uses (L3 T7) with the window
//     of CLEANED_BLOCKS_KEPT >= 32 blocks.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <string>

#include <core/uint256.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/coin/mweb_shape.hpp>
#include <core/coin/template_gate.hpp>
#include <core/coin/utxo.hpp>
#include <core/coin/utxo_view_cache.hpp>
#include <core/coin/utxo_view_db.hpp>

#include <impl/ltc/coin/header_chain.hpp>
#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/template_builder.hpp>
#include <impl/ltc/test/mempool_test_view.hpp>

namespace {

using namespace ltc::coin;

BlockHeaderType testnet_genesis()
{
    BlockHeaderType g;
    g.m_version = 1;
    g.m_previous_block.SetNull();
    g.m_merkle_root.SetHex("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9");
    g.m_timestamp = 1486949366;
    g.m_bits = 0x1e0ffff0;
    g.m_nonce = 293345;
    return g;
}

uint256 hash_of(const BlockHeaderType& hdr)
{
    return Hash(pack(hdr).get_span());
}

BlockHeaderType child_of(const uint256& prev, uint32_t tag)
{
    BlockHeaderType h;
    h.m_version = 0x20000000;
    h.m_previous_block = prev;
    h.m_merkle_root.SetHex(std::to_string(700 + tag));
    h.m_timestamp = 1486949366 + 150 * (tag + 1);
    h.m_bits = 0x1e0ffff0;
    h.m_nonce = tag;
    return h;
}

// genesis (h0) - T0 (h1) - T1 (h2) - T2 (h3), and S1 (h2), a sibling of T1
// seen after it (equal work: T1 stays on the best chain). Old enough below
// the peer's tip that the header chain checks them structurally.
struct Chain {
    HeaderChain chain{make_ltc_chain_params_testnet()};
    BlockHeaderType t0, t1, t2, s1;
    Chain()
    {
        EXPECT_TRUE(chain.init());
        EXPECT_TRUE(chain.add_header(testnet_genesis()));
        chain.set_peer_tip_height(10'000'000);
        t0 = child_of(hash_of(testnet_genesis()), 0);
        t1 = child_of(hash_of(t0), 1);
        s1 = child_of(hash_of(t0), 2);
        t2 = child_of(hash_of(t1), 3);
        EXPECT_TRUE(chain.add_header(t0));
        EXPECT_TRUE(chain.add_header(t1));
        EXPECT_TRUE(chain.add_header(s1));
        EXPECT_TRUE(chain.add_header(t2));
        EXPECT_EQ(chain.height(), 3u);
        EXPECT_EQ(chain.tip()->block_hash, hash_of(t2));
    }
};

// A UTXO view over a real DB in a temp dir, holding the coin the pool's tx
// spends; its best block is moved with flush().
struct View {
    std::filesystem::path dir;
    std::unique_ptr<core::coin::UTXOViewDB> db;
    std::unique_ptr<core::coin::UTXOViewCache> cache;
    View()
    {
        std::mt19937_64 rng(std::random_device{}());
        dir = std::filesystem::temp_directory_path() / ("ltc_gap_gate_" + std::to_string(rng()));
        std::filesystem::create_directories(dir);
        db = std::make_unique<core::coin::UTXOViewDB>(dir.string());
        EXPECT_TRUE(db->open());
        cache = std::make_unique<core::coin::UTXOViewCache>(db.get());
    }
    ~View()
    {
        cache.reset();
        db.reset();
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
    void add(const uint256& txid, uint32_t index, int64_t value)
    {
        core::coin::Coin coin;
        coin.value = value;
        coin.scriptPubKey.m_data = {0x51};  // OP_TRUE
        coin.height = 1;
        cache->add_coin(core::coin::Outpoint(txid, index), coin);
    }
    void best(const BlockHeaderType& hdr, uint32_t height)
    {
        ASSERT_TRUE(cache->flush(hash_of(hdr), height));
        ASSERT_EQ(cache->get_best_block(), hash_of(hdr));
    }
};

const uint256 FUND = []() { uint256 v; v.SetHex("00000000000000000000000000000000000000000000000000000000000000f1"); return v; }();

MutableTransaction pay_from_fund()
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash = FUND;
    in.prevout.index = 0;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = 99'000;
    out.scriptPubKey.m_data = {0x51};
    tx.vout.push_back(out);
    return tx;
}

void clean_for(Mempool& pool, const BlockHeaderType& hdr)
{
    BlockType b;
    static_cast<BlockHeaderType&>(b) = hdr;
    pool.remove_for_block(b);
}

// A pool holding one priced tx whose input is in `view`.
void fill(Mempool& pool, View& view)
{
    const MutableTransaction tx = pay_from_fund();
    ASSERT_TRUE(pool.add_tx(tx));
    pool.set_tx_fee(compute_txid(tx), 1'000);
    view.add(FUND, 0, 100'000);
    pool.set_utxo(view.cache.get());
}

struct Built {
    std::optional<rpc::WorkData> wd;
    std::optional<rpc::WorkData> refused;
    std::optional<std::string> code() const
    {
        return refused ? core::coin::template_refusal_code(refused->m_data) : std::nullopt;
    }
};

Built build(const HeaderChain& chain, const Mempool& pool)
{
    Built b;
    b.wd = TemplateBuilder::build_template(chain, pool, /*is_testnet=*/true, nullptr,
                                           TemplateBuilder::MAX_BLOCK_WEIGHT - TemplateBuilder::COINBASE_RESERVE,
                                           &b.refused);
    return b;
}

const std::string kAncestor = core::coin::kNotCleanedForAncestor;

} // namespace

// 2026-10-31 21:40Z (h 3205145): two blocks 10 s apart; the second's body
// was processed while the UTXO set was still before the first, and the first
// one's txs were in the template. View at T0, tip T2, pool cleaned for T2
// only: what the old tip-only gate let through.
TEST(LtcTemplateGapGate, BackToBackBlocksHoldUntilTheParentIsCleaned)
{
    Chain c;
    View view;
    Mempool pool;
    fill(pool, view);
    view.best(c.t0, 1);
    clean_for(pool, c.t2);
    ASSERT_TRUE(pool.cleaned_for(hash_of(c.t2))) << "the tip-only gate passes";

    auto b = build(c.chain, pool);
    EXPECT_FALSE(b.wd) << "T1's txs may still be in the pool";
    ASSERT_TRUE(b.refused);
    EXPECT_EQ(b.code(), std::optional<std::string>(kAncestor));
    EXPECT_TRUE(core::coin::check_template_shape(b.refused->m_data)) << "the ingress guard HOLDs it";

    // The fill connects T1: its body runs through the cleanup.
    clean_for(pool, c.t1);
    b = build(c.chain, pool);
    ASSERT_TRUE(b.wd);
    EXPECT_FALSE(core::coin::template_refusal_code(b.wd->m_data));
    ASSERT_EQ(b.wd->m_data["transactions"].size(), 1u) << "the priced tx ships";
    EXPECT_EQ(b.wd->m_data["coinbasevalue"].get<int64_t>(),
              static_cast<int64_t>(get_block_subsidy(4)) + 1'000);

    // The view reaches the tip: an empty segment.
    view.best(c.t2, 3);
    EXPECT_TRUE(build(c.chain, pool).wd);
}

// 2026-11-02 15:50Z (h 3206173): c2 sat on a sibling of litecoind's 3206172
// and reorged onto the child of the other one, whose body it had never
// cleaned for. The view on the sibling S1 is not on the tip's ancestry:
// refused even once T1 and T2 are cleaned, until the view rewinds.
TEST(LtcTemplateGapGate, SameHeightSiblingReorgHoldsUntilTheViewRewinds)
{
    Chain c;
    View view;
    Mempool pool;
    fill(pool, view);
    view.best(c.s1, 2);
    clean_for(pool, c.s1);
    clean_for(pool, c.t2);
    auto b = build(c.chain, pool);
    EXPECT_FALSE(b.wd);
    EXPECT_EQ(b.code(), std::optional<std::string>(kAncestor)) << "T1 was never cleaned";

    clean_for(pool, c.t1);
    b = build(c.chain, pool);
    EXPECT_FALSE(b.wd) << "the view is on a sibling of T1: a reorg in progress";
    EXPECT_EQ(b.code(), std::optional<std::string>(kAncestor));

    // The UTXO set rewinds to the fork point: T1 and T2 are both cleaned.
    view.best(c.t0, 1);
    EXPECT_TRUE(build(c.chain, pool).wd);
    // ... and connects the new branch.
    view.best(c.t1, 2);
    EXPECT_TRUE(build(c.chain, pool).wd);
}

// A view above the tip (a reorg onto a shorter branch, the view not yet
// rewound) is no ancestor either.
TEST(LtcTemplateGapGate, ViewAboveTheTipRefuses)
{
    Chain c;
    View view;
    Mempool pool;
    fill(pool, view);
    clean_for(pool, c.t2);
    const BlockHeaderType above = child_of(hash_of(c.t2), 9);
    view.best(above, 4);
    auto b = build(c.chain, pool);
    EXPECT_FALSE(b.wd);
    EXPECT_EQ(b.code(), std::optional<std::string>(kAncestor));
}

// The tip check keeps its own code and comes first; an empty pool, and a view
// without a best block (it prices nothing), need no segment.
TEST(LtcTemplateGapGate, TipCheckFirstAndNothingToGate)
{
    Chain c;
    {
        View view;
        Mempool pool;
        fill(pool, view);
        view.best(c.t0, 1);
        auto b = build(c.chain, pool);
        EXPECT_FALSE(b.wd);
        EXPECT_EQ(b.code(), std::optional<std::string>("mempool-not-cleaned-for-tip"));
    }
    {
        View view;
        Mempool empty;
        empty.set_utxo(view.cache.get());
        view.best(c.t0, 1);
        EXPECT_TRUE(build(c.chain, empty).wd) << "nothing to select, nothing to gate";
    }
    {
        Mempool pool;
        ASSERT_TRUE(pool.add_tx(pay_from_fund()));
        pool.set_tx_fee(compute_txid(pay_from_fund()), 1'000);
        ltc_test::CoveringView mem;  // no DB: no best block
        mem.cover(pool);
        clean_for(pool, c.t2);
        auto b = build(c.chain, pool);
        ASSERT_TRUE(b.wd);
        EXPECT_EQ(b.wd->m_data["transactions"].size(), 1u);
    }
}

// core::coin::segment_cleaned over a synthetic chain of hashes.
TEST(LtcTemplateGapGate, SegmentCleanedHelper)
{
    using core::coin::BlockRef;
    using core::coin::SegmentGate;
    auto hx = [](uint32_t n) { uint256 v; v.SetHex(std::to_string(1000 + n)); return v; };
    // Block n at height n, parent n - 1 (block 0 has none).
    auto parent_of = [&](const uint256& b) -> std::optional<uint256> {
        for (uint32_t n = 1; n < 100; ++n)
            if (b == hx(n))
                return hx(n - 1);
        return std::nullopt;
    };
    std::map<uint256, bool> cleaned;
    auto cleaned_for = [&](const uint256& b) { return cleaned.count(b) > 0; };

    // Empty segment: the view is the tip.
    EXPECT_TRUE(core::coin::segment_cleaned(BlockRef{5, hx(5)}, BlockRef{5, hx(5)}, cleaned_for, parent_of, 32).ok());
    // Same height, another block.
    auto r = core::coin::segment_cleaned(BlockRef{5, hx(55)}, BlockRef{5, hx(5)}, cleaned_for, parent_of, 32);
    EXPECT_EQ(r.gate, SegmentGate::NotAncestor);

    // View at 2, tip at 5: 3, 4, 5 must be cleaned; the walk reports the
    // highest one that is not.
    cleaned[hx(5)] = true;
    cleaned[hx(3)] = true;
    r = core::coin::segment_cleaned(BlockRef{2, hx(2)}, BlockRef{5, hx(5)}, cleaned_for, parent_of, 32);
    EXPECT_EQ(r.gate, SegmentGate::NotCleaned);
    EXPECT_EQ(r.height, 4u);
    EXPECT_EQ(r.hash, hx(4));
    cleaned[hx(4)] = true;
    EXPECT_TRUE(core::coin::segment_cleaned(BlockRef{2, hx(2)}, BlockRef{5, hx(5)}, cleaned_for, parent_of, 32).ok());
    // The view's block is not the tip's ancestor at its height.
    r = core::coin::segment_cleaned(BlockRef{2, hx(77)}, BlockRef{5, hx(5)}, cleaned_for, parent_of, 32);
    EXPECT_EQ(r.gate, SegmentGate::NotAncestor);
    EXPECT_EQ(r.height, 2u);
    EXPECT_EQ(r.hash, hx(2));
    // A header missing on the way down.
    cleaned[hx(200)] = true;
    r = core::coin::segment_cleaned(BlockRef{198, hx(198)}, BlockRef{200, hx(200)}, cleaned_for, parent_of, 32);
    EXPECT_EQ(r.gate, SegmentGate::NotAncestor);
    EXPECT_EQ(r.height, 199u);
    // View above the tip.
    r = core::coin::segment_cleaned(BlockRef{6, hx(6)}, BlockRef{5, hx(5)}, cleaned_for, parent_of, 32);
    EXPECT_EQ(r.gate, SegmentGate::NotAncestor);

    // The bound: a segment of exactly max_blocks is walked, one more is not.
    for (uint32_t n = 1; n < 100; ++n)
        cleaned[hx(n)] = true;
    EXPECT_TRUE(core::coin::segment_cleaned(BlockRef{60, hx(60)}, BlockRef{92, hx(92)}, cleaned_for, parent_of, 32).ok());
    r = core::coin::segment_cleaned(BlockRef{59, hx(59)}, BlockRef{92, hx(92)}, cleaned_for, parent_of, 32);
    EXPECT_EQ(r.gate, SegmentGate::NotCleaned);
    EXPECT_EQ(r.height, 92u);
}

// L3 T7's cleaned_for semantics, with the window the segment gate relies on:
// the tip stays cleaned while up to CLEANED_BLOCKS_KEPT - 1 later bodies (late
// copies, stale siblings) are cleaned after it; one more pushes it out.
TEST(LtcTemplateGapGate, CleanedForRemembersAtLeast32Blocks)
{
    static_assert(Mempool::CLEANED_BLOCKS_KEPT >= 32, "the segment gate needs >= 32 cleaned blocks");
    Mempool pool;
    const BlockHeaderType tip = child_of(hash_of(testnet_genesis()), 50);
    clean_for(pool, tip);
    for (uint32_t i = 0; i + 1 < Mempool::CLEANED_BLOCKS_KEPT; ++i)
        clean_for(pool, child_of(hash_of(tip), 100 + i));
    EXPECT_TRUE(pool.cleaned_for(hash_of(tip)));
    // The same block again does not take a second place.
    clean_for(pool, tip);
    EXPECT_TRUE(pool.cleaned_for(hash_of(tip)));
    clean_for(pool, child_of(hash_of(tip), 999));
    EXPECT_FALSE(pool.cleaned_for(hash_of(tip)));
}
