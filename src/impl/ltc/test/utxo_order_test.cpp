// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// LTC embedded: blocks reach the UTXO set strictly in height order
// (rides share_test).
//
// connect_block has no continuity check and a warm restart resumes at
// best + 1, so a block connected over a missing parent is a permanent gap.
// The race is routine with compact blocks: N waits on getblocktxn, N+1
// reconstructs at once. Drives a REAL UTXOViewCache over a REAL UTXOViewDB
// (LevelDB in a temp dir) through the helpers main_ltc.cpp's full-block
// handler uses (utxo_order.hpp), composed in the same order:
//   ordered pipeline active -> ordered_buffer, ordered_drain, ordered_refill
//   otherwise utxo_connect_action: Connect / Gap (ordered_arm + buffer +
//   refill) / Skip.
// Also: the reorg path (disconnect to the fork, then the new branch through
// the pipeline) and tip_change_is_reorg.
// Folded into the allowlisted share_test target (no new executable: #769).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/coin/utxo.hpp>
#include <core/coin/utxo_view_db.hpp>
#include <core/coin/utxo_view_cache.hpp>
#include <core/coin/block_bootstrapper.hpp>

#include <impl/ltc/coin/block.hpp>
#include <impl/ltc/coin/transaction.hpp>
#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/utxo_order.hpp>

namespace {

using namespace ltc::coin;
using core::coin::Outpoint;

struct TempDb {
    std::filesystem::path dir;
    std::unique_ptr<core::coin::UTXOViewDB> db;
    std::unique_ptr<core::coin::UTXOViewCache> cache;
    TempDb()
    {
        std::mt19937_64 rng(std::random_device{}());
        dir = std::filesystem::temp_directory_path() / ("ltc_utxo_order_" + std::to_string(rng()));
        std::filesystem::create_directories(dir);
        db = std::make_unique<core::coin::UTXOViewDB>(dir.string());
        EXPECT_TRUE(db->open());
        cache = std::make_unique<core::coin::UTXOViewCache>(db.get());
    }
    ~TempDb()
    {
        cache.reset();
        db.reset();
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

std::vector<unsigned char> p2pkh(uint8_t tag)
{
    std::vector<unsigned char> s{0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, tag);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

MutableTransaction coinbase(uint32_t height)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xffffffff;
    in.scriptSig.m_data = {0x03, static_cast<unsigned char>(height), 0x00, 0x00};
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = 5000000000LL;
    out.scriptPubKey.m_data = p2pkh(0xc0 + static_cast<uint8_t>(height));
    tx.vout.push_back(out);
    return tx;
}

MutableTransaction spend(const uint256& prev, uint32_t index, int64_t value, uint8_t tag)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash = prev;
    in.prevout.index = index;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = value;
    out.scriptPubKey.m_data = p2pkh(tag);
    tx.vout.push_back(out);
    return tx;
}

BlockType make_block(const uint256& prev, uint32_t height, std::vector<MutableTransaction> extra)
{
    BlockType b;
    b.m_version = 0x20000000;
    b.m_previous_block = prev;
    b.m_timestamp = 1700000000 + height;
    b.m_bits = 0x207fffff;
    b.m_nonce = height;
    b.m_txs.push_back(coinbase(height));
    for (auto& t : extra)
        b.m_txs.push_back(std::move(t));
    return b;
}

uint256 hash_of(const BlockType& b)
{
    auto packed = pack(static_cast<const BlockHeaderType&>(b));
    return Hash(packed.get_span());
}

// The full-block handler's UTXO feed (main_ltc.cpp), over the helpers.
struct Feed {
    core::coin::UTXOViewCache& utxo;
    core::coin::UTXOViewDB& db;
    core::coin::BlockBootstrapState<BlockType> bs;
    std::vector<uint32_t> connected;   // heights, in connect order
    std::vector<uint32_t> requested;   // heights asked for
    std::map<uint32_t, core::coin::BlockUndo> undo;

    void connect(const BlockType& b, const uint256& h, uint32_t height)
    {
        undo[height] = utxo.connect_block(b, height, [](const MutableTransaction& tx) {
            return compute_txid(tx);
        });
        utxo.flush(h, height);
        connected.push_back(height);
    }

    void deliver(const BlockType& b, uint32_t height, bool on_best_chain = true)
    {
        const uint256 h = hash_of(b);
        if (bs.active) {
            if (on_best_chain)
                ordered_buffer(bs, height, b, h);
            ordered_drain(bs, [&](const BlockType& blk, const uint256& bh, uint32_t hh) {
                connect(blk, bh, hh);
            });
            ordered_refill(bs, [&](uint32_t rh) { requested.push_back(rh); });
            if (ordered_done(bs))
                bs.active = false;
            return;
        }
        const uint32_t best = utxo.get_best_height();
        const auto act = on_best_chain ? utxo_connect_action(best, height) : UtxoConnect::Skip;
        if (act == UtxoConnect::Gap) {
            ordered_arm(bs, best + 1, height);
            ordered_buffer(bs, height, b, h);
            ordered_refill(bs, [&](uint32_t rh) { requested.push_back(rh); });
            return;
        }
        if (act == UtxoConnect::Connect)
            connect(b, h, height);
    }
};

bool has(core::coin::UTXOViewCache& utxo, const MutableTransaction& tx, uint32_t index = 0)
{
    return utxo.have_coin(Outpoint(compute_txid(tx), index));
}

} // namespace

TEST(LtcUtxoOrder, ConnectAction)
{
    EXPECT_EQ(utxo_connect_action(100, 101), UtxoConnect::Connect);
    EXPECT_EQ(utxo_connect_action(100, 102), UtxoConnect::Gap);
    EXPECT_EQ(utxo_connect_action(100, 100), UtxoConnect::Skip);
    EXPECT_EQ(utxo_connect_action(100, 99), UtxoConnect::Skip);
    EXPECT_EQ(utxo_connect_action(100, 0), UtxoConnect::Skip) << "height unknown";
    EXPECT_EQ(utxo_connect_action(0, 1), UtxoConnect::Connect);
}

// N+1 (instant reconstruction) arrives before N (getblocktxn round trip):
// both end up connected, in order, and nothing is skipped.
TEST(LtcUtxoOrder, OutOfOrderArrivalConnectsInOrder)
{
    TempDb t;
    Feed f{*t.cache, *t.db, {}, {}, {}, {}};

    uint256 g;
    g.SetHex("00000000000000000000000000000000000000000000000000000000000000aa");
    const BlockType b1 = make_block(g, 1, {});
    const auto x_tx = b1.m_txs[0];                                        // X: b1's coinbase
    const BlockType b2 = make_block(hash_of(b1), 2, {spend(compute_txid(x_tx), 0, 4000000000LL, 0x22)});
    const auto y_tx = b2.m_txs[1];                                        // Y spends X
    const BlockType b3 = make_block(hash_of(b2), 3, {spend(compute_txid(y_tx), 0, 3000000000LL, 0x33)});
    const auto z_tx = b3.m_txs[1];                                        // Z spends Y

    f.deliver(b1, 1);
    ASSERT_EQ(t.cache->get_best_height(), 1u);

    // b3 first: buffered, b2 requested, nothing connected over the gap.
    f.deliver(b3, 3);
    EXPECT_EQ(t.cache->get_best_height(), 1u) << "never connected over a missing parent";
    EXPECT_TRUE(f.bs.active);
    EXPECT_EQ(f.requested, (std::vector<uint32_t>{2}));
    EXPECT_FALSE(has(*t.cache, z_tx));

    // b2's late completion lands: b2 then b3, in order.
    f.deliver(b2, 2);
    EXPECT_FALSE(f.bs.active);
    EXPECT_EQ(f.connected, (std::vector<uint32_t>{1, 2, 3}));
    EXPECT_EQ(t.cache->get_best_height(), 3u);
    EXPECT_EQ(t.cache->get_best_block(), hash_of(b3));
    EXPECT_FALSE(has(*t.cache, x_tx)) << "X spent by b2";
    EXPECT_FALSE(has(*t.cache, y_tx)) << "Y spent by b3";
    EXPECT_TRUE(has(*t.cache, z_tx));
    EXPECT_TRUE(has(*t.cache, b2.m_txs[0]));
    EXPECT_TRUE(has(*t.cache, b3.m_txs[0]));

    // Later copies of b2 / b3 are old: nothing changes.
    f.deliver(b2, 2);
    f.deliver(b3, 3);
    EXPECT_EQ(f.connected, (std::vector<uint32_t>{1, 2, 3}));
}

// A wider gap fills in order, and a new tip mined meanwhile extends the range.
TEST(LtcUtxoOrder, WideGapAndExtension)
{
    TempDb t;
    Feed f{*t.cache, *t.db, {}, {}, {}, {}};
    uint256 g;
    g.SetHex("00000000000000000000000000000000000000000000000000000000000000ab");
    std::vector<BlockType> chain;
    uint256 prev = g;
    for (uint32_t h = 1; h <= 6; ++h) {
        chain.push_back(make_block(prev, h, {}));
        prev = hash_of(chain.back());
    }
    f.deliver(chain[0], 1);
    f.deliver(chain[4], 5);                     // gap 2..4
    EXPECT_EQ(f.requested, (std::vector<uint32_t>{2, 3, 4}));
    f.deliver(chain[5], 6);                     // extends the range
    f.deliver(chain[2], 3);                     // out of order inside the gap
    EXPECT_EQ(t.cache->get_best_height(), 1u);
    f.deliver(chain[1], 2);                     // 2, 3 drain
    EXPECT_EQ(t.cache->get_best_height(), 3u);
    f.deliver(chain[3], 4);                     // 4, 5, 6 drain
    EXPECT_FALSE(f.bs.active);
    EXPECT_EQ(f.connected, (std::vector<uint32_t>{1, 2, 3, 4, 5, 6}));
    EXPECT_EQ(t.cache->get_best_block(), hash_of(chain[5]));
}

// Sibling reorg: N connected, the chain switches to N'. The reorg path
// disconnects N back to the fork and re-feeds the new branch through the
// pipeline; a late copy of the old N (not on the best chain) is never
// buffered in N's place.
TEST(LtcUtxoOrder, SiblingReorgConnectsTheNewBranch)
{
    TempDb t;
    Feed f{*t.cache, *t.db, {}, {}, {}, {}};
    uint256 g;
    g.SetHex("00000000000000000000000000000000000000000000000000000000000000ac");
    const BlockType b1 = make_block(g, 1, {});
    BlockType b2 = make_block(hash_of(b1), 2, {});
    BlockType b2s = make_block(hash_of(b1), 2, {});
    b2s.m_nonce ^= 0x5a5a;                 // sibling header
    b2s.m_txs[0].vout[0].scriptPubKey.m_data = p2pkh(0x99);
    ASSERT_NE(hash_of(b2), hash_of(b2s));

    f.deliver(b1, 1);
    f.deliver(b2, 2);
    ASSERT_EQ(t.cache->get_best_block(), hash_of(b2));

    // The sibling arrives while the UTXO set still holds b2: same height, old.
    f.deliver(b2s, 2);
    EXPECT_EQ(t.cache->get_best_block(), hash_of(b2)) << "checked against the old branch";

    // Reorg handler: disconnect above the fork (h=1), then the new branch in order.
    t.cache->disconnect_from_undo(f.undo[2]);
    t.cache->flush(hash_of(b1), 1);
    ASSERT_EQ(t.cache->get_best_height(), 1u);
    ordered_arm(f.bs, 2, 2);
    ordered_refill(f.bs, [&](uint32_t rh) { f.requested.push_back(rh); });
    EXPECT_EQ(f.requested, (std::vector<uint32_t>{2}));

    f.deliver(b2, 2, /*on_best_chain=*/false);   // late copy of the old branch
    EXPECT_TRUE(f.bs.active) << "not buffered in the sibling's place";
    f.deliver(b2s, 2);                           // the refetched sibling
    EXPECT_FALSE(f.bs.active);
    EXPECT_EQ(t.cache->get_best_height(), 2u);
    EXPECT_EQ(t.cache->get_best_block(), hash_of(b2s));
    EXPECT_TRUE(has(*t.cache, b2s.m_txs[0]));
    EXPECT_FALSE(has(*t.cache, b2.m_txs[0])) << "the old branch's outputs are gone";
}

TEST(LtcUtxoOrder, TipChangeIsReorg)
{
    uint256 a, b, c;
    a.SetHex("0a");
    b.SetHex("0b");
    c.SetHex("0c");
    // new chain: height 10 -> a, 11 -> b
    auto ancestors = [&](uint32_t h) { return h == 10 ? a : (h == 11 ? b : uint256()); };
    EXPECT_FALSE(tip_change_is_reorg(a, 10, 11, ancestors)) << "extension";
    EXPECT_TRUE(tip_change_is_reorg(c, 10, 11, ancestors)) << "heavier side branch, higher tip";
    EXPECT_TRUE(tip_change_is_reorg(a, 10, 10, ancestors)) << "equal-height switch";
    EXPECT_TRUE(tip_change_is_reorg(a, 10, 9, ancestors));
    EXPECT_FALSE(tip_change_is_reorg(uint256(), 0, 5, ancestors)) << "first tip";
}
