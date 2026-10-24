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

// The full-block handler's UTXO feed (main_ltc.cpp), over the same helpers
// in the same order: the active branch (buffer if best chain, checked drain,
// recover on refusal, refill, done), the normal path (Gap / checked Connect /
// Skip) and the reorg handler (disconnect to the fork, re-arm from the UTXO
// set's real best). best_chain stands in for the header chain's height index.
struct Feed {
    core::coin::UTXOViewCache& utxo;
    core::coin::UTXOViewDB& db;
    core::coin::BlockBootstrapState<BlockType> bs;
    std::vector<uint32_t> connected;   // heights, in connect order
    std::vector<uint32_t> requested;   // heights asked for
    std::map<uint32_t, core::coin::BlockUndo> undo;
    std::map<uint32_t, uint256> best_chain;
    ConnectCheck last_refusal{ConnectCheck::Ok};

    void set_chain(const std::vector<BlockType>& blocks, uint32_t first_height)
    {
        best_chain.clear();
        for (size_t i = 0; i < blocks.size(); ++i)
            best_chain[first_height + static_cast<uint32_t>(i)] = hash_of(blocks[i]);
    }
    uint32_t tip_height() const { return best_chain.empty() ? 0 : best_chain.rbegin()->first; }

    ConnectCheck check(const BlockType& b, const uint256& h, uint32_t height)
    {
        auto it = best_chain.find(height);
        return utxo_connect_check(utxo.get_best_height(), utxo.get_best_block(), height, h,
                                  b.m_previous_block, it == best_chain.end() ? uint256() : it->second);
    }

    void connect(const BlockType& b, const uint256& h, uint32_t height)
    {
        undo[height] = utxo.connect_block(b, height, [](const MutableTransaction& tx) {
            return compute_txid(tx);
        });
        utxo.flush(h, height);
        connected.push_back(height);
    }

    void refill()
    {
        ordered_refill(bs, [&](uint32_t rh) { requested.push_back(rh); });
    }

    // The active branch after buffering.
    void pump()
    {
        const auto r = ordered_drain(
            bs, [&](const BlockType& b, const uint256& h, uint32_t hh) { return check(b, h, hh); },
            [&](const BlockType& b, const uint256& h, uint32_t hh) { connect(b, h, hh); });
        if (r.refused != ConnectCheck::Ok) {
            last_refusal = r.refused;
            if (ordered_recover(bs, r.refused, utxo.get_best_height(), tip_height()))
                refill();
        }
        if (bs.active)
            refill();
        if (bs.active && ordered_done(bs))
            bs.active = false;
    }

    void deliver(const BlockType& b, uint32_t height)
    {
        const uint256 h = hash_of(b);
        auto it = best_chain.find(height);
        const bool on_best_chain = it != best_chain.end() && it->second == h;
        if (bs.active) {
            if (on_best_chain)
                ordered_buffer(bs, height, b, h);
            pump();
            return;
        }
        const uint32_t best = utxo.get_best_height();
        const auto act = on_best_chain ? utxo_connect_action(best, height) : UtxoConnect::Skip;
        if (act == UtxoConnect::Gap) {
            ordered_arm(bs, best + 1, height);
            ordered_buffer(bs, height, b, h);
            refill();
            return;
        }
        if (act == UtxoConnect::Connect) {
            const auto c = check(b, h, height);
            if (c == ConnectCheck::Ok)
                connect(b, h, height);
            else
                last_refusal = c;
        }
    }

    // The reorg handler: disconnect above the fork, then the new branch in
    // order from the UTXO set's real best.
    void reorg(uint32_t fork_height, const uint256& fork_hash, uint32_t new_height)
    {
        const uint32_t best = utxo.get_best_height();
        if (best > fork_height) {
            for (uint32_t h = best; h > fork_height; --h)
                utxo.disconnect_from_undo(undo[h]);
            utxo.flush(fork_hash, fork_height);
        }
        if (ordered_rearm_after_reorg(bs, utxo.get_best_height(), new_height))
            refill();
    }
};

bool has(core::coin::UTXOViewCache& utxo, const MutableTransaction& tx, uint32_t index = 0)
{
    return utxo.have_coin(Outpoint(compute_txid(tx), index));
}

std::vector<BlockType> make_chain(const uint256& prev0, uint32_t first_height, size_t n, uint8_t tag)
{
    std::vector<BlockType> out;
    uint256 prev = prev0;
    for (size_t i = 0; i < n; ++i) {
        BlockType b = make_block(prev, first_height + static_cast<uint32_t>(i), {});
        b.m_nonce ^= static_cast<uint32_t>(tag) << 16;
        b.m_txs[0].vout[0].scriptPubKey.m_data = p2pkh(static_cast<uint8_t>(tag + i));
        out.push_back(b);
        prev = hash_of(out.back());
    }
    return out;
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

TEST(LtcUtxoOrder, ConnectCheck)
{
    uint256 tip, other, parent, hash;
    tip.SetHex("01");
    other.SetHex("02");
    parent.SetHex("03");
    hash.SetHex("04");
    EXPECT_EQ(utxo_connect_check(10, parent, 11, hash, parent, hash), ConnectCheck::Ok);
    EXPECT_EQ(utxo_connect_check(10, parent, 12, hash, parent, hash), ConnectCheck::NotNext);
    EXPECT_EQ(utxo_connect_check(10, parent, 11, hash, parent, other), ConnectCheck::NotBestChain);
    EXPECT_EQ(utxo_connect_check(10, parent, 11, hash, parent, uint256()), ConnectCheck::NotBestChain);
    EXPECT_EQ(utxo_connect_check(10, other, 11, hash, parent, hash), ConnectCheck::ParentMismatch);
    EXPECT_EQ(utxo_connect_check(0, uint256(), 5000, hash, parent, hash), ConnectCheck::Ok)
        << "an empty UTXO set starts anywhere on the best chain (cold-start bootstrap)";
    EXPECT_EQ(utxo_connect_check(0, uint256(), 5000, hash, parent, other), ConnectCheck::NotBestChain);
}

// N+1 (instant reconstruction) arrives before N (getblocktxn round trip):
// both end up connected, in order, and nothing is skipped.
TEST(LtcUtxoOrder, OutOfOrderArrivalConnectsInOrder)
{
    TempDb t;
    Feed f{*t.cache, *t.db};

    uint256 g;
    g.SetHex("00000000000000000000000000000000000000000000000000000000000000aa");
    const BlockType b1 = make_block(g, 1, {});
    const auto x_tx = b1.m_txs[0];                                        // X: b1's coinbase
    const BlockType b2 = make_block(hash_of(b1), 2, {spend(compute_txid(x_tx), 0, 4000000000LL, 0x22)});
    const auto y_tx = b2.m_txs[1];                                        // Y spends X
    const BlockType b3 = make_block(hash_of(b2), 3, {spend(compute_txid(y_tx), 0, 3000000000LL, 0x33)});
    const auto z_tx = b3.m_txs[1];                                        // Z spends Y
    f.set_chain({b1, b2, b3}, 1);

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
    Feed f{*t.cache, *t.db};
    uint256 g;
    g.SetHex("00000000000000000000000000000000000000000000000000000000000000ab");
    const auto chain = make_chain(g, 1, 6, 0x40);
    f.set_chain(chain, 1);
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

// Sibling reorg with no fill running: N connected, the chain switches to N'.
TEST(LtcUtxoOrder, SiblingReorgConnectsTheNewBranch)
{
    TempDb t;
    Feed f{*t.cache, *t.db};
    uint256 g;
    g.SetHex("00000000000000000000000000000000000000000000000000000000000000ac");
    const auto a = make_chain(g, 1, 2, 0x50);             // a1, a2
    const auto b = make_chain(hash_of(a[0]), 2, 1, 0x60); // b2 (sibling of a2)
    f.set_chain(a, 1);
    f.deliver(a[0], 1);
    f.deliver(a[1], 2);
    ASSERT_EQ(t.cache->get_best_block(), hash_of(a[1]));

    // The header chain switches to b2; the sibling's body arrives first and
    // is checked against the old branch (same height: old).
    f.set_chain({a[0], b[0]}, 1);
    f.deliver(b[0], 2);
    EXPECT_EQ(t.cache->get_best_block(), hash_of(a[1]));

    // Reorg handler: disconnect to the fork, refetch the new branch in order.
    f.reorg(1, hash_of(a[0]), 2);
    ASSERT_EQ(t.cache->get_best_height(), 1u);
    EXPECT_TRUE(f.bs.active);
    EXPECT_EQ(f.requested, (std::vector<uint32_t>{2}));
    f.deliver(a[1], 2);                       // late copy of the old branch
    EXPECT_TRUE(f.bs.active) << "not buffered in the sibling's place";
    f.deliver(b[0], 2);                       // the refetched sibling
    EXPECT_FALSE(f.bs.active);
    EXPECT_EQ(t.cache->get_best_height(), 2u);
    EXPECT_EQ(t.cache->get_best_block(), hash_of(b[0]));
    EXPECT_TRUE(has(*t.cache, b[0].m_txs[0]));
    EXPECT_FALSE(has(*t.cache, a[1].m_txs[0])) << "the old branch's outputs are gone";
}

// A reorg while a fill is running. Fill 2..5 has drained to 3 and holds the
// old branch's 5; the chain forks at 2. The pipeline must restart at the UTXO
// set's real next height (3) with the stale buffer gone: B4 alone must not
// connect over 2, and the old 5 never connects.
TEST(LtcUtxoOrder, ReorgMidFillRestartsFromTheUtxoBest)
{
    TempDb t;
    Feed f{*t.cache, *t.db};
    uint256 g;
    g.SetHex("00000000000000000000000000000000000000000000000000000000000000ad");
    const auto a = make_chain(g, 1, 5, 0x70);              // a1..a5
    const auto b = make_chain(hash_of(a[1]), 3, 3, 0x80);  // b3..b5, fork at a2
    f.set_chain(a, 1);

    f.deliver(a[0], 1);
    f.deliver(a[4], 5);                                    // fill 2..5, holds a5
    f.deliver(a[1], 2);
    f.deliver(a[2], 3);                                    // drained to 3
    ASSERT_EQ(t.cache->get_best_height(), 3u);
    ASSERT_EQ(f.bs.next_height, 4u);
    ASSERT_EQ(f.bs.buffer.count(5), 1u);

    // The chain switches to b3..b5 (fork at 2).
    f.set_chain({a[0], a[1], b[0], b[1], b[2]}, 1);
    f.requested.clear();
    f.reorg(2, hash_of(a[1]), 5);
    EXPECT_EQ(t.cache->get_best_height(), 2u);
    EXPECT_EQ(t.cache->get_best_block(), hash_of(a[1]));
    EXPECT_TRUE(f.bs.active);
    EXPECT_EQ(f.bs.next_height, 3u) << "restarted at the UTXO set's real next height";
    EXPECT_TRUE(f.bs.buffer.empty()) << "the old branch's buffered block is gone";
    EXPECT_EQ(f.requested, (std::vector<uint32_t>{3, 4, 5}));

    f.deliver(b[1], 4);
    EXPECT_EQ(t.cache->get_best_height(), 2u) << "b4 must not connect over 2";
    EXPECT_EQ(f.bs.next_height, 3u);
    f.deliver(a[4], 5);                                    // old branch: never buffered
    f.deliver(b[0], 3);                                    // b3, b4 drain
    EXPECT_EQ(t.cache->get_best_height(), 4u);
    f.deliver(b[2], 5);
    EXPECT_FALSE(f.bs.active);
    EXPECT_EQ(t.cache->get_best_height(), 5u);
    EXPECT_EQ(t.cache->get_best_block(), hash_of(b[2]));
    EXPECT_EQ(f.connected, (std::vector<uint32_t>{1, 2, 3, 3, 4, 5}));
    EXPECT_TRUE(has(*t.cache, b[2].m_txs[0]));
    EXPECT_FALSE(has(*t.cache, a[4].m_txs[0])) << "the old branch's 5 never connected";
    EXPECT_FALSE(has(*t.cache, a[2].m_txs[0])) << "the old branch's 3 disconnected";
}

// Defence in depth at the connect point: whatever sits in the buffer, a block
// connects only as the UTXO set's next height, on the best chain, on the
// UTXO set's best block. A stale entry is dropped and the fill restarts.
TEST(LtcUtxoOrder, StaleBufferedBlockNeverConnects)
{
    TempDb t;
    Feed f{*t.cache, *t.db};
    uint256 g;
    g.SetHex("00000000000000000000000000000000000000000000000000000000000000ae");
    const auto a = make_chain(g, 1, 4, 0x90);              // a1..a4
    const auto b = make_chain(hash_of(a[1]), 3, 2, 0xa0);  // b3, b4
    f.set_chain(a, 1);
    f.deliver(a[0], 1);
    f.deliver(a[1], 2);
    f.set_chain({a[0], a[1], b[0], b[1]}, 1);

    // An old-branch block that slipped into the buffer (e.g. buffered before
    // a tip change was processed).
    ordered_arm(f.bs, 3, 3);
    ordered_buffer(f.bs, 3, a[2], hash_of(a[2]));
    f.pump();
    EXPECT_EQ(f.last_refusal, ConnectCheck::NotBestChain);
    EXPECT_EQ(t.cache->get_best_height(), 2u);
    EXPECT_FALSE(has(*t.cache, a[2].m_txs[0]));
    EXPECT_TRUE(f.bs.active) << "re-armed at the UTXO set's next height";
    EXPECT_EQ(f.bs.next_height, 3u);

    // A pipeline that sits above the UTXO set's next height (b4 buffered,
    // UTXO at 2): b4 is refused, the fill restarts at 3.
    f.bs.next_height = 4;
    f.bs.next_request = 5;
    ordered_buffer(f.bs, 4, b[1], hash_of(b[1]));
    f.pump();
    EXPECT_EQ(f.last_refusal, ConnectCheck::NotNext);
    EXPECT_EQ(t.cache->get_best_height(), 2u) << "b4 never connects over 2";
    EXPECT_EQ(f.bs.next_height, 3u);

    f.deliver(b[0], 3);
    f.deliver(b[1], 4);
    EXPECT_EQ(t.cache->get_best_height(), 4u);
    EXPECT_EQ(t.cache->get_best_block(), hash_of(b[1]));
}

// The UTXO set itself on another branch (its best block is not the parent):
// the best chain's next block is not connected over it.
TEST(LtcUtxoOrder, ParentMismatchIsNotConnected)
{
    TempDb t;
    Feed f{*t.cache, *t.db};
    uint256 g;
    g.SetHex("00000000000000000000000000000000000000000000000000000000000000af");
    const auto a = make_chain(g, 1, 2, 0xb0);              // a1, a2
    const auto b = make_chain(hash_of(a[0]), 2, 2, 0xc0);  // b2, b3
    f.set_chain(a, 1);
    f.deliver(a[0], 1);
    f.deliver(a[1], 2);
    // The chain moved to b2, b3 but nothing disconnected a2.
    f.set_chain({a[0], b[0], b[1]}, 1);
    f.deliver(b[1], 3);
    EXPECT_EQ(f.last_refusal, ConnectCheck::ParentMismatch);
    EXPECT_EQ(t.cache->get_best_block(), hash_of(a[1]));
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
