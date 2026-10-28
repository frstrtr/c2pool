// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// Embedded DOGE: the UTXO set follows the best chain, in height order and
// through reorgs (#2070). Rides share_test.
//
// Drives doge::coin::UtxoLane -- the object main_ltc.cpp's DOGE full-block
// and tip-change handlers call -- over a REAL UTXOViewCache / UTXOViewDB
// (LevelDB in a temp dir). A map stands in for the DOGE header chain (the
// best chain by height, every header's parent) and records the heights the
// lane asks for. deliver() is the full-block handler (the lane, then the
// mempool passes main_ltc runs around it); switch_to() is the header chain
// moving to another best chain and firing its tip change.
//
// The money path: a DOGE template built on a UTXO view that is not the best
// chain's selects txs whose inputs are missing or spent on the best chain
// (bad-txns-inputs-missingorspent): the aux block is invalid.
//   - TallerHeavierSiblingBranchIsAReorg: a heavier branch that ends higher
//     than the old tip is a reorg (the view ends on the new branch);
//   - OutOfOrderBodiesConnectInOrder: h+2 before h+1 -> both, in order;
//   - MultiBlockReorgConnectsEveryNewBranchBlock: every block of the new
//     branch is connected, not only its tip;
//   - LegacyUndoRecordRebuilds: a record that cannot put its spent coins back
//     makes the lane rebuild, not carry on with coins missing;
//   - OrphanedTxChildIsNotSelectedAfterReorg: T confirmed only on the old
//     branch, its child C relayed -> the template never carries C without T.
// The rest pin the request kinds, the startup check, a parent mismatch the
// tip change did not report (add_headers fires one tip change per batch),
// the cold start, and the counters.
// Folded into the allowlisted share_test target (no new executable: #769).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/coin/utxo.hpp>
#include <core/coin/utxo_view_db.hpp>
#include <core/coin/utxo_view_cache.hpp>

#include <impl/ltc/coin/block.hpp>
#include <impl/ltc/coin/transaction.hpp>
#include <impl/ltc/coin/mempool.hpp>
#include <impl/doge/coin/template_builder.hpp>
#include <impl/doge/coin/utxo_lane.hpp>

namespace {

using namespace ltc::coin;
using core::coin::Outpoint;
using doge::coin::UtxoAsk;
using doge::coin::UtxoLane;

constexpr int64_t DOGE_SUBSIDY = 1000000000000LL;  // 10,000 DOGE in koinu

struct TempDb {
    std::filesystem::path dir;
    std::unique_ptr<core::coin::UTXOViewDB> db;
    std::unique_ptr<core::coin::UTXOViewCache> cache;
    TempDb()
    {
        std::mt19937_64 rng(std::random_device{}());
        dir = std::filesystem::temp_directory_path() / ("doge_utxo_lane_" + std::to_string(rng()));
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

MutableTransaction coinbase(uint32_t height, uint8_t tag)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xffffffff;
    in.scriptSig.m_data = {0x03, static_cast<unsigned char>(height), static_cast<unsigned char>(tag), 0x00};
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = DOGE_SUBSIDY;
    out.scriptPubKey.m_data = p2pkh(tag);
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

uint256 hash_of(const BlockType& b)
{
    auto packed = pack(static_cast<const BlockHeaderType&>(b));
    return Hash(packed.get_span());
}

uint256 txid_of(const MutableTransaction& tx) { return compute_txid(tx); }

/// A block at `height` on `prev`: a coinbase tagged `tag`, then `extra`.
BlockType make_block(const uint256& prev, uint32_t height, uint8_t tag,
                     std::vector<MutableTransaction> extra = {})
{
    BlockType b;
    b.m_version = 0x00620104;  // DOGE: chain id 98, AuxPoW bit
    b.m_previous_block = prev;
    b.m_timestamp = 1700000000 + height * 60;
    b.m_bits = 0x1a01d2c3;
    b.m_nonce = height | (static_cast<uint32_t>(tag) << 16);
    b.m_txs.push_back(coinbase(height, tag));
    for (auto& t : extra)
        b.m_txs.push_back(std::move(t));
    return b;
}

/// n blocks from first_height on prev0, coinbases tagged tag, tag+1, ...
std::vector<BlockType> make_chain(const uint256& prev0, uint32_t first_height, size_t n, uint8_t tag)
{
    std::vector<BlockType> out;
    uint256 prev = prev0;
    for (size_t i = 0; i < n; ++i) {
        out.push_back(make_block(prev, first_height + static_cast<uint32_t>(i),
                                 static_cast<uint8_t>(tag + i)));
        prev = hash_of(out.back());
    }
    return out;
}

uint256 genesis(uint8_t tag)
{
    static const char* hex = "0123456789abcdef";
    uint256 g;
    g.SetHex(std::string(62, '0') + hex[tag >> 4] + hex[tag & 15]);
    return g;
}

/// The header chain the lane sees: its best chain by height and every header
/// it has seen (hash -> parent). Records what the lane asks for.
struct Net {
    std::map<uint32_t, uint256> best;
    std::map<uint256, uint256> parent;
    std::vector<uint32_t> requested;
    std::vector<UtxoAsk> asked_how;
    std::vector<uint32_t> connected;  // heights, in connect order
    uint32_t wiped{0};
    uint32_t headers_taken{0};  // headers the chain took from bodies
    uint32_t headers_requests{0};  // getheaders asked for (body's parent unknown)
    std::vector<std::string> events;     // clean / header, in order
    bool cleaned_when_header_taken{false};
    Mempool* pool{nullptr};

    void set_chain(const std::vector<BlockType>& blocks, uint32_t first_height)
    {
        best.clear();
        for (size_t i = 0; i < blocks.size(); ++i) {
            best[first_height + static_cast<uint32_t>(i)] = hash_of(blocks[i]);
            parent[hash_of(blocks[i])] = blocks[i].m_previous_block;
        }
    }
    uint32_t tip_height() const { return best.empty() ? 0 : best.rbegin()->first; }
    uint256 tip() const { return best.empty() ? uint256() : best.rbegin()->second; }

    doge::coin::UtxoLaneHost host()
    {
        doge::coin::UtxoLaneHost h;
        h.chain_height = [this]() { return tip_height(); };
        h.chain_hash_at = [this](uint32_t height) {
            auto it = best.find(height);
            return it == best.end() ? uint256() : it->second;
        };
        h.prev_of = [this](const uint256& hh) -> std::optional<uint256> {
            auto it = parent.find(hh);
            if (it == parent.end())
                return std::nullopt;
            return it->second;
        };
        // The header chain taking a body's header (main_ltc: HeaderChain::
        // add_header): a header that extends the tip extends the best chain.
        // main_ltc: the body's txs leave the mempool before its header.
        h.clean_before_header = [this](const BlockType& b, uint32_t height) {
            events.push_back("clean " + std::to_string(height));
            if (pool) {
                pool->set_tip_height(height);
                pool->remove_for_block(b);
            }
        };
        h.add_header = [this](const BlockType& b) {
            const uint256 hh = hash_of(b);
            if (parent.count(hh) || !parent.count(b.m_previous_block))
                return false;
            events.push_back("header");
            cleaned_when_header_taken = pool && pool->cleaned_for(hh);
            parent[hh] = b.m_previous_block;
            if (!best.empty() && best.rbegin()->second == b.m_previous_block)
                best[best.rbegin()->first + 1] = hh;
            ++headers_taken;
            return true;
        };
        h.headers_needed = [this]() { ++headers_requests; };
        h.request = [this](uint32_t height, UtxoAsk how) {
            requested.push_back(height);
            asked_how.push_back(how);
        };
        // main_ltc: a drained block gets the explorer / mempool / coinbase
        // passes here (the mempool's is what matters for templates).
        h.connected = [this](const BlockType& b, const uint256&, uint32_t height, bool drained) {
            connected.push_back(height);
            if (drained && pool) {
                pool->set_tip_height(height);
                pool->remove_for_block(b);
            }
        };
        // main_ltc: the mempool's priced txs are quarantined.
        h.wiped = [this]() {
            ++wiped;
            if (pool)
                pool->requarantine_all();
        };
        return h;
    }
};

struct Lane {
    TempDb t;
    Net net;
    UtxoLane lane;
    explicit Lane(uint32_t keep = core::coin::DOGE_MIN_BLOCKS_TO_KEEP)
        : lane(*t.cache, *t.db, net.host(), keep)
    {
    }

    /// The header chain moves to `chain` (from first_height) and fires its
    /// tip change; main_ltc's handler hands it to the lane. Returns whether
    /// the lane took it as a reorg.
    bool switch_to(const std::vector<BlockType>& chain, uint32_t first_height)
    {
        const uint256 old_tip = net.tip();
        const uint32_t old_height = net.tip_height();
        net.set_chain(chain, first_height);
        return lane.on_tip_changed(old_tip, old_height, net.tip(), net.tip_height());
    }

    /// main_ltc's DOGE full-block handler: the lane, then the mempool passes.
    UtxoLane::FeedResult deliver(const BlockType& b, uint32_t height)
    {
        const auto r = lane.on_block(b, hash_of(b), height);
        Mempool* pool = net.pool;
        if (!pool)
            return r;
        if (r.fed == UtxoLane::Fed::Pipeline) {
            if (r.on_best_chain) {
                if (net.tip_height() == height)
                    pool->set_tip_height(height);
                pool->remove_for_block(b);
            }
            if (r.connected > 0) {
                pool->recompute_unknown_fees(t.cache.get());
                pool->revalidate_inputs(t.cache.get());
            }
            return r;
        }
        pool->set_tip_height(height);
        pool->remove_for_block(b);
        pool->recompute_unknown_fees(t.cache.get());
        pool->revalidate_inputs(t.cache.get());
        return r;
    }

    /// Connect a chain from height 1 the ordinary way: header, then body.
    void grow(const std::vector<BlockType>& chain)
    {
        for (size_t i = 0; i < chain.size(); ++i) {
            std::vector<BlockType> upto(chain.begin(), chain.begin() + static_cast<long>(i) + 1);
            switch_to(upto, 1);
            deliver(chain[i], static_cast<uint32_t>(i + 1));
        }
    }

    bool has(const MutableTransaction& tx, uint32_t index = 0)
    {
        return t.cache->have_coin(Outpoint(txid_of(tx), index));
    }
};

/// The DOGE template's transactions, as TemplateBuilder::build_template
/// selects them (same call, same weight budget, unknown-fee fill on).
std::vector<uint256> template_txids(const Mempool& pool)
{
    const auto sel = pool.get_sorted_txs_with_fees(
        doge::coin::TemplateBuilder::MAX_BLOCK_WEIGHT - doge::coin::TemplateBuilder::COINBASE_RESERVE,
        /*fill_unknown_fee=*/true);
    std::vector<uint256> out;
    for (const auto& s : sel.first)
        out.push_back(compute_txid(s.tx));
    return out;
}

bool contains(const std::vector<uint256>& v, const uint256& x)
{
    return std::find(v.begin(), v.end(), x) != v.end();
}

} // namespace

// The canary's daily reorg kind is an equal-work sibling; this one is rarer
// and the predicate `new_height <= old_height` missed it: a heavier branch
// b2..b5 that forks below the old tip a3 and ends higher. The header chain
// picks its tip by chain work, so the new tip does not descend from the old
// one: a reorg. The view must end on b2..b5 with a2 / a3 gone, not on
// a1 a2 a3 + b5 with b2..b4 never connected.
TEST(DogeUtxoOrder, TallerHeavierSiblingBranchIsAReorg)
{
    Lane l;
    const uint256 g = genesis(0x10);
    const auto a = make_chain(g, 1, 3, 0x10);               // a1 a2 a3
    const auto b = make_chain(hash_of(a[0]), 2, 4, 0x20);   // b2 b3 b4 b5, fork at a1
    l.grow(a);
    ASSERT_EQ(l.t.cache->get_best_block(), hash_of(a[2]));

    l.net.requested.clear();
    EXPECT_TRUE(l.switch_to({a[0], b[0], b[1], b[2], b[3]}, 1)) << "b5 does not descend from a3";
    EXPECT_EQ(l.t.cache->get_best_block(), hash_of(a[0])) << "walked back to the fork";
    EXPECT_FALSE(l.has(a[1].m_txs[0]));
    EXPECT_FALSE(l.has(a[2].m_txs[0]));
    EXPECT_EQ(l.net.requested, (std::vector<uint32_t>{2, 3, 4, 5})) << "the whole new branch";

    // The tip's body first (the tip handler asks for it), then the fill.
    l.deliver(b[3], 5);
    l.deliver(b[0], 2);
    l.deliver(b[2], 4);
    l.deliver(b[1], 3);
    EXPECT_FALSE(l.lane.fill().active);
    EXPECT_EQ(l.t.cache->get_best_height(), 5u);
    EXPECT_EQ(l.t.cache->get_best_block(), hash_of(b[3]));
    for (const auto& blk : b)
        EXPECT_TRUE(l.has(blk.m_txs[0])) << "every block of the new branch is connected";
    EXPECT_FALSE(l.has(a[1].m_txs[0])) << "the old branch's outputs are gone";
    EXPECT_FALSE(l.has(a[2].m_txs[0]));
    EXPECT_TRUE(l.has(a[0].m_txs[0]));
}

// h+2's body before h+1's (h+1 still in flight, or never announced to us):
// h+2 is buffered and h+1 fetched; both end up connected, in order. Before,
// h+2 was connected over the gap and h+1 skipped as old for good: h+1's
// outputs never existed in the view and the coin h+1 spent stayed
// spendable (a double-spend the template could carry).
TEST(DogeUtxoOrder, OutOfOrderBodiesConnectInOrder)
{
    Lane l;
    const uint256 g = genesis(0x30);
    const BlockType c1 = make_block(g, 1, 0x31);
    const BlockType c2 = make_block(hash_of(c1), 2, 0x32);
    const auto v_tx = spend(txid_of(c1.m_txs[0]), 0, DOGE_SUBSIDY - 100000000, 0x3a);  // V spends c1's coinbase
    const BlockType c3 = make_block(hash_of(c2), 3, 0x33, {v_tx});
    const auto z_tx = spend(txid_of(v_tx), 0, DOGE_SUBSIDY - 200000000, 0x3b);         // Z spends V
    const BlockType c4 = make_block(hash_of(c3), 4, 0x34, {z_tx});
    l.grow({c1, c2});
    l.switch_to({c1, c2, c3, c4}, 1);   // one headers batch: 3 and 4
    l.net.requested.clear();

    l.deliver(c4, 4);
    EXPECT_EQ(l.t.cache->get_best_height(), 2u) << "never connected over a missing parent";
    EXPECT_EQ(l.net.requested, (std::vector<uint32_t>{3}));

    l.deliver(c3, 3);
    EXPECT_FALSE(l.lane.fill().active);
    EXPECT_EQ(l.t.cache->get_best_block(), hash_of(c4));
    EXPECT_TRUE(l.has(c3.m_txs[0])) << "h+1's outputs exist";
    EXPECT_FALSE(l.has(c1.m_txs[0])) << "the coin h+1 spent is spent";
    EXPECT_FALSE(l.has(v_tx)) << "V spent by h+2";
    EXPECT_TRUE(l.has(z_tx));
    EXPECT_TRUE(l.has(c4.m_txs[0]));
    core::coin::BlockUndo u;
    ASSERT_TRUE(l.t.db->get_block_undo(3, u));
    EXPECT_EQ(u.block_hash, hash_of(c3));
}

// A reorg onto a shorter but heavier branch, two blocks deep: a3..a5 go, b3
// and b4 both come. Before, only the new tip was asked for and connected
// over the fork, so b3 never reached the view.
TEST(DogeUtxoOrder, MultiBlockReorgConnectsEveryNewBranchBlock)
{
    Lane l;
    const uint256 g = genesis(0x40);
    const auto a = make_chain(g, 1, 5, 0x40);               // a1..a5
    const BlockType b3 = make_block(hash_of(a[1]), 3, 0x50);
    const auto w_tx = spend(txid_of(b3.m_txs[0]), 0, DOGE_SUBSIDY - 100000000, 0x5a);  // W spends b3's coinbase
    const BlockType b4 = make_block(hash_of(b3), 4, 0x51, {w_tx});
    l.grow(a);
    l.net.requested.clear();

    EXPECT_TRUE(l.switch_to({a[0], a[1], b3, b4}, 1));
    EXPECT_EQ(l.t.cache->get_best_block(), hash_of(a[1]));
    EXPECT_EQ(l.net.requested, (std::vector<uint32_t>{3, 4}));

    l.deliver(b4, 4);   // the new tip first
    EXPECT_EQ(l.t.cache->get_best_height(), 2u) << "b4 waits for b3";
    l.deliver(b3, 3);
    EXPECT_EQ(l.t.cache->get_best_block(), hash_of(b4));
    EXPECT_FALSE(l.has(b3.m_txs[0])) << "b3 connected, then its coinbase spent by b4";
    EXPECT_TRUE(l.has(w_tx));
    EXPECT_TRUE(l.has(b4.m_txs[0]));
    for (int i = 2; i < 5; ++i)
        EXPECT_FALSE(l.has(a[i].m_txs[0])) << "a" << i + 1 << " is gone";
    core::coin::BlockUndo u;
    ASSERT_TRUE(l.t.db->get_block_undo(3, u)) << "b3 was connected";
    EXPECT_EQ(u.block_hash, hash_of(b3));
    ASSERT_EQ(u.tx_undos.size(), 0u);
    ASSERT_TRUE(l.t.db->get_block_undo(4, u));
    ASSERT_EQ(u.tx_undos.size(), 1u);
    ASSERT_EQ(u.tx_undos[0].spent_coins.size(), 1u);
    EXPECT_EQ(u.tx_undos[0].spent_coins[0].value, DOGE_SUBSIDY)
        << "b4 found b3's coinbase in the view: its record holds the coin, not an unknown one";
}

// An undo record written before #2059 (an upgraded node, within 1440 blocks
// of the upgrade) cannot put the coins its block spent back. The lane must
// not carry on with X missing: it wipes the set and rebuilds it from the
// best chain.
TEST(DogeUtxoOrder, LegacyUndoRecordRebuilds)
{
    Lane l;
    const uint256 g = genesis(0x60);
    const BlockType a1 = make_block(g, 1, 0x61);
    const Outpoint X(txid_of(a1.m_txs[0]), 0);
    const auto y_tx = spend(X.txid, 0, DOGE_SUBSIDY - 100000000, 0x6a);   // Y spends X
    const BlockType a2 = make_block(hash_of(a1), 2, 0x62, {y_tx});
    const BlockType b2 = make_block(hash_of(a1), 2, 0x63);                 // sibling, does not spend X
    l.grow({a1, a2});
    ASSERT_FALSE(l.t.cache->have_coin(X));
    // a2's record as the node that connected a2 before the upgrade left it.
    core::coin::BlockUndo v2;
    ASSERT_TRUE(l.t.db->get_block_undo(2, v2));
    ASSERT_TRUE(l.t.db->put_block_undo_legacy(2, v2));
    l.net.requested.clear();

    EXPECT_TRUE(l.switch_to({a1, b2}, 1));
    EXPECT_EQ(l.net.wiped, 1u) << "rebuilt, not carried on";
    EXPECT_TRUE(l.t.cache->get_best_block().IsNull()) << "wiped";
    EXPECT_TRUE(l.lane.fill().active);
    EXPECT_EQ(l.net.requested, (std::vector<uint32_t>{1, 2})) << "the best chain's last blocks";

    l.deliver(b2, 2);
    l.deliver(a1, 1);
    EXPECT_FALSE(l.lane.fill().active);
    EXPECT_EQ(l.t.cache->get_best_block(), hash_of(b2));
    EXPECT_TRUE(l.t.cache->have_coin(X)) << "X is unspent on the best chain";
    EXPECT_FALSE(l.has(y_tx));
    EXPECT_FALSE(l.has(a2.m_txs[0]));
    EXPECT_TRUE(l.has(b2.m_txs[0]));
}

// #2070's invalid-block path, no adversary needed: T is confirmed only on
// the old branch. After the reorg, T is unconfirmed again (dogecoind puts it
// back in its mempool), and C, which spends T, is relayed. With the old
// branch still in the view, T's output looks confirmed, C is selected
// without T, and the aux block is invalid (bad-txns-inputs-missingorspent).
// After the reorg the view does not have T's output: C is never selected
// without T; once T is relayed too, both are, T first.
TEST(DogeUtxoOrder, OrphanedTxChildIsNotSelectedAfterReorg)
{
    Lane l;
    Mempool pool(core::coin::DOGE_LIMITS);
    pool.set_utxo(l.t.cache.get());
    l.net.pool = &pool;

    uint256 outside;
    outside.SetHex("ee00000000000000000000000000000000000000000000000000000000000001");
    const auto f_tx = spend(outside, 0, 50000000000LL, 0x7a);                // F: creates X (not a coinbase)
    const uint256 g = genesis(0x70);
    const BlockType a1 = make_block(g, 1, 0x71, {f_tx});
    const auto t_tx = spend(txid_of(f_tx), 0, 49000000000LL, 0x7b);             // T spends X
    const BlockType a2 = make_block(hash_of(a1), 2, 0x72, {t_tx});
    const BlockType a3 = make_block(hash_of(a2), 3, 0x73);
    const auto b = make_chain(hash_of(a1), 2, 3, 0x80);                     // b2 b3 b4: no T
    const auto c_tx = spend(txid_of(t_tx), 0, 48000000000LL, 0x7c);             // C spends T
    l.grow({a1, a2, a3});
    ASSERT_TRUE(l.has(t_tx));

    l.switch_to({a1, b[0], b[1], b[2]}, 1);
    ASSERT_TRUE(pool.add_tx(c_tx, l.t.cache.get()));
    EXPECT_FALSE(contains(template_txids(pool), txid_of(c_tx))) << "C without T right after the reorg";

    l.deliver(b[2], 4);
    l.deliver(b[0], 2);
    l.deliver(b[1], 3);
    ASSERT_EQ(l.t.cache->get_best_block(), hash_of(b[2]));
    EXPECT_FALSE(l.has(t_tx)) << "T's output is not on the best chain";
    EXPECT_TRUE(l.has(f_tx)) << "X is unspent on the best chain";
    EXPECT_FALSE(contains(template_txids(pool), txid_of(c_tx))) << "C without T on the new branch";

    ASSERT_TRUE(pool.add_tx(t_tx, l.t.cache.get()));
    const auto sel = template_txids(pool);
    const auto ti = std::find(sel.begin(), sel.end(), txid_of(t_tx));
    const auto ci = std::find(sel.begin(), sel.end(), txid_of(c_tx));
    ASSERT_NE(ti, sel.end()) << "T spends X, unspent on the best chain";
    ASSERT_NE(ci, sel.end());
    EXPECT_LT(ti - sel.begin(), ci - sel.begin()) << "parent first";
}

// ── Beyond the five: request kinds, startup, a mismatch the tip change did
//    not report, the cold start, counters ────────────────────────────────

// On the canary 62 % of DOGE bodies arrive before the header chain knows the
// block (a peer's inv is answered with the body; headers come with the 60 s
// getheaders): p50 10 s, up to 61 s early. The body carries its header: the
// header chain takes it and the block is connected on this delivery. Before,
// the body was dropped (not on the best chain yet), fetched again after the
// header landed, and meanwhile the mempool pass evicted the children of its
// txs.
TEST(DogeUtxoOrder, BodyBeforeHeaderConnectsOnFirstDelivery)
{
    Lane l;
    const auto a = make_chain(genesis(0xe0), 1, 3, 0xe0);
    l.grow(a);
    const auto x_tx = spend(txid_of(a[0].m_txs[0]), 0, DOGE_SUBSIDY - 100000000, 0xea);
    const BlockType a4 = make_block(hash_of(a[2]), 4, 0xe4, {x_tx});
    l.net.requested.clear();

    const auto r = l.deliver(a4, 4);   // the header chain has never seen a4
    EXPECT_EQ(r.fed, UtxoLane::Fed::Connected) << "connected on the first delivery";
    EXPECT_EQ(l.net.headers_taken, 1u) << "the header came from the body";
    EXPECT_EQ(l.net.best[4], hash_of(a4));
    EXPECT_EQ(l.t.cache->get_best_block(), hash_of(a4));
    EXPECT_TRUE(l.has(x_tx));
    EXPECT_FALSE(l.has(a[0].m_txs[0])) << "the coin a4 spent is spent";
    EXPECT_TRUE(l.net.requested.empty()) << "nothing fetched again";
    // The tip change the header chain fired: an extension, nothing to do.
    EXPECT_FALSE(l.lane.on_tip_changed(hash_of(a[2]), 3, hash_of(a4), 4));
    EXPECT_TRUE(l.net.requested.empty());
    // The late copy (another peer, or the old re-request): already connected.
    EXPECT_EQ(l.deliver(a4, 4).fed, UtxoLane::Fed::Skipped);
    EXPECT_EQ(l.lane.stats().headers_from_bodies.load(), 1u);

    EXPECT_EQ(l.net.headers_requests, 0u);
    // A body whose parent the chain does not know either: the header chain
    // is behind. Nothing taken or connected; headers are asked for now
    // instead of at the next periodic getheaders.
    const BlockType stray = make_block(genesis(0xef), 6, 0xe6);
    EXPECT_EQ(l.deliver(stray, 0).fed, UtxoLane::Fed::Skipped);
    EXPECT_EQ(l.net.headers_taken, 1u);
    EXPECT_EQ(l.net.headers_requests, 1u);
    EXPECT_EQ(l.lane.stats().headers_requested.load(), 1u);
}

// The header taken from a body moves the tip at once, and the merged-mining
// poll (another thread) may build the DOGE template on it right then. The
// txs the block confirmed must already be out of the mempool: the pool is
// cleaned for the block BEFORE its header goes in.
TEST(DogeUtxoOrder, BodyBeforeHeaderCleansThePoolFirst)
{
    Lane l;
    Mempool pool(core::coin::DOGE_LIMITS);
    pool.set_utxo(l.t.cache.get());
    l.net.pool = &pool;
    const auto a = make_chain(genesis(0xd5), 1, 3, 0xd5);
    l.grow(a);
    const auto q_tx = spend(txid_of(a[0].m_txs[0]), 0, DOGE_SUBSIDY - 100000000, 0xdb);
    ASSERT_TRUE(pool.add_tx(q_tx, l.t.cache.get()));
    const BlockType a4 = make_block(hash_of(a[2]), 4, 0xd9, {q_tx});   // confirms Q
    l.net.events.clear();

    EXPECT_EQ(l.deliver(a4, 4).fed, UtxoLane::Fed::Connected);
    EXPECT_EQ(l.net.events, (std::vector<std::string>{"clean 4", "header"}));
    EXPECT_TRUE(l.net.cleaned_when_header_taken) << "Q was in the pool when the tip moved";
    EXPECT_FALSE(pool.contains(txid_of(q_tx)));

    // A body whose header the chain already has: nothing extra.
    l.net.events.clear();
    l.deliver(a4, 4);
    EXPECT_TRUE(l.net.events.empty());
}

// A block buffered by a fill that is no longer the best chain's at its
// height when the drain reaches it (the header chain switched, its tip
// change not handled yet): it is not connected; the fill restarts at the
// set's real next height and fetches the best chain's block.
TEST(DogeUtxoOrder, StaleBufferedBlockIsRefetched)
{
    Lane l;
    const auto a = make_chain(genesis(0xf0), 1, 4, 0xf0);   // a1..a4
    const BlockType a4x = make_block(hash_of(a[2]), 4, 0xf9); // sibling of a4
    l.grow({a[0], a[1]});
    l.switch_to(a, 1);
    l.deliver(a[3], 4);                        // gap: a4 buffered, 3 requested
    ASSERT_TRUE(l.lane.fill().active);
    l.net.set_chain({a[0], a[1], a[2], a4x}, 1);  // switched, not yet handled
    l.net.requested.clear();
    l.deliver(a[2], 3);                        // 3 drains; a4 is refused
    EXPECT_EQ(l.t.cache->get_best_block(), hash_of(a[2]));
    EXPECT_TRUE(l.lane.fill().active);
    EXPECT_EQ(l.net.requested, (std::vector<uint32_t>{4}));
    l.deliver(a4x, 4);
    EXPECT_FALSE(l.lane.fill().active);
    EXPECT_EQ(l.t.cache->get_best_block(), hash_of(a4x));
    EXPECT_FALSE(l.has(a[3].m_txs[0]));
    EXPECT_TRUE(l.has(a4x.m_txs[0]));
}

// Each fill asks the way main_ltc's EMB-LTC lane does: a gap asks the peer
// that delivered the block (it has its parents), a reorg fill one peer at a
// time, the cold-start window every peer.
TEST(DogeUtxoOrder, RequestKindsPerFill)
{
    {
        Lane l;
        const auto c = make_chain(genesis(0x90), 1, 4, 0x90);
        l.grow({c[0], c[1]});
        l.switch_to(c, 1);
        l.net.requested.clear();
        l.net.asked_how.clear();
        l.deliver(c[3], 4);
        EXPECT_EQ(l.net.requested, (std::vector<uint32_t>{3}));
        EXPECT_EQ(l.net.asked_how, (std::vector<UtxoAsk>{UtxoAsk::FromPeer}));
    }
    {
        Lane l;
        const auto a = make_chain(genesis(0x91), 1, 2, 0x91);
        const auto b = make_chain(hash_of(a[0]), 2, 1, 0x95);
        l.grow(a);
        l.net.asked_how.clear();
        l.switch_to({a[0], b[0]}, 1);
        EXPECT_EQ(l.net.asked_how, (std::vector<UtxoAsk>{UtxoAsk::Targeted}));
    }
    {
        Lane l(4);
        const auto c = make_chain(genesis(0x92), 1, 10, 0x92);
        l.net.set_chain(c, 1);
        l.deliver(c[9], 10);   // cold start: the last 4 below the tip
        EXPECT_EQ(l.net.requested, (std::vector<uint32_t>{6, 7, 8, 9}));
        EXPECT_EQ(l.net.asked_how, std::vector<UtxoAsk>(4, UtxoAsk::Broadcast));
    }
}

// A crash after a reorg's tip was persisted but before the UTXO side ran: on
// restart no tip change fires. The startup check walks the set back and
// refills; on a set already on the best chain it does nothing.
TEST(DogeUtxoOrder, StartupHealsACrashBetweenTipAndDisconnect)
{
    Lane l;
    const auto a = make_chain(genesis(0xa0), 1, 3, 0xa0);
    const auto b = make_chain(hash_of(a[0]), 2, 3, 0xa8);
    l.grow(a);
    l.net.requested.clear();
    l.lane.startup();
    EXPECT_TRUE(l.net.requested.empty());
    EXPECT_EQ(l.t.cache->get_best_block(), hash_of(a[2]));

    l.net.set_chain({a[0], b[0], b[1], b[2]}, 1);   // persisted, never handled
    l.lane.startup();
    EXPECT_EQ(l.t.cache->get_best_block(), hash_of(a[0]));
    EXPECT_EQ(l.net.requested, (std::vector<uint32_t>{2, 3, 4}));
    l.deliver(b[0], 2);
    l.deliver(b[1], 3);
    l.deliver(b[2], 4);
    EXPECT_EQ(l.t.cache->get_best_block(), hash_of(b[2]));
    EXPECT_FALSE(l.has(a[1].m_txs[0]));
    EXPECT_FALSE(l.has(a[2].m_txs[0]));
}

// add_headers fires one tip change per batch: a batch that switches branch
// and then extends the new one reports old = b3, new = b4, an extension.
// The connect-point check finds the set's best (a3) is not b4's parent and
// walks the set back to the best chain.
TEST(DogeUtxoOrder, ParentMismatchTheTipChangeDidNotReportHeals)
{
    Lane l;
    const auto a = make_chain(genesis(0xb0), 1, 3, 0xb0);
    const auto b = make_chain(hash_of(a[0]), 2, 3, 0xb8);   // b2 b3 b4
    l.grow(a);
    const uint256 old_tip = hash_of(b[1]);
    l.net.set_chain({a[0], b[0], b[1], b[2]}, 1);
    EXPECT_FALSE(l.lane.on_tip_changed(old_tip, 3, hash_of(b[2]), 4)) << "b4 extends b3";
    EXPECT_EQ(l.t.cache->get_best_block(), hash_of(a[2])) << "nothing told the lane yet";

    l.net.requested.clear();
    const auto r = l.deliver(b[2], 4);
    EXPECT_EQ(r.fed, UtxoLane::Fed::Refused);
    EXPECT_EQ(l.t.cache->get_best_block(), hash_of(a[0])) << "walked back to the best chain";
    EXPECT_EQ(l.net.requested, (std::vector<uint32_t>{2, 3, 4}));
    l.deliver(b[0], 2);
    l.deliver(b[1], 3);
    EXPECT_EQ(l.t.cache->get_best_block(), hash_of(b[2])) << "b4 kept for the refill";
    EXPECT_FALSE(l.has(a[1].m_txs[0]));
    EXPECT_TRUE(l.has(b[2].m_txs[0]));
}

// Controls the old lane passed too: the cold start fetches the last `keep`
// blocks in order, a plain extension is no reorg.
TEST(DogeUtxoOrder, ColdStartAndExtension)
{
    Lane l(4);
    const auto c = make_chain(genesis(0xc0), 1, 12, 0xc0);
    l.net.set_chain(std::vector<BlockType>(c.begin(), c.begin() + 10), 1);
    l.deliver(c[9], 10);
    for (uint32_t h = 9; h >= 6; --h)
        l.deliver(c[h - 1], h);
    EXPECT_FALSE(l.lane.fill().active);
    EXPECT_EQ(l.net.connected, (std::vector<uint32_t>{6, 7, 8, 9, 10}));
    EXPECT_EQ(l.t.cache->get_best_block(), hash_of(c[9]));

    EXPECT_FALSE(l.switch_to(std::vector<BlockType>(c.begin(), c.begin() + 11), 1)) << "extension";
    l.deliver(c[10], 11);
    EXPECT_EQ(l.t.cache->get_best_block(), hash_of(c[10]));
    EXPECT_FALSE(l.switch_to(c, 1));
    l.deliver(c[11], 12);
    EXPECT_EQ(l.net.connected, (std::vector<uint32_t>{6, 7, 8, 9, 10, 11, 12}));
}

// The /local_stats "doge_utxo" counters.
TEST(DogeUtxoOrder, StatsCountGapsReorgsHealsAndRebuilds)
{
    Lane l;
    const auto a = make_chain(genesis(0xd0), 1, 4, 0xd0);
    const BlockType b3 = make_block(hash_of(a[1]), 3, 0xd8);
    const BlockType b4 = make_block(hash_of(b3), 4, 0xd9,
                                    {spend(txid_of(b3.m_txs[0]), 0, DOGE_SUBSIDY - 100000000, 0xda)});
    const std::vector<BlockType> b{b3, b4};
    l.grow({a[0], a[1]});
    l.switch_to(a, 1);
    l.deliver(a[3], 4);   // gap
    l.deliver(a[2], 3);
    l.switch_to({a[0], a[1], b[0], b[1]}, 1);   // a3 a4 out, b3 b4 in
    l.deliver(b[0], 3);
    l.deliver(b[1], 4);
    // b4's record legacy (it spent b3's coinbase), then b4's sibling: a rebuild.
    const auto b4x = make_chain(hash_of(b[0]), 4, 1, 0xdc)[0];
    core::coin::BlockUndo u;
    ASSERT_TRUE(l.t.db->get_block_undo(4, u));
    ASSERT_TRUE(l.t.db->put_block_undo_legacy(4, u));
    l.switch_to({a[0], a[1], b[0], b4x}, 1);
    const auto j = l.lane.stats().to_json();
    EXPECT_EQ(j.at("gaps").get<uint64_t>(), 1u);
    EXPECT_EQ(j.at("reorgs").get<uint64_t>(), 2u);
    EXPECT_EQ(j.at("heals").get<uint64_t>(), 1u);
    EXPECT_EQ(j.at("disconnected").get<uint64_t>(), 2u);
    EXPECT_EQ(j.at("rebuilds").get<uint64_t>(), 1u);
    EXPECT_EQ(j.at("connected").get<uint64_t>(), 6u);
    EXPECT_EQ(j.at("heal_failures").get<uint64_t>(), 0u);
}
