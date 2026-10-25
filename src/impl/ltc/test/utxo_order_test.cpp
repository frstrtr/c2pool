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
// And the undo records the reorg path disconnects with (#2059): a disconnect
// puts back every coin the block spent (also coins created and spent inside
// the block), the format-2 record layout, and the mainnet pair 3199539 /
// 3199540 disconnected byte-exact against litecoind's own coins
// (ltc_utxo_undo_fixtures.hpp).
// Folded into the allowlisted share_test target (no new executable: #769).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
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
#include <btclibs/util/strencodings.h>

#include <impl/ltc/coin/block.hpp>
#include <impl/ltc/coin/transaction.hpp>
#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/utxo_order.hpp>

#include "ltc_utxo_undo_fixtures.hpp"

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
// Undo records live in the UTXO DB, as main_ltc keeps them.
struct Feed {
    core::coin::UTXOViewCache& utxo;
    core::coin::UTXOViewDB& db;
    core::coin::BlockBootstrapState<BlockType> bs;
    std::vector<uint32_t> connected;   // heights, in connect order
    std::vector<uint32_t> requested;   // heights asked for
    std::map<uint32_t, uint256> best_chain;
    std::map<uint256, uint256> headers;  // every header seen: hash -> parent
    ConnectCheck last_refusal{ConnectCheck::Ok};

    void set_chain(const std::vector<BlockType>& blocks, uint32_t first_height)
    {
        best_chain.clear();
        for (size_t i = 0; i < blocks.size(); ++i) {
            best_chain[first_height + static_cast<uint32_t>(i)] = hash_of(blocks[i]);
            headers[hash_of(blocks[i])] = blocks[i].m_previous_block;
        }
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
        const auto undo = utxo.connect_block(b, height, [](const MutableTransaction& tx) {
            return compute_txid(tx);
        });
        db.put_block_undo(height, undo);
        utxo.flush(h, height);
        connected.push_back(height);
    }

    void refill()
    {
        ordered_refill(bs, [&](uint32_t rh) { requested.push_back(rh); });
    }

    // main_ltc's utxo_heal: walk the UTXO set back to the best chain (undo
    // data, at most LTC_KEEP), flush, drop the undo records, re-arm from its
    // real best. crash_after > 0 stops the walk dead after that many
    // disconnects (a crash before the flush).
    enum class Heal { Startup, Reorg, ParentMismatch };
    uint32_t crash_after{0};
    struct Crash {};

    bool heal(uint32_t target, Heal kind)
    {
        std::vector<uint32_t> undone;
        const auto rw = rewind_to_best_chain(
            288, tip_height(), utxo.get_best_height(), utxo.get_best_block(),
            [&](uint32_t h) {
                auto it = best_chain.find(h);
                return it == best_chain.end() ? uint256() : it->second;
            },
            [&](const uint256& hh) -> std::optional<uint256> {
                auto it = headers.find(hh);
                if (it == headers.end())
                    return std::nullopt;
                return it->second;
            },
            [&](uint32_t h) {
                core::coin::BlockUndo undo;
                if (!db.get_block_undo(h, undo))
                    return false;
                utxo.disconnect_from_undo(undo);
                undone.push_back(h);
                if (crash_after != 0 && undone.size() == crash_after)
                    throw Crash{};
                return true;
            });
        if (rw.disconnected > 0) {
            utxo.flush(rw.hash, rw.height);
            for (uint32_t h : undone)
                db.remove_block_undo(h);
        }
        if (!rw.ok)
            return false;
        if (rw.disconnected == 0 && kind == Heal::ParentMismatch)
            return false;
        if (rw.disconnected == 0 && kind == Heal::Startup)
            return true;
        if (ordered_rearm_after_reorg(bs, utxo.get_best_height(), target))
            refill();
        return true;
    }

    // The active branch after buffering.
    void pump()
    {
        const auto r = ordered_drain(
            bs, [&](const BlockType& b, const uint256& h, uint32_t hh) { return check(b, h, hh); },
            [&](const BlockType& b, const uint256& h, uint32_t hh) { connect(b, h, hh); });
        if (r.refused != ConnectCheck::Ok) {
            last_refusal = r.refused;
            if (r.refused == ConnectCheck::ParentMismatch) {
                if (!heal(tip_height(), Heal::ParentMismatch)) {
                    bs.active = false;
                    bs.buffer.clear();
                }
            } else if (ordered_recover(bs, r.refused, utxo.get_best_height(), tip_height())) {
                refill();
            }
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
            if (c == ConnectCheck::Ok) {
                connect(b, h, height);
            } else {
                last_refusal = c;
                if (c == ConnectCheck::ParentMismatch && heal(tip_height(), Heal::ParentMismatch) && bs.active)
                    ordered_buffer(bs, height, b, h);
            }
        }
    }

    // The reorg handler: utxo_heal to the new tip.
    void reorg(uint32_t new_height) { heal(new_height, Heal::Reorg); }
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

auto txid_fn = [](const MutableTransaction& tx) { return compute_txid(tx); };

::testing::AssertionResult coin_eq(const core::coin::Coin& c, int64_t value,
                                   const std::vector<unsigned char>& spk, uint32_t height,
                                   bool coinbase, bool pegout)
{
    if (c.value == value && c.scriptPubKey.m_data == spk && c.height == height
        && c.coinbase == coinbase && c.pegout == pegout)
        return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure()
        << "coin {" << c.value << ", " << HexStr(c.scriptPubKey.m_data) << ", h=" << c.height
        << ", coinbase=" << c.coinbase << ", pegout=" << c.pegout << "} expected {" << value
        << ", " << HexStr(spk) << ", h=" << height << ", coinbase=" << coinbase
        << ", pegout=" << pegout << "}";
}

uint256 bytes_from(uint8_t first)
{
    uint256 u;
    for (int i = 0; i < 32; ++i)
        u.data()[i] = static_cast<uint8_t>(first + i);
    return u;
}

uint256 from_hex(const char* hex)
{
    uint256 u;
    u.SetHex(hex);
    return u;
}

BlockType parse_block(const char* hex)
{
    auto bytes = ParseHex(hex);
    PackStream ps(bytes);
    BlockType b;
    ps >> b;
    return b;
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
    f.reorg(2);
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
    f.reorg(5);
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

// The UTXO set itself on another branch (its best block is not the parent
// of the best chain's next block): it is walked back to the best chain and
// the best chain is connected from there.
TEST(LtcUtxoOrder, ParentMismatchRewindsAndHeals)
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
    EXPECT_EQ(t.cache->get_best_height(), 1u) << "walked back to the best chain";
    EXPECT_EQ(t.cache->get_best_block(), hash_of(a[0]));
    EXPECT_TRUE(f.bs.active);
    EXPECT_EQ(f.bs.next_height, 2u);
    f.deliver(b[0], 2);                                    // b2, then the kept b3
    EXPECT_FALSE(f.bs.active);
    EXPECT_EQ(t.cache->get_best_height(), 3u);
    EXPECT_EQ(t.cache->get_best_block(), hash_of(b[1]));
    EXPECT_FALSE(has(*t.cache, a[1].m_txs[0]));
    EXPECT_TRUE(has(*t.cache, b[0].m_txs[0]));
    EXPECT_TRUE(has(*t.cache, b[1].m_txs[0]));
}

// A crash after a reorg's tip was persisted but before its UTXO disconnect
// ran: on restart there is no tip change. The startup check walks the UTXO
// set back and refills the new branch; on a UTXO set already on the best
// chain it does nothing. Past the undo data it gives up (ERROR stop).
TEST(LtcUtxoOrder, StartupHealsACrashBetweenTipAndDisconnect)
{
    TempDb t;
    Feed f{*t.cache, *t.db};
    uint256 g;
    g.SetHex("00000000000000000000000000000000000000000000000000000000000000b1");
    const auto a = make_chain(g, 1, 3, 0xd0);              // a1..a3
    const auto b = make_chain(hash_of(a[0]), 2, 3, 0xe0);  // b2..b4, fork at a1
    f.set_chain(a, 1);
    for (uint32_t h = 1; h <= 3; ++h)
        f.deliver(a[h - 1], h);
    ASSERT_EQ(t.cache->get_best_block(), hash_of(a[2]));

    // Already on the best chain: the startup check is a no-op.
    EXPECT_TRUE(f.heal(3, Feed::Heal::Startup));
    EXPECT_FALSE(f.bs.active);
    EXPECT_EQ(t.cache->get_best_height(), 3u);

    // Header chain now b2..b4; the UTXO set never heard of it.
    f.set_chain({a[0], b[0], b[1], b[2]}, 1);
    f.requested.clear();
    EXPECT_TRUE(f.heal(4, Feed::Heal::Startup));
    EXPECT_EQ(t.cache->get_best_height(), 1u);
    EXPECT_EQ(t.cache->get_best_block(), hash_of(a[0]));
    EXPECT_TRUE(f.bs.active);
    EXPECT_EQ(f.requested, (std::vector<uint32_t>{2, 3, 4}));
    f.deliver(b[0], 2);
    f.deliver(b[1], 3);
    f.deliver(b[2], 4);
    EXPECT_FALSE(f.bs.active);
    EXPECT_EQ(t.cache->get_best_block(), hash_of(b[2]));
    EXPECT_FALSE(has(*t.cache, a[1].m_txs[0]));
    EXPECT_FALSE(has(*t.cache, a[2].m_txs[0]));
    EXPECT_TRUE(has(*t.cache, b[2].m_txs[0]));
}

TEST(LtcUtxoOrder, HealGivesUpWithoutUndoData)
{
    TempDb t;
    Feed f{*t.cache, *t.db};
    uint256 g;
    g.SetHex("00000000000000000000000000000000000000000000000000000000000000b2");
    const auto a = make_chain(g, 1, 3, 0xf0);              // a1..a3
    const auto b = make_chain(hash_of(a[0]), 2, 2, 0x10);  // b2, b3
    f.set_chain(a, 1);
    for (uint32_t h = 1; h <= 3; ++h)
        f.deliver(a[h - 1], h);
    f.set_chain({a[0], b[0], b[1]}, 1);
    t.db->remove_block_undo(2);                            // pruned
    EXPECT_FALSE(f.heal(3, Feed::Heal::Reorg)) << "cannot reach the best chain";
    EXPECT_EQ(t.cache->get_best_height(), 2u) << "a3 undone, a2 has no undo data";
    EXPECT_FALSE(f.bs.active) << "no fill armed on a UTXO set off the best chain";
}

// A reorg onto a shorter but heavier chain: the UTXO set's best (a4) is above
// the new tip (b2), where the header chain has no block to compare against.
// Everything above the tip is off the best chain and goes at once; the walk
// stops at the fork and the new branch is filled from there.
TEST(LtcUtxoOrder, ReorgOntoAShorterChainDisconnectsAboveTheTip)
{
    TempDb t;
    Feed f{*t.cache, *t.db};
    uint256 g;
    g.SetHex("00000000000000000000000000000000000000000000000000000000000000b3");
    const auto a = make_chain(g, 1, 4, 0x20);              // a1..a4
    const auto b = make_chain(hash_of(a[0]), 2, 1, 0x30);  // b2, fork at a1
    f.set_chain(a, 1);
    for (uint32_t h = 1; h <= 4; ++h)
        f.deliver(a[h - 1], h);
    ASSERT_EQ(t.cache->get_best_block(), hash_of(a[3]));

    f.set_chain({a[0], b[0]}, 1);
    f.reorg(2);
    EXPECT_EQ(t.cache->get_best_height(), 1u) << "a4, a3 (above the tip) and a2 undone";
    EXPECT_EQ(t.cache->get_best_block(), hash_of(a[0]));
    EXPECT_TRUE(f.bs.active);
    EXPECT_EQ(f.requested, (std::vector<uint32_t>{2}));
    core::coin::BlockUndo u;
    EXPECT_FALSE(t.db->get_block_undo(3, u)) << "undo records go with the flush";
    EXPECT_FALSE(t.db->get_block_undo(4, u));
    f.deliver(b[0], 2);
    EXPECT_FALSE(f.bs.active);
    EXPECT_EQ(t.cache->get_best_block(), hash_of(b[0]));
    for (int i = 1; i < 4; ++i)
        EXPECT_FALSE(has(*t.cache, a[i].m_txs[0])) << "a" << i + 1 << "'s outputs are gone";
    EXPECT_TRUE(has(*t.cache, b[0].m_txs[0]));
}

// A height index with a hole at the UTXO set's best (a fast-start checkpoint
// above it, a rebuild in progress): the walk cannot tell whether that block
// is on the best chain, so it fails instead of calling the set good, and a
// parent mismatch at the next height does not re-request the same range.
TEST(LtcUtxoOrder, HealFailsOnAHeightTheChainCannotJudge)
{
    TempDb t;
    Feed f{*t.cache, *t.db};
    uint256 g;
    g.SetHex("00000000000000000000000000000000000000000000000000000000000000b4");
    const auto a = make_chain(g, 1, 4, 0x40);              // a1..a4
    f.set_chain(a, 1);
    for (uint32_t h = 1; h <= 3; ++h)
        f.deliver(a[h - 1], h);
    f.best_chain.erase(3);
    f.requested.clear();
    EXPECT_FALSE(f.heal(4, Feed::Heal::ParentMismatch));
    EXPECT_FALSE(f.heal(4, Feed::Heal::Reorg));
    EXPECT_EQ(t.cache->get_best_height(), 3u) << "nothing undone";
    EXPECT_FALSE(f.bs.active);
    EXPECT_TRUE(f.requested.empty());
}

// The best chain's block at best + 1 does not build on the UTXO set's best,
// yet the index agrees with the UTXO set at best (an index caught between two
// rebuilds). Nothing can be disconnected, so the heal fails: re-arming the
// same range would request the same block and hit the same mismatch forever.
TEST(LtcUtxoOrder, ParentMismatchOnTheBestChainDoesNotRefill)
{
    TempDb t;
    Feed f{*t.cache, *t.db};
    uint256 g;
    g.SetHex("00000000000000000000000000000000000000000000000000000000000000b5");
    const auto a = make_chain(g, 1, 2, 0x50);              // a1, a2
    const auto x = make_chain(hash_of(a[0]), 2, 2, 0x60);  // x2, x3 (x3's parent is x2)
    f.set_chain(a, 1);
    f.deliver(a[0], 1);
    f.deliver(a[1], 2);
    f.best_chain[3] = hash_of(x[1]);
    f.headers[hash_of(x[1])] = hash_of(x[0]);
    f.requested.clear();
    f.deliver(x[1], 3);
    EXPECT_EQ(f.last_refusal, ConnectCheck::ParentMismatch);
    EXPECT_EQ(t.cache->get_best_block(), hash_of(a[1])) << "a2 kept: it is the index's block at 2";
    EXPECT_FALSE(f.bs.active);
    EXPECT_TRUE(f.requested.empty()) << "no refill of the range that just failed";
}

// A crash in the middle of the walk, before the flush: the DB still has the
// old best, so its undo records must still be there for the next heal.
TEST(LtcUtxoOrder, CrashMidHealKeepsTheUndoForTheRestart)
{
    TempDb t;
    uint256 g;
    g.SetHex("00000000000000000000000000000000000000000000000000000000000000b6");
    const auto a = make_chain(g, 1, 3, 0x70);              // a1..a3
    const auto b = make_chain(hash_of(a[0]), 2, 2, 0x80);  // b2, b3
    std::map<uint32_t, uint256> best_chain;
    std::map<uint256, uint256> headers;
    {
        Feed f{*t.cache, *t.db};
        f.set_chain(a, 1);
        for (uint32_t h = 1; h <= 3; ++h)
            f.deliver(a[h - 1], h);
        f.set_chain({a[0], b[0], b[1]}, 1);
        f.crash_after = 1;
        EXPECT_THROW(f.heal(3, Feed::Heal::Reorg), Feed::Crash);
        core::coin::BlockUndo u;
        EXPECT_TRUE(t.db->get_block_undo(3, u)) << "undo of the block the DB still has as best";
        EXPECT_TRUE(t.db->get_block_undo(2, u));
        best_chain = f.best_chain;
        headers = f.headers;
    }

    // Restart: a fresh cache over the same DB (the undo records with it).
    t.cache = std::make_unique<core::coin::UTXOViewCache>(t.db.get());
    ASSERT_EQ(t.cache->get_best_block(), hash_of(a[2])) << "nothing flushed before the crash";
    Feed r{*t.cache, *t.db};
    r.best_chain = best_chain;
    r.headers = headers;
    EXPECT_TRUE(r.heal(3, Feed::Heal::Startup));
    EXPECT_EQ(t.cache->get_best_block(), hash_of(a[0]));
    EXPECT_TRUE(r.bs.active);
    EXPECT_EQ(r.requested, (std::vector<uint32_t>{2, 3}));
    EXPECT_FALSE(has(*t.cache, a[1].m_txs[0]));
    EXPECT_FALSE(has(*t.cache, a[2].m_txs[0]));
    EXPECT_TRUE(has(*t.cache, a[0].m_txs[0]));
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

// ── Undo records: a disconnect puts back what the block spent (#2059) ──────

// The old branch spent a coin created before the fork (X, a1's coinbase) and
// the new branch does not: after the reorg X is back exactly as it was and
// the old branch's output is gone. Nothing on the new branch re-creates X, so
// the disconnect is the only thing that can. Then the same with a new branch
// that spends X itself.
TEST(LtcUtxoOrder, ReorgRestoresEveryCoinTheOldBranchSpent)
{
    uint256 g;
    g.SetHex("00000000000000000000000000000000000000000000000000000000000000c0");
    const BlockType a1 = make_block(g, 1, {});
    const auto x_tx = a1.m_txs[0];                         // X: 5e9 sat, p2pkh(0xc1), h=1, coinbase
    const Outpoint X(compute_txid(x_tx), 0);
    const BlockType a2 = make_block(hash_of(a1), 2, {spend(X.txid, 0, 4000000000LL, 0x22)});
    const auto y_tx = a2.m_txs[1];                         // Y spends X
    const BlockType b2 = make_chain(hash_of(a1), 2, 1, 0x60)[0];
    BlockType b2s = make_chain(hash_of(a1), 2, 1, 0x61)[0];
    b2s.m_txs.push_back(spend(X.txid, 0, 3000000000LL, 0x33));
    const auto z_tx = b2s.m_txs[1];                        // Z spends X on the new branch
    {
        TempDb t;
        Feed f{*t.cache, *t.db};
        f.set_chain({a1, a2}, 1);
        f.deliver(a1, 1);
        f.deliver(a2, 2);
        ASSERT_EQ(t.cache->get_best_block(), hash_of(a2));
        EXPECT_FALSE(t.cache->have_coin(X)) << "X spent by a2";
        EXPECT_TRUE(has(*t.cache, y_tx));

        f.set_chain({a1, b2}, 1);
        f.reorg(2);
        ASSERT_EQ(t.cache->get_best_block(), hash_of(a1));
        core::coin::Coin c;
        ASSERT_TRUE(t.cache->get_coin(X, c)) << "the coin a2 spent is back";
        EXPECT_TRUE(coin_eq(c, 5000000000LL, p2pkh(0xc1), 1, true, false));
        EXPECT_FALSE(has(*t.cache, y_tx)) << "a2's output is gone";
        core::coin::BlockUndo u;
        EXPECT_FALSE(t.db->get_block_undo(2, u)) << "a2's record goes with the disconnect";

        f.deliver(b2, 2);
        EXPECT_EQ(t.cache->get_best_block(), hash_of(b2));
        EXPECT_TRUE(t.cache->have_coin(X)) << "b2 does not spend X";
        EXPECT_FALSE(has(*t.cache, y_tx));
        EXPECT_TRUE(has(*t.cache, b2.m_txs[0]));
    }
    {
        TempDb t;
        Feed f{*t.cache, *t.db};
        f.set_chain({a1, a2}, 1);
        f.deliver(a1, 1);
        f.deliver(a2, 2);
        f.set_chain({a1, b2s}, 1);
        f.reorg(2);
        f.deliver(b2s, 2);
        EXPECT_EQ(t.cache->get_best_block(), hash_of(b2s));
        EXPECT_FALSE(t.cache->have_coin(X)) << "spent by b2s";
        EXPECT_TRUE(has(*t.cache, z_tx));
        EXPECT_FALSE(has(*t.cache, y_tx));
        core::coin::BlockUndo u;
        ASSERT_TRUE(t.db->get_block_undo(2, u));
        ASSERT_EQ(u.tx_undos.size(), 1u);
        ASSERT_EQ(u.tx_undos[0].spent_coins.size(), 1u);
        EXPECT_TRUE(coin_eq(u.tx_undos[0].spent_coins[0], 5000000000LL, p2pkh(0xc1), 1, true, false))
            << "b2s found X in the view: its record holds the coin, not an unknown one";
    }
}

// Outputs created and spent inside one block (Y and Z; on mainnet every block
// with peg-ins, whose HogEx spends them) end absent after a disconnect, and the
// pre-block coin the block spent is back. Restoring before removing is what
// keeps Y and Z out: the body-based disconnect_block removed first and
// resurrected them.
TEST(LtcUtxoOrder, IntraBlockSpendChainDisconnectsClean)
{
    uint256 g;
    g.SetHex("00000000000000000000000000000000000000000000000000000000000000c1");
    const BlockType a1 = make_block(g, 1, {});
    const Outpoint X(compute_txid(a1.m_txs[0]), 0);
    const auto s1 = spend(X.txid, 0, 4000000000LL, 0x22);                // X -> Y
    const auto s2 = spend(compute_txid(s1), 0, 3000000000LL, 0x23);      // Y -> Z
    const auto s3 = spend(compute_txid(s2), 0, 2000000000LL, 0x24);      // Z -> W
    const BlockType a2 = make_block(hash_of(a1), 2, {s1, s2, s3});
    const BlockType b2 = make_chain(hash_of(a1), 2, 1, 0x60)[0];

    auto expect_a2_undone = [&](core::coin::UTXOViewCache& utxo, const char* path) {
        core::coin::Coin c;
        ASSERT_TRUE(utxo.get_coin(X, c)) << path << ": X back";
        EXPECT_TRUE(coin_eq(c, 5000000000LL, p2pkh(0xc1), 1, true, false)) << path;
        EXPECT_FALSE(has(utxo, s1)) << path << ": Y (created and spent in a2) absent";
        EXPECT_FALSE(has(utxo, s2)) << path << ": Z (created and spent in a2) absent";
        EXPECT_FALSE(has(utxo, s3)) << path << ": W absent";
        EXPECT_FALSE(has(utxo, a2.m_txs[0])) << path << ": a2's coinbase absent";
    };
    {
        // From the record alone (the reorg path).
        TempDb t;
        Feed f{*t.cache, *t.db};
        f.set_chain({a1, a2}, 1);
        f.deliver(a1, 1);
        f.deliver(a2, 2);
        EXPECT_FALSE(t.cache->have_coin(X));
        EXPECT_FALSE(has(*t.cache, s1));
        EXPECT_FALSE(has(*t.cache, s2));
        EXPECT_TRUE(has(*t.cache, s3));
        f.set_chain({a1, b2}, 1);
        f.reorg(2);
        ASSERT_EQ(t.cache->get_best_block(), hash_of(a1));
        expect_a2_undone(*t.cache, "record");
    }
    {
        // With the body (BCH's BlockConnector shape), same block.
        TempDb t;
        t.cache->connect_block(a1, 1, txid_fn);
        const auto undo = t.cache->connect_block(a2, 2, txid_fn);
        ASSERT_TRUE(t.cache->disconnect_block(a2, undo, txid_fn));
        expect_a2_undone(*t.cache, "body");
    }
}

// disconnect_block checks the record against the body before touching
// anything, as Core's DisconnectBlock does (validation.cpp:1787-1790,
// 1814-1817), plus each stored outpoint against the input's prevout. A legacy
// record (no outpoints) takes them from the body.
TEST(LtcUtxoOrder, DisconnectBlockChecksTheRecordAgainstTheBody)
{
    uint256 g;
    g.SetHex("00000000000000000000000000000000000000000000000000000000000000c2");
    const BlockType a1 = make_block(g, 1, {});
    const Outpoint X(compute_txid(a1.m_txs[0]), 0);
    const BlockType a2 = make_block(hash_of(a1), 2, {spend(X.txid, 0, 4000000000LL, 0x22)});
    const auto y_tx = a2.m_txs[1];
    const BlockType b2 = make_chain(hash_of(a1), 2, 1, 0x60)[0];

    TempDb t;
    t.cache->connect_block(a1, 1, txid_fn);
    const auto undo = t.cache->connect_block(a2, 2, txid_fn);
    ASSERT_EQ(undo.tx_undos.size(), 1u);
    ASSERT_EQ(undo.tx_undos[0].spent_outpoints.size(), 1u) << "connect_block records the outpoint";
    auto untouched = [&](const char* what) {
        EXPECT_FALSE(t.cache->have_coin(X)) << what;
        EXPECT_TRUE(has(*t.cache, y_tx)) << what;
        EXPECT_TRUE(has(*t.cache, a2.m_txs[0])) << what;
    };

    EXPECT_FALSE(t.cache->disconnect_block(b2, undo, txid_fn)) << "a2's record, b2's body";
    untouched("another block's body");

    auto wrong_outpoint = undo;
    wrong_outpoint.tx_undos[0].spent_outpoints[0].index = 7;
    EXPECT_FALSE(t.cache->disconnect_block(a2, wrong_outpoint, txid_fn));
    untouched("an outpoint that is not the input's prevout");

    auto short_record = undo;
    short_record.tx_undos[0].spent_coins.clear();
    short_record.tx_undos[0].spent_outpoints.clear();
    EXPECT_FALSE(t.cache->disconnect_block(a2, short_record, txid_fn));
    untouched("one coin short");

    auto legacy = undo;
    legacy.tx_undos[0].spent_outpoints.clear();
    legacy.format = 1;
    ASSERT_FALSE(legacy.restorable());
    EXPECT_TRUE(t.cache->disconnect_block(a2, legacy, txid_fn));
    core::coin::Coin c;
    ASSERT_TRUE(t.cache->get_coin(X, c)) << "the body supplied the outpoint";
    EXPECT_TRUE(coin_eq(c, 5000000000LL, p2pkh(0xc1), 1, true, false));
    EXPECT_FALSE(has(*t.cache, y_tx));
    EXPECT_FALSE(has(*t.cache, a2.m_txs[0]));
}

// The format-2 record, byte by byte (utxo.hpp serialize_block_undo_v2), its
// fail-closed reader, the legacy format next to it, and the UTXOViewDB keys:
// 'R' for format 2, 'U' legacy (read, replaced by a put at the same height,
// removed with it).
TEST(LtcUtxoOrder, V2RecordGoldenBytes)
{
    core::coin::BlockUndo undo;
    undo.block_hash = bytes_from(0x00);
    core::coin::TxUndo tu;
    OPScript spk;
    spk.m_data = p2pkh(0xc1);
    tu.spent_coins.push_back(core::coin::Coin(5000000000LL, spk, 1, true));
    tu.spent_outpoints.push_back(Outpoint(bytes_from(0x20), 0));
    undo.tx_undos.push_back(tu);
    undo.added_outpoints.push_back(Outpoint(bytes_from(0x40), 1));

    const std::string golden =
        "02"                                                                  // version
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"    // block hash
        "01"                                                                  // n_tx
        "01"                                                                  // n_in
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"    // prevout txid
        "00"                                                                  // prevout index
        "03"                                                                  // code: h=1 *2 + coinbase
        "80e497d012"                                                          // value 5000000000
        "19" "76a914c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c188ac"             // script
        "01"                                                                  // n_added
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"    // txid
        "01";                                                                 // index
    const auto bytes = core::coin::serialize_block_undo_v2(undo);
    EXPECT_EQ(HexStr(bytes), golden);

    core::coin::BlockUndo back;
    ASSERT_TRUE(core::coin::deserialize_block_undo_v2(bytes, back));
    EXPECT_EQ(back.format, 2);
    EXPECT_EQ(back.block_hash, undo.block_hash);
    ASSERT_EQ(back.tx_undos.size(), 1u);
    ASSERT_EQ(back.tx_undos[0].spent_outpoints.size(), 1u);
    EXPECT_EQ(back.tx_undos[0].spent_outpoints[0], Outpoint(bytes_from(0x20), 0));
    EXPECT_TRUE(coin_eq(back.tx_undos[0].spent_coins[0], 5000000000LL, p2pkh(0xc1), 1, true, false));
    EXPECT_EQ(back.added_outpoints, undo.added_outpoints);
    EXPECT_TRUE(back.restorable());

    // Fail closed: every truncation, a trailing byte, another version.
    for (size_t n = 0; n < bytes.size(); ++n) {
        core::coin::BlockUndo cut;
        EXPECT_FALSE(core::coin::deserialize_block_undo_v2(bytes.data(), n, cut)) << "prefix " << n;
    }
    auto longer = bytes;
    longer.push_back(0x00);
    EXPECT_FALSE(core::coin::deserialize_block_undo_v2(longer, back));
    auto v3 = bytes;
    v3[0] = 0x03;
    EXPECT_FALSE(core::coin::deserialize_block_undo_v2(v3, back));

    // A record without outpoints is never written as format 2.
    auto no_outpoints = undo;
    no_outpoints.tx_undos[0].spent_outpoints.clear();
    EXPECT_TRUE(core::coin::serialize_block_undo_v2(no_outpoints).empty());

    // The legacy bytes of the same record: no outpoints, cannot restore.
    core::coin::BlockUndo legacy;
    ASSERT_TRUE(core::coin::deserialize_block_undo(core::coin::serialize_block_undo(undo), legacy));
    EXPECT_EQ(legacy.format, 1);
    EXPECT_TRUE(legacy.block_hash.IsNull());
    EXPECT_TRUE(legacy.tx_undos[0].spent_outpoints.empty());
    EXPECT_EQ(legacy.unrestorable_coins(), 1u);
    EXPECT_FALSE(legacy.restorable());
    // ... unless none of its coins was in the view at connect (nothing to put back).
    auto unknown_only = legacy;
    unknown_only.tx_undos[0].spent_coins[0].clear();
    EXPECT_TRUE(unknown_only.restorable());

    // UTXOViewDB: 'R' format 2, 'U' legacy.
    TempDb t;
    core::coin::BlockUndo got;
    ASSERT_TRUE(t.db->put_block_undo(5, undo));
    ASSERT_TRUE(t.db->get_block_undo(5, got));
    EXPECT_EQ(got.format, 2);
    EXPECT_EQ(core::coin::serialize_block_undo_v2(got), bytes);
    EXPECT_FALSE(t.db->put_block_undo(6, no_outpoints)) << "nothing written";
    EXPECT_FALSE(t.db->get_block_undo(6, got));

    ASSERT_TRUE(t.db->put_block_undo_legacy(5, undo));
    ASSERT_TRUE(t.db->get_block_undo(5, got));
    EXPECT_EQ(got.format, 1);
    EXPECT_FALSE(got.restorable());
    EXPECT_EQ(t.db->count_legacy_undo(0, 10), 1u);
    ASSERT_TRUE(t.db->put_block_undo(5, undo)) << "a reconnect at 5";
    ASSERT_TRUE(t.db->get_block_undo(5, got));
    EXPECT_EQ(got.format, 2);
    EXPECT_EQ(t.db->count_legacy_undo(0, 10), 0u) << "no stale legacy record left behind";

    ASSERT_TRUE(t.db->put_block_undo_legacy(7, undo));
    ASSERT_TRUE(t.db->remove_block_undo(5));
    ASSERT_TRUE(t.db->remove_block_undo(7));
    EXPECT_FALSE(t.db->get_block_undo(5, got));
    EXPECT_FALSE(t.db->get_block_undo(7, got)) << "remove drops the legacy record too";

    ASSERT_TRUE(t.db->put_block_undo(8, undo));
    ASSERT_TRUE(t.db->put_block_undo_legacy(9, undo));
    ASSERT_TRUE(t.cache->reanchor());
    EXPECT_FALSE(t.db->get_block_undo(8, got)) << "reset wipes 'R'";
    EXPECT_FALSE(t.db->get_block_undo(9, got)) << "and 'U'";
}

// Mainnet 3199539 -> 3199540 (ltc_utxo_undo_fixtures.hpp), against litecoind's
// own coins: 3199540's HogEx spends 3199539's HogAddr and its tx[4] spends
// tx[3]:1 of the same block. Connect both over a view seeded with every coin
// they spend, check 3199540's record against litecoind's table, disconnect it,
// and the view is exactly what it was after 3199539: every coin 3199540 spent
// is back byte for byte (the HogAddr the new branch's HogEx would spend
// included), every output it created is gone (the intra-block one included).
TEST(LtcUtxoOrder, MainnetBlockPair3199539_3199540DisconnectsByteExact)
{
    namespace fx = ltc_utxo_undo_fixture;
    const BlockType b539 = parse_block(fx::kBlock539Hex);
    const BlockType b540 = parse_block(fx::kBlock540Hex);
    const uint256 hash539 = from_hex(fx::kHash539);
    const uint256 hash540 = from_hex(fx::kHash540);
    ASSERT_EQ(hash_of(b539), hash539);
    ASSERT_EQ(hash_of(b540), hash540);
    ASSERT_EQ(b540.m_previous_block, hash539);
    ASSERT_EQ(b539.m_txs.size(), fx::kTxCount539);
    ASSERT_EQ(b540.m_txs.size(), fx::kTxCount540);
    ASSERT_TRUE(b539.m_txs.back().m_hogEx) << "the P2P form parsed the HogEx flag";
    ASSERT_TRUE(b540.m_txs.back().m_hogEx);
    ASSERT_EQ(compute_txid(b539.m_txs.back()).GetHex(), fx::kHogexTxid539);
    ASSERT_EQ(compute_txid(b540.m_txs.back()).GetHex(), fx::kHogexTxid540);

    auto op_of = [](const fx::SpentCoin& s) { return Outpoint(from_hex(s.prev_txid), s.prev_n); };
    auto spk_of = [](const fx::SpentCoin& s) { return ParseHex(s.spk_hex); };
    auto find_spent = [&](uint32_t block, uint32_t tx_index, uint32_t vin) -> const fx::SpentCoin* {
        for (const auto& s : fx::kSpent)
            if (s.block == block && s.tx_index == tx_index && s.vin == vin)
                return &s;
        return nullptr;
    };
    // The record of `b` at `block` holds, per input, its prevout and litecoind's coin.
    auto expect_record = [&](const core::coin::BlockUndo& u, const BlockType& b, uint32_t block) {
        ASSERT_EQ(u.tx_undos.size() + 1, b.m_txs.size());
        for (size_t i = 1; i < b.m_txs.size(); ++i) {
            const auto& tu = u.tx_undos[i - 1];
            ASSERT_EQ(tu.spent_coins.size(), b.m_txs[i].vin.size()) << "tx " << i;
            ASSERT_TRUE(tu.has_outpoints()) << "tx " << i;
            for (size_t j = 0; j < tu.spent_coins.size(); ++j) {
                const auto* s = find_spent(block, static_cast<uint32_t>(i), static_cast<uint32_t>(j));
                ASSERT_NE(s, nullptr) << block << " tx " << i << " vin " << j;
                EXPECT_EQ(tu.spent_outpoints[j], op_of(*s)) << block << " tx " << i << " vin " << j;
                EXPECT_TRUE(coin_eq(tu.spent_coins[j], s->value, spk_of(*s), s->height, s->coinbase,
                                    s->pegout))
                    << block << " tx " << i << " vin " << j;
            }
        }
    };
    // The outputs connect_block keeps (spendable, non-zero).
    auto outputs_of = [](const BlockType& b) {
        std::vector<Outpoint> out;
        for (const auto& tx : b.m_txs) {
            const uint256 txid = compute_txid(tx);
            for (uint32_t n = 0; n < tx.vout.size(); ++n)
                if (tx.vout[n].value != 0 && !core::coin::is_unspendable(tx.vout[n].scriptPubKey))
                    out.emplace_back(txid, n);
        }
        return out;
    };

    TempDb t;
    auto& utxo = *t.cache;
    size_t seeded = 0;
    for (const auto& s : fx::kSpent) {
        if (s.height >= fx::kHeight539)
            continue;                                   // created by 3199539 / 3199540 themselves
        OPScript spk;
        spk.m_data = spk_of(s);
        utxo.add_coin(op_of(s), core::coin::Coin(s.value, spk, s.height, s.coinbase, s.pegout));
        ++seeded;
    }
    ASSERT_EQ(seeded, 30u) << "11 coins 3199539 spends + 19 older ones 3199540 spends";
    ASSERT_TRUE(utxo.flush(from_hex(fx::kPrev539), fx::kHeight539 - 1));

    // 3199539
    ASSERT_TRUE(t.db->put_block_undo(fx::kHeight539, utxo.connect_block(b539, fx::kHeight539, txid_fn, hash539)));
    ASSERT_TRUE(utxo.flush(hash539, fx::kHeight539));
    for (size_t k = 0; k < fx::kSpentCount539; ++k)
        EXPECT_FALSE(utxo.have_coin(op_of(fx::kSpent[k]))) << "3199539 spent kSpent[" << k << "]";
    const auto out539 = outputs_of(b539);
    for (const auto& op : out539)
        EXPECT_TRUE(utxo.have_coin(op)) << op.txid.GetHex() << ":" << op.index;
    const Outpoint hogaddr539(from_hex(fx::kHogexTxid539), 0);
    {
        core::coin::Coin c;
        ASSERT_TRUE(utxo.get_coin(hogaddr539, c));
        EXPECT_FALSE(c.pegout) << "the HogAddr is not a peg-out (coins.cpp:114-115)";
        core::coin::BlockUndo u539;
        ASSERT_TRUE(t.db->get_block_undo(fx::kHeight539, u539));
        expect_record(u539, b539, fx::kHeight539);
    }
    // The view after 3199539: every outpoint either block touches.
    std::map<Outpoint, std::optional<core::coin::Coin>> snapshot;
    auto take = [&](const Outpoint& op) {
        core::coin::Coin c;
        snapshot[op] = utxo.get_coin(op, c) ? std::optional<core::coin::Coin>(c) : std::nullopt;
    };
    for (const auto& s : fx::kSpent)
        take(op_of(s));
    for (const auto& op : out539)
        take(op);
    const auto out540 = outputs_of(b540);
    for (const auto& op : out540)
        take(op);

    // 3199540
    ASSERT_TRUE(t.db->put_block_undo(fx::kHeight540, utxo.connect_block(b540, fx::kHeight540, txid_fn, hash540)));
    ASSERT_TRUE(utxo.flush(hash540, fx::kHeight540));
    const Outpoint intra(compute_txid(b540.m_txs[3]), 1);
    ASSERT_EQ(b540.m_txs[4].vin[0].prevout.hash, intra.txid);
    ASSERT_EQ(b540.m_txs[4].vin[0].prevout.index, intra.index);
    EXPECT_FALSE(utxo.have_coin(hogaddr539)) << "spent by 3199540's HogEx";
    EXPECT_FALSE(utxo.have_coin(intra)) << "created and spent inside 3199540";
    for (size_t k = fx::kSpentCount539; k < fx::kSpentCount; ++k)
        EXPECT_FALSE(utxo.have_coin(op_of(fx::kSpent[k]))) << "3199540 spent kSpent[" << k << "]";

    core::coin::BlockUndo u540;
    ASSERT_TRUE(t.db->get_block_undo(fx::kHeight540, u540));
    EXPECT_EQ(u540.format, 2);
    EXPECT_EQ(u540.block_hash, hash540);
    ASSERT_EQ(u540.tx_undos.size(), 17u);
    ASSERT_EQ(u540.tx_undos[16].spent_coins.size(), 1u) << "the HogEx: 1 in";
    ASSERT_TRUE(u540.tx_undos[16].has_outpoints());
    EXPECT_EQ(u540.tx_undos[16].spent_outpoints[0], hogaddr539);
    EXPECT_TRUE(coin_eq(u540.tx_undos[16].spent_coins[0], 47102262080748LL,
                        ParseHex("5820737d47fda1ad7fa98c9aaecc2b5b94e9fde203997c3d35db3beb2fb14691dfea"),
                        fx::kHeight539, false, false));
    expect_record(u540, b540, fx::kHeight540);

    // Disconnect 3199540 from its record alone.
    ASSERT_TRUE(utxo.disconnect_from_undo(u540));
    ASSERT_TRUE(utxo.flush(hash539, fx::kHeight539));
    for (size_t k = fx::kSpentCount539; k < fx::kSpentCount; ++k) {
        const auto& s = fx::kSpent[k];
        core::coin::Coin c;
        if (op_of(s) == intra) {
            EXPECT_FALSE(utxo.get_coin(op_of(s), c)) << "the intra-block output stays gone";
            continue;
        }
        ASSERT_TRUE(utxo.get_coin(op_of(s), c)) << "kSpent[" << k << "] back";
        EXPECT_TRUE(coin_eq(c, s.value, spk_of(s), s.height, s.coinbase, s.pegout)) << "kSpent[" << k << "]";
    }
    EXPECT_TRUE(utxo.have_coin(hogaddr539)) << "the new branch's HogEx spends it";
    for (const auto& op : out540)
        EXPECT_FALSE(utxo.have_coin(op)) << "3199540 output " << op.txid.GetHex() << ":" << op.index;
    for (const auto& [op, want] : snapshot) {
        core::coin::Coin c;
        const bool present = utxo.get_coin(op, c);
        ASSERT_EQ(present, want.has_value()) << op.txid.GetHex() << ":" << op.index;
        if (present)
            EXPECT_TRUE(coin_eq(c, want->value, want->scriptPubKey.m_data, want->height, want->coinbase,
                                want->pegout))
                << op.txid.GetHex() << ":" << op.index;
    }
}
