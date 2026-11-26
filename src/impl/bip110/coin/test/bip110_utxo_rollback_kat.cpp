// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_utxo_rollback_kat -- a rollback of c2pool-bip110's own UTXO view that
// fails half-way (bip110::coin::reorg_disconnect_or_discard,
// impl/bip110/coin/utxo_reorg.hpp), over a real core::coin::UTXOViewDB +
// UTXOViewCache and a fake header chain.
//
// The view holds A1 A2 A3 (A2 spends A1's coinbase, A3 spends A2's output).
// The chain reorgs to a branch B that forks below A1; A1's undo record is
// missing, so the rollback undoes A3 and A2 in the cache and then fails at A1.
//
// Proves:
//   [A] reorg_disconnect_or_discard returns the failure and leaves the view as
//       the DB had it: best A3, A3's output unspent, A2's output and A1's coin
//       spent (nothing half-undone).
//   [B] the chain flips back to A and A4 (spending A3's output) connects and
//       is flushed: the DB holds A1..A4's ledger exactly; reopened, the same.
//   [C] the regression witness: with the plain reorg_disconnect_to_fork the
//       same failure leaves A3 and A2 undone in the cache, and A4's flush
//       writes them: A1's coinbase (spent by A2) comes back unspent, A2's and
//       A3's coinbases are gone -- a wrong ledger under a best that names A4.
//
// Pure store test: no node, no network.

#include <impl/bip110/coin/block.hpp>
#include <impl/bip110/coin/header_chain.hpp>
#include <impl/bip110/coin/mempool.hpp>
#include <impl/bip110/coin/template_builder.hpp>
#include <impl/bip110/coin/transaction.hpp>
#include <impl/bip110/coin/utxo_reorg.hpp>

#include <core/coin/utxo.hpp>
#include <core/coin/utxo_view_cache.hpp>
#include <core/coin/utxo_view_db.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <map>
#include <optional>
#include <string>
#include <vector>

using namespace bip110::coin;

namespace {

int g_fail = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { std::printf("FAIL: %s\n", msg); ++g_fail; } \
    else         { std::printf("ok:   %s\n", msg); } \
} while (0)

uint256 txid_of(const MutableTransaction& tx)
{
    auto packed = pack(TX_NO_WITNESS(tx));
    return Hash(packed.get_span());
}

MutableTransaction coinbase(uint32_t tag)
{
    MutableTransaction cb;
    TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xffffffff;
    in.scriptSig.m_data = {0x04, static_cast<unsigned char>(tag & 0xff),
                           static_cast<unsigned char>((tag >> 8) & 0xff), 0x01, 0x02};
    in.sequence = 0xffffffff;
    cb.vin.push_back(in);
    TxOut o;
    o.value = 312500000;
    o.scriptPubKey.m_data = {0x51};
    cb.vout.push_back(o);
    return cb;
}

MutableTransaction spend(const uint256& txid, uint32_t n, int64_t value)
{
    MutableTransaction tx;
    TxIn in;
    in.prevout.hash = txid;
    in.prevout.index = n;
    in.scriptSig.m_data = {0x51};
    in.sequence = 0xfffffffe;
    tx.vin.push_back(in);
    TxOut o;
    o.value = value;
    o.scriptPubKey.m_data = {0x51, 0x51};
    tx.vout.push_back(o);
    return tx;
}

BlockType block(const uint256& prev, uint32_t height, uint32_t tag, std::vector<MutableTransaction> txs)
{
    BlockType b;
    b.m_version = 0x80000000u | 0x20000000u;
    b.m_previous_block = prev;
    b.m_timestamp = 1790000000u + height;
    b.m_bits = 0x1d00ffff;
    b.m_nonce = tag;
    b.m_extranonce.fill(0x33);
    b.m_height = static_cast<int32_t>(height);
    b.m_txs.push_back(coinbase(tag));
    for (auto& tx : txs)
        b.m_txs.push_back(std::move(tx));
    std::vector<uint256> ids;
    for (const auto& tx : b.m_txs)
        ids.push_back(txid_of(tx));
    b.m_merkle_root = compute_merkle_root(ids);
    b.m_txcount = static_cast<uint16_t>(b.m_txs.size());
    return b;
}

/// What reorg_disconnect_to_fork reads of the header chain.
struct FakeChain {
    std::map<uint256, IndexEntry> by_id;
    std::map<uint32_t, uint256>   active;

    void add(const BlockType& b, uint32_t height)
    {
        IndexEntry e;
        e.header = b;
        e.block_hash = block_hash(b);
        e.height = height;
        by_id[e.block_hash] = e;
    }
    std::optional<IndexEntry> get_header(const uint256& h) const
    {
        auto it = by_id.find(h);
        if (it == by_id.end()) return std::nullopt;
        return it->second;
    }
    std::optional<IndexEntry> get_header_by_height(uint32_t h) const
    {
        auto it = active.find(h);
        if (it == active.end()) return std::nullopt;
        return get_header(it->second);
    }
};

bool has_coin(core::coin::UTXOViewCache& cache, const uint256& txid, uint32_t n)
{
    core::coin::Coin c;
    return cache.get_coin(core::coin::Outpoint(txid, n), c);
}

bool connect(core::coin::UTXOViewCache& cache, core::coin::UTXOViewDB& db, const BlockType& b,
             uint32_t height, bool store_undo)
{
    const uint256 id = block_hash(b);
    auto undo = cache.connect_block(b, height, txid_of, id);
    if (store_undo)
        db.put_block_undo(height, undo);
    return cache.flush(id, height);
}

struct Setup {
    std::string path;
    core::coin::UTXOViewDB db;
    core::coin::UTXOViewCache cache;
    FakeChain chain;
    BlockType a1, a2, a3, a4, b1, b2, b3;
    uint256 c1, o2, o3, o4;   // A1's coinbase, A2's / A3's / A4's spends
    uint256 cb2, cb3;         // A2's / A3's coinbases

    explicit Setup(const std::string& p) : path(p), db(p), cache(&db) {}

    bool build()
    {
        if (!db.open())
            return false;
        uint256 p;
        p.SetHex("00000000000000000000000000000000000000000000000000000000000f0000");
        a1 = block(p, 100, 1, {});
        c1 = txid_of(a1.m_txs[0]);
        a2 = block(block_hash(a1), 101, 2, {spend(c1, 0, 100000)});
        o2 = txid_of(a2.m_txs[1]);
        a3 = block(block_hash(a2), 102, 3, {spend(o2, 0, 90000)});
        o3 = txid_of(a3.m_txs[1]);
        cb2 = txid_of(a2.m_txs[0]);
        cb3 = txid_of(a3.m_txs[0]);
        a4 = block(block_hash(a3), 103, 4, {spend(o3, 0, 80000)});
        o4 = txid_of(a4.m_txs[1]);
        b1 = block(p, 100, 11, {});
        b2 = block(block_hash(b1), 101, 12, {});
        b3 = block(block_hash(b2), 102, 13, {});
        const std::pair<const BlockType*, uint32_t> entries[] = {
            {&a1, 100}, {&a2, 101}, {&a3, 102}, {&a4, 103}, {&b1, 100}, {&b2, 101}, {&b3, 102}};
        for (const auto& [b, h] : entries)
            chain.add(*b, h);
        // A1 without its undo record: the rollback fails there.
        return connect(cache, db, a1, 100, false) && connect(cache, db, a2, 101, true)
            && connect(cache, db, a3, 102, true);
    }

    void follow_b()
    {
        chain.active = {{100, block_hash(b1)}, {101, block_hash(b2)}, {102, block_hash(b3)}};
    }
    void follow_a()
    {
        chain.active = {{100, block_hash(a1)}, {101, block_hash(a2)}, {102, block_hash(a3)},
                        {103, block_hash(a4)}};
    }
};

} // namespace

int run_utxo_rollback_kat()
{
    const std::string base = "/tmp/bip110_utxo_rollback_kat_" + std::to_string(::getpid());

    // ── [A] [B] the failing rollback is dropped; the next connect is clean ────
    {
        Setup s(base + "_discard");
        CHECK(s.build(), "[A] the view holds A1 A2 A3");
        CHECK(has_coin(s.cache, s.o3, 0) && !has_coin(s.cache, s.o2, 0) && !has_coin(s.cache, s.c1, 0),
              "[A] A3's output unspent, A2's output and A1's coinbase spent");
        s.follow_b();
        const auto r = reorg_disconnect_or_discard(s.cache, s.db, s.chain, block_hash(s.b3), 288);
        CHECK(r == ReorgResult::UNDO_MISSING, "[A] the rollback fails at A1 (its undo record is missing)");
        const auto best = s.cache.get_best();
        CHECK(best.first == block_hash(s.a3) && best.second == 102, "[A] the view's best is still A3");
        CHECK(has_coin(s.cache, s.o3, 0) && !has_coin(s.cache, s.o2, 0) && !has_coin(s.cache, s.c1, 0)
                  && has_coin(s.cache, s.cb2, 0) && has_coin(s.cache, s.cb3, 0),
              "[A] nothing half-undone: A3 and A2 are not rolled back in the view");

        // The chain flips back to A before any re-anchor; A4 connects.
        s.follow_a();
        CHECK(connect(s.cache, s.db, s.a4, 103, true), "[B] the chain flips back; A4 connects");
        CHECK(has_coin(s.cache, s.o4, 0) && !has_coin(s.cache, s.o3, 0) && !has_coin(s.cache, s.o2, 0)
                  && !has_coin(s.cache, s.c1, 0) && has_coin(s.cache, s.cb2, 0)
                  && has_coin(s.cache, s.cb3, 0) && s.cache.get_best().first == block_hash(s.a4),
              "[B] the DB holds the A1..A4 ledger exactly");
        core::coin::UTXOViewCache reopened(&s.db);
        CHECK(has_coin(reopened, s.o4, 0) && !has_coin(reopened, s.o3, 0) && !has_coin(reopened, s.o2, 0)
                  && !has_coin(reopened, s.c1, 0) && has_coin(reopened, s.cb2, 0)
                  && has_coin(reopened, s.cb3, 0),
              "[B] read back through a new cache: the same");
    }

    // ── [C] the regression witness: the plain rollback ───────────────────────
    {
        Setup s(base + "_plain");
        CHECK(s.build(), "[C] the view holds A1 A2 A3");
        s.follow_b();
        const auto r = reorg_disconnect_to_fork(s.cache, s.db, s.chain, block_hash(s.b3), 288);
        CHECK(r == ReorgResult::UNDO_MISSING, "[C] the plain rollback fails at A1 too");
        CHECK(has_coin(s.cache, s.c1, 0) && !has_coin(s.cache, s.o3, 0) && !has_coin(s.cache, s.cb3, 0),
              "[C] ... and leaves A3 and A2 undone in the cache");
        s.follow_a();
        connect(s.cache, s.db, s.a4, 103, true);
        core::coin::UTXOViewCache reopened(&s.db);
        CHECK(has_coin(reopened, s.c1, 0) && !has_coin(reopened, s.cb2, 0) && !has_coin(reopened, s.cb3, 0)
                  && reopened.get_best().first == block_hash(s.a4),
              "[C] A4's flush writes them: A1's coinbase back unspent, A2's and A3's gone (why the drop)");
    }

    std::printf("%s\n", g_fail == 0 ? "bip110_utxo_rollback_kat PASS" : "bip110_utxo_rollback_kat FAIL");
    return g_fail;
}
