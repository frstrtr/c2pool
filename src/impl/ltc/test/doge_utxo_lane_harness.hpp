// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// The DOGE UTXO lane harness, shared by doge_utxo_lane_test.cpp (accrual
// lane) and doge_utxo_full_test.cpp (full set): a REAL UTXOViewCache /
// UTXOViewDB (LevelDB in a temp dir), a map standing in for the DOGE header
// chain (the best chain by height, every header's parent) that records the
// heights the lane asks for, and the full-block / tip-change handlers as
// main_ltc.cpp calls them (Lane::deliver, Lane::switch_to).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <ctime>
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
#include <impl/doge/coin/chain_params.hpp>
#include <impl/doge/coin/header_chain.hpp>
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

/// A coin of `value` at `height`, paying p2pkh(tag).
core::coin::Coin coin_of(int64_t value, uint32_t height, bool is_coinbase, uint8_t tag = 0x41)
{
    core::coin::Coin c;
    c.value = value;
    c.scriptPubKey.m_data = p2pkh(tag);
    c.height = height;
    c.coinbase = is_coinbase;
    return c;
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
/// selects them (same call, same weight budget).
std::vector<uint256> template_txids(const Mempool& pool)
{
    const auto sel = pool.get_sorted_txs_with_fees(
        doge::coin::TemplateBuilder::MAX_BLOCK_WEIGHT - doge::coin::TemplateBuilder::COINBASE_RESERVE);
    std::vector<uint256> out;
    for (const auto& s : sel.first)
        out.push_back(compute_txid(s.tx));
    return out;
}

bool contains(const std::vector<uint256>& v, const uint256& x)
{
    return std::find(v.begin(), v.end(), x) != v.end();
}

/// A DOGE header chain whose tip is `tip` at `height`, rooted at a
/// checkpoint on its parent: what TemplateBuilder::build_template and
/// EmbeddedCoinNode read. testnet4alpha's parameters: AuxPoW from genesis,
/// so a test header is taken at any height (no scrypt PoW on it).
struct DogeTip {
    doge::coin::DOGEChainParams params = doge::coin::DOGEChainParams::testnet4alpha();
    doge::coin::HeaderChain chain{params};
    BlockType body;  // the tip's block (header only unless given one)

    DogeTip(const BlockType& tip, uint32_t height)
        : body(tip)
    {
        chain.set_dynamic_checkpoint(height - 1, tip.m_previous_block);
        EXPECT_TRUE(chain.add_header(static_cast<const BlockHeaderType&>(tip)));
        EXPECT_EQ(chain.height(), height);
    }

    /// A header-only tip at `height`, `age` seconds old.
    static BlockType header_at(uint32_t height, uint32_t age = 60)
    {
        BlockType b;
        b.m_version = 0x00620104;
        b.m_previous_block = genesis(static_cast<uint8_t>(height));
        b.m_timestamp = static_cast<uint32_t>(std::time(nullptr)) - age;
        b.m_bits = 0x1a01d2c3;
        b.m_nonce = height;
        return b;
    }

    uint256 hash() const { return hash_of(body); }
    uint32_t height() const { return chain.height(); }

    /// The tip's body ran through the pool's cleanup (the template builds).
    void clean(Mempool& pool) const { pool.remove_for_block(body); }

    nlohmann::json build(const Mempool& pool) const
    {
        auto wd = doge::coin::TemplateBuilder::build_template(chain, pool, params);
        EXPECT_TRUE(wd.has_value());
        return wd ? wd->m_data : nlohmann::json();
    }

    int64_t subsidy() const
    {
        return static_cast<int64_t>(doge::coin::get_doge_block_subsidy(height() + 1, params, hash()));
    }
};

} // namespace
