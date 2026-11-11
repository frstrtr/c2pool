// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ---------------------------------------------------------------------------
// Shared fixture of the hybrid MWEB extension KATs (#2137 S3): a REAL
// mainnet tip (block 3200604 on a fast-start checkpoint at 3200603) with its
// MWEB state fed to a REAL MWEBTracker, a UTXO view over a REAL DB whose
// best block is moved with flush(), a pool priced against it, and the dump
// of a template that the none-mode KAT compares byte for byte with the
// template the S0+S1 head (6edb9326b) built from the same fixture.
//
// Only APIs that the S0+S1 head already had are used here, so the same file
// compiles against both trees: none_mode_dump() is the template that head's
// TemplateBuilder builds, and the KAT pins this tree's to it.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <vector>

#include <core/uint256.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/coin/utxo.hpp>
#include <core/coin/utxo_view_cache.hpp>
#include <core/coin/utxo_view_db.hpp>
#include <btclibs/util/strencodings.h>

#include <impl/ltc/coin/header_chain.hpp>
#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/mweb_builder.hpp>
#include <impl/ltc/coin/template_builder.hpp>

#include <nlohmann/json.hpp>

#include "ltc_mweb_ext_fixtures.hpp"
#include "ltc_mweb_tx_fixtures.hpp"

namespace ltc_mweb_ext_test {

using namespace ltc::coin;
namespace xf = ltc_mweb_ext_fixture;
namespace tf = ltc_mweb_tx_fixture;

inline std::vector<unsigned char> bytes_of(const std::string& hex)
{
    return ParseHex(hex);
}

inline std::string hex_of(const std::vector<unsigned char>& b)
{
    return HexStr(std::span<const unsigned char>(b.data(), b.size()));
}

inline uint256 u256(const char* hex)
{
    uint256 v;
    v.SetHex(hex);
    return v;
}

inline uint256 hash_of(const BlockHeaderType& h)
{
    return Hash(pack(h).get_span());
}

inline BlockHeaderType header_from_hex(const char* hex)
{
    auto b = bytes_of(hex);
    PackStream ps(b);
    BlockHeaderType h;
    ps >> h;
    return h;
}

inline MutableTransaction tx_from_hex(const std::string& hex)
{
    auto b = bytes_of(hex);
    PackStream ps(b);
    MutableTransaction tx;
    ps >> TX_WITH_WITNESS(tx);
    return tx;
}

inline std::string tx_hex(const MutableTransaction& tx)
{
    auto p = pack(TX_WITH_WITNESS(tx));
    return HexStr(p.get_span());
}

/// A mainnet chain whose tip is the real block 3200604: a fast-start
/// checkpoint at 3200603, then the real header (real PoW).
inline std::unique_ptr<HeaderChain> chain_at_3200604()
{
    auto p = make_ltc_chain_params_mainnet();
    LTCChainParams::Checkpoint cp;
    cp.height = xf::kHeight3200604 - 1;
    cp.hash.SetHex(xf::kHash3200603);
    p.fast_start_checkpoint = cp;
    auto chain = std::make_unique<HeaderChain>(p);
    chain->init();
    chain->add_header(header_from_hex(xf::kHeader3200604Hex));
    return chain;
}

/// A block MWEBTracker::update accepts: the real header, a coinbase, the
/// block's real HogEx and its real mw::Block (the tracker checks the HogEx
/// commitment, not the Merkle root).
inline BlockType state_block(const char* header_hex, const char* hogex_hex, const char* mweb_raw_hex)
{
    BlockType b;
    static_cast<BlockHeaderType&>(b) = header_from_hex(header_hex);
    MutableTransaction cb;
    cb.version = 1;
    cb.locktime = 0;
    TxIn cin;
    cin.prevout.hash.SetNull();
    cin.prevout.index = 0xffffffff;
    cin.sequence = 0xffffffff;
    cb.vin.push_back(cin);
    TxOut cb_out;
    cb_out.value = 625000000;
    cb_out.scriptPubKey.m_data = {0x51};
    cb.vout.push_back(cb_out);
    b.m_txs = {cb, tx_from_hex(hogex_hex)};
    b.m_mweb_raw = bytes_of(mweb_raw_hex);
    return b;
}

/// The tip 3200604's MWEB state, from its real HogEx and mw::Block.
inline bool feed_3200604(MWEBTracker& tracker)
{
    const BlockType b = state_block(xf::kHeader3200604Hex, tf::kBlock3200604HogexHex, tf::kBlock3200604MwebRawHex);
    return tracker.update(b, xf::kHeight3200604, b.m_mweb_raw);
}

/// A UTXO view over a real DB in a temp dir; its best block is moved with
/// flush().
struct View {
    std::filesystem::path dir;
    std::unique_ptr<core::coin::UTXOViewDB> db;
    std::unique_ptr<core::coin::UTXOViewCache> cache;
    View()
    {
        std::mt19937_64 rng(std::random_device{}());
        dir = std::filesystem::temp_directory_path() / ("ltc_mweb_ext_" + std::to_string(rng()));
        std::filesystem::create_directories(dir);
        db = std::make_unique<core::coin::UTXOViewDB>(dir.string());
        db->open();
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
    bool best(const uint256& hash, uint32_t height) { return cache->flush(hash, height); }
};

/// One input, one OP_TRUE output; `tag` goes into the locktime-free
/// scriptSig so equal spends of different outpoints differ.
inline MutableTransaction spend(const uint256& txid, uint32_t index, int64_t out_value, uint8_t tag = 0)
{
    MutableTransaction tx;
    tx.version = 2;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash = txid;
    in.prevout.index = index;
    in.sequence = 0xffffffff;
    in.scriptSig.m_data = {0x01, tag};
    tx.vin.push_back(in);
    TxOut out;
    out.value = out_value;
    out.scriptPubKey.m_data = {0x51};
    tx.vout.push_back(out);
    return tx;
}

inline void clean_for(Mempool& pool, const BlockHeaderType& hdr)
{
    BlockType b;
    static_cast<BlockHeaderType&>(b) = hdr;
    pool.remove_for_block(b);
}

// Funding outpoints the view holds (no pool tx funds them).
inline uint256 fund(uint8_t n)
{
    uint256 v;
    v.SetNull();
    v.data()[0] = 0xf0;
    v.data()[1] = n;
    return v;
}

/// The pool of the none-mode KAT: four txs priced against `view` at
/// admission -- two independent ones, and a parent with a CPFP child.
inline void fill_pool(Mempool& pool, View& view)
{
    view.add(fund(1), 0, 100'000);
    view.add(fund(2), 0, 200'000);
    view.add(fund(3), 0, 300'000);
    pool.set_utxo(view.cache.get());
    const MutableTransaction t1 = spend(fund(1), 0, 99'000, 1);       // fee 1,000
    const MutableTransaction t2 = spend(fund(2), 0, 190'000, 2);      // fee 10,000
    const MutableTransaction p = spend(fund(3), 0, 299'500, 3);       // fee 500
    const MutableTransaction c = spend(compute_txid(p), 0, 290'000, 4);  // fee 9,500
    pool.admit(t1, view.cache.get());
    pool.admit(t2, view.cache.get());
    pool.admit(p, view.cache.get());
    pool.admit(c, view.cache.get());
}

/// A template as bytes: its json without curtime (the wall clock), and the
/// txid list the stratum merkle branches are built from.
inline std::string template_dump(const rpc::WorkData& wd)
{
    nlohmann::json d = wd.m_data;
    d.erase("curtime");
    nlohmann::json hashes = nlohmann::json::array();
    for (const auto& h : wd.m_hashes)
        hashes.push_back(h.GetHex());
    d["__hashes"] = std::move(hashes);
    return d.dump();
}

/// The none-mode reference: the templates the builder makes from this
/// fixture on the real tip 3200604 -- the full template (the pool's four
/// txs and the HogEx), the same with a budget that takes two txs, the
/// empty template on the tip with the view one block behind, and the
/// refused template without the tip's MWEB state.
inline std::string none_mode_dump()
{
    auto chain = chain_at_3200604();
    MWEBTracker tracker;
    feed_3200604(tracker);
    const BlockHeaderType tip_hdr = header_from_hex(xf::kHeader3200604Hex);
    std::string out;
    {
        View view;
        Mempool pool;
        fill_pool(pool, view);
        view.best(hash_of(tip_hdr), xf::kHeight3200604);
        clean_for(pool, tip_hdr);
        std::optional<rpc::WorkData> refused;
        auto full = TemplateBuilder::build_template(*chain, pool, false, &tracker,
                                                    TemplateBuilder::MAX_BLOCK_WEIGHT - TemplateBuilder::COINBASE_RESERVE,
                                                    &refused);
        out += "full:" + (full ? template_dump(*full) : std::string("none")) + "\n";
        auto small = TemplateBuilder::build_template(*chain, pool, false, &tracker, 900, &refused);
        out += "budget:" + (small ? template_dump(*small) : std::string("none")) + "\n";
        view.best(u256(xf::kHash3200603), xf::kHeight3200604 - 1);
        auto behind = TemplateBuilder::build_template(*chain, pool, false, &tracker,
                                                      TemplateBuilder::MAX_BLOCK_WEIGHT - TemplateBuilder::COINBASE_RESERVE,
                                                      &refused);
        out += "behind:" + (behind ? template_dump(*behind) : std::string("none")) + "\n";
    }
    {
        View view;
        Mempool pool;
        fill_pool(pool, view);
        view.best(hash_of(tip_hdr), xf::kHeight3200604);
        clean_for(pool, tip_hdr);
        MWEBTracker no_state;
        std::optional<rpc::WorkData> refused;
        auto held = TemplateBuilder::build_template(*chain, pool, false, &no_state,
                                                    TemplateBuilder::MAX_BLOCK_WEIGHT - TemplateBuilder::COINBASE_RESERVE,
                                                    &refused);
        out += "nostate:" + std::string(held ? "built" : "refused") + ":"
             + (refused ? template_dump(*refused) : std::string("none")) + "\n";
    }
    return out;
}

} // namespace ltc_mweb_ext_test
