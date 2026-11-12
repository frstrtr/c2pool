// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The HogAddr (HogEx output 0) is spent by the next block's HogEx, as its
// vin[0]; no other tx of a valid block spends it (litecoind ConnectBlock:
// invalid-hogex-input, and the double spend bad-txns-inputs-missingorspent).
// Pinned over a REAL HeaderChain (the real tip 3200604 on a checkpoint), a
// REAL MWEBTracker fed the tip's real HogEx and mw::Block, a REAL Mempool
// and UTXOViewCache/UTXOViewDB (rides share_test; #2137):
//   - the template's selection starts with the HogEx's inputs spent: a pool
//     tx spending the tip's HogAddr is never selected, whether the view
//     holds that coin with its HogAddr script or not;
//   - the selection never spends a HogAddr coin, and a seeded outpoint is
//     never spent again;
//   - admission refuses a tx with a HogAddr input (hogaddr_spend), counted;
//     paying to a HogAddr-shaped script and spending an ordinary coin are
//     admitted as before.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include <core/uint256.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/coin/mweb_shape.hpp>
#include <core/coin/template_txs_check.hpp>
#include <core/coin/utxo.hpp>
#include <core/coin/utxo_view_cache.hpp>
#include <core/coin/utxo_view_db.hpp>
#include <btclibs/util/strencodings.h>

#include <impl/ltc/coin/header_chain.hpp>
#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/mweb_builder.hpp>
#include <impl/ltc/coin/template_builder.hpp>

#include "ltc_mweb_ext_fixtures.hpp"
#include "ltc_mweb_tx_fixtures.hpp"

namespace {

using namespace ltc::coin;
namespace xf = ltc_mweb_ext_fixture;
namespace tf = ltc_mweb_tx_fixture;
using Outpoint = std::pair<uint256, uint32_t>;

uint256 u256(const char* hex)
{
    uint256 v;
    v.SetHex(hex);
    return v;
}

BlockHeaderType header_from_hex(const char* hex)
{
    auto b = ParseHex(hex);
    PackStream ps(b);
    BlockHeaderType h;
    ps >> h;
    return h;
}

MutableTransaction tx_from_hex(const std::string& hex)
{
    auto b = ParseHex(hex);
    PackStream ps(b);
    MutableTransaction tx;
    ps >> TX_WITH_WITNESS(tx);
    return tx;
}

uint256 hash_of(const BlockHeaderType& h)
{
    return Hash(pack(h).get_span());
}

// The real tip 3200604: a fast-start checkpoint at 3200603, then the real
// header (real PoW).
std::unique_ptr<HeaderChain> chain_at_3200604()
{
    auto p = make_ltc_chain_params_mainnet();
    LTCChainParams::Checkpoint cp;
    cp.height = xf::kHeight3200604 - 1;
    cp.hash.SetHex(xf::kHash3200603);
    p.fast_start_checkpoint = cp;
    auto chain = std::make_unique<HeaderChain>(p);
    EXPECT_TRUE(chain->init());
    EXPECT_TRUE(chain->add_header(header_from_hex(xf::kHeader3200604Hex)));
    return chain;
}

// The tip's MWEB state, from its real HogEx and mw::Block.
void feed_3200604(MWEBTracker& tracker)
{
    BlockType b;
    static_cast<BlockHeaderType&>(b) = header_from_hex(xf::kHeader3200604Hex);
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
    b.m_txs = {cb, tx_from_hex(tf::kBlock3200604HogexHex)};
    b.m_mweb_raw = ParseHex(tf::kBlock3200604MwebRawHex);
    ASSERT_TRUE(tracker.update(b, xf::kHeight3200604, b.m_mweb_raw));
}

// A UTXO view over a real DB in a temp dir; its best block is moved with
// flush().
struct View {
    std::filesystem::path dir;
    std::unique_ptr<core::coin::UTXOViewDB> db;
    std::unique_ptr<core::coin::UTXOViewCache> cache;
    View()
    {
        std::mt19937_64 rng(std::random_device{}());
        dir = std::filesystem::temp_directory_path() / ("ltc_hogaddr_guard_" + std::to_string(rng()));
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
    void add(const uint256& txid, uint32_t index, int64_t value, std::vector<unsigned char> spk = {0x51})
    {
        core::coin::Coin coin;
        coin.value = value;
        coin.scriptPubKey.m_data = std::move(spk);
        coin.height = 1;
        cache->add_coin(core::coin::Outpoint(txid, index), coin);
    }
};

uint256 fund(uint8_t n)
{
    uint256 v;
    v.SetNull();
    v.data()[0] = 0xf0;
    v.data()[1] = n;
    return v;
}

MutableTransaction spend(const uint256& txid, uint32_t index, int64_t out_value, uint8_t tag)
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

void clean_for(Mempool& pool, const BlockHeaderType& hdr)
{
    BlockType b;
    static_cast<BlockHeaderType&>(b) = hdr;
    pool.remove_for_block(b);
}

// No outpoint is spent by two txs of the template (the HogEx included).
bool spends_each_outpoint_once(const nlohmann::json& tmpl)
{
    std::set<Outpoint> spent;
    for (const auto& e : tmpl["transactions"]) {
        auto t = core::coin::walk_tx_hex(e["data"].get<std::string>());
        if (!t)
            return false;
        for (const auto& op : t->prevouts)
            if (!spent.insert(op).second)
                return false;
    }
    return true;
}

bool carries(const nlohmann::json& tmpl, const MutableTransaction& tx)
{
    for (const auto& e : tmpl["transactions"])
        if (e["txid"].get<std::string>() == compute_txid(tx).GetHex())
            return true;
    return false;
}

} // namespace

// The template's HogEx spends the tip's HogEx output 0; the selection
// starts with it spent, so a pool tx spending it never rides along -- with
// the coin in the view under its HogAddr script, and under any other
// script (the reservation alone).
TEST(LtcHogaddrSpendGuard, SelectionReservesTheHogexInputs)
{
    auto chain = chain_at_3200604();
    MWEBTracker tracker;
    feed_3200604(tracker);
    const auto st = tracker.get_state();
    ASSERT_TRUE(st);
    const BlockHeaderType tip = header_from_hex(xf::kHeader3200604Hex);
    const auto hogaddr_spk = tx_from_hex(tf::kBlock3200604HogexHex).vout[0].scriptPubKey.m_data;

    for (bool real_script : {true, false}) {
        View view;
        Mempool pool;
        pool.set_utxo(view.cache.get());
        view.add(st->prev_hogex_txid, 0, st->hogaddr_value,
                 real_script ? hogaddr_spk : std::vector<unsigned char>{0x51});
        view.add(fund(1), 0, 100'000);
        ASSERT_TRUE(view.cache->flush(hash_of(tip), xf::kHeight3200604));
        clean_for(pool, tip);

        // Past admission (which refuses the HogAddr spend), priced from the view.
        const MutableTransaction x = spend(st->prev_hogex_txid, 0, st->hogaddr_value - 1'000'000, 1);
        ASSERT_TRUE(pool.add_tx_unchecked(x, view.cache.get()));
        ASSERT_TRUE(pool.get_entry(compute_txid(x))->fee_known);
        const MutableTransaction a = spend(fund(1), 0, 99'000, 2);
        ASSERT_FALSE(pool.admit(a, view.cache.get()));

        std::optional<rpc::WorkData> refused;
        auto wd = TemplateBuilder::build_template(*chain, pool, false, &tracker,
                                                  TemplateBuilder::MAX_BLOCK_WEIGHT - TemplateBuilder::COINBASE_RESERVE,
                                                  &refused);
        ASSERT_TRUE(wd) << "real_script=" << real_script;
        const auto& d = wd->m_data;
        EXPECT_FALSE(carries(d, x)) << "real_script=" << real_script;
        EXPECT_TRUE(carries(d, a)) << "real_script=" << real_script;
        ASSERT_EQ(d["transactions"].size(), 2u) << "the ordinary tx and the HogEx";
        ASSERT_TRUE(core::coin::tx_hex_is_hogex(d["transactions"].back()["data"].get<std::string>()));
        ASSERT_FALSE(wd->m_txs.empty());
        EXPECT_EQ(wd->m_txs.back().vin[0].prevout.hash, st->prev_hogex_txid) << "the HogEx is its only spender";
        EXPECT_EQ(wd->m_txs.back().vin[0].prevout.index, 0u);
        EXPECT_TRUE(spends_each_outpoint_once(d)) << "real_script=" << real_script;
        EXPECT_FALSE(core::coin::check_template_txs(d));
        EXPECT_EQ(d["coinbasevalue"].get<int64_t>(), static_cast<int64_t>(get_block_subsidy(xf::kHeight3200604 + 1)) + 1'000)
            << "only the ordinary tx's fee";
    }
}

// The selection itself: a seeded outpoint is never spent again, a seeded
// txid is never selected again, and a HogAddr coin is never spent.
TEST(LtcHogaddrSpendGuard, SelectionSeedAndHogaddrCoins)
{
    View view;
    Mempool pool;
    pool.set_utxo(view.cache.get());
    std::vector<unsigned char> hogaddr_spk(34, 0x5c);
    hogaddr_spk[0] = 0x58;
    hogaddr_spk[1] = 0x20;
    view.add(fund(1), 0, 100'000);
    view.add(fund(2), 0, 100'000);
    view.add(fund(3), 0, 100'000, hogaddr_spk);
    const MutableTransaction a = spend(fund(1), 0, 99'000, 1);
    const MutableTransaction b = spend(fund(2), 0, 98'000, 2);
    const MutableTransaction h = spend(fund(3), 0, 97'000, 3);
    ASSERT_FALSE(pool.admit(a, view.cache.get()));
    ASSERT_FALSE(pool.admit(b, view.cache.get()));
    ASSERT_TRUE(pool.add_tx_unchecked(h, view.cache.get()));

    auto ids = [](const std::vector<Mempool::SelectedTx>& sel) {
        std::set<uint256> s;
        for (const auto& t : sel)
            s.insert(compute_txid(t.tx));
        return s;
    };
    auto [all, fees] = pool.get_sorted_txs_with_fees(4'000'000);
    EXPECT_EQ(ids(all), (std::set<uint256>{compute_txid(a), compute_txid(b)})) << "never the HogAddr spend";
    EXPECT_EQ(fees, 3'000u);

    Mempool::SelectionSeed seed;
    seed.consumed.emplace(fund(2), 0);
    seed.in_template.insert(compute_txid(a));
    auto [rest, rest_fees] = pool.get_sorted_txs_with_fees(4'000'000, &seed);
    EXPECT_TRUE(rest.empty()) << "a is in the template already, b's input is spent by it";
    EXPECT_EQ(rest_fees, 0u);
}

// Admission refuses a tx with a HogAddr input of the view: hogaddr_spend,
// counted, not pooled. Paying to a HogAddr-shaped script, and spending an
// ordinary coin, are admitted as before.
TEST(LtcHogaddrSpendGuard, AdmissionRefusesAHogaddrSpend)
{
    MWEBTracker tracker;
    feed_3200604(tracker);
    const auto st = tracker.get_state();
    ASSERT_TRUE(st);
    const auto hogaddr_spk = tx_from_hex(tf::kBlock3200604HogexHex).vout[0].scriptPubKey.m_data;

    View view;
    Mempool pool;
    pool.set_utxo(view.cache.get());
    view.add(st->prev_hogex_txid, 0, st->hogaddr_value, hogaddr_spk);
    view.add(fund(1), 0, 100'000);

    const MutableTransaction x = spend(st->prev_hogex_txid, 0, st->hogaddr_value - 1'000'000, 1);
    auto r = pool.admit(x, view.cache.get());
    ASSERT_TRUE(r);
    EXPECT_EQ(r->code, Mempool::Reject::hogaddr_spend);
    EXPECT_FALSE(pool.contains(compute_txid(x)));
    EXPECT_EQ(pool.orphan_count(), 0u);
    // With a second, ordinary input it is refused all the same.
    MutableTransaction x2 = spend(fund(1), 0, 50'000, 2);
    x2.vin.push_back(x.vin[0]);
    r = pool.admit(x2, view.cache.get());
    ASSERT_TRUE(r);
    EXPECT_EQ(r->code, Mempool::Reject::hogaddr_spend);

    const auto j = pool.reject_stats_json();
    EXPECT_EQ(j["rejected"]["hogaddr_spend"], 2);
    EXPECT_EQ(pool.reject_stats().by_code[Mempool::Reject::hogaddr_spend].load(), 2u);

    // Paying to a HogAddr-shaped script is not spending one.
    MutableTransaction pay = spend(fund(1), 0, 90'000, 3);
    pay.vout[0].scriptPubKey.m_data = hogaddr_spk;
    EXPECT_FALSE(pool.admit(pay, view.cache.get()));
    EXPECT_TRUE(pool.contains(compute_txid(pay)));
    EXPECT_EQ(std::string(Mempool::reject_code_name(Mempool::Reject::hogaddr_spend)), "hogaddr_spend");
}
