// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The full LTC UTXO view (#2137 S2; rides share_test). The lane is
// core::coin::UtxoLane in Mode::Full on LTC's parameters, on a REAL
// UTXOViewCache / UTXOViewDB, with the harness's header chain map:
//   - a tx spending block 1's coinbase is priced and selected with the full
//     view (built from genesis); with the accrual view (its last `keep`
//     blocks) it is admitted fee-unknown and never selected; with the full
//     view an input in neither the set nor the pool is an orphan
//     (missing_inputs), the only unpriced kind left;
//   - utxo_stats_ltc (--ltc-utxo-stats) is Litecoin Core 0.21.4's
//     gettxoutsetinfo: hash_serialized_2, transactions, txouts, bogosize and
//     total_amount of a set with a multi-output tx and an OP_RETURN output,
//     recomputed here independently of production code from the coins the
//     chain created;
//   - against litecoind itself: with C2POOL_LTC_REGTEST_UTXO set to a
//     directory holding blocks.hex (one block per line, heights 0..N, from
//     getblock <hash> 0) and gettxoutsetinfo.json (litecoind's at N), the
//     set the full lane builds from those blocks has litecoind's figures.
//     Skipped without it.
// ---------------------------------------------------------------------------

#define C2_LANE_KEEP core::coin::LTC_MIN_BLOCKS_TO_KEEP
#define C2_LANE_LIMITS core::coin::LTC_LIMITS
#define C2_LANE_CHAIN core::coin::LTC_UTXO_LANE

#include "doge_utxo_lane_harness.hpp"

#include <core/coin/utxo_stats.hpp>
#include <core/coin/coin_compressor.hpp>
#include <btclibs/util/strencodings.h>

#include <nlohmann/json.hpp>

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>

namespace {

using Mode = UtxoLane::Mode;

size_t serve_all(UtxoLane& lane, Net& net, const std::vector<BlockType>& chain)
{
    size_t served = 0;
    while (served < net.requested.size()) {
        const uint32_t h = net.requested[served++];
        lane.on_block(chain[h - 1], hash_of(chain[h - 1]), h);
    }
    return served;
}

/// Build the set of `lane` from `chain` (heights 1..n on `g`): the tip's body
/// arms the fill (full: from height 1; accrual: the last `keep`), then every
/// request is answered.
void build(Lane& l, const uint256& g, const std::vector<BlockType>& chain)
{
    l.net.set_chain(chain, 1);
    l.net.best[0] = g;
    const uint32_t n = static_cast<uint32_t>(chain.size());
    l.lane.on_block(chain[n - 1], hash_of(chain[n - 1]), n);
    serve_all(l.lane, l.net, chain);
}

BlockType parse_block_hex(const std::string& hex)
{
    auto bytes = ParseHex(hex);
    PackStream ps(bytes);
    BlockType b;
    ps >> b;
    return b;
}

/// Litecoin Core 0.21.4 node/coinstats.cpp, written out again from the coins
/// a chain's txs created and spent (independent of utxo_stats_ltc and of the
/// UTXO DB): txid -> index -> (value, script, height, coinbase).
struct RefCoin {
    int64_t value;
    std::vector<unsigned char> script;
    uint32_t height;
    bool coinbase;
};
using RefSet = std::map<uint256, std::map<uint32_t, RefCoin>>;

RefSet reference_set(const std::vector<BlockType>& chain)
{
    RefSet set;
    for (size_t i = 0; i < chain.size(); ++i) {
        const uint32_t h = static_cast<uint32_t>(i + 1);
        for (size_t t = 0; t < chain[i].m_txs.size(); ++t) {
            const auto& tx = chain[i].m_txs[t];
            if (t > 0)
                for (const auto& in : tx.vin) {
                    set[in.prevout.hash].erase(in.prevout.index);
                    if (set[in.prevout.hash].empty())
                        set.erase(in.prevout.hash);
                }
            const uint256 id = compute_txid(tx);
            for (uint32_t n = 0; n < tx.vout.size(); ++n) {
                const auto& s = tx.vout[n].scriptPubKey.m_data;
                if (!s.empty() && s[0] == 0x6a)
                    continue;  // OP_RETURN: IsUnspendable, never a coin
                set[id][n] = RefCoin{tx.vout[n].value, s, h, t == 0};
            }
        }
    }
    return set;
}

struct RefStats {
    uint64_t transactions{0}, txouts{0}, bogosize{0};
    uint64_t total{0};
    uint256 hash;
};

RefStats reference_stats(const RefSet& set, const uint256& best)
{
    // The coins DB's order: 'C' + txid's 32 bytes, so the txids bytewise.
    std::vector<uint256> ids;
    for (const auto& [id, outs] : set)
        ids.push_back(id);
    std::sort(ids.begin(), ids.end(), [](const uint256& a, const uint256& b) {
        return std::memcmp(a.data(), b.data(), 32) < 0;
    });
    std::vector<unsigned char> ss(best.data(), best.data() + 32);
    RefStats r;
    for (const auto& id : ids) {
        const auto& outs = set.at(id);
        ss.insert(ss.end(), id.data(), id.data() + 32);
        const auto& first = outs.begin()->second;
        core::coin::WriteVarInt(ss, (first.height * 2 + first.coinbase) ? 1u : 0u);
        ++r.transactions;
        for (const auto& [n, c] : outs) {
            core::coin::WriteVarInt(ss, static_cast<uint64_t>(n) + 1);
            core::coin::WriteCompactSize(ss, c.script.size());
            ss.insert(ss.end(), c.script.begin(), c.script.end());
            core::coin::WriteVarInt(ss, static_cast<uint64_t>(c.value));
            ++r.txouts;
            r.total += static_cast<uint64_t>(c.value);
            r.bogosize += 32 + 4 + 4 + 8 + 2 + c.script.size();
        }
        ss.push_back(0x00);
    }
    r.hash = Hash(std::span<const unsigned char>(ss.data(), ss.size()));
    return r;
}

} // namespace

// A tx spending block 1's coinbase (mature at 101), relayed at the tip 130:
// the accrual view (keep 20: heights 110..130) does not hold the coin, so it
// is admitted fee-unknown and never selected; the full view, built from
// genesis, prices and selects it.
TEST(LtcFullView, ACoinFromBlock1IsPricedAndSelectedWithTheFullView)
{
    constexpr uint32_t N = 130;
    const uint256 g = genesis(0x7a);
    std::vector<BlockType> chain = make_chain(g, 1, N, 0x10);

    Lane full(core::coin::LTC_MIN_BLOCKS_TO_KEEP, Mode::Full, 16);
    build(full, g, chain);
    ASSERT_EQ(full.t.cache->get_best_height(), N);
    EXPECT_EQ(full.t.cache->sync_state().anchor_height, 0u);
    EXPECT_TRUE(full.t.cache->complete(N, hash_of(chain[N - 1])));
    EXPECT_EQ(full.net.completed, 1u);

    Lane acc(20, Mode::Accrual);
    build(acc, g, chain);
    ASSERT_EQ(acc.t.cache->get_best_height(), N);
    ASSERT_FALSE(acc.t.cache->complete(N, hash_of(chain[N - 1])));

    const MutableTransaction& cb1 = chain[0].m_txs[0];
    ASSERT_TRUE(full.has(cb1));
    ASSERT_FALSE(acc.has(cb1)) << "the accrual view starts at " << N - 20;
    const int64_t fee = 1'000'000;
    const MutableTransaction tx = spend(compute_txid(cb1), 0, cb1.vout[0].value - fee, 0xee);

    auto selected = [](const Mempool& pool, const MutableTransaction& t) {
        const auto sel = pool.get_sorted_txs_with_fees(4'000'000);
        for (const auto& s : sel.first)
            if (compute_txid(s.tx) == compute_txid(t))
                return true;
        return false;
    };

    Mempool with_full(core::coin::LTC_LIMITS);
    with_full.set_utxo(full.t.cache.get());
    with_full.set_tip_height(N);
    EXPECT_FALSE(with_full.admit(tx, full.t.cache.get()));
    EXPECT_EQ(with_full.unpriced_count(), 0u) << "priced against the full view";
    EXPECT_TRUE(selected(with_full, tx));
    EXPECT_EQ(with_full.get_sorted_txs_with_fees(4'000'000).second, static_cast<uint64_t>(fee));

    Mempool with_acc(core::coin::LTC_LIMITS);
    with_acc.set_utxo(acc.t.cache.get());
    with_acc.set_tip_height(N);
    EXPECT_FALSE(with_acc.admit(tx, acc.t.cache.get())) << "a partial view admits it fee-unknown";
    EXPECT_EQ(with_acc.unpriced_count(), 1u);
    EXPECT_FALSE(selected(with_acc, tx));

    // With the full view the only unpriced txs are true orphans: an input in
    // neither the set nor the pool is missing_inputs, parked outside the pool.
    uint256 nowhere;
    nowhere.SetHex("00000000000000000000000000000000000000000000000000000000000dead1");
    const auto r = with_full.admit(spend(nowhere, 0, 1'000, 0xef), full.t.cache.get());
    ASSERT_TRUE(r);
    EXPECT_EQ(r->code, Mempool::Reject::missing_inputs);
    EXPECT_EQ(with_full.orphan_count(), 1u);
    EXPECT_EQ(with_full.unpriced_count(), 0u);
}

// --ltc-utxo-stats: Litecoin Core 0.21.4's gettxoutsetinfo of the full set,
// against the same figures computed here from the chain's txs.
TEST(LtcFullView, LtcUtxoStatsIsLitecoindsGettxoutsetinfo)
{
    constexpr uint32_t N = 120;
    const uint256 g = genesis(0x7b);
    std::vector<BlockType> chain;
    uint256 prev = g;
    for (uint32_t h = 1; h <= N; ++h) {
        std::vector<MutableTransaction> extra;
        if (h == 110) {
            // Block 3's coinbase (mature) into three outputs, one of them
            // OP_RETURN (never a coin), and a large script output.
            MutableTransaction t = spend(compute_txid(chain[2].m_txs[0]), 0, 0, 0x31);
            t.vout.clear();
            TxOut a;
            a.value = 400'000'000;
            a.scriptPubKey.m_data = p2pkh(0x41);
            TxOut ret;
            ret.value = 0;
            ret.scriptPubKey.m_data = {0x6a, 0x04, 1, 2, 3, 4};
            TxOut big;
            big.value = 123'456'789;
            big.scriptPubKey.m_data.assign(300, 0x51);
            t.vout = {a, ret, big};
            extra.push_back(t);
        }
        if (h == 115) {
            // Block 4's coinbase, spent whole.
            extra.push_back(spend(compute_txid(chain[3].m_txs[0]), 0, chain[3].m_txs[0].vout[0].value - 5'000, 0x32));
        }
        chain.push_back(make_block(prev, h, static_cast<uint8_t>(h), extra));
        prev = hash_of(chain.back());
    }
    Lane l(core::coin::LTC_MIN_BLOCKS_TO_KEEP, Mode::Full, 16);
    build(l, g, chain);
    ASSERT_EQ(l.t.cache->get_best_height(), N);
    ASSERT_EQ(l.lane.stats().strict_refusals.load(), 0u);

    const auto st = core::coin::utxo_stats_ltc(*l.t.db);
    ASSERT_TRUE(st.ok);
    const RefStats ref = reference_stats(reference_set(chain), hash_of(chain[N - 1]));
    EXPECT_EQ(st.best_height, N);
    EXPECT_EQ(st.best_block, hash_of(chain[N - 1]));
    EXPECT_EQ(st.transactions, ref.transactions);
    EXPECT_EQ(st.txouts, ref.txouts);
    EXPECT_EQ(st.bogosize, ref.bogosize);
    EXPECT_EQ(st.total_amount.hi, 0u);
    EXPECT_EQ(st.total_amount.lo, ref.total);
    EXPECT_EQ(st.hash_serialized, ref.hash);
    EXPECT_EQ(st.unspendable_skipped, 0u);
    // 120 coinbases, less blocks 3 and 4's spent ones, plus two of the three
    // outputs and the whole-coin spend.
    EXPECT_EQ(st.transactions, 120u - 2u + 2u);
    EXPECT_EQ(st.txouts, 120u - 2u + 2u + 1u);
    // The DOGE format (Bitcoin 0.14's per-tx hash) is another hash.
    EXPECT_NE(core::coin::utxo_stats(*l.t.db).hash_serialized, st.hash_serialized);
}

// litecoind's own figures: its regtest chain's blocks into the full lane,
// then gettxoutsetinfo compared field by field.
TEST(LtcFullView, LtcUtxoStatsMatchesLitecoindOnItsChain)
{
    const char* dir = std::getenv("C2POOL_LTC_REGTEST_UTXO");
    if (!dir || !*dir)
        GTEST_SKIP() << "C2POOL_LTC_REGTEST_UTXO not set (a directory with blocks.hex and gettxoutsetinfo.json)";
    std::ifstream bf(std::string(dir) + "/blocks.hex");
    std::ifstream jf(std::string(dir) + "/gettxoutsetinfo.json");
    ASSERT_TRUE(bf && jf);
    std::vector<BlockType> all;
    for (std::string line; std::getline(bf, line);)
        if (!line.empty())
            all.push_back(parse_block_hex(line));
    const nlohmann::json want = nlohmann::json::parse(jf);
    ASSERT_GE(all.size(), 2u);
    const uint32_t n = static_cast<uint32_t>(all.size() - 1);
    ASSERT_EQ(want["height"].get<uint32_t>(), n);

    const uint256 g = hash_of(all[0]);
    const std::vector<BlockType> chain(all.begin() + 1, all.end());
    Lane l(core::coin::LTC_MIN_BLOCKS_TO_KEEP, Mode::Full, 64);
    build(l, g, chain);
    ASSERT_EQ(l.t.cache->get_best_height(), n);
    EXPECT_EQ(l.lane.stats().strict_refusals.load(), 0u);
    EXPECT_EQ(l.lane.stats().bad_bodies.load(), 0u);

    const auto st = core::coin::utxo_stats_ltc(*l.t.db);
    ASSERT_TRUE(st.ok);
    EXPECT_EQ(st.best_block.GetHex(), want["bestblock"].get<std::string>());
    EXPECT_EQ(st.transactions, want["transactions"].get<uint64_t>());
    EXPECT_EQ(st.txouts, want["txouts"].get<uint64_t>());
    EXPECT_EQ(st.bogosize, want["bogosize"].get<uint64_t>());
    EXPECT_EQ(st.hash_serialized.GetHex(), want["hash_serialized_2"].get<std::string>());
    // total_amount: litecoind prints it in coins with 8 decimals.
    const std::string total = core::coin::format_coin_amount(st.total_amount);
    std::ostringstream w;
    w << std::fixed << std::setprecision(8) << want["total_amount"].get<double>();
    EXPECT_EQ(total, w.str());
    std::cout << "[ltc-regtest] h=" << n << " transactions=" << st.transactions << " txouts=" << st.txouts
              << " bogosize=" << st.bogosize << " hash_serialized_2=" << st.hash_serialized.GetHex()
              << " total_amount=" << total << std::endl;
}
