// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The full DOGE UTXO set (rides share_test): built from genesis, strictly
// connected (DESIGN doge-underfill §3.1-§3.3, KATs 1-4).
//
// The canary's DOGE set was a partial "accrual" view born from the last
// 1,440 blocks: a 499-input consolidation spending coins 1-10 days old was
// held fee-unknown and never selected (UNDERFILL, 36.7 DOGE of fees per block
// lost), a restart more than 1,440 blocks behind left a hole, and the mining
// gate counted connected blocks, not what the set holds.
//   1. DeepInputConsolidationIsPricedAndSelected: the lane arms from height 1
//      (requests 1..N in order, within the window), every coin is in the set,
//      the consolidation is priced and in the template.
//   2. RestartBehindByMoreThanKeepConnectsEveryBlock: a restart far behind
//      connects every block from best + 1 (no jump, no hole).
//   3. MiningGateClosedUntilSetComplete: a set not built from genesis keeps
//      the gate closed and the template coinbase-only (utxo-incomplete).
//   4. StrictConnectRefusesUnknownInput: a body spending a coin the set does
//      not hold is refused, the set untouched, the body fetched again; past
//      the refusal bound the set is left as is (heal_failures).
// Plus: zero-value outputs are coins (as in Core), a body that is not what
// its header commits to is refetched, the sync state is written with the best
// block, and the digest (--utxo-digest) pins the set.
// Drives doge::coin::UtxoLane (Mode::Full) through the harness main_ltc's
// handlers mirror (doge_utxo_lane_harness.hpp).
// ---------------------------------------------------------------------------
#include "doge_utxo_lane_harness.hpp"

#include <core/coin/utxo_digest.hpp>

#include <numeric>

namespace {

using Mode = UtxoLane::Mode;

/// Serve the lane's requests in the order it made them (a peer answering
/// every getdata), from `chain` (heights from 1). Returns the most requests
/// ever outstanding at once.
size_t serve(UtxoLane& lane, Net& net, const std::vector<BlockType>& chain, size_t from = 0)
{
    size_t served = from, peak = 0;
    while (served < net.requested.size()) {
        peak = std::max(peak, net.requested.size() - served);
        const uint32_t h = net.requested[served++];
        lane.on_block(chain[h - 1], hash_of(chain[h - 1]), h);
    }
    return peak;
}

bool contains_height(const std::vector<uint32_t>& v, uint32_t h)
{
    return std::find(v.begin(), v.end(), h) != v.end();
}

std::vector<uint32_t> range(uint32_t lo, uint32_t hi)
{
    std::vector<uint32_t> v(hi - lo + 1);
    std::iota(v.begin(), v.end(), lo);
    return v;
}

/// A chain of n blocks on `g`; extra[h] goes into block h.
std::vector<BlockType> chain_with(const uint256& g, uint32_t n,
                                  std::map<uint32_t, std::vector<MutableTransaction>> extra = {})
{
    std::vector<BlockType> c;
    uint256 prev = g;
    for (uint32_t h = 1; h <= n; ++h) {
        c.push_back(make_block(prev, h, static_cast<uint8_t>(h), extra[h]));
        prev = hash_of(c.back());
    }
    return c;
}

} // namespace

// KAT 1. The f2ee8d3b... shape: 499 P2PKH inputs created at heights 3..40
// (round robin over 38 blocks), 1 output, fee 36.6995 DOGE, relayed at the
// tip (60). With keep = 20 the accrual lane armed at 60 - 20 = 40 and never
// asked for 1..39: the coins at 3..39 were unknown, the fee unknown, the tx
// excluded.
TEST(DogeUtxoFull, DeepInputConsolidationIsPricedAndSelected)
{
    constexpr uint32_t KEEP = 20, N = 60, FIRST = 3, LAST = 40, COINS = 499, WINDOW = 16;
    constexpr int64_t FEE = 3'669'950'000LL;
    Lane l(KEEP, Mode::Full, WINDOW);
    const uint256 g = genesis(0x51);

    // Block h in 3..40 carries a funding tx paying the coins c with
    // c % 38 == h - 3, spending the coinbase of block h - 2.
    std::vector<Outpoint> coins(COINS);
    std::vector<int64_t> values(COINS);
    std::vector<BlockType> chain;
    uint256 prev = g;
    for (uint32_t h = 1; h <= N; ++h) {
        std::vector<MutableTransaction> extra;
        if (h >= FIRST && h <= LAST) {
            MutableTransaction f = spend(txid_of(chain[h - 3].m_txs[0]), 0, 0, static_cast<uint8_t>(h));
            f.vout.clear();
            std::vector<uint32_t> paid;
            for (uint32_t c = h - FIRST; c < COINS; c += LAST - FIRST + 1) {
                TxOut out;
                values[c] = 8'800'000'000LL + int64_t(c) * 2'000'000LL;  // 88..98 DOGE
                out.value = values[c];
                out.scriptPubKey.m_data = p2pkh(static_cast<uint8_t>(c));
                f.vout.push_back(out);
                paid.push_back(c);
            }
            for (uint32_t i = 0; i < paid.size(); ++i)
                coins[paid[i]] = Outpoint(txid_of(f), i);
            extra.push_back(f);
        }
        chain.push_back(make_block(prev, h, static_cast<uint8_t>(h), extra));
        prev = hash_of(chain.back());
    }
    l.net.set_chain(chain, 1);
    l.net.best[0] = g;

    // The tip's body arms the fill from height 1, in order, within the window.
    const auto r = l.lane.on_block(chain[N - 1], hash_of(chain[N - 1]), N);
    EXPECT_EQ(r.fed, UtxoLane::Fed::Pipeline);
    ASSERT_TRUE(l.lane.fill().active);
    EXPECT_EQ(l.lane.fill().phase, "IBD");
    EXPECT_EQ(l.net.requested, range(1, WINDOW)) << "armed at 1, not at " << N - KEEP;
    const size_t peak = serve(l.lane, l.net, chain);
    EXPECT_LE(peak, WINDOW) << "more requests in flight than the window";
    EXPECT_EQ(l.net.requested, range(1, N)) << "every height, once, in order";
    EXPECT_FALSE(l.lane.fill().active);
    EXPECT_EQ(l.t.cache->get_best_height(), N);
    EXPECT_EQ(l.net.completed, 1u);
    const auto ss = l.t.cache->sync_state();
    EXPECT_EQ(ss.anchor_height, 0u);
    EXPECT_EQ(ss.strict, 1);
    EXPECT_EQ(ss.synced, 1);
    EXPECT_TRUE(l.t.cache->complete(N));
    for (uint32_t c = 0; c < COINS; ++c)
        ASSERT_TRUE(l.t.cache->have_coin(coins[c])) << "coin " << c << " (created at height "
                                                    << FIRST + c % (LAST - FIRST + 1) << ") not in the set";

    // The consolidation, relayed at the tip.
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    int64_t in = 0;
    for (uint32_t c = 0; c < COINS; ++c) {
        TxIn txin;
        txin.prevout.hash = coins[c].txid;
        txin.prevout.index = coins[c].index;
        txin.scriptSig.m_data.assign(107, 0x30);  // a 71-byte signature and a 33-byte key
        txin.sequence = 0xffffffff;
        tx.vin.push_back(txin);
        in += values[c];
    }
    TxOut out;
    out.value = in - FEE;
    out.scriptPubKey.m_data = p2pkh(0xf2);
    tx.vout.push_back(out);
    const uint256 txid = txid_of(tx);

    DogeTip tip(chain[N - 1], N);
    Mempool pool(core::coin::DOGE_LIMITS);
    pool.set_utxo(l.t.cache.get());
    pool.set_tip_height(N);
    EXPECT_FALSE(pool.admit(tx, l.t.cache.get()).has_value());
    const auto e = pool.get_entry(txid);
    ASSERT_TRUE(e.has_value());
    EXPECT_TRUE(e->fee_known);
    EXPECT_EQ(e->fee, static_cast<uint64_t>(FEE));
    EXPECT_GT(e->base_size, 70'000u) << "the 73 kB shape";

    tip.clean(pool);
    const auto t = tip.build(pool);
    EXPECT_FALSE(t.contains("degraded"));
    ASSERT_EQ(t["transactions"].size(), 1u);
    EXPECT_EQ(t["transactions"][0]["txid"], txid.GetHex());
    EXPECT_EQ(t["transactions"][0]["fee"].get<int64_t>(), FEE);
    EXPECT_EQ(t["coinbasevalue"].get<int64_t>(), tip.subsidy() + FEE);
    const uint64_t selected = t["transactions"][0]["data"].get<std::string>().size() / 2;
    EXPECT_FALSE(doge::coin::TemplateBuilder::underfill(selected, pool.byte_size(), pool.total_fees()));
}

// KAT 2. A set complete at 10 restarts with the chain at 10 + keep + 5. The
// accrual rule jumped to 35 - keep = 15: 11..14 were never connected, coin A
// (created at 5, spent at 13) stayed "unspent", coin B (created at 12)
// was unknown.
TEST(DogeUtxoFull, RestartBehindByMoreThanKeepConnectsEveryBlock)
{
    constexpr uint32_t KEEP = 20, BEST = 10, TIP_H = BEST + KEEP + 5;
    const uint256 g = genesis(0x52);
    // A: block 5 spends block 1's coinbase into A; block 13 spends A.
    // B: block 12 spends block 2's coinbase into B.
    const auto pre = chain_with(g, 2);
    const auto a_tx = spend(txid_of(pre[0].m_txs[0]), 0, DOGE_SUBSIDY - 1000, 0x5a);
    const auto b_tx = spend(txid_of(pre[1].m_txs[0]), 0, DOGE_SUBSIDY - 1000, 0x5b);
    const auto a_spend = spend(txid_of(a_tx), 0, DOGE_SUBSIDY - 2000, 0x5c);
    const auto chain = chain_with(g, TIP_H, {{5, {a_tx}}, {12, {b_tx}}, {13, {a_spend}}});

    TempDb t;
    Net net;
    net.set_chain(std::vector<BlockType>(chain.begin(), chain.begin() + BEST), 1);
    net.best[0] = g;
    {
        UtxoLane lane(*t.cache, *t.db, net.host(), KEEP, Mode::Full, 16);
        lane.on_block(chain[BEST - 1], hash_of(chain[BEST - 1]), BEST);
        serve(lane, net, chain);
        ASSERT_EQ(t.cache->get_best_height(), BEST);
        ASSERT_TRUE(t.cache->complete(BEST));
        ASSERT_TRUE(t.cache->have_coin(Outpoint(txid_of(a_tx), 0)));
    }

    // Restart, the chain now at 35.
    t.reopen();
    ASSERT_EQ(t.cache->get_best_height(), BEST);
    net.set_chain(chain, 1);
    net.best[0] = g;
    net.requested.clear();
    UtxoLane lane(*t.cache, *t.db, net.host(), KEEP, Mode::Full, 16);
    lane.startup();
    lane.on_block(chain[TIP_H - 1], hash_of(chain[TIP_H - 1]), TIP_H);
    serve(lane, net, chain);
    EXPECT_EQ(net.requested, range(BEST + 1, TIP_H)) << "every block from best + 1, in order";
    EXPECT_EQ(t.cache->get_best_height(), TIP_H);
    EXPECT_FALSE(t.cache->have_coin(Outpoint(txid_of(a_tx), 0))) << "A was spent at 13";
    EXPECT_TRUE(t.cache->have_coin(Outpoint(txid_of(b_tx), 0))) << "B was created at 12";
    EXPECT_EQ(t.cache->anchor_height(), 0u);
    EXPECT_TRUE(t.cache->complete(TIP_H));
}

// KAT 3. A DB at best 1,000 holding coins from 900 only. The old gate read
// blocks_connected(), initialised to the DB's best height on a restart:
// 1,000 >= 250, open.
TEST(DogeUtxoFull, MiningGateClosedUntilSetComplete)
{
    constexpr uint32_t TIP = 5'000'001;
    TempDb t;
    uint256 b1000;
    b1000.SetHex("00000000000000000000000000000000000000000000000000000000000b1000");
    ASSERT_TRUE(t.db->write_batch({}, b1000, 1000));
    core::coin::SyncState partial;
    partial.anchor_height = 900;
    partial.strict = 1;
    ASSERT_TRUE(t.cache->set_sync_state(partial));
    t.reopen();
    EXPECT_EQ(t.cache->blocks_connected(), 1000u) << "the old gate's input";

    DogeTip tip(DogeTip::header_at(TIP), TIP);
    ASSERT_TRUE(tip.chain.is_synced());
    Mempool pool(core::coin::DOGE_LIMITS);
    pool.set_utxo(t.cache.get());
    const Outpoint x(genesis(0x53), 0);
    const auto tx = spend(x.txid, 0, 500000000, 0x53);
    ASSERT_TRUE(pool.add_tx_unchecked(tx));
    pool.set_tx_fee(txid_of(tx), 1000000);
    tip.clean(pool);

    doge::coin::EmbeddedCoinNode node(tip.chain, pool, tip.params);
    node.gate_on_pool_view();
    EXPECT_FALSE(node.is_synced()) << "a set not built from genesis opened the mining gate";
    const auto wd = node.getwork();
    EXPECT_TRUE(wd.m_data["transactions"].empty());
    EXPECT_EQ(wd.m_data.value("degraded", std::string()), doge::coin::kUtxoIncomplete);
    EXPECT_EQ(wd.m_data["coinbasevalue"].get<int64_t>(), tip.subsidy());

    // Built from genesis but not at the tip yet (never synced): still closed.
    core::coin::SyncState full;
    full.anchor_height = 0;
    full.strict = 1;
    ASSERT_TRUE(t.cache->set_sync_state(full));
    EXPECT_FALSE(node.is_synced());

    // At the tip, holding the tx's input: open, and the template prices it.
    ASSERT_TRUE(t.db->write_batch({{x, coin_of(600000000, TIP - 100, false)}}, tip.hash(), TIP));
    full.synced = 1;
    ASSERT_TRUE(t.cache->set_sync_state(full));
    EXPECT_TRUE(node.is_synced());
    const auto wd2 = node.getwork();
    EXPECT_FALSE(wd2.m_data.contains("degraded"));
    EXPECT_EQ(wd2.m_data["transactions"].size(), 1u);

    // A block in flight (the header chain one ahead): the gate stays open,
    // that template is coinbase-only.
    ASSERT_TRUE(t.db->write_batch({}, genesis(0x54), TIP - 1));
    EXPECT_TRUE(node.is_synced()) << "a closed gate keeps the old tip's merged work";
    EXPECT_EQ(node.getwork().m_data.value("degraded", std::string()), doge::coin::kUtxoIncomplete);
}

// KAT 4. A best-chain body spending an outpoint the set does not hold. The
// non-strict connect recorded the input as unknown and connected the block.
TEST(DogeUtxoFull, StrictConnectRefusesUnknownInput)
{
    const uint256 g = genesis(0x55);
    Lane l(20, Mode::Full, 16);
    auto chain = chain_with(g, 5);
    l.net.set_chain(chain, 1);
    l.net.best[0] = g;
    l.lane.on_block(chain[4], hash_of(chain[4]), 5);
    serve(l.lane, l.net, chain);
    ASSERT_TRUE(l.t.cache->complete(5));

    uint256 nowhere;
    nowhere.SetHex("ee000000000000000000000000000000000000000000000000000000000000ee");
    const auto bad = spend(nowhere, 3, 100000000, 0x56);
    chain.push_back(make_block(hash_of(chain[4]), 6, 0x56, {bad}));
    l.net.set_chain(chain, 1);
    l.net.best[0] = g;
    l.net.requested.clear();
    l.net.asked_how.clear();
    const size_t cache_before = l.t.cache->cache_size();

    const auto r = l.lane.on_block(chain[5], hash_of(chain[5]), 6);
    EXPECT_EQ(r.fed, UtxoLane::Fed::Refused);
    EXPECT_EQ(l.lane.stats().strict_refusals.load(), 1u);
    EXPECT_EQ(l.lane.stats().refused.load(), 1u);
    EXPECT_EQ(l.t.cache->get_best_height(), 5u);
    EXPECT_EQ(l.t.cache->get_best_block(), hash_of(chain[4]));
    EXPECT_EQ(l.t.cache->cache_size(), cache_before) << "the refused block touched the set";
    EXPECT_FALSE(l.has(chain[5].m_txs[0])) << "a coin of the refused block was added";
    EXPECT_EQ(l.net.requested, (std::vector<uint32_t>{6})) << "fetched again (another peer)";

    // Refused every time: from the third refusal the body is asked from
    // every peer; at the bound the set is left as is.
    for (uint32_t i = 2; i <= UtxoLane::REFUSALS_MAX; ++i)
        l.lane.on_block(chain[5], hash_of(chain[5]), 6);
    EXPECT_EQ(l.lane.stats().strict_refusals.load(), UtxoLane::REFUSALS_MAX);
    EXPECT_TRUE(std::find(l.net.asked_how.begin(), l.net.asked_how.end(), UtxoAsk::Broadcast)
                != l.net.asked_how.end());
    EXPECT_EQ(l.lane.stats().heal_failures.load(), 1u);
    EXPECT_TRUE(l.lane.stuck());
    EXPECT_FALSE(l.lane.fill().active);
    EXPECT_EQ(l.t.cache->get_best_height(), 5u);
    EXPECT_EQ(l.lane.on_block(chain[5], hash_of(chain[5]), 6).fed, UtxoLane::Fed::Skipped);
}

// The strict connect itself: an input spent twice in one block, or one the
// view does not hold, refuses the block and leaves the view untouched.
TEST(DogeUtxoFull, StrictConnectIsAllOrNothing)
{
    TempDb t;
    const auto chain = chain_with(genesis(0x57), 2);
    ASSERT_TRUE(t.cache->connect_block(chain[0], 1, txid_of, hash_of(chain[0]), true).has_value());
    ASSERT_TRUE(t.cache->flush(hash_of(chain[0]), 1));
    const uint256 cb1 = txid_of(chain[0].m_txs[0]);

    const auto s1 = spend(cb1, 0, 100, 0x58);
    const auto s2 = spend(cb1, 0, 200, 0x59);    // the same coin again
    const auto twice = make_block(hash_of(chain[0]), 2, 0x58, {s1, s2});
    core::coin::UTXOViewCache::StrictRefusal why;
    EXPECT_FALSE(t.cache->connect_block(twice, 2, txid_of, hash_of(twice), true, &why).has_value());
    EXPECT_EQ(why.missing, Outpoint(cb1, 0));
    EXPECT_EQ(why.txid, txid_of(s2));
    EXPECT_EQ(why.tx_index, 2u);
    EXPECT_EQ(t.cache->cache_size(), 0u);
    EXPECT_TRUE(t.cache->have_coin(Outpoint(cb1, 0)));

    // A chain inside one block (an output of an earlier tx) connects.
    const auto s3 = spend(txid_of(s1), 0, 50, 0x5a);
    const auto chained = make_block(hash_of(chain[0]), 2, 0x59, {s1, s3});
    EXPECT_TRUE(t.cache->connect_block(chained, 2, txid_of, hash_of(chained), true).has_value());
    EXPECT_FALSE(t.cache->have_coin(Outpoint(cb1, 0)));
    EXPECT_FALSE(t.cache->have_coin(Outpoint(txid_of(s1), 0)));
    EXPECT_TRUE(t.cache->have_coin(Outpoint(txid_of(s3), 0)));
}

// A zero-value output is a coin in Dogecoin Core's chainstate (only an
// unspendable script is left out); a block spending one connects. The
// accrual connect drops zero-value outputs: a full set built that way would
// refuse a valid block.
TEST(DogeUtxoFull, ZeroValueOutputIsACoin)
{
    const uint256 g = genesis(0x5b);
    const auto pre = chain_with(g, 1);
    auto z = spend(txid_of(pre[0].m_txs[0]), 0, DOGE_SUBSIDY - 1000, 0x5b);
    TxOut zero;
    zero.value = 0;
    zero.scriptPubKey.m_data = p2pkh(0x5c);
    z.vout.push_back(zero);
    const auto z_spend = spend(txid_of(z), 1, 0, 0x5d);
    const auto chain = chain_with(g, 3, {{2, {z}}, {3, {z_spend}}});
    Lane l(20, Mode::Full, 16);
    l.net.set_chain(chain, 1);
    l.net.best[0] = g;
    l.lane.on_block(chain[2], hash_of(chain[2]), 3);
    serve(l.lane, l.net, chain);
    EXPECT_EQ(l.t.cache->get_best_height(), 3u);
    EXPECT_EQ(l.lane.stats().strict_refusals.load(), 0u);
    EXPECT_FALSE(l.t.cache->have_coin(Outpoint(txid_of(z), 1))) << "spent at 3";
}

// A body whose transactions are not the ones its header commits to (Merkle
// root) is not connected; the height is fetched again.
TEST(DogeUtxoFull, BodyNotMatchingItsHeaderIsRefetched)
{
    const uint256 g = genesis(0x5e);
    const auto chain = chain_with(g, 4);
    Lane l(20, Mode::Full, 16);
    l.net.set_chain(chain, 1);
    l.net.best[0] = g;
    l.lane.on_block(chain[3], hash_of(chain[3]), 4);
    l.lane.on_block(chain[0], hash_of(chain[0]), 1);
    BlockType forged = chain[1];
    forged.m_txs[0].vout[0].value += 1;   // same header, other txs
    ASSERT_EQ(hash_of(forged), hash_of(chain[1]));
    l.net.requested.clear();
    l.lane.on_block(forged, hash_of(forged), 2);
    EXPECT_EQ(l.lane.stats().bad_bodies.load(), 1u);
    EXPECT_EQ(l.t.cache->get_best_height(), 1u);
    EXPECT_TRUE(contains_height(l.net.requested, 2)) << "fetched again";
    serve(l.lane, l.net, chain);
    EXPECT_EQ(l.t.cache->get_best_height(), 4u);
}

// The sync state is written in the same batch as the best block: a reopened
// DB has them agree; a wipe removes it.
TEST(DogeUtxoFull, SyncStateTravelsWithTheBestBlock)
{
    const uint256 g = genesis(0x5f);
    const auto chain = chain_with(g, 6);
    Lane l(20, Mode::Full, 16);
    l.net.set_chain(chain, 1);
    l.net.best[0] = g;
    l.lane.on_block(chain[5], hash_of(chain[5]), 6);
    serve(l.lane, l.net, chain);
    const uint64_t coins = l.t.cache->sync_state().coins;
    EXPECT_EQ(coins, 6u) << "one coinbase output per block";
    l.t.reopen();
    const auto ss = l.t.db->get_sync_state();
    EXPECT_EQ(ss.anchor_height, 0u);
    EXPECT_EQ(ss.best_height, 6u);
    EXPECT_EQ(ss.best_height, l.t.db->get_best_height());
    EXPECT_EQ(ss.coins, coins);
    ASSERT_TRUE(l.t.db->reset());
    EXPECT_FALSE(l.t.db->get_sync_state().tracked());
}

// The digest (c2pool --utxo-digest): equal for the same set built twice,
// different once one more block is connected; counts the coins.
TEST(DogeUtxoFull, DigestPinsTheSet)
{
    const uint256 g = genesis(0x60);
    const auto chain = chain_with(g, 8);
    auto build = [&](Lane& l, uint32_t n) {
        l.net.set_chain(std::vector<BlockType>(chain.begin(), chain.begin() + n), 1);
        l.net.best[0] = g;
        l.lane.on_block(chain[n - 1], hash_of(chain[n - 1]), n);
        serve(l.lane, l.net, chain);
        ASSERT_EQ(l.t.cache->get_best_height(), n);
    };
    Lane a(20, Mode::Full, 16), b(20, Mode::Full, 4), c(20, Mode::Full, 16);
    build(a, 7);
    build(b, 7);
    build(c, 8);
    const auto da = core::coin::utxo_digest(*a.t.db);
    const auto db = core::coin::utxo_digest(*b.t.db);
    const auto dc = core::coin::utxo_digest(*c.t.db);
    ASSERT_TRUE(da.ok && db.ok && dc.ok);
    EXPECT_EQ(da.sha256_hex.size(), 64u);
    EXPECT_EQ(da.sha256_hex, db.sha256_hex) << "the same set, built with another window";
    EXPECT_NE(da.sha256_hex, dc.sha256_hex);
    EXPECT_EQ(da.coins, 7u);
    EXPECT_EQ(da.best_height, 7u);
    EXPECT_EQ(da.sync.anchor_height, 0u);
}
