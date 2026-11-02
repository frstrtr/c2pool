// SPDX-License-Identifier: AGPL-3.0-or-later
//
// N1 KATs: GET /api/utxo/scan over the DASH full UTXO set (utxo_scan.hpp,
// UTXOViewCache::scan_coins, Mempool::pool_spenders). Every set here is built
// the way the node builds it (dash_utxo_full_fixture.hpp: snapshot file,
// digest-gated pin, the real import, the S2-2 open rule) and read through a
// real LevelDB.

#include "dash_utxo_full_fixture.hpp"

#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/utxo_scan.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>

using namespace dash_utxo_full;
using dash::coin::UtxoLane;
using dash::coin::UtxoScanSource;

namespace {

constexpr uint32_t kBase = 1000;
constexpr uint8_t  kA = 0xA1;   // the scanned scripts
constexpr uint8_t  kB = 0xB2;

std::string hexs(const std::vector<uint8_t>& v)
{
    return dash::coin::utxo_scan_detail::hex(v.data(), v.size());
}

SnapCoin coin_with(const Outpoint& op, int64_t value, const std::vector<uint8_t>& spk, uint32_t h, bool cb)
{
    SnapCoin c;
    c.op = op;
    c.coin = Coin(value, script(spk), h, cb);
    return c;
}

/// A: two coinbase rows (one of 1 duff) and one plain row; B: two rows; four
/// coins of other scripts, one of them A's script with one byte more.
std::vector<SnapCoin> base_coins()
{
    std::vector<uint8_t> a_plus = p2pkh(kA);
    a_plus.push_back(0x00);
    return {
        coin_with(Outpoint(fake_hash(11), 0), 5000, p2pkh(kA), 900, true),
        coin_with(Outpoint(fake_hash(11), 3), 7000, p2pkh(kA), 950, false),
        coin_with(Outpoint(fake_hash(12), 1), 1, p2pkh(kA), 990, true),
        coin_with(Outpoint(fake_hash(13), 0), 9000, p2pkh(kB), 800, false),
        coin_with(Outpoint(fake_hash(14), 2), 4000, p2pkh(kB), 999, true),
        coin_with(Outpoint(fake_hash(15), 0), 123, p2pkh(0xC3), 700, false),
        coin_with(Outpoint(fake_hash(16), 0), 456, p2pkh(0xC4), 701, true),
        coin_with(Outpoint(fake_hash(17), 1), 789, a_plus, 702, false),
        coin_with(Outpoint(fake_hash(18), 0), 1000, p2pkh(kA - 1), 703, false),
    };
}

struct Rig {
    TempDir tmp{"scan"};
    UtxoLane lane;
    Chain chain;
    std::vector<uint32_t> requested;
    BlockType base_block = block(fake_hash(999), {coinbase(50, 999)}, 999);
    uint256 base_hash = hash_of(base_block);
    dash::coin::Mempool pool;
    std::shared_ptr<UtxoScanSource> source;
    std::atomic<bool> cancel{false};

    bool open(std::vector<SnapCoin> coins, bool testnet = true)
    {
        if (!open_full_set(lane, tmp, std::move(coins), kBase, base_hash)) return false;
        chain.hashes[kBase] = base_hash;
        lane.set_hash_at_fn(chain.fn());
        lane.set_request_block_fn([this](uint32_t h) {
            requested.push_back(h);
            return true;
        });
        pool.set_utxo(lane.cache());
        source = std::make_shared<UtxoScanSource>(
            lane, [this](const std::vector<Outpoint>& ops) { return pool.pool_spenders(ops); }, testnet);
        return true;
    }
    void serve() { lane.on_header_tip(kBase); }
    void deliver(const BlockType& b, uint32_t h)
    {
        chain.hashes[h] = hash_of(b);
        lane.on_block_connected(b, h);
    }
    nlohmann::json scan(const std::string& query) { return source->handle(query, cancel); }
};

using RowKey = std::pair<std::string, uint32_t>;

std::map<RowKey, nlohmann::json> rows_of(const nlohmann::json& reply)
{
    std::map<RowKey, nlohmann::json> m;
    for (const auto& r : reply.at("unspents"))
        m[{r.at("txid").get<std::string>(), r.at("vout").get<uint32_t>()}] = r;
    return m;
}

std::set<RowKey> keys_of(const std::vector<std::pair<Outpoint, Coin>>& rows)
{
    std::set<RowKey> s;
    for (const auto& [op, c] : rows) s.insert({op.txid.GetHex(), op.index});
    return s;
}

std::function<bool(const uint8_t*, size_t)> match_script(const std::vector<uint8_t>& spk)
{
    return [spk](const uint8_t* p, size_t n) { return n == spk.size() && std::memcmp(p, spk.data(), n) == 0; };
}

} // namespace

// The query: addresses of the node's network, hex scripts, the knobs, and
// every malformed form refused by name before anything is read.
TEST(DashUtxoScan, ParsesTheQueryAndRefusesBadParametersByName)
{
    using dash::coin::parse_utxo_scan_query;
    dash::coin::UtxoScanRequest req;
    std::string err, det;
    const std::string xdgf = "XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u";   // mainnet P2PKH (the tenant payout address)
    const std::string xdgf_spk = "76a91420cb5c22b1e4d5947e5c112c7696b51ad9af3c6188ac";

    ASSERT_TRUE(parse_utxo_scan_query("address=" + xdgf + "&script=" + hexs(p2pkh(kA)) +
                                          "&script=" + xdgf_spk + "&exclude_mempool_spent=0&min_value=1000&limit=7",
                                      /*testnet=*/false, req, err, det))
        << err << " " << det;
    ASSERT_EQ(req.scripts.size(), 2u) << "the address and the same script given as hex count once";
    EXPECT_EQ(req.scripts[0].address, xdgf);
    EXPECT_EQ(hexs(req.scripts[0].spk), xdgf_spk);
    EXPECT_EQ(req.scripts[1].address, "");
    EXPECT_EQ(req.scripts[1].spk, p2pkh(kA));
    EXPECT_FALSE(req.exclude_mempool_spent);
    EXPECT_EQ(req.min_value, 1000);
    EXPECT_EQ(req.limit, 7u);

    ASSERT_TRUE(parse_utxo_scan_query("script=" + hexs(p2pkh(kB)), true, req, err, det));
    EXPECT_TRUE(req.exclude_mempool_spent) << "default 1";
    EXPECT_EQ(req.min_value, 0);
    EXPECT_EQ(req.limit, dash::coin::kUtxoScanDefaultLimit);
    // Percent-encoding is decoded.
    ASSERT_TRUE(parse_utxo_scan_query("%61ddress=" + xdgf, false, req, err, det)) << err;

    struct Bad {
        std::string query;
        bool testnet;
        const char* error;
    };
    std::string seventeen;
    for (int i = 0; i < 17; ++i) seventeen += "&script=" + hexs(p2pkh(static_cast<uint8_t>(i)));
    const std::vector<Bad> bad = {
        {"", false, "utxo-scan-no-script"},
        {"limit=5", false, "utxo-scan-no-script"},
        {"address=" + xdgf, true, "utxo-scan-bad-address"},   // a mainnet address on a testnet node
        {"address=XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84v", false, "utxo-scan-bad-address"},   // checksum
        {"address=", false, "utxo-scan-bad-address"},
        {"script=76a9zz", false, "utxo-scan-bad-script"},
        {"script=76a", false, "utxo-scan-bad-script"},
        {"script=", false, "utxo-scan-bad-script"},
        {seventeen.substr(1), false, "utxo-scan-too-many-scripts"},
        {"script=51&limit=0", false, "utxo-scan-bad-param"},
        {"script=51&limit=100001", false, "utxo-scan-bad-param"},
        {"script=51&limit=-1", false, "utxo-scan-bad-param"},
        {"script=51&min_value=x", false, "utxo-scan-bad-param"},
        {"script=51&min_value=2100000000000001", false, "utxo-scan-bad-param"},
        {"script=51&exclude_mempool_spent=yes", false, "utxo-scan-bad-param"},
        {"script=51&adress=x", false, "utxo-scan-bad-param"},
        {"script=51%zz", false, "utxo-scan-bad-param"},
    };
    for (const auto& b : bad) {
        EXPECT_FALSE(parse_utxo_scan_query(b.query, b.testnet, req, err, det)) << b.query;
        EXPECT_EQ(err, b.error) << b.query << " -> " << det;
    }
    ASSERT_TRUE(parse_utxo_scan_query(seventeen.substr(1 + seventeen.find("&script", 1)), false, req, err, det))
        << "16 scripts are accepted";
    EXPECT_EQ(req.scripts.size(), 16u);
}

// K1: exactly the coins paying the scanned scripts — value, height, coinbase,
// script — and nothing else (a script one byte longer with A's prefix does
// not match). The reply names the set's tip and how many records it read.
TEST(DashUtxoScan, ReturnsExactlyTheCoinsOfTheScannedScripts)
{
    Rig r;
    ASSERT_TRUE(r.open(base_coins()));
    r.serve();
    ASSERT_EQ(r.lane.full_status().state, "serving");

    const auto j = r.scan("script=" + hexs(p2pkh(kA)));
    ASSERT_EQ(j.value("http_status", 0), 200) << j.dump();
    EXPECT_EQ(j["ok"], true);
    EXPECT_EQ(j["tip_height"], kBase);
    EXPECT_EQ(j["tip_hash"], r.base_hash.GetHex());
    EXPECT_EQ(j["scanned"], 9);
    EXPECT_EQ(j["tip_moved"], false);
    EXPECT_EQ(j["truncated"], false);
    EXPECT_EQ(j["utxo"]["mode"], "full");
    EXPECT_EQ(j["utxo"]["state"], "serving");
    EXPECT_EQ(j["utxo"]["coins"], 9);
    ASSERT_EQ(j["scripts"].size(), 1u);
    EXPECT_EQ(j["scripts"][0]["script_hex"], hexs(p2pkh(kA)));
    EXPECT_FALSE(j["scripts"][0].contains("address"));
    EXPECT_TRUE(j["mempool_spent"].empty());
    EXPECT_EQ(j["total_value"], 5000 + 7000 + 1);

    const auto rows = rows_of(j);
    ASSERT_EQ(rows.size(), 3u) << j.dump();
    const auto& a0 = rows.at({fake_hash(11).GetHex(), 0});
    EXPECT_EQ(a0["value"], 5000);
    EXPECT_EQ(a0["height"], 900);
    EXPECT_EQ(a0["coinbase"], true);
    EXPECT_EQ(a0["script_hex"], hexs(p2pkh(kA)));
    const auto& a3 = rows.at({fake_hash(11).GetHex(), 3});
    EXPECT_EQ(a3["value"], 7000);
    EXPECT_EQ(a3["height"], 950);
    EXPECT_EQ(a3["coinbase"], false);
    const auto& dust = rows.at({fake_hash(12).GetHex(), 1});
    EXPECT_EQ(dust["value"], 1);
    EXPECT_EQ(dust["height"], 990);
    EXPECT_EQ(dust["coinbase"], true);

    // Two scripts in one pass; a script that pays nothing answers no rows.
    const auto ab = r.scan("script=" + hexs(p2pkh(kA)) + "&script=" + hexs(p2pkh(kB)));
    ASSERT_EQ(ab.value("http_status", 0), 200);
    const auto rab = rows_of(ab);
    EXPECT_EQ(rab.size(), 5u);
    EXPECT_EQ(rab.at({fake_hash(14).GetHex(), 2})["coinbase"], true);
    EXPECT_EQ(rab.at({fake_hash(14).GetHex(), 2})["height"], 999);
    EXPECT_EQ(ab["total_value"], 5000 + 7000 + 1 + 9000 + 4000);
    const auto none = r.scan("script=" + hexs(p2pkh(0xEE)));
    ASSERT_EQ(none.value("http_status", 0), 200);
    EXPECT_TRUE(none["unspents"].empty());
    EXPECT_EQ(none["total_value"], 0);
    EXPECT_EQ(none["scanned"], 9);
}

// K4: limit stops the pass with truncated:true; min_value drops small coins.
TEST(DashUtxoScan, LimitTruncatesAndMinValueFilters)
{
    Rig r;
    ASSERT_TRUE(r.open(base_coins()));
    r.serve();
    const std::string a = "script=" + hexs(p2pkh(kA));
    const auto two = r.scan(a + "&limit=2");
    ASSERT_EQ(two.value("http_status", 0), 200);
    EXPECT_EQ(two["unspents"].size(), 2u);
    EXPECT_EQ(two["truncated"], true);
    const auto three = r.scan(a + "&limit=3");
    EXPECT_EQ(three["unspents"].size(), 3u);
    EXPECT_EQ(three["truncated"], false) << "exactly as many rows as the limit: nothing left out";
    const auto big = r.scan(a + "&min_value=1000");
    EXPECT_EQ(big["unspents"].size(), 2u);
    EXPECT_EQ(big["total_value"], 12000);
    EXPECT_EQ(rows_of(big).count({fake_hash(12).GetHex(), 1}), 0u) << "the 1-duff row is below min_value";
}

// K5: no scan unless the full set is serving — each posture refused by name,
// with no "scanned" (the web server's interval stays free) — and none after
// the coin target detached the source.
TEST(DashUtxoScan, RefusedUnlessTheFullSetIsServing)
{
    const std::string a = "script=" + hexs(p2pkh(kA));
    {
        Rig r;
        ASSERT_TRUE(r.open(base_coins()));
        auto j = r.scan(a);   // base not yet placed on the header chain
        EXPECT_EQ(j.value("http_status", 0), 409);
        EXPECT_EQ(j["error"], "utxo-set-verifying-base");
        EXPECT_EQ(j["utxo"]["state"], "verifying-base");
        EXPECT_FALSE(j.contains("scanned"));
        // A bad request is refused first (400), whatever the posture.
        EXPECT_EQ(r.scan("script=zz").value("http_status", 0), 400);

        r.serve();
        const uint32_t far = kBase + 50;
        r.deliver(block(fake_hash(far - 1), {coinbase(50, far)}, far), far);
        j = r.scan(a);
        EXPECT_EQ(j.value("http_status", 0), 409);
        EXPECT_EQ(j["error"], "utxo-set-catching-up");
        EXPECT_FALSE(j.contains("scanned"));
    }
    {
        Rig r;
        ASSERT_TRUE(r.open(base_coins()));
        r.serve();
        const BlockType bad = block(r.base_hash, {coinbase(50, 1), spend({Outpoint(fake_hash(66), 0)}, {out(10, p2pkh(9))}, 1)}, 1);
        r.deliver(bad, kBase + 1);
        r.deliver(bad, kBase + 1);
        ASSERT_TRUE(r.lane.withheld());
        const auto j = r.scan(a);
        EXPECT_EQ(j.value("http_status", 0), 409);
        EXPECT_EQ(j["error"], "utxo-set-withheld");
        EXPECT_NE(j.value("detail", "").find("utxo-strict-refusal"), std::string::npos) << j.dump();
        EXPECT_FALSE(j.contains("scanned"));
    }
    {
        // The accrual view (the 288-block window) would silently miss old coins.
        UtxoLane accrual;
        ASSERT_TRUE(accrual.open(""));
        dash::coin::Mempool mp;
        UtxoScanSource src(accrual, [&mp](const std::vector<Outpoint>& ops) { return mp.pool_spenders(ops); }, true);
        std::atomic<bool> cancel{false};
        const auto j = src.handle(a, cancel);
        EXPECT_EQ(j.value("http_status", 0), 409);
        EXPECT_EQ(j["error"], "utxo-set-not-full");
        EXPECT_EQ(j["utxo"]["mode"], "not-full");
        EXPECT_FALSE(j.contains("scanned"));
    }
    {
        Rig r;
        ASSERT_TRUE(r.open(base_coins()));
        r.serve();
        EXPECT_EQ(r.scan(a).value("http_status", 0), 200);
        r.source->detach();
        const auto j = r.scan(a);
        EXPECT_EQ(j.value("http_status", 0), 503);
        EXPECT_EQ(j["error"], "utxo-scan-detached");
    }
}

// K3: a block connected DURING the pass. The pass reads the snapshot taken
// with the best block, so its rows are the set at the tip it reports (the
// coin the block spends is there, the coin it creates is not), and it says
// the tip moved. The next pass is at the new tip. This also proves the cache
// lock is not held during the pass: the lane's flush takes it exclusively on
// this very thread.
TEST(DashUtxoScan, ABlockConnectedDuringThePassLeavesItsRowsAtTheStartTip)
{
    Rig r;
    ASSERT_TRUE(r.open(base_coins()));
    r.serve();
    const MutableTransaction cb1 = coinbase(50, kA);   // pays A
    const BlockType b1 = block(r.base_hash,
                               {cb1, spend({Outpoint(fake_hash(11), 0)}, {out(5000, p2pkh(0xC5))}, 1)}, 1);
    r.chain.hashes[kBase + 1] = hash_of(b1);

    std::vector<std::pair<Outpoint, Coin>> rows;
    bool connected = false;
    const auto st = r.lane.cache()->scan_coins(match_script(p2pkh(kA)), [&](const Outpoint& op, const Coin& c) {
        if (!connected) {
            connected = true;
            r.lane.on_block_connected(b1, kBase + 1);
        }
        rows.emplace_back(op, c);
        return true;
    });
    ASSERT_TRUE(connected);
    ASSERT_EQ(r.lane.cache()->get_best_block(), hash_of(b1)) << r.lane.full_status().withheld_reason;
    ASSERT_TRUE(st.ok);
    EXPECT_EQ(st.best_block, r.base_hash);
    EXPECT_EQ(st.best_height, kBase);
    EXPECT_EQ(st.best_after, hash_of(b1));
    EXPECT_TRUE(st.tip_moved());
    EXPECT_EQ(keys_of(rows), (std::set<RowKey>{{fake_hash(11).GetHex(), 0},
                                                {fake_hash(11).GetHex(), 3},
                                                {fake_hash(12).GetHex(), 1}}))
        << "the rows are the set at the start tip";

    const auto j = r.scan("script=" + hexs(p2pkh(kA)));
    ASSERT_EQ(j.value("http_status", 0), 200) << j.dump();
    EXPECT_EQ(j["tip_height"], kBase + 1);
    EXPECT_EQ(j["tip_hash"], hash_of(b1).GetHex());
    EXPECT_EQ(j["tip_moved"], false);
    const auto now = rows_of(j);
    EXPECT_EQ(now.count({fake_hash(11).GetHex(), 0}), 0u) << "spent by the block";
    const auto& made = now.at({dash::coin::dash_txid(cb1).GetHex(), 0});
    EXPECT_EQ(made["coinbase"], true);
    EXPECT_EQ(made["height"], kBase + 1);
    EXPECT_EQ(made["value"], 50);
    EXPECT_EQ(now.size(), 3u);
}

// K2: changes the cache holds unflushed are applied (a coin they spend is
// dropped, a coin they add that matches is passed), and the reply says the
// tip moved so the caller scans again once the lane has flushed.
TEST(DashUtxoScan, UnflushedChangesAreAppliedAndFlagged)
{
    Rig r;
    ASSERT_TRUE(r.open(base_coins()));
    r.serve();
    auto* cache = r.lane.cache();
    cache->add_coin(Outpoint(fake_hash(21), 0), Coin(777, script(p2pkh(kA)), kBase + 1, false));
    cache->add_coin(Outpoint(fake_hash(22), 0), Coin(888, script(p2pkh(0xC7)), kBase + 1, false));
    ASSERT_TRUE(cache->spend_coin(Outpoint(fake_hash(11), 3)).has_value());

    std::vector<std::pair<Outpoint, Coin>> rows;
    const auto st = cache->scan_coins(match_script(p2pkh(kA)), [&](const Outpoint& op, const Coin& c) {
        rows.emplace_back(op, c);
        return true;
    });
    ASSERT_TRUE(st.ok);
    EXPECT_EQ(st.pending, 3u);
    EXPECT_TRUE(st.tip_moved());
    EXPECT_EQ(keys_of(rows), (std::set<RowKey>{{fake_hash(11).GetHex(), 0},
                                                {fake_hash(12).GetHex(), 1},
                                                {fake_hash(21).GetHex(), 0}}));
    const auto j = r.scan("script=" + hexs(p2pkh(kA)));
    EXPECT_EQ(j["tip_moved"], true);
    EXPECT_EQ(j["total_value"], 5000 + 1 + 777);

    cache->discard_pending();
    const auto again = r.scan("script=" + hexs(p2pkh(kA)));
    EXPECT_EQ(again["tip_moved"], false);
    EXPECT_EQ(again["total_value"], 5000 + 7000 + 1);
}

// K8: a coin a pool tx spends is listed in mempool_spent with its spender and,
// by default, left out of the rows and the total. pool_spenders reads every
// pool entry, so a coin two pool txs spend stays listed when one leaves.
TEST(DashUtxoScan, MempoolSpendsAreListedAndExcluded)
{
    Rig r;
    ASSERT_TRUE(r.open(base_coins()));
    r.serve();
    const Outpoint spent(fake_hash(11), 0);
    const auto tx1 = spend({spent}, {out(4000, p2pkh(0xC6))}, 77);
    const auto tx2 = spend({spent}, {out(3000, p2pkh(0xC6))}, 78);
    ASSERT_TRUE(r.pool.add_tx(tx1));
    ASSERT_TRUE(r.pool.add_tx(tx2));
    auto sp = r.pool.pool_spenders({spent, Outpoint(fake_hash(11), 3)});
    ASSERT_EQ(sp.size(), 2u);
    r.pool.remove_tx(dash::coin::dash_txid(tx2));
    sp = r.pool.pool_spenders({spent});
    ASSERT_EQ(sp.size(), 1u) << "tx1 still spends it";
    EXPECT_EQ(sp[0].second, dash::coin::dash_txid(tx1));

    const std::string a = "script=" + hexs(p2pkh(kA));
    const auto ex = r.scan(a);
    ASSERT_EQ(ex.value("http_status", 0), 200);
    EXPECT_EQ(rows_of(ex).count({spent.txid.GetHex(), 0}), 0u);
    ASSERT_EQ(ex["mempool_spent"].size(), 1u);
    EXPECT_EQ(ex["mempool_spent"][0]["txid"], spent.txid.GetHex());
    EXPECT_EQ(ex["mempool_spent"][0]["vout"], 0);
    EXPECT_EQ(ex["mempool_spent"][0]["spent_by"], dash::coin::dash_txid(tx1).GetHex());
    EXPECT_EQ(ex["total_value"], 7000 + 1);

    const auto keep = r.scan(a + "&exclude_mempool_spent=0");
    EXPECT_EQ(rows_of(keep).count({spent.txid.GetHex(), 0}), 1u);
    EXPECT_EQ(keep["mempool_spent"].size(), 1u);
    EXPECT_EQ(keep["total_value"], 5000 + 7000 + 1);
}

// Read-only: a scan leaves the set, the cache and the mempool as they were.
TEST(DashUtxoScan, AScanChangesNothing)
{
    Rig r;
    ASSERT_TRUE(r.open(base_coins()));
    r.serve();
    const auto tx1 = spend({Outpoint(fake_hash(13), 0)}, {out(8000, p2pkh(0xC6))}, 79);
    ASSERT_TRUE(r.pool.add_tx(tx1));
    auto snapshot = [&] {
        auto* c = r.lane.cache();
        std::vector<std::pair<Outpoint, Coin>> all;
        c->scan_coins([](const uint8_t*, size_t) { return true; }, [&](const Outpoint& op, const Coin& coin) {
            all.emplace_back(op, coin);
            return true;
        });
        std::vector<std::tuple<std::string, uint32_t, int64_t, uint32_t, bool>> flat;
        for (const auto& [op, coin] : all)
            flat.emplace_back(op.txid.GetHex(), op.index, coin.value, coin.height, coin.coinbase);
        return std::make_tuple(c->get_best_block(), c->get_best_height(), c->sync_state().coins, c->cache_size(),
                               r.pool.size(), r.pool.get_entry(dash::coin::dash_txid(tx1)).has_value(), flat,
                               r.lane.full_status().state);
    };
    const auto before = snapshot();
    for (const char* q : {"script=a1", "exclude_mempool_spent=0&script=", "limit=1&script="}) {
        std::string query = q;
        if (query.back() == '=') query += hexs(p2pkh(kB));
        r.scan(query);
    }
    EXPECT_EQ(snapshot(), before);
}

// K9: the tenant payout address's 170 real rows (the dashd getaddressutxos
// capture at tip 2563986 the wallet tests use), loaded into a full set among
// other coins, come back through address= byte-equal: txid, vout, value,
// script, height; total 60963705 duffs. The capture has no coinbase flag, so
// the rows are planted with a mixed one and it must come back as planted.
TEST(DashUtxoScan, TheXdgF55FixtureRowsComeBackByteEqual)
{
    std::ifstream f(XDGF_GETADDRESSUTXOS_FIXTURE);
    ASSERT_TRUE(f.good()) << XDGF_GETADDRESSUTXOS_FIXTURE;
    const auto fixture = nlohmann::json::parse(f);
    ASSERT_EQ(fixture.size(), 170u);
    std::vector<SnapCoin> coins;
    std::map<RowKey, nlohmann::json> want;
    int64_t want_total = 0;
    for (const auto& u : fixture) {
        uint256 txid;
        txid.SetHex(u.at("txid").get<std::string>());
        std::vector<uint8_t> spk;
        ASSERT_TRUE(dash::coin::utxo_scan_detail::unhex(u.at("script").get<std::string>(), spk));
        const uint32_t vout = u.at("outputIndex").get<uint32_t>();
        const bool cb = coins.size() % 3 != 0;
        coins.push_back(coin_with(Outpoint(txid, vout), u.at("satoshis").get<int64_t>(), spk,
                                  u.at("height").get<uint32_t>(), cb));
        want[{txid.GetHex(), vout}] = u;
        want[{txid.GetHex(), vout}]["coinbase"] = cb;
        want_total += u.at("satoshis").get<int64_t>();
    }
    ASSERT_EQ(want_total, 60963705);
    for (uint32_t i = 0; i < 40; ++i)
        coins.push_back(coin_with(Outpoint(fake_hash(5000 + i), i % 3), 1000 + i, p2pkh(static_cast<uint8_t>(i)),
                                  2560000 + i, i % 2 == 0));

    Rig r;
    ASSERT_TRUE(r.open(coins, /*testnet=*/false));
    r.serve();
    const auto j = r.scan("address=XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u");
    ASSERT_EQ(j.value("http_status", 0), 200) << j.dump();
    EXPECT_EQ(j["scanned"], 210);
    EXPECT_EQ(j["scripts"][0]["address"], "XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u");
    EXPECT_EQ(j["scripts"][0]["script_hex"], "76a91420cb5c22b1e4d5947e5c112c7696b51ad9af3c6188ac");
    EXPECT_EQ(j["total_value"], 60963705);
    const auto got = rows_of(j);
    ASSERT_EQ(got.size(), 170u);
    for (const auto& [k, u] : want) {
        const auto it = got.find(k);
        ASSERT_NE(it, got.end()) << k.first << ":" << k.second;
        EXPECT_EQ(it->second["value"], u["satoshis"]);
        EXPECT_EQ(it->second["script_hex"], u["script"]);
        EXPECT_EQ(it->second["height"], u["height"]);
        EXPECT_EQ(it->second["coinbase"], u["coinbase"]);
    }
}
