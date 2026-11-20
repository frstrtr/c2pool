// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// --import-found-blocks and the SOURCE node's measured effort.
//
// An outside LTC + DOGE node imported our /recent_blocks and
// /recent_merged_blocks (0.2.12.10). Its Merged Mining Blocks card showed
// Effort "--" on every imported DOGE row: /recent_merged_blocks rows carry no
// pool_hashrate_at_find, so the node had nothing to compute an effort from,
// and its own rate history starts on 11-12. DOGE 6454700 showed 98.5 %
// integrated over the 5 % of the round that history covers, where our node,
// which covers all of it, says 139.1 %.
//
// The pool rate luck integrates is the SHARE CHAIN's, the same on every node:
// a round our node measured is measured for the pool. These KATs pin:
//
//   * /recent_merged_blocks serves pool_hashrate_at_find, and it round-trips
//     through an import;
//   * an imported row takes the source's integrated effort where the node
//     has a worse measurement of the same round (none, a single sample, or
//     less of it covered) -- merged rows and parent rows alike;
//   * a node whose own history covers as much keeps its own figure;
//   * an implausible or malformed source effort is refused and counted;
//   * the operator's sequence: rows imported by 0.2.12.10 (no source effort)
//     gain it on the next import of the same files, once; a third import
//     changes nothing.
//
// Everything here goes through API that predates the change (the import
// entry point, the endpoints' JSON, the rate history, the merged manager), so
// this file also builds against the code before it -- and fails there.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cmath>
#include <cstdint>
#include <functional>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>

#include <c2pool/merged/merged_mining.hpp>
#include <c2pool/storage/found_block_store.hpp>
#include <core/found_block_import.hpp>
#include <core/uint256.hpp>
#include <core/web_server.hpp>

using core::MiningInterface;
using c2pool::address::Blockchain;
namespace fbi = core::found_block_import;

namespace {

constexpr double kT32 = 4294967296.0;
const std::string kMiner = "LVypi56LPcT9jR3e5Y5AdoVc5EGdrVk26F";

std::string hash_of(unsigned tag)
{
    std::ostringstream os;
    os << std::hex << tag;
    const std::string tail = os.str();
    return std::string(64 - tail.size(), 'e') + tail;
}

/// A header chain as a map (hash -> entry).
struct FakeChain {
    struct Entry { uint64_t height; uint64_t ts; double difficulty; };
    std::map<std::string, Entry> entries;
    uint64_t tip{0};
    uint64_t lowest{0};

    void add(const std::string& hash, uint64_t height, uint64_t ts, double difficulty)
    {
        entries[hash] = {height, ts, difficulty};
        if (height > tip) tip = height;
    }
    fbi::ChainLookup lookup()
    {
        fbi::ChainLookup l;
        l.header = [this](const std::string& hash) {
            fbi::Header h;
            auto it = entries.find(hash);
            if (it == entries.end()) return h;
            h.known = true;
            h.main_chain = true;
            h.height = it->second.height;
            h.ts = it->second.ts;
            h.difficulty = it->second.difficulty;
            h.tip_height = tip;
            return h;
        };
        l.ready = [] { return true; };
        l.lowest_height = [this] { return lowest; };
        return l;
    }
};

fbi::Report import_json(MiningInterface& mi, const nlohmann::json& file, const fbi::Source& src)
{
    const auto parsed = fbi::parse(file.dump());
    EXPECT_TRUE(parsed.error.empty()) << parsed.error;
    return mi.import_found_blocks(parsed.rows, src);
}

nlohmann::json row_of(const nlohmann::json& arr, const std::string& key, const std::string& value)
{
    for (const auto& b : arr)
        if (b.contains(key) && b[key].is_string() && b[key].get<std::string>() == value)
            return b;
    return nlohmann::json(nullptr);
}

double num(const nlohmann::json& row, const char* key)
{
    if (!row.is_object() || !row.contains(key) || !row[key].is_number())
        return std::nan("");
    return row[key].get<double>();
}

std::string str(const nlohmann::json& row, const char* key)
{
    if (!row.is_object() || !row.contains(key) || !row[key].is_string())
        return "<absent>";
    return row[key].get<std::string>();
}

/// Samples of the rate history, one an hour: each covers the hour before it.
void feed(MiningInterface& mi, double from, double to, double rate, double parent_diff)
{
    for (double t = from + 3600.0; t <= to + 3600.0; t += 3600.0)
        mi.add_luck_rate_sample(t, rate, 0.0, parent_diff);
}

// The pool every generated fixture runs.
constexpr double kLtcDiff = 9.5e7;
constexpr double kDogeDiff = 3.3e7;
constexpr double kRate = 2.0e11;           // the gross pool rate
constexpr double kShareDiff = 500.0;
constexpr uint64_t kT0 = 1790000000;
constexpr double kDay = 86400.0;

/// The source node: four DOGE blocks of the pool, its rate history covering
/// every round (at 1.2x the rate it recorded at find, as a pool's rate
/// moves). Its /recent_merged_blocks is the import file.
struct DogeSource {
    MiningInterface mi{false, nullptr, Blockchain::LITECOIN};
    std::vector<std::string> hashes;
    std::vector<uint64_t> ts;
    DogeSource()
    {
        feed(mi, kT0 - 7200.0, kT0 + 6 * kDay, 1.2 * kRate, kLtcDiff);
        const double days[4] = {0.0, 1.0, 2.5, 4.0};
        for (unsigned i = 0; i < 4; ++i) {
            const std::string h = hash_of(0xd00 + i);
            const uint64_t t = kT0 + static_cast<uint64_t>(days[i] * kDay);
            mi.record_found_block(6454000 + i * 100, uint256S(h), t, "DOGE", kMiner, "",
                                  kDogeDiff, 0.0, kRate, 1000000000000ULL,
                                  MiningInterface::BlockAuthorship::sharechain_peer);
            hashes.push_back(h);
            ts.push_back(t);
        }
    }
    void add_to(FakeChain& doge) const
    {
        for (size_t i = 0; i < hashes.size(); ++i)
            doge.add(hashes[i], 6454000 + i * 100, ts[i], kDogeDiff);
        doge.tip = 6470000;
    }
};

fbi::Source doge_source(FakeChain& ltc, FakeChain& doge)
{
    fbi::Source s;
    s.primary_chain = "LTC";
    s.primary = ltc.lookup();
    s.aux["DOGE"] = doge.lookup();
    return s;
}

} // namespace

// ── The rate at find, served and taken ───────────────────────────────────────
// A /recent_merged_blocks row carries pool_hashrate_at_find as a
// /recent_blocks row does, and the import takes it: the importing node, which
// has no rate history over these rounds, serves the same rate.
TEST(ImportEffort, RecentMergedBlocksRoundTripsTheRateAtFind)
{
    DogeSource src;
    const auto served = src.mi.rest_recent_merged_blocks();
    ASSERT_EQ(served.size(), 4u);
    for (const auto& r : served) {
        EXPECT_NEAR(num(r, "pool_hashrate_at_find"), kRate, 1e-3) << r.dump();
        EXPECT_EQ(str(r, "pool_hashrate_source"), "recorded") << r.dump();
    }

    FakeChain ltc, doge;
    src.add_to(doge);
    MiningInterface node(false, nullptr, Blockchain::LITECOIN);
    // Only the rate: the source's effort is not offered here.
    nlohmann::json file = served;
    for (auto& r : file) r.erase("effort_method");
    const auto rep = import_json(node, file, doge_source(ltc, doge));
    EXPECT_EQ(rep.imported, 4u) << rep.summary();
    EXPECT_EQ(rep.rate_refused, 0u);
    const auto rows = node.rest_recent_merged_blocks();
    for (const auto& h : src.hashes) {
        const auto r = row_of(rows, "pow_hash", h);
        EXPECT_NEAR(num(r, "pool_hashrate_at_find"), kRate, 1e-3) << r.dump();
    }
    // With the rate the node computes a single sample of its own.
    const auto r1 = row_of(rows, "pow_hash", src.hashes[1]);
    EXPECT_EQ(str(r1, "effort_method"), "single_sample") << r1.dump();
    EXPECT_NEAR(num(r1, "effort"), kDay * kRate / (kDogeDiff * kT32), 1e-9);
}

// ── The source's effort fills an imported merged row ───────────────────────
// The node has no rate history over the rounds: without the source's figure
// a row is a single sample at best. The source integrated each round over all
// of it -- the same rounds, bounded by the same blocks -- and that figure is
// what the node serves, marked "imported" with the source's coverage. The
// first block stays the 1.0 it is by definition.
TEST(ImportEffort, MergedRowTakesTheSourceEffort)
{
    DogeSource src;
    const auto served = src.mi.rest_recent_merged_blocks();
    FakeChain ltc, doge;
    src.add_to(doge);
    MiningInterface node(false, nullptr, Blockchain::LITECOIN);
    const auto rep = import_json(node, served, doge_source(ltc, doge));
    EXPECT_EQ(rep.imported, 4u);
    // The first row is the source's first block: its 1.0 is no measurement.
    EXPECT_NE(rep.summary().find("source effort taken 3, refused 0, not used 0"), std::string::npos)
        << rep.summary();

    const auto rows = node.rest_recent_merged_blocks();
    EXPECT_EQ(str(row_of(rows, "pow_hash", src.hashes[0]), "effort_method"), "first_block");
    for (size_t i = 1; i < 4; ++i) {
        const auto want = row_of(served, "pow_hash", src.hashes[i]);
        const auto got = row_of(rows, "pow_hash", src.hashes[i]);
        ASSERT_EQ(str(want, "effort_method"), "integrated");
        // The source integrated the round at 1.2x the rate it recorded at find.
        const double round = static_cast<double>(src.ts[i] - src.ts[i - 1]);
        EXPECT_NEAR(num(want, "effort"), round * 1.2 * kRate / (kDogeDiff * kT32), 1e-9);
        EXPECT_EQ(str(got, "effort_method"), "imported") << got.dump();
        EXPECT_DOUBLE_EQ(num(got, "effort"), num(want, "effort"));
        EXPECT_NEAR(num(got, "luck"), 100.0 / num(want, "effort"), 1e-9);
        EXPECT_NEAR(num(got, "history_coverage"), 1.0, 1e-12) << "the source's coverage";
        EXPECT_NEAR(num(got, "effort_covered"), num(want, "effort"), 1e-12);
        EXPECT_TRUE(got["measured"].get<bool>());
        EXPECT_EQ(str(got, "prev_block_hash"), src.hashes[i - 1]);
        EXPECT_EQ(str(got, "luck_method"), "simple_avg");
        EXPECT_NEAR(num(got, "time_to_find"), round, 1e-9) << "this node's own round";
        EXPECT_NEAR(num(got, "expected_time"), round / num(want, "effort"), 1e-6);
    }
}

// ── This node's own measurement, where it covers as much ───────────────────
// A node whose history covers the rounds as fully as the source's keeps its
// own figure: a tie never replaces it. Nothing is written.
TEST(ImportEffort, LocalCoverageAtLeastTheSourcesKeepsTheLocalFigure)
{
    DogeSource src;
    const auto served = src.mi.rest_recent_merged_blocks();
    FakeChain ltc, doge;
    src.add_to(doge);

    MiningInterface node(false, nullptr, Blockchain::LITECOIN);
    // Its own history covers every round, at the rate it recorded.
    feed(node, kT0 - 7200.0, kT0 + 6 * kDay, kRate, kLtcDiff);
    int persisted = 0;
    node.set_found_block_persistence(
        [&persisted](const MiningInterface::FoundBlock&) { ++persisted; return true; },
        [] { return std::vector<MiningInterface::FoundBlock>{}; });
    const auto rep = import_json(node, served, doge_source(ltc, doge));
    EXPECT_EQ(rep.imported, 4u);
    EXPECT_EQ(persisted, 4) << "the four new rows, nothing more";
    const auto rows = node.rest_recent_merged_blocks();
    for (size_t i = 1; i < 4; ++i) {
        const auto got = row_of(rows, "pow_hash", src.hashes[i]);
        EXPECT_EQ(str(got, "effort_method"), "integrated") << got.dump();
        const double round = static_cast<double>(src.ts[i] - src.ts[i - 1]);
        EXPECT_NEAR(num(got, "effort"), round * kRate / (kDogeDiff * kT32), 1e-9)
            << "this node's own integral, not the source's (1.2x)";
        EXPECT_NEAR(num(got, "history_coverage"), 1.0, 1e-12);
    }
    // Again: nothing to fill.
    persisted = 0;
    const auto again = import_json(node, served, doge_source(ltc, doge));
    EXPECT_EQ(again.imported, 0u);
    EXPECT_EQ(again.merged, 0u);
    EXPECT_EQ(again.unchanged, 4u);
    EXPECT_EQ(persisted, 0);
}

// ── A source effort that is not plausibly the pool's ───────────────────────
// Effort is display only, but a forged figure must not put a luck of a
// million percent on the page either. The rate an effort implies over this
// node's own round -- effort * D * 2^32 / round -- is held to the bounds a
// rate at find is: above the share chain's floor, above 1 % of the file's own
// rates, below the whole network's. Malformed figures are refused too; all of
// them are counted. A figure the source does not claim as an integrated,
// watched measurement is not offered at all.
TEST(ImportEffort, ImplausibleSourceEffortIsRefusedAndCounted)
{
    FakeChain ltc;
    ltc.tip = 3300000;
    nlohmann::json file = nlohmann::json::array();
    const double rate = kLtcDiff * kT32 / kDay;   // one block a day
    for (unsigned i = 0; i < 8; ++i) {
        const std::string h = hash_of(0x100 + i);
        const uint64_t t = kT0 + i * static_cast<uint64_t>(kDay);
        ltc.add(h, 3200000 + i, t, kLtcDiff);
        nlohmann::json r{{"hash", h}, {"chain", "LTC"}, {"height", 3200000 + i}, {"ts", t},
                         {"pool_hashrate_at_find", rate}, {"share_difficulty", kShareDiff},
                         {"effort_method", "integrated"}, {"measured", true},
                         {"history_coverage", 0.9}, {"effort", 1.25}};
        if (i > 0) r["prev_block_hash"] = hash_of(0x100 + i - 1);
        file.push_back(r);
    }
    file[0]["effort_method"] = "first_block";
    file[1]["effort"] = 1.25;                       // plausible: taken
    file[2]["effort"] = 1.0e6;                      // the pool above the whole network
    file[3]["effort"] = 1.0e-6;                     // below what its shares allow
    file[4]["history_coverage"] = 1.5;              // malformed
    file[5].erase("prev_block_hash");               // malformed: no round
    file[6]["measured"] = false;                    // not offered: found in the source's gap
    file[7]["effort_method"] = "single_sample";     // not offered: the node's own to compute

    MiningInterface node(false, nullptr, Blockchain::LITECOIN);
    fbi::Source src;
    src.primary_chain = "LTC";
    src.primary = ltc.lookup();
    const auto rep = import_json(node, file, src);
    EXPECT_EQ(rep.imported, 8u);
    EXPECT_EQ(rep.rate_refused, 0u);
    EXPECT_NE(rep.summary().find("source effort taken 1, refused 4, not used 0"),
              std::string::npos) << rep.summary();

    const auto rows = node.rest_recent_blocks();
    const auto taken = row_of(rows, "hash", hash_of(0x101));
    EXPECT_EQ(str(taken, "effort_method"), "imported") << taken.dump();
    EXPECT_DOUBLE_EQ(num(taken, "effort"), 1.25);
    for (unsigned i = 2; i < 8; ++i) {
        const auto r = row_of(rows, "hash", hash_of(0x100 + i));
        EXPECT_EQ(str(r, "effort_method"), "single_sample") << i << " " << r.dump();
        EXPECT_NEAR(num(r, "effort"), 1.0, 1e-9) << "the node's own single sample";
        EXPECT_LT(num(r, "luck"), 1000.0);
    }
}

// ── /recent_blocks: the source's integral beats a single sample ────────────
// An imported LTC row has the rate at find (pool_hashrate_at_find) and, with
// no history of its own, was a single sample. The source integrated the round
// over all of it: that is the row's effort now, and what the period counts.
TEST(ImportEffort, LtcRowTakesTheSourceEffortOverASingleSample)
{
    MiningInterface other(false, nullptr, Blockchain::LITECOIN);
    feed(other, kT0 - 7200.0, kT0 + 6 * kDay, 1.2 * kRate, kLtcDiff);
    FakeChain ltc;
    const double days[4] = {0.0, 1.0, 2.5, 4.0};
    std::vector<std::string> hashes;
    for (unsigned i = 0; i < 4; ++i) {
        const std::string h = hash_of(0x200 + i);
        const uint64_t t = kT0 + static_cast<uint64_t>(days[i] * kDay);
        other.record_found_block(3200000 + i, uint256S(h), t, "LTC", kMiner, h, kLtcDiff,
                                 kShareDiff, kRate, 625000000,
                                 MiningInterface::BlockAuthorship::sharechain_peer);
        ltc.add(h, 3200000 + i, t, kLtcDiff);
        hashes.push_back(h);
    }
    ltc.tip = 3200100;
    const auto served = other.rest_recent_blocks();

    MiningInterface node(false, nullptr, Blockchain::LITECOIN);
    fbi::Source src;
    src.primary_chain = "LTC";
    src.primary = ltc.lookup();
    const auto rep = import_json(node, served, src);
    EXPECT_EQ(rep.imported, 4u);

    const double now = static_cast<double>(kT0) + 4 * kDay + 60.0;
    const auto rows = node.rest_recent_blocks_at(now);
    EXPECT_EQ(str(row_of(rows, "hash", hashes[0]), "effort_method"), "first_block");
    double expected = 1.0;   // the first block
    for (size_t i = 1; i < 4; ++i) {
        const auto want = row_of(served, "hash", hashes[i]);
        const auto got = row_of(rows, "hash", hashes[i]);
        EXPECT_EQ(str(got, "effort_method"), "imported") << got.dump();
        EXPECT_DOUBLE_EQ(num(got, "effort"), num(want, "effort"));
        EXPECT_NEAR(num(got, "history_coverage"), 1.0, 1e-12);
        EXPECT_FALSE(got["luck_approximate"].get<bool>()) << "a fully covered round";
        EXPECT_TRUE(got["avg_hashrate_used"].is_null()) << "no rate of this node's is behind it";
        EXPECT_EQ(str(got, "provenance"), "imported");
        // Not the single sample it was (the rate at find, 1/1.2 of the history's).
        EXPECT_GT(std::fabs(num(got, "effort") - num(want, "effort") / 1.2), 1e-3);
        expected += num(want, "effort");
    }
    EXPECT_EQ(num(rows[0], "imported_luck_count"), 3.0) << rows[0].dump();
    const auto all = node.rest_luck_stats_at(now)["periods"]["all"];
    EXPECT_EQ(all["k"].get<uint64_t>(), 4u) << all.dump();
    EXPECT_NEAR(all["blocks_expected"].get<double>(), expected, 1e-9) << all.dump();
}

// ── The operator's node: import, upgrade, import again, and again ──────────
// The outside operator's LTC + DOGE node, as its dashboard showed it on
// 2026-11-19. Its rate history begins on 11-12, 5.2 % of the way into the
// round that ended in DOGE 6454700 (and LTC 3211872, the block that DOGE
// solve rode). It imported the two files of ltc.voidbind.com with 0.2.12.10,
// which took no source effort:
//   DOGE 6437923 and older: no effort ("--"): no history, no rate in the file;
//   DOGE 6454700:           98.5 % integrated over 5.2 % of the round;
//   DOGE 6463962:           found while the node was up (it learned it from a
//                           peer's share): integrated over all of it.
// After the upgrade the operator imports the same two files again. Each row
// that lacks the source's effort and covers less of its round than the
// source did gains it; 6463962 keeps its own; a third import changes nothing.
// The rows are the files' real values (ltc.voidbind.com, 2026-11-19).
namespace {

const char* kVoidbindRecentBlocks = R"([
{"hash":"f11e7c6c88ac3c37cb593086a6f4d666d7fc8101bd60265be8d24d17b367b72a","chain":"LTC","height":27588573,"ts":1792690954,"network_difficulty":91737839.63838163,"share_difficulty":693.5440248241151,"pool_hashrate_at_find":194452269748.0,"effort":3.2633082564968157,"effort_method":"integrated","history_coverage":0.9456386476055673,"measured":false,"main_chain":false,"prev_block_hash":"62ea7394b708fcb49cd2d1127c0734b5b2d605ea248ec8eea5f93665bb63afb2"},
{"hash":"521906df2ba641bf155313b2574a9196070e97fcdaa64d87c04257aded38e96d","chain":"LTC","height":27272772,"ts":1787831788,"network_difficulty":null,"share_difficulty":785.1381125177094,"pool_hashrate_at_find":14818454121.0,"effort":1.007104366970721,"effort_method":"integrated","history_coverage":0.9917607587056751,"measured":false,"main_chain":false,"prev_block_hash":"62ea7394b708fcb49cd2d1127c0734b5b2d605ea248ec8eea5f93665bb63afb2"},
{"hash":"84024db9063696eabf560504fa15737d6ab15a560441e5bab7fd51bd03571223","chain":"LTC","height":3211872,"ts":1794498365,"network_difficulty":94729203.34146552,"share_difficulty":514.3346070441622,"pool_hashrate_at_find":145082644198.0,"effort":0.5272590076633431,"effort_method":"integrated","history_coverage":1.0,"measured":true,"main_chain":true,"prev_block_hash":"fdb03a27a5b288d9655ee17dd4d9112dcd815a9587db07a2b5b21b6be402255c"},
{"hash":"fdb03a27a5b288d9655ee17dd4d9112dcd815a9587db07a2b5b21b6be402255c","chain":"LTC","height":3204796,"ts":1793436566,"network_difficulty":95864124.33164336,"share_difficulty":709.9291624908818,"pool_hashrate_at_find":205598863308.0,"effort":3.6139514308953773,"effort_method":"integrated","history_coverage":0.9517760347104401,"measured":true,"main_chain":true,"prev_block_hash":"62ea7394b708fcb49cd2d1127c0734b5b2d605ea248ec8eea5f93665bb63afb2"},
{"hash":"62ea7394b708fcb49cd2d1127c0734b5b2d605ea248ec8eea5f93665bb63afb2","chain":"LTC","height":3160570,"ts":1786832375,"network_difficulty":90789408.8020904,"share_difficulty":null,"pool_hashrate_at_find":409927234921.6537,"effort":9.498690441667183,"effort_method":"integrated","history_coverage":0.12320021061147583,"measured":true,"main_chain":true,"prev_block_hash":"e353fe7d65896bfeeab87efec46890ed8f67d5609fc1e365fb76162906075dee"},
{"hash":"e353fe7d65896bfeeab87efec46890ed8f67d5609fc1e365fb76162906075dee","chain":"LTC","height":3085349,"ts":1775491294,"network_difficulty":96307458.34169681,"share_difficulty":null,"pool_hashrate_at_find":null,"effort":1.0,"effort_method":"first_block","history_coverage":null,"measured":true,"main_chain":true,"prev_block_hash":null}
])";

const char* kVoidbindRecentMergedBlocks = R"([
{"pow_hash":"da2714c8e3c4d17214ea4c9daa7d079df8682acbcfea0d9c6068da56e649a6fb","symbol":"DOGE","height":6454700,"ts":1794498365,"parent_hash":"84024db9063696eabf560504fa15737d6ab15a560441e5bab7fd51bd03571223","network_difficulty":37146875.79962987,"effort":1.3911304960028799,"effort_method":"integrated","history_coverage":1.0,"measured":true,"main_chain":true,"prev_block_hash":"b9ed3c3db5272887feafe7156b1f152954810bc1ccd39d99e3d475362a7045e5"},
{"pow_hash":"b9ed3c3db5272887feafe7156b1f152954810bc1ccd39d99e3d475362a7045e5","symbol":"DOGE","height":6437923,"ts":1793436566,"parent_hash":"fdb03a27a5b288d9655ee17dd4d9112dcd815a9587db07a2b5b21b6be402255c","network_difficulty":44166729.705880135,"effort":0.12991402967563126,"effort_method":"integrated","history_coverage":1.0,"measured":true,"main_chain":true,"prev_block_hash":"8e93608a26370cb15782b13b36b39b7b0ab8dc89dbf8531b7dc7d57dddbaef5e"},
{"pow_hash":"8e93608a26370cb15782b13b36b39b7b0ab8dc89dbf8531b7dc7d57dddbaef5e","symbol":"DOGE","height":6436056,"ts":1793318319,"parent_hash":"8bfc06bf81d369372e09cab2d8a548a980bcb165d0bfea200f1008f4076748f4","network_difficulty":38210965.19729772,"effort":0.711745234331286,"effort_method":"integrated","history_coverage":1.0,"measured":true,"main_chain":true,"prev_block_hash":"b5ac47f643a550abe361a1978b2b5ba0eba379b87eb5cb66622bb386faafe28e"},
{"pow_hash":"b5ac47f643a550abe361a1978b2b5ba0eba379b87eb5cb66622bb386faafe28e","symbol":"DOGE","height":6426090,"ts":1792690954,"parent_hash":"f11e7c6c88ac3c37cb593086a6f4d666d7fc8101bd60265be8d24d17b367b72a","network_difficulty":53804967.88060514,"effort":1.8939385615293847,"effort_method":"integrated","history_coverage":0.9912621398972022,"measured":true,"main_chain":true,"prev_block_hash":"17300f9b386285ca506d3737f7a5bfec244680dc784de99430cfefc0dfdb33d6"},
{"pow_hash":"17300f9b386285ca506d3737f7a5bfec244680dc784de99430cfefc0dfdb33d6","symbol":"DOGE","height":6390469,"ts":1790437397,"parent_hash":"9c82a173957e10d7d3bf3bc448152ff2adcdf159dbb0f2acd5a5446aed18f93a","network_difficulty":30530498.72434954,"effort":1.8113757748469794,"effort_method":"integrated","history_coverage":0.951373739976202,"measured":true,"main_chain":true,"prev_block_hash":"ac6346846574ff1ae6fcba26c5247cc0ff23ac5cd956bde38f142dbeb09eb63c"},
{"pow_hash":"ac6346846574ff1ae6fcba26c5247cc0ff23ac5cd956bde38f142dbeb09eb63c","symbol":"DOGE","height":6367875,"ts":1789001801,"parent_hash":"e178d664dadbd35d513d9df28ccc0832a7ba9dd927ec6c3a6f89c0dbfc5eba2a","network_difficulty":46031760.43841846,"effort":0.9261526079323648,"effort_method":"integrated","history_coverage":0.8113294959071963,"measured":true,"main_chain":true,"prev_block_hash":"2f3e4d8aa870c238ff0d8194ef6e36605d1b1fda1f70f269a0800b8fc0d59576"},
{"pow_hash":"2f3e4d8aa870c238ff0d8194ef6e36605d1b1fda1f70f269a0800b8fc0d59576","symbol":"DOGE","height":6349371,"ts":1787831788,"parent_hash":"521906df2ba641bf155313b2574a9196070e97fcdaa64d87c04257aded38e96d","network_difficulty":44984508.97264497,"effort":1.94497719511698,"effort_method":"integrated","history_coverage":0.9917607587056751,"measured":true,"main_chain":true,"prev_block_hash":"60adffcf93ed1c8e0e3e13b33b22764b650f39f459028a5a6b979bd26f75881c"},
{"pow_hash":"60adffcf93ed1c8e0e3e13b33b22764b650f39f459028a5a6b979bd26f75881c","symbol":"DOGE","height":6333587,"ts":1786832375,"parent_hash":"62ea7394b708fcb49cd2d1127c0734b5b2d605ea248ec8eea5f93665bb63afb2","network_difficulty":45535956.88911236,"effort":18.40684441747968,"effort_method":"integrated","history_coverage":0.12320021061147583,"measured":true,"main_chain":true,"prev_block_hash":"eb44867b1dc7e48d29b250e8794fdcb30ded792de291fc250ce62528448be964"},
{"pow_hash":"eb44867b1dc7e48d29b250e8794fdcb30ded792de291fc250ce62528448be964","symbol":"DOGE","height":6154761,"ts":1775491294,"parent_hash":"e353fe7d65896bfeeab87efec46890ed8f67d5609fc1e365fb76162906075dee","network_difficulty":null,"effort":1.0,"effort_method":"first_block","history_coverage":null,"measured":true,"main_chain":true,"prev_block_hash":null},
{"pow_hash":"acc0c3ee323b71f2f59ea81235249c22a352d970feecfbf9f96fc25410c59e66","symbol":"DOGE","height":6463962,"ts":1795083273,"parent_hash":"d9afde83110e5eec36653eeff67da1ed3a671ed43fa6a65986df5cce964df3e6","network_difficulty":42136316.98663563,"effort":0.6022337301473598,"effort_method":"integrated","history_coverage":1.0,"measured":true,"main_chain":true,"prev_block_hash":"da2714c8e3c4d17214ea4c9daa7d079df8682acbcfea0d9c6068da56e649a6fb"}
])";

const std::string kDoge6463962 = "acc0c3ee323b71f2f59ea81235249c22a352d970feecfbf9f96fc25410c59e66";
const std::string kDoge6454700 = "da2714c8e3c4d17214ea4c9daa7d079df8682acbcfea0d9c6068da56e649a6fb";
const std::string kDoge6437923 = "b9ed3c3db5272887feafe7156b1f152954810bc1ccd39d99e3d475362a7045e5";
const std::string kDoge6333587 = "60adffcf93ed1c8e0e3e13b33b22764b650f39f459028a5a6b979bd26f75881c";
const std::string kLtc3211872 = "84024db9063696eabf560504fa15737d6ab15a560441e5bab7fd51bd03571223";
const std::string kLtc3204796 = "fdb03a27a5b288d9655ee17dd4d9112dcd815a9587db07a2b5b21b6be402255c";
const std::string kLtc3160570 = "62ea7394b708fcb49cd2d1127c0734b5b2d605ea248ec8eea5f93665bb63afb2";
// The DOGE rows that were "--" on the operator's dashboard.
const char* const kDogeNoEffort[] = {
    "b9ed3c3db5272887feafe7156b1f152954810bc1ccd39d99e3d475362a7045e5",   // 6437923
    "8e93608a26370cb15782b13b36b39b7b0ab8dc89dbf8531b7dc7d57dddbaef5e",   // 6436056
    "b5ac47f643a550abe361a1978b2b5ba0eba379b87eb5cb66622bb386faafe28e",   // 6426090
    "17300f9b386285ca506d3737f7a5bfec244680dc784de99430cfefc0dfdb33d6",   // 6390469
    "ac6346846574ff1ae6fcba26c5247cc0ff23ac5cd956bde38f142dbeb09eb63c",   // 6367875
    "2f3e4d8aa870c238ff0d8194ef6e36605d1b1fda1f70f269a0800b8fc0d59576",   // 6349371
};

/// The operator's node: its header chains (rooted at the fast-start
/// checkpoints, LTC 3,088,000 and DOGE 6,160,000), its rate history, and the
/// merged manager that learned 6463962 from a peer's share.
struct OperatorNode {
    FakeChain ltc, doge;
    double history_start{0.0};
    static constexpr double kPoolRate = 1.48e11;   // its history's gross pool rate
    OperatorNode()
    {
        ltc.lowest = 3088000;
        doge.lowest = 6160000;
        for (const auto& r : nlohmann::json::parse(kVoidbindRecentBlocks)) {
            if (!r["main_chain"].get<bool>()) continue;   // the two phantoms: no such block
            if (r["height"].get<uint64_t>() < ltc.lowest) continue;   // below its root
            ltc.add(r["hash"].get<std::string>(), r["height"].get<uint64_t>(),
                    r["ts"].get<uint64_t>(), r["network_difficulty"].get<double>());
        }
        for (const auto& r : nlohmann::json::parse(kVoidbindRecentMergedBlocks)) {
            if (r["height"].get<uint64_t>() < doge.lowest) continue;   // below its root
            doge.add(r["pow_hash"].get<std::string>(), r["height"].get<uint64_t>(),
                     r["ts"].get<uint64_t>(), r["network_difficulty"].get<double>());
        }
        ltc.tip = 3220000;
        doge.tip = 6470000;
        // The history begins 5.2 % of the way into the round 6437923 ->
        // 6454700 (1,061,799 s) and runs on past 6463962.
        history_start = 1794498365.0 - 0.052 * (1794498365.0 - 1793436566.0);
    }
    void start(MiningInterface& mi) const
    {
        feed(mi, history_start, 1795083273.0 + 3600.0, kPoolRate, 94729203.34146552);
    }
    fbi::Source source() { return doge_source(ltc, doge); }
};

/// A file as 0.2.12.10 read it: the effort fields were not taken.
nlohmann::json as_read_by_0_2_12_10(const char* text)
{
    auto file = nlohmann::json::parse(text);
    for (auto& r : file)
        for (const char* k : {"effort", "effort_method", "history_coverage", "measured"})
            r.erase(k);
    return file;
}

} // namespace

TEST(ImportEffort, OperatorReimportFillsTheSourceEffortOnceThenChangesNothing)
{
    // The disk: what the node persists, as a build without the effort tail
    // writes it (only the fields that build has).
    using c2pool::storage::FoundBlockRecord;
    using FB = MiningInterface::FoundBlock;
    std::map<std::string, std::vector<uint8_t>> disk;
    int writes = 0;
    auto wire = [&](MiningInterface& mi) {
        mi.set_found_block_persistence(
            [&](const FB& b) {
                FoundBlockRecord rec;
                rec.chain = b.chain; rec.height = b.height; rec.block_hash = b.hash;
                rec.timestamp = b.ts; rec.status = static_cast<uint8_t>(b.status);
                rec.confirmations = b.confirmations; rec.finder_address = b.miner;
                rec.network_difficulty = b.network_difficulty;
                rec.pool_hashrate = b.pool_hashrate; rec.share_difficulty = b.share_difficulty;
                rec.share_hash = b.share_hash;
                rec.authorship = static_cast<uint8_t>(b.authorship);
                rec.parent_hash = b.parent_hash; rec.parent_height = b.parent_height;
                rec.aux_difficulty_known = b.aux_difficulty_known;
                rec.imported = b.imported;
                disk[b.chain + ":" + b.hash] = rec.serialize();
                ++writes;
                return true;
            },
            [&]() {
                std::vector<FB> out;
                for (const auto& [k, bytes] : disk) {
                    const auto rec = FoundBlockRecord::deserialize(bytes);
                    FB b{};
                    b.chain = rec.chain; b.height = rec.height; b.hash = rec.block_hash;
                    b.ts = rec.timestamp;
                    b.status = static_cast<MiningInterface::BlockStatus>(rec.status);
                    b.confirmations = rec.confirmations; b.miner = rec.finder_address;
                    b.network_difficulty = rec.network_difficulty;
                    b.pool_hashrate = rec.pool_hashrate;
                    b.share_difficulty = rec.share_difficulty; b.share_hash = rec.share_hash;
                    b.authorship = static_cast<MiningInterface::BlockAuthorship>(rec.authorship);
                    b.parent_hash = rec.parent_hash; b.parent_height = rec.parent_height;
                    b.aux_difficulty_known = rec.aux_difficulty_known;
                    b.imported = rec.imported;
                    out.push_back(std::move(b));
                }
                return out;
            });
    };

    // 6463962, learned from a peer's share while the node was up.
    boost::asio::io_context ioc;
    c2pool::merged::MergedMiningManager mm{ioc};
    {
        c2pool::merged::DiscoveredMergedBlock blk;
        blk.chain_id = 98;
        blk.symbol = "DOGE";
        blk.height = 6463962;
        blk.block_hash = kDoge6463962;
        blk.parent_hash = "d9afde83110e5eec36653eeff67da1ed3a671ed43fa6a65986df5cce964df3e6";
        blk.timestamp = 1795083273;
        blk.accepted = true;
        blk.miner = kMiner;
        blk.difficulty = 42136316.98663563;
        mm.add_discovered_block(blk);
    }
    OperatorNode op;

    // ── 1. 0.2.12.10 imports both files.
    {
        MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
        op.start(mi);
        mi.set_merged_mining_manager(&mm);
        wire(mi);
        const auto rb = import_json(mi, as_read_by_0_2_12_10(kVoidbindRecentBlocks), op.source());
        const auto rm = import_json(mi, as_read_by_0_2_12_10(kVoidbindRecentMergedBlocks),
                                    op.source());
        EXPECT_EQ(rb.imported, 3u) << rb.summary();   // 2 phantoms, 1 below the root
        EXPECT_EQ(rm.imported, 9u) << rm.summary();   // 6154761 below the root
        const auto merged = mi.rest_recent_merged_blocks();
        // What the operator's dashboard showed.
        for (const char* h : kDogeNoEffort) {
            const auto r = row_of(merged, "pow_hash", h);
            ASSERT_TRUE(r.is_object()) << h;
            EXPECT_TRUE(r["effort"].is_null()) << r.dump();
            EXPECT_TRUE(r["luck"].is_null());
            EXPECT_TRUE(r["history_coverage"].is_null());
            EXPECT_FALSE(r["measured"].get<bool>());
        }
        const auto d = row_of(merged, "pow_hash", kDoge6454700);
        EXPECT_EQ(str(d, "effort_method"), "integrated");
        EXPECT_NEAR(num(d, "history_coverage"), 0.052, 1e-9);
        EXPECT_NEAR(num(d, "effort"), 0.985, 0.001) << "98.5 %: 5 % of the round, scaled up";
        EXPECT_TRUE(d["measured"].get<bool>());
        const auto own = row_of(merged, "pow_hash", kDoge6463962);
        EXPECT_EQ(str(own, "effort_method"), "integrated");
        EXPECT_NEAR(num(own, "history_coverage"), 1.0, 1e-12);
        EXPECT_EQ(str(row_of(mi.rest_recent_blocks(), "hash", kLtc3204796), "effort_method"),
                  "single_sample");
    }

    // ── 2. The fixed build: the node restarts on the same disk and imports
    // the same two files again.
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    op.start(mi);
    mi.set_merged_mining_manager(&mm);
    wire(mi);
    mi.load_persisted_found_blocks();
    const auto local_6463962 = num(row_of(mi.rest_recent_merged_blocks(), "pow_hash", kDoge6463962),
                                   "effort");
    writes = 0;
    const auto rb = import_json(mi, nlohmann::json::parse(kVoidbindRecentBlocks), op.source());
    const auto rm = import_json(mi, nlohmann::json::parse(kVoidbindRecentMergedBlocks),
                                op.source());
    // LTC: 3211872 (5.2 % covered here) and 3204796 (a single sample here)
    // gain the source's; 3160570 is this node's first LTC block.
    EXPECT_EQ(rb.imported, 0u);
    EXPECT_EQ(rb.merged, 2u) << rb.summary();
    EXPECT_EQ(rb.unchanged, 1u);
    EXPECT_NE(rb.summary().find("source effort taken 2, refused 0, not used 1"), std::string::npos)
        << rb.summary();
    // DOGE: the six "--" rows and 6454700 (5.2 % covered here) gain the
    // source's; 6333587 is this node's first DOGE block (6154761 is below
    // its root) and keeps its 1.0; 6463962 keeps its own, covered as fully
    // as the source's.
    EXPECT_EQ(rm.imported, 0u);
    EXPECT_EQ(rm.merged, 7u) << rm.summary();
    EXPECT_EQ(rm.unchanged, 2u);
    EXPECT_NE(rm.summary().find("source effort taken 7, refused 0, not used 2"), std::string::npos)
        << rm.summary();
    EXPECT_EQ(writes, 9) << "each row that gained the effort is written once";

    const auto file = nlohmann::json::parse(kVoidbindRecentMergedBlocks);
    const auto merged = mi.rest_recent_merged_blocks();
    for (const char* h : kDogeNoEffort) {
        const auto want = row_of(file, "pow_hash", h);
        const auto got = row_of(merged, "pow_hash", h);
        EXPECT_EQ(str(got, "effort_method"), "imported") << got.dump();
        EXPECT_DOUBLE_EQ(num(got, "effort"), num(want, "effort"));
        EXPECT_DOUBLE_EQ(num(got, "history_coverage"), num(want, "history_coverage"));
        EXPECT_TRUE(got["measured"].get<bool>());
        EXPECT_EQ(str(got, "prev_block_hash"), str(want, "prev_block_hash"));
    }
    const auto d = row_of(merged, "pow_hash", kDoge6454700);
    EXPECT_EQ(str(d, "effort_method"), "imported");
    EXPECT_DOUBLE_EQ(num(d, "effort"), 1.3911304960028799) << "139.1 %, as the source says";
    EXPECT_NEAR(num(d, "luck"), 71.88398233474783, 1e-9);
    EXPECT_DOUBLE_EQ(num(d, "history_coverage"), 1.0);
    const auto own = row_of(merged, "pow_hash", kDoge6463962);
    EXPECT_EQ(str(own, "effort_method"), "integrated") << own.dump();
    EXPECT_DOUBLE_EQ(num(own, "effort"), local_6463962) << "measured here, over all of it";
    EXPECT_NEAR(num(own, "history_coverage"), 1.0, 1e-12);
    EXPECT_EQ(str(row_of(merged, "pow_hash", kDoge6333587), "effort_method"), "first_block");

    const auto blocks_file = nlohmann::json::parse(kVoidbindRecentBlocks);
    const auto blocks = mi.rest_recent_blocks();
    for (const auto& h : {kLtc3211872, kLtc3204796}) {
        const auto got = row_of(blocks, "hash", h);
        EXPECT_EQ(str(got, "effort_method"), "imported") << got.dump();
        EXPECT_DOUBLE_EQ(num(got, "effort"), num(row_of(blocks_file, "hash", h), "effort"));
    }
    EXPECT_EQ(str(row_of(blocks, "hash", kLtc3160570), "effort_method"), "first_block");

    // ── 3. Once more: nothing changes, nothing is written.
    const auto merged_before = mi.rest_recent_merged_blocks();
    writes = 0;
    const auto rb3 = import_json(mi, nlohmann::json::parse(kVoidbindRecentBlocks), op.source());
    const auto rm3 = import_json(mi, nlohmann::json::parse(kVoidbindRecentMergedBlocks),
                                 op.source());
    EXPECT_EQ(rb3.imported + rb3.merged, 0u) << rb3.summary();
    EXPECT_EQ(rb3.unchanged, 3u);
    EXPECT_EQ(rm3.imported + rm3.merged, 0u) << rm3.summary();
    EXPECT_EQ(rm3.unchanged, 9u);
    EXPECT_NE(rm3.summary().find("source effort taken 0"), std::string::npos) << rm3.summary();
    EXPECT_EQ(writes, 0);
    EXPECT_EQ(mi.rest_recent_merged_blocks(), merged_before);
}
