// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// --import-found-blocks (core/found_block_import.hpp,
// MiningInterface::import_found_blocks / start_found_block_import): a node
// restores the pool's found-block history from another node's /recent_blocks.
//
// An outside LTC operator's dashboard showed ONE found block: the node's
// ledger only knows the blocks it saw itself. These KATs pin the import that
// fills it, with no network: the header chain is a map, the source file is a
// real /recent_blocks dump of another MiningInterface.
//
//   * a valid /recent_blocks file imports, each row's height / time /
//     difficulty taken from THIS node's header chain;
//   * importing it again changes nothing;
//   * a phantom (a hash the chain does not hold), a block below the chain's
//     root, a side-branch block, another chain's row, a duplicate and a
//     malformed entry are refused, each counted by reason;
//   * a row at a wrong height is imported at the header's height;
//   * a row the node recorded itself is never overwritten (fill-only);
//   * the imported rows take part in period luck per the effort model, and a
//     rate at find that is not plausibly the pool's is refused (no absurd
//     luck);
//   * a plain hash list (lines, or a JSON array of strings) imports;
//   * the import waits for the header chain and retries until it is ready;
//   * merged (DOGE) rows need the aux header chain; a coinbase that does not
//     pay the pool's donation is refused where the body is at hand; the
//     provenance survives a restart (fblk extension byte, no version bump)
//     and a later record by the node itself supersedes it.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>

#include <c2pool/storage/found_block_record_map.hpp>
#include <c2pool/storage/found_block_store.hpp>
#include <core/found_block_import.hpp>
#include <core/uint256.hpp>
#include <core/web_server.hpp>
#include <impl/ltc/found_block_pool_check.hpp>

using core::MiningInterface;
using c2pool::address::Blockchain;
namespace fbi = core::found_block_import;

namespace {

constexpr double kT32 = 4294967296.0;
const std::string kMinerA = "LVypi56LPcT9jR3e5Y5AdoVc5EGdrVk26F";
const std::string kMinerB = "LTpYZG19YmfvY2bQDYfQ5HpxT6XsGHEFnF";

std::string hash_of(unsigned tag)
{
    std::ostringstream os;
    os << std::hex << tag;
    const std::string tail = os.str();
    return std::string(64 - tail.size(), 'c') + tail;
}

/// A header chain as a map (hash -> entry), with a tip, a root and a sync flag.
struct FakeChain {
    struct Entry { uint64_t height; uint64_t ts; double difficulty; bool main; };
    std::map<std::string, Entry> entries;
    uint64_t tip{0};
    uint64_t lowest{0};
    std::function<bool()> synced = [] { return true; };
    int asked{0};

    void add(const std::string& hash, uint64_t height, uint64_t ts, double difficulty,
             bool main = true)
    {
        entries[hash] = {height, ts, difficulty, main};
        if (main && height > tip) tip = height;
    }
    fbi::ChainLookup lookup()
    {
        fbi::ChainLookup l;
        l.header = [this](const std::string& hash) {
            ++asked;
            fbi::Header h;
            auto it = entries.find(hash);
            if (it == entries.end()) return h;
            h.known = true;
            h.main_chain = it->second.main;
            h.height = it->second.height;
            h.ts = it->second.ts;
            h.difficulty = it->second.difficulty;
            h.tip_height = tip;
            return h;
        };
        l.ready = [this] { return synced(); };
        l.lowest_height = [this] { return lowest; };
        return l;
    }
};

fbi::Source source_over(FakeChain& ltc)
{
    fbi::Source s;
    s.primary_chain = "LTC";
    s.primary = ltc.lookup();
    return s;
}

fbi::Report import_text(MiningInterface& mi, const std::string& text, const fbi::Source& src,
                        uint64_t* malformed = nullptr)
{
    const auto parsed = fbi::parse(text);
    EXPECT_TRUE(parsed.error.empty()) << parsed.error;
    if (malformed) *malformed = parsed.malformed;
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

uint64_t rejected(const fbi::Report& r, const char* reason)
{
    auto it = r.rejected.find(reason);
    return it == r.rejected.end() ? 0 : it->second;
}

/// Rows of `chain` refused for `reason`.
uint64_t rejected_on(const fbi::Report& r, const std::string& chain, const char* reason)
{
    auto c = r.rejected_by_chain.find(chain);
    if (c == r.rejected_by_chain.end()) return 0;
    auto it = c->second.find(reason);
    return it == c->second.end() ? 0 : it->second;
}

// The pool every fixture runs: LTC difficulty D, a rate that finds one block
// a day at D, winning shares of difficulty 500.
constexpr double kD = 9.5e7;
constexpr double kRate = kD * kT32 / 86400.0;   // effort 1.0 per day
constexpr double kShareDiff = 500.0;
constexpr uint64_t kT0 = 1790000000;            // 2026-09-21

/// Another node: three blocks recorded there, served as /recent_blocks.
std::string source_node_recent_blocks(const std::vector<std::pair<unsigned, uint64_t>>& blocks)
{
    MiningInterface other(false, nullptr, Blockchain::LITECOIN);
    uint64_t height = 3200000;
    for (const auto& [tag, ts] : blocks) {
        const std::string h = hash_of(tag);
        other.record_found_block(++height, uint256S(h), ts, "LTC", kMinerA, h, kD, kShareDiff,
                                 kRate, 625000000,
                                 MiningInterface::BlockAuthorship::sharechain_peer);
    }
    return other.rest_recent_blocks().dump();
}

} // namespace

// ── A valid /recent_blocks file ──────────────────────────────────────────────
// The file is a real /recent_blocks dump of another node. Every row gets in,
// and what makes it a row is THIS node's header chain: the height, the time
// and the difficulty are the header's (here deliberately unlike the file's),
// the rest is the source's word, and the row says so (provenance).
TEST(FoundBlockImport, ValidRecentBlocksFileImports)
{
    const std::string json = source_node_recent_blocks(
        {{0x1, kT0}, {0x2, kT0 + 86400}, {0x3, kT0 + 2 * 86400}});

    FakeChain ltc;
    const double header_diff = 1.01e8;
    ltc.add(hash_of(0x1), 3200001, kT0 + 11, header_diff);
    ltc.add(hash_of(0x2), 3200002, kT0 + 86400 + 11, header_diff);
    ltc.add(hash_of(0x3), 3200003, kT0 + 2 * 86400 + 11, header_diff);
    ltc.tip = 3200100;

    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    std::vector<MiningInterface::FoundBlock> written;
    mi.set_found_block_persistence(
        [&written](const MiningInterface::FoundBlock& b) { written.push_back(b); return true; },
        [] { return std::vector<MiningInterface::FoundBlock>{}; });

    const auto rep = import_text(mi, json, source_over(ltc));
    EXPECT_EQ(rep.rows, 3u);
    EXPECT_EQ(rep.imported, 3u) << rep.summary();
    EXPECT_EQ(rep.rejected_total(), 0u) << rep.summary();
    EXPECT_EQ(rep.height_corrected, 0u);
    EXPECT_EQ(rep.rate_refused, 0u);
    EXPECT_TRUE(rep.deferred.empty());

    const auto rows = mi.rest_recent_blocks();
    ASSERT_EQ(rows.size(), 3u) << rows.dump(1);
    for (unsigned tag : {0x1u, 0x2u, 0x3u}) {
        const auto r = row_of(rows, "hash", hash_of(tag));
        ASSERT_TRUE(r.is_object()) << tag;
        EXPECT_EQ(str(r, "provenance"), "imported");
        EXPECT_FALSE(r["found_locally"].get<bool>()) << "another node's record, not this node's";
        EXPECT_EQ(str(r, "found_by"), "unknown");
        EXPECT_EQ(str(r, "status"), "confirmed") << "98 deep on this node's best chain";
        EXPECT_EQ(str(r, "chain"), "LTC");
        EXPECT_EQ(str(r, "miner"), kMinerA);
        EXPECT_EQ(str(r, "share"), hash_of(tag));
        EXPECT_NEAR(num(r, "network_difficulty"), header_diff, 1e-6) << "the header's bits win";
        EXPECT_NEAR(num(r, "pool_hashrate_at_find"), kRate, kRate * 1e-12);
        EXPECT_TRUE(r["main_chain"].get<bool>());
    }
    const auto r1 = row_of(rows, "hash", hash_of(0x1));
    const auto r3 = row_of(rows, "hash", hash_of(0x3));
    EXPECT_EQ(r3["height"].get<uint64_t>(), 3200003u);
    EXPECT_EQ(r3["ts"].get<uint64_t>(), kT0 + 2 * 86400 + 11) << "the header's time wins";
    EXPECT_EQ(str(r1, "effort_method"), "first_block");
    EXPECT_EQ(str(r3, "effort_method"), "single_sample");
    EXPECT_EQ(str(r3, "prev_block_hash"), hash_of(0x2));
    // relayed: luck computed like any row's, learned rather than recorded.
    EXPECT_EQ(str(r3, "luck_method"), "relayed");
    const double effort = 86400.0 * kRate / (header_diff * kT32);
    EXPECT_NEAR(num(r3, "effort"), effort, effort * 1e-9);

    // Persisted, flagged.
    ASSERT_EQ(written.size(), 3u);
    for (const auto& b : written) {
        EXPECT_TRUE(b.imported);
        EXPECT_EQ(b.status, MiningInterface::BlockStatus::confirmed);
    }
}

// ── Idempotent ───────────────────────────────────────────────────────────────
TEST(FoundBlockImport, ReimportChangesNothing)
{
    const std::string json = source_node_recent_blocks({{0x11, kT0}, {0x12, kT0 + 3600}});
    FakeChain ltc;
    ltc.add(hash_of(0x11), 3200001, kT0, kD);
    ltc.add(hash_of(0x12), 3200002, kT0 + 3600, kD);
    ltc.tip = 3200050;

    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    size_t writes = 0;
    mi.set_found_block_persistence(
        [&writes](const MiningInterface::FoundBlock&) { ++writes; return true; },
        [] { return std::vector<MiningInterface::FoundBlock>{}; });

    const auto first = import_text(mi, json, source_over(ltc));
    EXPECT_EQ(first.imported, 2u);
    const size_t writes_after_first = writes;
    const std::string before = mi.rest_recent_blocks_at(kT0 + 7200.0).dump();

    const auto again = import_text(mi, json, source_over(ltc));
    EXPECT_EQ(again.imported, 0u);
    EXPECT_EQ(again.merged, 0u);
    EXPECT_EQ(again.unchanged, 2u) << again.summary();
    EXPECT_EQ(again.rejected_total(), 0u);
    EXPECT_EQ(writes, writes_after_first) << "nothing to write the second time";
    EXPECT_EQ(mi.get_found_blocks().size(), 2u);
    EXPECT_EQ(mi.rest_recent_blocks_at(kT0 + 7200.0).dump(), before);
}

// ── Phantoms and foreign rows ────────────────────────────────────────────────
// Only a hash THIS node's header chain holds on its best chain gets in.
TEST(FoundBlockImport, PhantomAndForeignRowsAreRefusedByReason)
{
    FakeChain ltc;
    ltc.lowest = 3088000;   // the default mainnet header checkpoint
    ltc.add(hash_of(0x21), 3200001, kT0, kD);
    ltc.add(hash_of(0x22), 3200002, kT0 + 600, kD, /*main=*/false);   // a side branch
    ltc.tip = 3200100;

    auto row = [](unsigned tag, uint64_t height, const char* chain) {
        return nlohmann::json{{"hash", hash_of(tag)}, {"height", height}, {"ts", kT0},
                              {"chain", chain}};
    };
    nlohmann::json file = nlohmann::json::array({
        row(0x21, 3200001, "LTC"),                  // real
        row(0x23, 3200003, "LTC"),                  // phantom: the chain spans it, holds no such hash
        row(0x24, 3000000, "LTC"),                  // below the header chain's root
        row(0x22, 3200002, "LTC"),                  // a side-branch block
        row(0x25, 800000, "BTC"),                   // another chain
        row(0x26, 3200004, "tLTC"),                 // this coin, another network
        row(0x27, 6454700, "DOGE"),                 // a merged chain this node cannot check
        row(0x21, 3200001, "LTC"),                  // duplicate
        nlohmann::json(5),                          // malformed: not a row
        nlohmann::json{{"height", 3200009}},        // malformed: no hash
        nlohmann::json{{"hash", hash_of(0x28)}, {"height", -1}},   // malformed height
        nlohmann::json{{"hash", "zz"}},             // malformed hash
    });

    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    uint64_t malformed = 0;
    const auto rep = import_text(mi, file.dump(), source_over(ltc), &malformed);
    EXPECT_EQ(malformed, 4u);
    EXPECT_EQ(rep.imported, 1u) << rep.summary();
    EXPECT_EQ(rejected(rep, fbi::kNotOnChain), 1u);
    EXPECT_EQ(rejected(rep, fbi::kBelowHeaderChain), 1u);
    EXPECT_EQ(rejected(rep, fbi::kNotMainChain), 1u);
    EXPECT_EQ(rejected(rep, fbi::kOtherChain), 2u);
    EXPECT_EQ(rejected(rep, fbi::kMergedUnvalidated), 1u);
    EXPECT_EQ(rejected(rep, fbi::kDuplicate), 1u);

    const auto blocks = mi.get_found_blocks();
    ASSERT_EQ(blocks.size(), 1u);
    EXPECT_EQ(blocks[0].hash, hash_of(0x21));

    // No header chain at all (an RPC-mode node): nothing can be validated.
    MiningInterface rpc_node(false, nullptr, Blockchain::LITECOIN);
    fbi::Source none;
    none.primary_chain = "LTC";
    const auto r2 = import_text(rpc_node, file.dump(), none);
    EXPECT_EQ(r2.imported, 0u);
    EXPECT_EQ(rejected(r2, fbi::kNoHeaderChain), 4u) << r2.summary();
    EXPECT_TRUE(rpc_node.get_found_blocks().empty());
}

// ── Heights ──────────────────────────────────────────────────────────────────
// The header of a hash fixes its height. A pre-fix LTC peer row stored the
// share ABSHEIGHT (27707625 for block 3211872): imported at 3211872. A row
// without a height takes the header's.
TEST(FoundBlockImport, WrongOrMissingHeightIsRepairedFromTheHeader)
{
    FakeChain ltc;
    ltc.add(hash_of(0x31), 3211872, kT0, kD);
    ltc.add(hash_of(0x32), 3211900, kT0 + 4000, kD);
    ltc.tip = 3212000;
    nlohmann::json file = nlohmann::json::array({
        {{"hash", hash_of(0x31)}, {"height", 27707625}, {"number", 27707625}, {"chain", "LTC"}},
        {{"hash", hash_of(0x32)}, {"chain", "LTC"}},
    });
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    const auto rep = import_text(mi, file.dump(), source_over(ltc));
    EXPECT_EQ(rep.imported, 2u);
    EXPECT_EQ(rep.height_corrected, 1u);
    EXPECT_EQ(rep.height_filled, 1u);
    const auto rows = mi.rest_recent_blocks();
    EXPECT_EQ(row_of(rows, "hash", hash_of(0x31))["height"].get<uint64_t>(), 3211872u);
    EXPECT_EQ(row_of(rows, "hash", hash_of(0x32))["height"].get<uint64_t>(), 3211900u);
    EXPECT_EQ(row_of(rows, "hash", hash_of(0x32))["ts"].get<uint64_t>(), kT0 + 4000);
}

// ── Fill-only ────────────────────────────────────────────────────────────────
// A block the node recorded itself keeps everything it recorded -- its finder,
// its rate, its time, its status, its authorship -- and gains only what it
// lacked.
TEST(FoundBlockImport, ExistingRowIsNeverOverwritten)
{
    const std::string h = hash_of(0x41);
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    mi.record_found_block(3200001, uint256S(h), kT0, "LTC", kMinerA, h, kD, kShareDiff, kRate,
                          /*subsidy=*/0, MiningInterface::BlockAuthorship::this_node);

    FakeChain ltc;
    ltc.add(h, 3200001, kT0 + 30, 1.2e8);
    ltc.tip = 3200100;
    nlohmann::json file = nlohmann::json::array({{
        {"hash", h}, {"height", 3200001}, {"ts", kT0 + 999}, {"chain", "LTC"},
        {"miner", kMinerB}, {"share", h}, {"pool_hashrate_at_find", 2.0 * kRate},
        {"network_difficulty", 1.3e8}, {"share_difficulty", 700.0},
        {"subsidy", 625000000}, {"coinbase_txid", hash_of(0x4c1)}, {"tx_count", 12},
    }});
    const auto rep = import_text(mi, file.dump(), source_over(ltc));
    EXPECT_EQ(rep.imported, 0u);
    EXPECT_EQ(rep.merged, 1u) << rep.summary();

    const auto r = row_of(mi.rest_recent_blocks(), "hash", h);
    ASSERT_TRUE(r.is_object());
    EXPECT_EQ(str(r, "miner"), kMinerA);
    EXPECT_NEAR(num(r, "pool_hashrate_at_find"), kRate, kRate * 1e-12);
    EXPECT_NEAR(num(r, "network_difficulty"), kD, 1e-6);
    EXPECT_NEAR(num(r, "share_difficulty"), kShareDiff, 1e-9);
    EXPECT_EQ(r["ts"].get<uint64_t>(), kT0);
    EXPECT_EQ(str(r, "status"), "pending") << "the import never gives a verdict on a held row";
    EXPECT_EQ(str(r, "found_by"), "this_node");
    EXPECT_EQ(str(r, "provenance"), "recorded");
    EXPECT_TRUE(r["found_locally"].get<bool>());
    // What it lacked.
    EXPECT_EQ(r["subsidy"].get<uint64_t>(), 625000000u);
    EXPECT_EQ(str(r, "coinbase_txid"), hash_of(0x4c1));
    EXPECT_EQ(r["tx_count"].get<uint32_t>(), 12u);
}

// ── Luck ─────────────────────────────────────────────────────────────────────
// The node holds its own block B0; the history before it comes in. No rate
// history covers the imported rounds, so each is single_sample at the rate
// the source recorded at find. One imported rate is not plausibly the pool's
// (1 H/s on a pool the rest of the file puts at ~5 TH/s): refused, so its
// round has no effort -- it still ends the round before B0 and is a block, it
// is just left out of the count with its round (k_unmeasured). Never a luck
// of millions of percent.
TEST(FoundBlockImport, LuckPeriodsCountTheImportedRows)
{
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    const std::string b0 = hash_of(0x50);
    mi.record_found_block(3200010, uint256S(b0), kT0, "LTC", kMinerA, b0, kD, kShareDiff, kRate,
                          625000000, MiningInterface::BlockAuthorship::this_node);
    // Before the import: one block, by definition one found for one expected.
    auto stats = mi.rest_luck_stats_at(kT0 + 1.0);
    EXPECT_EQ(stats["periods"]["all"]["k"].get<uint64_t>(), 1u);

    FakeChain ltc;
    const uint64_t ta = kT0 - 3 * 86400, tb = kT0 - 2 * 86400, tc = kT0 - 86400,
                   tx = kT0 - 43200;
    ltc.add(hash_of(0x51), 3199000, ta, kD);
    ltc.add(hash_of(0x52), 3199500, tb, kD);
    ltc.add(hash_of(0x53), 3199900, tc, kD);
    ltc.add(hash_of(0x54), 3199950, tx, kD);
    ltc.add(b0, 3200010, kT0, kD);
    ltc.tip = 3200100;
    auto row = [](unsigned tag, uint64_t ts, double rate, double share_diff) {
        nlohmann::json j{{"hash", hash_of(tag)}, {"ts", ts}, {"chain", "LTC"},
                         {"pool_hashrate_at_find", rate}};
        if (share_diff > 0.0) j["share_difficulty"] = share_diff;
        return j;
    };
    nlohmann::json file = nlohmann::json::array({
        row(0x51, ta, kRate, kShareDiff), row(0x52, tb, kRate, kShareDiff),
        row(0x53, tc, kRate, kShareDiff),
        row(0x54, tx, 1.0, 0.0),   // no share difficulty: the file's own rates are the yardstick
    });
    const auto rep = import_text(mi, file.dump(), source_over(ltc));
    EXPECT_EQ(rep.imported, 4u) << rep.summary();
    EXPECT_EQ(rep.rate_refused, 1u);

    const double now = kT0 + 3600.0;
    const auto rows = mi.rest_recent_blocks_at(now);
    const auto ra = row_of(rows, "hash", hash_of(0x51));
    const auto rb = row_of(rows, "hash", hash_of(0x52));
    const auto rx = row_of(rows, "hash", hash_of(0x54));
    const auto r0 = row_of(rows, "hash", b0);
    EXPECT_EQ(str(ra, "effort_method"), "first_block");
    EXPECT_EQ(str(rb, "effort_method"), "single_sample");
    EXPECT_NEAR(num(rb, "effort"), 1.0, 1e-9);
    EXPECT_NEAR(num(rb, "luck"), 100.0, 1e-6);
    EXPECT_EQ(str(rx, "luck_method"), "hashrate_unavailable");
    EXPECT_TRUE(rx["pool_hashrate_at_find"].is_null()) << "1 H/s is not the pool's rate";
    EXPECT_TRUE(rx["luck"].is_null());
    EXPECT_TRUE(rx["main_chain"].get<bool>());
    // The node's own block is timed from the newest imported block before it.
    EXPECT_EQ(str(r0, "prev_block_hash"), hash_of(0x54));
    EXPECT_EQ(str(r0, "effort_method"), "single_sample");
    EXPECT_NEAR(num(r0, "effort"), 0.5, 1e-9);
    EXPECT_EQ(str(r0, "provenance"), "recorded");

    // all: A (first block: 1), B (1), C (1), X (no effort: left out), B0 (0.5).
    stats = mi.rest_luck_stats_at(now);
    const auto all = stats["periods"]["all"];
    EXPECT_EQ(all["k"].get<uint64_t>(), 4u) << all.dump();
    EXPECT_EQ(all["k_unmeasured"].get<uint64_t>(), 1u);
    EXPECT_NEAR(all["blocks_expected"].get<double>(), 3.5, 1e-9);
    EXPECT_NEAR(all["luck"].get<double>(), 400.0 / 3.5, 1e-6);
    // 1d: C at kT0 - 86400 sits on the window's start; B0's round is inside.
    for (const auto& b : stats["blocks"])
        if (b["luck"].is_number())
            EXPECT_LT(b["luck"].get<double>(), 1000.0) << b.dump();
}

// A rate at find above the whole network's, or below what the share chain
// allows, is not stored: such a row gets hashrate_unavailable, not an absurd
// luck either way.
TEST(FoundBlockImport, ImplausibleImportedRatesAreRefused)
{
    FakeChain ltc;
    ltc.add(hash_of(0x61), 3200001, kT0, kD);
    ltc.add(hash_of(0x62), 3200002, kT0 + 86400, kD);
    ltc.add(hash_of(0x63), 3200003, kT0 + 2 * 86400, kD);
    ltc.tip = 3200100;
    const double network_rate = kD * kT32 / 150.0;
    nlohmann::json file = nlohmann::json::array({
        {{"hash", hash_of(0x61)}, {"pool_hashrate_at_find", kRate}, {"share_difficulty", kShareDiff}},
        {{"hash", hash_of(0x62)}, {"pool_hashrate_at_find", 2.0 * network_rate}},
        {{"hash", hash_of(0x63)}, {"pool_hashrate_at_find", 4.0e6}, {"share_difficulty", kShareDiff}},
    });
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    const auto rep = import_text(mi, file.dump(), source_over(ltc));
    EXPECT_EQ(rep.imported, 3u);
    EXPECT_EQ(rep.rate_refused, 2u) << rep.summary();
    const auto rows = mi.rest_recent_blocks();
    for (unsigned tag : {0x62u, 0x63u}) {
        const auto r = row_of(rows, "hash", hash_of(tag));
        EXPECT_TRUE(r["pool_hashrate_at_find"].is_null()) << r.dump();
        EXPECT_EQ(str(r, "luck_method"), "hashrate_unavailable");
    }
}

// ── A plain list of hashes ───────────────────────────────────────────────────
TEST(FoundBlockImport, PlainHashListImports)
{
    FakeChain ltc;
    ltc.add(hash_of(0x71), 3200001, kT0, kD);
    ltc.add(hash_of(0x72), 3200002, kT0 + 600, kD);
    ltc.tip = 3200100;

    std::string upper = hash_of(0x72);
    for (auto& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    const std::string text = "# pool blocks\n\n" + hash_of(0x71) + "\n  " + upper + "  \r\n"
                             "not-a-hash\n" + hash_of(0x71) + "\n";
    const auto parsed = fbi::parse(text);
    EXPECT_EQ(parsed.format, "hash_list");
    EXPECT_EQ(parsed.rows.size(), 3u);
    EXPECT_EQ(parsed.malformed, 1u);

    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    const auto rep = mi.import_found_blocks(parsed.rows, source_over(ltc));
    EXPECT_EQ(rep.imported, 2u) << rep.summary();
    EXPECT_EQ(rep.height_filled, 2u);
    EXPECT_EQ(rejected(rep, fbi::kDuplicate), 1u);
    const auto rows = mi.rest_recent_blocks();
    const auto r2 = row_of(rows, "hash", hash_of(0x72));
    EXPECT_EQ(r2["height"].get<uint64_t>(), 3200002u);
    EXPECT_EQ(r2["ts"].get<uint64_t>(), kT0 + 600);
    EXPECT_NEAR(num(r2, "network_difficulty"), kD, 1e-6);
    EXPECT_EQ(str(r2, "chain"), "LTC");
    EXPECT_EQ(str(r2, "provenance"), "imported");
    EXPECT_EQ(str(r2, "luck_method"), "hashrate_unavailable") << "no rate in a hash list";

    // A JSON array of strings is the same list.
    const auto arr = fbi::parse("[\"" + hash_of(0x71) + "\", \"" + hash_of(0x72) + "\"]");
    EXPECT_EQ(arr.format, "json");
    ASSERT_EQ(arr.rows.size(), 2u);
    EXPECT_EQ(arr.rows[1].hash, hash_of(0x72));

    // Not a list at all.
    EXPECT_FALSE(fbi::parse("").error.empty());
    EXPECT_FALSE(fbi::parse("{\"hello\": 1}").error.empty());
    EXPECT_FALSE(fbi::parse("[{\"hash\": ").error.empty());
}

// ── The import waits for the header chain ────────────────────────────────────
// Rows are imported only once the chain can judge them. Before that they wait
// (nothing is written), and the startup one-shot retries until it is ready.
TEST(FoundBlockImport, ImportWaitsUntilTheHeaderChainIsReady)
{
    FakeChain ltc;
    ltc.add(hash_of(0x81), 3200001, kT0, kD);
    ltc.add(hash_of(0x82), 3200002, kT0 + 600, kD);
    ltc.tip = 3200100;
    int ready_calls = 0;
    ltc.synced = [&ready_calls] { return ++ready_calls > 3; };   // syncing for 3 passes

    const std::string text = hash_of(0x81) + "\n" + hash_of(0x82) + "\n";

    // One pass: everything waits, nothing is asked, nothing is written.
    {
        MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
        FakeChain never;
        never.add(hash_of(0x81), 3200001, kT0, kD);
        never.synced = [] { return false; };
        const auto parsed = fbi::parse(text);
        const auto rep = mi.import_found_blocks(parsed.rows, source_over(never));
        EXPECT_EQ(rep.imported, 0u);
        EXPECT_EQ(rep.deferred.size(), 2u);
        EXPECT_EQ(rep.rejected_total(), 0u);
        EXPECT_EQ(never.asked, 0) << "a chain that is not ready is not asked";
        EXPECT_TRUE(mi.get_found_blocks().empty());
    }

    // The startup one-shot retries on the event loop until the chain is ready.
    boost::asio::io_context ioc;
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    mi.set_io_context(&ioc);
    std::optional<fbi::Report> done;
    mi.start_found_block_import(fbi::parse(text), source_over(ltc), std::chrono::milliseconds(5),
                                [&done](const fbi::Report& r) { done = r; });
    EXPECT_FALSE(done.has_value()) << "the first pass waits";
    EXPECT_TRUE(mi.get_found_blocks().empty());
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (!done && std::chrono::steady_clock::now() < deadline)
        ioc.run_for(std::chrono::milliseconds(20));
    ASSERT_TRUE(done.has_value());
    EXPECT_EQ(done->rows, 2u);
    EXPECT_EQ(done->imported, 2u) << done->summary();
    EXPECT_TRUE(done->deferred.empty());
    EXPECT_GE(ready_calls, 4);
    EXPECT_EQ(mi.get_found_blocks().size(), 2u);
}

// ── Merged (DOGE) rows ───────────────────────────────────────────────────────
// A merged row gets in only if the AUX header chain holds it; its difficulty
// is the aux header's, its parent the LTC block this node's chain holds. It is
// a /recent_merged_blocks row, never a /recent_blocks one. What the DOGE chain
// refuses is counted as DOGE's, against the DOGE chain's own root
// (checkpoint 6,160,000): 6154761 is below it.
TEST(FoundBlockImport, MergedRowsNeedTheAuxHeaderChain)
{
    FakeChain ltc, doge;
    ltc.lowest = 3088000;
    ltc.add(hash_of(0x91), 3200001, kT0, kD);
    ltc.tip = 3200100;
    const double doge_diff = 3.3e7;
    doge.lowest = 6160000;
    doge.add(hash_of(0xd1), 6454700, kT0 + 5, doge_diff);
    doge.tip = 6455000;
    auto src = source_over(ltc);
    src.aux["DOGE"] = doge.lookup();

    // /recent_merged_blocks rows: pow_hash, symbol.
    nlohmann::json file = nlohmann::json::array({
        {{"pow_hash", hash_of(0xd1)}, {"symbol", "DOGE"}, {"height", 6454700},
         {"parent_hash", hash_of(0x91)}, {"network_difficulty", 9.5e7}},
        {{"pow_hash", hash_of(0xd2)}, {"symbol", "DOGE"}, {"height", 6454800}},   // phantom
        {{"pow_hash", hash_of(0xd3)}, {"symbol", "DOGE"}, {"height", 6154761}},   // below the root
    });
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    const auto rep = import_text(mi, file.dump(), src);
    EXPECT_EQ(rep.imported, 1u) << rep.summary();
    EXPECT_EQ(rep.imported_aux, 1u);
    EXPECT_EQ(rep.imported_by_chain.at("DOGE"), 1u);
    EXPECT_EQ(rejected_on(rep, "DOGE", fbi::kNotOnChain), 1u) << rep.summary();
    EXPECT_EQ(rejected_on(rep, "DOGE", fbi::kBelowHeaderChain), 1u);
    EXPECT_EQ(rejected_on(rep, "LTC", fbi::kBelowHeaderChain), 0u)
        << "6154761 is a DOGE height: the LTC root says nothing about it";
    EXPECT_NE(rep.summary().find("DOGE: below_header_chain=1 not_on_chain=1"), std::string::npos)
        << rep.summary();

    // A node without the DOGE header chain cannot check any of them.
    MiningInterface no_doge(false, nullptr, Blockchain::LITECOIN);
    const auto r2 = import_text(no_doge, file.dump(), source_over(ltc));
    EXPECT_EQ(r2.imported, 0u);
    EXPECT_EQ(rejected_on(r2, "DOGE", fbi::kMergedUnvalidated), 3u) << r2.summary();

    EXPECT_TRUE(mi.rest_recent_blocks().empty()) << "a merged find is not a block of this chain";
    const auto r = row_of(mi.rest_recent_merged_blocks(), "pow_hash", hash_of(0xd1));
    ASSERT_TRUE(r.is_object());
    EXPECT_NEAR(num(r, "network_difficulty"), doge_diff, 1e-6)
        << "the aux header's, never the file's (which may be the parent's)";
    EXPECT_EQ(str(r, "parent_hash"), hash_of(0x91));
    const auto blocks = mi.get_found_blocks();
    ASSERT_EQ(blocks.size(), 1u);
    EXPECT_EQ(blocks[0].chain, "DOGE");
    EXPECT_TRUE(blocks[0].aux_difficulty_known);
    ASSERT_TRUE(blocks[0].parent_height.has_value());
    EXPECT_EQ(*blocks[0].parent_height, 3200001u);
}

// ── Two files in one run: the parent chain's and the merged chain's ────────
// What an outside operator does against a public node:
//   curl .../recent_blocks > blocks.json; curl .../recent_merged_blocks > merged.json
//   --import-found-blocks blocks.json --import-found-blocks merged.json
// Both dumps are real ones of another node shaped like ltc.voidbind.com's:
// 6 LTC rows, 2 of them phantoms (stored at the share absheight, never on the
// chain); 9 DOGE rows 6154761..6454700, the first below the DOGE header
// chain's checkpoint 6,160,000. Each file gets its summary, then the total;
// every refusal is counted against its own chain.
TEST(FoundBlockImport, ParentAndMergedFilesImportInOneRun)
{
    MiningInterface other(false, nullptr, Blockchain::LITECOIN);
    FakeChain ltc, doge;
    ltc.lowest = 3088000;
    doge.lowest = 6160000;
    const double doge_diff = 3.3e7;
    for (unsigned i = 0; i < 4; ++i) {
        const std::string h = hash_of(0x100 + i);
        other.record_found_block(3200001 + i, uint256S(h), kT0 + i * 86400, "LTC", kMinerA, h,
                                 kD, kShareDiff, kRate, 625000000,
                                 MiningInterface::BlockAuthorship::sharechain_peer);
        ltc.add(h, 3200001 + i, kT0 + i * 86400, kD);
    }
    for (unsigned i = 0; i < 2; ++i) {   // phantoms: the share absheight, no such block
        const std::string h = hash_of(0x1f0 + i);
        other.record_found_block(27588573 + i * 27, uint256S(h), kT0 + 3600 + i * 600, "LTC",
                                 kMinerA, h, kD, kShareDiff, kRate, 625000000,
                                 MiningInterface::BlockAuthorship::sharechain_peer);
    }
    ltc.tip = 3200200;
    const uint64_t doge_heights[9] = {6154761, 6200000, 6250000, 6300000, 6350000,
                                      6400000, 6430000, 6450000, 6454700};
    for (unsigned i = 0; i < 9; ++i) {
        const std::string h = hash_of(0xd00 + i);
        other.record_found_block(doge_heights[i], uint256S(h), kT0 + i * 7200, "DOGE", kMinerA, "",
                                 doge_diff, 0.0, 0.0, 1000000000000ULL,
                                 MiningInterface::BlockAuthorship::sharechain_peer);
        if (doge_heights[i] >= doge.lowest)
            doge.add(h, doge_heights[i], kT0 + i * 7200, doge_diff);
    }
    doge.tip = 6455000;
    const auto blocks_rows = other.rest_recent_blocks();
    const auto merged_rows = other.rest_recent_merged_blocks();
    ASSERT_EQ(blocks_rows.size(), 6u);
    ASSERT_EQ(merged_rows.size(), 9u);

    const std::string dir = testing::TempDir();
    const std::string blocks_path = dir + "/fbi_blocks.json";
    const std::string merged_path = dir + "/fbi_merged.json";
    { std::ofstream(blocks_path) << blocks_rows.dump(); }
    { std::ofstream(merged_path) << merged_rows.dump(); }

    // The CLI's list: given twice, or as one comma list -- the same two files.
    const auto paths = fbi::split_paths(" " + blocks_path + " ," + merged_path + ",");
    ASSERT_EQ(paths.size(), 2u);
    EXPECT_EQ(paths[0], blocks_path);
    EXPECT_EQ(paths[1], merged_path);
    std::vector<fbi::File> files;
    for (const auto& p : paths) files.push_back({p, fbi::read_file(p)});

    boost::asio::io_context ioc;
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    mi.set_io_context(&ioc);
    auto src = source_over(ltc);
    src.aux["DOGE"] = doge.lookup();
    std::optional<fbi::Report> done;
    mi.start_found_block_import(std::move(files), src, std::chrono::milliseconds(5),
                                [&done](const fbi::Report& r) { done = r; });
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (!done && std::chrono::steady_clock::now() < deadline)
        ioc.run_for(std::chrono::milliseconds(20));
    ASSERT_TRUE(done.has_value());
    const fbi::Report& t = *done;
    EXPECT_EQ(t.rows, 15u);
    EXPECT_EQ(t.imported, 12u) << t.summary();
    EXPECT_EQ(t.imported_by_chain.at("LTC"), 4u);
    EXPECT_EQ(t.imported_by_chain.at("DOGE"), 8u);
    EXPECT_EQ(t.rejected_total(), 3u);
    EXPECT_EQ(rejected_on(t, "LTC", fbi::kNotOnChain), 2u) << t.summary();
    EXPECT_EQ(rejected_on(t, "DOGE", fbi::kBelowHeaderChain), 1u) << t.summary();
    EXPECT_EQ(rejected_on(t, "LTC", fbi::kBelowHeaderChain), 0u);
    EXPECT_EQ(rejected_on(t, "DOGE", fbi::kNotOnChain), 0u);
    EXPECT_NE(t.summary().find("imported 12 (DOGE 8, LTC 4)"), std::string::npos) << t.summary();
    EXPECT_NE(t.summary().find("DOGE: below_header_chain=1; LTC: not_on_chain=2"),
              std::string::npos) << t.summary();

    EXPECT_EQ(mi.rest_recent_blocks().size(), 4u);
    EXPECT_EQ(mi.rest_recent_merged_blocks().size(), 8u);
    const auto d = row_of(mi.rest_recent_merged_blocks(), "pow_hash", hash_of(0xd08));
    EXPECT_EQ(d["height"].get<uint64_t>(), 6454700u);
    EXPECT_NEAR(num(d, "network_difficulty"), doge_diff, 1e-6);

    // Again: nothing new, nothing refused that was not refused before.
    std::vector<fbi::File> again;
    for (const auto& p : paths) again.push_back({p, fbi::read_file(p)});
    done.reset();
    mi.start_found_block_import(std::move(again), src, std::chrono::milliseconds(5),
                                [&done](const fbi::Report& r) { done = r; });
    ASSERT_TRUE(done.has_value()) << "every chain is ready: no wait";
    EXPECT_EQ(done->imported, 0u);
    EXPECT_EQ(done->unchanged, 12u) << done->summary();
    EXPECT_EQ(done->rejected_total(), 3u);
}

// ── The flag's value, checked when it is parsed ─────────────────────────────
// main_ltc refuses (exit 1) what file_problem names, before the node starts:
// --import-found-blocks --testnet must not swallow --testnet and start a
// MAINNET node; a missing, unreadable or over-cap file must not surface only
// after the header sync. ci/golden_resolved_config.sh runs the binary on
// the same cases.
TEST(FoundBlockImport, FlagValueIsCheckedBeforeTheNodeStarts)
{
    const std::filesystem::path dir = std::filesystem::path(testing::TempDir()) /
        ("fbi_flag_" + std::to_string(static_cast<long long>(::getpid())));
    std::filesystem::create_directories(dir);
    const std::string ok = (dir / "blocks.json").string();
    { std::ofstream(ok) << "[]"; }
    const std::string big = (dir / "huge.json").string();
    { std::ofstream(big) << "["; }
    std::filesystem::resize_file(big, fbi::kMaxFileBytes + 1);   // sparse

    EXPECT_EQ(fbi::file_problem(ok), "");
    EXPECT_NE(fbi::file_problem("--testnet"), "") << "an option is not a file";
    EXPECT_NE(fbi::file_problem("-h"), "");
    EXPECT_NE(fbi::file_problem(""), "");
    EXPECT_EQ(fbi::file_problem((dir / "none.json").string()), "no such file");
    EXPECT_EQ(fbi::file_problem(dir.string()), "not a regular file");
    EXPECT_NE(fbi::file_problem(big).find("above the cap"), std::string::npos)
        << fbi::file_problem(big);
    // read_file refuses it without reading it whole.
    EXPECT_NE(fbi::read_file(big).error.find("above the cap"), std::string::npos);

    const auto paths = fbi::split_paths(ok + ",," + ok + " , ");
    EXPECT_EQ(paths.size(), 2u);
    EXPECT_TRUE(fbi::split_paths(" , ").empty());

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

// ── open_import_file: the one place an import file is opened ───────────────
// Only the canonical path (absolute, symlinks followed) is checked and
// opened, and its final target must be a regular file: a directory, a device
// (/dev/null, also behind a symlink), a FIFO (a read would block the start)
// and a socket are refused without being opened.
TEST(FoundBlockImport, ImportFileIsCanonicalAndRegular)
{
    namespace fs = std::filesystem;
    const fs::path dir = fs::weakly_canonical(fs::path(testing::TempDir())) /
        ("fbi_open_" + std::to_string(static_cast<long long>(::getpid())));
    fs::remove_all(dir);
    fs::create_directories(dir / "sub");
    const fs::path real = dir / "blocks.json";
    { std::ofstream(real) << "[\"" << hash_of(0x1) << "\"]"; }

    // A regular file: its canonical path and its contents.
    const auto opened = fbi::open_import_file(real.string());
    ASSERT_EQ(opened.error, "");
    EXPECT_EQ(opened.path, fs::canonical(real).string());
    EXPECT_EQ(fbi::parse(opened.contents).rows.size(), 1u);

    // A relative path, and one through "..", come back absolute and canonical.
    const fs::path cwd = fs::current_path();
    fs::current_path(dir / "sub");
    const auto rel = fbi::open_import_file("../blocks.json");
    const auto rel2 = fbi::open_import_file("./../sub/../blocks.json");
    fs::current_path(cwd);
    ASSERT_EQ(rel.error, "");
    EXPECT_TRUE(fs::path(rel.path).is_absolute()) << rel.path;
    EXPECT_EQ(rel.path, fs::canonical(real).string());
    EXPECT_EQ(rel2.path, fs::canonical(real).string());

    // A symlink to a regular file is the file it points at.
    fs::create_symlink(real, dir / "link.json");
    const auto via_link = fbi::open_import_file((dir / "link.json").string());
    ASSERT_EQ(via_link.error, "");
    EXPECT_EQ(via_link.path, fs::canonical(real).string()) << "followed to the target";

    // A directory, and a symlink to one.
    EXPECT_EQ(fbi::open_import_file((dir / "sub").string()).error, "not a regular file");
    fs::create_directory_symlink(dir / "sub", dir / "dirlink");
    EXPECT_EQ(fbi::open_import_file((dir / "dirlink").string()).error, "not a regular file");

    // A device behind a symlink: /dev/null.
    if (fs::exists("/dev/null")) {
        EXPECT_EQ(fbi::open_import_file("/dev/null").error, "not a regular file");
        fs::create_symlink("/dev/null", dir / "null.json");
        const auto null_link = fbi::open_import_file((dir / "null.json").string());
        EXPECT_EQ(null_link.error, "not a regular file");
        EXPECT_TRUE(null_link.path.empty());
        EXPECT_TRUE(null_link.contents.empty());
    }

    // A FIFO, and a symlink to one: refused without being opened (an open
    // would block until a writer came).
    const fs::path fifo = dir / "pipe.json";
    ASSERT_EQ(::mkfifo(fifo.c_str(), 0600), 0);
    EXPECT_EQ(fbi::open_import_file(fifo.string()).error, "not a regular file");
    fs::create_symlink(fifo, dir / "pipelink.json");
    EXPECT_EQ(fbi::open_import_file((dir / "pipelink.json").string()).error,
              "not a regular file");
    EXPECT_NE(fbi::read_file(fifo.string()).error.find("not a regular file"), std::string::npos);

    // A dangling symlink resolves to nothing.
    fs::create_symlink(dir / "gone.json", dir / "dangling.json");
    EXPECT_EQ(fbi::open_import_file((dir / "dangling.json").string()).error, "no such file");

    std::error_code ec;
    fs::remove_all(dir, ec);
}

// ── Caps ─────────────────────────────────────────────────────────────────────
// A file of more than kMaxRows entries is refused whole, as text or JSON;
// exactly kMaxRows is a file like any other.
TEST(FoundBlockImport, OverCapFilesAreRefusedWhole)
{
    std::string list;
    list.reserve((fbi::kMaxRows + 1) * 65);
    for (size_t i = 0; i < fbi::kMaxRows; ++i) {
        list += hash_of(static_cast<unsigned>(0x100000 + i));
        list += '\n';
    }
    const auto at_cap = fbi::parse(list);
    EXPECT_TRUE(at_cap.error.empty()) << at_cap.error;
    EXPECT_EQ(at_cap.rows.size(), fbi::kMaxRows);

    list += hash_of(0x1);
    list += '\n';
    const auto over = fbi::parse(list);
    EXPECT_NE(over.error.find("above the cap"), std::string::npos) << over.error;
    EXPECT_TRUE(over.rows.empty()) << "refused whole, not truncated";

    nlohmann::json arr = nlohmann::json::array();
    for (size_t i = 0; i <= fbi::kMaxRows; ++i)
        arr.push_back(hash_of(static_cast<unsigned>(0x100000 + i)));
    const auto json_over = fbi::parse(arr.dump());
    EXPECT_NE(json_over.error.find("above the cap"), std::string::npos) << json_over.error;
    EXPECT_TRUE(json_over.rows.empty());

    EXPECT_NE(fbi::parse(std::string(fbi::kMaxFileBytes + 1, ' ')).error.find("above the cap"),
              std::string::npos);
}

// A large import merges by an index, and its rows are all there once.
TEST(FoundBlockImport, LargeImportMergesEachRowOnce)
{
    FakeChain ltc;
    constexpr unsigned kN = 20000;
    std::string list;
    for (unsigned i = 0; i < kN; ++i) {
        const std::string h = hash_of(0x200000 + i);
        ltc.add(h, 2000000 + i, kT0 + i * 150ull, kD);
        list += h + "\n";
    }
    ltc.tip = 2000000 + kN + 100;
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    const auto first = import_text(mi, list, source_over(ltc));
    EXPECT_EQ(first.imported, kN);
    const auto again = import_text(mi, list, source_over(ltc));
    EXPECT_EQ(again.imported, 0u);
    EXPECT_EQ(again.unchanged, kN);
    EXPECT_EQ(mi.get_found_blocks().size(), kN);
}

// ── Strictly fill-only ───────────────────────────────────────────────────────
// A pre-fix LTC peer row holds its miner as raw hex (it renders through
// found_block_miner_display). That is still the node's own record: the file
// does not replace it.
TEST(FoundBlockImport, NodeRecordedMinerIsNeverReplacedByTheFile)
{
    const std::string h = hash_of(0x4d1);
    std::string raw_hex;
    for (unsigned char c : kMinerA) {
        static const char* digits = "0123456789abcdef";
        raw_hex += digits[c >> 4];
        raw_hex += digits[c & 0xf];
    }
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    mi.record_found_block(3200001, uint256S(h), kT0, "LTC", raw_hex, h, kD, kShareDiff, kRate,
                          625000000, MiningInterface::BlockAuthorship::sharechain_peer);
    ASSERT_EQ(mi.get_found_blocks().at(0).miner, raw_hex);

    FakeChain ltc;
    ltc.add(h, 3200001, kT0, kD);
    ltc.tip = 3200100;
    nlohmann::json file = nlohmann::json::array({{{"hash", h}, {"miner", kMinerB},
                                                  {"coinbase_txid", hash_of(0x4d2)}}});
    const auto rep = import_text(mi, file.dump(), source_over(ltc));
    EXPECT_EQ(rep.merged, 1u) << "the missing coinbase_txid is filled";
    EXPECT_EQ(mi.get_found_blocks().at(0).miner, raw_hex) << "the node's own miner stays";
    EXPECT_EQ(str(row_of(mi.rest_recent_blocks(), "hash", h), "miner"), kMinerA)
        << "and still renders as the address it encodes";
}

// ── Is it a POOL block? ──────────────────────────────────────────────────────
// Where the block's coinbase is at hand it must pay the pool's donation;
// where it is not (an old block on a daemonless node) the source is trusted.
TEST(FoundBlockImport, CoinbaseThatDoesNotPayThePoolIsRefused)
{
    FakeChain ltc;
    ltc.add(hash_of(0xa1), 3200001, kT0, kD);
    ltc.add(hash_of(0xa2), 3200002, kT0 + 600, kD);
    ltc.add(hash_of(0xa3), 3200003, kT0 + 1200, kD);
    ltc.tip = 3200100;
    auto src = source_over(ltc);
    src.pays_pool = [](const std::string& hash, uint64_t) -> std::optional<bool> {
        if (hash == hash_of(0xa1)) return false;   // a block of someone else
        if (hash == hash_of(0xa2)) return true;    // pays the donation
        return std::nullopt;                       // body not at hand
    };
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    const auto rep = import_text(
        mi, hash_of(0xa1) + "\n" + hash_of(0xa2) + "\n" + hash_of(0xa3) + "\n", src);
    EXPECT_EQ(rejected(rep, fbi::kNotPoolBlock), 1u);
    EXPECT_EQ(rep.pool_verified, 1u);
    EXPECT_EQ(rep.imported, 2u) << rep.summary();

    // The LTC check itself: a p2pool coinbase carries the donation output.
    using ltc::coin::BlockType;
    auto out = [](const std::vector<unsigned char>& script) {
        ltc::coin::TxOut o;
        o.value = 1;
        o.scriptPubKey.m_data = script;
        return o;
    };
    const std::vector<unsigned char> p2pkh = {0x76, 0xa9, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                                              11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0x88, 0xac};
    const auto& v36 = ltc::PoolConfig::COMBINED_DONATION_SCRIPT;
    const auto& v35 = ltc::PoolConfig::DONATION_SCRIPT;
    BlockType pool, pre_v36, other, empty;
    pool.m_txs.resize(1);
    pool.m_txs[0].vout = {out(p2pkh), out(std::vector<unsigned char>(v36.begin(), v36.end()))};
    pre_v36.m_txs.resize(1);
    pre_v36.m_txs[0].vout = {out(p2pkh), out(std::vector<unsigned char>(v35.begin(), v35.end()))};
    other.m_txs.resize(1);
    other.m_txs[0].vout = {out(p2pkh)};
    EXPECT_EQ(ltc::found_block::coinbase_pays_donation(pool), std::optional<bool>(true));
    EXPECT_EQ(ltc::found_block::coinbase_pays_donation(pre_v36), std::optional<bool>(true));
    EXPECT_EQ(ltc::found_block::coinbase_pays_donation(other), std::optional<bool>(false));
    EXPECT_FALSE(ltc::found_block::coinbase_pays_donation(empty).has_value());
}

// ── Persistence ──────────────────────────────────────────────────────────────
// The imported flag rides the fblk extension byte (bit 0x02) beside the aux
// flag, with no version bump: a build that predates it reads the row. After a
// restart the row is still "imported".
TEST(FoundBlockImport, ProvenanceSurvivesARestartWithoutAVersionBump)
{
    using c2pool::storage::FoundBlockRecord;
    using FB = MiningInterface::FoundBlock;
    std::map<std::string, std::vector<uint8_t>> disk;   // hash -> record bytes
    auto to_rec = [](const FB& b) {
        FoundBlockRecord rec;
        rec.chain = b.chain; rec.height = b.height; rec.block_hash = b.hash;
        rec.timestamp = b.ts; rec.status = static_cast<uint8_t>(b.status);
        rec.confirmations = b.confirmations; rec.finder_address = b.miner;
        rec.network_difficulty = b.network_difficulty; rec.pool_hashrate = b.pool_hashrate;
        rec.share_difficulty = b.share_difficulty; rec.share_hash = b.share_hash;
        rec.authorship = static_cast<uint8_t>(b.authorship);
        rec.aux_difficulty_known = b.aux_difficulty_known;
        rec.imported = b.imported;
        return rec;
    };
    auto from_rec = [](const FoundBlockRecord& rec) {
        FB b{};
        b.chain = rec.chain; b.height = rec.height; b.hash = rec.block_hash;
        b.ts = rec.timestamp; b.status = static_cast<MiningInterface::BlockStatus>(rec.status);
        b.confirmations = rec.confirmations; b.miner = rec.finder_address;
        b.network_difficulty = rec.network_difficulty; b.pool_hashrate = rec.pool_hashrate;
        b.share_difficulty = rec.share_difficulty; b.share_hash = rec.share_hash;
        b.authorship = static_cast<MiningInterface::BlockAuthorship>(rec.authorship);
        b.aux_difficulty_known = rec.aux_difficulty_known;
        b.imported = rec.imported;
        return b;
    };
    auto wire = [&](MiningInterface& mi) {
        mi.set_found_block_persistence(
            [&](const FB& b) { disk[b.hash] = to_rec(b).serialize(); return true; },
            [&]() {
                std::vector<FB> out;
                for (const auto& [h, bytes] : disk)
                    out.push_back(from_rec(FoundBlockRecord::deserialize(bytes)));
                return out;
            });
    };

    FakeChain ltc;
    ltc.add(hash_of(0xb1), 3200001, kT0, kD);
    ltc.tip = 3200100;
    {
        MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
        wire(mi);
        EXPECT_EQ(import_text(mi, hash_of(0xb1) + "\n", source_over(ltc)).imported, 1u);
    }
    ASSERT_EQ(disk.size(), 1u);
    const auto& bytes = disk.begin()->second;
    EXPECT_EQ(bytes.front(), 4) << "no version bump";
    EXPECT_EQ(bytes.back(), FoundBlockRecord::kExtImported) << "the extension byte";
    // A reader that knows only the aux bit sees an ordinary row.
    EXPECT_FALSE(FoundBlockRecord::deserialize(bytes).aux_difficulty_known);
    {
        auto pre = bytes;
        pre.pop_back();   // the row as a build before the extension byte writes it back
        EXPECT_FALSE(FoundBlockRecord::deserialize(pre).imported);
        EXPECT_EQ(FoundBlockRecord::deserialize(pre).block_hash, hash_of(0xb1));
    }

    MiningInterface restarted(false, nullptr, Blockchain::LITECOIN);
    wire(restarted);
    restarted.load_persisted_found_blocks();
    const auto r = row_of(restarted.rest_recent_blocks(), "hash", hash_of(0xb1));
    ASSERT_TRUE(r.is_object());
    EXPECT_EQ(str(r, "provenance"), "imported");
    EXPECT_TRUE(r["from_history"].get<bool>());
    EXPECT_FALSE(r["found_locally"].get<bool>());
    EXPECT_EQ(str(r, "status"), "confirmed");
}

// A block the node later records itself (the sharechain hook re-records the
// winning share's block) is the node's own row from then on.
TEST(FoundBlockImport, ALaterRecordByThisNodeSupersedesTheImport)
{
    FakeChain ltc;
    const std::string h = hash_of(0xc1);
    ltc.add(h, 3200001, kT0, kD);
    ltc.tip = 3200100;
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    EXPECT_EQ(import_text(mi, h + "\n", source_over(ltc)).imported, 1u);
    EXPECT_EQ(str(row_of(mi.rest_recent_blocks(), "hash", h), "provenance"), "imported");

    mi.record_found_block(3200001, uint256S(h), kT0, "LTC", kMinerA, h, kD, kShareDiff, kRate,
                          625000000, MiningInterface::BlockAuthorship::sharechain_peer,
                          /*height_from_block=*/true);
    const auto r = row_of(mi.rest_recent_blocks(), "hash", h);
    EXPECT_EQ(str(r, "provenance"), "recorded");
    EXPECT_TRUE(r["found_locally"].get<bool>());
    EXPECT_EQ(str(r, "found_by"), "sharechain_peer");
    EXPECT_EQ(str(r, "miner"), kMinerA);
    EXPECT_EQ(str(r, "status"), "confirmed") << "the verdict the import gave stands";
    EXPECT_EQ(mi.get_found_blocks().size(), 1u);
}

// A block fewer than 6 deep is not final: imported pending, and it still
// counts as a block of the chain for luck.
TEST(FoundBlockImport, ShallowBlockIsImportedPending)
{
    FakeChain ltc;
    ltc.add(hash_of(0xe1), 3200001, kT0, kD);
    ltc.add(hash_of(0xe2), 3200098, kT0 + 600, kD);
    ltc.tip = 3200100;   // 0xe2 is 3 deep
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    const auto rep = import_text(mi, hash_of(0xe1) + "\n" + hash_of(0xe2) + "\n", source_over(ltc));
    EXPECT_EQ(rep.imported, 2u);
    EXPECT_EQ(rep.pending, 1u);
    const auto rows = mi.rest_recent_blocks();
    EXPECT_EQ(str(row_of(rows, "hash", hash_of(0xe1)), "status"), "confirmed");
    const auto r2 = row_of(rows, "hash", hash_of(0xe2));
    EXPECT_EQ(str(r2, "status"), "pending");
    EXPECT_TRUE(r2["main_chain"].get<bool>());
}

// ── The source's effort survives a restart ───────────────────────────────────
// It is kept with the row (FoundBlock::imported_effort) and persisted in the
// fblk extension tail, through the same mapping the LTC node's persistence
// callbacks use (c2pool/storage/found_block_record_map.hpp). After a restart
// the rows still serve it, and importing the file again changes nothing.
TEST(FoundBlockImport, SourceEffortSurvivesARestart)
{
    using c2pool::storage::FoundBlockRecord;
    using FB = MiningInterface::FoundBlock;
    std::map<std::string, std::vector<uint8_t>> disk;
    int writes = 0;
    auto wire = [&](MiningInterface& mi) {
        mi.set_found_block_persistence(
            [&](const FB& b) {
                disk[b.chain + ":" + b.hash] =
                    c2pool::storage::found_block_record_of(b, 0).serialize();
                ++writes;
                return true;
            },
            [&]() {
                std::vector<FB> out;
                for (const auto& [k, bytes] : disk)
                    out.push_back(c2pool::storage::found_block_of<FB>(
                        FoundBlockRecord::deserialize(bytes)));
                return out;
            });
    };

    const double doge_diff = 3.3e7;
    FakeChain ltc, doge;
    ltc.tip = 3200100;
    nlohmann::json file = nlohmann::json::array();
    const double coverage[3] = {0.0, 1.0, 0.7};
    const double effort[3] = {1.0, 1.1, 0.4};
    for (unsigned i = 0; i < 3; ++i) {
        const std::string h = hash_of(0xf10 + i);
        const uint64_t t = kT0 + i * 86400;
        doge.add(h, 6454000 + i, t, doge_diff);
        nlohmann::json r{{"pow_hash", h}, {"symbol", "DOGE"}, {"height", 6454000 + i}, {"ts", t},
                         {"pool_hashrate_at_find", kRate}, {"measured", true},
                         {"effort", effort[i]}};
        if (i == 0) {
            r["effort_method"] = "first_block";
        } else {
            r["effort_method"] = "integrated";
            r["history_coverage"] = coverage[i];
            r["prev_block_hash"] = hash_of(0xf10 + i - 1);
        }
        file.push_back(r);
    }
    doge.tip = 6455000;
    auto src = source_over(ltc);
    src.aux["DOGE"] = doge.lookup();
    {
        MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
        wire(mi);
        const auto rep = import_text(mi, file.dump(), src);
        EXPECT_EQ(rep.imported, 3u);
        EXPECT_EQ(rep.effort_taken, 2u) << rep.summary();
        EXPECT_EQ(rep.effort_refused, 0u);
        EXPECT_EQ(rep.effort_not_used, 0u);
    }
    ASSERT_EQ(disk.size(), 3u);
    const auto rec = FoundBlockRecord::deserialize(disk.at("DOGE:" + hash_of(0xf11)));
    EXPECT_EQ(disk.at("DOGE:" + hash_of(0xf11))[0], 4) << "no version bump";
    EXPECT_DOUBLE_EQ(rec.imported_effort, 1.1);
    EXPECT_DOUBLE_EQ(rec.imported_coverage, 1.0);
    EXPECT_EQ(rec.imported_prev_hash, hash_of(0xf10));
    EXPECT_DOUBLE_EQ(rec.pool_hashrate, kRate);
    EXPECT_FALSE(FoundBlockRecord::deserialize(disk.at("DOGE:" + hash_of(0xf10)))
                     .has_imported_effort()) << "the first block took none";

    MiningInterface restarted(false, nullptr, Blockchain::LITECOIN);
    wire(restarted);
    restarted.load_persisted_found_blocks();
    const auto rows = restarted.rest_recent_merged_blocks();
    const auto r1 = row_of(rows, "pow_hash", hash_of(0xf11));
    EXPECT_EQ(str(r1, "effort_method"), "imported") << r1.dump();
    EXPECT_DOUBLE_EQ(num(r1, "effort"), 1.1);
    EXPECT_DOUBLE_EQ(num(r1, "history_coverage"), 1.0);
    const auto r2 = row_of(rows, "pow_hash", hash_of(0xf12));
    EXPECT_EQ(str(r2, "effort_method"), "imported");
    EXPECT_DOUBLE_EQ(num(r2, "effort"), 0.4);
    EXPECT_DOUBLE_EQ(num(r2, "history_coverage"), 0.7);
    EXPECT_NEAR(num(r2, "effort_covered"), 0.28, 1e-12);
    EXPECT_NEAR(num(r2, "pool_hashrate_at_find"), kRate, 1e-3);
    // /found_block/<hash> serves the ledger row the same way.
    EXPECT_EQ(str(restarted.rest_found_block(hash_of(0xf12)), "effort_method"), "imported");

    writes = 0;
    const auto again = import_text(restarted, file.dump(), src);
    EXPECT_EQ(again.imported + again.merged, 0u) << again.summary();
    EXPECT_EQ(again.unchanged, 3u);
    EXPECT_EQ(again.effort_taken, 0u);
    EXPECT_EQ(again.effort_not_used, 2u) << "both rows hold one already";
    EXPECT_EQ(writes, 0);
}

// ── The source's effort: what a hostile or stale file cannot do ──────────────
// Regression KATs from the independent verification of the first cut of this
// change (each asserted the hole then; each asserts it closed now).
namespace {

const double kOneADay = kD * kT32 / 86400.0;   // the pool rate of one block a day

nlohmann::json ltc_file_row(const std::string& h, uint64_t height, uint64_t t,
                            bool with_rate = true)
{
    nlohmann::json r{{"hash", h}, {"chain", "LTC"}, {"height", height}, {"ts", t}};
    if (with_rate) {
        r["pool_hashrate_at_find"] = kOneADay;
        r["share_difficulty"] = kShareDiff;
    }
    return r;
}

MiningInterface::FoundBlock mi_row(const MiningInterface& mi, const std::string& hash)
{
    for (const auto& b : mi.get_found_blocks())
        if (b.hash == hash) return b;
    return MiningInterface::FoundBlock{};
}

void offer_effort(nlohmann::json& r, double effort, double coverage, const std::string& prev)
{
    r["effort_method"] = "integrated";
    r["measured"] = true;
    r["effort"] = effort;
    r["history_coverage"] = coverage;
    r["prev_block_hash"] = prev;
}

} // namespace

// Four blocks a day apart at one block a day: 4 found, 4 expected. A file
// that claims each round integrated over 1e-12 of it (an effort of 1.0,
// perfectly plausible) would replace each single sample and count its block
// against ~0 expected (effort x coverage): 400 % all-time luck. Under half of
// the round measured, a source figure does not compete.
TEST(FoundBlockImport, SourceEffortOverATinyCoverageIsNotUsed)
{
    const double now = static_cast<double>(kT0) + 3 * 86400.0 + 60.0;
    FakeChain ltc;
    ltc.tip = 3300000;
    nlohmann::json file = nlohmann::json::array();
    for (unsigned i = 0; i < 4; ++i) {
        const std::string h = hash_of(0x300 + i);
        const uint64_t t = kT0 + i * 86400ull;
        ltc.add(h, 3200000 + i, t, kD);
        auto r = ltc_file_row(h, 3200000 + i, t);
        if (i > 0) offer_effort(r, 1.0, 1e-12, hash_of(0x300 + i - 1));
        file.push_back(r);
    }
    MiningInterface node(false, nullptr, Blockchain::LITECOIN);
    const auto rep = import_text(node, file.dump(), source_over(ltc));
    EXPECT_EQ(rep.imported, 4u) << rep.summary();
    EXPECT_EQ(rep.effort_taken, 0u) << rep.summary();
    EXPECT_EQ(rep.effort_not_used, 3u);
    EXPECT_EQ(str(row_of(node.rest_recent_blocks_at(now), "hash", hash_of(0x302)), "effort_method"),
              "single_sample");
    const auto all = node.rest_luck_stats_at(now)["periods"]["all"];
    EXPECT_EQ(all["k"].get<uint64_t>(), 4u) << all.dump();
    EXPECT_NEAR(all["blocks_expected"].get<double>(), 4.0, 1e-6);
    EXPECT_NEAR(all["luck"].get<double>(), 100.0, 1e-4);
}

// The node's own history covers the last ~60 % of a one-day round at one
// block a day: its own effort is ~1.0. A file claiming the whole round at
// effort 50 -- a mean pool rate 50x what the node itself measured over most
// of the same round -- passes every absolute bound (share floor, 1 % of the
// yardstick, the network's rate: up to effort 576 here). It is refused: an
// imported figure must agree with the node's own measurement within
// kImportedRateBand. One 3x off is refused; one 2x off is taken.
TEST(FoundBlockImport, SourceEffortFarFromTheNodesOwnRateIsRefused)
{
    FakeChain ltc;
    ltc.tip = 3300000;
    const std::string P = hash_of(0x400), X = hash_of(0x401);
    const uint64_t tP = kT0, tX = kT0 + 86400;
    ltc.add(P, 3200000, tP, kD);
    ltc.add(X, 3200001, tX, kD);
    auto own_node = [&](MiningInterface& node) {
        for (double t = tP + 0.4 * 86400.0 + 3600.0; t <= tX + 3600.0; t += 3600.0)
            node.add_luck_rate_sample(t, kOneADay, 0.0, kD);
        nlohmann::json plain = nlohmann::json::array({ltc_file_row(P, 3200000, tP),
                                                      ltc_file_row(X, 3200001, tX)});
        ASSERT_EQ(import_text(node, plain.dump(), source_over(ltc)).imported, 2u);
        const auto own = row_of(node.rest_recent_blocks(), "hash", X);
        ASSERT_EQ(str(own, "effort_method"), "integrated");
        ASSERT_NEAR(num(own, "effort"), 1.0, 0.05);
        ASSERT_GT(num(own, "history_coverage"), 0.5);
        ASSERT_LT(num(own, "history_coverage"), 0.7);
    };
    auto offered = [&](double effort) {
        nlohmann::json f = nlohmann::json::array({ltc_file_row(P, 3200000, tP),
                                                  ltc_file_row(X, 3200001, tX)});
        offer_effort(f[1], effort, 1.0, P);
        return f.dump();
    };
    for (double forged : {50.0, 3.2, 0.3}) {
        MiningInterface node(false, nullptr, Blockchain::LITECOIN);
        own_node(node);
        const auto rep = import_text(node, offered(forged), source_over(ltc));
        EXPECT_EQ(rep.effort_taken, 0u) << forged << " " << rep.summary();
        EXPECT_EQ(rep.effort_refused, 1u) << forged;
        const auto after = row_of(node.rest_recent_blocks(), "hash", X);
        EXPECT_EQ(str(after, "effort_method"), "integrated") << forged << " " << after.dump();
        EXPECT_NEAR(num(after, "effort"), 1.0, 0.05);
        EXPECT_TRUE(after["luck_approximate"].get<bool>()) << "60 % covered: approximate";
    }
    MiningInterface node(false, nullptr, Blockchain::LITECOIN);
    own_node(node);
    const auto rep = import_text(node, offered(2.0), source_over(ltc));
    EXPECT_EQ(rep.effort_taken, 1u) << rep.summary();
    EXPECT_EQ(str(row_of(node.rest_recent_blocks(), "hash", X), "effort_method"), "imported");
}

// No history, two rows, no rate and no share difficulty in the file: no
// yardstick at all. An effort of 1e-300 would be a luck of 1e302 %; the
// smallest denormal a luck of inf, served as null under a method claiming a
// value. Out of its absolute bounds, a figure is refused whatever the
// yardstick; the row is what the node can say of it alone
// (hashrate_unavailable, a null luck under the label that says why). A rate
// at find of 1e-300 in the same file shape is no pool rate either.
TEST(FoundBlockImport, SourceEffortOutsideItsBoundsIsRefusedWithoutAYardstick)
{
    for (double effort : {1e-300, std::numeric_limits<double>::denorm_min(), 1e-7, 2e6}) {
        FakeChain ltc;
        ltc.tip = 3300000;
        const std::string P = hash_of(0x500), X = hash_of(0x501);
        const uint64_t tP = kT0, tX = kT0 + 86400;
        ltc.add(P, 3200000, tP, kD);
        ltc.add(X, 3200001, tX, kD);
        nlohmann::json file = nlohmann::json::array({ltc_file_row(P, 3200000, tP, false),
                                                     ltc_file_row(X, 3200001, tX, false)});
        offer_effort(file[1], effort, 1.0, P);
        MiningInterface node(false, nullptr, Blockchain::LITECOIN);
        const auto rep = import_text(node, file.dump(), source_over(ltc));
        EXPECT_EQ(rep.effort_taken, 0u) << effort << " " << rep.summary();
        EXPECT_EQ(rep.effort_refused, 1u) << effort;
        const auto r = row_of(node.rest_recent_blocks(), "hash", X);
        EXPECT_EQ(str(r, "luck_method"), "hashrate_unavailable") << effort << " " << r.dump();
        EXPECT_TRUE(r["luck"].is_null());
        EXPECT_TRUE(r["effort_method"].is_null());
    }
    FakeChain ltc;
    ltc.tip = 3300000;
    const std::string P = hash_of(0x510), X = hash_of(0x511);
    ltc.add(P, 3200000, kT0, kD);
    ltc.add(X, 3200001, kT0 + 86400, kD);
    nlohmann::json file = nlohmann::json::array({ltc_file_row(P, 3200000, kT0, false),
                                                 ltc_file_row(X, 3200001, kT0 + 86400, false)});
    file[1]["pool_hashrate_at_find"] = 1e-300;
    MiningInterface node(false, nullptr, Blockchain::LITECOIN);
    const auto rep = import_text(node, file.dump(), source_over(ltc));
    EXPECT_EQ(rep.rate_refused, 1u) << rep.summary();
    const auto r = row_of(node.rest_recent_blocks(), "hash", X);
    EXPECT_EQ(str(r, "luck_method"), "hashrate_unavailable") << r.dump();
    EXPECT_TRUE(r["luck"].is_null());
}

// File A has P, X: X takes the source's effort over P -> X. File B, a later
// and fuller snapshot, has P, Q, X: X's round now runs from Q, the figure it
// holds applies to nothing, and B's valid Q -> X figure takes its place.
// Importing B again changes nothing.
TEST(FoundBlockImport, SourceEffortOfARoundThatChangedMakesWayForAValidOne)
{
    FakeChain ltc;
    ltc.tip = 3300000;
    const std::string P = hash_of(0x600), Q = hash_of(0x601), X = hash_of(0x602);
    const uint64_t tP = kT0, tQ = kT0 + 86400, tX = kT0 + 2 * 86400;
    ltc.add(P, 3200000, tP, kD);
    ltc.add(Q, 3200001, tQ, kD);
    ltc.add(X, 3200002, tX, kD);
    MiningInterface node(false, nullptr, Blockchain::LITECOIN);

    nlohmann::json a = nlohmann::json::array({ltc_file_row(P, 3200000, tP),
                                              ltc_file_row(X, 3200002, tX)});
    offer_effort(a[1], 2.2, 1.0, P);
    EXPECT_EQ(import_text(node, a.dump(), source_over(ltc)).effort_taken, 1u);
    EXPECT_EQ(str(row_of(node.rest_recent_blocks(), "hash", X), "effort_method"), "imported");

    nlohmann::json b = nlohmann::json::array({ltc_file_row(P, 3200000, tP),
                                              ltc_file_row(Q, 3200001, tQ),
                                              ltc_file_row(X, 3200002, tX)});
    offer_effort(b[1], 1.1, 1.0, P);
    offer_effort(b[2], 1.15, 1.0, Q);
    const auto rb = import_text(node, b.dump(), source_over(ltc));
    EXPECT_EQ(rb.effort_taken, 2u) << rb.summary();
    EXPECT_EQ(rb.effort_not_used, 0u);
    const auto x = row_of(node.rest_recent_blocks(), "hash", X);
    EXPECT_EQ(str(x, "effort_method"), "imported") << x.dump();
    EXPECT_DOUBLE_EQ(num(x, "effort"), 1.15);
    EXPECT_EQ(str(x, "prev_block_hash"), Q);
    const auto held = mi_row(node, X);
    EXPECT_EQ(held.imported_prev_hash, Q);

    const auto again = import_text(node, b.dump(), source_over(ltc));
    EXPECT_EQ(again.effort_taken, 0u) << again.summary();
    EXPECT_EQ(again.effort_not_used, 2u) << "both hold one for their round now";
    EXPECT_EQ(again.merged, 0u);
}

// A row whose own difficulty this node does not know (a merged row stored
// before the aux difficulty was, with no aux header to name it) has no round
// the figure can be judged on: counted as not judged, not as refused.
TEST(FoundBlockImport, SourceEffortThatCannotBeJudgedIsCountedApart)
{
    FakeChain ltc, doge;
    ltc.tip = 3300000;
    const std::string D1 = hash_of(0x6d0), D2 = hash_of(0x6d1);
    doge.add(D1, 6454000, kT0, 0.0);           // headers without a difficulty
    doge.add(D2, 6454100, kT0 + 86400, 0.0);
    doge.tip = 6460000;
    auto src = source_over(ltc);
    src.aux["DOGE"] = doge.lookup();
    nlohmann::json file = nlohmann::json::array({
        {{"pow_hash", D1}, {"symbol", "DOGE"}, {"height", 6454000}, {"ts", kT0}},
        {{"pow_hash", D2}, {"symbol", "DOGE"}, {"height", 6454100}, {"ts", kT0 + 86400}}});
    offer_effort(file[1], 1.2, 1.0, D1);
    MiningInterface node(false, nullptr, Blockchain::LITECOIN);
    const auto rep = import_text(node, file.dump(), src);
    EXPECT_EQ(rep.imported, 2u) << rep.summary();
    EXPECT_EQ(rep.effort_not_judged, 1u) << rep.summary();
    EXPECT_EQ(rep.effort_refused, 0u);
    EXPECT_NE(rep.summary().find("not judged 1"), std::string::npos) << rep.summary();
}
