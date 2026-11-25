// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// c2pool-btc found-block ledger (impl/btc/found_block_ledger.hpp): kept across
// restarts in found_blocks_db, and restorable from another node with
// --import-found-blocks. Display only.
//
// btc.voidbind.com showed an empty /recent_blocks: c2pool-btc held its ledger
// in memory only (every restart emptied it) and had no import. These KATs pin
// LTC's two wirings, ported:
//
//   * a row survives a restart: a fresh MiningInterface on the same LevelDB
//     gets back every persisted field of a row recorded the way main_btc
//     records one, of a fully enriched row and of an imported row;
//   * --import-found-blocks: the value never swallows the next option, a
//     comma list and a repeated flag work, and a missing value or file, an
//     option as the value, a directory and a second file without its own
//     flag are refused before the node starts;
//   * the import runs against the REAL embedded BTC header chain type
//     (btc::coin::HeaderChain, in memory, regtest headers mined here): a hash
//     on its best chain is imported under the BTC label with the header's
//     height and time, a hash it does not hold is refused as not_on_chain;
//   * main_btc.cpp uses these (source-structural guard).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include <unistd.h>

#include <nlohmann/json.hpp>

#include <core/found_block_import.hpp>
#include <core/uint256.hpp>
#include <core/web_server.hpp>
#include <impl/btc/coin/header_chain.hpp>
#include <impl/btc/found_block_ledger.hpp>

#ifndef BTC_MAIN_SRC
#error "BTC_MAIN_SRC must be defined by CMake to the path of src/c2pool/main_btc.cpp"
#endif

namespace {

namespace fbl = btc::found_block_ledger;
namespace fbi = core::found_block_import;
using core::MiningInterface;
using FoundBlock = core::MiningInterface::FoundBlock;

/// A fresh directory under the test temp dir.
std::filesystem::path fresh_dir(const std::string& name)
{
    const auto dir = std::filesystem::path(testing::TempDir())
        / (name + "_" + std::to_string(static_cast<long long>(::getpid())));
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    std::filesystem::create_directories(dir);
    return dir;
}

std::string write_file(const std::filesystem::path& path, const std::string& text)
{
    std::ofstream(path) << text;
    return path.string();
}

/// A BTC node's MiningInterface, as main_btc stands it up.
std::unique_ptr<MiningInterface> btc_mi()
{
    auto mi = std::make_unique<MiningInterface>(false, nullptr,
                                                c2pool::address::Blockchain::BITCOIN);
    mi->set_coin_label("BTC");
    return mi;
}

/// Mine `n` regtest headers onto `chain` (rooted at the regtest genesis),
/// the last one a minute ago so the chain counts as synced. Returns their
/// hashes, index i = height i + 1.
std::vector<uint256> mine(btc::coin::HeaderChain& chain, uint32_t n)
{
    std::vector<uint256> hashes;
    const auto now = static_cast<uint32_t>(std::time(nullptr));
    uint256 prev = chain.tip()->block_hash;
    for (uint32_t i = 0; i < n; ++i) {
        btc::coin::BlockHeaderType h;
        h.m_version = 0x20000000;
        h.m_previous_block = prev;
        h.m_merkle_root.SetHex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
        h.m_timestamp = now - 60 - (n - 1 - i) * 600;
        h.m_bits = 0x207fffff;   // regtest powLimit
        h.m_nonce = 0;
        const uint256 limit = btc::coin::target_from_bits(h.m_bits);
        while (!(btc::coin::block_hash(h) <= limit)) ++h.m_nonce;
        EXPECT_TRUE(chain.add_header(h)) << "header " << i + 1;
        prev = btc::coin::block_hash(h);
        hashes.push_back(prev);
    }
    return hashes;
}

/// Every field a stored row carries (c2pool/storage/found_block_record_map.hpp).
void expect_same_stored_fields(const FoundBlock& want, const FoundBlock& got)
{
    EXPECT_EQ(got.height, want.height);
    EXPECT_EQ(got.hash, want.hash);
    EXPECT_EQ(got.ts, want.ts);
    EXPECT_EQ(got.status, want.status);
    EXPECT_EQ(got.check_count, want.check_count);
    EXPECT_EQ(got.chain, want.chain);
    EXPECT_EQ(got.confirmations, want.confirmations);
    EXPECT_EQ(got.miner, want.miner);
    EXPECT_EQ(got.share_hash, want.share_hash);
    EXPECT_DOUBLE_EQ(got.network_difficulty, want.network_difficulty);
    EXPECT_DOUBLE_EQ(got.share_difficulty, want.share_difficulty);
    EXPECT_DOUBLE_EQ(got.pool_hashrate, want.pool_hashrate);
    EXPECT_EQ(got.subsidy, want.subsidy);
    EXPECT_EQ(got.authorship, want.authorship);
    EXPECT_EQ(got.parent_hash, want.parent_hash);
    EXPECT_EQ(got.parent_height, want.parent_height);
    EXPECT_EQ(got.coinbase_txid, want.coinbase_txid);
    EXPECT_EQ(got.tx_count, want.tx_count);
    EXPECT_EQ(got.aux_difficulty_known, want.aux_difficulty_known);
    EXPECT_EQ(got.imported, want.imported);
    EXPECT_DOUBLE_EQ(got.imported_effort, want.imported_effort);
    EXPECT_DOUBLE_EQ(got.imported_coverage, want.imported_coverage);
    EXPECT_EQ(got.imported_prev_hash, want.imported_prev_hash);
}

std::optional<FoundBlock> row(const MiningInterface& mi, const std::string& hash)
{
    for (const auto& b : mi.get_found_blocks())
        if (b.hash == hash) return b;
    return std::nullopt;
}

// Comments -> spaces (offsets kept); string and char literals left intact.
std::string strip_comments(const std::string& s)
{
    std::string out = s;
    enum { kCode, kLine, kBlock, kStr, kChr } st = kCode;
    for (size_t i = 0; i < out.size(); ++i) {
        const char c = out[i];
        const char n = (i + 1 < out.size()) ? out[i + 1] : '\0';
        switch (st) {
        case kCode:
            if (c == '/' && n == '/') { st = kLine; out[i] = ' '; }
            else if (c == '/' && n == '*') { st = kBlock; out[i] = ' '; }
            else if (c == '"') st = kStr;
            else if (c == '\'') st = kChr;
            break;
        case kLine:
            if (c == '\n') st = kCode; else out[i] = ' ';
            break;
        case kBlock:
            if (c == '*' && n == '/') { out[i] = ' '; out[i + 1] = ' '; ++i; st = kCode; }
            else if (c != '\n') out[i] = ' ';
            break;
        case kStr:
            if (c == '\\') ++i;
            else if (c == '"') st = kCode;
            break;
        case kChr:
            if (c == '\\') ++i;
            else if (c == '\'') st = kCode;
            break;
        }
    }
    return out;
}

std::string main_btc()
{
    std::ifstream in(BTC_MAIN_SRC);
    EXPECT_TRUE(in.good()) << "cannot open " << BTC_MAIN_SRC;
    std::stringstream ss;
    ss << in.rdbuf();
    return strip_comments(ss.str());
}

} // namespace

// ── found_blocks_db: a row survives a restart ──────────────────────────────
// The ledger is written to the LevelDB as rows are recorded, verified and
// imported; a fresh MiningInterface on the same path (the node restarted)
// gets every stored field of every row back, the rows marked as history.
TEST(BtcFoundBlockLedger, RowsSurviveARestart)
{
    const auto dir = fresh_dir("btc_fbl_restart");
    const std::string db = fbl::db_path(dir / "bitcoin").string();
    EXPECT_EQ(db, (dir / "bitcoin" / "found_blocks_db").string());

    btc::coin::HeaderChain chain(btc::coin::BTCChainParams::regtest());
    ASSERT_TRUE(chain.init());
    const auto headers = mine(chain, 12);

    // A: the way main_btc's won-block reporter records a block, then the
    // confirm lane's verdict.
    const std::string a = "00000000000000000001822dc3db70b75d281687f8baa10d1818d0703f49fec0";
    // B: every input a row can carry.
    const std::string b = "00000000000000000000c9f3c1b80c0f3fd57d18a8fc223cbec004f92b716fb7";
    // C: imported from another node, against the header chain.
    const std::string c = headers[3].GetHex();
    std::vector<FoundBlock> before;
    {
        auto mi = btc_mi();
        ASSERT_TRUE(fbl::enable_persistence(*mi, db));
        EXPECT_TRUE(mi->get_found_blocks().empty());
        mi->set_block_verify_fn([](const std::string&) { return 7; });

        mi->record_found_block(886688, uint256S(a), 1741327702, fbl::kChainLabel, "", a,
                               1.1e14, 0.0, 0.0, 0);
        EXPECT_EQ(mi->run_block_verification_now(a), 7);

        mi->record_found_block(955609, uint256S(b), 1782538484, fbl::kChainLabel,
                               "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", b,
                               1.3e14, 2.5e9, 7.5e17, 312500000,
                               MiningInterface::BlockAuthorship::this_node);

        const auto rep = mi->import_found_blocks(fbi::parse(c + "\n").rows,
                                                 fbl::import_source(&chain));
        EXPECT_EQ(rep.imported, 1u) << rep.summary();

        before = mi->get_found_blocks();
        ASSERT_EQ(before.size(), 3u);
    }   // the node stops: its callbacks, and the LevelDB, go

    auto restarted = btc_mi();
    ASSERT_TRUE(fbl::enable_persistence(*restarted, db));
    ASSERT_EQ(restarted->get_found_blocks().size(), 3u);
    for (const auto& want : before) {
        SCOPED_TRACE(want.hash);
        const auto got = row(*restarted, want.hash);
        ASSERT_TRUE(got.has_value()) << "row lost across the restart";
        expect_same_stored_fields(want, *got);
        EXPECT_TRUE(got->from_history);
    }
    const auto ra = row(*restarted, a);
    ASSERT_TRUE(ra.has_value());
    EXPECT_EQ(ra->chain, "BTC");
    EXPECT_EQ(ra->status, MiningInterface::BlockStatus::confirmed);
    EXPECT_EQ(ra->confirmations, 7u);
    const auto rc = row(*restarted, c);
    ASSERT_TRUE(rc.has_value());
    EXPECT_TRUE(rc->imported);
    EXPECT_EQ(rc->height, 4u);

    // Served as BTC rows of /recent_blocks.
    const auto rows = restarted->rest_recent_blocks();
    ASSERT_EQ(rows.size(), 3u) << rows.dump(1);
    for (const auto& r : rows)
        EXPECT_EQ(r["chain"].get<std::string>(), "BTC");

    restarted.reset();
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

// ── --import-found-blocks: the argv pass before the parse loop ─────────────
TEST(BtcFoundBlockLedger, ImportFlagIsParsedWithoutSwallowingTheNextOption)
{
    const auto dir = fresh_dir("btc_fbl_flag");
    const std::string a = write_file(dir / "a.json", "[]");
    const std::string b = write_file(dir / "b.txt", "# hashes\n");
    const std::string canon_a = std::filesystem::weakly_canonical(a).string();
    const std::string canon_b = std::filesystem::weakly_canonical(b).string();
    auto take = [](std::vector<std::string> args) {
        std::vector<const char*> argv;
        for (const auto& s : args) argv.push_back(s.c_str());
        return fbl::take_import_flags(static_cast<int>(argv.size()), argv.data());
    };
    // The arguments the parse loop still sees (main_btc skips is_value).
    auto rest = [](const std::vector<std::string>& args, const fbl::ImportFlags& f) {
        std::vector<std::string> out;
        for (int i = 1; i < static_cast<int>(args.size()); ++i)
            if (!f.is_value(i)) out.push_back(args[static_cast<size_t>(i)]);
        return out;
    };

    {   // One file, then an option: the option is still an option.
        const std::vector<std::string> args = {"c2pool-btc", "--import-found-blocks", a, "--testnet"};
        const auto f = take(args);
        EXPECT_EQ(f.error, "");
        EXPECT_EQ(f.paths, std::vector<std::string>({canon_a}));
        EXPECT_EQ(rest(args, f), std::vector<std::string>({"--import-found-blocks", "--testnet"}));
    }
    {   // A comma list.
        const std::vector<std::string> args = {"c2pool-btc", "--import-found-blocks", a + " ," + b + ",",
                                               "--http", "8083"};
        const auto f = take(args);
        EXPECT_EQ(f.error, "");
        EXPECT_EQ(f.paths, std::vector<std::string>({canon_a, canon_b}));
        EXPECT_EQ(rest(args, f), std::vector<std::string>({"--import-found-blocks", "--http", "8083"}));
    }
    {   // The flag twice, in order.
        const std::vector<std::string> args = {"c2pool-btc", "--import-found-blocks", b,
                                               "--import-found-blocks", a};
        const auto f = take(args);
        EXPECT_EQ(f.error, "");
        EXPECT_EQ(f.paths, std::vector<std::string>({canon_b, canon_a}));
    }
    {   // No flag: nothing taken.
        const auto f = take({"c2pool-btc", "--testnet", a});
        EXPECT_EQ(f.error, "");
        EXPECT_TRUE(f.paths.empty());
        EXPECT_FALSE(f.is_value(2));
    }

    // Refused before the node starts.
    EXPECT_NE(take({"c2pool-btc", "--import-found-blocks"}).error.find("needs a FILE"),
              std::string::npos);
    EXPECT_NE(take({"c2pool-btc", "--import-found-blocks", "--testnet"}).error.find("needs a FILE"),
              std::string::npos) << "the next option must not be taken as the file";
    EXPECT_NE(take({"c2pool-btc", "--import-found-blocks", (dir / "none.json").string()})
                  .error.find("no such file"),
              std::string::npos);
    EXPECT_NE(take({"c2pool-btc", "--import-found-blocks", a + "," + (dir / "none.json").string()})
                  .error.find("no such file"),
              std::string::npos) << "every file of a comma list is checked";
    EXPECT_NE(take({"c2pool-btc", "--import-found-blocks", dir.string()}).error.find("not a regular file"),
              std::string::npos);
    EXPECT_NE(take({"c2pool-btc", "--import-found-blocks", " , "}).error.find("no file named"),
              std::string::npos);
    EXPECT_NE(take({"c2pool-btc", "--import-found-blocks", a, b}).error.find("its own --import-found-blocks"),
              std::string::npos) << "a second file without its own flag";

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

// ── The import, against the embedded BTC header chain ──────────────────────
// Only a hash the node's own BTC header chain holds on its best chain gets
// in, under the BTC label, with the header's height and time; anything else
// is refused and counted by reason.
TEST(BtcFoundBlockLedger, ImportTakesOnlyBlocksOfTheBtcHeaderChain)
{
    btc::coin::HeaderChain chain(btc::coin::BTCChainParams::regtest());
    ASSERT_TRUE(chain.init());
    const auto headers = mine(chain, 12);
    ASSERT_EQ(chain.height(), 12u);
    ASSERT_TRUE(chain.is_synced());
    EXPECT_EQ(chain.lowest_height(), 0u) << "rooted at genesis";

    const auto dir = fresh_dir("btc_fbl_import");
    const std::string on_chain = headers[4].GetHex();   // height 5
    const std::string phantom =
        "00000000000000000000c9f3c1b80c0f3fd57d18a8fc223cbec004f92b716fb7";
    const std::string list = write_file(dir / "blocks.txt",
        "# BTC blocks of the pool\n" + on_chain + "\n" + phantom + "\n");
    const std::string json = write_file(dir / "blocks.json",
        nlohmann::json::array({
            {{"hash", headers[6].GetHex()}, {"height", 999}, {"chain", "BTC"}, {"ts", 1}},
            {{"hash", headers[7].GetHex()}, {"height", 8}, {"chain", "LTC"}},
        }).dump());

    auto mi = btc_mi();
    std::optional<fbi::Report> done;
    fbl::start_import(*mi, {list, json}, &chain,
                      [&done](const fbi::Report& r) { done = r; });
    ASSERT_TRUE(done.has_value()) << "a synced chain judges every row in the first pass";
    EXPECT_EQ(done->imported, 2u) << done->summary();
    EXPECT_EQ(done->imported_by_chain.at("BTC"), 2u);
    EXPECT_EQ(done->rejected_by_chain["BTC"][fbi::kNotOnChain], 1u) << done->summary();
    EXPECT_EQ(done->rejected_by_chain["LTC"][fbi::kOtherChain], 1u) << done->summary();
    EXPECT_EQ(done->height_corrected, 1u);
    EXPECT_TRUE(done->deferred.empty());

    const auto got = row(*mi, on_chain);
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(got->chain, "BTC");
    EXPECT_EQ(got->height, 5u);
    EXPECT_EQ(got->ts, chain.get_header(headers[4])->header.m_timestamp);
    EXPECT_TRUE(got->imported);
    EXPECT_EQ(got->status, MiningInterface::BlockStatus::confirmed) << "8 deep";
    const auto repaired = row(*mi, headers[6].GetHex());
    ASSERT_TRUE(repaired.has_value());
    EXPECT_EQ(repaired->height, 7u) << "the header's height, not the file's";
    EXPECT_FALSE(row(*mi, phantom).has_value()) << "a hash the BTC header chain does not hold";
    EXPECT_FALSE(row(*mi, headers[7].GetHex()).has_value()) << "another chain's row";

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

// ── main_btc.cpp uses the above ────────────────────────────────────────────
TEST(BtcFoundBlockLedger, MainBtcWiresPersistenceAndImport)
{
    const auto src = main_btc();
    ASSERT_FALSE(src.empty());

    // The argv pass runs before the parse loop, whose values it skips.
    const auto take = src.find("btc::found_block_ledger::take_import_flags(argc, argv)");
    const auto loop = src.find("import_found_blocks.is_value(i)");
    ASSERT_NE(take, std::string::npos);
    ASSERT_NE(loop, std::string::npos);
    EXPECT_LT(take, loop);
    EXPECT_NE(src.find("arg == \"--import-found-blocks\""), std::string::npos);

    // The won-block reporter records under the label the import validates.
    const auto reporter = src.find("*found_block_report =");
    const auto recorded = src.find("mi->record_found_block(", reporter);
    ASSERT_NE(reporter, std::string::npos);
    ASSERT_NE(recorded, std::string::npos);
    EXPECT_LT(src.find("btc::found_block_ledger::kChainLabel", recorded),
              src.find(';', recorded))
        << "record_found_block's chain must be btc::found_block_ledger::kChainLabel";

    // Persistence beside this network's embedded_headers, after the stat log
    // and the verify fn; then the pending rows re-verified, then the import.
    const auto verify = src.find("mi->set_block_verify_fn(");
    const auto stat_log = src.find("mi->load_stat_log();");
    const auto persist = src.find(
        "btc::found_block_ledger::enable_persistence(*mi, fblk_db_path)");
    const auto path = src.find("btc::found_block_ledger::db_path(net_dir)");
    const auto reverify = src.find("mi->reverify_pending_found_blocks();");
    const auto import = src.find(
        "btc::found_block_ledger::start_import(*mi, import_found_blocks.paths, &header_chain)");
    ASSERT_NE(verify, std::string::npos);
    ASSERT_NE(stat_log, std::string::npos);
    ASSERT_NE(persist, std::string::npos) << "found-block persistence is not wired";
    ASSERT_NE(path, std::string::npos);
    ASSERT_NE(reverify, std::string::npos);
    ASSERT_NE(import, std::string::npos) << "--import-found-blocks is not run";
    EXPECT_LT(verify, persist);
    EXPECT_LT(stat_log, persist);
    EXPECT_LT(path, persist);
    EXPECT_LT(persist, reverify);
    EXPECT_LT(reverify, import);
    EXPECT_NE(src.find("net_dir = core::filesystem::config_path() / net_subdir"),
              std::string::npos);
}
