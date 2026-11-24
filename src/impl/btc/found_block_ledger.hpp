// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
//
// found_block_ledger.hpp -- c2pool-btc's found-block ledger across restarts
// (found_blocks_db) and from another node (--import-found-blocks). Display
// only: nothing here reaches a share, a payout, a block or the sharechain.
//
// The ledger is core::MiningInterface's (/recent_blocks, luck, effort).
// c2pool-btc held it in memory only, so every restart emptied Recent Blocks,
// and a node had no way to learn the blocks the pool found before it ran.
// This is main_ltc.cpp's wiring of the same two, for BTC:
//
//   * PERSISTENCE (LTC "Layer +2"): a LevelDB at <net_dir>/found_blocks_db,
//     <net_dir> the BTC network directory that holds embedded_headers
//     (<data>/bitcoin, bitcoin_testnet, bitcoin_testnet4, bitcoin_regtest).
//     LTC's ledger is <data>/mainnet|testnet/found_blocks_db: a BTC and an
//     LTC node on one data directory never share one. Every field a row
//     carries is stored and restored through
//     c2pool/storage/found_block_record_map.hpp, as on LTC.
//   * --import-found-blocks FILE[,FILE...] (repeatable): taken out of argv
//     before the main parse loop, so a value never swallows the next option;
//     each file is checked and canonicalized by
//     core::found_block_import::open_import_file before anything starts. The
//     import (core/found_block_import.hpp) waits for the embedded BTC header
//     chain to sync and takes a row only when that chain holds its hash on
//     its best chain. No merged chain is validated (an NMC row is refused as
//     merged_unvalidated) and no coinbase is checked (c2pool-btc keeps no
//     block bodies): a row's being a pool block is the source's word, and the
//     row says so (provenance "imported").

#include <c2pool/storage/found_block_record_map.hpp>
#include <c2pool/storage/found_block_store.hpp>
#include <core/found_block_import.hpp>
#include <core/leveldb_store.hpp>
#include <core/log.hpp>
#include <core/web_server.hpp>
#include <impl/btc/coin/header_chain.hpp>

#include <chrono>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace btc {
namespace found_block_ledger {

/// The chain label c2pool-btc records its own blocks under, on every network
/// (record_found_block's chain, the /recent_blocks "chain" field).
inline constexpr const char* kChainLabel = "BTC";

/// The ledger's LevelDB: <net_dir>/found_blocks_db, `net_dir` the BTC network
/// directory (core::filesystem::config_path() / "bitcoin", ...).
inline std::filesystem::path db_path(const std::filesystem::path& net_dir)
{
    return net_dir / "found_blocks_db";
}

/// Open the LevelDB at `path`, make it `mi`'s found-block store, restore the
/// rows it holds and seed the network-difficulty series from them. The store
/// lives as long as `mi`'s callbacks. false: it could not be opened, and the
/// ledger stays in memory only.
inline bool enable_persistence(core::MiningInterface& mi, const std::string& path)
{
    auto db = std::make_shared<core::LevelDBStore>(path, core::LevelDBOptions{});
    if (!db->open())
        return false;
    auto store = std::make_shared<c2pool::storage::FoundBlockStore>(*db);
    using FoundBlock = core::MiningInterface::FoundBlock;
    mi.set_found_block_persistence(
        [store, db](const FoundBlock& blk) -> bool {
            const auto rec = c2pool::storage::found_block_record_of(
                blk, static_cast<uint64_t>(std::time(nullptr)));
            // A corrected height names the key it moved from.
            return store->store(rec, blk.replaced_height);
        },
        [store, db]() -> std::vector<FoundBlock> {
            std::vector<FoundBlock> rows;
            for (const auto& rec : store->load_all())
                rows.push_back(c2pool::storage::found_block_of<FoundBlock>(rec));
            return rows;
        });
    mi.load_persisted_found_blocks();
    mi.seed_netdiff_history_from_found_blocks();
    return true;
}

/// --import-found-blocks FILE[,FILE...] (repeatable), taken out of argv.
struct ImportFlags {
    std::vector<std::string> paths;   ///< canonical, in the order given
    std::vector<bool> value_at;       ///< argv index -> a value taken here
    std::string error;                ///< non-empty: the node must not start

    /// argv[i] is an --import-found-blocks value (the main parse skips it).
    bool is_value(int i) const
    {
        return i >= 0 && static_cast<size_t>(i) < value_at.size()
            && value_at[static_cast<size_t>(i)];
    }
};

/// The pass over argv before the main parse loop. Refused (ImportFlags::error):
/// no value, or a value that is the next option (--import-found-blocks
/// --testnet would start a MAINNET node); a file open_import_file refuses
/// (missing, not a regular file, above the cap); a second file after the
/// value without its own flag.
inline ImportFlags take_import_flags(int argc, const char* const* argv)
{
    namespace fbi = core::found_block_import;
    ImportFlags out;
    out.value_at.assign(static_cast<size_t>(argc > 0 ? argc : 0), false);
    int cur = 1;
    while (cur < argc) {
        if (std::string(argv[cur]) != "--import-found-blocks") {
            ++cur;
            continue;
        }
        const std::string value = cur + 1 < argc ? argv[cur + 1] : "";
        if (value.empty() || value[0] == '-') {
            out.error = "--import-found-blocks needs a FILE (or FILE,FILE), got "
                + (value.empty() ? std::string("nothing") : "'" + value + "'");
            return out;
        }
        out.value_at[static_cast<size_t>(cur + 1)] = true;
        const auto paths = fbi::split_paths(value);
        if (paths.empty()) {
            out.error = "--import-found-blocks '" + value + "': no file named";
            return out;
        }
        for (const auto& p : paths) {
            const auto file = fbi::open_import_file(p);
            if (!file.error.empty()) {
                out.error = "--import-found-blocks " + p + ": " + file.error;
                return out;
            }
            out.paths.push_back(file.path);
        }
        const int after = cur + 2;
        if (after < argc && argv[after][0] != '-'
            && fbi::open_import_file(argv[after]).error.empty()) {
            out.error = "--import-found-blocks takes one FILE (or FILE,FILE): give "
                + std::string(argv[after]) + " its own --import-found-blocks";
            return out;
        }
        cur = after;
    }
    return out;
}

/// Where an import is validated: the embedded BTC header chain, for rows
/// labelled kChainLabel (a row without a label is one). `hc` must outlive the
/// import.
inline core::found_block_import::Source import_source(const btc::coin::HeaderChain* hc)
{
    core::found_block_import::Source src;
    src.primary_chain = kChainLabel;
    src.primary = core::found_block_import::header_chain_lookup(hc);
    return src;
}

/// The startup one-shot: read the files (`paths`, canonical, in order) and
/// import them into `mi`'s ledger, validated against `hc`, retrying on `mi`'s
/// io_context until the chain is synced (MiningInterface::start_found_block_import).
inline void start_import(core::MiningInterface& mi, const std::vector<std::string>& paths,
                         const btc::coin::HeaderChain* hc,
                         std::function<void(const core::found_block_import::Report&)> on_done = {})
{
    namespace fbi = core::found_block_import;
    std::vector<fbi::File> files;
    for (const auto& path : paths) {
        fbi::File f{path, fbi::read_file(path)};
        LOG_INFO << "[BTC-POOL] found-block import from " << path << ": "
                 << f.parsed.rows.size() << " rows ("
                 << (f.parsed.format.empty() ? "unreadable" : f.parsed.format) << ")";
        files.push_back(std::move(f));
    }
    mi.start_found_block_import(std::move(files), import_source(hc),
                                std::chrono::seconds(30), std::move(on_done));
}

} // namespace found_block_ledger
} // namespace btc
