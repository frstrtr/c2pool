// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
//
// found_block_import.hpp -- restore a node's found-block history from another
// node. Display only: nothing here reaches a share, a payout or a block.
//
// A node's found-block ledger only holds the blocks the node saw itself, so
// a node that joins the pool late (or lost its found_blocks_db) shows one
// block, and its Recent Blocks, luck and effort start from there. The pool's
// history is on every other node: its /recent_blocks rows. This is the
// one-shot that brings them in (--import-found-blocks FILE, repeatable or a
// comma list; YAML import_found_blocks), never an HTTP write endpoint: a
// public node must not let a stranger write its ledger.
//
// INPUT (parse): the /recent_blocks JSON array, as served, and the
// /recent_merged_blocks one (pow_hash / symbol) for the merged chains --
//     curl http://<node>:<web-port>/recent_blocks > blocks.json
//     curl http://<node>:<web-port>/recent_merged_blocks > merged.json
//     --import-found-blocks blocks.json --import-found-blocks merged.json
// -- or block hashes, one per line or as a JSON array of strings. A row needs its hash;
// height, ts, chain, network_difficulty, share_difficulty,
// pool_hashrate_at_find, share, miner, subsidy, coinbase_txid, tx_count and
// parent_hash are taken when present and well-formed.
//
// TRUST: only the HASH is taken on trust, and only as a question to the
// node's own header chain for the row's chain (LTC; DOGE for a merged row),
// each against its own root: what it refuses is counted per chain. A row gets
// in when that chain holds the hash on its best chain; the height, time and difficulty are then the header's (a
// height that disagrees is repaired, a missing one filled), never the file's.
// Anything else is refused and counted by reason. Whether the block is a
// POOL block can be checked only where the node has the block's coinbase
// (Source::pays_pool); elsewhere -- every old block on a daemonless node --
// the source is trusted on that, and the row says so (provenance
// "imported").
//
// IDEMPOTENT: a block the ledger already holds is merged, fill-only: a field
// the row lacks is filled, nothing the node recorded itself is replaced.
// Importing the same file twice changes nothing the second time.

#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace core {
namespace found_block_import {

/// One row of an import file. Every field but `hash` is optional:
/// 0 / "" / nullopt = not given.
struct Row {
    std::string             hash;                   ///< 64 hex chars, lowercase
    std::optional<uint64_t> height;
    uint64_t                ts{0};
    std::string             chain;                  ///< "" = the node's own chain
    double                  network_difficulty{0.0};
    double                  share_difficulty{0.0};
    double                  pool_hashrate{0.0};     ///< pool_hashrate_at_find
    std::string             share_hash;
    std::string             miner;
    uint64_t                subsidy{0};
    std::string             coinbase_txid;
    std::optional<uint32_t> tx_count;
    std::string             parent_hash;            ///< merged (aux) rows only
};

/// A parsed import file.
struct Parsed {
    std::vector<Row> rows;
    uint64_t malformed{0};               ///< entries that are not a row
    std::vector<std::string> problems;   ///< the first few, for the log
    std::string error;                   ///< non-empty: the file is unusable
    std::string format;                  ///< "json" or "hash_list"
};

/// Parse an import file's text (see the top of this file).
Parsed parse(const std::string& text);
/// Read and parse `path`; Parsed::error says why a file cannot be read.
Parsed read_file(const std::string& path);

/// One file of an import run (imported in the order given).
struct File {
    std::string name;   ///< for the log (the path)
    Parsed parsed;
};

/// A comma-separated path list ("blocks.json,merged.json") as paths; blanks
/// around each are dropped, empty items skipped. --import-found-blocks may
/// also be given more than once.
std::vector<std::string> split_paths(const std::string& list);

/// What a node's header chain says of one block hash.
struct Header {
    bool     known{false};       ///< the chain holds the header
    bool     main_chain{false};  ///< ... on its best chain
    uint64_t height{0};
    uint64_t ts{0};              ///< the header's time
    double   difficulty{0.0};    ///< off the header's bits
    uint64_t tip_height{0};      ///< the best chain's tip
};

/// One header chain to validate rows against.
struct ChainLookup {
    std::function<Header(const std::string& hash)> header;
    /// Can the chain judge a block yet (it is synced)? Null: always.
    std::function<bool()> ready;
    /// The lowest height the chain holds (a fast-start checkpoint). Null: 0.
    std::function<uint64_t()> lowest_height;
    explicit operator bool() const { return static_cast<bool>(header); }
};

/// Where an import is validated.
struct Source {
    /// The label this node records its own blocks under ("LTC", "tLTC").
    /// Empty: the node's symbol.
    std::string primary_chain;
    ChainLookup primary;
    /// Merged (aux) chains by their found-block label ("DOGE").
    std::map<std::string, ChainLookup> aux;
    /// Does the block's coinbase pay the pool's donation script? nullopt:
    /// its body is not at hand (an old block on a daemonless node).
    /// Parent-chain rows only. Null: never at hand.
    std::function<std::optional<bool>(const std::string& hash, uint64_t height)> pays_pool;
};

/// Rejection reasons (Report::rejected keys).
inline constexpr const char* kMalformed         = "malformed";
inline constexpr const char* kDuplicate         = "duplicate";
inline constexpr const char* kOtherChain        = "other_chain";
inline constexpr const char* kNoHeaderChain     = "no_header_chain";
inline constexpr const char* kNotOnChain        = "not_on_chain";
inline constexpr const char* kBelowHeaderChain  = "below_header_chain";
inline constexpr const char* kNotMainChain      = "not_main_chain";
inline constexpr const char* kNotPoolBlock      = "not_pool_block";
inline constexpr const char* kMergedUnvalidated = "merged_unvalidated";
/// Report::rejected_by_chain key of what parsing refused (no chain read yet).
inline constexpr const char* kUnparsedChain     = "file";

/// What an import did.
struct Report {
    uint64_t rows{0};              ///< rows considered (malformed entries included)
    uint64_t imported{0};          ///< new ledger rows
    uint64_t imported_aux{0};      ///< ... of which merged (aux) chain rows
    uint64_t merged{0};            ///< rows already held that gained a missing field
    uint64_t unchanged{0};         ///< rows already held, nothing to add
    uint64_t height_filled{0};     ///< rows without a height, given the header's
    uint64_t height_corrected{0};  ///< rows whose height the header contradicted
    uint64_t pool_verified{0};     ///< coinbase checked: pays the pool's donation
    uint64_t rate_refused{0};      ///< pool_hashrate_at_find not plausibly the pool's
    uint64_t pending{0};           ///< imported less than 6 deep: verified like a find
    std::map<std::string, uint64_t> imported_by_chain;   ///< chain label -> new rows
    std::map<std::string, uint64_t> rejected;            ///< reason -> rows, every chain
    /// chain label (the row's: "LTC", "DOGE", "BTC"; kUnparsedChain for what
    /// parsing refused) -> reason -> rows. A DOGE row below the DOGE header
    /// chain's checkpoint is DOGE below_header_chain, never LTC's.
    std::map<std::string, std::map<std::string, uint64_t>> rejected_by_chain;
    std::vector<Row> deferred;     ///< waiting for a header chain to be ready

    void reject(const char* reason, const std::string& chain, uint64_t n = 1)
    {
        if (!n) return;
        rejected[reason] += n;
        rejected_by_chain[chain][reason] += n;
    }
    uint64_t rejected_total() const
    {
        uint64_t n = 0;
        for (const auto& [reason, count] : rejected) n += count;
        return n;
    }
    /// Fold a later pass (or another file's report) in: counts add up and
    /// `deferred` rows are appended. `rows` is the caller's: a deferred row
    /// comes back in a later pass and must not be counted twice.
    void add(const Report& pass);
    /// One line for the log.
    std::string summary() const;
};

/// A ChainLookup over an embedded header chain whose get_header(hash) /
/// get_header_by_height(h) entries carry `height`, `block_hash`,
/// `header.m_timestamp` and `header.m_bits`, with height(), lowest_height()
/// and is_synced() (the LTC and DOGE header chains). `hc` must outlive it.
template <class HeaderChainT>
ChainLookup header_chain_lookup(const HeaderChainT* hc)
{
    ChainLookup l;
    if (!hc) return l;
    l.header = [hc](const std::string& hash_hex) -> Header {
        Header out;
        uint256 h;
        h.SetHex(hash_hex);
        const auto e = hc->get_header(h);
        if (!e) return out;
        out.known = true;
        out.height = static_cast<uint64_t>(e->height);
        out.ts = static_cast<uint64_t>(e->header.m_timestamp);
        out.difficulty = chain::target_to_difficulty(chain::bits_to_target(e->header.m_bits));
        const auto at = hc->get_header_by_height(e->height);
        out.main_chain = at && at->block_hash == h;
        out.tip_height = static_cast<uint64_t>(hc->height());
        return out;
    };
    l.ready = [hc]() { return hc->is_synced(); };
    l.lowest_height = [hc]() { return static_cast<uint64_t>(hc->lowest_height()); };
    return l;
}

} // namespace found_block_import
} // namespace core
