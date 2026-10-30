// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// DASH full UTXO set from a pinned `dumptxoutset` snapshot (DESIGN S2):
/// the pin, the import into <net>/utxo_full_leveldb, and the rule that opens
/// that directory as the node's full set.
///
/// PIN. A snapshot is never loaded without one: the built-in
/// checkpoints/dash_utxo_snapshot_<network>.inc, or an operator file
/// (--embedded-utxo-snapshot-pin) for a newer snapshot. Both are the
/// digest-gated c2pool-utxo-snapshot/1 text (core/coin/utxo_snapshot.hpp). The
/// pin's coin must be "dash" and its network the node's; its height must not
/// be below the header chain's checkpoint (the chain the node can place the
/// base in starts there).
///
/// IMPORT. core::coin::import_utxo_snapshot (verify pass, then write pass),
/// with the node's records in the same synced final batch as 'B':
///   'S'  sync state v1 (anchor 0, best = base, strict, coins) — the set holds
///        every coin of the chain up to its base;
///   'A'  the assumed base (core/coin/utxo_assumed.hpp): height, hash, muhash,
///        hash_serialized_2, coins, coin, network, pin digest, validated = 0.
/// A coin with value 0 and an empty script refuses the import: c2pool's
/// Coin::is_spent() reads it as absent (VERIFY-S1 S2-3).
/// The base-in-header-chain check runs here when the header chain already
/// holds the pin's height; otherwise the lane runs it before it uses the set
/// (FullOpen below leaves it to UtxoLane::verify_base).
///
/// OPEN RULE (VERIFY-S1 S2-2). The directory is the node's full set only if:
///   'B' and 'S' are present, 'S' is tracked with anchor 0 and strict, 'A'
///   parses, 'A' is DASH on the node's network, its base is at or above the
///   checkpoint and at or below the set's best. 'C' records without 'B'/'S'
///   (an import cut short) refuse by name; the operator deletes the directory.
///   header(best) == best is the lane's check (UtxoLane::verify_base), run when
///   the header chain holds that height.
///
/// FENCED: src/impl/dash. Links core_utxo (c2pool-dash, test_dash_mempool).

#include "utxo_adapter.hpp"

#include <core/coin/utxo_assumed.hpp>
#include <core/coin/utxo_snapshot.hpp>
#include <core/coin/utxo_view_db.hpp>
#include <core/leveldb_store.hpp>
#include <core/log.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace dash {
namespace coin {

namespace utxo_snapshot_refusal {
inline constexpr const char* kNoPin            = "utxo-snapshot-no-pin";
inline constexpr const char* kPinUnreadable    = "utxo-snapshot-pin-unreadable";
inline constexpr const char* kPinInvalid       = "utxo-snapshot-pin-invalid";
inline constexpr const char* kPinWrongCoin     = "utxo-snapshot-pin-wrong-coin";
inline constexpr const char* kPinWrongNetwork  = "utxo-snapshot-pin-wrong-network";
inline constexpr const char* kBelowCheckpoint  = "utxo-snapshot-base-below-checkpoint";
inline constexpr const char* kFullDbIncomplete = "utxo-full-db-incomplete";
inline constexpr const char* kFullDbEmpty      = "utxo-full-db-empty";
inline constexpr const char* kFullDbNotTracked = "utxo-full-db-not-tracked";
inline constexpr const char* kFullDbNoAssumed  = "utxo-full-db-no-assumed-base";
inline constexpr const char* kFullDbWrongCoin  = "utxo-full-db-wrong-coin";
inline constexpr const char* kFullDbWrongNet   = "utxo-full-db-wrong-network";
inline constexpr const char* kFullDbBelowCkpt  = "utxo-full-db-base-below-checkpoint";
inline constexpr const char* kFullDbBestBelow  = "utxo-full-db-best-below-base";
inline constexpr const char* kFullDbOpenFailed = "utxo-full-db-open-failed";
inline constexpr const char* kFullDbHeld       = "utxo-full-db-held";
} // namespace utxo_snapshot_refusal

/// The built-in pin text of a network ("" = none shipped).
inline std::string builtin_dash_utxo_pin_text(const std::string& network)
{
    if (network == "mainnet") {
        static const char* kMainnet =
#include "checkpoints/dash_utxo_snapshot_mainnet.inc"
            ;
        return kMainnet;
    }
    return std::string();
}

struct DashUtxoPin {
    std::optional<::core::coin::SnapshotPin> pin;
    std::string digest;    // the pin's own digest line
    std::string source;    // "built-in mainnet" / "file <path>"
    std::string refusal;   // named, empty on success
    std::string detail;
};

/// Parse + check a pin text for the node's network.
inline DashUtxoPin check_dash_utxo_pin(const std::string& text, const std::string& network,
                                       const std::string& source)
{
    namespace R = utxo_snapshot_refusal;
    DashUtxoPin out;
    out.source = source;
    std::string err;
    auto pin = ::core::coin::parse_snapshot_pin(text, err);
    if (!pin) {
        out.refusal = R::kPinInvalid;
        out.detail = source + ": " + err;
        return out;
    }
    if (pin->coin != "dash") {
        out.refusal = R::kPinWrongCoin;
        out.detail = source + ": coin '" + pin->coin + "', this node is dash";
        return out;
    }
    if (pin->network != network) {
        out.refusal = R::kPinWrongNetwork;
        out.detail = source + ": network '" + pin->network + "', this node runs " + network;
        return out;
    }
    out.digest = ::core::coin::snapshot_pin_digest(::core::coin::render_snapshot_pin(*pin));
    out.pin = std::move(pin);
    return out;
}

/// The pin a node imports against: `pin_file` when given, else the built-in
/// pin of `network`. No pin = refused (a snapshot is never loaded without one).
inline DashUtxoPin load_dash_utxo_pin(const std::string& pin_file, const std::string& network)
{
    namespace R = utxo_snapshot_refusal;
    if (!pin_file.empty()) {
        std::ifstream f(pin_file, std::ios::binary);
        if (!f) {
            DashUtxoPin out;
            out.source = "file " + pin_file;
            out.refusal = R::kPinUnreadable;
            out.detail = pin_file;
            return out;
        }
        std::stringstream ss;
        ss << f.rdbuf();
        return check_dash_utxo_pin(ss.str(), network, "file " + pin_file);
    }
    const std::string text = builtin_dash_utxo_pin_text(network);
    if (text.empty()) {
        DashUtxoPin out;
        out.source = "built-in " + network;
        out.refusal = R::kNoPin;
        out.detail = "no built-in UTXO snapshot pin for " + network + "; pass --embedded-utxo-snapshot-pin";
        return out;
    }
    return check_dash_utxo_pin(text, network, "built-in " + network);
}

struct DashUtxoImportConfig {
    std::string network;
    uint32_t    min_base_height{0};   // the header chain's checkpoint height
    /// The header chain's hash at a height; nullopt = not held yet (the lane
    /// checks the base later). Empty = no header chain at all.
    ::core::coin::HeaderLookup hash_at_height;
    std::function<void(const std::string&)> log;
    size_t      batch_records{16384};
};

/// The records the import writes with 'B': 'S' (anchor 0, strict) and 'A'.
inline std::vector<std::pair<std::string, std::vector<uint8_t>>>
dash_full_set_final_records(const ::core::coin::SnapshotPin& pin, const std::string& digest,
                            const std::string& network)
{
    ::core::coin::SyncState s;
    s.anchor_height = 0;
    s.best_height = pin.height;
    s.strict = 1;
    s.synced = 0;
    s.coins = pin.coins;
    ::core::coin::AssumedBase a;
    a.base_height = pin.height;
    a.base_hash = pin.blockhash;
    a.muhash = pin.muhash;
    if (pin.hash_serialized_2) a.hash_serialized_2 = *pin.hash_serialized_2;
    a.coins = pin.coins;
    a.validated = 0;
    a.coin = "dash";
    a.network = network;
    a.pin_digest = digest;
    return {
        {::core::coin::UTXOViewDB::make_sync_key(), s.serialize()},
        {::core::coin::AssumedBase::key(), a.serialize()},
    };
}

/// Import `parts` into the empty full-set directory `db_path` against `pin`.
inline ::core::coin::SnapshotImportResult
import_dash_utxo_snapshot(const std::vector<std::string>& parts, const std::string& db_path,
                          const DashUtxoPin& pin, const DashUtxoImportConfig& cfg)
{
    namespace R = utxo_snapshot_refusal;
    ::core::coin::SnapshotImportResult r;
    auto log = [&](const std::string& l) { if (cfg.log) cfg.log(l); };
    if (!pin.pin) {
        r.refusal = pin.refusal.empty() ? R::kNoPin : pin.refusal;
        r.detail = pin.detail;
        log("[UTXO-SNAPSHOT] REFUSED " + r.refusal + ": " + r.detail);
        return r;
    }
    if (pin.pin->height < cfg.min_base_height) {
        r.refusal = R::kBelowCheckpoint;
        r.detail = "pin height " + std::to_string(pin.pin->height) + " is below the header chain's checkpoint " +
                   std::to_string(cfg.min_base_height);
        log("[UTXO-SNAPSHOT] REFUSED " + r.refusal + ": " + r.detail);
        return r;
    }
    ::core::coin::SnapshotImportOptions opts;
    if (cfg.hash_at_height && cfg.hash_at_height(pin.pin->height)) {
        opts.hash_at_height = cfg.hash_at_height;
    } else {
        // The header chain does not reach the base yet: the lane places it
        // (UtxoLane::verify_base) before the set prices or connects anything.
        opts.offline_no_header_chain = true;
    }
    opts.batch_records = cfg.batch_records;
    opts.log = cfg.log;
    opts.refuse_spent_shaped_coins = true;
    opts.final_records = dash_full_set_final_records(*pin.pin, pin.digest, cfg.network);
    return ::core::coin::import_utxo_snapshot(parts, db_path, *pin.pin, opts);
}

/// The full set, opened under the S2-2 rule (header check left to the lane).
struct DashFullSetOpen {
    std::unique_ptr<UtxoViewDB> db;
    ::core::coin::AssumedBase   assumed;
    bool        absent{false};   // no LevelDB directory there: nothing to open
    std::string refusal;         // named, empty on success
    std::string detail;
    bool ok() const { return db != nullptr; }
};

inline DashFullSetOpen open_dash_full_utxo_set(const std::string& db_path, const std::string& network,
                                               uint32_t min_base_height)
{
    namespace R = utxo_snapshot_refusal;
    DashFullSetOpen out;
    auto refuse = [&](const char* name, std::string detail) {
        out.refusal = name;
        out.detail = std::move(detail);
        out.db.reset();
        return std::move(out);
    };
    std::error_code ec;
    if (!std::filesystem::exists(std::filesystem::path(db_path) / "CURRENT", ec)) {
        out.absent = true;
        return out;
    }
    long holder = 0;
    if (::core::coin::leveldb_dir_lock_held(db_path, &holder))
        return refuse(R::kFullDbHeld, db_path + " is held by pid " + std::to_string(holder));
    ::core::LevelDBOptions opts;
    opts.block_cache_size  = 32 * 1024 * 1024;
    opts.write_buffer_size =  8 * 1024 * 1024;
    out.db = std::make_unique<UtxoViewDB>(db_path, opts);
    if (!out.db->open())
        return refuse(R::kFullDbOpenFailed, db_path);

    const bool have_best = !out.db->get_best_block().IsNull();
    const auto sync = out.db->get_sync_state();
    if (!have_best || !sync.tracked()) {
        bool any_coin = false;
        out.db->for_each_record(std::string(1, 'C'), [&](const std::string&, const std::vector<uint8_t>&) {
            any_coin = true;
            return false;
        });
        if (any_coin)
            return refuse(R::kFullDbIncomplete,
                          db_path + " holds coins without " + (have_best ? "a sync state" : "a best block") +
                              " (an import cut short); delete the directory and import again");
        return refuse(R::kFullDbEmpty, db_path + " holds no set");
    }
    if (sync.anchor_height != 0 || !sync.strict)
        return refuse(R::kFullDbNotTracked, "sync state anchor=" + std::to_string(sync.anchor_height) +
                                                " strict=" + std::to_string(int(sync.strict)) +
                                                ": not a full set");
    std::vector<uint8_t> raw;
    if (!out.db->get_record(::core::coin::AssumedBase::key(), raw) || !out.assumed.deserialize(raw))
        return refuse(R::kFullDbNoAssumed, "no readable assumed-base record");
    if (out.assumed.coin != "dash")
        return refuse(R::kFullDbWrongCoin, "set of coin '" + out.assumed.coin + "'");
    if (out.assumed.network != network)
        return refuse(R::kFullDbWrongNet, "set of network '" + out.assumed.network + "', node runs " + network);
    if (out.assumed.base_height < min_base_height)
        return refuse(R::kFullDbBelowCkpt, "base " + std::to_string(out.assumed.base_height) +
                                               " below the checkpoint " + std::to_string(min_base_height));
    if (out.db->get_best_height() < out.assumed.base_height)
        return refuse(R::kFullDbBestBelow, "best " + std::to_string(out.db->get_best_height()) +
                                               " below the base " + std::to_string(out.assumed.base_height));
    return out;
}

} // namespace coin
} // namespace dash
