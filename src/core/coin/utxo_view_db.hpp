#pragma once

/// UTXOViewDB: LevelDB-backed persistent UTXO store.
///
/// Stores unspent transaction outputs (coins) in LevelDB with atomic
/// batch writes for crash-safe block connection/disconnection.
///
/// Key schema:
///   'C' + txid(32B) + index(4B LE)  →  serialized Coin
///   'B'                              →  best_block_hash(32B) + height(4B LE)
///   'U' + height(4B BE)             →  BlockUndo format 1 (legacy, read-only:
///                                       no outpoints, cannot restore spent
///                                       coins; removed by a put at the same
///                                       height, aged out by prune_undo)
///   'R' + height(4B BE)             →  BlockUndo format 2 (serialize_block_undo_v2)
///   'F' + height(4B BE)             →  raw serialized full block (explorer)
///   'S'                              →  sync state (SyncState below), written
///                                       in the same batch as 'B'
///
/// Reference: Litecoin Core txdb.h CCoinsViewDB

#include "utxo.hpp"

#include <core/leveldb_store.hpp>
#include <core/uint256.hpp>
#include <core/log.hpp>

#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace core {
namespace coin {

/// What the set holds and how it was built ('S'). A DB without the record is
/// a legacy accrual view: anchor unknown, not strict.
///
/// Value: u8 version (1) | u32 LE anchor_height | u32 LE best_height |
///        u8 flags (bit 0 strict, bit 1 synced) | u64 LE coins
struct SyncState {
    static constexpr uint32_t ANCHOR_UNKNOWN = 0xFFFFFFFFu;
    static constexpr uint8_t  VERSION = 1;
    static constexpr uint8_t  FLAG_STRICT = 1;
    static constexpr uint8_t  FLAG_SYNCED = 2;
    static constexpr size_t   SIZE = 1 + 4 + 4 + 1 + 8;

    uint32_t anchor_height{ANCHOR_UNKNOWN};  // first height whose coins the set holds (0 = from genesis)
    uint32_t best_height{0};                 // mirrors 'B'
    uint8_t  strict{0};                      // 1 = connect refuses an unknown input (full mode)
    uint8_t  synced{0};                      // 1 = the set has reached the header chain's tip once
    uint64_t coins{0};                       // coins in the set (counted by the connects since anchor 0)

    /// The record exists (the set knows its anchor).
    bool tracked() const { return anchor_height != ANCHOR_UNKNOWN; }

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> v(SIZE, 0);
        v[0] = VERSION;
        for (int i = 0; i < 4; ++i) {
            v[1 + i] = static_cast<uint8_t>(anchor_height >> (8 * i));
            v[5 + i] = static_cast<uint8_t>(best_height >> (8 * i));
        }
        v[9] = static_cast<uint8_t>((strict ? FLAG_STRICT : 0) | (synced ? FLAG_SYNCED : 0));
        for (int i = 0; i < 8; ++i)
            v[10 + i] = static_cast<uint8_t>(coins >> (8 * i));
        return v;
    }

    /// False (state left as it was) for a record of another version or size.
    bool deserialize(const std::vector<uint8_t>& v) {
        if (v.size() != SIZE || v[0] != VERSION)
            return false;
        SyncState s;
        s.anchor_height = 0;
        s.best_height = 0;
        for (int i = 0; i < 4; ++i) {
            s.anchor_height |= uint32_t(v[1 + i]) << (8 * i);
            s.best_height |= uint32_t(v[5 + i]) << (8 * i);
        }
        s.strict = (v[9] & FLAG_STRICT) ? 1 : 0;
        s.synced = (v[9] & FLAG_SYNCED) ? 1 : 0;
        for (int i = 0; i < 8; ++i)
            s.coins |= uint64_t(v[10 + i]) << (8 * i);
        *this = s;
        return true;
    }
};

class UTXOViewDB {
public:
    explicit UTXOViewDB(const std::string& db_path,
                        const LevelDBOptions& opts = {})
        : m_store(db_path, opts)
    {}

    /// Open the database. Must be called before any other operation.
    bool open() {
        if (!m_store.open())
            return false;
        // Load best block state
        load_best_block();
        load_sync_state();
        LOG_INFO << "[UTXO-DB] opened at " << m_store.is_open()
                 << " best_height=" << m_best_height
                 << " best_block=" << m_best_block.GetHex().substr(0, 16)
                 << " anchor=" << (m_sync.tracked() ? std::to_string(m_sync.anchor_height) : std::string("unknown"))
                 << " strict=" << int(m_sync.strict) << " synced=" << int(m_sync.synced);
        return true;
    }

    void close() { m_store.close(); }
    bool is_open() const { return m_store.is_open(); }

    // ── Single-coin access ──────────────────────────────────────────────

    /// Retrieve a coin by outpoint. Returns false if not found.
    bool get_coin(const Outpoint& op, Coin& coin) {
        auto key = make_coin_key(op);
        std::vector<uint8_t> data;
        if (!m_store.get(key, data))
            return false;
        return deserialize_coin(data, coin);
    }

    /// Check if a coin exists.
    bool have_coin(const Outpoint& op) {
        auto key = make_coin_key(op);
        return m_store.exists(key);
    }

    // ── Best block state ────────────────────────────────────────────────

    uint256 get_best_block() const { return m_best_block; }
    uint32_t get_best_height() const { return m_best_height; }

    // ── Sync state ('S') ────────────────────────────────────────────────

    /// The set's sync state; {anchor unknown, not strict} without a record.
    SyncState get_sync_state() const { return m_sync; }

    /// Write the sync state now (its best_height is the DB's best). Every
    /// later write_batch rewrites it with the new best in the same batch.
    bool put_sync_state(SyncState s) {
        s.best_height = m_best_height;
        auto batch = m_store.create_batch();
        batch.put(make_sync_key(), s.serialize());
        if (!batch.commit())
            return false;
        m_sync = s;
        return true;
    }

    // ── Raw records (digest) ────────────────────────────────────────────

    /// Ordered scan of the raw records under `prefix` (false: scan error).
    bool for_each_record(const std::string& prefix,
                         const std::function<bool(const std::string&, const std::vector<uint8_t>&)>& fn) {
        return m_store.for_each_prefix(prefix, fn);
    }

    /// One raw record (false: absent).
    bool get_record(const std::string& key, std::vector<uint8_t>& value) {
        return m_store.get(key, value);
    }

    // ── Batch write (atomic block connection) ───────────────────────────

    /// Flags for coin changes:
    ///   - Coin present in optional → add/update
    ///   - nullopt → erase (spent)
    using CoinChange = std::optional<Coin>;
    using ChangeMap = std::unordered_map<Outpoint, CoinChange, OutpointHasher>;

    /// Atomically apply a batch of coin changes and update best block.
    /// This is called once per block connection or disconnection. A tracked
    /// set ('S' present) gets its sync state in the same batch: best_height
    /// and coins (+ coin_delta) never disagree with 'B' after a crash.
    bool write_batch(const ChangeMap& changes,
                     const uint256& best_block,
                     uint32_t best_height,
                     int64_t coin_delta = 0) {
        auto batch = m_store.create_batch();

        for (const auto& [op, change] : changes) {
            auto key = make_coin_key(op);
            if (change.has_value()) {
                // Add/update coin
                auto data = serialize_coin(*change);
                batch.put(key, data);
            } else {
                // Erase spent coin
                batch.remove(key);
            }
        }

        // Update best block
        {
            std::vector<uint8_t> state_data;
            state_data.resize(36);
            std::memcpy(state_data.data(), best_block.data(), 32);
            state_data[32] = best_height & 0xFF;
            state_data[33] = (best_height >> 8) & 0xFF;
            state_data[34] = (best_height >> 16) & 0xFF;
            state_data[35] = (best_height >> 24) & 0xFF;
            batch.put(make_state_key(), state_data);
        }

        SyncState sync = m_sync;
        if (sync.tracked()) {
            sync.best_height = best_height;
            const int64_t coins = static_cast<int64_t>(sync.coins) + coin_delta;
            sync.coins = coins > 0 ? static_cast<uint64_t>(coins) : 0;
            batch.put(make_sync_key(), sync.serialize());
        }

        if (!batch.commit())
            return false;

        m_best_block = best_block;
        m_best_height = best_height;
        m_sync = sync;
        return true;
    }

    // ── Block undo data ─────────────────────────────────────────────────

    /// Store undo data for a block at given height ('R', format 2). The legacy
    /// 'U' record at the same height goes in the same batch, so a reconnect at
    /// h never leaves a stale legacy record behind. False (nothing written) for
    /// a record without outpoints.
    bool put_block_undo(uint32_t height, const BlockUndo& undo) {
        auto data = serialize_block_undo_v2(undo);
        if (data.empty()) {
            LOG_ERROR << "[UTXO-DB] undo record at h=" << height
                      << " has no outpoints; not written";
            return false;
        }
        auto batch = m_store.create_batch();
        batch.put(make_undo_key(height), data);
        batch.remove(make_legacy_undo_key(height));
        return batch.commit();
    }

    /// Retrieve undo data for a block at given height: the format-2 record, else
    /// a legacy one (format = 1, no outpoints: BlockUndo::restorable() tells
    /// whether it can put the spent coins back). False if neither exists or the
    /// record does not parse.
    bool get_block_undo(uint32_t height, BlockUndo& undo) {
        std::vector<uint8_t> data;
        if (m_store.get(make_undo_key(height), data))
            return deserialize_block_undo_v2(data, undo);
        if (!m_store.get(make_legacy_undo_key(height), data))
            return false;
        undo = BlockUndo{};
        return deserialize_block_undo(data, undo);
    }

    /// Remove undo data for a block (after successful disconnect or pruning):
    /// both the format-2 and any legacy record.
    bool remove_block_undo(uint32_t height) {
        auto batch = m_store.create_batch();
        batch.remove(make_undo_key(height));
        batch.remove(make_legacy_undo_key(height));
        return batch.commit();
    }

    /// Legacy undo records in [lo, hi] (startup diagnostic).
    uint32_t count_legacy_undo(uint32_t lo, uint32_t hi) {
        uint32_t n = 0;
        for (uint64_t h = lo; h <= hi; ++h) {
            if (m_store.exists(make_legacy_undo_key(static_cast<uint32_t>(h))))
                ++n;
        }
        return n;
    }

    /// Drop every format-2 record in [lo, hi] that sits next to a legacy one
    /// at the same height. put_block_undo removes the legacy record, so both
    /// exist only when an older binary ran in between (downgrade, then
    /// upgrade again): it wrote the legacy record and left the format-2 one,
    /// which then describes an earlier connect at that height and would be
    /// read first. Returns how many were dropped (startup).
    uint32_t drop_shadowed_undo(uint32_t lo, uint32_t hi) {
        auto batch = m_store.create_batch();
        uint32_t n = 0;
        for (uint64_t h = lo; h <= hi; ++h) {
            const auto height = static_cast<uint32_t>(h);
            if (m_store.exists(make_legacy_undo_key(height)) && m_store.exists(make_undo_key(height))) {
                batch.remove(make_undo_key(height));
                ++n;
            }
        }
        if (n > 0 && !batch.commit())
            return 0;
        return n;
    }

    /// TEST ONLY: write `undo` as a legacy (format 1) record under 'U', as an
    /// older binary writes it. drop_v2: also drop the format-2 record at the
    /// same height (a node that connected the block before format 2 existed);
    /// false leaves it (an older binary run after an upgrade).
    bool put_block_undo_legacy(uint32_t height, const BlockUndo& undo, bool drop_v2 = true) {
        auto batch = m_store.create_batch();
        batch.put(make_legacy_undo_key(height), serialize_block_undo(undo));
        if (drop_v2)
            batch.remove(make_undo_key(height));
        return batch.commit();
    }

    // ── Raw block storage (explorer) ────────────────────────────────────

    /// Store raw serialized block at given height (for lite explorer API).
    bool put_raw_block(uint32_t height, const std::vector<uint8_t>& data) {
        return m_store.put(make_block_key(height), data);
    }

    /// Retrieve raw serialized block at given height.
    std::optional<std::vector<uint8_t>> get_raw_block(uint32_t height) {
        std::vector<uint8_t> data;
        if (!m_store.get(make_block_key(height), data))
            return std::nullopt;
        return data;
    }

    /// Remove raw block at given height.
    bool remove_raw_block(uint32_t height) {
        return m_store.remove(make_block_key(height));
    }

    /// Prune raw blocks below (tip_height - keep_depth).
    uint32_t prune_raw_blocks(uint32_t tip_height, uint32_t keep_depth) {
        if (tip_height <= keep_depth) return 0;
        uint32_t prune_below = tip_height - keep_depth;
        // Skip already-pruned range on first call (same fix as UTXOViewCache::prune_undo)
        if (m_oldest_block_height == 0 && prune_below > 0) {
            m_oldest_block_height = prune_below;
            return 0;
        }
        constexpr uint32_t MAX_PRUNE_BATCH = 500;
        uint32_t end = std::min(prune_below, m_oldest_block_height + MAX_PRUNE_BATCH);
        uint32_t pruned = 0;
        for (uint32_t h = m_oldest_block_height; h < end; ++h) {
            if (remove_raw_block(h))
                ++pruned;
        }
        m_oldest_block_height = end;
        if (pruned > 0) {
            LOG_INFO << "[UTXO-DB] Pruned " << pruned << " raw blocks below height "
                     << end << " (keep_depth=" << keep_depth << ")";
        }
        return pruned;
    }

    // ── Re-anchor (wipe) ────────────────────────────────────────────────

    /// Wipe the entire persisted accrual view — every coin ('C'), undo record
    /// ('U', 'R') and retained raw block ('F') — and reset best-block state to zero,
    /// so accrual restarts fresh from the next connected block. The sync state
    /// ('S') goes too: the anchor is unknown until the next arm writes one. Used when the
    /// confirmed header tip has advanced past the persisted view by more than
    /// one block (e.g. after a restart): the stale view cannot legally extend
    /// by one, so it is dropped and re-anchored rather than latching dead.
    ///
    /// Fail-closed: on a scan or commit failure the on-disk view and the cached
    /// best_* fields are left UNCHANGED and false is returned; the caller must
    /// then NOT connect the current block (hold the old view).
    bool reset() {
        // Snapshot every key under the data prefixes first (not removing
        // mid-iteration) so the scan reads a stable view, then batch-remove
        // them + zero the best-state marker in one atomic commit.
        std::vector<std::string> keys;
        auto collect = [&keys](const std::string& key,
                               const std::vector<uint8_t>&) {
            keys.push_back(key);
            return true;
        };
        for (char prefix : {'C', 'U', 'R', 'F'}) {
            if (!m_store.for_each_prefix(std::string(1, prefix), collect))
                return false;  // scan failure -> fail-closed, view untouched.
        }
        auto batch = m_store.create_batch();
        for (const auto& k : keys)
            batch.remove(k);
        // Reset best-block state to genesis-of-accrual (null hash, height 0).
        {
            std::vector<uint8_t> state_data(36, 0);
            batch.put(make_state_key(), state_data);
        }
        batch.remove(make_sync_key());
        if (!batch.commit())
            return false;  // commit failure -> fail-closed, cached fields intact.
        m_best_block = uint256();
        m_best_height = 0;
        m_oldest_block_height = 0;
        m_sync = SyncState{};
        return true;
    }

private:
    LevelDBStore m_store;
    uint256  m_best_block;
    uint32_t m_best_height{0};
    uint32_t m_oldest_block_height{0};  // for raw block pruning
    SyncState m_sync;

    // ── Key construction ────────────────────────────────────────────────

    static std::string make_coin_key(const Outpoint& op) {
        std::string key;
        key.reserve(37);  // 'C' + 32 + 4
        key.push_back('C');
        key.append(outpoint_to_key(op));
        return key;
    }

public:
    /// 'B' (best block) and 'S' (sync state) record keys.
    static std::string make_state_key() {
        return std::string(1, 'B');
    }
    static std::string make_sync_key() {
        return std::string(1, 'S');
    }

private:
    static std::string make_height_key(char prefix, uint32_t height) {
        std::string key;
        key.reserve(5);  // prefix + 4 bytes (big-endian for sorted iteration)
        key.push_back(prefix);
        key.push_back(static_cast<char>((height >> 24) & 0xFF));
        key.push_back(static_cast<char>((height >> 16) & 0xFF));
        key.push_back(static_cast<char>((height >> 8) & 0xFF));
        key.push_back(static_cast<char>(height & 0xFF));
        return key;
    }

    static std::string make_undo_key(uint32_t height) { return make_height_key('R', height); }
    static std::string make_legacy_undo_key(uint32_t height) { return make_height_key('U', height); }
    static std::string make_block_key(uint32_t height) { return make_height_key('F', height); }

    void load_best_block() {
        std::vector<uint8_t> data;
        if (m_store.get(make_state_key(), data) && data.size() >= 36) {
            std::memcpy(m_best_block.data(), data.data(), 32);
            m_best_height = uint32_t(data[32]) | (uint32_t(data[33]) << 8)
                          | (uint32_t(data[34]) << 16) | (uint32_t(data[35]) << 24);
        }
    }

    void load_sync_state() {
        m_sync = SyncState{};
        std::vector<uint8_t> data;
        if (m_store.get(make_sync_key(), data) && !m_sync.deserialize(data))
            LOG_ERROR << "[UTXO-DB] sync state record unreadable (" << data.size()
                      << " bytes); read as a legacy accrual view";
        if (m_sync.tracked() && m_sync.best_height != m_best_height)
            LOG_ERROR << "[UTXO-DB] sync state best_height=" << m_sync.best_height
                      << " disagrees with the best block's height " << m_best_height;
    }
};

} // namespace coin
} // namespace core
