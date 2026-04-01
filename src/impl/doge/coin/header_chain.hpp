// DOGE HeaderChain — Phase 5.2
// Copy of LTC header_chain.hpp with DOGE-specific difficulty (DigiShield v3)
// and chain parameters. Reuses scrypt PoW, LevelDB persistence, and P2P sync.

#pragma once

/// DOGE Header Chain — Phase 5.2
///
/// Validated header-only chain for Dogecoin. Reuses LTC scrypt PoW
/// and block format. Difficulty: DigiShield v3 (per-block retarget).

#include <impl/ltc/coin/block.hpp>
#include <impl/doge/coin/chain_params.hpp>

#include <core/uint256.hpp>
#include <core/leveldb_store.hpp>
#include <core/log.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>

#include <btclibs/crypto/scrypt.h>

#include <atomic>
#include <map>
#include <mutex>
#include <optional>
#include <thread>
#include <functional>
#include <iomanip>
#include <string>
#include <vector>

namespace doge {
namespace coin {

// Reuse LTC block types — DOGE uses identical Bitcoin wire format
using ltc::coin::BlockHeaderType;
using ltc::coin::BlockType;
// PoW functions (scrypt_hash, check_pow, block_hash, get_block_proof) are
// defined inline below — copied from LTC since they're header-local.

// ─── Index Entry ────────────────────────────────────────────────────────────

/// Status flags for header validation state
enum HeaderStatus : uint32_t {
    HEADER_VALID_UNKNOWN  = 0,
    HEADER_VALID_HEADER   = 1,  // Header parsed and PoW valid
    HEADER_VALID_TREE     = 2,  // Connected to genesis via prev_hash chain
    HEADER_VALID_CHAIN    = 3,  // Difficulty validated
};

/// A validated header with chain metadata.
struct IndexEntry {
    BlockHeaderType header;
    uint256         hash;           // scrypt(header) for PoW check, SHA256d for identification
    uint256         block_hash;     // SHA256d(header) — the "real" block hash used for getdata/inv
    uint32_t        height{0};
    uint256         chain_work;     // cumulative work up to this header
    uint256         prev_hash;
    HeaderStatus    status{HEADER_VALID_UNKNOWN};

    // Serialization for LevelDB persistence
    template<typename Stream>
    void Serialize(Stream& s) const {
        ::Serialize(s, header);
        ::Serialize(s, hash);
        ::Serialize(s, block_hash);
        ::Serialize(s, height);
        ::Serialize(s, chain_work);
        ::Serialize(s, prev_hash);
        ::Serialize(s, static_cast<uint32_t>(status));
    }
    template<typename Stream>
    void Unserialize(Stream& s) {
        ::Unserialize(s, header);
        ::Unserialize(s, hash);
        ::Unserialize(s, block_hash);
        ::Unserialize(s, height);
        ::Unserialize(s, chain_work);
        ::Unserialize(s, prev_hash);
        uint32_t st;
        ::Unserialize(s, st);
        status = static_cast<HeaderStatus>(st);
    }
};

// DOGEChainParams is defined in chain_params.hpp (included above)

// ─── PoW Functions ──────────────────────────────────────────────────────────

/// Compute scrypt hash of an 80-byte block header (for PoW validation).
inline uint256 scrypt_hash(const BlockHeaderType& header) {
    auto packed = pack(header);
    char pow_hash_bytes[32];
    scrypt_1024_1_1_256(reinterpret_cast<const char*>(packed.data()), pow_hash_bytes);
    uint256 result;
    memcpy(result.data(), pow_hash_bytes, 32);
    return result;
}

/// Compute SHA256d hash of an 80-byte block header (block identification).
inline uint256 block_hash(const BlockHeaderType& header) {
    auto packed = pack(header);
    return Hash(packed.get_span());
}

/// Compute the target from compact nBits representation.
inline uint256 target_from_bits(uint32_t bits) {
    uint256 target;
    target.SetCompact(bits);
    return target;
}

/// Check that a scrypt hash meets the target specified by nBits.
inline bool check_pow(const uint256& scrypt_hash_val, uint32_t bits, const uint256& pow_limit) {
    bool negative, overflow;
    uint256 target;
    target.SetCompact(bits, &negative, &overflow);

    if (negative || target.IsNull() || overflow || target > pow_limit)
        return false;

    return scrypt_hash_val <= target;
}

/// Compute work represented by a compact target.
/// Work = 2^256 / (target + 1)
inline uint256 get_block_proof(uint32_t bits) {
    bool negative, overflow;
    uint256 target;
    target.SetCompact(bits, &negative, &overflow);

    if (negative || target.IsNull() || overflow)
        return uint256::ZERO;

    // work = ~target / (target + 1) + 1
    return (~target / (target + uint256::ONE)) + uint256::ONE;
}

// ─── LTC Difficulty Retarget ────────────────────────────────────────────────
// Adapted from Litecoin Core pow.cpp (MIT license).
// Litecoin uses Bitcoin's original 2016-block retarget with:
//   nPowTargetTimespan = 3.5 days (302400 s)
//   nPowTargetSpacing  = 2.5 min (150 s)
//   DifficultyAdjustmentInterval = 302400 / 150 = 2016

// DOGE difficulty calculation is in chain_params.hpp: calculate_doge_next_work()
// DigiShield v3 for height >= 145000, standard retarget for earlier blocks.

// ─── HeaderChain ────────────────────────────────────────────────────────────

class HeaderChain {
public:
    HeaderChain(const DOGEChainParams& params, const std::string& db_path = "")
        : m_params(params)
        , m_db_path(db_path)
    {
    }

    ~HeaderChain() = default;

    // Disable copy
    HeaderChain(const HeaderChain&) = delete;
    HeaderChain& operator=(const HeaderChain&) = delete;

    /// Initialize: open LevelDB (if path given), load persisted state.
    /// Returns false if LevelDB open fails.
    bool init() {
        if (!m_db_path.empty()) {
            core::LevelDBOptions opts;
            opts.write_buffer_size = 2 * 1024 * 1024;  // 2MB
            opts.block_cache_size = 4 * 1024 * 1024;    // 4MB
            m_db = std::make_unique<core::LevelDBStore>(m_db_path, opts);
            if (!m_db->open())
                return false;
            load_from_db();
        }
        // Fast-start checkpoint: if chain is empty and a checkpoint is configured,
        // seed it as the starting point.  All headers before this height are
        // implicitly trusted.  The chain will sync forward from this point.
        if (m_tip.IsNull() && m_params.fast_start_checkpoint.has_value()) {
            auto& cp = m_params.fast_start_checkpoint.value();
            IndexEntry entry;
            entry.block_hash = cp.hash;
            entry.height = cp.height;
            entry.chain_work = uint256::ONE;  // minimal non-zero work
            entry.prev_hash = uint256::ZERO;  // no parent (checkpoint is trusted root)
            entry.status = HEADER_VALID_CHAIN;
            // Minimal header — we don't have the actual header data, but we
            // have the hash.  Peers will send headers AFTER this point.
            entry.header.m_previous_block.SetNull();

            m_headers[cp.hash] = entry;
            m_height_index[cp.height] = cp.hash;
            m_tip = cp.hash;
            m_tip_height = cp.height;
            m_best_work = entry.chain_work;
            persist_header(entry);
            persist_tip();
            LOG_INFO << "HeaderChain: fast-start from checkpoint height="
                     << cp.height << " hash=" << cp.hash.GetHex().substr(0, 16) << "...";
        }
        return true;
    }

    /// Current chain tip (best header).
    std::optional<IndexEntry> tip() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_tip.IsNull()) return std::nullopt;
        auto it = m_headers.find(m_tip);
        if (it == m_headers.end()) return std::nullopt;
        return it->second;
    }

    /// Current chain tip height. Returns 0 if empty.
    uint32_t height() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_tip_height;
    }

    /// Cumulative work of the best chain.
    uint256 cumulative_work() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_best_work;
    }

    /// Number of headers stored.
    size_t size() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_headers.size();
    }

    /// Check if we have a header by its SHA256d block hash.
    bool has_header(const uint256& block_hash) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_headers.count(block_hash) > 0;
    }

    /// Get header by SHA256d block hash.
    std::optional<IndexEntry> get_header(const uint256& block_hash) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_headers.find(block_hash);
        if (it == m_headers.end()) return std::nullopt;
        return it->second;
    }

    /// Get header by height (only works for headers on the best chain).
    std::optional<IndexEntry> get_header_by_height(uint32_t h) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_height_index.find(h);
        if (it == m_height_index.end()) return std::nullopt;
        auto hit = m_headers.find(it->second);
        if (hit == m_headers.end()) return std::nullopt;
        return hit->second;
    }

    /// Add a single header. Returns true if accepted (new + valid).
    bool add_header(const BlockHeaderType& header) {
        PendingTipChange ptc;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            bool ok = add_header_internal(header);
            if (ok) persist_tip();
            ptc = m_pending_tip_change;
            m_pending_tip_change.fired = false;
            if (!ok) return false;
        }
        // Fire tip-changed callback OUTSIDE the mutex to avoid deadlock
        if (ptc.fired && m_on_tip_changed)
            m_on_tip_changed(ptc.old_tip, ptc.old_height, ptc.new_tip, ptc.new_height);
        return true;
    }

    /// Set the estimated network tip height (from peer's version message).
    /// Used to skip scrypt PoW validation for old headers during initial sync.
    /// Headers below (tip - SCRYPT_VALIDATION_DEPTH) are validated structurally
    /// only (prev_hash linkage + difficulty retarget), making bulk sync ~100x faster.
    /// Set the estimated network tip height (from peer's version message).
    void set_peer_tip_height(uint32_t height) { m_peer_tip_height.store(height); }

    /// Dynamically seed a checkpoint at runtime (e.g., from RPC getblockhash).
    /// Only applied if the chain is still at or below the hardcoded checkpoint.
    /// This allows an accessible daemon to provide a more recent starting point.
    void set_dynamic_checkpoint(uint32_t height, const uint256& hash) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (height > m_tip_height) {
            IndexEntry entry;
            entry.block_hash = hash;
            entry.height = height;
            entry.chain_work = uint256::ONE;
            entry.prev_hash = uint256::ZERO;
            entry.status = HEADER_VALID_CHAIN;
            entry.header.m_previous_block.SetNull();
            m_headers[hash] = entry;
            m_height_index[height] = hash;
            m_tip = hash;
            m_tip_height = height;
            m_best_work = entry.chain_work;
            persist_header(entry);
            persist_tip();
            LOG_INFO << "HeaderChain: dynamic checkpoint at height="
                     << height << " hash=" << hash.GetHex().substr(0, 16) << "...";
        }
    }

    /// Add a batch of headers (from a `headers` P2P message).
    /// Returns the number of new headers accepted.
    /// Processes in sub-batches to avoid holding the mutex for the entire batch.
    /// With fast-sync (scrypt skipped for old headers), structural validation
    /// is microseconds per header, so large batches are fine.  Near the tip
    /// (scrypt active), each header takes ~20ms, so we use smaller batches.
    int add_headers(const std::vector<BlockHeaderType>& headers) {
        uint32_t peer_tip = m_peer_tip_height.load(std::memory_order_relaxed);
        // Large batches during fast-sync (no scrypt), small near tip (scrypt active)
        size_t BATCH_SIZE = (peer_tip > 0 && m_tip_height + 2100 < peer_tip) ? 500 : 50;
        int accepted = 0;
        PendingTipChange last_ptc;
        for (size_t offset = 0; offset < headers.size(); offset += BATCH_SIZE) {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                size_t end = std::min(offset + BATCH_SIZE, headers.size());
                for (size_t i = offset; i < end; ++i) {
                    if (add_header_internal(headers[i]))
                        ++accepted;
                }
                // Capture any pending tip change from this batch
                if (m_pending_tip_change.fired)
                    last_ptc = m_pending_tip_change;
                m_pending_tip_change.fired = false;
            }
            // Yield between batches so ioc-thread callers (get_height,
            // is_synced, get_tip) can acquire the mutex.
            if (offset + BATCH_SIZE < headers.size()) {
                // Short yield during fast-sync (structural only), longer near tip (scrypt)
                auto ms = (BATCH_SIZE >= 500) ? 1 : 10;
                std::this_thread::sleep_for(std::chrono::milliseconds(ms));
            }
        }
        if (accepted > 0) {
            std::lock_guard<std::mutex> lock(m_mutex);
            persist_tip();
            // Progress indicator for header sync
            uint32_t peer_tip = m_peer_tip_height.load(std::memory_order_relaxed);
            if (peer_tip > 0 && m_tip_height > 0) {
                double pct = 100.0 * m_tip_height / peer_tip;
                // Log every 1% or every 2000 blocks
                static uint32_t s_last_logged = 0;
                if (m_tip_height - s_last_logged >= 2000 || pct >= 99.9) {
                    s_last_logged = m_tip_height;
                    LOG_INFO << "[DOGE] Header sync: " << m_tip_height << "/" << peer_tip
                             << " (" << std::fixed << std::setprecision(1) << pct << "%)";
                }
            }
        }
        // Fire tip-changed callback OUTSIDE the mutex to avoid deadlock
        if (last_ptc.fired && m_on_tip_changed)
            m_on_tip_changed(last_ptc.old_tip, last_ptc.old_height, last_ptc.new_tip, last_ptc.new_height);
        return accepted;
    }

    /// Build a block locator for getheaders (BIP 31-style exponential backoff).
    /// Returns a list of block hashes from tip back to genesis.
    std::vector<uint256> get_locator() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return get_locator_internal();
    }

    /// Check if a prev_hash connects to our chain.
    bool is_connected(const uint256& prev_hash) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_headers.count(prev_hash) > 0;
    }

    /// Whether the chain is synced (tip timestamp within 2 hours of wall clock).
    /// The 2-hour (7200s) threshold matches Bitcoin Core's IsInitialBlockDownload()
    /// check (chainparams.h nMaxTipAge). p2pool uses the same gate implicitly:
    /// getblocktemplate() fails until the daemon considers itself synced.
    bool is_synced() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_tip.IsNull()) return false;
        auto it = m_headers.find(m_tip);
        if (it == m_headers.end()) return false;
        auto now = static_cast<uint32_t>(std::time(nullptr));
        uint32_t age = now - it->second.header.m_timestamp;
        bool synced = age < 7200; // 2 hours
        // Log state changes (throttled via static)
        static bool s_last_synced = false;
        if (synced != s_last_synced) {
            LOG_INFO << "[EMB-DOGE] Sync state changed: synced=" << synced
                     << " tip_age=" << age << "s height=" << m_tip_height;
            s_last_synced = synced;
        }
        return synced;
    }

    /// Get params (for external difficulty validation tests).
    const DOGEChainParams& params() const { return m_params; }

    /// Register a callback fired when the chain tip changes (reorg or equal-work switch).
    /// Signature: void(old_tip_hash, old_height, new_tip_hash, new_height)
    using TipChangedCallback = std::function<void(const uint256&, uint32_t, const uint256&, uint32_t)>;
    void set_on_tip_changed(TipChangedCallback cb) { m_on_tip_changed = std::move(cb); }

private:
    /// Add a single header (caller holds mutex).
    bool add_header_internal(const BlockHeaderType& header) {
        // Compute hashes
        uint256 bhash = block_hash(header);
        
        // Skip if already known
        if (m_headers.count(bhash))
            return false;

        // Genesis block special case: accept if it matches known genesis
        if (header.m_previous_block.IsNull()) {
            if (bhash != m_params.genesis_hash)
                return false; // wrong genesis
            
            IndexEntry entry;
            entry.header = header;
            entry.block_hash = bhash;
            entry.hash = scrypt_hash(header);
            entry.height = 0;
            entry.chain_work = get_block_proof(header.m_bits);
            entry.prev_hash = uint256::ZERO;
            entry.status = HEADER_VALID_CHAIN;

            m_headers[bhash] = entry;
            m_height_index[0] = bhash;
            m_tip = bhash;
            m_tip_height = 0;
            m_best_work = entry.chain_work;
            persist_header(entry);
            return true;
        }

        // Must connect to an existing header
        auto prev_it = m_headers.find(header.m_previous_block);
        if (prev_it == m_headers.end())
            return false; // orphan — not connected

        const auto& prev = prev_it->second;
        uint32_t new_height = prev.height + 1;

        // AuxPoW blocks (DOGE after auxpow_height): PoW is on the PARENT block
        // header (e.g. LTC), not on the 80-byte DOGE base header.  Since we only
        // store the base header (AuxPoW proof stripped during parsing), we cannot
        // validate PoW from the base header alone.  For AuxPoW blocks, rely on
        // structural validation (prev_hash linkage + difficulty retarget) only.
        //
        // Non-AuxPoW blocks (pre-auxpow_height): validate scrypt PoW normally,
        // with fast-sync skip for old headers during initial sync.
        bool is_auxpow = m_params.is_auxpow(new_height);
        uint256 pow_hash;
        if (is_auxpow) {
            // AuxPoW: trust PoW (validated by parent chain), store SHA256d placeholder
            pow_hash = block_hash(header);
        } else {
            // Non-AuxPoW: scrypt PoW validation (with fast-sync skip for old headers)
            static constexpr uint32_t SCRYPT_VALIDATION_DEPTH = 2100;
            uint32_t peer_tip = m_peer_tip_height.load(std::memory_order_relaxed);
            bool need_scrypt = (peer_tip == 0)
                            || (new_height + SCRYPT_VALIDATION_DEPTH >= peer_tip);
            if (need_scrypt) {
                pow_hash = scrypt_hash(header);
                if (!check_pow(pow_hash, header.m_bits, m_params.pow_limit))
                    return false;
            } else {
                pow_hash = block_hash(header);
            }
        }

        // Validate difficulty
        if (!validate_difficulty(header, new_height))
            return false;

        // Build index entry
        IndexEntry entry;
        entry.header = header;
        entry.block_hash = bhash;
        entry.hash = pow_hash;
        entry.height = new_height;
        entry.chain_work = prev.chain_work + get_block_proof(header.m_bits);
        entry.prev_hash = header.m_previous_block;
        entry.status = HEADER_VALID_CHAIN;

        m_headers[bhash] = entry;
        persist_header(entry);

        // Update tip if this chain has more work, or equal-work competing block
        // at the same height (peer represents network consensus).
        bool dominated    = entry.chain_work > m_best_work;
        bool equal_at_tip = entry.chain_work == m_best_work
                         && new_height == m_tip_height
                         && bhash != m_tip;
        if (dominated || equal_at_tip) {
            uint32_t old_height = m_tip_height;
            uint256  old_tip    = m_tip;
            m_best_work = entry.chain_work;
            m_tip = bhash;
            m_tip_height = new_height;
            // Incremental height index update: if this header extends the
            // previous tip (common case during sync), just add one entry.
            // Only do a full rebuild on reorgs (tip changed branch).
            if (new_height == old_height + 1 && entry.prev_hash == m_height_index[old_height]) {
                m_height_index[new_height] = bhash;
            } else {
                rebuild_height_index(bhash);
                if (equal_at_tip) {
                    LOG_WARNING << "[EMB-DOGE] EQUAL-WORK REORG at height " << new_height
                                << ": old_tip=" << old_tip.GetHex().substr(0, 16)
                                << " new_tip=" << bhash.GetHex().substr(0, 16);
                } else if (new_height <= old_height && old_height > 0) {
                    LOG_WARNING << "[EMB-DOGE] REORG detected: old_height=" << old_height
                                << " new_height=" << new_height << " hash=" << bhash.GetHex().substr(0, 16);
                }
            }
            // Defer reorg callback — will fire AFTER mutex is released by caller.
            m_pending_tip_change.fired = true;
            m_pending_tip_change.old_tip = old_tip;
            m_pending_tip_change.old_height = old_height;
            m_pending_tip_change.new_tip = bhash;
            m_pending_tip_change.new_height = new_height;
        }

        return true;
    }

    /// Validate DOGE difficulty using DigiShield v3 (or pre-DigiShield for early blocks).
    bool validate_difficulty(const BlockHeaderType& header, uint32_t new_height) {
        if (new_height < 2) return true;

        // Skip validation after checkpoint until we have enough ancestor headers
        if (m_params.fast_start_checkpoint.has_value()) {
            uint32_t cp_h = m_params.fast_start_checkpoint->height;
            if (new_height > cp_h && new_height < cp_h + 250)
                return true; // trust first 250 blocks after checkpoint
        }
        if (m_headers.size() < 250)
            return true; // not enough history yet

        auto prev_it = m_headers.find(header.m_previous_block);
        if (prev_it == m_headers.end()) return false;
        const auto& prev = prev_it->second;

        // DigiShield: retarget every block using previous block's data
        if (m_params.is_digishield(new_height)) {
            // For DigiShield, "first_time" is the timestamp of the block
            // one interval before prev (i.e., the grandparent for 1-block interval)
            int64_t first_time = prev.header.m_timestamp - DOGEChainParams::TARGET_SPACING;
            // If we have the grandparent, use its actual timestamp
            if (prev.prev_hash != uint256::ZERO) {
                auto gp_it = m_headers.find(prev.prev_hash);
                if (gp_it != m_headers.end())
                    first_time = gp_it->second.header.m_timestamp;
            }
            uint32_t expected = calculate_doge_next_work(
                prev.header.m_bits, prev.header.m_timestamp,
                first_time, new_height, m_params);
            return header.m_bits == expected;
        }

        // Pre-DigiShield: standard retarget every 240 blocks
        int64_t interval = DOGEChainParams::PRE_DIGISHIELD_INTERVAL;
        if ((new_height % interval) != 0)
            return header.m_bits == prev.header.m_bits; // no retarget

        // Find block at (new_height - interval) for timespan calculation
        auto first_entry = get_header_by_height_internal(
            new_height - static_cast<uint32_t>(interval));
        if (!first_entry.has_value())
            return true; // can't validate without ancestor

        uint32_t expected = calculate_doge_next_work(
            prev.header.m_bits, prev.header.m_timestamp,
            first_entry->header.m_timestamp, new_height, m_params);
        return header.m_bits == expected;
    }

    /// Internal get_header_by_height (caller holds mutex).
    std::optional<IndexEntry> get_header_by_height_internal(uint32_t h) const {
        auto it = m_height_index.find(h);
        if (it == m_height_index.end()) return std::nullopt;
        auto hit = m_headers.find(it->second);
        if (hit == m_headers.end()) return std::nullopt;
        return hit->second;
    }

    /// Rebuild height index from a new tip back to genesis.
    void rebuild_height_index(const uint256& new_tip) {
        m_height_index.clear();
        uint256 current = new_tip;
        while (!current.IsNull()) {
            auto it = m_headers.find(current);
            if (it == m_headers.end()) break;
            m_height_index[it->second.height] = current;
            current = it->second.prev_hash;
        }
    }

    /// Block locator: exponential backoff from tip (caller holds mutex).
    std::vector<uint256> get_locator_internal() const {
        std::vector<uint256> locator;
        if (m_tip.IsNull()) {
            // Chain is empty — send EMPTY locator so the peer responds with
            // headers starting from genesis (height 0).  If we included the
            // genesis hash, the peer would skip genesis and start from height 1,
            // but height 1's prev_hash wouldn't connect to any stored header.
            return locator;
        }

        int64_t step = 1;
        int64_t h = static_cast<int64_t>(m_tip_height);

        while (h >= 0) {
            auto it = m_height_index.find(static_cast<uint32_t>(h));
            if (it != m_height_index.end())
                locator.push_back(it->second);

            if (h == 0) break;
            h -= step;
            if (h < 0) h = 0;
            if (locator.size() > 10)
                step *= 2;
        }
        return locator;
    }

    // ─── LevelDB persistence ──────────────────────────────────────────────
    // Schema:
    //   "h" + block_hash(32 bytes) → IndexEntry (serialized)
    //   "H" + height(4 bytes BE)   → block_hash(32 bytes)
    //   "tip"                      → block_hash(32 bytes)
    //   "height"                   → uint32_t

    void persist_header(const IndexEntry& entry) {
        if (!m_db || !m_db->is_open()) return;

        auto packed = pack(entry);
        std::vector<uint8_t> data(
            reinterpret_cast<const uint8_t*>(packed.data()),
            reinterpret_cast<const uint8_t*>(packed.data()) + packed.size());

        std::string key = "h";
        key.append(reinterpret_cast<const char*>(entry.block_hash.data()), 32);
        m_db->put(key, data);
    }

    void persist_tip() {
        if (!m_db || !m_db->is_open()) return;

        // Store tip hash
        std::vector<uint8_t> tip_data(m_tip.data(), m_tip.data() + 32);
        m_db->put("tip", tip_data);

        // Store height
        uint32_t h = m_tip_height;
        std::vector<uint8_t> height_data(4);
        height_data[0] = (h >> 24) & 0xFF;
        height_data[1] = (h >> 16) & 0xFF;
        height_data[2] = (h >> 8) & 0xFF;
        height_data[3] = h & 0xFF;
        m_db->put("height", height_data);
    }

    void load_from_db() {
        if (!m_db || !m_db->is_open()) return;

        // Load all headers
        auto keys = m_db->list_keys("h", 10000000);
        for (auto& key : keys) {
            if (key.size() != 33) continue; // 'h' + 32-byte hash
            std::vector<uint8_t> data;
            if (!m_db->get(key, data)) continue;

            try {
                PackStream ps(data);
                IndexEntry entry;
                ps >> entry;
                m_headers[entry.block_hash] = entry;
            } catch (...) {
                // skip corrupt entries
            }
        }

        // Load tip
        std::vector<uint8_t> tip_data;
        if (m_db->get("tip", tip_data) && tip_data.size() == 32) {
            memcpy(m_tip.data(), tip_data.data(), 32);
            auto it = m_headers.find(m_tip);
            if (it != m_headers.end()) {
                m_tip_height = it->second.height;
                m_best_work = it->second.chain_work;
                rebuild_height_index(m_tip);
            } else {
                m_tip.SetNull();
            }
        }
    }

    // ─── State ────────────────────────────────────────────────────────────

    DOGEChainParams m_params;
    std::string    m_db_path;

    mutable std::mutex m_mutex;

    std::map<uint256, IndexEntry>  m_headers;       // block_hash → entry
    std::map<uint32_t, uint256>    m_height_index;  // height → block_hash (best chain only)

    uint256    m_tip;                                // best chain tip hash
    uint32_t   m_tip_height{0};
    uint256    m_best_work;

    // Peer-reported tip height for fast-sync scrypt skip.
    // Set from version message; headers below (tip - 2100) skip scrypt PoW.
    std::atomic<uint32_t> m_peer_tip_height{0};

    std::unique_ptr<core::LevelDBStore> m_db;

    /// Callback fired on tip change (reorg / equal-work switch).
    TipChangedCallback m_on_tip_changed;

    /// Deferred tip change — fired OUTSIDE mutex to avoid deadlock.
    struct PendingTipChange {
        bool fired{false};
        uint256 old_tip, new_tip;
        uint32_t old_height{0}, new_height{0};
    };
    PendingTipChange m_pending_tip_change;
};

} // namespace coin
} // namespace doge
