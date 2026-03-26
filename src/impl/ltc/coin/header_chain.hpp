#pragma once

/// LTC Header Chain — Phase 1
///
/// Validated header-only chain for Litecoin, implementing headers-first
/// sync from P2P peers. Tracks chain tip, height, and cumulative work.
/// Persistence via LevelDB for fast restarts.

#include "block.hpp"

#include <core/uint256.hpp>
#include <core/leveldb_store.hpp>
#include <core/log.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>

#include <btclibs/crypto/scrypt.h>

#include <atomic>
#include <chrono>
#include <map>
#include <mutex>
#include <optional>
#include <thread>
#include <functional>
#include <iomanip>
#include <string>
#include <vector>

namespace ltc {
namespace coin {

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

// ─── LTC Chain Parameters ───────────────────────────────────────────────────

struct LTCChainParams {
    // Mainnet
    static constexpr int64_t MAINNET_TARGET_TIMESPAN = 302400;     // 3.5 days
    static constexpr int64_t MAINNET_TARGET_SPACING  = 150;        // 2.5 minutes
    static constexpr bool    MAINNET_ALLOW_MIN_DIFF  = false;

    // Testnet
    static constexpr int64_t TESTNET_TARGET_TIMESPAN = 302400;     // 3.5 days
    static constexpr int64_t TESTNET_TARGET_SPACING  = 150;        // 2.5 minutes
    static constexpr bool    TESTNET_ALLOW_MIN_DIFF  = true;

    // Computed: difficulty adjustment interval = timespan / spacing
    static constexpr int64_t difficulty_adjustment_interval(int64_t timespan, int64_t spacing) {
        return timespan / spacing;
    }

    int64_t target_timespan;
    int64_t target_spacing;
    bool    allow_min_difficulty;
    bool    no_retargeting{false};
    uint256 pow_limit;
    uint256 genesis_hash;      // SHA256d genesis block hash (for identification)

    // Fast-start checkpoint: skip syncing from genesis, start from a recent height.
    // The header chain seeds this checkpoint as if it were the genesis block.
    // All headers before this height are implicitly trusted.
    struct Checkpoint { uint32_t height{0}; uint256 hash; };
    std::optional<Checkpoint> fast_start_checkpoint;

    /// Standard LTC mainnet params
    static LTCChainParams mainnet() {
        LTCChainParams p;
        p.target_timespan = MAINNET_TARGET_TIMESPAN;
        p.target_spacing  = MAINNET_TARGET_SPACING;
        p.allow_min_difficulty = MAINNET_ALLOW_MIN_DIFF;
        p.no_retargeting = false;
        p.pow_limit.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        p.genesis_hash.SetHex("12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2");
        return p;
    }

    /// Standard LTC testnet4 params
    static LTCChainParams testnet() {
        LTCChainParams p;
        p.target_timespan = TESTNET_TARGET_TIMESPAN;
        p.target_spacing  = TESTNET_TARGET_SPACING;
        p.allow_min_difficulty = TESTNET_ALLOW_MIN_DIFF;
        p.no_retargeting = false;
        p.pow_limit.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        p.genesis_hash.SetHex("4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0");
        // No hardcoded checkpoint — use --header-checkpoint CLI arg or
        // set_dynamic_checkpoint() from RPC for any chain/network.
        return p;
    }

    int64_t difficulty_adjustment_interval() const {
        return target_timespan / target_spacing;
    }
};

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

/// Core retarget calculation: adjust difficulty based on actual vs target timespan.
inline uint32_t calculate_next_work_required(
    uint32_t tip_bits,
    int64_t tip_time,
    int64_t first_block_time,
    const LTCChainParams& params)
{
    if (params.no_retargeting)
        return tip_bits;

    int64_t actual_timespan = tip_time - first_block_time;

    // Clamp to [timespan/4, timespan*4]
    if (actual_timespan < params.target_timespan / 4)
        actual_timespan = params.target_timespan / 4;
    if (actual_timespan > params.target_timespan * 4)
        actual_timespan = params.target_timespan * 4;

    // Retarget
    uint256 bn_new;
    bn_new.SetCompact(tip_bits);
    const uint256 bn_pow_limit = params.pow_limit;

    // Litecoin: intermediate uint256 can overflow by 1 bit
    bool shift = bn_new.bits() > bn_pow_limit.bits() - 1;
    if (shift)
        bn_new >>= 1;
    bn_new *= static_cast<uint32_t>(actual_timespan);
    bn_new /= uint256(static_cast<uint64_t>(params.target_timespan));
    if (shift)
        bn_new <<= 1;

    if (bn_new > bn_pow_limit)
        bn_new = bn_pow_limit;

    return bn_new.GetCompact();
}

/// Calculate next work required at a given height.
/// @param get_ancestor  Function to look up ancestor header by height.
/// @param tip_height    Height of the current tip (the block we're building on).
/// @param tip_bits      nBits of the current tip.
/// @param tip_time      Timestamp of the current tip.
/// @param new_time      Timestamp of the new block being validated.
/// @param params        Chain parameters.
inline uint32_t get_next_work_required(
    std::function<std::optional<IndexEntry>(uint32_t)> get_ancestor,
    uint32_t tip_height,
    uint32_t tip_bits,
    uint32_t tip_time,
    uint32_t new_time,
    const LTCChainParams& params)
{
    uint256 pow_limit_compact;
    pow_limit_compact = params.pow_limit;
    uint32_t pow_limit_bits = pow_limit_compact.GetCompact();

    // Next block height
    uint32_t new_height = tip_height + 1;
    int64_t interval = params.difficulty_adjustment_interval();

    // Only change once per difficulty adjustment interval
    if (new_height % interval != 0) {
        if (params.allow_min_difficulty) {
            // Testnet special rule: if >2x target spacing since last block,
            // allow min-difficulty block.
            if (static_cast<int64_t>(new_time) > static_cast<int64_t>(tip_time) + params.target_spacing * 2)
                return pow_limit_bits;
            
            // Return the last non-special-min-difficulty-rules-block
            uint32_t h = tip_height;
            uint32_t last_bits = tip_bits;
            while (h > 0 && (h % interval) != 0 && last_bits == pow_limit_bits) {
                auto ancestor = get_ancestor(h - 1);
                if (!ancestor) break;
                last_bits = ancestor->header.m_bits;
                h--;
            }
            return last_bits;
        }
        return tip_bits;
    }

    if (params.no_retargeting)
        return tip_bits;

    // Go back the full period unless it's the first retarget after genesis.
    // Code courtesy of Art Forz (Litecoin fix for 51% attack difficulty manipulation).
    int64_t blocks_to_go_back = interval - 1;
    if (new_height != interval)
        blocks_to_go_back = interval;

    // Get the first block of the retarget period
    uint32_t first_height = static_cast<uint32_t>(tip_height - blocks_to_go_back);
    auto first_entry = get_ancestor(first_height);
    if (!first_entry)
        return tip_bits; // shouldn't happen for a connected chain

    int64_t first_time = first_entry->header.m_timestamp;

    return calculate_next_work_required(tip_bits, tip_time, first_time, params);
}

// ─── HeaderChain ────────────────────────────────────────────────────────────

class HeaderChain {
public:
    HeaderChain(const LTCChainParams& params, const std::string& db_path = "")
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
        LOG_INFO << "[EMB-LTC] HeaderChain::init() db_path=" << (m_db_path.empty() ? "(in-memory)" : m_db_path)
                 << " genesis=" << m_params.genesis_hash.GetHex().substr(0, 16) << "..."
                 << " pow_limit=" << m_params.pow_limit.GetHex().substr(0, 16) << "..."
                 << " timespan=" << m_params.target_timespan << "s spacing=" << m_params.target_spacing << "s"
                 << " allow_min_diff=" << m_params.allow_min_difficulty;
        if (!m_db_path.empty()) {
            core::LevelDBOptions opts;
            opts.write_buffer_size = 2 * 1024 * 1024;  // 2MB
            opts.block_cache_size = 4 * 1024 * 1024;    // 4MB
            m_db = std::make_unique<core::LevelDBStore>(m_db_path, opts);
            if (!m_db->open()) {
                LOG_WARNING << "[EMB-LTC] HeaderChain LevelDB open FAILED at " << m_db_path;
                return false;
            }
            LOG_INFO << "[EMB-LTC] HeaderChain LevelDB opened at " << m_db_path;
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
        std::lock_guard<std::mutex> lock(m_mutex);
        bool ok = add_header_internal(header);
        if (ok) {
            persist_tip();
            LOG_INFO << "[EMB-LTC] Single header accepted: height=" << m_tip_height
                     << " hash=" << m_tip.GetHex().substr(0, 16) << "..."
                     << " bits=0x" << std::hex << header.m_bits << std::dec
                     << " ts=" << header.m_timestamp;
        }
        return ok;
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
        for (size_t offset = 0; offset < headers.size(); offset += BATCH_SIZE) {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                size_t end = std::min(offset + BATCH_SIZE, headers.size());
                for (size_t i = offset; i < end; ++i) {
                    if (add_header_internal(headers[i]))
                        ++accepted;
                }
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
                    LOG_INFO << "[LTC] Header sync: " << m_tip_height << "/" << peer_tip
                             << " (" << std::fixed << std::setprecision(1) << pct << "%)";
                }
            }
        }
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
            LOG_INFO << "[EMB-LTC] Sync state changed: synced=" << synced
                     << " tip_age=" << age << "s height=" << m_tip_height;
            s_last_synced = synced;
        }
        return synced;
    }

    /// Get params (for external difficulty validation tests).
    const LTCChainParams& params() const { return m_params; }

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
            if (bhash != m_params.genesis_hash) {
                LOG_WARNING << "[EMB-LTC] REJECT genesis: hash=" << bhash.GetHex().substr(0, 16)
                            << " expected=" << m_params.genesis_hash.GetHex().substr(0, 16);
                return false; // wrong genesis
            }

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
            LOG_INFO << "[EMB-LTC] Genesis accepted: hash=" << bhash.GetHex()
                     << " scrypt=" << entry.hash.GetHex().substr(0, 16)
                     << " bits=0x" << std::hex << header.m_bits << std::dec;
            return true;
        }

        // Must connect to an existing header
        auto prev_it = m_headers.find(header.m_previous_block);
        if (prev_it == m_headers.end()) {
            LOG_DEBUG_COIND << "[EMB-LTC] ORPHAN header: hash=" << bhash.GetHex().substr(0, 16)
                      << " prev=" << header.m_previous_block.GetHex().substr(0, 16)
                      << " — not connected to chain";
            return false; // orphan — not connected
        }

        const auto& prev = prev_it->second;
        uint32_t new_height = prev.height + 1;

        // Validate PoW — skip expensive scrypt for old headers during initial sync.
        // Headers below (peer_tip - SCRYPT_VALIDATION_DEPTH) are validated
        // structurally only (prev_hash + difficulty retarget).  This makes bulk
        // sync ~100x faster: 170k headers × 0.01ms vs 170k × 20ms.
        // The depth threshold (2100) covers: 1 difficulty retarget interval (2016)
        // + margin for block_rel_height scoring (~72 blocks).
        static constexpr uint32_t SCRYPT_VALIDATION_DEPTH = 2100;
        uint32_t peer_tip = m_peer_tip_height.load(std::memory_order_relaxed);
        bool need_scrypt = (peer_tip == 0) // unknown tip → validate everything
                        || (new_height + SCRYPT_VALIDATION_DEPTH >= peer_tip);
        uint256 pow_hash;
        if (need_scrypt) {
            pow_hash = scrypt_hash(header);
            if (!check_pow(pow_hash, header.m_bits, m_params.pow_limit)) {
                LOG_WARNING << "[EMB-LTC] PoW FAIL at height=" << new_height
                            << " hash=" << bhash.GetHex().substr(0, 16)
                            << " scrypt=" << pow_hash.GetHex().substr(0, 16)
                            << " bits=0x" << std::hex << header.m_bits << std::dec;
                return false;
            }
        } else {
            // Structural-only: trust PoW, store zero hash (not needed for old blocks)
            pow_hash = block_hash(header); // SHA256d, not scrypt — cheap placeholder
        }

        // Validate difficulty
        if (!validate_difficulty(header, new_height)) {
            LOG_WARNING << "[EMB-LTC] Difficulty FAIL at height=" << new_height
                        << " hash=" << bhash.GetHex().substr(0, 16)
                        << " bits=0x" << std::hex << header.m_bits << std::dec
                        << " prev_bits=0x" << prev.header.m_bits << std::dec;
            return false;
        }

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

        // Update tip if this chain has more work
        if (entry.chain_work > m_best_work) {
            uint32_t old_height = m_tip_height;
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
                if (new_height <= old_height && old_height > 0) {
                    LOG_WARNING << "[EMB-LTC] REORG detected: old_height=" << old_height
                                << " new_height=" << new_height << " hash=" << bhash.GetHex().substr(0, 16);
                }
            }
        }

        return true;
    }

    /// Validate that the header's nBits matches the expected difficulty.
    bool validate_difficulty(const BlockHeaderType& header, uint32_t new_height) {
        int64_t interval = m_params.difficulty_adjustment_interval();
        if (new_height < 2) return true; // genesis + first block

        // After a fast-start checkpoint, skip difficulty validation until we have
        // enough headers for the retarget lookback (interval = 2016).
        // Without this, get_ancestor() fails because the checkpoint doesn't have
        // the previous 2016 headers needed for difficulty calculation.
        if (m_params.fast_start_checkpoint.has_value()) {
            uint32_t cp_h = m_params.fast_start_checkpoint->height;
            if (new_height > cp_h && new_height < cp_h + static_cast<uint32_t>(interval) + 10)
                return true; // trust difficulty within first retarget window after checkpoint
        }
        // Also skip when we have a dynamic checkpoint (no fast_start_checkpoint set
        // but chain started at a non-zero height)
        if (m_headers.size() < static_cast<size_t>(interval + 10))
            return true;

        // Get tip (the block we're building on)
        auto prev_it = m_headers.find(header.m_previous_block);
        if (prev_it == m_headers.end()) return false;
        const auto& tip = prev_it->second;

        auto get_ancestor = [this](uint32_t h) -> std::optional<IndexEntry> {
            return this->get_header_by_height_internal(h);
        };

        uint32_t expected_bits = get_next_work_required(
            get_ancestor, tip.height, tip.header.m_bits, tip.header.m_timestamp,
            header.m_timestamp, m_params);

        return header.m_bits == expected_bits;
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
        if (m_tip.IsNull()) return locator;

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
        if (!m_db || !m_db->is_open()) {
            LOG_DEBUG_COIND << "[EMB-LTC] persist_header: no DB (in-memory mode)";
            return;
        }

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

        LOG_INFO << "[EMB-LTC] load_from_db: scanning LevelDB for headers...";
        auto t0 = std::chrono::steady_clock::now();

        // Load all headers
        auto keys = m_db->list_keys("h", 10000000);
        int loaded = 0, corrupt = 0;
        for (auto& key : keys) {
            if (key.size() != 33) continue; // 'h' + 32-byte hash
            std::vector<uint8_t> data;
            if (!m_db->get(key, data)) continue;

            try {
                PackStream ps(data);
                IndexEntry entry;
                ps >> entry;
                m_headers[entry.block_hash] = entry;
                ++loaded;
            } catch (const std::exception& e) {
                ++corrupt;
                LOG_WARNING << "[EMB-LTC] Corrupt header entry in DB: " << e.what();
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
                LOG_WARNING << "[EMB-LTC] Tip hash in DB not found among loaded headers — resetting";
                m_tip.SetNull();
            }
        }

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();
        LOG_INFO << "[EMB-LTC] load_from_db: loaded " << loaded << " headers"
                 << (corrupt > 0 ? ", " + std::to_string(corrupt) + " corrupt" : "")
                 << " in " << elapsed << "ms"
                 << " tip_height=" << m_tip_height
                 << " tip=" << (m_tip.IsNull() ? "(null)" : m_tip.GetHex().substr(0, 16) + "...");
    }

    // ─── State ────────────────────────────────────────────────────────────

    LTCChainParams m_params;
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
};

} // namespace coin
} // namespace ltc
