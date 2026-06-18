#pragma once

/// BCH Header Chain
///
/// Validated header-only chain for Bitcoin Cash, implementing headers-first
/// sync from BCHN P2P peers. Tracks chain tip, height, and cumulative work.
/// Persistence via LevelDB for fast restarts.
///
/// Mirrors src/impl/btc/coin/header_chain.hpp — same store/sync/persistence
/// machinery and the same PoW hash (SHA256d; BCH is a standalone SHA256d
/// parent). The ONE divergence is difficulty: BCH replaced Bitcoin's
/// 2016-block 2-week retarget with ASERT (aserti3-2d, CHIP-2020-05, Nov 2020).
/// The retarget math lives in asert.hpp (1:1 BCHN pow.cpp port); this file
/// only wires validate_difficulty() to it. ASERT governs which headers the
/// SPV engine accepts — it does NOT touch share format or PoW hash, so there
/// is no p2pool-merged-v36 surface change.

#include "asert.hpp"            // BCH ASERT (aserti3-2d) difficulty — s18a
#include "block.hpp"
#include <core/coin/utxo.hpp>  // DEFAULT_MAX_TIP_AGE

#include <core/uint256.hpp>
#include <core/leveldb_store.hpp>
#include <core/log.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>

// (BCH PoW is SHA256d via core/hash.hpp — byte-identical to BTC.)

#include <atomic>
#include <chrono>
#include <list>
#include <mutex>
#include <optional>
#include <thread>
#include <functional>
#include <iomanip>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace bch {
namespace coin {

// uint256 hasher for unordered containers (low-64 bits is already a uniform
// distribution over a cryptographic hash, no further mixing needed).
struct Uint256Hasher {
    size_t operator()(const uint256& h) const { return h.GetLow64(); }
};

// ─── Index Entry ────────────────────────────────────────────────────────────

/// Status flags for header validation state
enum HeaderStatus : uint32_t {
    HEADER_VALID_UNKNOWN  = 0,
    HEADER_VALID_HEADER   = 1,  // Header parsed and PoW valid
    HEADER_VALID_TREE     = 2,  // Connected to genesis via prev_hash chain
    HEADER_VALID_CHAIN    = 3,  // Difficulty validated
};

/// A validated header with chain metadata (in-memory representation).
///
/// On BTC, two fields that the on-disk layout carries are computable from
/// the rest and are not stored in RAM:
///   - "PoW hash" is identical to block_hash (both SHA256d(header)).
///   - "prev_hash" is always header.m_previous_block.
/// Dropping them saves 64 B/entry × ~1M headers = ~60 MB peak heap.
///
/// On-disk format is unchanged — see IndexEntryDiskV1 below.
struct IndexEntry {
    BlockHeaderType header;
    uint256         block_hash;     // SHA256d(header) — the block hash used for getdata/inv
    uint32_t        height{0};
    uint256         chain_work;     // cumulative work up to this header
    HeaderStatus    status{HEADER_VALID_UNKNOWN};
};

/// Legacy 6-field on-disk layout. Kept verbatim for backward read compat AND
/// forward write compat (so a roll-back to a pre-Phase-1B binary can still
/// parse what we wrote). The duplicate `hash` and `prev_hash` fields are
/// derived from the slim IndexEntry at write time.
struct IndexEntryDiskV1 {
    BlockHeaderType header;
    uint256         hash;           // SHA256d(header) — same as block_hash on BTC
    uint256         block_hash;     // SHA256d(header) — the block hash used for getdata/inv
    uint32_t        height{0};
    uint256         chain_work;     // cumulative work up to this header
    uint256         prev_hash;      // == header.m_previous_block on BTC
    HeaderStatus    status{HEADER_VALID_UNKNOWN};

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

    /// Materialize the slim in-memory form (drops the duplicate fields).
    IndexEntry to_entry() const {
        IndexEntry e;
        e.header     = header;
        e.block_hash = block_hash;
        e.height     = height;
        e.chain_work = chain_work;
        e.status     = status;
        return e;
    }

    /// Build the legacy on-disk form from a slim entry (computes duplicates).
    static IndexEntryDiskV1 from_entry(const IndexEntry& e) {
        IndexEntryDiskV1 d;
        d.header     = e.header;
        d.hash       = e.block_hash;
        d.block_hash = e.block_hash;
        d.height     = e.height;
        d.chain_work = e.chain_work;
        d.prev_hash  = e.header.m_previous_block;
        d.status     = e.status;
        return d;
    }
};

// ─── BCH Chain Parameters ───────────────────────────────────────────────────
// Unlike BTC's 2016-block retarget, BCH difficulty is governed by ASERT
// (aserti3-2d). The difficulty state therefore is NOT a (timespan, spacing,
// interval) tuple but the ASERTParams anchor block carried in asert.hpp. The
// PoW hash is still SHA256d and the mainnet/testnet3 genesis blocks are shared
// with Bitcoin (BCH forked from BTC at height 478558), so those hashes match
// btc/coin/header_chain.hpp verbatim.

struct BCHChainParams {
    ASERTParams asert;                       // aserti3-2d difficulty params (asert.hpp)
    uint256     pow_limit;                   // == asert.pow_limit (mirror for check_pow)
    uint256     genesis_hash;                // SHA256d genesis block hash (identification)
    bool        allow_min_difficulty{false}; // == asert.allow_min_difficulty (testnet)

    // Fast-start checkpoint: skip syncing from genesis, start from a recent height.
    // The header chain seeds this checkpoint as if it were the genesis block.
    // All headers before this height are implicitly trusted.
    struct Checkpoint { uint32_t height{0}; uint256 hash; };
    std::optional<Checkpoint> fast_start_checkpoint;

    /// BCH mainnet params (port 8333). Genesis shared with Bitcoin (pre-fork
    /// block 0). ASERT anchor + powLimit from BCHN chainparams via asert.hpp.
    static BCHChainParams mainnet() {
        BCHChainParams p;
        p.asert                = asert_mainnet();
        p.pow_limit            = p.asert.pow_limit;
        p.allow_min_difficulty = p.asert.allow_min_difficulty;
        // Genesis: identical to Bitcoin mainnet (shared pre-fork history).
        p.genesis_hash.SetHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
        // Seed genesis as the chain root (height=0) — same rationale as BTC.
        p.fast_start_checkpoint = Checkpoint{0, p.genesis_hash};
        return p;
    }

    /// BCH testnet3 params (port 18333) — primary M3 parity target (VM300).
    /// Genesis: identical to Bitcoin testnet3 (shared pre-fork history).
    static BCHChainParams testnet() {
        BCHChainParams p;
        p.asert                = asert_testnet3();
        p.pow_limit            = p.asert.pow_limit;
        p.allow_min_difficulty = p.asert.allow_min_difficulty;
        p.genesis_hash.SetHex("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943");
        p.fast_start_checkpoint = Checkpoint{0, p.genesis_hash};
        return p;
    }

    /// BCH testnet4 params (port 28333). NOTE: BCH testnet4 has its OWN genesis
    /// (distinct from BTC testnet4) — this is a consensus constant.
    /// Verified vs BCHN v29.0.0 src/chainparams.cpp (commit 89a591f) genesis
    /// assert — pinned by test/genesis_conformance_test.cpp (M3 closed).
    static BCHChainParams testnet4() {
        BCHChainParams p;
        p.asert                = asert_testnet4();
        p.pow_limit            = p.asert.pow_limit;
        p.allow_min_difficulty = p.asert.allow_min_difficulty;
        p.genesis_hash.SetHex("000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b");
        p.fast_start_checkpoint = Checkpoint{0, p.genesis_hash};
        return p;
    }
};

// ─── PoW Functions ──────────────────────────────────────────────────────────

/// Compute SHA256d PoW hash of an 80-byte block header.
/// On BCH (like BTC) the PoW hash and the block-identity hash are the same
/// value (both SHA256d). BCH is a standalone SHA256d parent — no PoW/aux.
inline uint256 sha256d_hash(const BlockHeaderType& header) {
    auto packed = pack(header);
    return Hash(packed.get_span());
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

/// Check that a SHA256d PoW hash meets the target specified by nBits.
inline bool check_pow(const uint256& sha256d_hash_val, uint32_t bits, const uint256& pow_limit) {
    bool negative, overflow;
    uint256 target;
    target.SetCompact(bits, &negative, &overflow);

    if (negative || target.IsNull() || overflow || target > pow_limit)
        return false;

    return sha256d_hash_val <= target;
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

// ─── BCH Difficulty (ASERT / aserti3-2d) ─────────────────────────────────────
// BCH does NOT use Bitcoin's 2016-block retarget. Since the Nov 2020 upgrade
// (CHIP-2020-05) the required target for every block is computed directly from
// the ASERT anchor block via an absolute exponential formula — there is no
// 2016-block window, no "first block of period" lookback, and no off-by-one
// Art-Forz history to track. All the fixed-point math lives in asert.hpp
// (get_next_work_required_asert / CalculateASERT), a 1:1 BCHN src/pow.cpp port
// that is validated against BCHN's gold vectors. This file only adapts the
// call shape to header_chain's validate_difficulty().

/// Calculate the nBits the block at (tip_height + 1) must meet, per ASERT.
/// Unlike BTC's retarget this needs NO ancestor walk — the absolute ASERT
/// formulation references only the fixed anchor block (asert.hpp) plus the
/// tip's height/time and the new block's time (for the testnet min-diff rule).
/// @param tip_height  Height of the current tip (the block we build on).
/// @param tip_time    Timestamp of the current tip.
/// @param new_time    Timestamp of the new block being validated.
/// @param params      Chain parameters (carries the ASERT anchor).
inline uint32_t get_next_work_required(
    uint32_t tip_height,
    uint32_t tip_time,
    uint32_t new_time,
    const BCHChainParams& params)
{
    return get_next_work_required_asert(
        tip_height,
        static_cast<int64_t>(tip_time),
        static_cast<int64_t>(new_time),
        params.asert);
}

// ─── HeaderChain ────────────────────────────────────────────────────────────

class HeaderChain {
public:
    HeaderChain(const BCHChainParams& params, const std::string& db_path = "")
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
        LOG_INFO << "[EMB-BCH] HeaderChain::init() db_path=" << (m_db_path.empty() ? "(in-memory)" : m_db_path)
                 << " genesis=" << m_params.genesis_hash.GetHex().substr(0, 16) << "..."
                 << " pow_limit=" << m_params.pow_limit.GetHex().substr(0, 16) << "..."
                 << " asert_anchor_h=" << m_params.asert.anchor.height
                 << " asert_halflife=" << m_params.asert.half_life << "s"
                 << " spacing=" << m_params.asert.target_spacing << "s"
                 << " allow_min_diff=" << m_params.allow_min_difficulty;
        if (!m_db_path.empty()) {
            core::LevelDBOptions opts;
            opts.write_buffer_size = 2 * 1024 * 1024;  // 2MB
            opts.block_cache_size = 4 * 1024 * 1024;    // 4MB
            m_db = std::make_unique<core::LevelDBStore>(m_db_path, opts);
            if (!m_db->open()) {
                LOG_WARNING << "[EMB-BCH] HeaderChain LevelDB open FAILED at " << m_db_path;
                return false;
            }
            LOG_INFO << "[EMB-BCH] HeaderChain LevelDB opened at " << m_db_path;
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
            entry.status = HEADER_VALID_CHAIN;
            // Minimal header — we don't have the actual header data, but we
            // have the hash. Peers will send headers AFTER this point. The
            // null prev_block doubles as the "trusted root" marker for the
            // chain walk in get_header_by_height_internal().
            entry.header.m_previous_block.SetNull();

            put_header_internal(cp.hash, entry);
            m_height_index[cp.height] = cp.hash;
            mark_height_dirty_internal(cp.height);
            m_tip = cp.hash;
            m_tip_height = cp.height;
            m_best_work = entry.chain_work;
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
        return lookup_header_internal(m_tip);
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

    /// Number of headers stored on the best chain. Backed by m_height_index
    /// after Phase 1C — m_headers is a bounded cache, not authoritative.
    size_t size() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_height_index.size();
    }

    /// Check if we have a header by its SHA256d block hash. Looks in the LRU
    /// cache first, then the LevelDB store.
    bool has_header(const uint256& block_hash) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return has_header_internal(block_hash);
    }

    /// Get header by SHA256d block hash. Lazy-loads from disk on cache miss.
    std::optional<IndexEntry> get_header(const uint256& block_hash) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return lookup_header_internal(block_hash);
    }

    /// Get header by height (only works for headers on the best chain).
    std::optional<IndexEntry> get_header_by_height(uint32_t h) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_height_index.find(h);
        if (it == m_height_index.end()) return std::nullopt;
        return lookup_header_internal(it->second);
    }

    /// Add a single header. Returns true if accepted (new + valid).
    bool add_header(const BlockHeaderType& header) {
        PendingTipChange ptc;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            bool ok = add_header_internal(header);
            if (ok) {
                persist_tip();
                LOG_INFO << "[EMB-BCH] Single header accepted: height=" << m_tip_height
                         << " hash=" << m_tip.GetHex().substr(0, 16) << "..."
                         << " bits=0x" << std::hex << header.m_bits << std::dec
                         << " ts=" << header.m_timestamp;
            }
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
    /// Used to skip SHA256d PoW validation for old headers during initial sync.
    /// Headers below (tip - POW_VALIDATION_DEPTH) are validated structurally
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
            entry.status = HEADER_VALID_CHAIN;
            entry.header.m_previous_block.SetNull();
            put_header_internal(hash, entry);
            m_height_index[height] = hash;
            mark_height_dirty_internal(height);
            m_tip = hash;
            m_tip_height = height;
            m_best_work = entry.chain_work;
            persist_tip();
            LOG_INFO << "HeaderChain: dynamic checkpoint at height="
                     << height << " hash=" << hash.GetHex().substr(0, 16) << "...";
        }
    }

    /// Add a batch of headers (from a `headers` P2P message).
    /// Returns the number of new headers accepted.
    /// Processes in sub-batches to avoid holding the mutex for the entire batch.
    /// With fast-sync (PoW skipped for old headers), structural validation
    /// is microseconds per header, so large batches are fine.  Near the tip
    /// (PoW active), each header takes ~20ms, so we use smaller batches.
    int add_headers(const std::vector<BlockHeaderType>& headers) {
        uint32_t peer_tip = m_peer_tip_height.load(std::memory_order_relaxed);
        // Large batches during fast-sync (no PoW), small near tip (PoW active)
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
                // Short yield during fast-sync (structural only), longer near tip (PoW)
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
                    LOG_INFO << "[BCH] Header sync: " << m_tip_height << "/" << peer_tip
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
        return has_header_internal(prev_hash);
    }

    /// Whether the chain is synced (tip timestamp within DEFAULT_MAX_TIP_AGE of wall clock).
    /// Both litecoind and dogecoind use 24 hours (86400s) as DEFAULT_MAX_TIP_AGE.
    /// Reference: litecoin/src/validation.h  DEFAULT_MAX_TIP_AGE = 24 * 60 * 60
    /// p2pool uses the same gate implicitly: getblocktemplate() fails until
    /// litecoind considers itself synced (tip within nMaxTipAge).
    bool is_synced() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_tip.IsNull()) return false;
        auto tip_opt = lookup_header_internal(m_tip);
        if (!tip_opt) return false;
        auto now = static_cast<uint32_t>(std::time(nullptr));
        uint32_t age = now - tip_opt->header.m_timestamp;
        bool synced = age < core::coin::DEFAULT_MAX_TIP_AGE; // 24 hours (86400s)
        // Log state changes (throttled via static)
        static bool s_last_synced = false;
        if (synced != s_last_synced) {
            LOG_INFO << "[EMB-BCH] Sync state changed: synced=" << synced
                     << " tip_age=" << age << "s height=" << m_tip_height;
            s_last_synced = synced;
        }
        return synced;
    }

    /// Get params (for external difficulty validation tests).
    const BCHChainParams& params() const { return m_params; }

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
        if (has_header_internal(bhash))
            return false;

        // Genesis block special case: accept if it matches known genesis
        if (header.m_previous_block.IsNull()) {
            if (bhash != m_params.genesis_hash) {
                LOG_WARNING << "[EMB-BCH] REJECT genesis: hash=" << bhash.GetHex().substr(0, 16)
                            << " expected=" << m_params.genesis_hash.GetHex().substr(0, 16);
                return false; // wrong genesis
            }

            IndexEntry entry;
            entry.header = header;
            entry.block_hash = bhash;
            entry.height = 0;
            entry.chain_work = get_block_proof(header.m_bits);
            entry.status = HEADER_VALID_CHAIN;

            put_header_internal(bhash, entry);
            m_height_index[0] = bhash;
            mark_height_dirty_internal(0);
            m_tip = bhash;
            m_tip_height = 0;
            m_best_work = entry.chain_work;
            LOG_INFO << "[EMB-BCH] Genesis accepted: hash=" << bhash.GetHex()
                     << " bits=0x" << std::hex << header.m_bits << std::dec;
            return true;
        }

        // Must connect to an existing header
        auto prev_opt = lookup_header_internal(header.m_previous_block);
        if (!prev_opt) {
            LOG_DEBUG_COIND << "[EMB-BCH] ORPHAN header: hash=" << bhash.GetHex().substr(0, 16)
                      << " prev=" << header.m_previous_block.GetHex().substr(0, 16)
                      << " — not connected to chain";
            return false; // orphan — not connected
        }

        const auto& prev = *prev_opt;
        uint32_t new_height = prev.height + 1;

        // Validate PoW — skip expensive SHA256d PoW for old headers during initial sync.
        // Headers below (peer_tip - POW_VALIDATION_DEPTH) are validated
        // structurally only (prev_hash + difficulty retarget).  This makes bulk
        // sync ~100x faster: 170k headers × 0.01ms vs 170k × 20ms.
        // The depth threshold (2100) covers: 1 difficulty retarget interval (2016)
        // + margin for block_rel_height scoring (~72 blocks).
        static constexpr uint32_t POW_VALIDATION_DEPTH = 2100;
        uint32_t peer_tip = m_peer_tip_height.load(std::memory_order_relaxed);
        bool need_pow = (peer_tip == 0) // unknown tip → validate everything
                        || (new_height + POW_VALIDATION_DEPTH >= peer_tip);
        uint256 pow_hash;
        if (need_pow) {
            pow_hash = sha256d_hash(header);
            if (!check_pow(pow_hash, header.m_bits, m_params.pow_limit)) {
                LOG_WARNING << "[EMB-BCH] PoW FAIL at height=" << new_height
                            << " hash=" << bhash.GetHex().substr(0, 16)
                            << " pow=" << pow_hash.GetHex().substr(0, 16)
                            << " bits=0x" << std::hex << header.m_bits << std::dec;
                return false;
            }
        } else {
            // Structural-only: trust PoW, store zero hash (not needed for old blocks)
            pow_hash = block_hash(header); // cheap placeholder (PoW already trusted for old headers)
        }

        // Validate difficulty
        if (!validate_difficulty(header, new_height)) {
            LOG_WARNING << "[EMB-BCH] Difficulty FAIL at height=" << new_height
                        << " hash=" << bhash.GetHex().substr(0, 16)
                        << " bits=0x" << std::hex << header.m_bits << std::dec
                        << " prev_bits=0x" << prev.header.m_bits << std::dec;
            return false;
        }

        // Build index entry
        IndexEntry entry;
        entry.header = header;
        entry.block_hash = bhash;
        entry.height = new_height;
        entry.chain_work = prev.chain_work + get_block_proof(header.m_bits);
        entry.status = HEADER_VALID_CHAIN;
        (void)pow_hash; // PoW already checked above; not stored on BTC since == block_hash

        put_header_internal(bhash, entry);

        // Update tip if this chain has more work, OR if a competing block
        // at the same height has equal work (equal-work reorg).
        //
        // On testnet (min-difficulty), ALL blocks have identical per-block work.
        // When our miner and the network both find a block at the same height,
        // the `>` check alone never fires — the chain permanently diverges.
        // The peer sending us this header represents network consensus (litecoind
        // accepted their block), so we switch to it.
        //
        // Flip-flop is impossible: once both headers are stored, re-receiving
        // either is a no-op (line 551 skips known hashes).  After switching,
        // our mining builds on the new tip, so no new blocks appear on the
        // old fork.
        bool dominated    = entry.chain_work > m_best_work;
        // First-seen-wins (BCHN / Bitcoin consensus): an equal-work competitor
        // does NOT replace the incumbent tip. The equal-work reorg is permitted
        // ONLY under min-difficulty params (testnet 20-minute rule), where our
        // own miner and the network can independently mint same-work blocks at
        // one height and the peer header represents network consensus. On
        // mainnet this stays false, so a same-work fork can never flip-flop the
        // tip (which would also be a cheap reorg-DoS vector).
        bool equal_at_tip = m_params.allow_min_difficulty
                         && entry.chain_work == m_best_work
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
            if (new_height == old_height + 1 && entry.header.m_previous_block == m_height_index[old_height]) {
                m_height_index[new_height] = bhash;
                mark_height_dirty_internal(new_height);
            } else {
                rebuild_height_index(bhash);
                if (equal_at_tip) {
                    LOG_WARNING << "[EMB-BCH] EQUAL-WORK REORG at height " << new_height
                                << ": old_tip=" << old_tip.GetHex().substr(0, 16)
                                << " new_tip=" << bhash.GetHex().substr(0, 16);
                } else if (new_height <= old_height && old_height > 0) {
                    LOG_WARNING << "[EMB-BCH] REORG detected: old_height=" << old_height
                                << " new_height=" << new_height << " hash=" << bhash.GetHex().substr(0, 16);
                }
            }
            // Defer reorg callback — will fire AFTER mutex is released by caller.
            // Firing inside the lock causes deadlock (callback → getwork → get_header → lock).
            m_pending_tip_change.fired = true;
            m_pending_tip_change.old_tip = old_tip;
            m_pending_tip_change.old_height = old_height;
            m_pending_tip_change.new_tip = bhash;
            m_pending_tip_change.new_height = new_height;
        }

        return true;
    }

    /// Validate that the header's nBits matches the expected ASERT difficulty.
    /// Unlike BTC there is no 2016-block lookback window — ASERT is computed
    /// from the fixed anchor (asert.hpp) plus the tip's height/time, so we need
    /// only the immediate predecessor, not an ancestor walk.
    bool validate_difficulty(const BlockHeaderType& header, uint32_t new_height) {
        if (new_height < 2) return true; // genesis + first block

        // Get tip (the block we're building on).
        auto prev_opt = lookup_header_internal(header.m_previous_block);
        if (!prev_opt) return false;
        const auto& tip = *prev_opt;

        // ASERT is only defined from the anchor block forward. Pre-anchor
        // history used BCH's earlier DAA (and pre-Nov-2020 EDA); those blocks
        // sit far below any realistic integration checkpoint and are trusted
        // structurally during fast-sync. We also MUST NOT call into ASERT below
        // the anchor — asert.hpp asserts tip_height >= anchor.height.
        if (static_cast<int64_t>(tip.height) < m_params.asert.anchor.height)
            return true;

        // Fast-start / dynamic checkpoint seeds carry a synthetic header (null
        // prev, zero timestamp/bits). The block building directly on such a seed
        // has no real tip time to anchor the ASERT delta — trust it for one
        // block; its successors validate against a real tip header. (The true
        // genesis also has a null prev but height 0, already handled above.)
        if (tip.header.m_previous_block.IsNull() && tip.height != 0)
            return true;

        uint32_t expected_bits = get_next_work_required(
            tip.height, tip.header.m_timestamp, header.m_timestamp, m_params);

        return header.m_bits == expected_bits;
    }

    /// Internal get_header_by_height (caller holds mutex).
    std::optional<IndexEntry> get_header_by_height_internal(uint32_t h) const {
        auto it = m_height_index.find(h);
        if (it == m_height_index.end()) return std::nullopt;
        return lookup_header_internal(it->second);
    }

    /// Rebuild height index from a new tip back to genesis (chain walk).
    /// Marks every changed height dirty so flush_dirty() persists it.
    /// On a one-time legacy migration this walks the full chain — subsequent
    /// reorgs walk only as far as the divergence depth.
    void rebuild_height_index(const uint256& new_tip) {
        // Snapshot old mapping so we only dirty heights that actually change.
        std::unordered_map<uint32_t, uint256> old_index;
        old_index.swap(m_height_index);
        uint256 current = new_tip;
        while (!current.IsNull()) {
            auto cur_opt = lookup_header_internal(current);
            if (!cur_opt) break;
            uint32_t h = cur_opt->height;
            m_height_index[h] = current;
            auto oit = old_index.find(h);
            if (oit == old_index.end() || oit->second != current)
                mark_height_dirty_internal(h);
            current = cur_opt->header.m_previous_block;
        }
        // Any heights that were in the old index but not in the new one are now
        // orphan-chain entries; we don't have a way to delete LevelDB rows yet,
        // so they're left as stale records. Acceptable: reads through
        // m_height_index never see them, and the next reorg through the same
        // height will overwrite.
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
    //   "h" + block_hash(32 bytes) → IndexEntry (serialized as IndexEntryDiskV1)
    //   "i" + height(4 bytes BE)   → block_hash(32 bytes)  (Phase 1C — m_height_index persistence)
    //   "tip"                      → block_hash(32 bytes)
    //   "height"                   → uint32_t (4-byte BE)

    static std::string make_height_key(uint32_t h) {
        std::string k = "i";
        char buf[4];
        buf[0] = static_cast<char>((h >> 24) & 0xFF);
        buf[1] = static_cast<char>((h >> 16) & 0xFF);
        buf[2] = static_cast<char>((h >> 8) & 0xFF);
        buf[3] = static_cast<char>(h & 0xFF);
        k.append(buf, 4);
        return k;
    }

    static uint32_t parse_height_key(const std::string& k) {
        if (k.size() != 5 || k[0] != 'i') return UINT32_MAX;
        return (static_cast<uint32_t>(static_cast<uint8_t>(k[1])) << 24)
             | (static_cast<uint32_t>(static_cast<uint8_t>(k[2])) << 16)
             | (static_cast<uint32_t>(static_cast<uint8_t>(k[3])) <<  8)
             |  static_cast<uint32_t>(static_cast<uint8_t>(k[4]));
    }

    // ─── Phase 1C: LRU cache helpers ──────────────────────────────────────

    /// Move an existing cache entry to the front of the LRU list (most recent).
    void touch_lru_internal(const uint256& hash) const {
        auto pit = m_lru_iter.find(hash);
        if (pit == m_lru_iter.end()) return;
        if (pit->second == m_lru_order.begin()) return;
        m_lru_order.splice(m_lru_order.begin(), m_lru_order, pit->second);
    }

    /// Evict from the back of the LRU until we're at or below the cap.
    /// Dirty entries are never evicted — they have unwritten changes.
    void evict_lru_if_full_internal() const {
        auto bound = static_cast<size_t>(HEADER_CACHE_CAP);
        size_t guard = 0;
        while (m_headers.size() > bound && !m_lru_order.empty() && guard++ < bound) {
            const uint256 victim = m_lru_order.back();
            // Don't evict if dirty (would lose unflushed write).
            if (m_dirty_headers.count(victim)) {
                // Rotate dirty victim to the front so we try a different one.
                m_lru_order.splice(m_lru_order.begin(), m_lru_order, std::prev(m_lru_order.end()));
                auto it = m_lru_iter.find(victim);
                if (it != m_lru_iter.end()) it->second = m_lru_order.begin();
                continue;
            }
            m_lru_order.pop_back();
            m_lru_iter.erase(victim);
            m_headers.erase(victim);
        }
    }

    /// Insert into cache (or replace existing). Returns pointer into m_headers
    /// for the inserted entry. Triggers eviction if over cap. Pointer is stable
    /// only until the next cache mutation.
    const IndexEntry* insert_into_cache_internal(const uint256& hash, IndexEntry&& entry) const {
        auto pit = m_lru_iter.find(hash);
        if (pit != m_lru_iter.end()) {
            m_lru_order.splice(m_lru_order.begin(), m_lru_order, pit->second);
            auto& slot = m_headers[hash];
            slot = std::move(entry);
            return &slot;
        }
        m_lru_order.push_front(hash);
        m_lru_iter[hash] = m_lru_order.begin();
        auto [it, inserted] = m_headers.emplace(hash, std::move(entry));
        (void)inserted;
        evict_lru_if_full_internal();
        // After eviction, the iterator might still be valid (we don't evict the
        // entry we just inserted — it's at the front, eviction starts at back).
        return &it->second;
    }

    /// Read a single header from LevelDB by block_hash. Returns true if found.
    bool try_load_header_from_db_internal(const uint256& hash, IndexEntry& out) const {
        if (!m_db || !m_db->is_open()) return false;
        std::string key = "h";
        key.append(reinterpret_cast<const char*>(hash.data()), 32);
        std::vector<uint8_t> data;
        if (!m_db->get(key, data)) return false;
        try {
            PackStream ps(data);
            IndexEntryDiskV1 disk;
            ps >> disk;
            out = disk.to_entry();
            return true;
        } catch (const std::exception& e) {
            LOG_WARNING << "[EMB-BCH] try_load_header_from_db: corrupt entry hash="
                        << hash.GetHex().substr(0, 16) << " err=" << e.what();
            return false;
        }
    }

    /// Cache-then-DB lookup. Returns a copy (avoids pointer-stability hazards
    /// when callers do follow-up lookups). nullopt = not present anywhere.
    std::optional<IndexEntry> lookup_header_internal(const uint256& hash) const {
        auto it = m_headers.find(hash);
        if (it != m_headers.end()) {
            touch_lru_internal(hash);
            return it->second;
        }
        IndexEntry tmp;
        if (!try_load_header_from_db_internal(hash, tmp)) return std::nullopt;
        IndexEntry copy = tmp;
        insert_into_cache_internal(hash, std::move(tmp));
        return copy;
    }

    /// Existence check using cache + DB. Avoids loading the full entry into the
    /// cache for transient checks (count() / has_header() pattern).
    bool has_header_internal(const uint256& hash) const {
        if (m_headers.count(hash) > 0) return true;
        if (!m_db || !m_db->is_open()) return false;
        std::string key = "h";
        key.append(reinterpret_cast<const char*>(hash.data()), 32);
        return m_db->exists(key);
    }

    /// Store an entry in the cache and mark it dirty for the next flush.
    /// Use this in place of `m_headers[hash] = entry` to keep LRU + persistence
    /// state in sync.
    void put_header_internal(const uint256& hash, IndexEntry entry) {
        insert_into_cache_internal(hash, std::move(entry));
        m_dirty_headers.insert(hash);
    }

    /// Persist m_height_index entry to LevelDB on next flush.
    void mark_height_dirty_internal(uint32_t h) {
        m_dirty_heights.insert(h);
    }

    void persist_header(const IndexEntry& entry) {
        // Write-back model (matches Litecoin Core's setDirtyBlockIndex):
        // Mark header as dirty — actual DB write happens in flush_dirty().
        m_dirty_headers.insert(entry.block_hash);
    }

    /// Flush all dirty headers + height_index + tip to LevelDB in a single
    /// atomic WriteBatch with sync=true (fsync). Matches Litecoin Core's
    /// FlushStateToDisk() pattern. Caller must hold m_mutex.
    void flush_dirty() {
        if (!m_db || !m_db->is_open()) return;
        if (m_dirty_headers.empty() && m_dirty_heights.empty()) return;

        auto batch = m_db->create_batch();
        int header_count = 0;
        int height_count = 0;

        for (const auto& hash : m_dirty_headers) {
            auto it = m_headers.find(hash);
            if (it == m_headers.end()) continue;  // evicted before flush — should never happen given evict_lru protects dirty

            // Serialize as legacy V1 layout (with hash + prev_hash duplicates)
            // so a pre-Phase-1B binary can still read what we write.
            auto disk = IndexEntryDiskV1::from_entry(it->second);
            auto packed = pack(disk);
            std::vector<uint8_t> data(
                reinterpret_cast<const uint8_t*>(packed.data()),
                reinterpret_cast<const uint8_t*>(packed.data()) + packed.size());

            std::string key = "h";
            key.append(reinterpret_cast<const char*>(hash.data()), 32);
            batch.put(key, data);
            ++header_count;
        }

        // Phase 1C: persist m_height_index dirty entries under "i" + BE_height
        for (uint32_t h : m_dirty_heights) {
            auto it = m_height_index.find(h);
            if (it == m_height_index.end()) continue;
            std::vector<uint8_t> data(it->second.data(), it->second.data() + 32);
            batch.put(make_height_key(h), data);
            ++height_count;
        }

        // Include tip in the same atomic batch
        {
            std::vector<uint8_t> tip_data(m_tip.data(), m_tip.data() + 32);
            batch.put("tip", tip_data);

            uint32_t h = m_tip_height;
            std::vector<uint8_t> height_data(4);
            height_data[0] = (h >> 24) & 0xFF;
            height_data[1] = (h >> 16) & 0xFF;
            height_data[2] = (h >> 8) & 0xFF;
            height_data[3] = h & 0xFF;
            batch.put("height", height_data);
        }

        if (batch.commit_sync()) {
            m_dirty_headers.clear();
            m_dirty_heights.clear();
            LOG_DEBUG_COIND << "[EMB-BCH] flush_dirty: wrote " << header_count
                            << " headers + " << height_count << " height-index entries (synced)";
        } else {
            LOG_ERROR << "[EMB-BCH] flush_dirty: WriteBatch FAILED for " << header_count
                      << " headers + " << height_count << " height-index entries";
        }
    }

    void persist_tip() {
        // Write-back: flush all dirty headers + tip atomically.
        flush_dirty();
    }

    void load_from_db() {
        if (!m_db || !m_db->is_open()) return;

        auto t0 = std::chrono::steady_clock::now();

        // Phase 1C fast path: load m_height_index directly from "i:" entries.
        // This skips the full m_headers RAM residency that pre-Phase-1C used.
        auto i_keys = m_db->list_keys("i", 10000000);
        int hi_loaded = 0;
        if (!i_keys.empty()) {
            m_height_index.reserve(i_keys.size());
            for (auto& k : i_keys) {
                uint32_t h = parse_height_key(k);
                if (h == UINT32_MAX) continue;
                std::vector<uint8_t> data;
                if (!m_db->get(k, data) || data.size() != 32) continue;
                uint256 hash;
                memcpy(hash.data(), data.data(), 32);
                m_height_index[h] = hash;
                ++hi_loaded;
            }
            LOG_INFO << "[EMB-BCH] load_from_db: loaded " << hi_loaded
                     << " height-index entries directly (Phase 1C fast path)";
        }

        // Load tip
        bool need_migration = false;
        std::vector<uint8_t> tip_data;
        if (m_db->get("tip", tip_data) && tip_data.size() == 32) {
            memcpy(m_tip.data(), tip_data.data(), 32);
            // Lazy-load tip header into the cache so subsequent queries (e.g.
            // is_synced()) don't need to hit disk.
            auto tip_opt = lookup_header_internal(m_tip);
            if (tip_opt) {
                m_tip_height = tip_opt->height;
                m_best_work  = tip_opt->chain_work;
                if (hi_loaded == 0) {
                    // Phase 1C migration: older on-disk data has no "i:" entries.
                    // Do the legacy walk ONCE to populate m_height_index, persist,
                    // and let subsequent restarts use the fast path.
                    need_migration = true;
                }
            } else {
                LOG_WARNING << "[EMB-BCH] Tip hash in DB not found — resetting";
                m_tip.SetNull();
            }
        }

        if (need_migration) {
            LOG_INFO << "[EMB-BCH] load_from_db: legacy data detected, running one-time "
                     << "height-index migration (walks back from tip)";
            rebuild_height_index(m_tip);
            for (auto& [h, _] : m_height_index) mark_height_dirty_internal(h);
            // Flush right away so the next restart hits the fast path.
            flush_dirty();
            LOG_INFO << "[EMB-BCH] load_from_db: migration done, " << m_height_index.size()
                     << " height-index entries persisted";
        }

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();
        LOG_INFO << "[EMB-BCH] load_from_db: ready in " << elapsed << "ms"
                 << " tip_height=" << m_tip_height
                 << " tip=" << (m_tip.IsNull() ? "(null)" : m_tip.GetHex().substr(0, 16) + "...")
                 << " m_headers_cached=" << m_headers.size()
                 << " m_height_index=" << m_height_index.size();
    }

    // ─── State ────────────────────────────────────────────────────────────

    BCHChainParams m_params;
    std::string    m_db_path;

    mutable std::mutex m_mutex;

    // Phase 1C: bounded LRU cache for IndexEntry. The full m_height_index is
    // kept in RAM (~46 MB for the BTC mainnet tip), but m_headers is a
    // ~3 MB working-set cache backed by LevelDB. Front of m_lru_order is most
    // recently used; back is the eviction candidate. m_lru_iter gives O(1)
    // moves to front. All three are mutable so that const lookup helpers can
    // refresh LRU position / lazy-load on miss.
    static constexpr size_t HEADER_CACHE_CAP = 16384;
    mutable std::unordered_map<uint256, IndexEntry, Uint256Hasher>  m_headers; // block_hash → entry (LRU-bounded)
    mutable std::list<uint256>                                       m_lru_order;
    mutable std::unordered_map<uint256,
                               std::list<uint256>::iterator,
                               Uint256Hasher>                        m_lru_iter;

    std::unordered_map<uint32_t, uint256>                   m_height_index;  // height → block_hash (best chain only)

    uint256    m_tip;                                // best chain tip hash
    uint32_t   m_tip_height{0};
    uint256    m_best_work;

    // Peer-reported tip height for fast-sync PoW skip.
    // Set from version message; headers below (tip - 2100) skip SHA256d PoW.
    std::atomic<uint32_t> m_peer_tip_height{0};

    std::unique_ptr<core::LevelDBStore> m_db;

    /// Dirty sets: items modified since last flush (write-back model).
    std::unordered_set<uint256, Uint256Hasher> m_dirty_headers;
    std::unordered_set<uint32_t>               m_dirty_heights;

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
} // namespace bch
