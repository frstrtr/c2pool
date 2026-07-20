// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Coin-agnostic data types crossing the stratum API boundary.
//
// These types were originally defined as nested structs inside
// `core::MiningInterface` (web_server.hpp), tightly coupled to LTC's
// concrete stratum implementation. They were hoisted here as part of
// the IWorkSource extraction (B4-stratum / 2026-05) so multiple coin
// modules — LTC (`core::MiningInterface`), BTC (`btc::stratum::
// BTCWorkSource`), and future BCH/DGB ports — can share a single
// `core::StratumServer` driven by the same `IWorkSource` interface.
//
// Shape neutrality: every field here is either a primitive, a
// `uint256`/`uint128`, or a stdlib container of those. No coin-specific
// types appear. Where defaults exist (e.g. `share_version=36`,
// `desired_version=36`) they are LTC's defaults; non-LTC implementors
// override at construction time. The `mweb` field on `JobSnapshot` /
// `WorkSnapshot` is empty for chains without MimbleWimble (BTC, DOGE,
// DGB) — present only so the same struct serializes through both LTC
// and non-LTC paths without divergence.

#include <core/uint256.hpp>
#include <memory>

#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace core::stratum {

/// Static config for the stratum server's vardiff + work loop.
/// Shared across all sessions. Values match p2pool defaults.
struct StratumConfig {
    double min_difficulty       = 0.0005;   // floor for per-connection vardiff
    double max_difficulty       = 65536.0;  // ceiling for per-connection vardiff
    double target_time          = 3.0;      // seconds between pseudoshares (p2pool default: 3)
    bool   vardiff_enabled      = true;     // auto-adjust per-connection difficulty
    bool   use_hashrate_vardiff = false;    // stable-by-construction hashrate-based vardiff (DASH); off = legacy ratio feedback
    size_t max_coinbase_outputs = 4000;     // Python p2pool's [-4000:] cap; no consensus limit
    // Per-network mining.set_difficulty multiplier (p2pool net.DUMB_SCRYPT_DIFF):
    // 2^16 (65536) for scrypt nets (LTC/DOGE), 1 for SHA256d nets (bitcoin).
    // Default preserves the scrypt convention; SHA256d work sources override to 1.0.
    double set_difficulty_multiplier = 65536.0;
    // STRICT per-node miner cap (mining-hotel interim fix): maximum number of
    // concurrent stratum TCP sessions this node accepts. When the cap is hit
    // the excess socket is closed cleanly, a WARN is logged, the
    // refused_connections counter increments, and the accept loop keeps
    // running. 0 = unlimited (legacy behavior). Wire-through:
    // max_stratum_connections (YAML) / --max-stratum-connections (CLI).
    // Admission control only — zero wire-byte change for admitted sessions.
    size_t max_stratum_connections = 100;
    // Runtime coin tag for coin-agnostic core log lines (e.g. the "waiting
    // for block template" warning). Set by each coin's work source / main so
    // a DASH binary never logs "[LTC]" (issue #732 secondary defect). Empty
    // -> the core falls back to the neutral "[Stratum]" tag.
    std::string coin_symbol;
    // Coins whose coinbase validity is bound to the template height (DASH:
    // the masternode payee rotates EVERY block -> a coinbase built from one
    // template combined with the header of another is rejected bad-cb-payee)
    // set this true. The session then refuses to assemble a job unless
    // build_connection_coinbase() returned an atomic header+coinbase snapshot
    // (WorkSnapshot::has_header): no job is ever served from MIXED template
    // fetches, and the legacy stub-coinbase fallback is unreachable.
    // Default false: LTC/BTC/DGB behavior is byte-unchanged.
    bool require_job_snapshot{false};
};

/// Frozen share-construction fields returned by ref_hash_fn. These
/// capture the share-tracker state at the moment a job was assembled
/// so the resulting share matches even if the tip moved before submit.
struct RefHashResult {
    uint256  ref_hash;
    uint64_t last_txout_nonce{0};
    uint32_t absheight{0};
    uint128  abswork;
    uint256  far_share_hash;
    uint32_t max_bits{0};
    uint32_t bits{0};
    uint32_t timestamp{0};
    uint256  merged_payout_hash;
    int64_t  share_version{36};     // LTC default; BTC/etc. override at construction
    uint64_t desired_version{36};   // version vote (always target version)
    // Frozen mm_commitment — cached from rebuild_cached_blocks().
    // Empty if no merged mining (BTC: always empty in MVP).
    std::vector<uint8_t> frozen_mm_commitment;
    // Frozen segwit data — merkle branches and witness root change between
    // GBT updates, but the ref_hash was computed with the values at template time.
    std::vector<uint256> frozen_merkle_branches;
    uint256  frozen_witness_root;
    // V36 LTC: frozen merged coinbase info (pre-serialized vector<MergedCoinbaseEntry>)
    // Contains DOGE block header + merkle proof for consensus verification.
    // Empty for non-merged coins.
    std::vector<unsigned char> frozen_merged_coinbase_info;
};

/// All template data frozen at the time a mining job was sent, plus the
/// share-target bits the miner actually hashed against. Passed back into
/// IWorkSource::mining_submit() so the work source can validate without
/// re-fetching template state that may have rolled.
struct JobSnapshot {
    std::string coinb1, coinb2;
    std::string gbt_prevhash;      // BE display hex
    std::string nbits;             // BE hex e.g. "1e0fffff" (share target bits for header)
    uint32_t    version{0};
    std::vector<std::string> merkle_branches;
    std::shared_ptr<const std::vector<std::string>> tx_data;   // raw tx hex from GBT (a1: shared/lazy)
    std::string mweb;                    // empty for non-MWEB coins
    bool        segwit_active{false};
    uint256     prev_share_hash;  // share chain tip when this job was built
    uint64_t    subsidy{0};       // coinbasevalue frozen at job creation
    std::string witness_commitment_hex;  // P2Pool witness commitment frozen at job creation
    uint256     witness_root;            // raw wtxid merkle root frozen at job creation
    uint32_t    share_bits{0};    // share target bits from compute_share_target()
    uint32_t    share_max_bits{0}; // share max_bits from compute_share_target()
    std::string block_nbits;      // original GBT block bits (for block target check)
    RefHashResult frozen_ref;     // frozen share fields from template time
    int stale_info{0};            // 0=none, 253=orphan (stale block template)
};

/// Atomic snapshot of work-related fields under the work source's mutex.
/// Used by the connection-coinbase builder to freeze consistent state
/// matching the coinbase output it produces.
struct WorkSnapshot {
    bool segwit_active{false};
    std::string mweb;             // empty for non-MWEB coins
    uint64_t subsidy{0};
    std::string witness_commitment_hex;
    uint256 witness_root;
    RefHashResult frozen_ref;
    // Block body data — captured atomically with witness_commitment to
    // prevent merkle root mismatch when refresh_work() updates the template.
    std::shared_ptr<const std::vector<std::string>> tx_data;          // raw tx hex from template (a1: shared/lazy)
    std::vector<std::string> merkle_branches;  // stratum merkle branches
    // ── Atomic header binding (stale-payee fix) ──────────────────────────
    // Header fields frozen from the SAME template snapshot the coinbase was
    // built over. When has_header is true the stratum session OVERRIDES the
    // header fields it fetched separately via get_current_work_template()
    // with these, so the issued job (prevhash/version/nbits/ntime + coinbase
    // + merkle branches + tx set) is ONE frozen unit from ONE template — a
    // job can never carry the new tip's header with the old height's
    // masternode payee (dashd bad-cb-payee, a lost block reward). Work
    // sources that leave has_header false (LTC/BTC/DGB) are byte-unchanged.
    bool        has_header{false};
    std::string gbt_prevhash;        // BE display hex (template previousblockhash)
    uint32_t    header_version{0};   // block header version
    std::string block_nbits_hex;     // 8-char BE hex GBT block bits
    uint32_t    curtime{0};          // template curtime (0 = leave session value)
    uint32_t    height{0};           // template height (diagnostics/logging)
};

/// Result of build_connection_coinbase(): the two coinbase fragments
/// the miner needs (coinb1 + extranonce + coinb2 = full coinbase tx)
/// plus the work snapshot frozen at construction.
struct CoinbaseResult {
    std::string coinb1;
    std::string coinb2;
    WorkSnapshot snapshot;
};

/// Per-connection metadata maintained by the work source for dashboard
/// + stats display. Updated by the stratum session as shares accumulate.
struct WorkerInfo {
    std::string username;      // miner address (after parsing)
    std::string worker_name;   // worker suffix from "ADDRESS.worker" (e.g. "alpha")
    double hashrate{0.0};      // measured H/s from HashrateTracker
    double dead_hashrate{0.0}; // DOA H/s
    double difficulty{1.0};    // current vardiff difficulty
    uint64_t accepted{0};
    uint64_t rejected{0};
    uint64_t stale{0};
    std::chrono::steady_clock::time_point connected_at;
    std::string remote_endpoint;  // "ip:port"
};

}  // namespace core::stratum