// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// dash::stratum::DASHWorkSource -- concrete `core::stratum::IWorkSource`
// implementation for c2pool-dash (Dash X11, V36).
//
// Responsibility: bridge the coin-agnostic `core::StratumServer` (TCP,
// JSON-RPC, sessions, vardiff, rate monitor) to DASH-specific work
// generation + share validation. It is the concrete class the fused
// `dash::stratum::get_work()` capstone (get_work.hpp) refers to as the
// eventual "DASHWorkSource::get_work()" -- the single miner-facing entry
// point that sources a base template off the node-held coin-state and
// assembles the per-miner stratum job targets over it.
//
// The X11 note (NOT scrypt, NOT SHA256d): DASH mines the X11 chained-hash
// PoW. `compute_share_difficulty` encapsulates the X11 hash so the
// coin-agnostic stratum server never hardcodes an algo; the LTC-scrypt /
// BTC-sha256d / DGB-scrypt siblings each override the same seam.
//
// Embedded / fallback duality (MUST PERSIST): work generation sources the
// base block template through `dash::stratum::get_work()`, which itself
// picks the EMBEDDED arm when the node-held `coin::NodeCoinState` bundle is
// populated and otherwise falls back to the always-reachable dashd GBT RPC
// arm (`dashd_fallback_`). The dashd-RPC fallback is never removed -- it is
// the safety + [GBT-XCHECK] cross-check path (operator standing rule).
//
// Lifetime: holds non-owning references to the node-held coin-state and the
// header chain / mempool -- main_dash.cpp owns those for the process
// lifetime, DASHWorkSource is constructed after them and destroyed before.
// The submit-block callback captures whatever upstream state it needs
// (a coin_node ref + the dual-path won-block dispatcher from the
// block-broadcast slice: embedded P2P relay primary + submitblock RPC
// fallback).
//
// Threading: `core::StratumServer` runs on its own io_context; methods here
// may be invoked from any thread serviced by it. Internal synchronisation:
//   - `work_generation_`, `share_bits_`, `share_max_bits_` are atomics
//   - `workers_` is guarded by `workers_mutex_`
//   - `best_share_hash_fn_` / `mint_share_fn_` guarded by their own mutexes
//   - the template cache (stage 4c) is guarded by `template_mutex_`
//   - `coin_state_` has its own internal locking; `dashd_fallback_` is const
//
// What's deliberately MVP-incomplete in this 4a skeleton (mirrors
// dgb::stratum::DGBWorkSource's own 4a landing): every work-generation /
// submit method returns defaults or empty results; no vardiff feedback loop
// yet. The skeleton compiles, instantiates, and lets the next stacked slice
// validate the StratumServer wiring in main_dash.cpp end-to-end before the
// substantive X11 work-assembly + share-validation logic lands (4b/4c/4d).

#include <core/stratum_work_source.hpp>
#include <core/uint256.hpp>

#include <impl/dash/coin/node_coin_state.hpp>   // coin::NodeCoinState, coin::DashWorkData seam
#include <impl/dash/stratum/get_work.hpp>       // dash::stratum::get_work() fused capstone

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

// Forward declarations -- heavy headers live in the .cpp.
namespace dash::coin {
class HeaderChain;
class Mempool;
}  // namespace dash::coin

namespace dash::stratum {

class DASHWorkSource : public core::stratum::IWorkSource
{
public:
    /// Callback invoked when `mining_submit` validates a submission whose
    /// **X11** PoW meets DASH mainnet difficulty. main_dash.cpp wires this
    /// to the dual-path won-block broadcaster: embedded P2P relay primary +
    /// submitblock RPC fallback. Raw-bytes form keeps DASHWorkSource
    /// decoupled from the BlockType serialization details. Returns true iff
    /// the won block reached at least one network sink -- a false return
    /// means it reached NEITHER and the won-block path must log loudly
    /// (no silent drop -- the block-viability gate).
    using SubmitBlockFn = std::function<bool(const std::vector<unsigned char>& block_bytes,
                                             uint32_t height)>;

    /// Construct the DASH work source. Holds a NON-OWNING reference to the
    /// node-held coin-state (the embedded arm) and captures the REQUIRED dashd
    /// getblocktemplate fallback closure -- the always-reachable safety path +
    /// [GBT-XCHECK] cross-check, NEVER removed -- plus the dual-path won-block
    /// submit callback. main_dash.cpp owns coin_state for the process lifetime
    /// and constructs this after it (see the Lifetime note above); the fallback
    /// and submit closures capture the dashd RPC client + won-block dispatcher.
    DASHWorkSource(const coin::NodeCoinState& coin_state,
                   std::function<coin::DashWorkData()> dashd_fallback,
                   SubmitBlockFn submit_fn = {},
                   core::stratum::StratumConfig config = {});

    ~DASHWorkSource();

    /// Fused DASH work source: source the base template off the node-held
    /// coin-state (embedded when populated, retained dashd fallback on a
    /// set-gap) and assemble the per-miner job targets. This is the concrete
    /// DASHWorkSource::get_work() the capstone (get_work.hpp) forward-refs;
    /// the free function `dash::stratum::get_work()` carries the fusion so
    /// the member is a thin, node-bound adapter over it.
    GetWork get_work(const WorkJobTargetInputs& job_in) const;

    // ── IWorkSource: config + read-only state ────────────────────────────
    const core::stratum::StratumConfig& get_stratum_config() const override { return config_; }
    std::function<uint256()>            get_best_share_hash_fn() const override;
    std::string                         get_current_gbt_prevhash() const override;
    uint64_t                            get_work_generation() const override { return work_generation_.load(); }
    bool                                has_merged_chain(uint32_t chain_id) const override;

    // ── IWorkSource: per-connection bookkeeping ──────────────────────────
    void register_stratum_worker(const std::string& session_id,
                                 const core::stratum::WorkerInfo& info) override;
    void unregister_stratum_worker(const std::string& session_id) override;
    void update_stratum_worker(const std::string& session_id,
                               double hashrate, double dead_hashrate, double difficulty,
                               uint64_t accepted, uint64_t rejected, uint64_t stale) override;

    // ── IWorkSource: work generation ─────────────────────────────────────
    nlohmann::json                      get_current_work_template() const override;
    std::vector<std::string>            get_stratum_merkle_branches() const override;
    std::pair<std::string, std::string> get_coinbase_parts() const override;
    core::stratum::CoinbaseResult       build_connection_coinbase(
        const uint256& prev_share_hash,
        const std::string& extranonce1_hex,
        const std::vector<unsigned char>& payout_script,
        const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& merged_addrs) const override;

    // ── IWorkSource: share submission (the hot path) ─────────────────────
    nlohmann::json mining_submit(
        const std::string& username, const std::string& job_id,
        const std::string& extranonce1, const std::string& extranonce2,
        const std::string& ntime, const std::string& nonce,
        const std::string& request_id,
        const std::map<uint32_t, std::vector<unsigned char>>& merged_addresses,
        const core::stratum::JobSnapshot* job) override;

    /// Per-coin PoW-hash difficulty for a pseudoshare. DASH = X11
    /// (chained BLAKE/BMW/Groestl/... over the reconstructed 80-byte
    /// header). Stage 4b/4c implements the assembly + X11 call; the 4a
    /// skeleton returns 0.0 (the documented parse-error / not-yet default).
    double compute_share_difficulty(
        const std::string& coinb1, const std::string& coinb2,
        const std::string& extranonce1, const std::string& extranonce2,
        const std::string& ntime, const std::string& nonce,
        uint32_t version, const std::string& prevhash_hex,
        const std::string& nbits_hex,
        const std::vector<std::string>& merkle_branches) const override;

    // ── IWorkSource: atomic state ────────────────────────────────────────
    uint32_t get_share_bits() const override     { return share_bits_.load(); }
    uint32_t get_share_max_bits() const override { return share_max_bits_.load(); }

    // ── DASH-specific control surface (called from main_dash.cpp) ────────

    /// Increment work_generation. Called when the DASH tip moves (new
    /// headers / node coin-state republish) or the sharechain tip moves.
    /// Triggers stratum sessions to re-push work on their next heartbeat.
    void bump_work_generation() { work_generation_.fetch_add(1, std::memory_order_relaxed); }

    /// Set the current share-target bits (compact-target encoding).
    /// `max_bits` is the easiest the share target can be. Both atomically
    /// visible to stratum sessions.
    void set_share_target(uint32_t bits, uint32_t max_bits)
    {
        share_bits_.store(bits, std::memory_order_relaxed);
        share_max_bits_.store(max_bits, std::memory_order_relaxed);
    }

    /// Wire the share-tracker accessor that returns the current best-share
    /// hash. Called once at startup from main_dash.cpp after the DASH
    /// ShareTracker is constructed.
    void set_best_share_hash_fn(std::function<uint256()> fn);

private:
    // External dependencies (non-owning references) -- see Lifetime note.
    const coin::NodeCoinState&  coin_state_;    ///< embedded work arm (populated -> Embedded)
    std::function<coin::DashWorkData()> dashd_fallback_;  ///< always-reachable dashd GBT RPC arm (never removed)

    // Submission dispatch (dual-path won-block broadcaster).
    SubmitBlockFn               submit_block_fn_;

    // Config (held by value; const after construction in MVP).
    core::stratum::StratumConfig config_;

    // Atomic state.
    std::atomic<uint64_t>       work_generation_{0};
    std::atomic<uint32_t>       share_bits_{0};
    std::atomic<uint32_t>       share_max_bits_{0};

    // Worker registry (per-connection metadata).
    mutable std::mutex          workers_mutex_;
    std::map<std::string, core::stratum::WorkerInfo> workers_;

    // Best-share callback (from ShareTracker). Empty until wired.
    mutable std::mutex          best_share_mutex_;
    std::function<uint256()>    best_share_hash_fn_;

    // Template cache (filled lazily; invalidated when work_generation_ bumps).
    // Stage 4c populates these.
    mutable std::mutex          template_mutex_;
    // ... cache fields land here in stage 4c
};

}  // namespace dash::stratum
