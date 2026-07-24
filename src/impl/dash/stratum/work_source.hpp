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
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
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
    ///
    /// `height_race` is true when the submit-time payee guard classified the
    /// block as a HeightRace (the job's parent moved since issue): the block
    /// MIGHT be invalid at its real height, so the broadcaster dispatches it
    /// RPC-FIRST (local dashd validates before any coin-P2P relay) to avoid
    /// relaying an unvalidated block to peers and risking a coin-P2P ban.
    /// Daemonless (no RPC arm) keeps relay-first: the relay is then the ONLY
    /// path and dropping would forfeit a winnable block.
    using SubmitBlockFn = std::function<bool(const std::vector<unsigned char>& block_bytes,
                                             uint32_t height,
                                             bool height_race)>;

    /// Found-share fields handed to the sharechain mint dispatch when a
    /// stratum submission meets the share target (stage 4d). Mirrors the
    /// dgb::stratum::DGBWorkSource MintShareInputs seam: the run-loop binds
    /// the actual mint (ShareTracker add + peer broadcast) via
    /// set_mint_share_fn once the DASH node-side share-creation seam exists;
    /// until then submissions are accepted for vardiff and LOUDLY logged as
    /// earning no sharechain credit (never a silent drop).
    struct MintShareInputs {
        std::vector<unsigned char> header_bytes;    ///< the 80-byte solved header
        std::vector<unsigned char> coinbase_bytes;  ///< full reassembled coinbase tx
        uint64_t                   subsidy{0};      ///< coinbasevalue frozen at job time
        uint256                    prev_share_hash; ///< sharechain tip frozen at job time
        std::vector<uint256>       merkle_branches; ///< parsed LE-internal branch hashes
        std::vector<unsigned char> payout_script;   ///< miner payout script (from username)
        uint256                    pow_hash;        ///< X11 PoW hash of header_bytes
        // ── slice 3/3 (run-loop mint) additions ──────────────────────────
        /// The PPLNS OP_RETURN commitment of the job's coinbase — recovered
        /// from the coinb1 tail (the coinb1/coinb2 split sits immediately
        /// after the 32-byte ref_hash, before the 8-byte nonce64 slot). The
        /// run-loop keys its frozen-job registry on this; ZERO (non-producer
        /// coinbase) can never match a frozen job -> mint declines fail-closed.
        uint256                    ref_hash;
        /// nonce64 the miner filled into the OP_RETURN slot: LE u64 of
        /// extranonce1 || extranonce2 (4+4 bytes).
        uint64_t                   last_txout_nonce{0};
        /// Template tx hex frozen with the job (shared, may be null) — the
        /// run-loop registers these for share relay (remember_tx serving).
        std::shared_ptr<const std::vector<std::string>> tx_data;
    };
    /// Returns the minted share hash, or null-uint256 when the mint was
    /// declined/deferred (reason logged by the callee).
    using MintShareFn = std::function<uint256(const MintShareInputs&)>;

    /// PPLNS payout inputs for the per-connection coinbase (stage 4c). The
    /// run-loop walks the ShareTracker (walk_cumulative_weights) for the
    /// weight map + the ref-hash commitment and binds the walk here; the work
    /// source itself never reaches into the tracker. While UNBOUND (or when
    /// the producer returns nullopt) the coinbase degrades to the documented
    /// genesis form: the connecting miner's script carries the full
    /// worker_payout (fresh pool, empty sharechain) + the GBT-mandated
    /// masternode/superblock outputs + the donation tail.
    struct PplnsWeights {
        std::map<std::vector<unsigned char>, uint64_t> weights;  ///< script -> weight
        uint64_t total_weight{0};                                ///< grand total (incl. donation weight)
        uint256  ref_hash;                                       ///< PPLNS OP_RETURN commitment
    };
    using PplnsWeightsFn =
        std::function<std::optional<PplnsWeights>(const uint256& prev_share_hash)>;

    /// Producer-built share gentx for a connection's job (slice 3/3). When the
    /// run-loop binds set_producer_job_fn, build_connection_coinbase serves the
    /// producer share gentx VERBATIM as the stratum coinbase (split around the
    /// 8-byte nonce64 slot), so the bytes a miner hashes are byte-identical to
    /// what the mint-time rebuild (build_mint_share) reproduces — the mint's
    /// X11 identity gate then passes by construction. share_bits/max_bits are
    /// the oracle-retargeted share target committed in the share_info; the
    /// work source publishes them via set_share_target so the mining_submit
    /// classification gate matches the share's own target.
    struct ProducerJob {
        std::vector<unsigned char> gentx_bytes;    ///< full share gentx, nonce64 slot zeroed
        size_t                     nonce64_offset{0}; ///< first byte of the 8B nonce64 slot
        uint256                    ref_hash;       ///< PPLNS OP_RETURN commitment (registry key)
        uint32_t                   share_bits{0};  ///< share_info.bits (oracle retarget)
        uint32_t                   share_max_bits{0}; ///< share_info.max_bits
    };
    /// Returns nullopt when no producer job can be built right now (tracker
    /// busy, non-P2PKH payout, no template) — the coinbase then degrades to
    /// the non-producer path (block-valid, mint declines fail-closed).
    using ProducerJobFn = std::function<std::optional<ProducerJob>(
        const uint256& prev_share_hash,
        const std::vector<unsigned char>& payout_script,
        const coin::DashWorkData& wd)>;

    /// Construct the DASH work source. Holds a NON-OWNING reference to the
    /// node-held coin-state (the embedded arm) and captures the REQUIRED dashd
    /// getblocktemplate fallback closure -- the always-reachable safety path +
    /// [GBT-XCHECK] cross-check, NEVER removed -- plus the dual-path won-block
    /// submit callback. main_dash.cpp owns coin_state for the process lifetime
    /// and constructs this after it (see the Lifetime note above); the fallback
    /// and submit closures capture the dashd RPC client + won-block dispatcher.
    /// `is_testnet` selects the coin params (address versions for GBT payee
    /// decode + the v36 version gate) the coinbase builder consumes.
    DASHWorkSource(const coin::NodeCoinState& coin_state,
                   std::function<coin::DashWorkData()> dashd_fallback,
                   SubmitBlockFn submit_fn = {},
                   core::stratum::StratumConfig config = {},
                   bool is_testnet = false);

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

    /// Thread-safe snapshot of the per-connection worker registry
    /// (session_id -> WorkerInfo). The DASH stratum acceptor is a standalone
    /// core::StratumServer bound to THIS work source (main_dash.cpp), so its
    /// StratumSessions register/update HERE -- not into the dashboard
    /// WebServer's own MiningInterface registry (that acceptor is disabled).
    /// main_dash.cpp feeds this snapshot to
    /// MiningInterface::set_stratum_workers_fn so /local_stats reports the
    /// real per-worker hashrates + share/difficulty state (display only).
    std::map<std::string, core::stratum::WorkerInfo> get_stratum_workers() const;

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

    /// IWorkSource best-share feed: recompute the exact X11 pow-hash for this
    /// accepted pseudoshare and forward (difficulty, miner, pow_hash) to the
    /// dashboard best-share tracker via on_share_difficulty_fn_. Every accepted
    /// pseudoshare flows here (the stratum vardiff-accept path), so the "Best
    /// Share" card populates on the DASH solo path where shares seldom mint.
    void record_best_pseudoshare(
        double share_difficulty, const std::string& miner,
        const std::string& coinb1, const std::string& coinb2,
        const std::string& extranonce1, const std::string& extranonce2,
        const std::string& ntime, const std::string& nonce,
        uint32_t version, const std::string& prevhash_hex,
        const std::string& nbits_hex,
        const std::vector<std::string>& merkle_branches) override;

    // ── IWorkSource: atomic state ────────────────────────────────────────
    uint32_t get_share_bits() const override     { return share_bits_.load(); }
    uint32_t get_share_max_bits() const override { return share_max_bits_.load(); }

    // ── DASH-specific control surface (called from main_dash.cpp) ────────

    /// Increment work_generation. Called when the DASH tip moves (new
    /// headers / node coin-state republish) or the sharechain tip moves.
    /// Triggers stratum sessions to re-push work on their next heartbeat.
    void bump_work_generation() { work_generation_.fetch_add(1, std::memory_order_relaxed); }

    /// Gate-lift (v0.2.4 trigger): allow the daemonless embedded arm on MAINNET.
    /// The embedded CbTx (version, merkleRootMNList, merkleRootQuorums, bestCL,
    /// creditPoolBalance) is proven BYTE-IDENTICAL to a real dashd
    /// getblocktemplate — both roots reproduced from the raw mnlistdiff wire
    /// (test_dash_embedded_cbtx_byte_parity.cpp + test_dash_mnlistdiff_root_parity.cpp).
    /// Default OFF: an unconfigured mainnet node stays on the reward-safe dashd
    /// fallback (unchanged behaviour). When ON, the embedded arm still serves
    /// ONLY when NodeCoinState viability holds — SML+quorum fresh AT the tip and
    /// not a superblock height — else it fails safe to the dashd fallback.
    void set_embedded_mainnet(bool v) { embedded_mainnet_ = v; }

    /// GBT-xcheck reward-safety BACKSTOP (soak). When a dashd is reachable (the
    /// fallback arm), cross-check the EMBEDDED CbTx's creditPoolBalance against
    /// dashd getblocktemplate's before serving; on mismatch, serve dashd's
    /// reward-safe template instead. Catches ANY credit-pool seed bug (present or
    /// future) that the daemonless self-checks cannot. NOT pure-daemonless (uses
    /// dashd), so it is opt-in; main_dash enables it for --embedded-mainnet where
    /// a dashd fallback is configured. Pure-daemonless mode leaves it off and
    /// relies on the independent seed-height gate.
    void set_gbt_xcheck(bool v) { gbt_xcheck_ = v; }

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

    /// Best-share (highest-difficulty pseudoshare) reporter. Fired from
    /// mining_submit for EVERY accepted submission with the actual PoW
    /// difficulty of the found hash (target_to_difficulty(pow_hash)), the
    /// submitting miner (stratum username), and the pow-hash hex. main_dash.cpp
    /// binds this to MiningInterface::record_share_difficulty so the dashboard
    /// "Best Share" card shows how close DASH solo shares got to net difficulty
    /// even when no share ever mints onto the sharechain. Display only — never
    /// touches share/target/payout logic. While unbound this is a no-op.
    using ShareDifficultyFn =
        std::function<void(double difficulty, const std::string& miner,
                           const uint256& pow_hash)>;
    void set_on_share_difficulty_fn(ShareDifficultyFn fn);

    /// Found-block reporter for the dashboard "Recent Blocks" card. Fired from
    /// mining_submit the moment a submission meets the full network block
    /// target AND is dispatched to the network (NOT on a local payee-guard
    /// reject). Carries the block height, the X11 block hash (== pow_hash for
    /// DASH), the submitting miner, and whether at least one network sink was
    /// reached. main_dash.cpp binds this to MiningInterface::record_found_block
    /// so DASH block wins appear in the found-block history. Display only —
    /// never gates the won-block dispatch. While unbound this is a no-op.
    using FoundBlockFn =
        std::function<void(uint32_t height, const uint256& block_hash,
                           const std::string& miner, bool reached_network)>;
    void set_on_found_block_fn(FoundBlockFn fn);

    /// Wire the sharechain mint dispatch (stage 4d follow-up). While unbound,
    /// share-target submissions are accepted for vardiff + loudly logged.
    void set_mint_share_fn(MintShareFn fn);

    /// Wire the ShareTracker PPLNS weight walk (stage 4c multi-output path).
    /// While unbound, the coinbase uses the genesis single-miner split.
    void set_pplns_weights_fn(PplnsWeightsFn fn);

    /// Wire the run-loop producer-job builder (slice 3/3). While unbound the
    /// coinbase path is byte-unchanged (compute_dash_payouts + coinbase::build)
    /// and share-target submissions cannot mint (loud fail-closed decline).
    void set_producer_job_fn(ProducerJobFn fn);

    /// Drop the cached template snapshot + bump work_generation. Wired to the
    /// NodeRPC reconnect hook in main_dash.cpp (stale-payee fix, defect 3):
    /// a "CoindRPC reconnecting" churn means any cached template — and the
    /// masternode payee frozen inside it — may predate the reconnect, so no
    /// further job may be served from it. The generation bump makes every
    /// stratum session re-pull a FRESH template on its next heartbeat.
    void invalidate_template_cache(const char* reason = "reconnect");

    /// Non-fetching read of the last DashWorkData sourced through the
    /// embedded/dashd selector. Returns the cached snapshot (or nullptr when
    /// none has been sourced yet) WITHOUT triggering a refresh -- safe to call
    /// from the dashboard HTTP thread. main_dash.cpp feeds it to
    /// MiningInterface::set_coin_work_fn so /local_stats can report the real
    /// block_value / masternode payment split / network difficulty from the
    /// live template (display only; never drives coinbase or consensus).
    std::shared_ptr<const coin::DashWorkData> peek_template() const;

private:
    /// Template cache resolve: return the cached DashWorkData snapshot when it
    /// is still fresh (same work_generation AND younger than the staleness
    /// TTL), else re-source it through the embedded/fallback selector
    /// (coin_state_.select_work). Returns nullptr on an honest set-gap (no
    /// template source armed / empty template) -- never a fabricated one.
    /// Bumps work_generation_ when a refresh observes a moved coin tip so
    /// stratum sessions re-push work on their next heartbeat.
    std::shared_ptr<const coin::DashWorkData> cached_work() const;
    // io-thread-decouple: the blocking select_work()/dashd-GBT re-source, factored
    // out so it runs either inline (legacy blocking path, no executor wired) OR
    // on the background rpc_pool thread (via refresh_executor_). Updates the
    // template cache under template_mutex_.
    void resource_template_now() const;

public:
    // io-thread-decouple: wire a background executor (main_dash.cpp posts onto
    // the dedicated rpc_pool). When set, cached_work() NEVER blocks the caller
    // on a dashd GBT: it serves the (possibly stale) cache immediately and hands
    // the blocking re-source to this executor as a SINGLE-FLIGHT background job.
    // Set once at startup before the io loop runs. Only wired on the dashd-
    // fallback arm; unset -> the legacy inline-blocking path (embedded/tests).
    void set_refresh_executor(std::function<void(std::function<void()>)> fn)
    { refresh_executor_ = std::move(fn); }

private:
    // External dependencies (non-owning references) -- see Lifetime note.
    const coin::NodeCoinState&  coin_state_;    ///< embedded work arm (populated -> Embedded)
    std::function<coin::DashWorkData()> dashd_fallback_;  ///< always-reachable dashd GBT RPC arm (never removed)

    // Submission dispatch (dual-path won-block broadcaster).
    SubmitBlockFn               submit_block_fn_;

    // Config (held by value; const after construction in MVP).
    core::stratum::StratumConfig config_;

    // Network selector for coin-params resolution (address versions + v36 gate).
    bool is_testnet_{false};
    bool embedded_mainnet_{false};   // gate-lift opt-in: daemonless embedded arm on mainnet
    bool gbt_xcheck_{false};         // reward-safety backstop: cross-check embedded creditPool vs dashd

    // Atomic state. work_generation_ is mutable: the const template-cache
    // resolve (cached_work) bumps it when a refresh observes a moved tip.
    mutable std::atomic<uint64_t> work_generation_{0};
    std::atomic<uint32_t>       share_bits_{0};
    std::atomic<uint32_t>       share_max_bits_{0};

    // Worker registry (per-connection metadata).
    mutable std::mutex          workers_mutex_;
    std::map<std::string, core::stratum::WorkerInfo> workers_;

    // Best-share callback (from ShareTracker). Empty until wired.
    mutable std::mutex          best_share_mutex_;
    std::function<uint256()>    best_share_hash_fn_;

    // Best-share (highest-difficulty pseudoshare) reporter. Empty until wired.
    mutable std::mutex          share_difficulty_mutex_;
    ShareDifficultyFn           on_share_difficulty_fn_;

    // Found-block reporter (dashboard recent-blocks card). Empty until wired.
    mutable std::mutex          found_block_mutex_;
    FoundBlockFn                on_found_block_fn_;

    // Sharechain mint dispatch (stage 4d). Empty until wired.
    mutable std::mutex          mint_share_mutex_;
    MintShareFn                 mint_share_fn_;

    // PPLNS weight walk (stage 4c multi-output path). Empty until wired.
    mutable std::mutex          pplns_mutex_;
    PplnsWeightsFn              pplns_weights_fn_;

    // Producer-job builder (slice 3/3 run-loop mint). Empty until wired.
    mutable std::mutex          producer_job_mutex_;
    ProducerJobFn               producer_job_fn_;

    // Template cache (stage 4c): the last DashWorkData sourced through the
    // embedded/fallback selector, keyed on work_generation_ + a staleness TTL
    // (kStaleAfter). A failed fetch is negative-cached for kRetryAfter so a
    // down dashd is not hammered by every session's 1 s notify retry timer.
    mutable std::mutex          template_mutex_;
    mutable std::shared_ptr<const coin::DashWorkData> template_cache_;
    mutable uint64_t            template_cache_gen_{0};
    mutable std::chrono::steady_clock::time_point template_cache_at_{};
    // Whether the cached template came from the EMBEDDED arm. Serve-time re-check
    // (soak build-vs-serve skew): an embedded cache HIT is re-validated against
    // the CURRENT coin-state before being served, so a template built with a
    // stale credit-pool seed cannot be served after the seed advances.
    mutable bool                template_cache_is_embedded_{false};
    mutable std::chrono::steady_clock::time_point template_last_fail_at_{};

    // io-thread-decouple: background single-flight template refresh.
    // refresh_executor_ posts the blocking re-source onto the rpc_pool thread
    // (set_refresh_executor); template_refresh_inflight_ collapses concurrent
    // refreshes to one. Empty executor -> legacy inline-blocking cached_work().
    std::function<void(std::function<void()>)> refresh_executor_;
    mutable std::atomic<bool>   template_refresh_inflight_{false};
};

}  // namespace dash::stratum
