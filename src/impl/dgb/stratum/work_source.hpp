// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// dgb::stratum::DGBWorkSource — concrete `core::stratum::IWorkSource`
// implementation for c2pool-dgb (DigiByte Scrypt-only, V36).
//
// Responsibility: bridge the coin-agnostic `core::StratumServer` (TCP,
// JSON-RPC, sessions, vardiff, rate monitor) to DGB-specific work
// generation + share validation. Produces stratum jobs from the local
// header chain + mempool via `dgb::coin::TemplateBuilder` (Scrypt
// templates), validates submitted shares with **Scrypt** PoW (NOT
// SHA256d — DGB-Scrypt is the only algo this V36 binary mines; the other
// four DGB algos are accept-by-continuity / V37), and dispatches
// mainnet-hit blocks to the dual-path won-block broadcaster wired in
// main_dgb.cpp (coin/block_broadcast.hpp: P2P relay primary + submitblock
// RPC fallback — rpc.cpp:387 submit_block_hex, already real, NOT a stub).
//
// Lifetime: holds non-owning references to `HeaderChain` and `Mempool`
// — main_dgb.cpp owns those for the process lifetime, DGBWorkSource is
// constructed after them and destroyed before. The submit-block callback
// captures whatever upstream state it needs (typically a coin_node ref +
// the won-block dispatcher from PRs #166/#167).
//
// Threading: `core::StratumServer` runs on its own io_context; methods
// here may be invoked from any thread serviced by it. Internal
// synchronisation:
//   - `work_generation_`, `share_bits_`, `share_max_bits_` are atomics
//   - `workers_` is guarded by `workers_mutex_`
//   - the template cache is guarded by `template_mutex_`
//   - `chain_` and `mempool_` have their own internal locking
//
// What's deliberately MVP-incomplete in this commit (Stage 4a skeleton —
// mirrors btc::stratum::BTCWorkSource's own 4a landing @541c735f):
//   - All work-generation / submit methods return defaults or empty
//     results. Subsequent sub-stages (4b/4c/4d) implement the read-only
//     getters, the Scrypt work assembly, and the share-validation hot path.
//   - No vardiff feedback loop yet — `update_stratum_worker` records but
//     doesn't yet drive set_difficulty back to sessions.
// The skeleton is intentionally non-functional but compiles, instantiates,
// and lets us validate the StratumServer wiring in main_dgb.cpp end-to-end
// (the next stacked slice) before implementing the substantive logic.

#include <core/stratum_work_source.hpp>
#include <core/uint256.hpp>
#include <core/pow.hpp>       // core::SubsidyFunc — embedded coinbasevalue SSOT feed
#include <impl/dgb/coin/connection_coinbase.hpp>  // ConnCoinbasePplnsInputs (PPLNS->coinbase SSOT)

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

// Forward declarations — heavy headers live in the .cpp. Note the split
// namespaces: HeaderChain lives in c2pool::dgb (header_chain.hpp), Mempool
// in dgb::coin (mempool.hpp).
namespace c2pool::dgb {
class HeaderChain;
}  // namespace c2pool::dgb
namespace dgb::coin {
class Mempool;
}  // namespace dgb::coin

namespace dgb::stratum {

class DGBWorkSource : public core::stratum::IWorkSource
{
public:
    /// Callback invoked when `mining_submit` validates a submission whose
    /// **Scrypt** PoW meets DGB mainnet difficulty. main_dgb.cpp wires this
    /// to the dual-path won-block broadcaster (coin/block_broadcast.hpp):
    /// P2P relay primary + submitblock RPC fallback. Raw-bytes form keeps
    /// DGBWorkSource decoupled from the BlockType serialization details.
    /// Returns true iff the won block reached at least one network sink
    /// (P2P relay or submitblock RPC fallback). A false return means it
    /// reached NEITHER and the won-block path must log a loud error
    /// (no silent drop — the dual-path broadcaster gate on #82).
    using SubmitBlockFn = std::function<bool(const std::vector<unsigned char>& block_bytes,
                                             uint32_t height)>;

    /// Inputs the worker->mint sharechain-accept path hands to the run-loop:
    /// the assembled fields of a submission whose **Scrypt** PoW met the SHARE
    /// target (but NOT the full block target). Raw-bytes form (header +
    /// coinbase) keeps DGBWorkSource decoupled from the share/BlockType
    /// serialization details, exactly like SubmitBlockFn -- main_dgb.cpp parses
    /// these into create_local_share()'s arguments.
    struct MintShareInputs {
        std::vector<unsigned char> header_bytes;    ///< 80-byte reconstructed block header
        std::vector<unsigned char> coinbase_bytes;  ///< p2pool coinbase scriptSig (BIP34 height + marker)
        uint64_t                   subsidy = 0;      ///< coinbasevalue (block reward)
        uint256                    prev_share;       ///< current sharechain tip = the new share's parent
        std::vector<uint256>       merkle_branches;  ///< coinbase txid -> merkle root branches
        std::vector<unsigned char> payout_script;    ///< finder's scriptPubKey
        bool                       segwit_active = false;
    };

    /// Callback invoked when `mining_submit` validates a submission whose
    /// **Scrypt** PoW meets the SHARE target but NOT the full block target --
    /// the worker->mint sharechain-accept branch (the mining_submit classify
    /// step "pow_hash <= share target -> record share in tracker"). main_dgb.cpp
    /// binds this to mint_local_share_with_ratchet (run_loop_mint.hpp, #294)
    /// -> create_local_share: the WorkSource hands out the found-share fields,
    /// the run-loop asks the AutoRatchet for the {mint, vote} version pair and
    /// inserts the share. Returns the minted share hash (NULL uint256 on
    /// failure). Parallel to SubmitBlockFn but for the share-difficulty (not
    /// block-difficulty) outcome -- the two non-reject classes of mining_submit.
    using MintShareFn =
        std::function<uint256(const MintShareInputs&)>;

    DGBWorkSource(c2pool::dgb::HeaderChain&     chain,
                  dgb::coin::Mempool&           mempool,
                  bool                          is_testnet,
                  SubmitBlockFn                 submit_fn,
                  core::SubsidyFunc             subsidy_func,
                  core::stratum::StratumConfig  config = {});
    ~DGBWorkSource() override;

    DGBWorkSource(const DGBWorkSource&)            = delete;
    DGBWorkSource& operator=(const DGBWorkSource&) = delete;

    // ── IWorkSource: config + read-only state ────────────────────────────
    const core::stratum::StratumConfig& get_stratum_config() const override;
    std::function<uint256()>            get_best_share_hash_fn() const override;
    std::string                         get_current_gbt_prevhash() const override;
    uint64_t                            get_work_generation() const override;
    bool                                has_merged_chain(uint32_t chain_id) const override;

    // ── IWorkSource: per-connection bookkeeping ──────────────────────────
    void register_stratum_worker(const std::string& session_id,
                                 const core::stratum::WorkerInfo& info) override;
    void unregister_stratum_worker(const std::string& session_id) override;
    void update_stratum_worker(const std::string& session_id,
                               double hashrate, double dead_hashrate, double difficulty,
                               uint64_t accepted, uint64_t rejected, uint64_t stale) override;

    // ── IWorkSource: work generation ─────────────────────────────────────
    nlohmann::json                       get_current_work_template() const override;
    std::vector<std::string>             get_stratum_merkle_branches() const override;
    std::pair<std::string, std::string>  get_coinbase_parts() const override;
    core::stratum::CoinbaseResult        build_connection_coinbase(
        const uint256& prev_share_hash,
        const std::string& extranonce1_hex,
        const std::vector<unsigned char>& payout_script,
        const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& merged_addrs) const override;

    // ── IWorkSource: share submission ────────────────────────────────────
    nlohmann::json mining_submit(
        const std::string& username, const std::string& job_id,
        const std::string& extranonce1, const std::string& extranonce2,
        const std::string& ntime, const std::string& nonce,
        const std::string& request_id,
        const std::map<uint32_t, std::vector<unsigned char>>& merged_addresses,
        const core::stratum::JobSnapshot* job) override;

    /// Per-coin PoW-hash difficulty for a pseudoshare. DGB-Scrypt =
    /// scrypt_1024_1_1_256 over the reconstructed 80-byte header. Stage
    /// 4b/4c implements the assembly + scrypt call; the 4a skeleton
    /// returns 0.0 (the documented parse-error / not-yet default).
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

    // ── DGB-specific control surface (called from main_dgb.cpp) ──────────

    /// Increment work_generation. Called when the DGB tip moves (new
    /// headers) or when the sharechain tip moves. Triggers stratum sessions
    /// to re-push work on their next heartbeat.
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
    /// hash. Called once at startup from main_dgb.cpp after ShareTracker
    /// is constructed.
    void set_best_share_hash_fn(std::function<uint256()> fn);

    /// Wire the worker->mint sharechain-accept dispatch. Called once at startup
    /// from main_dgb.cpp, bound to mint_local_share_with_ratchet (#294) ->
    /// create_local_share. Empty until wired (mirrors set_best_share_hash_fn);
    /// while empty, try_mint_share() no-ops with a loud log rather than
    /// silently dropping an accepted share.
    void set_mint_share_fn(MintShareFn fn);

    /// Optional node-local fallback payout selector (Redistribute V2, #307).
    /// Invoked by the ShareAccept mint path when a submission's stratum
    /// username yields NO valid payout script (empty/broken credentials): it
    /// returns the scriptPubKey this node stamps onto the minted share per the
    /// operator's --redistribute policy. Empty until bound (opt-in only);
    /// while unbound the empty-credential path is byte-identical to before.
    /// Consensus-safe: chooses only this node's own stamp, not sharechain rules.
    using FallbackPayoutFn = std::function<std::vector<unsigned char>()>;
    void set_fallback_payout_fn(FallbackPayoutFn fn);

    /// Producer seam for the per-connection coinbase (Phase B live-wire).
    /// Given the share-chain tip a miner builds ON TOP OF, plus this session's
    /// extranonce1 and resolved payout/merged scripts, returns the fully
    /// populated PPLNS inputs (weight map sourced from the ShareTracker, ref_hash,
    /// subsidy, donation script). Bound once at startup in main_dgb.cpp where the
    /// ShareTracker + CoinParams are in scope; the tracker walk lives THERE so no
    /// sharechain logic leaks into the work source. While UNBOUND,
    /// build_connection_coinbase() returns an empty result (byte-identical to the
    /// pre-wire stub -- no behavior change until the producer is bound). Returning
    /// std::nullopt (e.g. tip not yet known) also yields an empty, safe job. The
    /// emitted coinbase is byte-identical to the verifier's
    /// generate_share_transaction() BY CONSTRUCTION: both delegate to the single
    /// compute_pplns_payout_split() SSOT via build_connection_coinbase_from_pplns.
    using PplnsInputsFn = std::function<std::optional<dgb::coin::ConnCoinbasePplnsInputs>(
        const uint256& prev_share_hash,
        const std::string& extranonce1_hex,
        const std::vector<unsigned char>& payout_script,
        const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& merged_addrs)>;
    void set_pplns_inputs_fn(PplnsInputsFn fn);

    /// Dispatch one share-difficulty submission to the bound mint callback.
    /// The stage-4d mining_submit classify branch calls this on the
    /// "pow_hash <= share target" outcome. Returns the minted share hash, or a
    /// NULL uint256 when no mint callback is wired (logged, never crashes) or
    /// when the callback itself returns null. Thread-safe: copies the callback
    /// under lock before invoking so a concurrent set_mint_share_fn() cannot
    /// tear it out mid-call.
    uint256 try_mint_share(const MintShareInputs& in) const;

    /// Embedded-path coinbasevalue for the template builder (Stage 4c).
    /// Routes through dgb::coin::resolve_coinbase_value: when the external
    /// digibyted GBT supplied a coinbasevalue it is returned verbatim (the
    /// external-daemon fallback that MUST PERSIST); otherwise the value is
    /// derived locally as subsidy_func(height) + total_fees from the DGB
    /// oracle decay schedule. First PRODUCTION invocation site of
    /// CoinParams::subsidy_func (SSOT guarded by test_dgb_coinbase_value).
    uint64_t coinbase_value(uint32_t height, uint64_t total_fees,
                            std::optional<uint64_t> gbt_coinbasevalue) const;

private:
    // External dependencies (non-owning references)
    c2pool::dgb::HeaderChain&   chain_;
    dgb::coin::Mempool&         mempool_;
    const bool                  is_testnet_;

    // Submission dispatch
    SubmitBlockFn               submit_block_fn_;

    // Embedded coinbasevalue SSOT feed (CoinParams::subsidy_func). Drives the
    // template builder's coinbasevalue when no external-daemon GBT value.
    core::SubsidyFunc           subsidy_func_;

    // Config (held by value; const after construction in MVP)
    core::stratum::StratumConfig config_;

    // Atomic state
    std::atomic<uint64_t>       work_generation_{0};
    std::atomic<uint32_t>       share_bits_{0};
    std::atomic<uint32_t>       share_max_bits_{0};

    // Worker registry (per-connection metadata)
    mutable std::mutex          workers_mutex_;
    std::map<std::string, core::stratum::WorkerInfo> workers_;

    // Best-share callback (from ShareTracker)
    mutable std::mutex          best_share_mutex_;
    std::function<uint256()>    best_share_hash_fn_;

    // Worker->mint sharechain-accept callback (to mint_local_share_with_ratchet
    // -> create_local_share, wired in main_dgb.cpp). Empty until set; the
    // mining_submit classify branch no-ops the mint when unbound.
    mutable std::mutex          mint_share_mutex_;
    MintShareFn                 mint_share_fn_;

    // Node-local --redistribute fallback payout selector (#307). Empty until
    // bound in main_dgb; consumed by the ShareAccept mint path when a
    // submitted username carries no valid payout address.
    mutable std::mutex          fallback_payout_mutex_;
    FallbackPayoutFn            fallback_payout_fn_;

    // Per-connection coinbase PPLNS-inputs producer (#327/#330 live-wire).
    // Empty until set_pplns_inputs_fn() bound in main_dgb; while empty the
    // per-connection coinbase path returns an empty job (pre-wire behavior).
    mutable std::mutex          pplns_inputs_mutex_;
    PplnsInputsFn               pplns_inputs_fn_;

    // Template cache (filled lazily; invalidated when work_generation_ bumps)
    // Stage 4c populates these.
    mutable std::mutex          template_mutex_;
    // ... cache fields land here in stage 4c
};

}  // namespace dgb::stratum