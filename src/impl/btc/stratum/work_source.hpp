#pragma once

// btc::stratum::BTCWorkSource — concrete `core::stratum::IWorkSource`
// implementation for c2pool-btc.
//
// Responsibility: bridge the coin-agnostic `core::StratumServer` (TCP,
// JSON-RPC, sessions, vardiff, rate monitor) to BTC-specific work
// generation + share validation. Produces stratum jobs from the local
// header chain + mempool via `btc::coin::TemplateBuilder::build_template`,
// validates submitted shares with SHA256d PoW, and dispatches mainnet-hit
// blocks to the B5 submit_block_p2p callback wired in main_btc.cpp.
//
// Lifetime: holds non-owning references to `HeaderChain` and `Mempool`
// — main_btc.cpp owns those for the process lifetime, BTCWorkSource is
// constructed after them and destroyed before. The submit-block callback
// captures whatever upstream state it needs (typically a coin_node ref +
// pending_submits map from B5).
//
// Threading: `core::StratumServer` runs on its own io_context; methods
// here may be invoked from any thread serviced by it. Internal
// synchronisation:
//   - `work_generation_`, `share_bits_`, `share_max_bits_` are atomics
//   - `workers_` is guarded by `workers_mutex_`
//   - the template cache is guarded by `template_mutex_`
//   - `chain_` and `mempool_` have their own internal locking
//
// What's deliberately MVP-incomplete in this commit (Stage 4a skeleton):
//   - All work-generation / submit methods return defaults or empty
//     results. Subsequent sub-stages (4b/4c/4d) implement the read-only
//     getters, the work assembly, and the share-validation hot path.
//   - No vardiff feedback loop yet — `update_stratum_worker` records but
//     doesn't yet drive set_difficulty back to sessions.

#include <core/stratum_work_source.hpp>
#include <core/uint256.hpp>

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

// Forward declarations — heavy headers live in the .cpp.
namespace btc::coin {
class HeaderChain;
class Mempool;
}  // namespace btc::coin

namespace btc::stratum {

class BTCWorkSource : public core::stratum::IWorkSource
{
public:
    /// Callback invoked when `mining_submit` validates a submission whose
    /// SHA256d PoW meets BTC mainnet difficulty. main_btc.cpp wires this
    /// to a lambda that calls `coin_node.get_p2p()->submit_block_raw(bytes)`
    /// + adds to the B5 pending_submits map. Raw-bytes form keeps
    /// BTCWorkSource decoupled from the BlockType serialization details.
    using SubmitBlockFn = std::function<void(const std::vector<unsigned char>& block_bytes,
                                             uint32_t height)>;

    /// PPLNS payout query: walks back N shares from prev_share_hash and
    /// returns {payout_script_bytes → satoshi_amount}. main_btc.cpp wires
    /// this to a lambda that calls
    /// `p2p_node->tracker().get_v35_expected_payouts(...)` under a
    /// TrackerReadGuard. Caller responsibility: apply finder fee
    /// (subsidy/200 to the miner's payout, deducted from donation).
    /// Returning an empty map means the share tracker isn't ready yet
    /// (cold start, no chain) — we then fall back to a single-output
    /// coinbase (full subsidy → miner) and skip the OP_RETURN.
    using PplnsFn = std::function<std::map<std::vector<unsigned char>, double>(
        const uint256& best_share_hash,
        const uint256& block_target,
        uint64_t subsidy,
        const std::vector<unsigned char>& donation_script)>;

    /// p2pool ref_hash computation: takes the share's identity fields and
    /// produces (ref_hash, last_txout_nonce). The ref_hash is embedded in
    /// the coinbase OP_RETURN; the nonce is REPLACED by the miner's
    /// extranonce1+extranonce2 (8 bytes total) at submit time, so the
    /// returned nonce is just a placeholder for hash_link prefix
    /// computation. main_btc.cpp wires this to a lambda calling
    /// btc::compute_ref_hash_for_work.
    using RefHashFn = std::function<std::pair<uint256, uint64_t>(
        const uint256& prev_share_hash,
        const std::vector<unsigned char>& coinbase_scriptSig,
        const std::vector<unsigned char>& payout_script,
        uint64_t subsidy, uint32_t bits, uint32_t timestamp)>;

    /// Sharechain WRITE path. Called from mining_submit when a share's
    /// SHA256d PoW meets sharechain (not block) target. main_btc.cpp wires
    /// this to a lambda that:
    ///   1. Acquires `unique_lock(p2p_node->tracker_mutex(), try_to_lock)`
    ///      — non-blocking; returns uint256::ZERO if compute thread busy
    ///   2. Calls btc::create_local_share() (templated on TrackerT) which
    ///      builds a v35 PaddingBugfixShare and tracker.add()s it
    ///   3. On non-zero return, calls p2p_node->broadcast_share(hash)
    ///      to announce to peers + notify_local_share(hash) to bump
    ///      local best so miners get fresh work tied to our new tip
    ///
    /// Returns the share hash on success, uint256::ZERO on failure
    /// (tracker busy, PoW recheck failed, prev_share unknown, etc.).
    /// mining_submit reports either share-accepted with the hash or
    /// share-deferred to the miner.
    ///
    /// The full_coinbase is the reconstructed coinb1||en1||en2||coinb2
    /// (non-witness form — txid math). The header_80b is the 80-byte
    /// block header bytes from mining_submit's classification step.
    using CreateShareFn = std::function<uint256(
        const std::vector<unsigned char>& full_coinbase,
        const std::vector<uint8_t>&        header_80b,
        const core::stratum::JobSnapshot&  job,
        const std::vector<unsigned char>& payout_script)>;

    BTCWorkSource(btc::coin::HeaderChain&       chain,
                  btc::coin::Mempool&           mempool,
                  bool                          is_testnet,
                  SubmitBlockFn                 submit_fn,
                  core::stratum::StratumConfig  config = {});
    ~BTCWorkSource() override;

    BTCWorkSource(const BTCWorkSource&)            = delete;
    BTCWorkSource& operator=(const BTCWorkSource&) = delete;

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

    // ── IWorkSource: atomic state ────────────────────────────────────────
    uint32_t get_share_bits() const override     { return share_bits_.load(); }
    uint32_t get_share_max_bits() const override { return share_max_bits_.load(); }

    // ── BTC-specific control surface (called from main_btc.cpp) ──────────

    /// Increment work_generation. Called when the bitcoind tip moves
    /// (new_headers fires) or when sharechain tip moves. Triggers stratum
    /// sessions to re-push work on their next heartbeat.
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
    /// hash. Called once at startup from main_btc.cpp after ShareTracker
    /// is constructed.
    void set_best_share_hash_fn(std::function<uint256()> fn);

    /// Wire the PPLNS payout-map producer. Called once at startup. May be
    /// left unset, in which case build_connection_coinbase falls back to
    /// a single-output coinbase paying the full subsidy to the miner
    /// (degraded mode — no c2pool sharechain participation but valid BTC
    /// blocks still produced).
    void set_pplns_fn(PplnsFn fn);

    /// Wire the ref_hash producer. Called once at startup. May be left
    /// unset; in that case the coinbase OP_RETURN is omitted (degraded
    /// mode, but coinbase still valid for BTC).
    void set_ref_hash_fn(RefHashFn fn);

    /// Wire the share-create callback (sharechain WRITE path). Called once
    /// at startup. May be left unset — mining_submit then logs accepted
    /// shares but doesn't add them to the tracker, leaving c2pool-btc as
    /// a stratum proxy without sharechain participation.
    void set_create_share_fn(CreateShareFn fn);

    /// Set the donation script (bytes of the c2pool donation
    /// scriptPubKey — typically a P2PKH or P2WPKH for the c2pool donation
    /// address). Used by build_connection_coinbase as the residual
    /// recipient of any payout-rounding remainder, plus added to the
    /// PPLNS map so it always appears as an output.
    void set_donation_script(std::vector<unsigned char> script);

private:
    // External dependencies (non-owning references)
    btc::coin::HeaderChain&     chain_;
    btc::coin::Mempool&         mempool_;
    const bool                  is_testnet_;

    // Submission dispatch
    SubmitBlockFn               submit_block_fn_;

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

    // PPLNS + ref_hash + share-create callbacks (from ShareTracker via main_btc.cpp)
    mutable std::mutex          callback_mutex_;
    PplnsFn                     pplns_fn_;
    RefHashFn                   ref_hash_fn_;
    CreateShareFn               create_share_fn_;
    std::vector<unsigned char>  donation_script_;

    // Template cache (filled lazily; invalidated when work_generation_ bumps)
    // Stage 4c populates these.
    mutable std::mutex          template_mutex_;
    // ... cache fields land here in stage 4c
};

}  // namespace btc::stratum
