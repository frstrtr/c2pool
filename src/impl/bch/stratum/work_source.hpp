#pragma once

// bch::stratum::BCHWorkSource — concrete `core::stratum::IWorkSource`
// implementation for c2pool-bch.
//
// Responsibility: bridge the coin-agnostic `core::StratumServer` (TCP,
// JSON-RPC, sessions, vardiff, rate monitor) to BCH-specific work
// generation + share validation. Produces stratum jobs from the local
// header chain + mempool via `bch::coin::TemplateBuilder::build_template`,
// validates submitted shares with SHA256d PoW (BCH shares the BTC PoW
// family), and dispatches mainnet-hit blocks to the won-block submit
// callback wired in main_bch.cpp (embedded P2P relay + BCHN-RPC
// submitblock fallback — fallback ALWAYS retained per the BCH lane law).
//
// BCH divergences vs the BTC work source (kept transparent here):
//   - NO SegWit: coinbase has no witness commitment; share/header math is
//     non-witness throughout. mining_submit's coinbase reconstruction is
//     coinb1||en1||en2||coinb2 only.
//   - CashTokens (CHIP-2022-02) ride through unchanged: token-prefixed
//     outputs are carried by build_template's mempool slice verbatim; the
//     work source never inspects or rewrites them (M1 §4 transparent-carry).
//   - ABLA dynamic block-size budget (CHIP-2023-01) is owned by the
//     embedded daemon / TemplateBuilder; the work source consumes whatever
//     template size the builder hands back.
//   - ASERT DAA governs header-accept, not share/PoW target selection here.
//
// Lifetime: holds non-owning references to `HeaderChain` and `Mempool`
// — main_bch.cpp owns those for the process lifetime, BCHWorkSource is
// constructed after them and destroyed before. The submit-block callback
// captures whatever upstream state it needs (typically a coin_node ref +
// pending_submits map).
//
// Threading: `core::StratumServer` runs on its own io_context; methods
// here may be invoked from any thread serviced by it. Internal
// synchronisation:
//   - `work_generation_`, `share_bits_`, `share_max_bits_` are atomics
//   - `workers_` is guarded by `workers_mutex_`
//   - the template cache is guarded by `template_mutex_`
//   - `chain_` and `mempool_` have their own internal locking
//
// What's deliberately MVP-incomplete in this commit (Stage a skeleton):
//   - All work-generation / submit methods return defaults or empty
//     results. Subsequent G2 sub-slices (b/c/d) implement the read-only
//     getters, the work assembly off TemplateBuilder, and the
//     share-validation hot path, then wire StratumServer into
//     standup_pool_run + main_bch.cpp --pool serve mode.
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
namespace bch::coin {
class HeaderChain;
class Mempool;
namespace rpc { struct WorkData; }
}  // namespace bch::coin

namespace bch::stratum {

class BCHWorkSource : public core::stratum::IWorkSource
{
public:
    /// Callback invoked when `mining_submit` validates a submission whose
    /// SHA256d PoW meets BCH mainnet difficulty. main_bch.cpp wires this
    /// to a lambda that broadcasts the won block over BOTH legs (embedded
    /// P2P relay + BCHN-RPC submitblock fallback) via the leg-guarded
    /// dual-broadcast path. Raw-bytes form keeps BCHWorkSource decoupled
    /// from the BlockType serialization details.
    /// Returns true iff the won block reached at least one network sink
    /// (P2P relay or submitblock RPC fallback). A false return means it
    /// reached NEITHER and the won-block path logs a loud error.
    using SubmitBlockFn = std::function<bool(const std::vector<unsigned char>& block_bytes,
                                             uint32_t height)>;

    /// PPLNS payout query: walks back N shares from prev_share_hash and
    /// returns {payout_script_bytes -> satoshi_amount}. main_bch.cpp wires
    /// this to a lambda that calls the share tracker's v35 expected-payout
    /// walk under a read guard. Caller responsibility: apply finder fee
    /// (subsidy/200 to the miner's payout, deducted from donation).
    /// Returning an empty map means the share tracker isn't ready yet
    /// (cold start, no chain) — we then fall back to a single-output
    /// coinbase (full subsidy -> miner) and skip the OP_RETURN.
    using PplnsFn = std::function<std::map<std::vector<unsigned char>, double>(
        const uint256& best_share_hash,
        const uint256& block_target,
        uint64_t subsidy,
        const std::vector<unsigned char>& donation_script)>;

    /// Computes the ref_hash AND walks the share tracker for all
    /// chain-derived values needed to populate snap.frozen_ref. Mirrors
    /// the BTC/LTC RefHashFn contract: returns the full
    /// `core::stratum::RefHashResult` so create_local_share can override
    /// its in-function compute_share_target safely (has_frozen=true), and
    /// the work source updates its share_bits_/share_max_bits_ atomics so
    /// stratum_server's pool_difficulty gate becomes non-zero.
    using RefHashFn = std::function<core::stratum::RefHashResult(
        const uint256& prev_share_hash,
        const std::vector<unsigned char>& coinbase_scriptSig,
        const std::vector<unsigned char>& payout_script,
        uint64_t subsidy, uint32_t block_bits, uint32_t timestamp)>;

    /// Sharechain WRITE path. Called from mining_submit when a share's
    /// SHA256d PoW meets sharechain (not block) target. main_bch.cpp wires
    /// this to a lambda that try-locks the tracker, builds a v36 BCH share
    /// via bch::create_local_share(), tracker.add()s it, and on success
    /// broadcasts the share hash to peers + bumps local best so miners get
    /// fresh work tied to our new tip.
    ///
    /// Returns the share hash on success, uint256::ZERO on failure
    /// (tracker busy, PoW recheck failed, prev_share unknown, etc.).
    ///
    /// The full_coinbase is the reconstructed coinb1||en1||en2||coinb2
    /// (BCH non-witness form — txid math). The header_80b is the 80-byte
    /// block header bytes from mining_submit's classification step.
    using CreateShareFn = std::function<uint256(
        const std::vector<unsigned char>& full_coinbase,
        const std::vector<uint8_t>&        header_80b,
        const core::stratum::JobSnapshot&  job,
        const std::vector<unsigned char>& payout_script)>;

    BCHWorkSource(bch::coin::HeaderChain&       chain,
                  bch::coin::Mempool&           mempool,
                  bool                          is_testnet,
                  SubmitBlockFn                 submit_fn,
                  core::stratum::StratumConfig  config = {});
    ~BCHWorkSource() override;

    BCHWorkSource(const BCHWorkSource&)            = delete;
    BCHWorkSource& operator=(const BCHWorkSource&) = delete;

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

    // ── IWorkSource: per-coin PoW (BCH = SHA256d, same family as BTC) ─────
    double compute_share_difficulty(
        const std::string& coinb1, const std::string& coinb2,
        const std::string& extranonce1, const std::string& extranonce2,
        const std::string& ntime, const std::string& nonce,
        uint32_t version, const std::string& prevhash_hex,
        const std::string& nbits_hex,
        const std::vector<std::string>& merkle_branches) const override;

    // ── BCH-specific control surface (called from main_bch.cpp) ──────────

    /// Increment work_generation. Called when the BCH tip moves
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
    /// hash. Called once at startup from main_bch.cpp after ShareTracker
    /// is constructed.
    void set_best_share_hash_fn(std::function<uint256()> fn);

    /// Wire the PPLNS payout-map producer. Called once at startup. May be
    /// left unset, in which case build_connection_coinbase falls back to
    /// a single-output coinbase paying the full subsidy to the miner
    /// (degraded mode — no c2pool sharechain participation but valid BCH
    /// blocks still produced).
    void set_pplns_fn(PplnsFn fn);

    /// Wire the ref_hash producer. Called once at startup. May be left
    /// unset; in that case the coinbase OP_RETURN is omitted (degraded
    /// mode, but coinbase still valid for BCH).
    void set_ref_hash_fn(RefHashFn fn);

    /// Wire the share-create callback (sharechain WRITE path). Called once
    /// at startup. May be left unset — mining_submit then logs accepted
    /// shares but doesn't add them to the tracker, leaving c2pool-bch as
    /// a stratum proxy without sharechain participation.
    void set_create_share_fn(CreateShareFn fn);

    /// Set the donation script (bytes of the c2pool donation
    /// scriptPubKey). For v36 BCH this is the version-gated COMBINED P2SH
    /// (1-of-2 forrestv+maintainer) for sv>=36 shares. Used by
    /// build_connection_coinbase as the residual recipient of any
    /// payout-rounding remainder, plus added to the PPLNS map so it always
    /// appears as an output.
    void set_donation_script(std::vector<unsigned char> script);

    /// Wire the author-version producer: returns the sharechain-tip version the
    /// next locally-authored share is stamped at (mirrors pool_entrypoint\x27s
    /// create_ver derivation off the tip). build_connection_coinbase uses it to
    /// gate the pre-v36 finder-fee shape. Left unset => v36-pure (no finder fee).
    void set_author_version_fn(std::function<int64_t()> fn);

private:
    // External dependencies (non-owning references)
    bch::coin::HeaderChain&     chain_;
    bch::coin::Mempool&         mempool_;
    const bool                  is_testnet_;

    // Submission dispatch
    SubmitBlockFn               submit_block_fn_;

    // Config (held by value; const after construction in MVP)
    core::stratum::StratumConfig config_;

    // Atomic state
    std::atomic<uint64_t>       work_generation_{0};
    // mutable so build_connection_coinbase (const) can refresh them from
    // ref_hash_fn's tracker.compute_share_target result.
    mutable std::atomic<uint32_t>       share_bits_{0};
    mutable std::atomic<uint32_t>       share_max_bits_{0};

    // Worker registry (per-connection metadata)
    mutable std::mutex          workers_mutex_;
    std::map<std::string, core::stratum::WorkerInfo> workers_;

    // Best-share callback (from ShareTracker)
    mutable std::mutex          best_share_mutex_;
    std::function<uint256()>    best_share_hash_fn_;

    // PPLNS + ref_hash + share-create callbacks (from ShareTracker via main_bch.cpp)
    mutable std::mutex          callback_mutex_;
    PplnsFn                     pplns_fn_;
    RefHashFn                   ref_hash_fn_;
    CreateShareFn               create_share_fn_;
    std::vector<unsigned char>  donation_script_;
    std::function<int64_t()>    author_version_fn_;

    // Template cache (filled lazily; invalidated when work_generation_ bumps)
    // Stage c populates these.
    mutable std::mutex          template_mutex_;
    // tx_data memo (single slot, guarded by template_mutex_): the per-job
    // tx-hex vector and a fingerprint over its merkle leaf set, so repeat
    // build_connection_coinbase calls against an unchanged tx set reuse the
    // shared_ptr instead of re-serializing the mempool.
    mutable uint256                                     tx_data_fp_;
    mutable std::shared_ptr<std::vector<std::string>>   tx_data_memo_;

    // ── Template cache (slice-c) ─────────────────────────────────────────
    // Single-slot memo of TemplateBuilder::build_template, keyed on
    // (work_generation_, chain tip block_hash). BCH Mempool exposes no
    // epoch/seq counter (unlike btc), so cache freshness rides on: a tip
    // move bumps work_generation_ via the new-headers hook, and an explicit
    // bump_work_generation() invalidates on a mempool roll. The tip-hash
    // key is a belt-and-suspenders guard so a tip change always rebuilds
    // even if a bump was missed. Guarded by template_mutex_.
    mutable std::shared_ptr<const bch::coin::rpc::WorkData> template_cache_;
    mutable uint64_t template_cache_gen_{~0ull};
    mutable uint256  template_cache_tip_{};

    // Build-or-reuse the current BCH work template (read-only over chain_ +
    // mempool_ via TemplateBuilder). Returns nullptr if the header chain has
    // no tip yet (pre-IBD / uninitialized).
    std::shared_ptr<const bch::coin::rpc::WorkData> cached_template() const;
};

}  // namespace bch::stratum
