#pragma once

// IWorkSource — abstract interface that decouples `core::StratumServer`
// (the protocol layer: TCP, JSON-RPC, session lifecycle, vardiff,
// rate-monitor) from the coin-specific work-generation + share-validation
// logic. Single source of truth for the stratum server: LTC's
// `core::MiningInterface` and BTC's `btc::stratum::BTCWorkSource` both
// implement this interface, and a single `core::StratumServer` instance
// drives either via virtual dispatch.
//
// Extraction history: prior to 2026-05, `core::StratumServer` held a
// `std::shared_ptr<core::MiningInterface>` (concrete LTC class) and
// invoked 13 non-virtual methods plus accessed two `std::atomic<uint32_t>`
// members directly. This made the entire stratum protocol layer
// LTC-only. The B4-stratum work introduced this interface as the
// minimum surface area covering every call site (verified by
// exhaustive grep of `mining_interface_->*` in stratum_server.cpp).
//
// Performance: every method on this interface is reached via virtual
// dispatch (~1 ns per call). For the hot paths — `mining_submit` is
// called once per share submission (3-30 Hz typical), the others
// once per job issue — this is well below the floor of meaningful
// overhead. No path is in a tight inner loop.
//
// Threading: implementors must guarantee internal synchronisation.
// `core::StratumServer` runs on a dedicated `boost::asio::io_context`
// and may invoke methods from any thread serviced by that context
// (typically one thread, but configurable). Implementors that share
// state with other subsystems (block templates, sharechain) must use
// their own mutexes/atomics.

#include <core/stratum_types.hpp>
#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace core::stratum {

class IWorkSource {
public:
    virtual ~IWorkSource() = default;

    // ── Config + read-only state ─────────────────────────────────────────
    // Called frequently from the stratum loop; kept lightweight by impls.

    /// Vardiff bounds + target share rate + coinbase output cap.
    /// Reference must remain valid for the lifetime of the work source;
    /// the server caches no copy and re-reads each time.
    virtual const StratumConfig& get_stratum_config() const = 0;

    /// Returns a callable that yields the current best-share hash from
    /// the share tracker. May be empty (`!fn`) if no share tracker is
    /// wired yet — the server then falls back to the GBT prevhash.
    virtual std::function<uint256()> get_best_share_hash_fn() const = 0;

    /// Current GBT-format previousblockhash (the BTC/LTC tip the pool is
    /// mining on top of), in BE display-hex form (matches what miners
    /// receive in `mining.notify`'s prevhash field). Used as a fallback
    /// when the best-share fn is unset and as the basis for `clean_jobs`
    /// detection.
    virtual std::string get_current_gbt_prevhash() const = 0;

    /// Monotonic counter that bumps on every template refresh. The server
    /// uses it to detect stale work between job-push timer firings without
    /// snapshotting full template state.
    virtual uint64_t get_work_generation() const = 0;

    /// True if the work source has merged-mining state for the given
    /// chain id. BTC MVP returns false unconditionally.
    virtual bool has_merged_chain(uint32_t chain_id) const = 0;

    // ── Per-connection bookkeeping ───────────────────────────────────────
    // Lifecycle: register on authorize, update each share, unregister on
    // disconnect. All keyed by stratum session_id.

    virtual void register_stratum_worker(const std::string& session_id,
                                         const WorkerInfo& info) = 0;
    virtual void unregister_stratum_worker(const std::string& session_id) = 0;
    virtual void update_stratum_worker(const std::string& session_id,
                                       double hashrate, double dead_hashrate,
                                       double difficulty,
                                       uint64_t accepted, uint64_t rejected,
                                       uint64_t stale) = 0;

    // ── Work generation ──────────────────────────────────────────────────
    // Called per-job-issue (when sending mining.notify). Implementors
    // must produce a snapshot consistent with their template state at
    // call time — the stratum session freezes the result into a JobEntry.

    /// Current full block template as JSON (legacy GBT-shaped). The
    /// stratum session reads `previousblockhash`, `bits`, `version`,
    /// `curtime`/`mintime`, etc. for header construction.
    virtual nlohmann::json get_current_work_template() const = 0;

    /// Stratum-format merkle branches (excludes coinbase txid; each
    /// branch hex is the natural-byte-order hash a miner needs to
    /// hash-with-coinbase-then-up to reach the merkle root).
    virtual std::vector<std::string> get_stratum_merkle_branches() const = 0;

    /// Cached fallback coinbase split for `mining.notify` when the
    /// per-connection builder isn't applicable. Returns (coinb1, coinb2)
    /// with the extranonce slot expected to be inserted between them.
    virtual std::pair<std::string, std::string> get_coinbase_parts() const = 0;

    /// Build a per-connection coinbase. The work source computes the
    /// p2pool ref_hash for the (prev_share, payout_script, merged_addrs)
    /// triple and produces (coinb1, coinb2) plus a frozen WorkSnapshot
    /// matching the extra outputs it just wrote into the coinbase.
    /// Caller passes the prev_share_hash to avoid race with a concurrent
    /// best-share update.
    virtual CoinbaseResult build_connection_coinbase(
        const uint256& prev_share_hash,
        const std::string& extranonce1_hex,
        const std::vector<unsigned char>& payout_script,
        const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& merged_addrs) const = 0;

    // ── Share submission (the hot path) ──────────────────────────────────

    /// Process a `mining.submit` from a stratum session. Validates the
    /// (extranonce1, extranonce2, ntime, nonce) tuple against the frozen
    /// JobSnapshot, computes the PoW hash, classifies the result:
    ///   - PoW ≤ block target  → submit to coin daemon (B5 path for BTC)
    ///   - PoW ≤ share target  → record share in tracker
    ///   - otherwise            → reject as low-difficulty
    /// Returns the JSON-RPC response payload (`true` for accepted, or
    /// `[code, message, null]` for rejection).
    /// `job` may be null for legacy callers; modern stratum sessions
    /// always pass a frozen snapshot to avoid template-rolling races.
    virtual nlohmann::json mining_submit(
        const std::string& username, const std::string& job_id,
        const std::string& extranonce1, const std::string& extranonce2,
        const std::string& ntime, const std::string& nonce,
        const std::string& request_id,
        const std::map<uint32_t, std::vector<unsigned char>>& merged_addresses,
        const JobSnapshot* job) = 0;

    // ── Atomic state read access ─────────────────────────────────────────
    // These replace direct `m_share_bits.load()` / `m_share_max_bits.load()`
    // member access in the prior LTC-coupled stratum_server.cpp. Implementors
    // back them with std::atomic so reads are wait-free; the virtual
    // indirection adds ~1 ns. Only reads — writes happen inside the
    // implementor when its template refreshes.

    /// Current share-target bits (compact-target encoding) the server
    /// will set as `nbits` in mining.notify. Matches the difficulty
    /// the miner must beat for the submission to count as a share.
    virtual uint32_t get_share_bits() const = 0;

    /// Maximum share-target bits — the easiest the share target can be
    /// at the moment. Used to validate stale jobs and detect retarget
    /// transitions.
    virtual uint32_t get_share_max_bits() const = 0;

    /// Compute the share difficulty for a stratum submission. The
    /// per-coin PoW hash function (scrypt for LTC, SHA256d for BTC,
    /// X11/Quark/etc. for future ports) is encapsulated here — the
    /// stratum server invokes this rather than calling a hardcoded
    /// scrypt function. The returned difficulty is "diff 1 / pow_hash"
    /// in standard Bitcoin convention. Returns 0.0 on parse error.
    ///
    /// Without this, a coin-agnostic stratum server can't validate
    /// pseudoshares from miners using a different PoW than the
    /// implementor's default — every submission gets garbage diff and
    /// rejects at the vardiff gate.
    virtual double compute_share_difficulty(
        const std::string& coinb1, const std::string& coinb2,
        const std::string& extranonce1, const std::string& extranonce2,
        const std::string& ntime, const std::string& nonce,
        uint32_t version, const std::string& prevhash_hex,
        const std::string& nbits_hex,
        const std::vector<std::string>& merkle_branches) const = 0;
};

}  // namespace core::stratum
