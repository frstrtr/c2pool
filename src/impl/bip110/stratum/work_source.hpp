// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// bip110::stratum::Bip110WorkSource — concrete core::stratum::IWorkSource for
// c2pool-bip110 M2 (MINEABLE). Bridges the coin-agnostic core::StratumServer to
// the BIP-110 BLAKE2b Stratum-v1 work-shape (src/impl/bip110/stratum/
// pseudoheader.hpp), the mapping stock Sia BLAKE2b ASICs already speak and the
// one the Knots DATUM Gateway reference bridge uses.
//
// Scope (M2): coinbase-ONLY templates (txs=[], fees=0, coinbasevalue==subsidy
// exact) built on top of the M1 daemonless BLAKE2b header-follower's HeaderChain.
// Serves work, validates submitted shares with an independent BLAKE2b recompute
// (never trusts a miner-reported hash), and on a block-target hit reassembles the
// 164-byte v2 header || varint(txcount) || coinbase and dispatches it via
// submit_block_fn (bip110 p2p submit_block_raw to fork peers). Mempool tx-serving
// + full p2pool-v36 BIP-110 sharechain participation (create_share_fn) are M3;
// the create_share_fn seam exists here but is left unset in M2 (degraded mode,
// exactly as c2pool-btc bootstrapped) — a scoped, stated limitation (R6), not a
// good-citizen omission of anything the chain needs to accept the block.
//
// PER-COIN ISOLATION: lives under src/impl/bip110/, pulls in only the lane-local
// pseudoheader/pow pipeline + the bip110 HeaderChain. No other lane is touched.

#include <core/stratum_work_source.hpp>
#include <core/uint256.hpp>

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "pseudoheader.hpp"

namespace bip110::coin { class HeaderChain; }

namespace bip110::stratum {

class Bip110WorkSource : public core::stratum::IWorkSource
{
public:
    // Dispatch a reassembled block (164-byte v2 header || varint || coinbase) to
    // the network. Returns true iff it reached at least one sink (fork-peer P2P
    // relay and/or Knots submitblock RPC fallback). main_bip110.cpp wires this.
    using SubmitBlockFn = std::function<bool(const std::vector<unsigned char>& block_bytes,
                                             uint32_t height)>;

    // Sharechain WRITE seam (M3). Called when a share meets sharechain (not
    // block) target. Left unset in M2 => shares are validated + counted but not
    // minted into a p2pool sharechain. Returns the share hash or uint256::ZERO.
    //
    // M3 SEAM PARITY (btc reference, main_btc.cpp:2215-2345): the mint must pay
    // the SUBMITTING miner, so the connection's payout_script — the same bytes
    // build_connection_coinbase() baked into this job's coinbase outputs — is
    // handed to the share builder. bip110's freeze (keyed by h2) now carries the
    // payout_script alongside the coinbase so it is recoverable at submit time
    // without re-deriving it from the coinbase outputs. Left unset in M2/M3-seam:
    // installing the fn requires the bip110 sharechain lane (share_types/share/
    // share_check/share_tracker/pool node — the ~10k-line btc-family port, still
    // absent on this branch), so shares are validated + counted but not minted.
    using CreateShareFn = std::function<uint256(
        const std::vector<unsigned char>& full_coinbase,
        const std::vector<unsigned char>& header_164b,
        const std::vector<unsigned char>& payout_script,
        const core::stratum::JobSnapshot&  job)>;

    Bip110WorkSource(bip110::coin::HeaderChain& chain,
                     bool is_testnet,
                     SubmitBlockFn submit_fn,
                     core::stratum::StratumConfig config = {});
    ~Bip110WorkSource() override;

    Bip110WorkSource(const Bip110WorkSource&)            = delete;
    Bip110WorkSource& operator=(const Bip110WorkSource&) = delete;

    // ── IWorkSource: config + read-only state ────────────────────────────
    const core::stratum::StratumConfig& get_stratum_config() const override { return config_; }
    std::function<uint256()>            get_best_share_hash_fn() const override;
    std::string                         get_current_gbt_prevhash() const override;
    uint64_t                            get_work_generation() const override { return work_generation_.load(); }
    bool                                has_merged_chain(uint32_t) const override { return false; }

    // ── IWorkSource: per-connection bookkeeping ──────────────────────────
    void register_stratum_worker(const std::string& id, const core::stratum::WorkerInfo& info) override;
    void unregister_stratum_worker(const std::string& id) override;
    void update_stratum_worker(const std::string& id, double hr, double dead, double diff,
                               uint64_t acc, uint64_t rej, uint64_t stale) override;

    // ── IWorkSource: work generation ─────────────────────────────────────
    nlohmann::json                       get_current_work_template() const override;
    std::vector<std::string>             get_stratum_merkle_branches() const override { return {}; }
    std::pair<std::string, std::string>  get_coinbase_parts() const override { return {"", ""}; }
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

    // ── IWorkSource: atomic state + PoW ──────────────────────────────────
    uint32_t get_share_bits() const override     { return share_bits_.load(); }
    uint32_t get_share_max_bits() const override { return share_max_bits_.load(); }
    double compute_share_difficulty(
        const std::string& coinb1, const std::string& coinb2,
        const std::string& extranonce1, const std::string& extranonce2,
        const std::string& ntime, const std::string& nonce,
        uint32_t version, const std::string& prevhash_hex,
        const std::string& nbits_hex,
        const std::vector<std::string>& merkle_branches) const override;

    // ── BIP-110 control surface (main_bip110.cpp) ────────────────────────
    void bump_work_generation() { work_generation_.fetch_add(1, std::memory_order_relaxed); }
    void set_share_target(uint32_t bits, uint32_t max_bits)
    { share_bits_.store(bits); share_max_bits_.store(max_bits); }
    void set_donation_script(std::vector<unsigned char> s) { donation_script_ = std::move(s); }
    // Node-owner fee destination. When empty the node-owner fee (if any) is paid
    // to the donation script (single-key consolidation, our 13zQ/bc1qyr94… key).
    void set_node_owner_script(std::vector<unsigned char> s) { node_owner_script_ = std::move(s); }
    // Author/dev donation as parts-per-million of the coinbase value (0.1% =
    // 1000 ppm). Default 0.1% is applied by the caller (main_bip110 / catalog
    // defaults); 0 => no author donation (miner keeps it). Integer floor split.
    void set_give_author_ppm(uint64_t ppm) { give_author_ppm_ = ppm; }
    // Node-owner fee as parts-per-million of the coinbase value (1% = 10000 ppm).
    // Default 0 => no node-owner output. Integer floor split.
    void set_node_owner_fee_ppm(uint64_t ppm) { node_owner_fee_ppm_ = ppm; }
    void set_create_share_fn(CreateShareFn fn) { create_share_fn_ = std::move(fn); }

private:
    // Recompute the PoW from a submit tuple by rebuilding the 164-byte header from
    // the h2-keyed freeze. Returns false if the job's freeze is unknown/expired.
    bool recompute_pow(const std::string& coinb1,
                       const std::string& extranonce1, const std::string& extranonce2,
                       const std::string& ntime, const std::string& nonce,
                       uint256& pow_out, std::vector<unsigned char>& header_out,
                       HeaderFreeze& freeze_out) const;

    // Coinbase-only next-block parameters read atomically from the M1 chain tip.
    struct NextWork {
        bool     ok{false};
        uint256  prev;            // internal order (== tip block hash)
        uint32_t height{0};
        uint32_t nbits{0};
        uint32_t curtime{0};
        uint64_t subsidy{0};
        uint32_t version{0xA0000000u};
    };
    NextWork next_work() const;

    bip110::coin::HeaderChain&   chain_;
    const bool                   is_testnet_;
    SubmitBlockFn                submit_block_fn_;
    core::stratum::StratumConfig config_;

    std::atomic<uint64_t>        work_generation_{1};
    std::atomic<uint32_t>        share_bits_{0};
    std::atomic<uint32_t>        share_max_bits_{0};

    std::vector<unsigned char>   donation_script_;     // author/dev donation destination
    std::vector<unsigned char>   node_owner_script_;   // node-owner fee destination (empty => == donation)
    uint64_t                     give_author_ppm_{0};  // author donation, ppm of coinbasevalue (0.1% = 1000)
    uint64_t                     node_owner_fee_ppm_{0};// node-owner fee, ppm of coinbasevalue (1% = 10000)
    CreateShareFn                create_share_fn_;

    mutable std::mutex           workers_mutex_;
    std::map<std::string, core::stratum::WorkerInfo> workers_;

    // h2-keyed freeze-map. TTL >= 360s (> core JOB_TTL 300s) so a share arriving
    // near the tail of a job's core-side lifetime still resolves (R5).
    // coinbase       = NON-witness serialization (txid/merkle/share source).
    // coinbase_block = BIP144 witness serialization for the BLOCK BODY (carries
    //                  the 1x32-byte witness reserved value the commitment output
    //                  requires; == coinbase when no commitment). See DEFECT 1.
    // payout_script = the submitting connection's payout destination, captured
    // at build_connection_coinbase() time so the M3 mint (create_share_fn_) can
    // pay the miner without re-parsing the frozen coinbase outputs (btc parity).
    struct FreezeEntry { HeaderFreeze freeze; std::vector<unsigned char> coinbase; std::vector<unsigned char> coinbase_block; std::vector<unsigned char> payout_script; std::chrono::steady_clock::time_point at; };
    mutable std::mutex           freeze_mutex_;
    mutable std::map<std::string, FreezeEntry> freeze_map_;   // key = hex(h2)
    static constexpr std::chrono::seconds FREEZE_TTL{360};
    void gc_freezes() const;
};

}  // namespace bip110::stratum
