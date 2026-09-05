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

namespace bip110::coin { class HeaderChain; class Mempool; }

namespace bip110::stratum {

// Extract the coinbase scriptSig from a serialized (non-witness) coinbase tx.
// The share's m_coinbase field is the coinbase *scriptSig* (share_init_verify
// bounds it to 2..100 bytes), NOT the whole coinbase transaction — so the M3
// mint path (main_bip110.cpp create_share_fn) slices it here before calling
// bip110::pool::create_local_share. Per-coin copy of the btc/dgb helper
// (btc/stratum/work_source.hpp:75) per the coin-isolation invariant; fail-closed
// (returns {} on any truncation/overrun -> the mint declines on size<2).
inline std::vector<unsigned char>
extract_coinbase_scriptsig(const std::vector<unsigned char>& coinbase_tx) {
    constexpr size_t kScriptOffset = 4 + 1 + 32 + 4;  // version|marker?|prevout(null)|index = 41
    if (coinbase_tx.size() < kScriptOffset + 1)
        return {};
    size_t off = kScriptOffset;
    uint64_t len = coinbase_tx[off++];
    if (len == 0xfd) {
        if (off + 2 > coinbase_tx.size()) return {};
        len = static_cast<uint64_t>(coinbase_tx[off])
            | (static_cast<uint64_t>(coinbase_tx[off + 1]) << 8);
        off += 2;
    } else if (len >= 0xfe) {
        return {};  // implausible for a consensus-capped (<=100B) coinbase scriptSig
    }
    if (off + len > coinbase_tx.size())
        return {};
    return std::vector<unsigned char>(coinbase_tx.begin() + off,
                                      coinbase_tx.begin() + off + len);
}

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
    // PR-B (M3): the 4th arg is the miner payout_script derived in mining_submit
    // from the authorized username (core::address_to_script, donation fallback).
    // create_local_share REQUIRES it to build the share's PPLNS payout identity;
    // BTC's CreateShareFn is likewise 4-arg (main_btc.cpp:2219). Left unset in
    // M2 (default OFF) => shares are validated + counted but not minted.
    using CreateShareFn = std::function<uint256(
        const std::vector<unsigned char>& full_coinbase,
        const std::vector<unsigned char>& header_164b,
        const core::stratum::JobSnapshot&  job,
        const std::vector<unsigned char>& payout_script)>;

    // Sharechain REF-COMMITMENT producer (M3 PR-C, flag-ON only). Given the job's
    // prev_share_hash (the sharechain tip fed by best_share_hash_fn_), the coinbase
    // scriptSig, the miner payout script, the block subsidy/bits/timestamp, returns
    // the p2pool ref_hash + the frozen share fields (absheight/abswork/far/bits/
    // max_bits/timestamp/merged_payout) that create_local_share must reproduce so
    // the OP_RETURN commitment the coinbase carries == the ref_hash a peer recomputes
    // off the minted share (mint==verify). main_bip110.cpp wires this to a lambda
    // that walks the share tracker (near-verbatim port of main_btc.cpp's ref_hash_fn,
    // minus merged-mining — bip110 v36 is single-chain, segwit sentinel constant).
    // Left UNSET in M2 (default OFF) => build_connection_coinbase emits the empty
    // {0x6a,0x00} M2 OP_RETURN and populates no frozen_ref (byte-identical to today).
    // Coinbase-only: no txid_merkle_branches / witness_root / merged blob args (the
    // segwit_data is the SegwitDataDefault none-sentinel, folded in by the lambda).
    using RefHashFn = std::function<core::stratum::RefHashResult(
        const uint256& prev_share_hash,
        const std::vector<unsigned char>& coinbase_scriptSig,
        const std::vector<unsigned char>& payout_script,
        uint64_t subsidy, uint32_t block_bits, uint32_t timestamp)>;

    // Sharechain PPLNS-payout producer (M3 PR-C F1b, flag-ON only). Given the job's
    // prev_share_hash (the sharechain tip) + the BLOCK subsidy + the canonical
    // donation script, returns the {scriptPubKey -> amount} map for the ENTIRE
    // decayed PPLNS window — EXACTLY what the verify SSOT generate_share_transaction
    // (share_check.hpp) reconstructs off the minted share (get_expected_payouts,
    // share_tracker.hpp). main_bip110 wires this to a lambda that, under
    // read_tracker(), calls ShareTracker::get_expected_payouts. build_connection_
    // coinbase consumes the map on the flag-ON path: extracts the donation entry,
    // sorts the miner outputs asc(amount, script), applies the 4000-output cap, and
    // emits them (donation output second-to-last, OP_RETURN ref last) so the minted
    // coinbase == generate_share_transaction byte-for-byte (peers ACCEPT the share).
    // Left UNSET in M2 (default OFF) => build_connection_coinbase keeps the single-
    // miner split (byte-identical to today). Mirrors main_btc.cpp set_pplns_fn.
    using PplnsFn = std::function<std::map<std::vector<unsigned char>, double>(
        const uint256& prev_share_hash, const uint256& block_target,
        uint64_t subsidy, const std::vector<unsigned char>& donation_script)>;

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
    /// #961: mark this node as running on the BIP-110 regtest network so the
    /// payout money-path validates a miner's address against the REGTEST set
    /// (testnet base58 bytes + "bcrt" HRP) instead of mainnet. Address-validation
    /// scope only; called from main under --regtest.
    void set_regtest(bool regtest) { is_regtest_ = regtest; }
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

    // M3 PR-C sharechain wiring (flag-ON only). set from main_bip110 INSIDE the
    // --bip110-sharechain block. When unset (M2 default OFF) the OP_RETURN stays
    // the empty {0x6a,0x00} commitment and no frozen_ref is populated — byte-
    // identical to M2. best_share_hash_fn_ feeds the sharechain tip into the job's
    // prev_share_hash (via get_best_share_hash_fn -> the generic stratum_server
    // seam); ref_hash_fn_ produces the coinbase ref commitment + frozen fields.
    void set_best_share_hash_fn(std::function<uint256()> fn) { best_share_hash_fn_ = std::move(fn); }
    void set_ref_hash_fn(RefHashFn fn) { ref_hash_fn_ = std::move(fn); }
    // M3 PR-C F1b: the PPLNS-distributed coinbase producer (flag-ON only). Set from
    // main_bip110 INSIDE the --bip110-sharechain block alongside set_ref_hash_fn.
    // When unset (M2 default OFF) build_connection_coinbase keeps the single-miner
    // split — byte-identical to M2.
    void set_pplns_fn(PplnsFn fn) { pplns_fn_ = std::move(fn); }

    // ── M3 daemonless mempool tx-serving ─────────────────────────────────
    // Wire the embedded mempool (P2P-ingested, daemonlessly priced) so templates
    // include REAL network txs instead of coinbase-only EMPTY blocks. serve=false
    // keeps the coinbase-only M2 behaviour (canary escape hatch). ready_fn gates
    // serving on the UTXO view being deep enough to price (fail closed to empty
    // when not ready). The work source only ever READS the mempool.
    void set_mempool(bip110::coin::Mempool* mp, bool serve, std::function<bool()> ready_fn)
    { mempool_ = mp; serve_txs_ = serve; utxo_ready_fn_ = std::move(ready_fn); }

    // Lock-safe copy of the per-connection worker registry for the shared
    // dashboard (set_stratum_workers_fn / set_stratum_hashrate_fn on the web
    // MiningInterface). The stratum sessions register/update here (workers_) but
    // nothing bridged it to the WebServer. Mirror of the BTC lane accessor
    // (src/impl/btc/stratum/work_source.hpp) — display-only, never a work path.
    std::map<std::string, core::stratum::WorkerInfo> snapshot_stratum_workers() const
    {
        std::lock_guard<std::mutex> lk(workers_mutex_);
        return workers_;
    }

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
    bool                         is_regtest_ = false;  // #961: --regtest address set
    SubmitBlockFn                submit_block_fn_;
    core::stratum::StratumConfig config_;

    std::atomic<uint64_t>        work_generation_{1};
    // mutable: build_connection_coinbase() is const but freezes the ref's share
    // target into these on the flag-ON path (mirrors btc work_source.hpp:355-356).
    mutable std::atomic<uint32_t> share_bits_{0};
    mutable std::atomic<uint32_t> share_max_bits_{0};

    std::vector<unsigned char>   donation_script_;     // author/dev donation destination
    std::vector<unsigned char>   node_owner_script_;   // node-owner fee destination (empty => == donation)
    uint64_t                     give_author_ppm_{0};  // author donation, ppm of coinbasevalue (0.1% = 1000)
    uint64_t                     node_owner_fee_ppm_{0};// node-owner fee, ppm of coinbasevalue (1% = 10000)
    CreateShareFn                create_share_fn_;

    // M3 PR-C sharechain ref-commitment (flag-ON only; unset in M2). See setters.
    std::function<uint256()>     best_share_hash_fn_;   // sharechain tip -> job.prev_share_hash
    RefHashFn                    ref_hash_fn_;          // coinbase ref_hash + frozen fields
    PplnsFn                      pplns_fn_;             // F1b: PPLNS-distributed coinbase payouts (flag-ON only)

    // M3 mempool tx-serving. Read-only pointer; owned by main_bip110.
    bip110::coin::Mempool*       mempool_{nullptr};
    bool                         serve_txs_{false};
    std::function<bool()>        utxo_ready_fn_;

    mutable std::mutex           workers_mutex_;
    std::map<std::string, core::stratum::WorkerInfo> workers_;

    // h2-keyed freeze-map. TTL >= 360s (> core JOB_TTL 300s) so a share arriving
    // near the tail of a job's core-side lifetime still resolves (R5).
    // coinbase       = NON-witness serialization (txid/merkle/share source).
    // coinbase_block = BIP144 witness serialization for the BLOCK BODY (carries
    //                  the 1x32-byte witness reserved value the commitment output
    //                  requires; == coinbase when no commitment). See DEFECT 1.
    // other_txs      = BIP144 witness-serialized bytes of each non-coinbase tx,
    //                  in block order (the block BODY after the coinbase).
    // other_txids    = SHA256d(non-witness) txid of each, same order (merkle).
    // fee_total      = provable fee sum baked into the coinbase value; the
    //                  pre-serve + submit xchecks re-derive and compare all three
    //                  against the frozen bytes (reward-safety, never trust the
    //                  builder). Empty for a coinbase-only (M2) freeze.
    struct FreezeEntry {
        HeaderFreeze freeze;
        std::vector<unsigned char> coinbase;
        std::vector<unsigned char> coinbase_block;
        std::vector<std::vector<unsigned char>> other_txs;
        std::vector<uint256> other_txids;
        uint64_t fee_total{0};
        std::chrono::steady_clock::time_point at;
    };
    mutable std::mutex           freeze_mutex_;
    mutable std::map<std::string, FreezeEntry> freeze_map_;   // key = hex(h2)
    static constexpr std::chrono::seconds FREEZE_TTL{360};
    void gc_freezes() const;
};

}  // namespace bip110::stratum
