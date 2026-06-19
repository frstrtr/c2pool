// dgb::stratum::DGBWorkSource — Stage 4a skeleton.
//
// All IWorkSource methods are stubbed to safe defaults. Subsequent
// sub-stages flesh them out (mirroring btc::stratum::BTCWorkSource's own
// 4b/4c/4d progression):
//   Stage 4b: read-only getters (config, prevhash, generation, workers)
//   Stage 4c: Scrypt work generation (template, merkle branches, coinbase)
//   Stage 4d: mining_submit hot path (Scrypt PoW classify + won-block dispatch)
//
// The skeleton is intentionally non-functional but compiles, instantiates,
// and lets us validate the StratumServer wiring in main_dgb.cpp end-to-end
// before implementing the substantive logic. DGB validates Scrypt blocks
// only (V36 / project_v36_dgb_scrypt_only); the other four DGB algos are
// accept-by-continuity / V37 and never reach this work source.

#include <impl/dgb/stratum/work_source.hpp>

#include <impl/dgb/coin/header_chain.hpp>
#include <impl/dgb/coin/mempool.hpp>
#include <impl/dgb/coin/embedded_coinbase_value.hpp>

#include <core/log.hpp>

namespace dgb::stratum {

DGBWorkSource::DGBWorkSource(c2pool::dgb::HeaderChain&     chain,
                             dgb::coin::Mempool&           mempool,
                             bool                          is_testnet,
                             SubmitBlockFn                 submit_fn,
                             core::SubsidyFunc             subsidy_func,
                             core::stratum::StratumConfig  config)
    : chain_(chain)
    , mempool_(mempool)
    , is_testnet_(is_testnet)
    , submit_block_fn_(std::move(submit_fn))
    , subsidy_func_(std::move(subsidy_func))
    , config_(std::move(config))
{
    LOG_INFO << "[DGB-STRATUM] DGBWorkSource constructed"
             << " (testnet=" << is_testnet_
             << " min_diff=" << config_.min_difficulty
             << " max_diff=" << config_.max_difficulty
             << " target_time=" << config_.target_time
             << "s vardiff=" << (config_.vardiff_enabled ? "on" : "off")
             << " subsidy_func=" << (subsidy_func_ ? "wired" : "UNSET") << ")";
}

DGBWorkSource::~DGBWorkSource() = default;

// ──────────────────────────────────────────────────────────────────
// Embedded coinbasevalue — first PRODUCTION caller of CoinParams::subsidy_func.
// Delegates to the dgb::coin SSOT (embedded_coinbase_value.hpp) so the embedded
// TemplateBuilder coinbasevalue and the external-daemon GBT coinbasevalue are
// computed from ONE definition and can never silently diverge. The GBT value,
// when present, is authoritative and returned verbatim (external-daemon
// fallback MUST PERSIST); otherwise subsidy_func(height)+fees is derived from
// the DGB oracle decay schedule.
// ──────────────────────────────────────────────────────────────────
uint64_t DGBWorkSource::coinbase_value(uint32_t height, uint64_t total_fees,
                                       std::optional<uint64_t> gbt_coinbasevalue) const
{
    return dgb::coin::resolve_coinbase_value(subsidy_func_, height, total_fees,
                                             gbt_coinbasevalue);
}

// ─────────────────────────────────────────────────────────────────────────────
// IWorkSource: config + read-only state — Stage 4b will fill these in.
// ─────────────────────────────────────────────────────────────────────────────

const core::stratum::StratumConfig& DGBWorkSource::get_stratum_config() const
{
    return config_;
}

std::function<uint256()> DGBWorkSource::get_best_share_hash_fn() const
{
    std::lock_guard<std::mutex> lk(best_share_mutex_);
    return best_share_hash_fn_;  // empty function until set_best_share_hash_fn() called
}

std::string DGBWorkSource::get_current_gbt_prevhash() const
{
    // Stage 4b: read chain_.tip() and return BE-display-hex form.
    return {};
}

uint64_t DGBWorkSource::get_work_generation() const
{
    return work_generation_.load(std::memory_order_relaxed);
}

bool DGBWorkSource::has_merged_chain(uint32_t /*chain_id*/) const
{
    // DGB V36 default build: standalone Scrypt parent, no merged mining.
    // The DGB-as-DOGE-parent dual-parent path (-DAUX_DOGE=ON) is a V36
    // STRETCH, parked behind the shared DOGE-aux settle — not wired here.
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// IWorkSource: per-connection bookkeeping — minimal but real now.
// ─────────────────────────────────────────────────────────────────────────────

void DGBWorkSource::register_stratum_worker(const std::string& session_id,
                                            const core::stratum::WorkerInfo& info)
{
    std::lock_guard<std::mutex> lk(workers_mutex_);
    workers_[session_id] = info;
    LOG_INFO << "[DGB-STRATUM] worker registered: session=" << session_id
             << " user=" << info.username
             << " worker=" << info.worker_name
             << " endpoint=" << info.remote_endpoint;
}

void DGBWorkSource::unregister_stratum_worker(const std::string& session_id)
{
    std::lock_guard<std::mutex> lk(workers_mutex_);
    auto it = workers_.find(session_id);
    if (it != workers_.end()) {
        LOG_INFO << "[DGB-STRATUM] worker unregistered: session=" << session_id
                 << " user=" << it->second.username
                 << " accepted=" << it->second.accepted
                 << " rejected=" << it->second.rejected
                 << " stale=" << it->second.stale;
        workers_.erase(it);
    }
}

void DGBWorkSource::update_stratum_worker(const std::string& session_id,
                                          double hashrate, double dead_hashrate,
                                          double difficulty,
                                          uint64_t accepted, uint64_t rejected, uint64_t stale)
{
    std::lock_guard<std::mutex> lk(workers_mutex_);
    auto it = workers_.find(session_id);
    if (it == workers_.end()) return;
    it->second.hashrate      = hashrate;
    it->second.dead_hashrate = dead_hashrate;
    it->second.difficulty    = difficulty;
    it->second.accepted      = accepted;
    it->second.rejected      = rejected;
    it->second.stale         = stale;
}

// ─────────────────────────────────────────────────────────────────────────────
// IWorkSource: work generation — Stage 4c will fill these in.
// ─────────────────────────────────────────────────────────────────────────────

nlohmann::json DGBWorkSource::get_current_work_template() const
{
    // Stage 4c: drive dgb::coin::TemplateBuilder over chain_ + mempool_ and
    // shape its WorkData into the GBT-style JSON the stratum session expects
    // (previousblockhash, bits, version, curtime, mintime, height,
    // coinbasevalue, transactions[]). Scrypt nBits, not SHA256d.
    return nlohmann::json::object();
}

std::vector<std::string> DGBWorkSource::get_stratum_merkle_branches() const
{
    // Stage 4c: return cached branches from last template build.
    return {};
}

std::pair<std::string, std::string> DGBWorkSource::get_coinbase_parts() const
{
    // Stage 4c: return cached coinb1/coinb2 (extranonce slot between them).
    return { {}, {} };
}

core::stratum::CoinbaseResult DGBWorkSource::build_connection_coinbase(
    const uint256& /*prev_share_hash*/,
    const std::string& /*extranonce1_hex*/,
    const std::vector<unsigned char>& /*payout_script*/,
    const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& /*merged_addrs*/) const
{
    // Stage 4c: build per-connection coinbase using the SSOT gentx assembler
    // (coin/gentx_coinbase.hpp) + ShareTracker ref_hash + PPLNS payout map.
    // For now return an empty result; sessions calling this will get an empty
    // job and skip pushing work, which is safe but non-functional.
    return {};
}

// ─────────────────────────────────────────────────────────────────────────────
// IWorkSource: share submission — Stage 4d (the hot path).
// ─────────────────────────────────────────────────────────────────────────────

nlohmann::json DGBWorkSource::mining_submit(
    const std::string& username, const std::string& job_id,
    const std::string& /*extranonce1*/, const std::string& /*extranonce2*/,
    const std::string& /*ntime*/, const std::string& /*nonce*/,
    const std::string& /*request_id*/,
    const std::map<uint32_t, std::vector<unsigned char>>& /*merged_addresses*/,
    const core::stratum::JobSnapshot* /*job*/)
{
    // Stage 4d will:
    //   1. Reconstruct the 80-byte block header from JobSnapshot + miner inputs
    //   2. Scrypt(header) → pow_hash (scrypt_1024_1_1_256, the DGB-Scrypt algo)
    //   3. Decode share target from job->share_bits (compact)
    //   4. Decode block target from job->block_nbits (compact)
    //   5. Classify:
    //        pow_hash <= block target → submit_block_fn_(full_block, height)
    //        pow_hash <= share target → record share in tracker (sharechain accept)
    //        otherwise                → reject as low-difficulty
    //   6. Update worker stats accordingly
    //
    // For now: log + reject everything as low-difficulty. Miners will see
    // stratum errors but the binary won't crash.
    LOG_WARNING << "[DGB-STRATUM] mining_submit not implemented (stage 4d): "
                << "user=" << username << " job=" << job_id
                << " — submission rejected as low-difficulty";

    return nlohmann::json::array({
        false,
        nlohmann::json::array({23, "Low difficulty share (stratum stub: stage 4d not implemented)", nullptr})
    });
}

double DGBWorkSource::compute_share_difficulty(
    const std::string& /*coinb1*/, const std::string& /*coinb2*/,
    const std::string& /*extranonce1*/, const std::string& /*extranonce2*/,
    const std::string& /*ntime*/, const std::string& /*nonce*/,
    uint32_t /*version*/, const std::string& /*prevhash_hex*/,
    const std::string& /*nbits_hex*/,
    const std::vector<std::string>& /*merkle_branches*/) const
{
    // Stage 4b/4c: reconstruct the 80-byte header from (coinb1+en1+en2+coinb2)
    // merkle-rooted with merkle_branches, then scrypt_1024_1_1_256(header) and
    // return diff1 / pow_hash. Until then the coin-agnostic StratumServer must
    // not credit pseudoshares it cannot score, so we return 0.0 — the documented
    // parse-error / not-yet sentinel that the vardiff gate already treats as a
    // hard reject (no garbage difficulty leaks into the rate monitor).
    return 0.0;
}

// ─────────────────────────────────────────────────────────────────────────────
// DGB-specific control surface
// ─────────────────────────────────────────────────────────────────────────────

void DGBWorkSource::set_best_share_hash_fn(std::function<uint256()> fn)
{
    std::lock_guard<std::mutex> lk(best_share_mutex_);
    best_share_hash_fn_ = std::move(fn);
}

}  // namespace dgb::stratum
