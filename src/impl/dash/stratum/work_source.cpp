// SPDX-License-Identifier: AGPL-3.0-or-later
// dash::stratum::DASHWorkSource -- Stage 4b bodies.
//
// This TU gives the 4a header a linkable definition: a constructor that binds
// the node-held coin-state + the REQUIRED dashd fallback + the dual-path
// won-block submit callback, real bodies for the read-only getters and the
// per-connection worker registry, and the fused get_work() adapter. The
// substantive X11 work-assembly + share-validation methods (work template,
// coinbase split, mining_submit hot path, compute_share_difficulty) are held
// at their documented safe defaults; they flesh out in 4c/4d exactly as
// dgb::stratum::DGBWorkSource progressed 4a->4b->4c->4d. Landing the bodies
// now makes DASHWorkSource a concrete, INSTANTIABLE core::stratum::IWorkSource
// (all pure virtuals defined) so the next stacked slice can hold it via
// shared_ptr<IWorkSource> and validate the StratumServer wiring in
// main_dash.cpp end-to-end before the X11 logic lands.
//
// Embedded / fallback duality (MUST PERSIST): get_work() sources the base
// template through dash::stratum::get_work(), which picks the EMBEDDED arm when
// the node-held NodeCoinState bundle is populated and otherwise falls back to
// the always-reachable dashd GBT RPC arm. The dashd-RPC fallback is never
// removed -- it is the safety + [GBT-XCHECK] cross-check path (operator rule).

#include <impl/dash/stratum/work_source.hpp>

#include <core/log.hpp>

#include <utility>

namespace dash::stratum {

DASHWorkSource::DASHWorkSource(const coin::NodeCoinState& coin_state,
                               std::function<coin::DashWorkData()> dashd_fallback,
                               SubmitBlockFn submit_fn,
                               core::stratum::StratumConfig config)
    : coin_state_(coin_state)
    , dashd_fallback_(std::move(dashd_fallback))
    , submit_block_fn_(std::move(submit_fn))
    , config_(std::move(config))
{
    LOG_INFO << "[DASH-STRATUM] DASHWorkSource constructed"
             << " (min_diff=" << config_.min_difficulty
             << " max_diff=" << config_.max_difficulty
             << " target_time=" << config_.target_time
             << "s vardiff=" << (config_.vardiff_enabled ? "on" : "off")
             << " dashd_fallback=" << (dashd_fallback_ ? "wired" : "UNSET")
             << " submit_fn=" << (submit_block_fn_ ? "wired" : "UNSET") << ")";
    if (!dashd_fallback_) {
        // The fallback is the always-reachable safety arm; an unbound one means
        // a set-gap (unpopulated bundle) would have NOTHING to source from.
        LOG_WARNING << "[DASH-STRATUM] dashd_fallback UNSET -- get_work() on a "
                       "coin-state set-gap has no template source (embedded arm "
                       "only). Bind the dashd GBT RPC fallback in main_dash.cpp.";
    }
}

DASHWorkSource::~DASHWorkSource() = default;

// ─────────────────────────────────────────────────────────────────────────────
// Fused get_work(): the single miner-facing entry point. Thin node-bound
// adapter over the free dash::stratum::get_work() capstone (#698) -- source the
// base template off the node-held coin-state (embedded when populated, retained
// dashd fallback on a set-gap) and assemble the per-miner job targets over it.
// ─────────────────────────────────────────────────────────────────────────────
GetWork DASHWorkSource::get_work(const WorkJobTargetInputs& job_in) const
{
    // Qualify the free function explicitly: unqualified `get_work` in this
    // member body resolves to THIS member (class scope shadows the namespace),
    // so name the capstone by its namespace to avoid a self-call.
    return ::dash::stratum::get_work(coin_state_, dashd_fallback_, job_in);
}

// ─────────────────────────────────────────────────────────────────────────────
// IWorkSource: config + read-only state -- real now.
// ─────────────────────────────────────────────────────────────────────────────

std::function<uint256()> DASHWorkSource::get_best_share_hash_fn() const
{
    std::lock_guard<std::mutex> lk(best_share_mutex_);
    return best_share_hash_fn_;  // empty until set_best_share_hash_fn() wires it
}

std::string DASHWorkSource::get_current_gbt_prevhash() const
{
    // Held back at the 4b stage: the served template + its previousblockhash
    // wire lands with the 4c work-assembly slice (mirrors dgb::stratum 4a/4c).
    // A truthful empty absence -- never a fabricated tip id. The stratum server
    // falls back to the best-share hash when this is empty.
    return {};
}

bool DASHWorkSource::has_merged_chain(uint32_t /*chain_id*/) const
{
    // DASH V36: standalone X11 parent, no merged mining. (Any future
    // merged-mining seam folds in at v37; never fabricated here.)
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// IWorkSource: per-connection bookkeeping -- minimal but real now.
// ─────────────────────────────────────────────────────────────────────────────

void DASHWorkSource::register_stratum_worker(const std::string& session_id,
                                             const core::stratum::WorkerInfo& info)
{
    std::lock_guard<std::mutex> lk(workers_mutex_);
    workers_[session_id] = info;
    LOG_INFO << "[DASH-STRATUM] worker registered: session=" << session_id
             << " user=" << info.username;
}

void DASHWorkSource::unregister_stratum_worker(const std::string& session_id)
{
    std::lock_guard<std::mutex> lk(workers_mutex_);
    auto it = workers_.find(session_id);
    if (it != workers_.end()) {
        LOG_INFO << "[DASH-STRATUM] worker unregistered: session=" << session_id
                 << " user=" << it->second.username
                 << " accepted=" << it->second.accepted
                 << " rejected=" << it->second.rejected
                 << " stale=" << it->second.stale;
        workers_.erase(it);
    }
    // Unknown session_id: idempotent no-op (the server may double-unregister on
    // a racing disconnect) -- never a crash.
}

void DASHWorkSource::update_stratum_worker(const std::string& session_id,
                                           double hashrate, double dead_hashrate,
                                           double difficulty,
                                           uint64_t accepted, uint64_t rejected,
                                           uint64_t stale)
{
    std::lock_guard<std::mutex> lk(workers_mutex_);
    auto it = workers_.find(session_id);
    if (it == workers_.end()) return;  // update for an unregistered session: drop.
    it->second.hashrate      = hashrate;
    it->second.dead_hashrate = dead_hashrate;
    it->second.difficulty    = difficulty;
    it->second.accepted      = accepted;
    it->second.rejected      = rejected;
    it->second.stale         = stale;
}

// ─────────────────────────────────────────────────────────────────────────────
// IWorkSource: work generation -- Stage 4c fills these in (safe defaults now).
// ─────────────────────────────────────────────────────────────────────────────

nlohmann::json DASHWorkSource::get_current_work_template() const
{
    // 4c: assemble the GBT-shaped template off the node-held coin-state (or the
    // dashd fallback). An empty object until then -- an honest "no template yet"
    // the stratum session treats as no work to push (safe, non-functional).
    return nlohmann::json::object();
}

std::vector<std::string> DASHWorkSource::get_stratum_merkle_branches() const
{
    return {};  // 4c: cached branches from the last template build.
}

std::pair<std::string, std::string> DASHWorkSource::get_coinbase_parts() const
{
    return { {}, {} };  // 4c: cached coinb1/coinb2 (extranonce slot between them).
}

core::stratum::CoinbaseResult DASHWorkSource::build_connection_coinbase(
    const uint256& /*prev_share_hash*/,
    const std::string& /*extranonce1_hex*/,
    const std::vector<unsigned char>& /*payout_script*/,
    const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& /*merged_addrs*/) const
{
    // 4c/4d: PPLNS->coinbase assembly (byte-identical to the verifier split).
    // Empty result until wired -> the session pushes no work (safe, non-functional).
    return {};
}

// ─────────────────────────────────────────────────────────────────────────────
// IWorkSource: share submission -- Stage 4d (the X11 hot path).
// ─────────────────────────────────────────────────────────────────────────────

nlohmann::json DASHWorkSource::mining_submit(
    const std::string& username, const std::string& job_id,
    const std::string& /*extranonce1*/, const std::string& /*extranonce2*/,
    const std::string& /*ntime*/, const std::string& /*nonce*/,
    const std::string& /*request_id*/,
    const std::map<uint32_t, std::vector<unsigned char>>& /*merged_addresses*/,
    const core::stratum::JobSnapshot* /*job*/)
{
    // 4d: reconstruct the 80-byte header, run the DASH X11 chained-hash PoW, and
    // classify WonBlock -> dual-path broadcaster / ShareAccept -> sharechain mint
    // / Reject. Until then every submission is rejected -- the coin-agnostic
    // stratum server must never credit a share this skeleton cannot score.
    LOG_INFO << "[DASH-STRATUM] mining_submit (4b skeleton -> reject): user="
             << username << " job=" << job_id;
    return nlohmann::json::array({
        false, nlohmann::json::array({20, "Not yet implemented (4b skeleton)", nullptr})
    });
}

double DASHWorkSource::compute_share_difficulty(
    const std::string& /*coinb1*/, const std::string& /*coinb2*/,
    const std::string& /*extranonce1*/, const std::string& /*extranonce2*/,
    const std::string& /*ntime*/, const std::string& /*nonce*/,
    uint32_t /*version*/, const std::string& /*prevhash_hex*/,
    const std::string& /*nbits_hex*/,
    const std::vector<std::string>& /*merkle_branches*/) const
{
    // 4b/4c: reconstruct the header, x11_hash(header), return diff1 / pow_hash.
    // Until then return 0.0 -- the documented parse-error / not-yet sentinel the
    // vardiff gate already treats as a hard reject (no garbage diff leaks into
    // the rate monitor).
    return 0.0;
}

// ─────────────────────────────────────────────────────────────────────────────
// DASH-specific control surface.
// ─────────────────────────────────────────────────────────────────────────────

void DASHWorkSource::set_best_share_hash_fn(std::function<uint256()> fn)
{
    std::lock_guard<std::mutex> lk(best_share_mutex_);
    best_share_hash_fn_ = std::move(fn);
}

}  // namespace dash::stratum
