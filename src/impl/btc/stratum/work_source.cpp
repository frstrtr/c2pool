// btc::stratum::BTCWorkSource — Stage 4a skeleton.
//
// All IWorkSource methods are stubbed to safe defaults. Subsequent
// sub-stages flesh them out:
//   Stage 4b: read-only getters (config, prevhash, generation, workers)
//   Stage 4c: work generation (template, merkle branches, coinbase)
//   Stage 4d: mining_submit hot path (PoW classify + B5 dispatch)
//
// The skeleton is intentionally non-functional but compiles, instantiates,
// and lets us validate the wiring in main_btc.cpp end-to-end before
// implementing the substantive logic.

#include <impl/btc/stratum/work_source.hpp>

#include <impl/btc/coin/header_chain.hpp>
#include <impl/btc/coin/mempool.hpp>
#include <impl/btc/coin/template_builder.hpp>  // build_template + merkle_hash_pair
#include <impl/btc/coin/transaction.hpp>       // BlockType (the SubmitBlockFn arg)

#include <core/log.hpp>

#include <utility>

namespace btc::stratum {

BTCWorkSource::BTCWorkSource(btc::coin::HeaderChain&       chain,
                             btc::coin::Mempool&           mempool,
                             bool                          is_testnet,
                             SubmitBlockFn                 submit_fn,
                             core::stratum::StratumConfig  config)
    : chain_(chain)
    , mempool_(mempool)
    , is_testnet_(is_testnet)
    , submit_block_fn_(std::move(submit_fn))
    , config_(std::move(config))
{
    LOG_INFO << "[BTC-STRATUM] BTCWorkSource constructed"
             << " (testnet=" << is_testnet_
             << " min_diff=" << config_.min_difficulty
             << " max_diff=" << config_.max_difficulty
             << " target_time=" << config_.target_time
             << "s vardiff=" << (config_.vardiff_enabled ? "on" : "off") << ")";
}

BTCWorkSource::~BTCWorkSource() = default;

// ─────────────────────────────────────────────────────────────────────────────
// IWorkSource: config + read-only state — Stage 4b will fill these in.
// ─────────────────────────────────────────────────────────────────────────────

const core::stratum::StratumConfig& BTCWorkSource::get_stratum_config() const
{
    return config_;
}

std::function<uint256()> BTCWorkSource::get_best_share_hash_fn() const
{
    std::lock_guard<std::mutex> lk(best_share_mutex_);
    return best_share_hash_fn_;  // empty function until set_best_share_hash_fn() called
}

std::string BTCWorkSource::get_current_gbt_prevhash() const
{
    // BE display-hex of the current bitcoind chain tip. Stratum sessions
    // use this both as the `prevhash` field in mining.notify and as the
    // dedup key for `clean_jobs` detection (when prevhash changes, all
    // outstanding jobs are invalidated and miners reset).
    //
    // Empty string if HeaderChain has no tip yet (uninitialized / pre-IBD).
    auto tip = chain_.tip();
    if (!tip) return {};
    return tip->block_hash.GetHex();
}

uint64_t BTCWorkSource::get_work_generation() const
{
    return work_generation_.load(std::memory_order_relaxed);
}

bool BTCWorkSource::has_merged_chain(uint32_t /*chain_id*/) const
{
    // BTC MVP: no merged mining (the LTC MM rig is DOGE — none for BTC currently).
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// IWorkSource: per-connection bookkeeping — minimal but real now.
// ─────────────────────────────────────────────────────────────────────────────

void BTCWorkSource::register_stratum_worker(const std::string& session_id,
                                            const core::stratum::WorkerInfo& info)
{
    std::lock_guard<std::mutex> lk(workers_mutex_);
    workers_[session_id] = info;
    LOG_INFO << "[BTC-STRATUM] worker registered: session=" << session_id
             << " user=" << info.username
             << " worker=" << info.worker_name
             << " endpoint=" << info.remote_endpoint;
}

void BTCWorkSource::unregister_stratum_worker(const std::string& session_id)
{
    std::lock_guard<std::mutex> lk(workers_mutex_);
    auto it = workers_.find(session_id);
    if (it != workers_.end()) {
        LOG_INFO << "[BTC-STRATUM] worker unregistered: session=" << session_id
                 << " user=" << it->second.username
                 << " accepted=" << it->second.accepted
                 << " rejected=" << it->second.rejected
                 << " stale=" << it->second.stale;
        workers_.erase(it);
    }
}

void BTCWorkSource::update_stratum_worker(const std::string& session_id,
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

nlohmann::json BTCWorkSource::get_current_work_template() const
{
    // TemplateBuilder::build_template already shapes the result as a
    // GBT-style nlohmann::json in WorkData::m_data — exactly what stratum
    // sessions expect (previousblockhash, bits, version, curtime, mintime,
    // height, coinbasevalue, transactions[]). Return that directly.
    //
    // Returns an empty object if HeaderChain isn't past genesis yet — the
    // session will skip work-push and retry on next poll.
    auto wd = btc::coin::TemplateBuilder::build_template(chain_, mempool_, is_testnet_);
    if (!wd) return nlohmann::json::object();
    return wd->m_data;
}

std::vector<std::string> BTCWorkSource::get_stratum_merkle_branches() const
{
    // Stratum merkle branches: at each level, the SIBLING of the left-most
    // node (the one that descends from the coinbase). The miner reconstructs
    // the merkle root by:
    //     hash_0 = SHA256d(coinbase_txid || branch[0])
    //     hash_1 = SHA256d(hash_0       || branch[1])
    //     ...continue until single hash → merkle_root
    //
    // Algorithm matches Bitcoin Core's merkle.cpp: at every level, if the
    // count is odd, duplicate the last element. The branches list is
    // typically log2(N) entries for N transactions.
    auto wd = btc::coin::TemplateBuilder::build_template(chain_, mempool_, is_testnet_);
    if (!wd || wd->m_hashes.empty()) return {};

    // wd->m_hashes[0] is the coinbase placeholder — the actual coinbase
    // hash doesn't matter for branch computation since the miner provides
    // their own coinbase. We only need the structure.
    std::vector<uint256> level = wd->m_hashes;
    std::vector<std::string> branches;
    while (level.size() > 1) {
        // Right-sibling of the left-most node = level[1].
        branches.push_back(level[1].GetHex());

        // Ascend: place a placeholder for the next-level coinbase combo,
        // then hash subsequent pairs (duplicate last on odd count).
        std::vector<uint256> next;
        next.reserve((level.size() + 2) / 2);
        next.push_back(uint256::ZERO);  // placeholder for combo of (cb, level[1])
        for (size_t i = 2; i < level.size(); i += 2) {
            const uint256& l = level[i];
            const uint256& r = (i + 1 < level.size()) ? level[i + 1] : level[i];
            next.push_back(btc::coin::merkle_hash_pair(l, r));
        }
        level = std::move(next);
    }
    return branches;
}

std::pair<std::string, std::string> BTCWorkSource::get_coinbase_parts() const
{
    // Stage 4c: return cached coinb1/coinb2 (extranonce slot between them).
    return { {}, {} };
}

core::stratum::CoinbaseResult BTCWorkSource::build_connection_coinbase(
    const uint256& /*prev_share_hash*/,
    const std::string& /*extranonce1_hex*/,
    const std::vector<unsigned char>& /*payout_script*/,
    const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& /*merged_addrs*/) const
{
    // Stage 4c: build per-connection coinbase using TemplateBuilder helpers
    // + ShareTracker ref_hash. For now return an empty result; sessions
    // calling this will get an empty job and skip pushing work, which is
    // safe but non-functional.
    return {};
}

// ─────────────────────────────────────────────────────────────────────────────
// IWorkSource: share submission — Stage 4d (the hot path).
// ─────────────────────────────────────────────────────────────────────────────

nlohmann::json BTCWorkSource::mining_submit(
    const std::string& username, const std::string& job_id,
    const std::string& /*extranonce1*/, const std::string& /*extranonce2*/,
    const std::string& /*ntime*/, const std::string& /*nonce*/,
    const std::string& /*request_id*/,
    const std::map<uint32_t, std::vector<unsigned char>>& /*merged_addresses*/,
    const core::stratum::JobSnapshot* /*job*/)
{
    // Stage 4d will:
    //   1. Reconstruct the 80-byte block header from JobSnapshot + miner inputs
    //   2. SHA256d the header → pow_hash
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
    LOG_WARNING << "[BTC-STRATUM] mining_submit not implemented (stage 4d): "
                << "user=" << username << " job=" << job_id
                << " — submission rejected as low-difficulty";

    return nlohmann::json::array({
        false,
        nlohmann::json::array({23, "Low difficulty share (stratum stub: stage 4d not implemented)", nullptr})
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// BTC-specific control surface
// ─────────────────────────────────────────────────────────────────────────────

void BTCWorkSource::set_best_share_hash_fn(std::function<uint256()> fn)
{
    std::lock_guard<std::mutex> lk(best_share_mutex_);
    best_share_hash_fn_ = std::move(fn);
}

}  // namespace btc::stratum
