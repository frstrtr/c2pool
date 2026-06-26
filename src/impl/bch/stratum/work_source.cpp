// bch::stratum::BCHWorkSource — slice-c implementation.
//
// Implements the read-only state accessors, per-connection worker
// bookkeeping, and the WORK-ASSEMBLY read path that bridges the
// coin-agnostic core::StratumServer to BCH work generation off
// bch::coin::TemplateBuilder::build_template:
//
//   - cached_template()            single-slot template memo (template cache)
//   - get_current_work_template()  GBT-shaped json for mining.notify
//   - get_stratum_merkle_branches()coinbase-left merkle siblings (CTOR order)
//   - get_coinbase_parts()         trivial fallback split
//   - get_current_gbt_prevhash()   tip display-hex for clean_jobs dedup
//   - worker registry + atomics
//
// DEFERRED to slice-d (share-WRITE / validation hot path, left as safe
// defaults here so the TU links and the read path is exercisable):
//   - build_connection_coinbase()  full PPLNS + ref_hash coinbase build
//   - mining_submit()              SHA256d classify + sharechain add + won-block
//   - compute_share_difficulty()   per-submission SHA256d difficulty
//
// BCH divergences from the BTC work source are confined here: no SegWit
// (non-witness coinbase + merkle throughout), CashTokens transparent-carry
// (build_template hands token-prefixed txs through unchanged), ABLA budget
// owned by TemplateBuilder. Per-coin isolation: bch tree only.

#include <impl/bch/stratum/work_source.hpp>

#include <impl/bch/coin/header_chain.hpp>
#include <impl/bch/coin/mempool.hpp>
#include <impl/bch/coin/merkle.hpp>            // merkle_hash_pair (CTOR SHA256d)
#include <impl/bch/coin/template_builder.hpp>  // build_template + rpc::WorkData

#include <core/log.hpp>
#include <btclibs/util/strencodings.h>         // HexStr

#include <ctime>
#include <span>
#include <utility>

namespace bch::stratum {

BCHWorkSource::BCHWorkSource(bch::coin::HeaderChain&       chain,
                             bch::coin::Mempool&           mempool,
                             bool                          is_testnet,
                             SubmitBlockFn                 submit_fn,
                             core::stratum::StratumConfig  config)
    : chain_(chain)
    , mempool_(mempool)
    , is_testnet_(is_testnet)
    , submit_block_fn_(std::move(submit_fn))
    , config_(std::move(config))
{
    LOG_INFO << "[BCH-STRATUM] BCHWorkSource constructed (testnet="
             << (is_testnet_ ? "1" : "0") << ")";
}

BCHWorkSource::~BCHWorkSource() = default;

// -- IWorkSource: config + read-only state ------------------------------------

const core::stratum::StratumConfig& BCHWorkSource::get_stratum_config() const
{
    return config_;
}

std::function<uint256()> BCHWorkSource::get_best_share_hash_fn() const
{
    std::lock_guard<std::mutex> lk(best_share_mutex_);
    return best_share_hash_fn_;  // empty until set_best_share_hash_fn()
}

std::string BCHWorkSource::get_current_gbt_prevhash() const
{
    // BE display-hex of the current BCH chain tip -- both the mining.notify
    // prevhash field and the clean_jobs dedup key. Empty until the header
    // chain has a tip (pre-IBD).
    auto tip = chain_.tip();
    if (!tip) return {};
    return tip->block_hash.GetHex();
}

uint64_t BCHWorkSource::get_work_generation() const
{
    return work_generation_.load(std::memory_order_relaxed);
}

bool BCHWorkSource::has_merged_chain(uint32_t /*chain_id*/) const
{
    // BCH is a STANDALONE parent in V36 -- no merged-mining aux module.
    return false;
}

// -- IWorkSource: per-connection bookkeeping ----------------------------------

void BCHWorkSource::register_stratum_worker(const std::string& session_id,
                                            const core::stratum::WorkerInfo& info)
{
    std::lock_guard<std::mutex> lk(workers_mutex_);
    workers_[session_id] = info;
    LOG_INFO << "[BCH-STRATUM] worker registered: session=" << session_id
             << " user=" << info.username
             << " worker=" << info.worker_name
             << " endpoint=" << info.remote_endpoint;
}

void BCHWorkSource::unregister_stratum_worker(const std::string& session_id)
{
    std::lock_guard<std::mutex> lk(workers_mutex_);
    auto it = workers_.find(session_id);
    if (it != workers_.end()) {
        LOG_INFO << "[BCH-STRATUM] worker unregistered: session=" << session_id
                 << " user=" << it->second.username
                 << " accepted=" << it->second.accepted
                 << " rejected=" << it->second.rejected
                 << " stale=" << it->second.stale;
        workers_.erase(it);
    }
}

void BCHWorkSource::update_stratum_worker(const std::string& session_id,
                                          double hashrate, double dead_hashrate,
                                          double difficulty,
                                          uint64_t accepted, uint64_t rejected,
                                          uint64_t stale)
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

// -- IWorkSource: work generation (slice-c) -----------------------------------

std::shared_ptr<const bch::coin::rpc::WorkData>
BCHWorkSource::cached_template() const
{
    const uint64_t gen = work_generation_.load(std::memory_order_relaxed);
    uint256 tip_hash{};
    if (auto tip = chain_.tip()) tip_hash = tip->block_hash;

    {
        std::lock_guard<std::mutex> lk(template_mutex_);
        if (template_cache_ &&
            template_cache_gen_ == gen &&
            template_cache_tip_ == tip_hash)
            return template_cache_;
    }

    // build_template is read-only over chain_ + mempool_ (their own internal
    // locking). Done OUTSIDE template_mutex_ so a slow build never blocks a
    // concurrent cache hit on another connection thread.
    auto built = bch::coin::TemplateBuilder::build_template(chain_, mempool_, is_testnet_);
    if (!built) return nullptr;  // chain has no tip yet

    auto sp = std::make_shared<const bch::coin::rpc::WorkData>(std::move(*built));
    std::lock_guard<std::mutex> lk(template_mutex_);
    template_cache_     = sp;
    template_cache_gen_ = gen;
    template_cache_tip_ = tip_hash;
    return sp;
}

nlohmann::json BCHWorkSource::get_current_work_template() const
{
    // TemplateBuilder::build_template already shapes WorkData::m_data as the
    // GBT-style json stratum sessions consume (previousblockhash, bits,
    // version, curtime, mintime, height, coinbasevalue, transactions[]).
    // Empty object until the header chain is past genesis -- sessions skip
    // work-push and retry. curtime is refreshed per-poll so mining.notify
    // ntime tracks wall-clock even on a cache hit.
    auto wd = cached_template();
    if (!wd) return nlohmann::json::object();
    nlohmann::json data = wd->m_data;
    data["curtime"] = static_cast<int64_t>(std::time(nullptr));
    return data;
}

std::vector<std::string> BCHWorkSource::get_stratum_merkle_branches() const
{
    // Coinbase-left merkle siblings for mining.notify. The miner rebuilds
    // the root via SHA256d(coinbase_txid || branch[0]), then folds in each
    // subsequent branch. BCH uses CTOR (Nov 2018) for the block tx ORDER,
    // but the merkle tree itself is the same SHA256d pairwise structure as
    // BTC with NO witness commitment -- so the branch algorithm is identical;
    // build_template has already emitted m_hashes in canonical (CTOR) order.
    //
    // Wire encoding: hex of the LE-internal 32 bytes (NOT GetHex() display
    // order) -- the miner hex2bin-s this straight into SHA256d, so the bytes
    // must match the leaves the pool hashed.
    auto wd = cached_template();
    if (!wd || wd->m_hashes.empty()) return {};

    std::vector<uint256> level = wd->m_hashes;  // [0] = coinbase placeholder
    std::vector<std::string> branches;
    while (level.size() > 1) {
        branches.push_back(HexStr(std::span<const unsigned char>(level[1].data(), 32)));
        std::vector<uint256> next;
        next.reserve((level.size() + 2) / 2);
        next.push_back(uint256::ZERO);  // placeholder for (coinbase, level[1]) combo
        for (size_t i = 2; i < level.size(); i += 2) {
            const uint256& l = level[i];
            const uint256& r = (i + 1 < level.size()) ? level[i + 1] : level[i];
            next.push_back(bch::coin::merkle_hash_pair(l, r));
        }
        level = std::move(next);
    }
    return branches;
}

std::pair<std::string, std::string> BCHWorkSource::get_coinbase_parts() const
{
    // Fallback split with no payout output -- the per-connection builder
    // (build_connection_coinbase, slice-d) produces the real coinbase.
    return { {}, {} };
}

// -- IWorkSource: setters (callback wiring from main_bch.cpp) ------------------

void BCHWorkSource::set_pplns_fn(PplnsFn fn)
{
    std::lock_guard<std::mutex> lk(callback_mutex_);
    pplns_fn_ = std::move(fn);
}

void BCHWorkSource::set_ref_hash_fn(RefHashFn fn)
{
    std::lock_guard<std::mutex> lk(callback_mutex_);
    ref_hash_fn_ = std::move(fn);
}

void BCHWorkSource::set_create_share_fn(CreateShareFn fn)
{
    std::lock_guard<std::mutex> lk(callback_mutex_);
    create_share_fn_ = std::move(fn);
}

void BCHWorkSource::set_donation_script(std::vector<unsigned char> script)
{
    std::lock_guard<std::mutex> lk(callback_mutex_);
    donation_script_ = std::move(script);
}

// -- DEFERRED to slice-d (share-WRITE / validation hot path) -------------------
// Safe defaults so the TU links and the read path is fully exercisable now.

core::stratum::CoinbaseResult BCHWorkSource::build_connection_coinbase(
    const uint256& /*prev_share_hash*/,
    const std::string& /*extranonce1_hex*/,
    const std::vector<unsigned char>& /*payout_script*/,
    const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& /*merged_addrs*/) const
{
    // slice-d: BCH v36 coinbase build (BIP34 height + /c2pool-bch/ tag, PPLNS
    // payouts via pplns_fn_, OP_RETURN ref_hash via ref_hash_fn_, NO witness
    // commitment). Until then no per-connection coinbase is offered.
    return {};
}

nlohmann::json BCHWorkSource::mining_submit(
    const std::string& /*username*/, const std::string& /*job_id*/,
    const std::string& /*extranonce1*/, const std::string& /*extranonce2*/,
    const std::string& /*ntime*/, const std::string& /*nonce*/,
    const std::string& /*request_id*/,
    const std::map<uint32_t, std::vector<unsigned char>>& /*merged_addresses*/,
    const core::stratum::JobSnapshot* /*job*/)
{
    // slice-d: reconstruct coinb1||en1||en2||coinb2 (non-witness), SHA256d
    // classify vs share/block target, add v36 share via create_share_fn_, and
    // on a mainnet hit fire submit_block_fn_ (embedded P2P relay + BCHN-RPC
    // submitblock fallback -- both legs, fallback always retained).
    return nlohmann::json{{"error", "mining_submit not yet implemented (slice-d)"}};
}

double BCHWorkSource::compute_share_difficulty(
    const std::string& /*coinb1*/, const std::string& /*coinb2*/,
    const std::string& /*extranonce1*/, const std::string& /*extranonce2*/,
    const std::string& /*ntime*/, const std::string& /*nonce*/,
    uint32_t /*version*/, const std::string& /*prevhash_hex*/,
    const std::string& /*nbits_hex*/,
    const std::vector<std::string>& /*merkle_branches*/) const
{
    // slice-d: rebuild header, SHA256d, target_to_difficulty (BCH shares the
    // BTC SHA256d PoW family).
    return 0.0;
}

}  // namespace bch::stratum
