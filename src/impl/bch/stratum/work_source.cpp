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

#include <impl/bch/stratum/coinbase_outputs.hpp>  // assemble_v36_coinbase_outputs

#include <impl/bch/coin/header_chain.hpp>
#include <impl/bch/coin/mempool.hpp>
#include <impl/bch/coin/merkle.hpp>            // merkle_hash_pair (CTOR SHA256d)
#include <impl/bch/coin/template_builder.hpp>  // build_template + rpc::WorkData

#include <core/log.hpp>
#include <btclibs/util/strencodings.h>         // HexStr

#include <ctime>
#include <span>
#include <utility>

#include <core/address_utils.hpp>             // address_to_script (share write path)
#include <core/hash.hpp>                      // Hash (SHA256d)
#include <core/target_utils.hpp>              // chain::target_to_difficulty
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>

namespace {

// Little-endian Bitcoin-wire byte helpers (shared with BTC; non-witness here).
inline void push_u32_le(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(static_cast<uint8_t>(x & 0xff));
    v.push_back(static_cast<uint8_t>((x >> 8) & 0xff));
    v.push_back(static_cast<uint8_t>((x >> 16) & 0xff));
    v.push_back(static_cast<uint8_t>((x >> 24) & 0xff));
}
inline void push_u64_le(std::vector<uint8_t>& v, uint64_t x) {
    for (int i = 0; i < 8; ++i)
        v.push_back(static_cast<uint8_t>((x >> (i * 8)) & 0xff));
}
inline void push_varint(std::vector<uint8_t>& v, uint64_t n) {
    if (n < 0xfd) { v.push_back(static_cast<uint8_t>(n)); }
    else if (n <= 0xffff) {
        v.push_back(0xfd);
        v.push_back(static_cast<uint8_t>(n & 0xff));
        v.push_back(static_cast<uint8_t>((n >> 8) & 0xff));
    } else if (n <= 0xffffffff) {
        v.push_back(0xfe); push_u32_le(v, static_cast<uint32_t>(n));
    } else { v.push_back(0xff); push_u64_le(v, n); }
}
// BIP34 minimally-encoded height push for the coinbase scriptSig.
inline std::vector<uint8_t> bip34_height_push(uint32_t h) {
    std::vector<uint8_t> enc; uint32_t tmp = h;
    while (tmp) { enc.push_back(static_cast<uint8_t>(tmp & 0xff)); tmp >>= 8; }
    if (enc.empty()) enc.push_back(0);
    if (enc.back() & 0x80) enc.push_back(0);
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>(enc.size()));   // OP_PUSHBYTES_n
    out.insert(out.end(), enc.begin(), enc.end());
    return out;
}
inline uint32_t parse_be_hex_u32(const std::string& str) {
    uint32_t v = 0; std::sscanf(str.c_str(), "%x", &v); return v;
}

}  // anonymous namespace

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

// -- slice-d: share-WRITE / validation hot path (SHA256d, non-SegWit) ---------

core::stratum::CoinbaseResult BCHWorkSource::build_connection_coinbase(
    const uint256& prev_share_hash,
    const std::string& /*extranonce1_hex*/,
    const std::vector<unsigned char>& payout_script,
    const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& /*merged_addrs*/) const
{
    // c2pool BCH v36 coinbase. Ported from the BTC v35 work source with the
    // BCH divergences applied:
    //   - NO SegWit: no witness-commitment output, no BIP141 reserved value;
    //     BCH never activated SegWit (M1 4) so the coinbase is non-witness.
    //   - pool tag is /c2pool-bch/.
    //   - CashTokens ride through build_template's mempool slice unchanged
    //     (transparent-carry; the coinbase author never inspects them).
    //   - CTOR governs block tx ORDER, not these coinbase bytes.
    // Byte-shape (PPLNS split + sv>=36 donation P2SH + OP_RETURN ref_hash) is
    // consensus-bearing -> pinned by the coinbase-KAT vs the p2pool-merged-v36
    // BCH oracle; any divergence is a HARD STOP, not a silent ship.
    auto wd = cached_template();
    if (!wd) return {};

    const uint32_t height        = wd->m_data.value("height", 0u);
    const uint64_t coinbasevalue = wd->m_data.value("coinbasevalue", uint64_t{0});

    uint32_t block_bits = 0;
    if (auto it = wd->m_data.find("bits"); it != wd->m_data.end() && it->is_string())
        block_bits = parse_be_hex_u32(it->get<std::string>());
    const uint32_t curtime = static_cast<uint32_t>(std::time(nullptr));

    PplnsFn pplns_fn; RefHashFn ref_hash_fn;
    std::vector<unsigned char> donation_script;
    {
        std::lock_guard<std::mutex> lk(callback_mutex_);
        pplns_fn = pplns_fn_; ref_hash_fn = ref_hash_fn_; donation_script = donation_script_;
    }

    // scriptSig (deterministic): BIP34 height + pool tag.
    auto bip34 = bip34_height_push(height);
    static const std::string POOL_TAG = "/c2pool-bch/";
    std::vector<uint8_t> scriptsig;
    scriptsig.insert(scriptsig.end(), bip34.begin(), bip34.end());
    if (!POOL_TAG.empty() && POOL_TAG.size() < 76) {
        scriptsig.push_back(static_cast<uint8_t>(POOL_TAG.size()));
        scriptsig.insert(scriptsig.end(), POOL_TAG.begin(), POOL_TAG.end());
    }

    // PPLNS payouts.
    std::map<std::vector<unsigned char>, double> payouts;
    if (pplns_fn) {
        uint256 block_target;
        if (block_bits != 0) block_target.SetCompact(block_bits);
        try { payouts = pplns_fn(prev_share_hash, block_target, coinbasevalue, donation_script); }
        catch (const std::exception& e) {
            LOG_WARNING << "[BCH-STRATUM] pplns_fn threw: " << e.what()
                        << " -- falling back to single-output coinbase";
            payouts.clear();
        }
    }

    // Drop empty-script entries; reabsorb their value into donation.
    {
        size_t dropped_n = 0; uint64_t dropped_value = 0;
        for (auto it = payouts.begin(); it != payouts.end(); ) {
            if (it->first.empty()) {
                dropped_n++; dropped_value += static_cast<uint64_t>(it->second);
                it = payouts.erase(it);
            } else { ++it; }
        }
        if (dropped_n > 0 && !donation_script.empty())
            payouts[donation_script] += static_cast<double>(dropped_value);
    }

    // V36 removes the finder fee -- pure PPLNS accounting. The oracle
    // (p2pool-merged-v36 data.py ~945) fires the subsidy/200 finder fee ONLY in
    // the `not v36_active` branch; the v36 gentx pays no finder fee. Byte-parity
    // to the canonical merged-v36 gentx is the HARD invariant, so the sv>=36
    // coinbase author deducts NOTHING here (integrator conform ruling 2026-06-27,
    // same shape as the DASH dust call). The pre-v36 (v35) finder fee lives in
    // the legacy work source's not-v36 path, not in this v36-only builder.

    // Degraded fallback: full subsidy -> miner.
    if (payouts.empty() && !payout_script.empty())
        payouts[payout_script] = static_cast<double>(coinbasevalue);

    // G3b safety net: a coinbase with NO value output (payouts empty AND the
    // miner supplied no decodable payout script -- e.g. the generic core stratum
    // address_to_script() could not decode a BCH CashAddr username) forfeits the
    // subsidy and serves a degenerate, byte-identical placeholder coinbase across
    // shares (only the value-0 OP_RETURN extranonce carrier). A won block then
    // loses to consensus (bad-txns / BIP30 duplicate-coinbase). NEVER emit a
    // payout-less coinbase: route the full subsidy to the always-present v36
    // donation script as residual recipient so the block stays valid. LAST
    // RESORT -- a real miner address must still be resolved upstream; flag loudly.
    if (payouts.empty() && !donation_script.empty()) {
        LOG_WARNING << "[BCH-STRATUM] no PPLNS payouts and miner payout_script "
                       "unresolved -- routing full subsidy to donation script "
                       "(degraded; check miner CashAddr decode upstream)";
        payouts[donation_script] = static_cast<double>(coinbasevalue);
    }

    // === Oracle-conforming output assembly (p2pool-merged-v36 data.py gentx) ===
    // The donation/marker output is forced LAST (immediately before the
    // OP_RETURN), EXCLUDED from the (amount asc, script asc) sort, and obeys the
    // V36 >= 1-satoshi consensus marker rule. PPLNS dests sort ascending and are
    // capped to the largest 4000 (oracle dests[-4000:]).

    // The donation forced-LAST rule, the V36 >=1-sat marker rule, the
    // (amount asc, script asc) sort and the dests[-4000:] cap all live in the
    // pure, header-only assemble_v36_coinbase_outputs() so the byte-shape is
    // pinned by coinbase_author_kat_test against the p2pool-merged-v36 oracle
    // (data.py generate_transaction) rather than asserted against this builder.
    auto outputs = assemble_v36_coinbase_outputs(std::move(payouts), donation_script, coinbasevalue);

    // ref_hash + frozen chain-walk values.
    core::stratum::RefHashResult rh_result;
    if (ref_hash_fn) {
        try {
            rh_result = ref_hash_fn(prev_share_hash, scriptsig, payout_script,
                                    coinbasevalue, block_bits, curtime);
            if (rh_result.bits != 0) {
                share_bits_.store(rh_result.bits, std::memory_order_relaxed);
                share_max_bits_.store(rh_result.max_bits, std::memory_order_relaxed);
            }
        } catch (const std::exception& e) {
            LOG_WARNING << "[BCH-STRATUM] ref_hash_fn threw: " << e.what()
                        << " -- coinbase will lack OP_RETURN commitment";
        }
    }
    const uint256&  ref_hash       = rh_result.ref_hash;
    const uint64_t  ref_nonce      = rh_result.last_txout_nonce;
    const bool      emit_op_return = ref_hash_fn && !ref_hash.IsNull();

    // Assemble coinb1: full tx up to (and including) ref_hash. NO SegWit
    // output -> output_count is PPLNS outputs + optional OP_RETURN only.
    const size_t output_count = outputs.size() + (emit_op_return ? 1 : 0);

    std::vector<uint8_t> coinb1;
    push_u32_le(coinb1, 1);                  // tx version
    coinb1.push_back(0x01);                  // vin_count = 1
    coinb1.insert(coinb1.end(), 32, 0x00);   // prev_hash = 32 zero bytes
    push_u32_le(coinb1, 0xFFFFFFFFu);        // prev_vout
    push_varint(coinb1, scriptsig.size());
    coinb1.insert(coinb1.end(), scriptsig.begin(), scriptsig.end());
    push_u32_le(coinb1, 0xFFFFFFFFu);        // sequence
    push_varint(coinb1, output_count);

    for (const auto& [script, amount] : outputs) {
        push_u64_le(coinb1, amount);
        push_varint(coinb1, script.size());
        coinb1.insert(coinb1.end(), script.begin(), script.end());
    }
    if (emit_op_return) {
        push_u64_le(coinb1, 0);   // 0 sats
        coinb1.push_back(0x2a);   // script_len = 42
        coinb1.push_back(0x6a);   // OP_RETURN
        coinb1.push_back(0x28);   // PUSH_40
        coinb1.insert(coinb1.end(), ref_hash.data(), ref_hash.data() + 32);
        // [8B nonce slot -- coinb1 ends here; en1+en2 fills it]
    }

    std::vector<uint8_t> coinb2;
    push_u32_le(coinb2, 0u);  // locktime

    core::stratum::CoinbaseResult result;
    result.coinb1 = HexStr(std::span<const uint8_t>(coinb1.data(), coinb1.size()));
    result.coinb2 = HexStr(std::span<const uint8_t>(coinb2.data(), coinb2.size()));

    auto& snap = result.snapshot;
    snap.subsidy       = coinbasevalue;
    snap.segwit_active = false;   // BCH: never SegWit
    snap.frozen_ref.share_version   = rh_result.share_version;
    snap.frozen_ref.desired_version = rh_result.desired_version;
    snap.frozen_ref.bits      = rh_result.bits ? rh_result.bits : share_bits_.load();
    snap.frozen_ref.max_bits  = rh_result.max_bits ? rh_result.max_bits : share_max_bits_.load();
    snap.frozen_ref.timestamp = rh_result.timestamp ? rh_result.timestamp : curtime;
    snap.frozen_ref.absheight = rh_result.absheight;
    snap.frozen_ref.abswork   = rh_result.abswork;
    snap.frozen_ref.far_share_hash   = rh_result.far_share_hash;
    snap.frozen_ref.ref_hash         = ref_hash;
    snap.frozen_ref.last_txout_nonce = ref_nonce;

    auto branches = get_stratum_merkle_branches();
    for (const auto& h : branches) {
        uint256 b; auto bb = ParseHex(h);
        if (bb.size() == 32) std::memcpy(b.begin(), bb.data(), 32);
        snap.frozen_ref.frozen_merkle_branches.push_back(b);
    }

    // tx_data: raw tx hex for full-block assembly at submit time. Built inline
    // (no cross-tree btc memo include -- per-coin isolation); a memo seam is a
    // follow-up only if a BCH heaptrack shows churn here.
    if (auto txs_field = wd->m_data.find("transactions");
        txs_field != wd->m_data.end() && txs_field->is_array())
    {
        auto txv = std::make_shared<std::vector<std::string>>();
        txv->reserve(txs_field->size());
        for (const auto& t : *txs_field) {
            if (!t.is_object()) continue;
            if (auto d = t.find("data"); d != t.end() && d->is_string())
                txv->push_back(d->get<std::string>());
        }
        snap.tx_data = txv;
    }
    snap.merkle_branches = std::move(branches);
    return result;
}

nlohmann::json BCHWorkSource::mining_submit(
    const std::string& username, const std::string& job_id,
    const std::string& extranonce1, const std::string& extranonce2,
    const std::string& ntime, const std::string& nonce,
    const std::string& /*request_id*/,
    const std::map<uint32_t, std::vector<unsigned char>>& /*merged_addresses*/,
    const core::stratum::JobSnapshot* job)
{
    auto reject = [](int code, const char* msg) {
        return nlohmann::json::array({ false, nlohmann::json::array({code, msg, nullptr}) });
    };
    if (!job) {
        LOG_WARNING << "[BCH-STRATUM] submit reject (no JobSnapshot): user=" << username
                    << " job=" << job_id;
        return reject(21, "Job not found");
    }

    // Reconstruct full coinbase: coinb1 || en1 || en2 || coinb2 (non-witness).
    auto coinb1_bytes = ParseHex(job->coinb1);
    auto en1_bytes    = ParseHex(extranonce1);
    auto en2_bytes    = ParseHex(extranonce2);
    auto coinb2_bytes = ParseHex(job->coinb2);
    std::vector<uint8_t> coinbase;
    coinbase.reserve(coinb1_bytes.size() + en1_bytes.size() + en2_bytes.size() + coinb2_bytes.size());
    coinbase.insert(coinbase.end(), coinb1_bytes.begin(), coinb1_bytes.end());
    coinbase.insert(coinbase.end(), en1_bytes.begin(),    en1_bytes.end());
    coinbase.insert(coinbase.end(), en2_bytes.begin(),    en2_bytes.end());
    coinbase.insert(coinbase.end(), coinb2_bytes.begin(), coinb2_bytes.end());

    uint256 coinbase_txid = Hash(std::span<const uint8_t>(coinbase.data(), coinbase.size()));

    // Ascend stratum merkle branches (LE-internal byte order; ParseHex+memcpy).
    uint256 merkle_root = coinbase_txid;
    for (const auto& branch_hex : job->merkle_branches) {
        uint256 b; auto bb = ParseHex(branch_hex);
        if (bb.size() == 32) std::memcpy(b.begin(), bb.data(), 32);
        merkle_root = bch::coin::merkle_hash_pair(merkle_root, b);
    }

    auto prevhash_be = ParseHex(job->gbt_prevhash);
    std::vector<uint8_t> prevhash_le(prevhash_be.rbegin(), prevhash_be.rend());

    std::vector<uint8_t> header; header.reserve(80);
    push_u32_le(header, job->version);
    header.insert(header.end(), prevhash_le.begin(), prevhash_le.end());
    header.insert(header.end(), merkle_root.data(), merkle_root.data() + 32);
    push_u32_le(header, parse_be_hex_u32(ntime));
    push_u32_le(header, parse_be_hex_u32(job->nbits));       // share-target bits in header
    push_u32_le(header, parse_be_hex_u32(nonce));

    uint256 pow_hash = Hash(std::span<const uint8_t>(header.data(), header.size()));

    uint256 share_target;
    if (job->share_bits != 0) share_target.SetCompact(job->share_bits);
    else share_target.SetCompact(/*diff 1*/ 0x1d00ffff);

    uint256 block_target;
    block_target.SetCompact(parse_be_hex_u32(
        job->block_nbits.empty() ? job->nbits : job->block_nbits));

    auto pow_hex_short = pow_hash.GetHex().substr(0, 16);

    // -- Classify --
    if (!(pow_hash > block_target)) {
        // BLOCK FOUND.
        uint32_t height = 0;
        if (auto tip = chain_.tip(); tip) height = tip->height + 1;
        LOG_WARNING << "[BCH-STRATUM-BLOCK] *** BLOCK FOUND *** user=" << username
                    << " height~=" << height << " pow_hash=" << pow_hex_short
                    << " job=" << job_id;

        // Full block: header || tx_count || coinbase || other_txs. BCH has NO
        // SegWit, so the coinbase is serialized as-is (no marker/flag/witness).
        static const std::vector<std::string> kEmptyTxData;
        const std::vector<std::string>& txs = job->tx_data ? *job->tx_data : kEmptyTxData;

        std::vector<uint8_t> block_bytes;
        block_bytes.reserve(80 + 9 + coinbase.size() + txs.size() * 256);
        block_bytes.insert(block_bytes.end(), header.begin(), header.end());
        push_varint(block_bytes, 1 + txs.size());
        block_bytes.insert(block_bytes.end(), coinbase.begin(), coinbase.end());
        for (const auto& tx_hex : txs) {
            auto tx_bytes = ParseHex(tx_hex);
            block_bytes.insert(block_bytes.end(), tx_bytes.begin(), tx_bytes.end());
        }

        // Won block: dual-path broadcast (embedded P2P relay + BCHN-RPC
        // submitblock fallback). submit_block_fn_ returns true iff it reached
        // at least one sink; NEITHER is a loud error (lost subsidy).
        bool reached_network = false;
        if (submit_block_fn_) {
            try { reached_network = submit_block_fn_(block_bytes, height); }
            catch (const std::exception& e) {
                LOG_ERROR << "[BCH-STRATUM-BLOCK] submit_block_fn threw: " << e.what();
            }
            if (!reached_network)
                LOG_ERROR << "[BCH-STRATUM-BLOCK] WON BLOCK height=" << height
                          << " reached NEITHER P2P nor RPC -- lost subsidy!";
        } else {
            LOG_ERROR << "[BCH-STRATUM-BLOCK] no submit_block_fn wired -- WON BLOCK height="
                      << height << " not broadcast -- lost subsidy!";
        }

        {
            std::lock_guard<std::mutex> lk(workers_mutex_);
            for (auto& [sid, w] : workers_) { (void)sid; if (w.username == username) { w.accepted++; break; } }
        }
        return nlohmann::json(true);
    }

    if (!(pow_hash > share_target)) {
        // Share meets sharechain target -> create_share_fn_ (v36 share add).
        CreateShareFn create_fn;
        { std::lock_guard<std::mutex> lk(callback_mutex_); create_fn = create_share_fn_; }

        uint256 share_hash;
        if (create_fn) {
            auto payout_script = core::address_to_script(username);
            try { share_hash = create_fn(coinbase, header, *job, payout_script); }
            catch (const std::exception& e) {
                LOG_WARNING << "[BCH-STRATUM-SHARE] create_share_fn threw: " << e.what()
                            << " -- share not added";
            }
        }

        if (!share_hash.IsNull())
            LOG_INFO << "[BCH-STRATUM-SHARE] ACCEPTED + ADDED user=" << username
                     << " share_hash=" << share_hash.GetHex().substr(0, 16)
                     << " pow_hash=" << pow_hex_short << " job=" << job_id;
        else if (create_fn)
            LOG_INFO << "[BCH-STRATUM-SHARE] accepted (deferred) user=" << username
                     << " pow_hash=" << pow_hex_short << " job=" << job_id;
        else
            LOG_INFO << "[BCH-STRATUM-SHARE] accepted (no-tracker) user=" << username
                     << " pow_hash=" << pow_hex_short << " job=" << job_id;

        {
            std::lock_guard<std::mutex> lk(workers_mutex_);
            for (auto& [sid, w] : workers_) { (void)sid; if (w.username == username) { w.accepted++; break; } }
        }
        return nlohmann::json(true);
    }

    // pow_hash > share_target -> low-difficulty rejection.
    {
        std::lock_guard<std::mutex> lk(workers_mutex_);
        for (auto& [sid, w] : workers_) { (void)sid; if (w.username == username) { w.rejected++; break; } }
    }
    return reject(23, "Low difficulty share");
}

double BCHWorkSource::compute_share_difficulty(
    const std::string& coinb1, const std::string& coinb2,
    const std::string& extranonce1, const std::string& extranonce2,
    const std::string& ntime, const std::string& nonce,
    uint32_t version, const std::string& prevhash_hex,
    const std::string& nbits_hex,
    const std::vector<std::string>& merkle_branches) const
{
    // SHA256d per-submission difficulty (BCH shares the BTC SHA256d PoW
    // family). Reconstruct coinbase -> txid -> merkle ascent -> 80B header
    // -> SHA256d -> target_to_difficulty. NO scrypt, NO SegWit.
    auto coinb1_bytes = ParseHex(coinb1);
    auto en1_bytes    = ParseHex(extranonce1);
    auto en2_bytes    = ParseHex(extranonce2);
    auto coinb2_bytes = ParseHex(coinb2);
    std::vector<uint8_t> coinbase;
    coinbase.reserve(coinb1_bytes.size() + en1_bytes.size() + en2_bytes.size() + coinb2_bytes.size());
    coinbase.insert(coinbase.end(), coinb1_bytes.begin(), coinb1_bytes.end());
    coinbase.insert(coinbase.end(), en1_bytes.begin(),    en1_bytes.end());
    coinbase.insert(coinbase.end(), en2_bytes.begin(),    en2_bytes.end());
    coinbase.insert(coinbase.end(), coinb2_bytes.begin(), coinb2_bytes.end());
    uint256 coinbase_txid = Hash(std::span<const uint8_t>(coinbase.data(), coinbase.size()));

    uint256 merkle_root = coinbase_txid;
    for (const auto& bhex : merkle_branches) {
        uint256 b; auto bb = ParseHex(bhex);
        if (bb.size() == 32) std::memcpy(b.begin(), bb.data(), 32);
        merkle_root = bch::coin::merkle_hash_pair(merkle_root, b);
    }

    auto prevhash_be = ParseHex(prevhash_hex);
    std::vector<uint8_t> prevhash_le(prevhash_be.rbegin(), prevhash_be.rend());
    std::vector<uint8_t> header; header.reserve(80);
    push_u32_le(header, version);
    header.insert(header.end(), prevhash_le.begin(), prevhash_le.end());
    header.insert(header.end(), merkle_root.data(), merkle_root.data() + 32);
    push_u32_le(header, parse_be_hex_u32(ntime));
    push_u32_le(header, parse_be_hex_u32(nbits_hex));
    push_u32_le(header, parse_be_hex_u32(nonce));
    if (header.size() != 80) return 0.0;

    uint256 pow_hash = Hash(std::span<const uint8_t>(header.data(), header.size()));
    if (pow_hash.IsNull()) return 0.0;
    return chain::target_to_difficulty(pow_hash);
}

}  // namespace bch::stratum
