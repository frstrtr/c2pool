// SPDX-License-Identifier: AGPL-3.0-or-later
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
#include <impl/dgb/coin/dgb_block_algo.hpp>
#include <impl/dgb/coin/template_builder.hpp>
#include <impl/dgb/coin/embedded_tx_select.hpp>  // make_mempool_tx_source (mempool -> GBT transactions[])
#include <impl/dgb/config_pool.hpp>              // dgb::PoolConfig::BLOCK_MAX_WEIGHT
#include <impl/dgb/coin/hash_format.hpp>
#include <impl/dgb/coin/scrypt_pow.hpp>        // scrypt_pow_hash (DGB-Scrypt PoW SSOT)
#include <impl/dgb/coin/submit_classify.hpp>   // classify_submission (Stage-4d decision SSOT)
#include <impl/dgb/coin/connection_coinbase.hpp>  // build_connection_coinbase_from_pplns SSOT
#include <impl/dgb/coin/header_sample_build.hpp>// compact_to_target (compact bits -> u256)

#include <core/log.hpp>
#include <core/hash.hpp>                        // Hash (sha256d) for coinbase txid + merkle pair
#include <core/target_utils.hpp>            // chain::target_to_difficulty (vardiff/pool unit parity)
#include <core/address_utils.hpp>              // address_to_script (share payout from username)

#include <btclibs/util/strencodings.h>          // ParseHex

#include <array>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <span>
#include <string>
#include <limits>

namespace dgb::stratum {

namespace {

// previousblockhash big-endian display-hex rendering is the dgb::coin SSOT
// (coin/hash_format.hpp), shared with the embedded work path
// (coin/embedded_coin_node.hpp) so the two build_work_template callers
// cannot emit a divergent previousblockhash encoding.
using dgb::coin::u256_be_display_hex;

// -- Byte-stream helpers for the Stage-4d header/block reconstruction --------
// Little-endian Bitcoin wire encodings, identical to btc::stratum's own
// mining_submit assembly (the DGB header layout is byte-for-byte Bitcoin's;
// only the PoW digest differs -- Scrypt, not SHA256d).
inline void push_u32_le(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(static_cast<uint8_t>( x        & 0xff));
    v.push_back(static_cast<uint8_t>((x >>  8) & 0xff));
    v.push_back(static_cast<uint8_t>((x >> 16) & 0xff));
    v.push_back(static_cast<uint8_t>((x >> 24) & 0xff));
}

inline void push_u64_le(std::vector<uint8_t>& v, uint64_t x) {
    for (int i = 0; i < 8; ++i)
        v.push_back(static_cast<uint8_t>((x >> (i * 8)) & 0xff));
}

inline void push_varint(std::vector<uint8_t>& v, uint64_t n) {
    if (n < 0xfd) {
        v.push_back(static_cast<uint8_t>(n));
    } else if (n <= 0xffff) {
        v.push_back(0xfd);
        v.push_back(static_cast<uint8_t>(n & 0xff));
        v.push_back(static_cast<uint8_t>((n >> 8) & 0xff));
    } else if (n <= 0xffffffff) {
        v.push_back(0xfe);
        push_u32_le(v, static_cast<uint32_t>(n));
    } else {
        v.push_back(0xff);
        push_u64_le(v, n);
    }
}

// Stratum sends ntime/nonce/version as big-endian hex; sscanf(%x) decodes them.
inline uint32_t parse_be_hex_u32(const std::string& s) {
    uint32_t v = 0;
    std::sscanf(s.c_str(), "%x", &v);
    return v;
}

// One merkle ascent step: sha256d(left||right) over the two LE-internal 32-byte
// node hashes (the dgb-local equivalent of btc::coin::merkle_hash_pair -- kept
// in-tree per the per-coin isolation invariant rather than reaching into btc).
inline uint256 merkle_pair(const uint256& left, const uint256& right) {
    return Hash(std::span<const uint8_t>(left.data(),  32),
                std::span<const uint8_t>(right.data(), 32));
}

} // namespace

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
    // Runtime coin tag for coin-agnostic core log lines (#732).
    if (config_.coin_symbol.empty())
        config_.coin_symbol = "DGB";
    // Stable-by-construction hashrate-based vardiff (see DASH). Consensus-neutral
    // (pseudoshare-only). PRE-STAGED — hold until DASH #766 validates live.
    config_.use_hashrate_vardiff = true;
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
    // The tip block id as GBT-conventional big-endian display hex, drawn from
    // the SAME source as get_current_work_template()'s previousblockhash field
    // (chain_.tip_hash(), the #216 HeaderChain accessor) through the SAME
    // u256_be_display_hex formatter -- ONE truthful source, so the dedicated
    // getter and the assembled template can never silently diverge. Empty
    // string when the chain carries no real tip hash (tip_hash() == nullopt:
    // an empty chain, or the block_hash==0 sentinel from the not-yet-wired
    // embedded P2P header ingest) -- a truthful absence, never a fabricated id.
    if (auto th = chain_.tip_hash())
        return u256_be_display_hex(*th);
    // Embedded chain unfed -> external-daemon GBT fallback (the mining.notify
    // prevhash path: stratum_server.cpp get_current_gbt_prevhash caller). Drawn
    // from the SAME single GBT source as get_current_work_template()'s
    // previousblockhash, so the dedicated getter and the assembled template can
    // never diverge. Empty on unbound / no-creds / RPC-failure -- the server
    // then falls back to the best-share hash (its documented empty-prevhash path).
    if (auto tip = resolve_gbt_tip_fallback())
        return tip->previousblockhash;
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
    // Stage 4c (coinbasevalue wire): the full GBT-shaped template
    // (previousblockhash, bits, version, curtime, mintime, transactions[])
    // is assembled by the embedded dgb::coin::TemplateBuilder in a following
    // slice. What lands here is the consensus-bearing reward field: the
    // coinbasevalue for the NEXT block, derived through the #207 SSOT
    // (coinbase_value -> resolve_coinbase_value -> subsidy_func) keyed on the
    // absolute next-block height from the #209 HeaderChain accessor
    // (next_block_height() == tip_height()+1, or base_height for an empty
    // chain). Embedded path: no external-daemon GBT value is plumbed in yet
    // and mempool-fee aggregation is not wired, so total_fees = 0 here. Both
    // compose in later slices WITHOUT changing this SSOT call (a present GBT
    // coinbasevalue stays authoritative; fees add on top of subsidy).
    const uint32_t next_h = chain_.next_block_height();

    // Phase B: feed the served template from the in-process embedded Mempool,
    // mirroring the embedded node path (#248, embedded_coin_node.hpp). The
    // make_mempool_tx_source SSOT selects fee-sorted txs up to BLOCK_MAX_WEIGHT
    // and shapes them into the GBT transactions[] form build_work_template passes
    // through verbatim; their fee total folds into coinbasevalue via the #207
    // resolve_coinbase_value SSOT (NOT added to the template). On today's empty
    // embedded mempool this yields an empty transactions[] and total_fees=0 --
    // byte-identical to the prior coinbase-only template; it lights up unchanged
    // once the embedded P2P mempool feed populates the pool.
    const dgb::coin::EmbeddedTxSelection tx_sel =
        dgb::coin::make_mempool_tx_source(mempool_, dgb::PoolConfig::BLOCK_MAX_WEIGHT)();
    const uint64_t coinbasevalue =
        coinbase_value(next_h, /*total_fees=*/tx_sel.total_fees, /*gbt_coinbasevalue=*/std::nullopt);

    // GBT-scaffold fields the embedded path can derive TRUTHFULLY from current
    // chain state, ahead of a full dgb::coin::TemplateBuilder port (M3 TODO):
    //   version      — BIP9 base | the DGB Scrypt algo nibble. A DGB block
    //                  template MUST pin the Scrypt lane: the mining algo lives
    //                  in 4 nVersion bits (coin/dgb_block_algo.hpp SSOT) and
    //                  Scrypt is the all-zero codepoint (DGB_BLOCK_VERSION_SCRYPT
    //                  == 0x0000); any other nibble is a non-Scrypt algo that is
    //                  accept-by-continuity / V37 here, never a template we emit.
    //   curtime      — current wall-clock; GBT's suggested header nTime.
    //   mintime      — median_time_past()+1 (#209 accessor): DGB Core's
    //                  ContextualCheckBlockHeader lower bound (nTime > MTP). An
    //                  empty chain returns INT64_MIN (unconstrained) -> emit 0.
    //   transactions — fee-sorted mempool selection via make_mempool_tx_source
    //                  (BLOCK_MAX_WEIGHT cap), shaped into GBT {data,txid,hash,fee}
    //                  objects; their fee total folds into the coinbasevalue above
    //                  (#207 SSOT). Empty embedded mempool -> empty array, fees 0.
    //
    // previousblockhash — the tip block id. Emitted ONLY when the HeaderChain
    //                  carries a real tip hash (tip_hash() accessor): the
    //                  Scrypt-only HeaderSample now carries a block_hash slot,
    //                  but the embedded P2P header-download -> validate_and_append
    //                  ingest that POPULATES it lands in a following slice, so on
    //                  today's chain state tip_hash() is nullopt and the field is
    //                  held back -- a truthful absence, never a fabricated hash.
    // bits          — HELD BACK. The only embedded next-target source is the
    //                  DigiShield/MultiShield damped multiply, which DGB Core
    //                  runs as MultiShield V4: a GLOBAL window across all 5 algos
    //                  with per-algo adjust + MTP deltas. A Scrypt-only header
    //                  walk cannot reconstruct that window (== V37, 5-algo
    //                  validation), so the ingest path deliberately demotes the
    //                  retarget gate to a no-op (see header_chain.hpp). Emitting
    //                  a digishield_next_target()-derived bits would be a
    //                  KNOWN-WRONG value -- the same fabrication the empty
    //                  transactions[] and total_fees=0 avoid. The authoritative
    //                  bits is the external-daemon GBT value. WorkTemplateInputs
    //                  now carries an optional bits field (template_builder.hpp),
    //                  so the plumb EXISTS: a daemon-GBT caller or the G1 replay
    //                  harness sets in.bits and the builder emits it. This
    //                  embedded Scrypt-only path still supplies none -- truthful
    //                  absence, identical to previousblockhash -- so bits stays
    //                  absent here until a daemon source is wired into this path.
    // and the per-connection coinbase (gentx + ShareTracker ref_hash + PPLNS
    // payout map) assembles in build_connection_coinbase() — that output is
    // consensus-bearing and surfaces for an operator tap, not in this field wire.
    // Shape the truthfully-derivable fields into the GBT template via the
    // dgb::coin::build_work_template SSOT so the embedded path and this work
    // source emit one template (Stage 4c extraction). version (Scrypt lane
    // pin), mintime (MTP+1 / 0 on empty chain), curtime, empty transactions[]
    // and the conditional previousblockhash all live in the builder now; this
    // method only resolves the chain-state inputs.
    dgb::coin::WorkTemplateInputs in;
    in.next_height       = next_h;
    in.coinbasevalue     = coinbasevalue;
    in.median_time_past  = chain_.median_time_past();
    in.curtime           = static_cast<int64_t>(std::time(nullptr));
    in.transactions      = tx_sel.transactions;
    if (auto th = chain_.tip_hash()) {
        // Embedded chain carries a real tip -> source previousblockhash from it.
        // bits stays absent here: the Scrypt-only walk cannot reconstruct the
        // MultiShield-V4 5-algo window (== V37) -- unchanged truthful absence.
        in.previousblockhash = u256_be_display_hex(*th);
    } else if (auto tip = resolve_gbt_tip_fallback()) {
        // Embedded HeaderChain unfed -> external-daemon GBT fallback (persist per
        // V36). Sources BOTH previousblockhash and the daemon-authoritative bits
        // from ONE getblocktemplate snapshot (consistent height). Unbound / no
        // creds / RPC failure -> both stay absent, byte-identical to before.
        in.previousblockhash = tip->previousblockhash;
        in.bits              = tip->bits;
    }

    return dgb::coin::build_work_template(in);
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
    const uint256& prev_share_hash,
    const std::string& extranonce1_hex,
    const std::vector<unsigned char>& payout_script,
    const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& merged_addrs) const
{
    // Phase B live-wire: delegate to the PPLNS->coinbase SSOT
    // (build_connection_coinbase_from_pplns), which itself routes through the
    // single compute_pplns_payout_split() the verifier uses -- so the coinbase a
    // miner hashes here is byte-identical to the one generate_share_transaction()
    // enforces, by construction (no second payout implementation to keep in sync).
    //
    // The PPLNS inputs (weight map walked from the ShareTracker, ref_hash,
    // subsidy, donation script) are produced by the seam bound in main_dgb.cpp
    // -- the tracker walk lives there, not in the work source. While the seam is
    // UNBOUND (or returns nullopt) this is byte-identical to the pre-wire stub:
    // an empty result, so the session pushes no work (safe, non-functional).
    PplnsInputsFn fn;
    {
        std::lock_guard<std::mutex> lk(pplns_inputs_mutex_);
        fn = pplns_inputs_fn_;  // copy under lock; a concurrent set_*_fn() cannot
                                // tear it out mid-call.
    }
    if (!fn)
        return {};  // unbound: pre-wire behavior (empty job).

    std::optional<dgb::coin::ConnCoinbasePplnsInputs> inputs =
        fn(prev_share_hash, extranonce1_hex, payout_script, merged_addrs);
    if (!inputs)
        return {};  // producer declined (e.g. tip not yet known) -> safe empty job.

    dgb::coin::ConnCoinbaseParts parts =
        dgb::coin::build_connection_coinbase_from_pplns(*inputs);

    core::stratum::CoinbaseResult out;
    out.coinb1 = std::move(parts.coinb1);
    out.coinb2 = std::move(parts.coinb2);
    // Freeze the consensus-bearing ref fields the submit path (mining_submit)
    // re-derives the won-block reconstruct from; the remaining snapshot fields
    // (merkle_branches / segwit) are populated by the template-cache follow-on.
    out.snapshot.subsidy                   = inputs->subsidy;
    out.snapshot.frozen_ref.ref_hash       = inputs->ref_hash;
    out.snapshot.frozen_ref.last_txout_nonce = inputs->last_txout_nonce;
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// IWorkSource: share submission — Stage 4d (the hot path).
// ─────────────────────────────────────────────────────────────────────────────

nlohmann::json DGBWorkSource::mining_submit(
    const std::string& username, const std::string& job_id,
    const std::string& extranonce1, const std::string& extranonce2,
    const std::string& ntime, const std::string& nonce,
    const std::string& /*request_id*/,
    const std::map<uint32_t, std::vector<unsigned char>>& /*merged_addresses*/,
    const core::stratum::JobSnapshot* job)
{
    // Stage 4d -- the hot path. Reconstruct the 80-byte block header from the
    // JobSnapshot + miner inputs, run the DGB-Scrypt PoW digest, and place the
    // result in EXACTLY ONE of three classes via the decision SSOT
    // (coin/submit_classify.hpp): WonBlock -> dual-path broadcaster (#82),
    // ShareAccept -> sharechain mint (try_mint_share -> #294), Reject -> stratum
    // low-difficulty error. The header assembly mirrors btc::stratum byte-for-
    // byte (the DGB header layout IS Bitcoin's); ONLY the PoW digest differs
    // (scrypt_1024_1_1_256, the sole algo c2pool-dgb validates in V36).

    // Stratum JSON-RPC error payload (false + [code, message, null]).
    auto reject = [](int code, const char* msg) {
        return nlohmann::json::array({
            false, nlohmann::json::array({code, msg, nullptr})
        });
    };

    if (!job) {
        LOG_WARNING << "[DGB-STRATUM] submit reject (no JobSnapshot): user=" << username
                    << " job=" << job_id;
        return reject(21, "Job not found");
    }

    // 1. coinbase = coinb1 || extranonce1 || extranonce2 || coinb2
    auto coinb1_bytes = ParseHex(job->coinb1);
    auto en1_bytes    = ParseHex(extranonce1);
    auto en2_bytes    = ParseHex(extranonce2);
    auto coinb2_bytes = ParseHex(job->coinb2);

    std::vector<uint8_t> coinbase;
    coinbase.reserve(coinb1_bytes.size() + en1_bytes.size()
                     + en2_bytes.size() + coinb2_bytes.size());
    coinbase.insert(coinbase.end(), coinb1_bytes.begin(), coinb1_bytes.end());
    coinbase.insert(coinbase.end(), en1_bytes.begin(),    en1_bytes.end());
    coinbase.insert(coinbase.end(), en2_bytes.begin(),    en2_bytes.end());
    coinbase.insert(coinbase.end(), coinb2_bytes.begin(), coinb2_bytes.end());

    // 2. coinbase_txid = sha256d(coinbase) (non-witness txid for the merkle root)
    uint256 coinbase_txid = Hash(
        std::span<const uint8_t>(coinbase.data(), coinbase.size()));

    // 3. merkle_root = ascend the frozen stratum merkle branches from the txid.
    //    Branches are LE-internal bytes (ParseHex+memcpy, NOT SetHex which
    //    reverses). Keep the parsed branches to hand to the share-mint path.
    std::vector<uint256> branch_hashes;
    branch_hashes.reserve(job->merkle_branches.size());
    uint256 merkle_root = coinbase_txid;
    for (const auto& branch_hex : job->merkle_branches) {
        uint256 b;
        auto bb = ParseHex(branch_hex);
        if (bb.size() == 32) std::memcpy(b.begin(), bb.data(), 32);
        branch_hashes.push_back(b);
        merkle_root = merkle_pair(merkle_root, b);
    }

    // 4. header = version(LE) || prev(LE) || merkle_root || ntime(LE)
    //             || nbits(LE) || nonce(LE)  -- prevhash arrives BE-display, so
    //    reverse to internal byte order.
    auto prevhash_be = ParseHex(job->gbt_prevhash);
    std::vector<uint8_t> prevhash_le(prevhash_be.rbegin(), prevhash_be.rend());

    std::vector<uint8_t> header;
    header.reserve(80);
    push_u32_le(header, job->version);
    header.insert(header.end(), prevhash_le.begin(), prevhash_le.end());
    header.insert(header.end(), merkle_root.data(), merkle_root.data() + 32);
    push_u32_le(header, parse_be_hex_u32(ntime));
    push_u32_le(header, parse_be_hex_u32(job->nbits));   // header carries share bits
    push_u32_le(header, parse_be_hex_u32(nonce));

    if (header.size() != 80) {
        LOG_WARNING << "[DGB-STRATUM] submit reject (reconstructed header "
                    << header.size() << "B != 80): user=" << username
                    << " job=" << job_id;
        return reject(20, "Malformed header reconstruction");
    }

    // 5. DGB-Scrypt PoW digest (scrypt_1024_1_1_256, the ONLY algo V36 validates).
    dgb::coin::u256 pow_hash = dgb::coin::scrypt_pow_hash(header.data());

    // Expand both compact targets to u256 (compact_to_target SSOT). Fall back to
    // a permissive diff-1 share target for jobs frozen before share_bits was set
    // so a missing share target never silently rejects every share.
    dgb::coin::u256 share_target = c2pool::dgb::compact_to_target(
        job->share_bits != 0 ? job->share_bits : 0x1d00ffffu);
    dgb::coin::u256 block_target = c2pool::dgb::compact_to_target(parse_be_hex_u32(
        job->block_nbits.empty() ? job->nbits : job->block_nbits));

    // 6. Classify via the Stage-4d SSOT (tighten-first: block target before share).
    const dgb::coin::SubmitClass klass =
        dgb::coin::classify_submission(pow_hash, block_target, share_target);

    auto bump_accepted = [&] {
        std::lock_guard<std::mutex> lk(workers_mutex_);
        for (auto& kv : workers_) {
            if (kv.second.username == username) { kv.second.accepted++; break; }
        }
    };

    switch (klass) {
    case dgb::coin::SubmitClass::WonBlock: {
        // pow_hash <= block_target -> a full network block. NEVER drop it.
        const uint32_t height = chain_.next_block_height();
        LOG_WARNING << "[DGB-STRATUM-BLOCK] *** BLOCK FOUND *** user=" << username
                    << " height~=" << height << " job=" << job_id;

        // Serialize the block: header || tx_count || coinbase[+witness] || txs.
        // A segwit-active coinbase is reserialized in BIP144 form with the
        // 32-byte witness reserved value (digibyted validates the aa21a9ed
        // commitment by hashing witness_root||reserved; a missing witness ->
        // bad-witness-merkle-match -> block rejected).
        std::vector<uint8_t> coinbase_serialized = coinbase;
        if (job->segwit_active) {
            const std::array<uint8_t, 2> marker_flag = {0x00, 0x01};
            coinbase_serialized.insert(coinbase_serialized.begin() + 4,
                marker_flag.begin(), marker_flag.end());
            std::array<uint8_t, 34> witness_bytes{};
            witness_bytes[0] = 0x01;  // stack_count = 1
            witness_bytes[1] = 0x20;  // item_len    = 32 (reserved value, all zero)
            coinbase_serialized.insert(coinbase_serialized.end() - 4,
                witness_bytes.begin(), witness_bytes.end());
        }

        static const std::vector<std::string> kEmptyTxData;
        const std::vector<std::string>& txs =
            job->tx_data ? *job->tx_data : kEmptyTxData;

        std::vector<uint8_t> block_bytes;
        block_bytes.reserve(80 + 9 + coinbase_serialized.size() + txs.size() * 256);
        block_bytes.insert(block_bytes.end(), header.begin(), header.end());
        push_varint(block_bytes, 1 + txs.size());   // total tx count (coinbase + others)
        block_bytes.insert(block_bytes.end(),
            coinbase_serialized.begin(), coinbase_serialized.end());
        for (const auto& tx_hex : txs) {
            auto tx_bytes = ParseHex(tx_hex);
            block_bytes.insert(block_bytes.end(), tx_bytes.begin(), tx_bytes.end());
        }

        // Dual-path broadcaster (#82): submit_block_fn_ relays via P2P (primary)
        // and falls back to the submitblock RPC; true iff it reached >=1 sink. A
        // won block reaching NEITHER is a lost subsidy -- scream, never drop.
        bool reached_network = false;
        if (submit_block_fn_) {
            try {
                reached_network = submit_block_fn_(block_bytes, height);
            } catch (const std::exception& e) {
                LOG_ERROR << "[DGB-STRATUM-BLOCK] submit_block_fn threw: " << e.what();
            }
            if (!reached_network) {
                LOG_ERROR << "[DGB-STRATUM-BLOCK] WON BLOCK height=" << height
                          << " reached NEITHER P2P relay NOR submitblock RPC -- "
                          << "lost subsidy!";
            }
        } else {
            LOG_ERROR << "[DGB-STRATUM-BLOCK] no submit_block_fn wired -- WON BLOCK"
                      << " height=" << height << " not broadcast -- lost subsidy!";
        }

        bump_accepted();
        return nlohmann::json(true);
    }

    case dgb::coin::SubmitClass::ShareAccept: {
        // share_target >= pow_hash > block_target -> meets sharechain difficulty
        // but not the full block. Hand the found-share fields to the run-loop
        // mint dispatch (try_mint_share -> mint_local_share_with_ratchet, #294).
        MintShareInputs in;
        in.header_bytes    = header;
        in.coinbase_bytes  = coinbase;
        in.subsidy         = job->subsidy;
        in.prev_share      = job->prev_share_hash;
        in.merkle_branches = branch_hashes;
        in.payout_script   = core::address_to_script(username);
        // Redistribute V2 (#307): a miner with empty/broken stratum creds
        // yields no payout script. When the operator opted into a
        // --redistribute policy (fallback bound) let it choose the pubkey this
        // node stamps onto the minted share; else leave it empty (byte-
        // identical to before). Fail-safe: an empty fallback is left empty.
        if (in.payout_script.empty()) {
            FallbackPayoutFn fb;
            { std::lock_guard<std::mutex> lk(fallback_payout_mutex_); fb = fallback_payout_fn_; }
            if (fb) {
                in.payout_script = fb();
                if (!in.payout_script.empty())
                    LOG_INFO << "[DGB-STRATUM-SHARE] empty payout addr (user=" << username
                             << ") -> redistribute policy stamped fallback script ("
                             << in.payout_script.size() << "B)";
            }
        }
        in.segwit_active   = job->segwit_active;

        uint256 share_hash = try_mint_share(in);

        if (!share_hash.IsNull()) {
            LOG_INFO << "[DGB-STRATUM-SHARE] ACCEPTED + MINTED user=" << username
                     << " share_hash=" << share_hash.GetHex().substr(0, 16)
                     << " job=" << job_id;
        } else {
            // PoW was valid (cleared the share target) so the miner still gets a
            // success reply; the share just earned no sharechain credit (no mint
            // fn wired, or the mint deferred/failed). try_mint_share logs the
            // reason -- never a silent drop.
            LOG_INFO << "[DGB-STRATUM-SHARE] accepted (no sharechain credit) user="
                     << username << " job=" << job_id;
        }

        bump_accepted();
        return nlohmann::json(true);
    }

    case dgb::coin::SubmitClass::Reject:
    default:
        return reject(23, "Low difficulty share");
    }
}
double DGBWorkSource::compute_share_difficulty(
    const std::string& coinb1, const std::string& coinb2,
    const std::string& extranonce1, const std::string& extranonce2,
    const std::string& ntime, const std::string& nonce,
    uint32_t version, const std::string& prevhash_hex,
    const std::string& nbits_hex,
    const std::vector<std::string>& merkle_branches) const
{
    // Stage 4b/4c LIVE: reconstruct the 80-byte header EXACTLY as mining_submit
    // does (coinb1||en1||en2||coinb2 -> sha256d txid -> ascend merkle branches ->
    // header), run the DGB-Scrypt digest (scrypt_1024_1_1_256, the sole algo V36
    // validates), and return the achieved difficulty in the SAME unit the coin-
    // agnostic StratumServer vardiff/pool gate uses (chain::target_to_difficulty,
    // diff-1 == 0x1d00ffff). A malformed reconstruct (bad hex -> header != 80B)
    // returns the documented 0.0 not-scored sentinel, which the gate treats as a
    // hard reject -- so no garbage difficulty leaks into the rate monitor.

    // 1. coinbase = coinb1 || extranonce1 || extranonce2 || coinb2
    auto coinb1_bytes = ParseHex(coinb1);
    auto en1_bytes    = ParseHex(extranonce1);
    auto en2_bytes    = ParseHex(extranonce2);
    auto coinb2_bytes = ParseHex(coinb2);

    std::vector<uint8_t> coinbase;
    coinbase.reserve(coinb1_bytes.size() + en1_bytes.size()
                     + en2_bytes.size() + coinb2_bytes.size());
    coinbase.insert(coinbase.end(), coinb1_bytes.begin(), coinb1_bytes.end());
    coinbase.insert(coinbase.end(), en1_bytes.begin(),    en1_bytes.end());
    coinbase.insert(coinbase.end(), en2_bytes.begin(),    en2_bytes.end());
    coinbase.insert(coinbase.end(), coinb2_bytes.begin(), coinb2_bytes.end());

    // 2. coinbase_txid = sha256d(coinbase) (non-witness txid for the merkle root)
    uint256 coinbase_txid = Hash(
        std::span<const uint8_t>(coinbase.data(), coinbase.size()));

    // 3. merkle_root = ascend the frozen stratum merkle branches (LE-internal).
    uint256 merkle_root = coinbase_txid;
    for (const auto& branch_hex : merkle_branches) {
        uint256 b;
        auto bb = ParseHex(branch_hex);
        if (bb.size() == 32) std::memcpy(b.begin(), bb.data(), 32);
        merkle_root = merkle_pair(merkle_root, b);
    }

    // 4. header = version(LE) || prev(LE) || merkle_root || ntime(LE)
    //             || nbits(LE) || nonce(LE); prevhash arrives BE-display, so
    //    reverse to internal byte order (mirrors mining_submit byte-for-byte).
    auto prevhash_be = ParseHex(prevhash_hex);
    std::vector<uint8_t> prevhash_le(prevhash_be.rbegin(), prevhash_be.rend());

    std::vector<uint8_t> header;
    header.reserve(80);
    push_u32_le(header, version);
    header.insert(header.end(), prevhash_le.begin(), prevhash_le.end());
    header.insert(header.end(), merkle_root.data(), merkle_root.data() + 32);
    push_u32_le(header, parse_be_hex_u32(ntime));
    push_u32_le(header, parse_be_hex_u32(nbits_hex));   // share target bits
    push_u32_le(header, parse_be_hex_u32(nonce));

    if (header.size() != 80)
        return 0.0;  // malformed reconstruct -> not-scored sentinel (hard reject).

    // 5. DGB-Scrypt PoW digest, then difficulty relative to diff-1. Bridge the
    //    coin-space u256 into core uint256 via the u256_be_display_hex SSOT so
    //    the number is unit-identical to required_difficulty / pool_difficulty
    //    (both computed through chain::target_to_difficulty on the core side).
    dgb::coin::u256 pow_hash = dgb::coin::scrypt_pow_hash(header.data());
    uint256 pow_core;
    pow_core.SetHex(dgb::coin::u256_be_display_hex(pow_hash));
    return chain::target_to_difficulty(pow_core);
}

// ─────────────────────────────────────────────────────────────────────────────
// DGB-specific control surface
// ─────────────────────────────────────────────────────────────────────────────

void DGBWorkSource::set_best_share_hash_fn(std::function<uint256()> fn)
{
    std::lock_guard<std::mutex> lk(best_share_mutex_);
    best_share_hash_fn_ = std::move(fn);
}

void DGBWorkSource::set_mint_share_fn(MintShareFn fn)
{
    std::lock_guard<std::mutex> lk(mint_share_mutex_);
    mint_share_fn_ = std::move(fn);
}

void DGBWorkSource::set_fallback_payout_fn(FallbackPayoutFn fn)
{
    std::lock_guard<std::mutex> lk(fallback_payout_mutex_);
    fallback_payout_fn_ = std::move(fn);
}

void DGBWorkSource::set_pplns_inputs_fn(PplnsInputsFn fn)
{
    std::lock_guard<std::mutex> lk(pplns_inputs_mutex_);
    pplns_inputs_fn_ = std::move(fn);
}

void DGBWorkSource::set_gbt_tip_fn(GbtTipFn fn)
{
    std::lock_guard<std::mutex> lk(gbt_tip_mutex_);
    gbt_tip_fn_ = std::move(fn);
    gbt_tip_cache_.reset();     // drop any stale cache when the seam is (re)bound
    gbt_tip_cache_time_ = 0;
}

std::optional<DGBWorkSource::GbtTip> DGBWorkSource::resolve_gbt_tip_fallback() const
{
    // Copy the seam + serve a fresh-enough cache under the lock; run the blocking
    // RPC round-trip OUTSIDE the lock (single io_context thread today, but never
    // hold a lock across network IO). TTL-bound so per-heartbeat template/prevhash
    // polls do not each trigger a getblocktemplate round-trip.
    GbtTipFn fn;
    const int64_t now = static_cast<int64_t>(std::time(nullptr));
    {
        std::lock_guard<std::mutex> lk(gbt_tip_mutex_);
        if (gbt_tip_cache_ && (now - gbt_tip_cache_time_) < GBT_TIP_TTL_SECONDS)
            return gbt_tip_cache_;
        fn = gbt_tip_fn_;  // copy so a concurrent set_gbt_tip_fn() cannot tear it out
    }
    if (!fn)
        return std::nullopt;   // unbound (no digibyted creds armed) -> truthful absence

    std::optional<GbtTip> tip = fn();   // blocking getblocktemplate; nullopt on RPC failure
    if (tip) {
        std::lock_guard<std::mutex> lk(gbt_tip_mutex_);
        gbt_tip_cache_      = tip;
        gbt_tip_cache_time_ = now;
    }
    return tip;
}

uint256 DGBWorkSource::try_mint_share(const MintShareInputs& in) const
{
    MintShareFn fn;
    {
        std::lock_guard<std::mutex> lk(mint_share_mutex_);
        fn = mint_share_fn_;  // copy so a concurrent set cannot tear it out mid-call
    }
    if (!fn) {
        LOG_WARNING << "[DGB-STRATUM] share met share-target but no mint callback "
                       "wired -- share NOT recorded (set_mint_share_fn unbound). "
                       "No silent drop: logged.";
        return uint256{};
    }
    return fn(in);
}

}  // namespace dgb::stratum