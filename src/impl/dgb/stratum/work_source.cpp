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
#include <impl/dgb/stratum_start_difficulty.hpp>   // dgb_start_difficulty (VARDIFF item 2)

#include <impl/dgb/coin/header_chain.hpp>
#include <impl/dgb/coin/mempool.hpp>
#include <impl/dgb/coin/embedded_coinbase_value.hpp>
#include <impl/dgb/coin/dgb_block_algo.hpp>
#include <impl/dgb/coin/template_builder.hpp>
#include <impl/dgb/coin/embedded_tx_select.hpp>  // make_mempool_tx_source (mempool -> GBT transactions[])
#include <impl/dgb/config_pool.hpp>              // dgb::PoolConfig::BLOCK_MAX_WEIGHT
#include <impl/dgb/params.hpp>                   // dgb::address_acceptance (#961 registry-sourced payout check)
#include <impl/dgb/coin/hash_format.hpp>
#include <impl/dgb/coin/scrypt_pow.hpp>        // scrypt_pow_hash (DGB-Scrypt PoW SSOT)
#include <impl/dgb/coin/submit_classify.hpp>   // classify_submission (Stage-4d decision SSOT)
#include <impl/dgb/coin/connection_coinbase.hpp>  // build_connection_coinbase_from_pplns SSOT
#include <c2pool/merged/merged_mining.hpp>       // MergedMiningManager (--merged DOGE aux backend)
#include <impl/dgb/coin/aux_doge_mm_commitment.hpp>  // AUX_MM_COMMITMENT_SIZE (44-byte MM blob)
#include <impl/dgb/coin/won_block_serialize.hpp>   // serialize_won_block SSOT (won-block framing)
#include <impl/dgb/coin/header_sample_build.hpp>// compact_to_target (compact bits -> u256)

#include <core/log.hpp>
#include <core/hash.hpp>                        // Hash (sha256d) for coinbase txid + merkle pair
#include <core/target_utils.hpp>            // chain::target_to_difficulty (vardiff/pool unit parity)
#include <core/address_utils.hpp>              // address_to_script (share payout from username)

#include <btclibs/base58.h>                      // DecodeBase58Check
#include <btclibs/util/strencodings.h>          // ParseHex, HexStr
#include <btclibs/span.h>                       // Span (HexStr arg)

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <ctime>
#include <span>
#include <string>
#include <limits>

namespace dgb::stratum {

namespace {
constexpr uint32_t kDogeChainId = 98;   // the DOGE AuxPoW chain id (--merged DOGE:98)
constexpr uint64_t kDustThreshold = 100000;   // DUST_THRESHOLD 0.001 DGB (params.hpp p.dust_threshold)
} // namespace

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

// Extract the coinbase scriptSig from a reconstructed coinbase TRANSACTION.
// The mint seam (create_local_share) stores the scriptSig in share.m_coinbase,
// which share_init_verify bounds to 2..100 bytes -- so the mint MUST be handed
// the scriptSig, NOT the full gentx. Coinbase tx layout (gentx_coinbase.hpp):
//   version(4) | vin_count(1=0x01) | prev_hash(32) | prev_idx(4) |
//   scriptSig(varint len + bytes) | sequence(4) | ...
// so the scriptSig length varint sits at fixed offset 41. The 8-byte extranonce
// lands in the OP_RETURN nonce slot near the tail (connection_coinbase.hpp),
// never in the scriptSig, so the bytes recovered here are exactly the scriptSig
// the producer froze at template time -- which is what keeps the mint's
// recomputed ref_hash equal to the one the miner's coinbase committed to.
inline std::vector<unsigned char>
extract_coinbase_scriptsig(const std::vector<uint8_t>& coinbase_tx) {
    constexpr size_t kScriptOffset = 4 + 1 + 32 + 4;  // = 41
    if (coinbase_tx.size() < kScriptOffset + 1)
        return {};  // truncated -> empty (fail-closed; mint declines on size<2)
    size_t off = kScriptOffset;
    uint64_t len = coinbase_tx[off++];
    // A coinbase scriptSig is consensus-capped at 100 bytes, so its length is
    // always a single-byte varint (< 0xfd). Handle the wider markers only to
    // stay well-formed against a malformed buffer.
    if (len == 0xfd) {
        if (off + 2 > coinbase_tx.size()) return {};
        len = static_cast<uint64_t>(coinbase_tx[off])
            | (static_cast<uint64_t>(coinbase_tx[off + 1]) << 8);
        off += 2;
    } else if (len >= 0xfe) {
        return {};  // implausible for a coinbase scriptSig -> fail-closed
    }
    if (off + len > coinbase_tx.size())
        return {};  // length overruns the buffer -> fail-closed
    return std::vector<unsigned char>(coinbase_tx.begin() + off,
                                      coinbase_tx.begin() + off + len);
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
    // Idle keepalive-notify (cross-coin reuse of DASH's D9 mitigation): many
    // ASIC/proxy clients drop a pool connection that receives no mining.notify
    // within ~60 s. Re-notify the CURRENT job (non-clean, so no ASIC work reset
    // and NO work-generation bump) every 25 s -- comfortably under any
    // reasonable client watchdog -- so idle DGB sessions stay stable backups.
    // Transport/liveness only; ZERO wire-byte and consensus change.
    config_.keepalive_notify_sec = 25;
    // A repeated submit of the same header on a job is refused with error 22
    // (p2pool / kr1z1s work.py received_header_hashes).
    config_.reject_duplicate_submits = true;
    // Session hygiene, the LTC / BTC / DASH profile (ltc/stratum_defaults.hpp):
    // a NAT-dropped rig's half-open socket and a client that connects and
    // never authorizes would each hold a slot forever, until the node refuses
    // every real miner at max_stratum_connections. Transport/liveness only.
    config_.tcp_keepalive_enabled      = true;   // kernel probes dead NAT paths
    config_.tcp_keepalive_idle_sec     = 60;
    config_.tcp_keepalive_interval_sec = 10;
    config_.tcp_keepalive_count        = 3;
    config_.handshake_timeout_sec      = 30;     // drop a connection that never authorizes
    config_.session_idle_timeout_sec   = 1800;   // backstop; never reaps an authorized session with keepalive on
    config_.max_write_queue_depth      = 256;    // drop a peer that stopped reading
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

bool DGBWorkSource::embedded_chain_serves() const
{
    // The one template-source choice (reviews 906a0e5e3 #4, dd1248abd #5,
    // 7793bfb6c #2), read by the template, the prevhash getter and the work
    // gate: the embedded header chain once it has a tip and has reached it.
    // While it syncs, its template is for an old height and prevhash. A latch,
    // as a node's initial block download: once at its tip it stays so (a
    // quiet network never holds work again; a lost digibyted is the work
    // gate's, stratum_work_gate.hpp).
    if (!chain_.tip_hash())
        return false;
    const uint32_t recent = tip_recent_sec_.load();
    if (recent == 0 || tip_latched_.load())
        return true;
    const int64_t age = static_cast<int64_t>(std::time(nullptr)) - chain_.median_time_past();
    if (age > static_cast<int64_t>(recent))
        return false;
    tip_latched_.store(true);
    if (tip_state_.exchange(1) != 1)
        LOG_INFO << "[DGB-STRATUM] header chain at its tip (median time " << age << " s old): serving work from it";
    return true;
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
    // The same source choice as the template (embedded_chain_serves): while
    // the embedded chain is behind its tip, the job push follows digibyted's
    // tip, not the syncing chain's.
    if (embedded_chain_serves())
        if (auto th = chain_.tip_hash())
            return u256_be_display_hex(*th);
    // Embedded chain unfed (or behind) -> external-daemon GBT fallback (the mining.notify
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

bool DGBWorkSource::has_merged_chain(uint32_t chain_id) const
{
    // The merged-mining manager main_dgb binds for --merged DOGE decides (as
    // btc work_source.cpp has_merged_chain). No manager (standalone DGB, or
    // no --merged) or a chain it does not mine => false. True arms the core
    // stratum login resolution for that chain: the "DGB,DOGE" login form, the
    // DOGE address auto-derived from the primary's key, and the #961 door
    // accepting the chain's addresses (stratum_server.cpp, merged_chain_addr.hpp).
    return mm_manager_ != nullptr && mm_manager_->has_chain(chain_id);
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

void DGBWorkSource::set_work_hold(const std::string& reason)
{
    std::lock_guard<std::mutex> lk(work_hold_mutex_);
    if (reason == work_hold_)
        return;
    if (!reason.empty())
        LOG_WARNING << "[DGB-STRATUM] work held, miners refused: " << reason;
    else
        LOG_INFO << "[DGB-STRATUM] work hold over (" << work_hold_ << "): serving work";
    work_hold_ = reason;
}

std::string DGBWorkSource::work_hold() const
{
    std::lock_guard<std::mutex> lk(work_hold_mutex_);
    return work_hold_;
}

nlohmann::json DGBWorkSource::get_current_work_template() const
{
    // The work gate (no sharechain peers, lost contact with digibyted): no
    // template, so the stratum layer sends no job.
    if (!work_hold().empty())
        return nlohmann::json::object();
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
    // The template's block: the embedded header chain's tip, or digibyted's
    // getblocktemplate (the GBT fallback) when the chain is unfed or, during
    // its initial sync, behind its tip.
    bool from_gbt = false;
    bool embedded_behind = false;
    if (auto th = chain_.tip_hash()) {
        // #179: derive the block-template bits from the synced header chain via
        // DigiByte-Core MultiShield V4 (chain_.next_scrypt_bits()), replacing the
        // fabricated diff-1 (0x1d00ffff) that made every won block INVALID and
        // every sharechain share weigh against a fake coin target. The V4 walk is
        // GLOBAL across all 5 algos and the header chain carries every algo's
        // header (continuity headers appended work-neutral), so the window is
        // fully present. When it is too shallow to run (< 61 headers) the accessor
        // returns nullopt: emit an EMPTY template so the stratum layer takes its
        // existing "waiting for block template (header sync)" wait path instead of
        // fabricating -- fail-closed, never a known-wrong target on the wire.
        auto nb = chain_.next_scrypt_bits();
        if (!nb)
            return nlohmann::json::object();  // hold work until the window fills.
        // Work from the embedded chain only once it is at its tip
        // (embedded_chain_serves); behind: digibyted's template when the GBT
        // fallback is bound, else no work.
        embedded_behind = !embedded_chain_serves();
        if (!embedded_behind) {
            // Embedded chain carries a real tip -> source previousblockhash from it.
            in.previousblockhash = u256_be_display_hex(*th);
            char bits_buf[9];
            std::snprintf(bits_buf, sizeof(bits_buf), "%08x", *nb);
            in.bits = std::string(bits_buf);
        }
    }
    if (!in.previousblockhash) {
        // Embedded HeaderChain unfed (or behind) -> external-daemon GBT fallback
        // (persist per V36). Sources previousblockhash, the daemon-authoritative
        // bits AND the height from ONE getblocktemplate snapshot; the empty
        // header chain has no height (next_block_height() would be its base, 0).
        // No height: no work. Unbound / no creds / RPC failure -> all absent.
        auto tip = resolve_gbt_tip_fallback();
        if (tip && tip->height != 0) {
            in.previousblockhash = tip->previousblockhash;
            in.bits              = tip->bits;
            in.next_height       = tip->height;
            in.coinbasevalue     = coinbase_value(tip->height, tx_sel.total_fees, std::nullopt);
            from_gbt = true;
        } else if (tip || embedded_behind) {
            if (embedded_behind && tip_state_.exchange(0) != 0)
                LOG_WARNING << "[DGB-STRATUM] header chain behind its tip (median time "
                            << (static_cast<int64_t>(std::time(nullptr)) - chain_.median_time_past())
                            << " s old > " << tip_recent_sec_.load() << " s) and no digibyted template:"
                               " work held until it syncs";
            return nlohmann::json::object();
        }
    }
    if (embedded_behind && from_gbt && tip_state_.exchange(2) != 2)
        LOG_WARNING << "[DGB-STRATUM] header chain behind its tip: serving digibyted's template until it syncs";

    nlohmann::json t = dgb::coin::build_work_template(in);
    // The dashboard's summary of the template served (last_template_summary).
    // Display only: never lets the work path fail.
    try {
        if (t.contains("bits") && t["bits"].is_string() && t.contains("height")) {
            TemplateSummary sum;
            sum.height = t["height"].get<uint32_t>();
            sum.bits = static_cast<uint32_t>(std::stoul(t["bits"].get<std::string>(), nullptr, 16));
            sum.coinbase_value = t.value("coinbasevalue", uint64_t(0));
            std::lock_guard<std::mutex> lk(summary_mutex_);
            summary_ = sum;
        }
    } catch (...) {
    }
    return t;
}

std::optional<DGBWorkSource::TemplateSummary> DGBWorkSource::last_template_summary() const
{
    std::lock_guard<std::mutex> lk(summary_mutex_);
    return summary_;
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

// Review 713dc77a0 R3. core resolve_merged_login gives every configured merged
// chain the primary's hash160 when the miner names no address for it. A DGB
// P2SH primary ("S...", version 63) is not in core address_to_hash160's P2SH
// list, so it is typed P2PKH and its DOGE script becomes P2PKH(redeem-script
// hash): an output no key can spend, and as the share's Tier-1 merged address
// it also hid the P2SH rule below. On DGB a P2SH login without a DOGE address
// of its own takes the operator's P2SH split instead (its DOGE share goes to
// the node owner and the donation, doge_merged_payouts), so the job drops the
// chain-98 entry that is the P2PKH of the P2SH payout's own hash. A DOGE
// address the miner gave (any other key, or a P2SH of the same redeem script)
// is kept.
void DGBWorkSource::decide_job_payout(std::vector<unsigned char>& payout_script,
                                      std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& merged) const
{
    if (!(payout_script.size() == 23 && payout_script[0] == 0xa9 && payout_script[1] == 0x14
          && payout_script[22] == 0x87))
        return;
    std::vector<unsigned char> derived{0x76, 0xa9, 0x14};
    derived.insert(derived.end(), payout_script.begin() + 2, payout_script.begin() + 22);
    derived.push_back(0x88);
    derived.push_back(0xac);
    merged.erase(std::remove_if(merged.begin(), merged.end(),
                                [&](const auto& e) { return e.first == kDogeChainId && e.second == derived; }),
                 merged.end());
}

namespace {
// The payouts a DGB share carries: a P2PKH, P2SH or 20-byte P2WPKH script (a
// V35 share's address, a V36 share's 20-byte payout hash).
bool payout_carried(const std::vector<unsigned char>& s)
{
    return (s.size() == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14)
           || (s.size() == 23 && s[0] == 0xa9 && s[1] == 0x14)
           || (s.size() == 22 && s[0] == 0x00 && s[1] == 0x14);
}
} // namespace

// Review 713dc77a0 #10 and #13. An empty login has no payout a share can carry
// and DGB does not redistribute one (the DGB split comes with the
// --redistribute split re-apply), and a V35 DGB share carries only a P2PKH,
// P2SH or 20-byte P2WPKH address: a dgb1 P2WSH/P2TR login was paid to a P2PKH
// of the first 20 bytes of its program (burned). Both are refused at
// authorize, with the reason. Other logins (a DOGE address as the primary, a
// foreign or undecodable one) are left to the core door.
std::string DGBWorkSource::authorize_refusal(const std::string& username) const
{
    // The work gate first, as python's preprocess_request runs before the
    // login is read.
    if (std::string hold = work_hold(); !hold.empty())
        return hold;
    if (username.empty())
        return "a DGB payout address is required (DGB_ADDRESS, or DGB_ADDRESS,DOGE_ADDRESS to name the "
               "DOGE payout)";
    // An UPPERCASE bech32 login: the python network keys V35 weights by the
    // address string as typed, so the same key typed in both cases would be
    // two outputs there and one here. The lowercase form is the same address.
    // (A base58 P2PKH may itself start "DGB1": only a string that is not a
    // valid base58check is read as an uppercase bech32 one.)
    std::vector<unsigned char> b58;
    const bool is_base58 = DecodeBase58Check(username, b58, 21);
    for (const char* hrp : {"DGB1", "DGBT1", "DGBRT1"})
        if (!is_base58 && username.rfind(hrp, 0) == 0) {
            std::string lower = username;
            for (auto& c : lower)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            return "use the lowercase form of this bech32 address (" + lower + ")";
        }
    std::vector<unsigned char> script;
    if (core::classify_address_for_coin(username, dgb::address_acceptance(is_testnet_, is_regtest_), script)
        != core::AddressCoinMatch::Own)
        return {};
    if (payout_carried(script))
        return {};
    return "DGB shares carry only a P2PKH (D...), P2SH (S...) or P2WPKH (dgb1q..., 20-byte) address; "
           "a P2WSH or P2TR address cannot be paid (use one of those)";
}

void DGBWorkSource::set_node_owner_fee(double pct, std::vector<unsigned char> script)
{
    std::lock_guard<std::mutex> lk(node_owner_fee_mutex_);
    node_owner_fee_pct_ = pct;
    node_owner_script_  = std::move(script);
}

void DGBWorkSource::set_owner_merged_scripts(
    std::vector<std::pair<uint32_t, std::vector<unsigned char>>> scripts)
{
    std::lock_guard<std::mutex> lk(node_owner_fee_mutex_);
    owner_merged_scripts_ = std::move(scripts);
}

std::vector<std::pair<uint32_t, std::vector<unsigned char>>> DGBWorkSource::effective_merged_addrs(
    const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& miner_merged,
    const std::vector<unsigned char>& miner_script,
    const std::vector<unsigned char>& effective_script) const
{
    if (effective_script == miner_script)
        return miner_merged;
    std::lock_guard<std::mutex> lk(node_owner_fee_mutex_);
    return owner_merged_scripts_;
}

// Deterministic per-(tip, connection) node-fee roll — ported verbatim from
// BTCWorkSource::effective_payout_script. The DGB payout script is derived from
// the miner's username at BOTH job build (build_connection_coinbase) and submit
// (mining_submit), so a random template-side roll would make the created share's
// committed identity mismatch the frozen job coinbase (a self-decline). A pure
// function of data BOTH sites hold (prev_share_hash + the session extranonce1 +
// the miner script) keeps template + share + verify coherent with no job-state
// carry: prev_share_hash re-rolls the decision every share interval, extranonce1
// decorrelates concurrent connections. The fee is NOT a coinbase output — it is a
// payout-identity substitution that flows into the share's existing committed
// pubkey_hash, so verify reproduces the resulting coinbase byte-for-byte.
std::vector<unsigned char> DGBWorkSource::effective_payout_script(
    const std::vector<unsigned char>& miner_script,
    const uint256& prev_share_hash,
    const std::string& extranonce1_hex) const
{
    double pct;
    std::vector<unsigned char> owner;
    {
        std::lock_guard<std::mutex> lk(node_owner_fee_mutex_);
        pct   = node_owner_fee_pct_;
        owner = node_owner_script_;
    }
    if (pct <= 0.0 || owner.empty() || miner_script.empty())
        return miner_script;

    std::vector<uint8_t> buf;
    buf.reserve(32 + extranonce1_hex.size() + miner_script.size());
    uint256 psh = prev_share_hash;  // non-const copy: uint256 begin()/end() are non-const-only
    buf.insert(buf.end(), psh.begin(), psh.end());
    buf.insert(buf.end(), extranonce1_hex.begin(), extranonce1_hex.end());
    buf.insert(buf.end(), miner_script.begin(), miner_script.end());

    uint256 h = Hash(std::span<const uint8_t>(buf.data(), buf.size()));
    // First 8 bytes as a little-endian u64; modulo 100000 gives 0.001%-granular rolls.
    uint64_t roll = 0;
    for (int i = 0; i < 8; ++i)
        roll |= static_cast<uint64_t>(h.begin()[i]) << (8 * i);
    roll %= 100000;

    return (static_cast<double>(roll) < pct * 1000.0) ? owner : miner_script;
}

core::stratum::CoinbaseResult DGBWorkSource::build_connection_coinbase(
    const uint256& prev_share_hash,
    const std::string& extranonce1_hex,
    const std::vector<unsigned char>& payout_script,
    const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& merged_addrs) const
{
    return build_coinbase(prev_share_hash, extranonce1_hex, payout_script, merged_addrs, /*local_hash_rate=*/0.0);
}

core::stratum::CoinbaseResult DGBWorkSource::build_connection_coinbase_for(
    const core::stratum::PayoutKey& login_key,
    const uint256& prev_share_hash,
    const std::string& extranonce1_hex,
    const std::vector<unsigned char>& payout_script,
    const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& merged_addrs) const
{
    LocalRateFn fn;
    {
        std::lock_guard<std::mutex> lk(local_rate_mutex_);
        fn = local_rate_fn_;
    }
    const double rate = fn ? fn(login_key) : 0.0;
    return build_coinbase(prev_share_hash, extranonce1_hex, payout_script, merged_addrs, rate);
}

void DGBWorkSource::set_local_rate_fn(LocalRateFn fn)
{
    std::lock_guard<std::mutex> lk(local_rate_mutex_);
    local_rate_fn_ = std::move(fn);
}

void DGBWorkSource::set_node_rate_fn(std::function<double()> fn)
{
    std::lock_guard<std::mutex> lk(local_rate_mutex_);
    node_rate_fn_ = std::move(fn);
}

double DGBWorkSource::start_difficulty(const core::stratum::PayoutKey&) const
{
    std::function<double()> fn;
    {
        std::lock_guard<std::mutex> lk(local_rate_mutex_);
        fn = node_rate_fn_;
    }
    const double node_rate = fn ? fn() : 0.0;
    uint32_t bits = 0;
    uint64_t value = 0;
    if (!(node_rate > 0.0)) {
        // No node rate yet: the current template's block.
        try {
            const nlohmann::json tmpl = get_current_work_template();
            if (tmpl.is_object() && tmpl.contains("bits") && tmpl.contains("height")) {
                bits = static_cast<uint32_t>(std::stoul(tmpl["bits"].get<std::string>(), nullptr, 16));
                value = coinbase_value(tmpl["height"].get<uint32_t>(), 0, std::nullopt);
            }
        } catch (const std::exception&) {
            return 0.0;
        }
    }
    return dgb::dgb_start_difficulty(node_rate, bits, value, dgb::PoolConfig::SPREAD, kDustThreshold);
}

core::stratum::CoinbaseResult DGBWorkSource::build_coinbase(
    const uint256& prev_share_hash,
    const std::string& extranonce1_hex,
    const std::vector<unsigned char>& payout_script,
    const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& merged_addrs,
    double local_hash_rate) const
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
    // UNBOUND (or returns nullopt) the result is HELD (no coinbase, no job).
    PplnsInputsFn fn;
    {
        std::lock_guard<std::mutex> lk(pplns_inputs_mutex_);
        fn = pplns_inputs_fn_;  // copy under lock; a concurrent set_*_fn() cannot
                                // tear it out mid-call.
    }
    // No coinbase its shares could carry (unbound producer, or the producer
    // declined below): HELD, never an empty result. An empty result made the
    // core stratum server fall back to the global coinbase (empty on DGB) and
    // then to its hard-coded stub (stratum_server.cpp send_notify_work: no
    // BIP34 height, 50 coins to hash160 0x00..00), so a miner hashed a coinbase
    // no share or block could ever be credited for. Held, the session sends no
    // job (the miner keeps its last real one) and retries, bounded by
    // StratumConfig::job_hold_limit_sec (CoinbaseResult::held).
    auto held = []() {
        core::stratum::CoinbaseResult r;
        r.held = true;
        return r;
    };
    if (!fn)
        return held();  // unbound producer: no job.

    // Node-owner fee (p2pool -f/--fee): resolve the payout IDENTITY that receives
    // this share's finder value (and, via the committed share, its future PPLNS
    // weight). effective_payout_script substitutes the node owner's script for
    // ~fee% of jobs, deterministically on (prev_share_hash, extranonce1,
    // payout_script) so the SAME decision is reproduced at submit time and by
    // verify. Default (fee 0 / no owner) => eff == payout_script, byte-identical.
    const std::vector<unsigned char> eff_payout_script =
        effective_payout_script(payout_script, prev_share_hash, extranonce1_hex);
    // No payout a share can carry (an empty login, a P2WSH/P2TR one: both
    // refused at authorize; this is the defence in depth, as the stratum
    // session may still build for a refused login): no job. A share minted
    // from an empty payout would carry one the submit path redistributes, so
    // its fields would differ from the ref the coinbase committed to; a
    // P2WSH/P2TR payout would be paid to a P2PKH of its program's first bytes.
    if (!payout_carried(eff_payout_script))
        return held();

    // ── DGB-as-DOGE-parent merged-mining commitment ───────────────────────────
    // Runtime-armed (--merged DOGE): the cached 44-byte AuxPoW commitment, as
    // [push 0x2c][fabe6d6d || aux_root32 BE || size4 LE || nonce4 LE] (the
    // cross-coin SSOT c2pool::merged::build_auxpow_commitment), read ONCE here
    // (rebuilt first when the payouts are dirty; no tracker lock is held yet,
    // the payout provider takes its own) and handed to the producer, which puts
    // it in the coinbase scriptSig BEFORE the ref preimage and the coinbase are
    // built (conn_job_producer.hpp). DOGE's AuxPoW check searches the whole
    // scriptSig for the magic. Before, it was appended to the scriptSig after
    // the producer had computed the ref: the share minted from that coinbase
    // committed to a scriptSig the OP_RETURN ref did not, so every local share
    // was declined once DOGE was on. Empty (merged off / no commitment yet):
    // the coinbase is byte-identical to standalone DGB.
    std::vector<unsigned char> aux_mm_scriptsig;
    if (mm_manager_ && mm_manager_->has_chains()) {
        // Rebuilt inline at most once a second (review 713dc77a0 NIT 15):
        // while the tracker is busy the provider declines and re-marks the
        // payouts dirty, and every session's job build retried the rebuild;
        // the manager's own poll rebuilds a dirty cache too.
        if (mm_manager_->is_pplns_dirty()) {
            const int64_t now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            int64_t last = last_inline_rebuild_ns_.load(std::memory_order_relaxed);
            if (now_ns - last >= 1000000000LL
                && last_inline_rebuild_ns_.compare_exchange_strong(last, now_ns))
                mm_manager_->rebuild_cached_blocks();
        }
        auto mm_snap = mm_manager_->get_cached_header_infos_and_commitment();
        const std::vector<uint8_t>& mm_commitment = mm_snap.second;
        // Push opcode == length for a 1..75-byte push; the commitment is 44 B => 0x2c.
        if (mm_commitment.size() == dgb::coin::AUX_MM_COMMITMENT_SIZE) {
            aux_mm_scriptsig.reserve(1 + mm_commitment.size());
            aux_mm_scriptsig.push_back(static_cast<unsigned char>(mm_commitment.size()));
            aux_mm_scriptsig.insert(aux_mm_scriptsig.end(), mm_commitment.begin(), mm_commitment.end());
        }
    }

    // The merged addresses the share commits to (V36 merged_addresses, in its
    // ref): the miner's, or the owner's on a node-fee job.
    const auto eff_merged_addrs = effective_merged_addrs(merged_addrs, payout_script, eff_payout_script);

    // The operator's P2SH rule, told to the miner once per payout script: a
    // P2SH login with DOGE configured and no DOGE address of its own gets no
    // DOGE (its DOGE share is split node owner / donation).
    if (mm_manager_ && payout_script.size() == 23 && payout_script[0] == 0xa9 && payout_script[1] == 0x14
        && payout_script[22] == 0x87 && mm_manager_->has_chain(kDogeChainId)) {
        bool has_doge = false;
        for (const auto& [cid, _] : eff_merged_addrs)
            has_doge = has_doge || cid == kDogeChainId;
        if (!has_doge) {
            std::lock_guard<std::mutex> lk(p2sh_warned_mutex_);
            if (p2sh_warned_.size() < 4096 && p2sh_warned_.insert(payout_script).second)
                LOG_WARNING << "[DGB-MM] a P2SH login (" << HexStr(Span<const uint8_t>(payout_script.data(), payout_script.size()))
                            << ") gives no DOGE address: its DOGE share is split between the node owner"
                               " and the donation. Add ,DOGEADDR or /98:DOGEADDR to the login to receive DOGE.";
        }
    }

    // The block this job is for, from ONE template: the producer builds the
    // coinbase for its height, bits and value, and the job carries that
    // template's header (snapshot.has_header), so the share's header bits, the
    // PPLNS walk's block target and the coinbase value all belong to the block
    // the miner hashes. Before, the producer took the block bits from the PREV
    // share's header and the value from subsidy(share absheight): every
    // coinbase claimed the subsidy of a block height ~20M lower (a won block
    // was bad-cb-amount), and the walk's cap differed from the verifier's.
    // A DGB job carries no transactions (no merkle branches, no tx_data), so
    // its coinbase may claim the subsidy alone: fees of transactions the block
    // does not include are never claimed.
    const nlohmann::json tmpl = get_current_work_template();
    JobBlock block;
    std::string tmpl_prev, tmpl_bits;
    try {
        if (!tmpl.is_object() || !tmpl.contains("height") || !tmpl.contains("bits")
            || !tmpl.contains("previousblockhash"))
            return held();  // no template (window not filled / no tip): no job.
        block.height = tmpl["height"].get<uint32_t>();
        tmpl_bits    = tmpl["bits"].get<std::string>();
        tmpl_prev    = tmpl["previousblockhash"].get<std::string>();
        if (tmpl_bits.size() != 8 || tmpl_prev.size() != 64)
            return held();
        block.bits = static_cast<uint32_t>(std::stoul(tmpl_bits, nullptr, 16));
    } catch (const std::exception&) {
        return held();
    }
    if (block.bits == 0)
        return held();
    block.value = coinbase_value(block.height, /*total_fees=*/0, /*gbt_coinbasevalue=*/std::nullopt);
    block.local_hash_rate = local_hash_rate;

    // The producer and the PPLNS->coinbase build may throw (review dd1248abd
    // #6: a V35 key the split cannot turn into a script). The core session
    // has no try around its job build, so an escaping throw would leave the
    // io handler: no job instead, logged at most once a minute.
    std::optional<dgb::coin::ConnCoinbasePplnsInputs> inputs;
    dgb::coin::ConnCoinbaseParts parts;
    try {
        inputs = fn(prev_share_hash, extranonce1_hex, eff_payout_script, eff_merged_addrs, aux_mm_scriptsig, block);
        if (!inputs)
            return held();  // producer declined (no or unknown prev share, tracker busy): no job.
        parts = dgb::coin::build_connection_coinbase_from_pplns(*inputs);
    } catch (const std::exception& e) {
        static std::atomic<int64_t> s_last_log{0};
        const int64_t now = static_cast<int64_t>(std::time(nullptr));
        int64_t last = s_last_log.load();
        if (now - last >= 60 && s_last_log.compare_exchange_strong(last, now))
            LOG_ERROR << "[DGB-STRATUM] job coinbase build failed (" << e.what() << "): no job";
        return held();
    }

    core::stratum::CoinbaseResult out;
    out.coinb1 = std::move(parts.coinb1);
    out.coinb2 = std::move(parts.coinb2);
    // Freeze the consensus-bearing ref fields the submit path (mining_submit)
    // re-derives the won-block reconstruct from; the remaining snapshot fields
    // (merkle_branches / segwit) are populated by the template-cache follow-on.
    out.snapshot.subsidy                   = inputs->subsidy;
    // A coinbase carrying the P2Pool witness commitment (V35) is a segwit
    // coinbase: its won block is serialized in witness form.
    out.snapshot.segwit_active             = inputs->segwit_commitment_script.has_value();
    out.snapshot.frozen_ref.ref_hash       = inputs->ref_hash;
    out.snapshot.frozen_ref.last_txout_nonce = inputs->last_txout_nonce;
    // #884: freeze the ratchet-selected version pair the coinbase was built at,
    // so the stratum server carries it on the job back to mining_submit's mint.
    out.snapshot.frozen_ref.share_version   = inputs->share_version;
    out.snapshot.frozen_ref.desired_version = inputs->desired_version;
    // The share fields the ref commits to (the mint stamps them, has_frozen) and
    // the job's share target: core stratum classifies with frozen_ref.bits
    // (pool_share_bits), never a fallback diff-1.
    out.snapshot.frozen_ref.absheight          = inputs->frozen_absheight;
    out.snapshot.frozen_ref.abswork            = inputs->frozen_abswork;
    out.snapshot.frozen_ref.far_share_hash     = inputs->frozen_far_share_hash;
    out.snapshot.frozen_ref.max_bits           = inputs->frozen_max_bits;
    out.snapshot.frozen_ref.bits               = inputs->frozen_bits;
    out.snapshot.frozen_ref.timestamp          = inputs->frozen_timestamp;
    out.snapshot.frozen_ref.merged_payout_hash = inputs->frozen_merged_payout_hash;
    // The job's header is the template the coinbase was built for.
    out.snapshot.has_header      = true;
    out.snapshot.gbt_prevhash    = tmpl_prev;
    out.snapshot.header_version  = static_cast<uint32_t>(tmpl.value("version", 0x20000000));
    out.snapshot.block_nbits_hex = tmpl_bits;
    out.snapshot.curtime         = static_cast<uint32_t>(tmpl.value("curtime", 0));
    out.snapshot.height          = block.height;
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
    const std::map<uint32_t, std::vector<unsigned char>>& merged_addresses,
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

    // Every coinbase this work source builds carries the producer's frozen ref
    // (build_connection_coinbase sets frozen_ref.ref_hash; the stratum server
    // carries it with the job to this snapshot). A job without one was not
    // built here: no share minted from it can be credited, so its share path
    // is refused below. A won block is NEVER refused: it is dispatched first,
    // whatever the job, and only its share is skipped.
    const bool built_here = !job->frozen_ref.ref_hash.IsNull();

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

    // -- Sharechain mint (#887) --
    // Hand the found-share fields to the run-loop mint dispatch
    // (try_mint_share -> mint_local_share_with_ratchet, #294). SHARED by both
    // accept classes: block_target <= share_target, so a solve that meets the
    // block target meets the share target too -- it is the highest-work share
    // this node will ever produce, and the sharechain and the coin blockchain
    // are independent systems. Before #887 the WonBlock case returned without
    // ever reaching this seam, forfeiting our own PPLNS weight in the very
    // window the block pays out from and denying peers our best work. LTC has
    // always minted on both classes (web_server.cpp).
    //
    // PRE-WIRING ON DGB (#884): main_dgb.cpp never calls set_mint_share_fn, so
    // DGB cannot mint ANY local share today -- neither this one nor an ordinary
    // ShareAccept. try_mint_share logs the unbound seam loudly and returns
    // null. This change makes the WonBlock arm REACH the seam so that DGB gets
    // the fix for free the moment #884 binds it; it does not by itself make a
    // DGB mint happen.
    //
    // ORDERING -- reward invariant: on the WonBlock arm this runs AFTER the
    // block has already been dispatched, never before. The mint can decline and
    // can throw; the block submit must never sit behind any of that.
    //
    // CONSENSUS: unchanged. Share construction, target derivation and
    // serialisation live entirely inside the (untouched) mint seam -- this
    // changes only WHETHER it is invoked, not what it builds.
    auto mint_solved_share = [&](bool won_block) {
        const char* tag = won_block ? "[DGB-STRATUM-BLOCK-SHARE]"
                                    : "[DGB-STRATUM-SHARE]";
        MintShareInputs in;
        in.header_bytes    = header;
        // #884/#902: hand the mint the coinbase SCRIPTSIG (share.m_coinbase is
        // the scriptSig, bounded 2..100B by share_init_verify), extracted from
        // the reconstructed coinbase tx -- NOT the full gentx `coinbase`, which
        // is >100B and would make create_local_share throw "bad coinbase size".
        // Recovering it from the tx (rather than re-deriving) guarantees it is
        // byte-identical to the scriptSig the producer froze into the template.
        in.coinbase_bytes  = extract_coinbase_scriptsig(coinbase);
        in.subsidy         = job->subsidy;
        in.prev_share      = job->prev_share_hash;
        in.merkle_branches = branch_hashes;
        // #961: validate the payout address against DGB's OWN version bytes / HRP
        // before building a script, so a foreign-coin address is rejected rather
        // than repurposed into a DGB script (which would MISDIRECT funds). The
        // accepted set is REGISTRY-SOURCED (dgb::address_acceptance → config_coin
        // SSOT) and derived from the TRUE network (mainnet/testnet/regtest) so a
        // --regtest payout address is accepted, not rejected as Foreign. Foreign
        // → empty → the existing redistribute/empty fallback below; never a
        // wrong-coin payment.
        {
            // The payout the job's coinbase was built for (the stratum server's
            // decision, JobSnapshot::payout_script), so the share commits to
            // the same script the producer did: also for a login whose primary
            // is a configured merged chain's address (Case 5), which DGB's own
            // classification below would reject. Jobs that carry no payout
            // derive it from the username as before.
            std::vector<unsigned char> payout_script;
            if (job->has_payout) {
                payout_script = job->payout_script;
            } else {
                auto amatch = core::classify_address_for_coin(
                    username, dgb::address_acceptance(is_testnet_, is_regtest_),
                    payout_script);
                if (amatch == core::AddressCoinMatch::Foreign)
                    LOG_WARNING << "[DGB-STRATUM] REJECTED foreign-coin payout address "
                                   "(user=" << username << ") — not a DGB address; "
                                   "refusing to misdirect funds";
            }
            // Node-owner fee (p2pool -f/--fee): substitute the owner's payout
            // identity for ~fee% of shares, deterministically on (prev_share,
            // extranonce1, miner_script) so this matches build_connection_coinbase
            // and verify exactly. A non-empty miner script that is substituted
            // stays non-empty (owner script), so the empty-only redistribute
            // fallback below never fires on it; an empty script is left empty
            // (effective_payout_script returns miner on empty) so --redistribute
            // is untouched. Default (fee 0) => byte-identical to before.
            in.payout_script =
                effective_payout_script(payout_script, job->prev_share_hash, extranonce1);
            // The merged scripts the job committed to (the map is ordered by
            // chain id, as the producer received them), after the node-fee rule.
            const std::vector<std::pair<uint32_t, std::vector<unsigned char>>> job_merged(
                merged_addresses.begin(), merged_addresses.end());
            in.merged_addrs = effective_merged_addrs(job_merged, payout_script, in.payout_script);
        }
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
                    LOG_INFO << tag << " empty payout addr (user=" << username
                             << ") -> redistribute policy stamped fallback script ("
                             << in.payout_script.size() << "B)";
            }
        }
        in.segwit_active   = job->segwit_active;
        // #884: mint at the version pair frozen when this job's coinbase was built.
        in.share_version   = job->frozen_ref.share_version;
        in.desired_version = job->frozen_ref.desired_version;
        // The coinbase the miner hashed and the share fields its OP_RETURN ref
        // commits to: the mint records exactly this work (the BTC lane's
        // has_frozen path). Without them the mint rebuilt the gentx with no
        // extranonce and a submit-time timestamp, so the share never matched.
        in.actual_coinbase.assign(coinbase.begin(), coinbase.end());
        in.has_frozen                = !job->frozen_ref.ref_hash.IsNull();
        in.frozen_absheight          = job->frozen_ref.absheight;
        in.frozen_abswork            = job->frozen_ref.abswork;
        in.frozen_far_share_hash     = job->frozen_ref.far_share_hash;
        in.frozen_max_bits           = job->frozen_ref.max_bits;
        in.frozen_bits               = job->frozen_ref.bits;
        in.frozen_timestamp          = job->frozen_ref.timestamp;
        in.frozen_merged_payout_hash = job->frozen_ref.merged_payout_hash;

        uint256 share_hash;
        try {
            share_hash = try_mint_share(in);
        } catch (const std::exception& e) {
            LOG_WARNING << tag << " mint dispatch threw: " << e.what()
                        << " -- share not minted";
        }

        if (!share_hash.IsNull()) {
            LOG_INFO << tag << " ACCEPTED + MINTED user=" << username
                     << " share_hash=" << share_hash.GetHex().substr(0, 16)
                     << " job=" << job_id;
        } else {
            // PoW was valid (cleared the share target) so the miner still gets a
            // success reply; the share just earned no sharechain credit (no mint
            // fn wired, or the mint deferred/failed). try_mint_share logs the
            // reason -- never a silent drop.
            LOG_INFO << tag << " accepted (no sharechain credit) user="
                     << username << " job=" << job_id;
        }

        // ── Merged-mining: submit any aux (DOGE) block THIS share solves ──────
        // Analog of the live-proven BTC->NMC parent lane (btc work_source.cpp:
        // 1103-1127) and p2pool check_merged_mining. The aux (DOGE) target sits
        // far below the parent DGB share target, so this must run per ACCEPTED
        // SHARE, not only on a won parent block -- most found DOGE blocks ride
        // ordinary shares. try_submit_merged_blocks self-gates on the aux target
        // (merged_mining.cpp ~:884), rebuilds the AuxPoW proof from the frozen
        // aux header committed in THIS job's coinbase (keyed by parent hash), and
        // relays via the CoinBroadcaster. DGB coinb1/coinb2 are witness-free by
        // construction -- correct for the AuxPoW parent-coinbase merkle branch.
        // On the won-block arm this runs AFTER the parent block was already
        // dispatched (reward invariant preserved). Null manager => no-op.
        if (mm_manager_ && mm_manager_->has_chains()) {
            try {
                std::string parent_header_hex =
                    HexStr(Span<const uint8_t>(header.data(), 80));
                std::string parent_coinbase_hex =
                    HexStr(Span<const uint8_t>(coinbase.data(), coinbase.size()));
                // dgb::coin::u256 -> core uint256: both hold a 32-byte
                // little-endian image; serialize pow_hash's limbs LE and read
                // them back through uint256's LE-vector ctor. The scrypt PoW hash
                // IS the parent block hash the aux-target gate compares.
                std::vector<unsigned char> ph_le(32, 0);
                for (int i = 0; i < 4; ++i)
                    for (int j = 0; j < 8; ++j)
                        ph_le[i * 8 + j] =
                            static_cast<unsigned char>((pow_hash.limb[i] >> (8 * j)) & 0xff);
                uint256 parent_hash(ph_le);
                mm_manager_->try_submit_merged_blocks(
                    parent_header_hex, parent_coinbase_hex,
                    job->merkle_branches, 0, parent_hash);
            } catch (const std::exception& e) {
                LOG_WARNING << "[DGB-MM] try_submit_merged_blocks threw: " << e.what();
            }
        }
    };

    switch (klass) {
    case dgb::coin::SubmitClass::WonBlock: {
        // pow_hash <= block_target -> a full network block. NEVER drop it.
        const uint32_t height = chain_.next_block_height();
        LOG_WARNING << "[DGB-STRATUM-BLOCK] *** BLOCK FOUND *** user=" << username
                    << " height~=" << height << " job=" << job_id;

        // Serialize the block through the dgb::coin::serialize_won_block SSOT
        // (coin/won_block_serialize.hpp).  It enforces the two invariants the
        // ALREADY-HASHED header pins and the old hand-rolled framing violated:
        //
        //   1. the body must be exactly the tx set the frozen merkle root
        //      commits to -- with NO merkle branches in the job the committed
        //      root is the bare coinbase txid, so the block is coinbase-only;
        //      appending job->tx_data anyway is a guaranteed bad-txnmrklroot;
        //   2. BIP144 witness form is emitted IFF the coinbase carries the
        //      BIP141 aa21a9ed commitment -- a witness-bearing coinbase
        //      without one is rejected (unexpected-witness), and the
        //      commitment cannot be injected here (it would change the
        //      coinbase txid and invalidate the header the miner hashed).
        //
        // Both conditions are LOGGED when they fire: they mean an upstream
        // job-build seam (branch cache / segwit_commitment_script producer)
        // is still unpopulated, and the block ships degraded-but-valid rather
        // than complete-but-rejected.
        static const std::vector<std::string> kEmptyTxData;
        const std::vector<std::string>& txs =
            job->tx_data ? *job->tx_data : kEmptyTxData;

        std::vector<std::vector<uint8_t>> other_txs;
        other_txs.reserve(txs.size());
        for (const auto& tx_hex : txs)
            other_txs.push_back(ParseHex(tx_hex));

        const dgb::coin::WonBlockAssembly asm_out = dgb::coin::serialize_won_block(
            header, coinbase, other_txs, job->segwit_active,
            /*committed_coinbase_only=*/job->merkle_branches.empty());
        const std::vector<uint8_t>& block_bytes = asm_out.bytes;

        if (asm_out.dropped_txs) {
            LOG_ERROR << "[DGB-STRATUM-BLOCK] job carried " << asm_out.dropped_txs
                      << " body tx(s) but NO merkle branches -- the frozen header"
                      << " commits to a COINBASE-ONLY block; shipping committed"
                      << " form (their fees are forfeit). Populate the branch"
                      << " cache (get_stratum_merkle_branches) to claim them.";
        }
        if (asm_out.witness_form_suppressed) {
            LOG_WARNING << "[DGB-STRATUM-BLOCK] segwit-active job but the coinbase"
                        << " carries no BIP141 commitment output -- emitting LEGACY"
                        << " (witness-form would be rejected unexpected-witness)."
                        << " Populate segwit_commitment_script at job build.";
        }

        // Won blocks are rare: dump the wire bytes so any daemon-side reject is
        // decodable offline without a second live repro.
        LOG_WARNING << "[DGB-STRATUM-BLOCK] wire: txs=" << asm_out.tx_count
                    << " witness_form=" << (asm_out.witness_form ? 1 : 0)
                    << " merkle_root=" << merkle_root.GetHex()
                    << " coinbase_txid=" << coinbase_txid.GetHex()
                    << " branches=" << job->merkle_branches.size()
                    << " block=" << HexStr(Span<const uint8_t>(block_bytes.data(),
                                                               block_bytes.size()));

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

        // #887: the won block is a SHARE too. The dispatch above has already
        // happened, so nothing here can delay, gate or endanger the block
        // submit -- the mint is strictly downstream of it.
        if (built_here)
            mint_solved_share(/*won_block=*/true);
        else
            LOG_WARNING << "[DGB-STRATUM] won block dispatched; its job carries no frozen ref, so no share"
                           " is minted: user=" << username << " job=" << job_id;

        bump_accepted();
        return nlohmann::json(true);
    }

    case dgb::coin::SubmitClass::ShareAccept: {
        // share_target >= pow_hash > block_target -> meets sharechain difficulty
        // but not the full block.
        if (!built_here) {
            LOG_WARNING << "[DGB-STRATUM] submit reject (job carries no frozen ref): user=" << username
                        << " job=" << job_id;
            return reject(21, "Job not found");
        }
        mint_solved_share(/*won_block=*/false);

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
    gbt_tip_fail_time_ = 0;
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
        // A failure is cached as long (review 7793bfb6c NIT): while digibyted
        // fails, each session's 1 s template retry would otherwise run its own
        // blocking getblocktemplate on the IO thread.
        if (gbt_tip_fail_time_ != 0 && (now - gbt_tip_fail_time_) < GBT_TIP_TTL_SECONDS)
            return std::nullopt;
        fn = gbt_tip_fn_;  // copy so a concurrent set_gbt_tip_fn() cannot tear it out
    }
    if (!fn)
        return std::nullopt;   // unbound (no digibyted creds armed) -> truthful absence

    std::optional<GbtTip> tip = fn();   // blocking getblocktemplate; nullopt on RPC failure
    {
        std::lock_guard<std::mutex> lk(gbt_tip_mutex_);
        if (tip) {
            gbt_tip_cache_      = tip;
            gbt_tip_cache_time_ = now;
            gbt_tip_fail_time_  = 0;
        } else {
            gbt_tip_fail_time_  = now;
        }
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