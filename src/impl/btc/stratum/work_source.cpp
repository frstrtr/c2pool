// SPDX-License-Identifier: AGPL-3.0-or-later
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
#include <impl/btc/stratum/tx_data_memo.hpp>   // H5 tx_data memo seam (work_source.cpp:634 churn fix)
#include <memory>

#include <impl/btc/coin/header_chain.hpp>
#include <impl/btc/coin/mempool.hpp>
#include <impl/btc/coin/template_builder.hpp>  // build_template + merkle_hash_pair
#include <impl/btc/coin/transaction.hpp>
#include <c2pool/merged/merged_mining.hpp>   // MergedMiningManager::has_chain (PR-2a)

#include <core/address_utils.hpp>               // address_to_script (for share write path)
#include <core/hash.hpp>
#include <core/log.hpp>
#include <core/target_utils.hpp>                // chain::target_to_difficulty
#include <btclibs/util/strencodings.h>          // HexStr, ParseHex

#include <cstdio>
#include <cstring>
#include <ctime>
#include <utility>

namespace {

// ── Byte-stream helpers used by coinbase + header construction ──────────────
// All encodings are little-endian (Bitcoin wire format). Push helpers append
// to a std::vector<uint8_t> for incremental building; the result becomes the
// raw serialized form ready for HexStr() conversion.

inline void push_u32_le(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(static_cast<uint8_t>(x       & 0xff));
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

// BIP 34 minimally-encoded height push for the coinbase scriptSig.
// Returns: [opcode_pushbytes_n][n bytes height_LE], where n is the smallest
// number of bytes needed to encode the height with the high bit clear (script
// integer convention — sign-bit safety prevents the value from being parsed
// as negative).
inline std::vector<uint8_t> bip34_height_push(uint32_t h) {
    std::vector<uint8_t> enc;
    uint32_t tmp = h;
    while (tmp) {
        enc.push_back(static_cast<uint8_t>(tmp & 0xff));
        tmp >>= 8;
    }
    if (enc.empty()) enc.push_back(0);
    if (enc.back() & 0x80) enc.push_back(0);
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>(enc.size()));   // OP_PUSHBYTES_n
    out.insert(out.end(), enc.begin(), enc.end());
    return out;
}

// Parse a BE hex string into a uint32_t. Stratum sends ntime/nonce/version
// as 8-char BE hex; sscanf(%x) is enough.
inline uint32_t parse_be_hex_u32(const std::string& s) {
    uint32_t v = 0;
    std::sscanf(s.c_str(), "%x", &v);
    return v;
}

// BIP 141 witness reserved value: 32 zero bytes embedded as the only
// stack item in the coinbase witness. The witness commitment in the
// coinbase OP_RETURN is computed against this exact value.
constexpr std::array<uint8_t, 32> WITNESS_RESERVED_VALUE{};  // all zeros

// BIP 141 witness commitment magic: OP_RETURN OP_PUSHBYTES_36 + "aa21a9ed".
// Followed by 32 bytes of commitment hash for total OP_RETURN script of 38 bytes.
constexpr std::array<uint8_t, 6> WITNESS_COMMIT_HEADER = {
    0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed
};

}  // anonymous namespace

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
    // BTC is SHA256d: p2pool's net.DUMB_SCRYPT_DIFF == 1 for SHA256d nets
    // (scrypt nets use 2^16). The shared StratumConfig defaults to the scrypt
    // 65536, so override here — otherwise mining.set_difficulty advertises a
    // 65536x-inflated wire diff that starves low-rate SHA256d miners of
    // acceptable shares. Wire-only; does not touch the share-accept target.
    config_.set_difficulty_multiplier = 1.0;
    // Runtime coin tag for coin-agnostic core log lines (#732).
    if (config_.coin_symbol.empty())
        config_.coin_symbol = "BTC";

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

bool BTCWorkSource::has_merged_chain(uint32_t chain_id) const
{
    // Wired in PR-2a: consult the merged-mining manager if main_btc set one
    // (--merged NMC:...). No manager or unknown chain_id => false.
    return mm_manager_ != nullptr && mm_manager_->has_chain(chain_id);
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

std::shared_ptr<const btc::coin::rpc::WorkData>
BTCWorkSource::cached_template() const
{
    const uint64_t gen = work_generation_.load(std::memory_order_relaxed);
    const uint64_t mep = mempool_.epoch();
    {
        std::lock_guard<std::mutex> lk(template_mutex_);
        if (template_cache_ && template_cache_gen_ == gen && template_cache_epoch_ == mep)
            return template_cache_;
    }
    auto built = btc::coin::TemplateBuilder::build_template(chain_, mempool_, is_testnet_);
    if (!built) return nullptr;
    auto sp = std::make_shared<const btc::coin::rpc::WorkData>(std::move(*built));
    std::lock_guard<std::mutex> lk(template_mutex_);
    template_cache_       = sp;
    template_cache_gen_   = gen;
    template_cache_epoch_ = mep;
    return sp;
}

nlohmann::json BTCWorkSource::get_current_work_template() const
{
    // TemplateBuilder::build_template already shapes the result as a
    // GBT-style nlohmann::json in WorkData::m_data — exactly what stratum
    // sessions expect (previousblockhash, bits, version, curtime, mintime,
    // height, coinbasevalue, transactions[]). Return that directly.
    //
    // Returns an empty object if HeaderChain isn't past genesis yet — the
    // session will skip work-push and retry on next poll.
    auto wd = cached_template();
    if (!wd) return nlohmann::json::object();
    nlohmann::json data = wd->m_data;
    data["curtime"] = static_cast<int64_t>(std::time(nullptr));
    return data;
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
    auto wd = cached_template();
    if (!wd || wd->m_hashes.empty()) return {};

    // PRODUCER/CONSUMER CONTRACT: wd->m_hashes is the pure tx-hash list
    // [tx1..txN] with NO coinbase slot (filled by rpc.cpp / template_builder.hpp
    // straight from GBT transactions[]). The stratum merkle tree, however, has
    // the coinbase as leaf 0. Prepend a placeholder leaf for it before folding
    // — the actual coinbase hash doesn't matter for branch computation since
    // the miner provides their own coinbase; we only need the leaf STRUCTURE.
    // Without this prepend, level[1] below would be tx2 (not tx1), tx1 would be
    // dropped, and the header merkle root would diverge from the serialized
    // body → bad-txnmrklroot rejection on any populated (>=1 tx) won block.
    // SSOT: branch sibling structure lives in btc::coin::stratum_merkle_siblings
    // (template_builder.hpp) so the merkle self-check in mining_submit and any
    // KAT exercise the SAME fold as the wire path. We only hex-encode here.
    std::vector<uint256> level = btc::coin::stratum_merkle_siblings(wd->m_hashes);
    std::vector<std::string> branches;
    branches.reserve(level.size());
    for (const auto& sib : level) {
        // Right-sibling of the left-most node = level[1].
        // Wire encoding: hex of LE-internal bytes (NOT GetHex() which is
        // BE display). Matches cgminer convention + LTC's working
        // compute_merkle_branches (web_server.cpp:1299). The miner does
        // hex2bin on this string and uses bytes directly in SHA256d, so
        // the bytes on the wire MUST be the same LE-internal bytes the
        // pool used to build the merkle tree. GetHex() reverses them and
        // produces a totally different merkle root in the miner's view.
        branches.push_back(HexStr(std::span<const unsigned char>(sib.data(), 32)));
    }
    return branches;
}

std::pair<std::string, std::string> BTCWorkSource::get_coinbase_parts() const
{
    // Fallback coinbase split with no payout output (the per-connection
    // builder produces the real one). Used only when stratum sessions
    // ask for default parts before authorize completes — they then skip
    // mining.notify until build_connection_coinbase becomes available.
    return { {}, {} };
}

core::stratum::CoinbaseResult BTCWorkSource::build_connection_coinbase(
    const uint256& prev_share_hash,
    const std::string& /*extranonce1_hex*/,
    const std::vector<unsigned char>& payout_script,
    const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& /*merged_addrs*/) const
{
    // c2pool BTC v35 coinbase layout (Phase 8b — full PPLNS + ref_hash).
    //
    // Reference: core/web_server.cpp::MiningInterface::build_coinbase_parts
    // (lines 1576-1735). We port that algorithm with BTC v35 simplifications
    // (no DOGE merged-mining, no state_root V37 prep, no MWEB):
    //
    //   ScriptSig (no extranonce — c2pool puts it in OP_RETURN nonce instead):
    //     [BIP 34 height push — incl. opcode prefix]
    //     [/c2pool-btc/ tag with 1-byte push opcode prefix]
    //
    //   Outputs:
    //     ── (segwit witness commitment FIRST if active — TODO 8c)
    //     ── PPLNS payouts (sorted asc by amount, asc by script)
    //        + finder fee subsidy/200 added to miner, deducted from donation
    //     ── OP_RETURN: 0 sats, script = 6a 28 [ref_hash 32B] [nonce 8B-slot]
    //        The 8-byte nonce slot is filled at submit time by
    //        extranonce1(4) || extranonce2(4) — see c2pool's hash_link
    //        deterministic-coinbase scheme.
    //
    //   coinb1 = entire coinbase tx UP TO AND INCLUDING ref_hash (NOT the
    //            8B nonce slot)
    //   coinb2 = "00000000" (just locktime)
    //
    // If pplns_fn_ or ref_hash_fn_ are unset (cold start, ShareTracker not
    // ready) the coinbase degrades gracefully: single-output paying full
    // subsidy to the miner, no OP_RETURN. Valid BTC block but no c2pool
    // sharechain credit.

    auto wd = cached_template();
    if (!wd) return {};

    const uint32_t height        = wd->m_data.value("height", 0u);
    const uint64_t coinbasevalue = wd->m_data.value("coinbasevalue", uint64_t{0});

    // GBT block-target bits (NOT the share-target bits — that's in nbits).
    uint32_t block_bits = 0;
    if (auto it = wd->m_data.find("bits"); it != wd->m_data.end() && it->is_string())
        block_bits = parse_be_hex_u32(it->get<std::string>());
    const uint32_t curtime = static_cast<uint32_t>(std::time(nullptr));

    // Detect segwit activation. GBT exposes this in two redundant ways:
    // a "rules" array containing "!segwit" or "segwit", or the presence of
    // a non-empty "default_witness_commitment" (which TemplateBuilder doesn't
    // currently emit, so we go off "rules"). For BTC mainnet segwit has been
    // active since 2017, so for our purposes this is effectively always true
    // post-IBD. We still gate on it to remain correct for testnet edges and
    // synthetic test fixtures.
    bool segwit_active = false;
    if (auto it = wd->m_data.find("rules"); it != wd->m_data.end() && it->is_array()) {
        for (const auto& r : *it) {
            if (!r.is_string()) continue;
            auto s = r.get<std::string>();
            if (s == "segwit" || s == "!segwit") { segwit_active = true; break; }
        }
    }

    // Snapshot callbacks under the lock (invoke them unlocked).
    PplnsFn pplns_fn;
    RefHashFn ref_hash_fn;
    std::vector<unsigned char> donation_script;
    {
        std::lock_guard<std::mutex> lk(callback_mutex_);
        pplns_fn        = pplns_fn_;
        ref_hash_fn     = ref_hash_fn_;
        donation_script = donation_script_;
    }

    // ── ScriptSig assembly (always the same — coinbase deterministic) ──
    auto bip34 = bip34_height_push(height);
    static const std::string POOL_TAG = "/c2pool-btc/";

    std::vector<uint8_t> scriptsig;
    scriptsig.insert(scriptsig.end(), bip34.begin(), bip34.end());
    if (!POOL_TAG.empty() && POOL_TAG.size() < 76) {
        // Push opcode: for 1-75 bytes, the opcode IS the length.
        scriptsig.push_back(static_cast<uint8_t>(POOL_TAG.size()));
        scriptsig.insert(scriptsig.end(), POOL_TAG.begin(), POOL_TAG.end());
    }

    // ── PPLNS payouts ──
    std::map<std::vector<unsigned char>, double> payouts;
    if (pplns_fn) {
        uint256 block_target;
        if (block_bits != 0) block_target.SetCompact(block_bits);
        try {
            payouts = pplns_fn(prev_share_hash, block_target, coinbasevalue, donation_script);
        } catch (const std::exception& e) {
            LOG_WARNING << "[BTC-STRATUM] pplns_fn threw: " << e.what()
                        << " — falling back to single-output coinbase";
            payouts.clear();
        }
    }

    // Drop any empty-script entries from the PPLNS map BEFORE applying the
    // finder fee. Empty payout_script means the share's miner had an
    // unrecognized/unsupported address (e.g. bech32 P2WSH that the stratum
    // address validator couldn't decode). Their sats would otherwise become
    // an unspendable 0-script output in the coinbase. Drop them — the value
    // flows back to the donation residual via the post-PPLNS rebalance below.
    {
        size_t dropped_n = 0;
        uint64_t dropped_value = 0;
        for (auto it = payouts.begin(); it != payouts.end(); ) {
            if (it->first.empty()) {
                dropped_n++;
                dropped_value += static_cast<uint64_t>(it->second);
                it = payouts.erase(it);
            } else {
                ++it;
            }
        }
        if (dropped_n > 0) {
            LOG_INFO << "[BTC-STRATUM] PPLNS: dropped " << dropped_n
                     << " empty-script entries (" << dropped_value
                     << " sats reabsorbed to donation)";
            // Reabsorb the dropped value into donation so total payouts == subsidy.
            if (!donation_script.empty())
                payouts[donation_script] += static_cast<double>(dropped_value);
        }
    }

    // v35 finder fee: 0.5% of subsidy goes to the share-finder (this miner),
    // deducted from donation. Reference: c2pool_refactored.cpp wiring +
    // share_tracker.hpp v35 PPLNS docs ("amounts WITHOUT finder fee — caller
    // adds subsidy/200 to the share creator's script"). Conditional on having
    // a non-empty payout_script — otherwise we'd reintroduce the empty-output
    // bug we just filtered. And the deduction-from-donation must succeed
    // (donation must hold ≥ finder_fee), else we'd inflate total > subsidy.
    if (!payouts.empty() && coinbasevalue > 0 && !payout_script.empty()) {
        const double finder_fee = static_cast<double>(coinbasevalue) / 200.0;
        if (!donation_script.empty()) {
            auto it = payouts.find(donation_script);
            if (it != payouts.end() && it->second >= finder_fee) {
                it->second   -= finder_fee;
                payouts[payout_script] += finder_fee;
            }
            // else: donation can't cover the fee — skip silently. Total stays
            // at subsidy (per get_v35_expected_payouts post-condition).
        }
    }

    // Degraded fallback: full subsidy → miner (only if miner address is OK).
    if (payouts.empty() && !payout_script.empty()) {
        payouts[payout_script] = static_cast<double>(coinbasevalue);
    }

    // ── Sort outputs: by amount asc, then by script asc (matches LTC) ──
    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> outputs;
    outputs.reserve(payouts.size());
    for (const auto& [script, amount_d] : payouts) {
        // Round to satoshi. Anything < 1 sat is dust — drop it (matches
        // Bitcoin Core dust-out-policy + LTC payout manager behaviour).
        // Empty scripts already filtered above but defense-in-depth.
        if (script.empty()) continue;
        const uint64_t amount = static_cast<uint64_t>(amount_d);
        if (amount > 0)
            outputs.emplace_back(script, amount);
    }
    std::sort(outputs.begin(), outputs.end(), [](const auto& a, const auto& b) {
        if (a.second != b.second) return a.second < b.second;
        return a.first  < b.first;
    });

    // ── ref_hash + chain-walked frozen_ref values (Phase 12) ──
    // The ref_hash_fn lambda walks the share tracker for the actual
    // network share target (bits/max_bits) plus the chain-position
    // fields (absheight/abswork/far_share_hash) and the clipped
    // timestamp. We update the share_bits_/share_max_bits_ atomics so
    // stratum_server's pool_difficulty gate sees the live network share
    // difficulty (was forever 0 before Phase 12 → mining_submit was
    // never called for ordinary pseudoshares → chain-share creation
    // never triggered).
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
            LOG_WARNING << "[BTC-STRATUM] ref_hash_fn threw: " << e.what()
                        << " — coinbase will lack OP_RETURN commitment";
        }
    }
    const uint256&  ref_hash      = rh_result.ref_hash;
    const uint64_t  ref_nonce     = rh_result.last_txout_nonce;
    const bool      emit_op_return = ref_hash_fn && !ref_hash.IsNull();

    // ── BIP 141 witness commitment (Output 0 if segwit active) ──
    //
    // Required for mainnet block acceptance since segwit activation
    // (2017-08). bitcoind validates: SHA256d(witness_root || reserved_value)
    // == commitment_hash present in coinbase OP_RETURN with magic aa21a9ed.
    //
    // witness_root is the merkle root of WTXIDs of all txs in the block.
    // The coinbase WTXID is conventionally 32 zero bytes (BIP 141), so it
    // takes the leftmost slot. Other txs' wtxids come from the GBT
    // template's "hash" field (TemplateBuilder line 226 emits this).
    //
    // For coinbase-only templates (no other txs) the witness root is just
    // the coinbase wtxid (zero), so commitment = SHA256d(zero32 || zero32).
    std::vector<uint8_t> witness_commitment_script;  // empty if segwit not active
    uint256 witness_root_uint;
    if (segwit_active) {
        // Collect the OTHER txs' wtxids (template "hash" field); the coinbase
        // wtxid placeholder (BIP141 = 32 zero bytes) at leaf 0 is prepended by
        // the shared witness_merkle_root() SSOT helper, so the leaf-0 contract
        // lives in ONE place (mirrors the txid-merkle leaf-0 fix, PR #570).
        std::vector<uint256> other_wtxids;
        other_wtxids.reserve(wd->m_txs.size());
        if (auto txs_field = wd->m_data.find("transactions");
            txs_field != wd->m_data.end() && txs_field->is_array())
        {
            for (const auto& t : *txs_field) {
                if (!t.is_object()) continue;
                if (auto h = t.find("hash"); h != t.end() && h->is_string()) {
                    uint256 wt; wt.SetHex(h->get<std::string>().c_str());
                    other_wtxids.push_back(wt);
                }
            }
        }
        witness_root_uint = btc::coin::witness_merkle_root(other_wtxids);

        // commitment_hash = SHA256d(witness_root || witness_reserved_value)
        std::array<uint8_t, 64> commit_in;
        std::memcpy(commit_in.data(),      witness_root_uint.data(),    32);
        std::memcpy(commit_in.data() + 32, WITNESS_RESERVED_VALUE.data(), 32);
        uint256 commit_hash = Hash(std::span<const uint8_t>(commit_in.data(), 64));

        // Build OP_RETURN script: 0x6a 0x24 [aa21a9ed] [commit 32B] = 38 bytes total
        witness_commitment_script.reserve(38);
        witness_commitment_script.insert(witness_commitment_script.end(),
            WITNESS_COMMIT_HEADER.begin(), WITNESS_COMMIT_HEADER.end());
        witness_commitment_script.insert(witness_commitment_script.end(),
            commit_hash.data(), commit_hash.data() + 32);
    }

    // ── Assemble coinb1: full tx up to (and including) ref_hash ──
    // Output count = [witness commitment if segwit] + [PPLNS outputs] + [OP_RETURN ref_hash if any]
    const size_t output_count = (segwit_active ? 1 : 0)
                              + outputs.size()
                              + (emit_op_return ? 1 : 0);

    std::vector<uint8_t> coinb1;
    push_u32_le(coinb1, /*tx version*/ 1);  // c2pool reference uses version 1
    coinb1.push_back(0x01);                  // vin_count = 1
    coinb1.insert(coinb1.end(), 32, 0x00);   // prev_hash = 32 zero bytes
    push_u32_le(coinb1, 0xFFFFFFFFu);        // prev_vout
    push_varint(coinb1, scriptsig.size());
    coinb1.insert(coinb1.end(), scriptsig.begin(), scriptsig.end());
    push_u32_le(coinb1, 0xFFFFFFFFu);        // sequence
    push_varint(coinb1, output_count);

    // Output 0: BIP 141 witness commitment (FIRST so it's stable across
    // PPLNS reordering — bitcoind scans for the LAST aa21a9ed commitment
    // but stable position helps reproducibility).
    if (segwit_active) {
        push_u64_le(coinb1, /*sats*/ 0);
        push_varint(coinb1, witness_commitment_script.size());
        coinb1.insert(coinb1.end(),
            witness_commitment_script.begin(), witness_commitment_script.end());
    }

    // PPLNS / payout outputs (already sorted)
    for (const auto& [script, amount] : outputs) {
        push_u64_le(coinb1, amount);
        push_varint(coinb1, script.size());
        coinb1.insert(coinb1.end(), script.begin(), script.end());
    }

    // Output last: OP_RETURN with c2pool ref_hash + 8B nonce slot.
    // Script: 6a (OP_RETURN) 28 (PUSH_40) ref_hash(32) nonce(8) — total 42 bytes.
    // The 8B nonce comes from extranonce1+extranonce2 between coinb1 and coinb2.
    if (emit_op_return) {
        push_u64_le(coinb1, /*sats*/ 0);
        coinb1.push_back(0x2a);   // script_len = 42
        coinb1.push_back(0x6a);   // OP_RETURN
        coinb1.push_back(0x28);   // PUSH_40
        coinb1.insert(coinb1.end(), ref_hash.data(), ref_hash.data() + 32);
        // [8B nonce slot — coinb1 ends here; en1+en2 fills it]
    }

    // ── coinb2: locktime only ──
    std::vector<uint8_t> coinb2;
    push_u32_le(coinb2, 0u);  // locktime = 0

    core::stratum::CoinbaseResult result;
    result.coinb1 = HexStr(std::span<const uint8_t>(coinb1.data(), coinb1.size()));
    result.coinb2 = HexStr(std::span<const uint8_t>(coinb2.data(), coinb2.size()));

    // ── Snapshot — frozen state matching this coinbase ──
    auto& snap = result.snapshot;
    snap.subsidy                    = coinbasevalue;
    snap.segwit_active              = segwit_active;
    snap.witness_root               = witness_root_uint;
    if (!witness_commitment_script.empty()) {
        snap.witness_commitment_hex = HexStr(std::span<const uint8_t>(
            witness_commitment_script.data(), witness_commitment_script.size()));
    }
    snap.frozen_ref.share_version   = rh_result.share_version;   // Pillar 1: AutoRatchet-voted
    snap.frozen_ref.desired_version = rh_result.desired_version;
    // Phase 12: source bits/max_bits/absheight/abswork/far_share_hash
    // from the ref_hash_fn result (which already walked the tracker for
    // the same values to feed compute_ref_hash_for_work). With these
    // populated, has_frozen=true in the create_share lambda properly
    // overrides create_local_share_v35's in-function tracker walk —
    // the override values are now correct (matching peers), instead of
    // forcing absheight=0 + share.m_bits=hardcoded-diff-1.
    snap.frozen_ref.bits            = rh_result.bits ? rh_result.bits
                                                      : share_bits_.load();
    snap.frozen_ref.max_bits        = rh_result.max_bits ? rh_result.max_bits
                                                          : share_max_bits_.load();
    snap.frozen_ref.timestamp       = rh_result.timestamp ? rh_result.timestamp
                                                           : curtime;
    snap.frozen_ref.absheight       = rh_result.absheight;
    snap.frozen_ref.abswork         = rh_result.abswork;
    snap.frozen_ref.far_share_hash  = rh_result.far_share_hash;
    snap.frozen_ref.ref_hash        = ref_hash;
    snap.frozen_ref.last_txout_nonce = ref_nonce;

    auto branches = get_stratum_merkle_branches();
    for (const auto& h : branches) {
        uint256 b;
        auto bb = ParseHex(h);
        if (bb.size() == 32) std::memcpy(b.begin(), bb.data(), 32);
        snap.frozen_ref.frozen_merkle_branches.push_back(b);
    }
    auto txs_field = wd->m_data.find("transactions");
    if (txs_field != wd->m_data.end() && txs_field->is_array()) {
        // a1 + H5 memo: build the per-tx hex vector ONCE and hand the snapshot a
        // shared_ptr to it (copies along CoinbaseResult -> JobSnapshot -> JobEntry
        // become refcount bumps, not deep copies of the full mempool tx hex).
        // The memo seam goes one further: it keys a single-slot cache to a
        // fingerprint over the merkle leaf set (wd->m_hashes), so a repeat call
        // against an UNCHANGED tx set reuses the cached shared_ptr instead of
        // re-serializing the whole mempool -- the dominant churn site in the
        // 2026-06-02 heaptrack (768MB / 1.2M calls). The key is the exact leaf
        // set that built this job merkle, so a hit is atomic-with-merkle by
        // construction. The seam does no locking; build_connection_coinbase runs
        // on connection threads, so guard the memo members with template_mutex_.
        std::lock_guard<std::mutex> lk(template_mutex_);
        snap.tx_data = btc::stratum::detail::tx_data_memo_get_or_build(
            wd->m_hashes, *txs_field, tx_data_fp_, tx_data_memo_);
    }
    snap.merkle_branches = std::move(branches);

    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// IWorkSource: share submission — Stage 4d (the hot path).
// ─────────────────────────────────────────────────────────────────────────────

nlohmann::json BTCWorkSource::mining_submit(
    const std::string& username, const std::string& job_id,
    const std::string& extranonce1, const std::string& extranonce2,
    const std::string& ntime, const std::string& nonce,
    const std::string& /*request_id*/,
    const std::map<uint32_t, std::vector<unsigned char>>& /*merged_addresses*/,
    const core::stratum::JobSnapshot* job)
{
    // Stratum-style JSON-RPC error payload (false + [code, message, null]).
    auto reject = [](int code, const char* msg) {
        return nlohmann::json::array({
            false, nlohmann::json::array({code, msg, nullptr})
        });
    };

    if (!job) {
        LOG_WARNING << "[BTC-STRATUM] submit reject (no JobSnapshot): user=" << username
                    << " job=" << job_id;
        return reject(21, "Job not found");
    }

    // ── Reconstruct full 80-byte block header from JobSnapshot + miner inputs ──
    //
    // 1. Coinbase = coinb1 ‖ extranonce1 ‖ extranonce2 ‖ coinb2
    // 2. coinbase_txid = SHA256d(coinbase) — non-witness for this stub
    // 3. merkle_root = ascend through frozen merkle branches starting from txid
    // 4. header = version(LE) ‖ prev_hash(LE) ‖ merkle_root ‖ ntime(LE)
    //             ‖ nbits(LE) ‖ nonce(LE)         (80 bytes total)
    // 5. pow_hash = SHA256d(header)
    // 6. Compare to block target + share target → classify

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

    // Ascend the stratum merkle branches. Branches are wire-formatted as
    // LE-internal bytes (see get_stratum_merkle_branches comment) — must
    // be parsed with ParseHex+memcpy, NOT SetHex (which reverses bytes).
    uint256 merkle_root = coinbase_txid;
    for (const auto& branch_hex : job->merkle_branches) {
        uint256 b;
        auto bb = ParseHex(branch_hex);
        if (bb.size() == 32) std::memcpy(b.begin(), bb.data(), 32);
        merkle_root = btc::coin::merkle_hash_pair(merkle_root, b);
    }

    // Build the 80-byte header (all little-endian little-endian).
    // prev_hash arrives in BE display-hex; reverse to internal byte order.
    auto prevhash_be = ParseHex(job->gbt_prevhash);
    std::vector<uint8_t> prevhash_le(prevhash_be.rbegin(), prevhash_be.rend());

    // 80-byte block header. version comes from the JobSnapshot as a uint32
    // (decimal). TODO(version-rolling): when BIP 310 is wired, the miner's
    // submitted version may differ from job->version within POOL_VERSION_MASK
    // — accept and use the miner's version then.
    std::vector<uint8_t> header;
    header.reserve(80);
    push_u32_le(header, job->version);
    header.insert(header.end(), prevhash_le.begin(), prevhash_le.end());
    header.insert(header.end(), merkle_root.data(), merkle_root.data() + 32);
    push_u32_le(header, parse_be_hex_u32(ntime));
    push_u32_le(header, parse_be_hex_u32(job->nbits));      // share-target bits in header
    push_u32_le(header, parse_be_hex_u32(nonce));

    uint256 pow_hash = Hash(std::span<const uint8_t>(header.data(), header.size()));

    // ── Non-fatal merkle self-check (producer/consumer contract guard) ──
    // Recompute the body merkle root over the full leaf set
    // [coinbase_txid, tx1..txN] and compare it to the branch-folded header
    // root above. If get_stratum_merkle_branches and the serialized body ever
    // disagree on the leaf structure (the latent bad-txnmrklroot class), this
    // logs a loud DIVERGENCE BEFORE the block is submitted and rejected. Uses
    // the current cached template's leaf set; a template roll between job
    // freeze and submit can produce a benign mismatch, so this is advisory
    // only and never rejects the share.
    if (auto wd_chk = cached_template()) {
        std::vector<uint256> body_leaves;
        body_leaves.reserve(wd_chk->m_hashes.size() + 1);
        body_leaves.push_back(coinbase_txid);
        body_leaves.insert(body_leaves.end(), wd_chk->m_hashes.begin(), wd_chk->m_hashes.end());
        uint256 body_root = btc::coin::compute_merkle_root(body_leaves);
        if (body_root == merkle_root) {
            LOG_DEBUG_OTHER << "[BTC-STRATUM] merkle self-check OK: body root matches header"
                            << " (" << body_leaves.size() << " leaves)";
        } else {
            LOG_WARNING << "[BTC-STRATUM] merkle self-check DIVERGENCE: header root="
                        << HexStr(std::span<const uint8_t>(merkle_root.data(), 32))
                        << " body root="
                        << HexStr(std::span<const uint8_t>(body_root.data(), 32))
                        << " over " << body_leaves.size() << " leaves"
                        << " — block would be rejected bad-txnmrklroot (template roll or leaf-set bug)";
        }
    }

    // Decode share target (separate from block target — pre-this-fix we
    // were comparing pow_hash against block target which is network
    // difficulty, so every share got rejected as low-diff. The miner
    // submits when their hash beats the per-session set_difficulty
    // target; we validate against the per-job share_bits (compact form
    // set by IWorkSource via get_share_bits()).
    uint256 share_target;
    if (job->share_bits != 0) {
        share_target.SetCompact(job->share_bits);
    } else {
        // Fallback for jobs frozen before share_bits was set — be
        // permissive: use the loosest possible target so PoW classifier
        // doesn't silently reject everything.
        share_target.SetCompact(/*diff 1*/ 0x1d00ffff);
    }

    uint256 block_target;
    block_target.SetCompact(parse_be_hex_u32(
        job->block_nbits.empty() ? job->nbits : job->block_nbits));

    auto pow_hex_short = pow_hash.GetHex().substr(0, 16);

    // ── Classify ──────────────────────────────────────────────────────────

    if (!(pow_hash > block_target)) {
        // pow_hash <= block_target → BLOCK FOUND.
        uint32_t height = 0;
        if (auto tip = chain_.tip(); tip) height = tip->height + 1;

        LOG_WARNING << "[BTC-STRATUM-BLOCK] *** BLOCK FOUND *** user=" << username
                    << " height~=" << height
                    << " pow_hash=" << pow_hex_short
                    << " job=" << job_id;

        // Build the full serialized block: header ‖ tx_count ‖ coinbase ‖ other_txs.
        // For segwit-active templates the coinbase MUST be serialized in BIP 144
        // form with the 32-byte witness reserved value as its single witness
        // stack item — bitcoind validates the OP_RETURN aa21a9ed commitment by
        // hashing (witness_root || reserved_value), and a missing witness here
        // makes that hash mismatch → block rejected as bad-witness-merkle-match.
        //
        // BIP 144 witness format inserts a marker(0x00) + flag(0x01) right
        // after the 4-byte version, and witness data right before the
        // 4-byte locktime. Coinbase witness = 1 stack item, 32 zero bytes.
        std::vector<uint8_t> coinbase_serialized = coinbase;
        if (job->segwit_active) {
            // Insert marker+flag after version (offset 4)
            const std::array<uint8_t, 2> marker_flag = {0x00, 0x01};
            coinbase_serialized.insert(coinbase_serialized.begin() + 4,
                marker_flag.begin(), marker_flag.end());
            // Append witness BEFORE locktime (last 4 bytes):
            //   [stack_count = 1][item_len = 0x20][32 zero bytes]
            std::array<uint8_t, 34> witness_bytes{};
            witness_bytes[0] = 0x01;  // stack_count
            witness_bytes[1] = 0x20;  // item_len = 32
            // bytes [2..33] already zero from default-init = WITNESS_RESERVED_VALUE
            coinbase_serialized.insert(coinbase_serialized.end() - 4,
                witness_bytes.begin(), witness_bytes.end());
        }

        // a1: lazy materialize the tx hex at submit time (the only reader).
        static const std::vector<std::string> kEmptyTxData;
        const std::vector<std::string>& txs =
            job->tx_data ? *job->tx_data : kEmptyTxData;

        std::vector<uint8_t> block_bytes;
        block_bytes.reserve(80 + 9 + coinbase_serialized.size() + txs.size() * 256);
        block_bytes.insert(block_bytes.end(), header.begin(), header.end());

        push_varint(block_bytes, 1 + txs.size());  // total tx count
        block_bytes.insert(block_bytes.end(),
            coinbase_serialized.begin(), coinbase_serialized.end());
        for (const auto& tx_hex : txs) {
            auto tx_bytes = ParseHex(tx_hex);
            block_bytes.insert(block_bytes.end(), tx_bytes.begin(), tx_bytes.end());
        }

        // A won block is a full subsidy: it must NEVER be silently dropped.
        // submit_block_fn_ relays via P2P (primary) and falls back to the
        // submitblock RPC; it returns true iff the block reached at least one
        // sink. If it reaches neither (false / throw / no fn wired) we scream.
        bool reached_network = false;
        if (submit_block_fn_) {
            try {
                reached_network = submit_block_fn_(block_bytes, height);
            } catch (const std::exception& e) {
                LOG_ERROR << "[BTC-STRATUM-BLOCK] submit_block_fn threw: " << e.what();
            }
            if (!reached_network) {
                LOG_ERROR << "[BTC-STRATUM-BLOCK] WON BLOCK height=" << height
                          << " reached NEITHER P2P nor RPC — lost subsidy!";
            }
        } else {
            LOG_ERROR << "[BTC-STRATUM-BLOCK] no submit_block_fn wired — WON BLOCK height="
                      << height << " not broadcast — lost subsidy!";
        }

        // Update worker stats (block-find counts as accepted)
        {
            std::lock_guard<std::mutex> lk(workers_mutex_);
            for (auto& [_, w] : workers_) {
                if (w.username == username) { w.accepted++; break; }
            }
        }
        return nlohmann::json(true);
    }

    if (!(pow_hash > share_target)) {
        // pow_hash <= share_target → share meets sharechain target.
        // Phase 11: dispatch to create_share_fn_ which builds a v35
        // PaddingBugfixShare, adds it to btc::ShareTracker, broadcasts
        // to peers, and bumps the local best. If the callback is unset
        // (degraded mode) we just log the acceptance — miner gets a
        // success reply but the share doesn't earn sharechain credit.

        CreateShareFn create_fn;
        {
            std::lock_guard<std::mutex> lk(callback_mutex_);
            create_fn = create_share_fn_;
        }

        uint256 share_hash;
        if (create_fn) {
            // Reconstruct the miner's payout_script from the username.
            // address_to_script handles bech32 (P2WPKH/P2WSH) + base58
            // (P2PKH/P2SH). Empty script (unsupported address format)
            // means the share can still be ADDED locally but won't carry
            // a payout — peers will reject it on consensus check, which
            // we tolerate during dev.
            auto payout_script = core::address_to_script(username);

            try {
                share_hash = create_fn(coinbase, header, *job, payout_script);
            } catch (const std::exception& e) {
                LOG_WARNING << "[BTC-STRATUM-SHARE] create_share_fn threw: "
                            << e.what() << " — share not added";
            }
        }

        if (!share_hash.IsNull()) {
            LOG_INFO << "[BTC-STRATUM-SHARE] ACCEPTED + ADDED user=" << username
                     << " share_hash=" << share_hash.GetHex().substr(0, 16)
                     << " pow_hash="   << pow_hex_short
                     << " job=" << job_id;
        } else if (create_fn) {
            // Callback was wired but couldn't add (tracker busy, prev_share
            // unknown, PoW recheck failed inside create_local_share, etc.).
            // Miner still gets a success reply since their PoW was valid.
            LOG_INFO << "[BTC-STRATUM-SHARE] accepted (deferred) user=" << username
                     << " pow_hash=" << pow_hex_short
                     << " job=" << job_id;
        } else {
            // No callback wired — degraded mode (proxy without sharechain).
            LOG_INFO << "[BTC-STRATUM-SHARE] accepted (no-tracker) user=" << username
                     << " pow_hash=" << pow_hex_short
                     << " job=" << job_id;
        }

        {
            std::lock_guard<std::mutex> lk(workers_mutex_);
            for (auto& [_, w] : workers_) {
                if (w.username == username) { w.accepted++; break; }
            }
        }
        return nlohmann::json(true);
    }

    // pow_hash > share_target → low-difficulty rejection.
    {
        std::lock_guard<std::mutex> lk(workers_mutex_);
        for (auto& [_, w] : workers_) {
            if (w.username == username) { w.rejected++; break; }
        }
    }
    return reject(23, "Low difficulty share");
}

// ─────────────────────────────────────────────────────────────────────────────
// BTC-specific control surface
// ─────────────────────────────────────────────────────────────────────────────

void BTCWorkSource::set_best_share_hash_fn(std::function<uint256()> fn)
{
    std::lock_guard<std::mutex> lk(best_share_mutex_);
    best_share_hash_fn_ = std::move(fn);
}

void BTCWorkSource::set_pplns_fn(PplnsFn fn)
{
    std::lock_guard<std::mutex> lk(callback_mutex_);
    pplns_fn_ = std::move(fn);
}

void BTCWorkSource::set_ref_hash_fn(RefHashFn fn)
{
    std::lock_guard<std::mutex> lk(callback_mutex_);
    ref_hash_fn_ = std::move(fn);
}

void BTCWorkSource::set_create_share_fn(CreateShareFn fn)
{
    std::lock_guard<std::mutex> lk(callback_mutex_);
    create_share_fn_ = std::move(fn);
}

double BTCWorkSource::compute_share_difficulty(
    const std::string& coinb1, const std::string& coinb2,
    const std::string& extranonce1, const std::string& extranonce2,
    const std::string& ntime, const std::string& nonce,
    uint32_t version, const std::string& prevhash_hex,
    const std::string& nbits_hex,
    const std::vector<std::string>& merkle_branches) const
{
    // Mirror of MiningInterface::calculate_share_difficulty (web_server.cpp)
    // but with SHA256d instead of scrypt for the PoW step. This is the
    // function whose return value gates pseudoshare acceptance in
    // stratum_server.cpp's handle_submit — getting this wrong (falling
    // back to LTC's scrypt) makes EVERY BTC submission look like garbage
    // diff and reject at the vardiff gate. Bitaxe testing 2026-05-01.

    // Reconstruct full coinbase: coinb1 || en1 || en2 || coinb2
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
    uint256 coinbase_txid = Hash(std::span<const uint8_t>(coinbase.data(), coinbase.size()));

    // Ascend stratum merkle branches. Branches are wire-formatted as LE
    // internal byte order (despite looking like BE display hex) — the
    // miner does `hex2bin` and feeds bytes directly into SHA256d.  Match
    // LTC's reconstruct_merkle_root (web_server.cpp:1330) which parses
    // via ParseHex + memcpy, NOT SetHex (which would reverse bytes and
    // produce a totally different merkle root than the miner computed).
    uint256 merkle_root = coinbase_txid;
    for (const auto& bhex : merkle_branches) {
        uint256 b;
        auto bb = ParseHex(bhex);
        if (bb.size() == 32) std::memcpy(b.begin(), bb.data(), 32);
        merkle_root = btc::coin::merkle_hash_pair(merkle_root, b);
    }

    // Build 80-byte header. prevhash arrives as BE display hex; reverse
    // to LE for header bytes.
    auto prevhash_be = ParseHex(prevhash_hex);
    std::vector<uint8_t> prevhash_le(prevhash_be.rbegin(), prevhash_be.rend());

    std::vector<uint8_t> header;
    header.reserve(80);
    push_u32_le(header, version);
    header.insert(header.end(), prevhash_le.begin(), prevhash_le.end());
    header.insert(header.end(), merkle_root.data(), merkle_root.data() + 32);
    push_u32_le(header, parse_be_hex_u32(ntime));
    push_u32_le(header, parse_be_hex_u32(nbits_hex));
    push_u32_le(header, parse_be_hex_u32(nonce));
    if (header.size() != 80) return 0.0;

    // SHA256d the header → pow_hash
    uint256 pow_hash = Hash(std::span<const uint8_t>(header.data(), header.size()));

    // diff = max_target / pow_hash (max_target = bitcoin diff-1 target)
    if (pow_hash.IsNull()) return 0.0;
    double diff = chain::target_to_difficulty(pow_hash);

    // Diagnostic — only first 5 to avoid spam. Detailed dump so we can
    // reproduce the bitaxe's expected hash off-line and pinpoint the
    // header-reconstruction bug (coinbase txid? merkle ascent? prevhash
    // byte-order? version-rolling convention?).
    {
        static std::atomic<int> diag{0};
        if (diag.fetch_add(1) < 5) {
            static const char* HX = "0123456789abcdef";
            auto to_hex = [&](const std::vector<uint8_t>& v) {
                std::string s; s.reserve(v.size()*2);
                for (auto b : v) { s += HX[b>>4]; s += HX[b&0xf]; }
                return s;
            };
            std::string hdr_hex; for (auto b : header) { hdr_hex += HX[b>>4]; hdr_hex += HX[b&0xf]; }
            LOG_INFO << "[BTC-DIFF] hdr=" << hdr_hex
                     << " pow=" << pow_hash.GetHex().substr(0,16)
                     << " diff=" << diff
                     << " ver=" << version << " ntime=" << ntime
                     << " nbits=" << nbits_hex << " nonce=" << nonce
                     << " en2=" << extranonce2;
            LOG_INFO << "[BTC-DIFF-CB] coinb1=" << coinb1
                     << " en1=" << extranonce1
                     << " en2=" << extranonce2
                     << " coinb2=" << coinb2;
            LOG_INFO << "[BTC-DIFF-CB] coinbase_full=" << to_hex(coinbase)
                     << " coinbase_txid_LE=" << HexStr(std::span<const uint8_t>(coinbase_txid.data(), 32))
                     << " coinbase_txid_BE=" << coinbase_txid.GetHex();
            for (size_t i = 0; i < merkle_branches.size(); ++i) {
                LOG_INFO << "[BTC-DIFF-MR] step=" << i
                         << " branch=" << merkle_branches[i];
            }
            LOG_INFO << "[BTC-DIFF-MR] merkle_root_LE="
                     << HexStr(std::span<const uint8_t>(merkle_root.data(), 32))
                     << " prevhash_in=" << prevhash_hex;
        }
    }
    return diff;
}

void BTCWorkSource::set_donation_script(std::vector<unsigned char> script)
{
    std::lock_guard<std::mutex> lk(callback_mutex_);
    donation_script_ = std::move(script);
}

}  // namespace btc::stratum