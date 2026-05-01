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
#include <impl/btc/coin/transaction.hpp>

#include <core/hash.hpp>
#include <core/log.hpp>
#include <btclibs/util/strencodings.h>          // HexStr, ParseHex

#include <cstdio>
#include <cstring>
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
    // Fallback coinbase split with no payout output (the per-connection
    // builder produces the real one). Used only when stratum sessions
    // ask for default parts before authorize completes — they then skip
    // mining.notify until build_connection_coinbase becomes available.
    return { {}, {} };
}

core::stratum::CoinbaseResult BTCWorkSource::build_connection_coinbase(
    const uint256& /*prev_share_hash*/,
    const std::string& /*extranonce1_hex*/,
    const std::vector<unsigned char>& payout_script,
    const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& /*merged_addrs*/) const
{
    // SOPHISTICATED STUB (B7-stratum-4c-iii). Produces a stratum-compatible
    // coinbase split with the miner's payout receiving the FULL subsidy
    // + fees. This is enough for end-to-end stratum-protocol testing and
    // mainnet PoW classification, but does NOT yet include the c2pool
    // sharechain payout outputs (PPLNS to other miners) or the p2pool
    // ref_hash extension. Shares submitted against this coinbase are
    // technically valid BTC blocks at PoW-target difficulty but won't
    // earn c2pool sharechain credit — the v35 share format coinbase
    // layout (jtoomim/SPB lineage) needs careful adaptation, which
    // belongs to a follow-up phase.
    //
    // TODO(B-future): add c2pool extra outputs:
    //   - Replace single full-payout output with PPLNS distribution
    //     among recent sharechain participants
    //   - Add c2pool donation output
    //   - Add OP_RETURN with c2pool protocol metadata (see
    //     core/coinbase_builder.hpp::C2POOL_PROTOCOL_VERSION)
    //   - Compute p2pool ref_hash via ShareTracker callback, populate
    //     CoinbaseResult.snapshot.frozen_ref accordingly
    //   - Handle segwit witness commitment OP_RETURN

    auto wd = btc::coin::TemplateBuilder::build_template(chain_, mempool_, is_testnet_);
    if (!wd) return {};

    uint32_t height        = wd->m_data.value("height", 0u);
    uint64_t coinbasevalue = wd->m_data.value("coinbasevalue", uint64_t{0});

    auto bip34 = bip34_height_push(height);
    constexpr size_t EXTRANONCE_SIZE = 8;  // 4 (extranonce1) + 4 (extranonce2)
    static const std::string POOL_TAG = "/c2pool-btc/";
    std::vector<uint8_t> tag_bytes(POOL_TAG.begin(), POOL_TAG.end());

    const size_t scriptsig_len = bip34.size() + EXTRANONCE_SIZE + tag_bytes.size();

    // ── coinb1: tx prefix up to (but not including) the extranonce slot ──
    std::vector<uint8_t> coinb1;
    push_u32_le(coinb1, /*tx version*/ 2);
    coinb1.push_back(0x01);                                     // vin_count = 1
    coinb1.insert(coinb1.end(), 32, 0x00);                       // prev_hash = 32 zero bytes
    push_u32_le(coinb1, 0xFFFFFFFFu);                            // prev_vout = 0xFFFFFFFF
    push_varint(coinb1, scriptsig_len);                          // scriptSig length
    coinb1.insert(coinb1.end(), bip34.begin(), bip34.end());     // BIP 34 height push

    // ── coinb2: scriptSig tail + sequence + outputs + locktime ──
    std::vector<uint8_t> coinb2;
    coinb2.insert(coinb2.end(), tag_bytes.begin(), tag_bytes.end());  // /c2pool-btc/
    push_u32_le(coinb2, 0xFFFFFFFFu);                            // sequence
    coinb2.push_back(0x01);                                      // vout_count = 1
    push_u64_le(coinb2, coinbasevalue);                          // value (subsidy + fees)
    push_varint(coinb2, payout_script.size());
    coinb2.insert(coinb2.end(), payout_script.begin(), payout_script.end());
    push_u32_le(coinb2, 0);                                      // locktime

    core::stratum::CoinbaseResult result;
    result.coinb1 = HexStr(std::span<const uint8_t>(coinb1.data(), coinb1.size()));
    result.coinb2 = HexStr(std::span<const uint8_t>(coinb2.data(), coinb2.size()));

    // Snapshot — frozen state matching this coinbase. Stratum sessions
    // store this in their JobEntry and pass it to mining_submit later.
    auto& snap = result.snapshot;
    snap.subsidy            = coinbasevalue;
    snap.segwit_active      = false;  // TODO: detect from wd->m_data["rules"]
    snap.witness_root       = uint256::ZERO;  // TODO: when segwit
    snap.frozen_ref.share_version  = 35;      // jtoomim BTC v35
    snap.frozen_ref.desired_version = 35;
    snap.frozen_ref.bits           = share_bits_.load();
    snap.frozen_ref.max_bits       = share_max_bits_.load();
    // frozen_merkle_branches mirrors public branches for now
    auto branches = get_stratum_merkle_branches();
    for (const auto& h : branches) {
        uint256 b;
        b.SetHex(h.c_str());
        snap.frozen_ref.frozen_merkle_branches.push_back(b);
    }
    // Capture raw tx hex from template (excludes coinbase — sessions reconstruct
    // the coinbase from coinb1+extranonces+coinb2)
    auto txs_field = wd->m_data.find("transactions");
    if (txs_field != wd->m_data.end() && txs_field->is_array()) {
        for (const auto& t : *txs_field) {
            if (t.is_object() && t.contains("data") && t["data"].is_string())
                snap.tx_data.push_back(t["data"].get<std::string>());
        }
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

    // Ascend the stratum merkle branches.
    uint256 merkle_root = coinbase_txid;
    for (const auto& branch_hex : job->merkle_branches) {
        uint256 b;
        b.SetHex(branch_hex.c_str());
        merkle_root = btc::coin::merkle_hash_pair(merkle_root, b);
    }

    // Build the 80-byte header (all little-endian little-endian).
    // prev_hash arrives in BE display-hex; reverse to internal byte order.
    auto prevhash_be = ParseHex(job->gbt_prevhash);
    std::vector<uint8_t> prevhash_le(prevhash_be.rbegin(), prevhash_be.rend());

    std::vector<uint8_t> header;
    header.reserve(80);
    push_u32_le(header, parse_be_hex_u32(std::to_string(job->version) /*decimal!*/));
    // ↑ subtle: version arrives as a decimal int in JobSnapshot, not BE hex.
    // The miner sends it in mining.submit ALSO as BE hex — we'd want that one,
    // but the miner can override for ASICBoost. For the stub we use the job's
    // version directly. (TODO: respect submitted version when version-rolling
    // is enabled and within POOL_VERSION_MASK.)
    header.clear();
    header.reserve(80);
    push_u32_le(header, job->version);
    header.insert(header.end(), prevhash_le.begin(), prevhash_le.end());
    header.insert(header.end(), merkle_root.data(), merkle_root.data() + 32);
    push_u32_le(header, parse_be_hex_u32(ntime));
    push_u32_le(header, parse_be_hex_u32(job->nbits));      // share-target bits in header
    push_u32_le(header, parse_be_hex_u32(nonce));

    uint256 pow_hash = Hash(std::span<const uint8_t>(header.data(), header.size()));

    // Decode share target (compact bits in header) and block target.
    uint256 share_target;
    share_target.SetCompact(parse_be_hex_u32(job->nbits));

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
        std::vector<uint8_t> block_bytes;
        block_bytes.reserve(80 + 9 + coinbase.size() + job->tx_data.size() * 256);
        block_bytes.insert(block_bytes.end(), header.begin(), header.end());

        push_varint(block_bytes, 1 + job->tx_data.size());  // total tx count
        block_bytes.insert(block_bytes.end(), coinbase.begin(), coinbase.end());
        for (const auto& tx_hex : job->tx_data) {
            auto tx_bytes = ParseHex(tx_hex);
            block_bytes.insert(block_bytes.end(), tx_bytes.begin(), tx_bytes.end());
        }

        if (submit_block_fn_) {
            try {
                submit_block_fn_(block_bytes, height);
            } catch (const std::exception& e) {
                LOG_WARNING << "[BTC-STRATUM-BLOCK] submit_block_fn threw: " << e.what();
            }
        } else {
            LOG_WARNING << "[BTC-STRATUM-BLOCK] no submit_block_fn wired — block not broadcast";
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
        // pow_hash <= share_target → share accepted.
        // TODO(B-future): record share in btc::ShareTracker (PPLNS state update).
        // For the stub, we accept the share but don't yet propagate to the
        // sharechain peer. The miner will see "share accepted" stratum responses
        // but the c2pool dashboard / payouts will be empty until ShareTracker
        // wiring lands.
        LOG_INFO << "[BTC-STRATUM-SHARE] accepted user=" << username
                 << " pow_hash=" << pow_hex_short
                 << " job=" << job_id;
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

void BTCWorkSource::set_donation_script(std::vector<unsigned char> script)
{
    std::lock_guard<std::mutex> lk(callback_mutex_);
    donation_script_ = std::move(script);
}

}  // namespace btc::stratum
