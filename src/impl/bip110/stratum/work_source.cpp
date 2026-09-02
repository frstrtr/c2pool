// SPDX-License-Identifier: AGPL-3.0-or-later

#include "work_source.hpp"

#include "../coin/header_chain.hpp"
#include "../coin/template_builder.hpp"   // get_block_subsidy
#include "../coin/gentx_coinbase.hpp"
#include "../pow.hpp"

#include <core/target_utils.hpp>
#include <core/log.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>

namespace bip110::stratum {

using core::stratum::CoinbaseResult;
using core::stratum::JobSnapshot;
using core::stratum::StratumConfig;
using core::stratum::WorkerInfo;
using core::stratum::WorkSnapshot;

namespace {

std::array<unsigned char, 4> hex4(const std::string& h)
{
    std::array<unsigned char, 4> a{};
    auto b = from_hex(h);
    for (size_t i = 0; i < 4 && i < b.size(); ++i) a[i] = b[i];
    return a;
}

// Parse a 4- or 8-byte submit hex into an 8-byte big-endian buffer. A 4-byte
// value fills the LOW half; the high half stays zero (m_nonce2 / m_nonce3 = 0).
std::array<unsigned char, 8> hex8_low(const std::string& h)
{
    std::array<unsigned char, 8> a{};
    auto b = from_hex(h);
    if (b.size() >= 8) { for (int i = 0; i < 8; ++i) a[i] = b[i]; }
    else { for (size_t i = 0; i < b.size() && i < 4; ++i) a[4 + i] = b[i]; }
    return a;
}

std::string bits_hex(uint32_t bits)
{
    char buf[9]; std::snprintf(buf, sizeof(buf), "%08x", bits); return std::string(buf);
}

}  // namespace

Bip110WorkSource::Bip110WorkSource(bip110::coin::HeaderChain& chain,
                                   bool is_testnet,
                                   SubmitBlockFn submit_fn,
                                   StratumConfig config)
    : chain_(chain)
    , is_testnet_(is_testnet)
    , submit_block_fn_(std::move(submit_fn))
    , config_(std::move(config))
{
    // BIP-110-native stratum defaults (SHA256d-net multiplier, coinbase-only
    // weight cap, atomic header+coinbase snapshot required — the payee/height is
    // committed INTO h1 so a job can never mix templates; raw wire prevhash).
    config_.coin_symbol             = "BIP110";
    config_.set_difficulty_multiplier = 1.0;   // BLAKE2b net, not scrypt
    config_.require_job_snapshot    = true;
    config_.raw_prevhash_wire       = true;
    config_.disable_version_rolling = true;   // R4: header commits version in h1
    if (config_.max_coinbase_outputs == 0 || config_.max_coinbase_outputs > 1500)
        config_.max_coinbase_outputs = 1500;   // R8 weight guard (800000 WU cap)

    // Seed the share floor at the powLimit so the pool-difficulty gate is
    // non-zero from the first job (miners get accepted pseudoshares immediately).
    const uint32_t floor_bits = 0x1d00ffffu;
    share_bits_.store(floor_bits);
    share_max_bits_.store(floor_bits);
}

Bip110WorkSource::~Bip110WorkSource() = default;

std::function<uint256()> Bip110WorkSource::get_best_share_hash_fn() const
{
    return {};  // M2: no p2pool sharechain best-share (create_share_fn unset)
}

Bip110WorkSource::NextWork Bip110WorkSource::next_work() const
{
    NextWork w;
    auto tip = chain_.tip();
    if (!tip) return w;
    const auto& params = chain_.params();
    w.prev    = tip->block_hash;
    w.height  = tip->height + 1;
    w.curtime = static_cast<uint32_t>(std::time(nullptr));

    auto get_anc = [this](uint32_t h) -> std::optional<bip110::coin::IndexEntry> {
        return chain_.get_header_by_height(h);
    };
    uint32_t nb = bip110::coin::get_next_work_required(
        get_anc, tip->height, tip->header.m_bits, tip->header.m_timestamp, w.curtime, params);
    if (nb == 0) nb = (tip->header.m_bits != 0) ? tip->header.m_bits : params.pow_limit.GetCompact();
    w.nbits = nb;

    w.subsidy = bip110::coin::get_block_subsidy(w.height, params.subsidy_halving_interval);
    // block_version 0xA0000000 = bit31 (v2) | 0x20000000 (BIP9 base).
    w.version = 0xA0000000u;
    w.ok = true;
    return w;
}

nlohmann::json Bip110WorkSource::get_current_work_template() const
{
    NextWork w = next_work();
    if (!w.ok) return nlohmann::json();
    nlohmann::json j;
    j["previousblockhash"] = w.prev.GetHex();
    j["height"]            = static_cast<int>(w.height);
    j["bits"]              = bits_hex(w.nbits);
    j["version"]           = static_cast<int64_t>(w.version);
    j["curtime"]           = static_cast<int64_t>(w.curtime);
    j["coinbasevalue"]     = static_cast<int64_t>(w.subsidy);
    return j;
}

std::string Bip110WorkSource::get_current_gbt_prevhash() const
{
    // Return the current tip's Sia prevblock_hidden (the SAME form the job's
    // gbt_prevhash carries), so the core's DOA/clean_jobs comparison is
    // like-for-like — not the raw tip block hash (which would flag every share).
    NextWork w = next_work();
    if (!w.ok) return std::string();
    Bytes32 prev; std::memcpy(prev.data(), w.prev.data(), 32);
    return to_hex(prevblock_hidden_from_prev(prev));
}

CoinbaseResult Bip110WorkSource::build_connection_coinbase(
    const uint256& /*prev_share_hash*/,
    const std::string& extranonce1_hex,
    const std::vector<unsigned char>& payout_script,
    const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& /*merged_addrs*/) const
{
    CoinbaseResult out;
    NextWork w = next_work();
    if (!w.ok) return out;  // chain not synced -> core suppresses the job

    // ── Build the FULL coinbase (BIP34 height + tag + witness-commitment(zero
    // witness root) + payout + donation + OP_RETURN ref). Coinbase-only, so the
    // whole reward is the single payout (fallback: subsidy -> miner). ──
    std::vector<unsigned char> cb_script;
    {
        // BIP34 minimal-push of the height.
        uint32_t h = w.height;
        std::vector<unsigned char> he;
        while (h) { he.push_back(h & 0xff); h >>= 8; }
        if (he.empty() || (he.back() & 0x80)) he.push_back(0x00);
        cb_script.push_back(static_cast<unsigned char>(he.size()));
        cb_script.insert(cb_script.end(), he.begin(), he.end());
        static const char* tag = "/c2pool-bip110/";
        for (const char* c = tag; *c; ++c) cb_script.push_back((unsigned char)*c);
    }

    // Witness commitment over a zero witness-merkle-root (coinbase-only: the only
    // wtxid is the coinbase's, defined as 0). BIP141 header 6a24aa21a9ed || root.
    std::vector<unsigned char> wroot(32, 0);
    {
        // commitment = SHA256d( witness_merkle_root(=0) || witness_reserved(=0*32) )
        std::vector<unsigned char> pre(64, 0);
        unsigned char a[32], b[32];
        CSHA256().Write(pre.data(), pre.size()).Finalize(a);
        CSHA256().Write(a, 32).Finalize(b);
        std::memcpy(wroot.data(), b, 32);
    }
    std::optional<std::vector<unsigned char>> segwit_commit;
    {
        std::vector<unsigned char> sc = {0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed};
        sc.insert(sc.end(), wroot.begin(), wroot.end());
        segwit_commit = std::move(sc);
    }

    // ── PER-BLOCK REWARD SPLIT (author donation + node-owner fee) + BURN GUARD ─
    // Integer FLOOR division ONLY (no float): the miner absorbs every remainder
    // (never burned, never over-claimed). Σ(all value outputs) == subsidy EXACTLY.
    //
    //   don   = subsidy * give_author_ppm  / 1e6   (0 if no donation script)
    //   owner = subsidy * node_owner_fee_ppm / 1e6 (0 if no owner script)
    //   miner = subsidy - don - owner               (remainder to the miner)
    //
    // The node-owner fee is paid to node_owner_script_ when set, otherwise to the
    // donation script (single-key consolidation: our 13zQ/bc1qyr94… key). When the
    // owner destination EQUALS the donation destination, don+owner are summed into
    // ONE output (saves a whole vout under the RDTS 800000 WU cap) rather than two.
    //
    // DEFECT 2 BURN GUARD: if the miner's payout script failed to resolve (empty)
    // AND no donation address is configured, every value-bearing output would be 0
    // and a found block would silently BURN the whole subsidy. Refuse to serve
    // such work — return an empty CoinbaseResult (empty coinb1), which the core
    // treats exactly like a not-yet-synced template and suppresses the job.
    const uint64_t subsidy = w.subsidy;
    const std::vector<unsigned char>& owner_script =
        !node_owner_script_.empty() ? node_owner_script_ : donation_script_;

    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> payouts;
    uint64_t donation_amt = 0;
    std::vector<unsigned char> donation = donation_script_;

    if (!payout_script.empty()) {
        // NORMAL MINING: split the subsidy between miner, author donation, owner.
        uint64_t don   = (!donation_script_.empty() && give_author_ppm_ > 0)
                       ? (subsidy * give_author_ppm_ / 1000000ULL) : 0;   // floor
        uint64_t owner = (!owner_script.empty() && node_owner_fee_ppm_ > 0)
                       ? (subsidy * node_owner_fee_ppm_ / 1000000ULL) : 0; // floor
        if (don + owner >= subsidy) {
            LOG_ERROR << "[BIP110-WS] REFUSING work: author+owner split (" << don << "+"
                      << owner << ") >= subsidy " << subsidy << " — would leave the miner "
                         "<= 0 (height=" << w.height << "). Lower --give-author / --fee.";
            return CoinbaseResult{};
        }
        uint64_t miner = subsidy - don - owner;    // remainder absorbs all rounding
        payouts.emplace_back(payout_script, miner);

        // Consolidate the author donation and the node-owner fee when they share a
        // key; otherwise emit a separate node-owner output.
        const bool same_key = (!owner_script.empty()
                            && !donation_script_.empty()
                            && owner_script == donation_script_);
        if (owner > 0 && same_key) {
            donation_amt = don + owner;            // ONE consolidated output
            donation     = donation_script_;
        } else {
            donation_amt = don;                    // author donation output (may be 0)
            donation     = donation_script_;
            if (owner > 0)                          // separate node-owner output
                payouts.emplace_back(owner_script, owner);
        }
    } else if (!donation_script_.empty()) {
        donation_amt = subsidy;                    // no miner script -> all to donation
        donation     = donation_script_;
    } else {
        LOG_ERROR << "[BIP110-WS] REFUSING work: miner payout script empty AND no "
                     "donation/node-owner address configured — serving would burn the "
                     "entire subsidy (height=" << w.height << "). Set --node-owner-address.";
        return CoinbaseResult{};
    }
    if (donation.empty()) donation = {0x6a};      // OP_RETURN placeholder (0-value)

    // Value-conservation guard: the sum of all non-commitment output values MUST
    // equal subsidy + fees (M2: fees == 0). A mismatch means a construction bug
    // would over-claim or burn value — refuse rather than emit an invalid/burning
    // coinbase.
    {
        uint64_t total_out = donation_amt;
        for (const auto& [scr, amt] : payouts) { (void)scr; total_out += amt; }
        if (total_out != w.subsidy) {
            LOG_ERROR << "[BIP110-WS] REFUSING work: coinbase output value " << total_out
                      << " != subsidy+fees " << w.subsidy << " (height=" << w.height << ")";
            return CoinbaseResult{};
        }
    }

    // OP_RETURN ref marker (M2: empty commitment; M3 carries the share ref).
    std::vector<unsigned char> op_return = {0x6a, 0x00};

    auto cb = bip110::coin::assemble_gentx_coinbase(
        cb_script, segwit_commit, payouts, donation_amt, donation, op_return);

    // Freeze the header-committed fields over this coinbase.
    HeaderFreeze f;
    f.version[0] = w.version & 0xff; f.version[1] = (w.version >> 8) & 0xff;
    f.version[2] = (w.version >> 16) & 0xff; f.version[3] = (w.version >> 24) & 0xff;
    std::memcpy(f.prev.data(), w.prev.data(), 32);            // internal order
    std::memcpy(f.merkle.data(), cb.txid.data(), 32);        // coinbase txid == merkle (coinbase-only)
    f.time[0] = w.curtime & 0xff; f.time[1] = (w.curtime >> 8) & 0xff;
    f.time[2] = (w.curtime >> 16) & 0xff; f.time[3] = (w.curtime >> 24) & 0xff;
    f.nbits[0] = w.nbits & 0xff; f.nbits[1] = (w.nbits >> 8) & 0xff;
    f.nbits[2] = (w.nbits >> 16) & 0xff; f.nbits[3] = (w.nbits >> 24) & 0xff;
    f.txcount = 1;
    f.flags = 0; f.clear_bits = 0;                            // R10
    f.height = w.height;
    compute_h1_h2(f);

    // h2 self-check: recompute h2 from the wire coinb1 and compare (loud on skew).
    auto coinb1 = wire_coinb1_bytes(f.h2);
    {
        Bytes32 h2_wire = parse_h2_from_wire_coinb1(coinb1);
        if (h2_wire != f.h2)
            LOG_WARNING << "[BIP110-WS] h2 self-check MISMATCH — freeze vs wire coinb1 diverge!";
    }

    // Persist the freeze keyed by hex(h2) for the submit path.
    {
        std::lock_guard<std::mutex> lk(freeze_mutex_);
        gc_freezes();
        FreezeEntry e; e.freeze = f;
        e.coinbase       = cb.bytes;        // non-witness (txid/merkle/share source)
        e.coinbase_block = cb.block_bytes;  // BIP144 witness form for the block body
        e.payout_script  = payout_script;   // M3: the miner the share must pay
        e.at = std::chrono::steady_clock::now();
        freeze_map_[to_hex(f.h2)] = std::move(e);
    }

    out.coinb1 = to_hex(coinb1);
    out.coinb2 = "";                                          // empty (Sv1 BLAKE2b)

    // Atomic header+coinbase snapshot: prevhash sent RAW on the wire (the Sia
    // ASIC needs prevblock_hidden as-is; core's raw_prevhash_wire honours it).
    WorkSnapshot& s = out.snapshot;
    s.has_header      = true;
    s.gbt_prevhash    = to_hex(f.prevblock_hidden);
    s.header_version  = w.version;
    s.block_nbits_hex = bits_hex(w.nbits);
    s.curtime         = w.curtime;
    s.height          = w.height;
    s.subsidy         = w.subsidy;
    s.segwit_active   = true;
    s.merkle_branches = {};                                   // literally empty
    s.witness_root    = uint256::ZERO;
    return out;
}

bool Bip110WorkSource::recompute_pow(
    const std::string& coinb1,
    const std::string& extranonce1, const std::string& extranonce2,
    const std::string& ntime, const std::string& nonce,
    uint256& pow_out, std::vector<unsigned char>& header_out,
    HeaderFreeze& freeze_out) const
{
    auto c1 = from_hex(coinb1);
    if (c1.size() < 36) return false;
    Bytes32 h2 = parse_h2_from_wire_coinb1(c1);
    std::string key = to_hex(h2);
    {
        std::lock_guard<std::mutex> lk(freeze_mutex_);
        auto it = freeze_map_.find(key);
        if (it == freeze_map_.end()) return false;
        freeze_out = it->second.freeze;
    }
    auto en1 = hex4(extranonce1);
    auto en2 = hex4(extranonce2);
    auto n8  = hex8_low(nonce);
    auto t8  = hex8_low(ntime);
    header_out = rebuild_header_v2(freeze_out, en1, en2, n8, t8);
    pow_out = bip110::pow::blake2b_block_hash(
        std::span<const unsigned char>(header_out.data(), header_out.size()));
    return true;
}

double Bip110WorkSource::compute_share_difficulty(
    const std::string& coinb1, const std::string& /*coinb2*/,
    const std::string& extranonce1, const std::string& extranonce2,
    const std::string& ntime, const std::string& nonce,
    uint32_t /*version*/, const std::string& /*prevhash_hex*/,
    const std::string& /*nbits_hex*/,
    const std::vector<std::string>& /*merkle_branches*/) const
{
    uint256 pow; std::vector<unsigned char> hdr; HeaderFreeze f;
    if (!recompute_pow(coinb1, extranonce1, extranonce2, ntime, nonce, pow, hdr, f))
        return 0.0;
    return chain::target_to_difficulty(pow);  // diff1 / pow (standard convention)
}

nlohmann::json Bip110WorkSource::mining_submit(
    const std::string& username, const std::string& /*job_id*/,
    const std::string& extranonce1, const std::string& extranonce2,
    const std::string& ntime, const std::string& nonce,
    const std::string& /*request_id*/,
    const std::map<uint32_t, std::vector<unsigned char>>& /*merged_addresses*/,
    const JobSnapshot* job)
{
    if (!job) return nlohmann::json(true);
    uint256 pow; std::vector<unsigned char> hdr; HeaderFreeze f;
    if (!recompute_pow(job->coinb1, extranonce1, extranonce2, ntime, nonce, pow, hdr, f)) {
        LOG_WARNING << "[BIP110-WS] submit for unknown/expired freeze (h2 miss) from " << username;
        return nlohmann::json(true);
    }

    // Block classification against the GBT block target (independent recompute —
    // never trust a miner-reported hash).
    uint32_t block_bits = f.nbits[0] | (f.nbits[1] << 8) | (f.nbits[2] << 16) | ((uint32_t)f.nbits[3] << 24);
    uint256 block_target = chain::bits_to_target(block_bits);
    const bool is_block = (pow <= block_target);

    if (is_block) {
        // BLOCK ARM: reassemble 164-byte v2 header || varint(txcount=1) || coinbase.
        // Use the BIP144 witness coinbase (coinbase_block): the block body carries
        // the commitment output, so its coinbase MUST expose the 1x32-byte witness
        // reserved value or fork peers/submitblock reject bad-witness-nonce-size
        // (DEFECT 1). txid/merkle/h1 were computed over the non-witness bytes and
        // are unchanged by the witness — the PoW re-slice below re-proves it.
        std::vector<unsigned char> coinbase;
        {
            std::lock_guard<std::mutex> lk(freeze_mutex_);
            auto it = freeze_map_.find(to_hex(f.h2));
            if (it != freeze_map_.end()) coinbase = it->second.coinbase_block;
        }
        std::vector<unsigned char> block = hdr;
        block.push_back(0x01);                                  // txcount varint = 1
        block.insert(block.end(), coinbase.begin(), coinbase.end());

        // Re-slice self-check: header || the recompute must be byte-consistent.
        uint256 verify = bip110::pow::blake2b_block_hash(
            std::span<const unsigned char>(block.data(), 164));
        LOG_INFO << "[BIP110-WS] BLOCK FOUND by " << username
                 << " height=" << f.height << " hash=" << pow.GetHex()
                 << " reassembled=" << block.size() << "B verify=" << (verify == pow ? "ok" : "MISMATCH");
        bool sunk = submit_block_fn_ ? submit_block_fn_(block, f.height) : false;
        if (!sunk)
            LOG_ERROR << "[BIP110-WS] won block reached NO network sink (height=" << f.height << ")";
        return nlohmann::json(true);
    }

    // SHARE ARM (M3 seam): p2pool sharechain write. Unset in M2 -> validated +
    // counted by the core, no mint.
    if (create_share_fn_) {
        std::vector<unsigned char> coinbase;
        std::vector<unsigned char> payout_script;
        {
            std::lock_guard<std::mutex> lk(freeze_mutex_);
            auto it = freeze_map_.find(to_hex(f.h2));
            if (it != freeze_map_.end()) {
                coinbase      = it->second.coinbase;
                payout_script = it->second.payout_script;
            }
        }
        // M3 mint seam: pay the SUBMITTING miner (payout_script), mirroring the
        // btc create_local_share path (main_btc.cpp:2338-2345). Unset here until
        // the bip110 sharechain lane exists — see the header note.
        create_share_fn_(coinbase, hdr, payout_script, *job);
    }
    return nlohmann::json(true);
}

void Bip110WorkSource::register_stratum_worker(const std::string& id, const WorkerInfo& info)
{
    std::lock_guard<std::mutex> lk(workers_mutex_);
    workers_[id] = info;
}

void Bip110WorkSource::unregister_stratum_worker(const std::string& id)
{
    std::lock_guard<std::mutex> lk(workers_mutex_);
    workers_.erase(id);
}

void Bip110WorkSource::update_stratum_worker(const std::string& id, double hr, double dead,
                                             double diff, uint64_t acc, uint64_t rej, uint64_t stale)
{
    std::lock_guard<std::mutex> lk(workers_mutex_);
    auto it = workers_.find(id);
    if (it == workers_.end()) return;
    it->second.hashrate = hr; it->second.dead_hashrate = dead; it->second.difficulty = diff;
    it->second.accepted = acc; it->second.rejected = rej; it->second.stale = stale;
}

void Bip110WorkSource::gc_freezes() const
{
    // caller holds freeze_mutex_
    const auto now = std::chrono::steady_clock::now();
    for (auto it = freeze_map_.begin(); it != freeze_map_.end();) {
        if (now - it->second.at > FREEZE_TTL) it = freeze_map_.erase(it);
        else ++it;
    }
}

}  // namespace bip110::stratum
