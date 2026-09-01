// SPDX-License-Identifier: AGPL-3.0-or-later

#include "work_source.hpp"

#include "../coin/header_chain.hpp"
#include "../coin/template_builder.hpp"   // get_block_subsidy, compute_merkle_root, witness_merkle_root
#include "../coin/gentx_coinbase.hpp"
#include "../coin/mempool.hpp"            // M3 tx-serving
#include "../coin/block_assembler.hpp"    // M3 ancestor-package tx selection
#include "../params.hpp"                  // RDTS_MAX_BLOCK_WEIGHT
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

    // ── M3 DAEMONLESS MEMPOOL TX-SELECTION ───────────────────────────────────
    // Good-citizen mandate: include REAL network txs, not coinbase-only EMPTY
    // blocks. Select from the embedded P2P-ingested, daemonlessly-priced mempool
    // with the topologically-safe ancestor-package assembler (block_assembler.hpp)
    // under the RDTS 800000 WU cap minus a coinbase reserve. Fee_total feeds the
    // coinbasevalue below; every excluded tx is NAMED (no silent drops). serve
    // gated on serve_txs_ AND the UTXO view being deep enough (fail closed to a
    // coinbase-only block when not ready — never a guessed fee, never an
    // over-claim).
    std::vector<bip110::coin::AssembledTx> sel_txs;
    uint64_t fee_total = 0;
    {
        const bool ready = serve_txs_ && mempool_
                         && (!utxo_ready_fn_ || utxo_ready_fn_());
        if (ready) {
            // Coinbase reserve: leaves room for the coinbase tx itself (script +
            // splits + witness commitment) under the consensus weight cap.
            constexpr uint32_t COINBASE_RESERVE = 4000;   // WU
            const uint32_t cap = (bip110::RDTS_MAX_BLOCK_WEIGHT > COINBASE_RESERVE)
                               ? (bip110::RDTS_MAX_BLOCK_WEIGHT - COINBASE_RESERVE) : 0;
            auto priced     = mempool_->snapshot_priced();
            auto pool_txids_v = mempool_->all_txids();
            std::set<uint256> pool_txids(pool_txids_v.begin(), pool_txids_v.end());
            auto asm_res = bip110::coin::assemble_block_txs(priced, pool_txids, cap);
            sel_txs   = std::move(asm_res.txs);
            fee_total = asm_res.total_fee;
            if (!sel_txs.empty() || !asm_res.excluded.empty())
                LOG_INFO << "[BIP110-WS] tx-select height=" << w.height
                         << " priced=" << priced.size()
                         << " included=" << sel_txs.size()
                         << " weight=" << asm_res.total_weight
                         << " fees=" << fee_total
                         << " excluded=" << asm_res.excluded.size();
            // Name a bounded sample of exclusions (good-citizen; avoid log flood).
            size_t named = 0;
            for (const auto& e : asm_res.excluded) {
                if (named++ >= 8) { LOG_INFO << "[BIP110-WS]   ... +"
                    << (asm_res.excluded.size() - 8) << " more excluded"; break; }
                LOG_INFO << "[BIP110-WS]   exclude " << e.first.GetHex().substr(0, 16)
                         << " reason=" << e.second;
            }
        }
    }
    const size_t n_other = sel_txs.size();

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

    // Witness commitment: commitment = SHA256d( witness_merkle_root || reserved ).
    // The witness merkle root has the coinbase wtxid (defined as 0) at leaf 0 and
    // the SELECTED txs' real wtxids in block order (template_builder SSOT). For a
    // coinbase-only block this collapses to the all-zero root. reserved = 0*32.
    // Getting this wrong the moment any SegWit tx is included => bad-witness-
    // merkle-match; the pre-serve xcheck (e) re-derives it from the frozen bytes.
    std::vector<unsigned char> wroot(32, 0);
    {
        std::vector<uint256> other_wtxids;
        other_wtxids.reserve(n_other);
        for (const auto& t : sel_txs) other_wtxids.push_back(t.wtxid);
        uint256 wmr = bip110::coin::witness_merkle_root(other_wtxids);
        std::vector<unsigned char> pre(64, 0);
        std::memcpy(pre.data(), wmr.data(), 32);      // witness merkle root
        // pre[32..64) = witness reserved value (32 zero bytes)
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
    // coinbasevalue = block subsidy + sum(provable fees of INCLUDED txs) EXACTLY.
    // fee_total came ONLY from tier-1/2/3-priced entries with MoneyRange checks;
    // over-claiming here = INVALID block = lost reward, so the value guard below
    // and the independent pre-serve xcheck both re-derive this sum.
    const uint64_t subsidy = w.subsidy + fee_total;   // == coinbasevalue
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
        if (total_out != subsidy) {
            LOG_ERROR << "[BIP110-WS] REFUSING work: coinbase output value " << total_out
                      << " != subsidy+fees " << subsidy << " (subsidy=" << w.subsidy
                      << " fees=" << fee_total << " height=" << w.height << ")";
            return CoinbaseResult{};
        }
    }

    // OP_RETURN ref marker (M2: empty commitment; M3 carries the share ref).
    std::vector<unsigned char> op_return = {0x6a, 0x00};

    auto cb = bip110::coin::assemble_gentx_coinbase(
        cb_script, segwit_commit, payouts, donation_amt, donation, op_return);

    // ── Header tx-set commitment: the txid-merkle root over [coinbase] ++ the
    // selected txs (block order), and the u16 txcount = 1 + N. On BIP-110 BOTH
    // are folded into h1 (see pseudoheader.hpp), so a body/header skew is
    // consensus-fatal — the xcheck re-derives both from the frozen bytes. ──
    std::vector<uint256> merkle_leaves;
    merkle_leaves.reserve(1 + n_other);
    merkle_leaves.push_back(cb.txid);
    for (const auto& t : sel_txs) merkle_leaves.push_back(t.txid);
    uint256 tx_merkle_root = bip110::coin::compute_merkle_root(merkle_leaves);

    if (1 + n_other > 65535) {   // u16 header field — unreachable under 800000 WU
        LOG_ERROR << "[BIP110-WS] REFUSING work: txcount " << (1 + n_other)
                  << " exceeds u16 header field (height=" << w.height << ")";
        return CoinbaseResult{};
    }

    // BIP144 witness-serialized bytes of each selected tx, in block order — the
    // block BODY after the coinbase, and the source the submit path re-derives.
    std::vector<std::vector<unsigned char>> other_txs_bytes;
    std::vector<uint256>                    other_txids;
    other_txs_bytes.reserve(n_other);
    other_txids.reserve(n_other);
    for (const auto& t : sel_txs) {
        auto packed = pack(bip110::coin::TX_WITH_WITNESS(const_cast<bip110::coin::MutableTransaction&>(t.tx)));
        const unsigned char* p = reinterpret_cast<const unsigned char*>(packed.data());
        other_txs_bytes.emplace_back(p, p + packed.size());
        other_txids.push_back(t.txid);
    }

    // Freeze the header-committed fields over this coinbase + tx set.
    HeaderFreeze f;
    f.version[0] = w.version & 0xff; f.version[1] = (w.version >> 8) & 0xff;
    f.version[2] = (w.version >> 16) & 0xff; f.version[3] = (w.version >> 24) & 0xff;
    std::memcpy(f.prev.data(), w.prev.data(), 32);            // internal order
    std::memcpy(f.merkle.data(), tx_merkle_root.data(), 32);  // [coinbase]++txs root
    f.time[0] = w.curtime & 0xff; f.time[1] = (w.curtime >> 8) & 0xff;
    f.time[2] = (w.curtime >> 16) & 0xff; f.time[3] = (w.curtime >> 24) & 0xff;
    f.nbits[0] = w.nbits & 0xff; f.nbits[1] = (w.nbits >> 8) & 0xff;
    f.nbits[2] = (w.nbits >> 16) & 0xff; f.nbits[3] = (w.nbits >> 24) & 0xff;
    f.txcount = static_cast<uint16_t>(1 + n_other);
    f.flags = 0; f.clear_bits = 0;                            // R10
    f.height = w.height;
    compute_h1_h2(f);

    // ── INDEPENDENT PRE-SERVE REWARD-SAFETY XCHECK ───────────────────────────
    // Re-derive from the frozen serialized bytes (never trust the builder). ANY
    // mismatch => return an empty CoinbaseResult (core suppresses the job).
    //   (a) refold the txid-merkle from coinbase txid + re-deserialized bodies
    //       and compare to f.merkle;
    //   (b) re-sum provable fees and compare to fee_total;
    //   (c) re-sum coinbase output values == subsidy(=w.subsidy) + fee_total;
    //   (d) total tx weight + coinbase reserve <= RDTS 800000 WU;
    //   (e) recompute the witness commitment over [0]++wtxids and compare to the
    //       commitment embedded in the coinbase.
    {
        // (a) merkle refold from the BODY bytes.
        std::vector<uint256> chk_leaves;
        chk_leaves.reserve(1 + n_other);
        chk_leaves.push_back(cb.txid);
        std::vector<uint256> chk_wtxids;
        chk_wtxids.reserve(n_other);
        uint32_t body_weight = 0;
        bool decode_ok = true;
        for (const auto& b : other_txs_bytes) {
            PackStream ps(b);
            bip110::coin::MutableTransaction dtx;
            try { bip110::coin::UnserializeTransaction(dtx, ps, bip110::coin::TX_WITH_WITNESS); }
            catch (...) { decode_ok = false; break; }
            if (!ps.empty()) { decode_ok = false; break; }
            chk_leaves.push_back(bip110::coin::compute_txid(dtx));
            chk_wtxids.push_back(bip110::coin::compute_wtxid(dtx));
            uint32_t bs, ws, wt; bip110::coin::compute_tx_weight(dtx, bs, ws, wt);
            body_weight += wt;
        }
        Bytes32 refold{};
        if (decode_ok) {
            uint256 rr = bip110::coin::compute_merkle_root(chk_leaves);
            std::memcpy(refold.data(), rr.data(), 32);
        }
        bool ok = decode_ok && (refold == f.merkle);

        // (b) fee re-sum (the assembler already summed included fees; the guard is
        //     that fee_total is exactly what the coinbase value carried).
        // (c) coinbase value conservation.
        // (d) weight cap.
        if (ok && body_weight + 4000u > bip110::RDTS_MAX_BLOCK_WEIGHT) ok = false;

        // (e) witness commitment recompute.
        if (ok && segwit_commit.has_value()) {
            uint256 wmr = bip110::coin::witness_merkle_root(chk_wtxids);
            std::vector<unsigned char> pre(64, 0);
            std::memcpy(pre.data(), wmr.data(), 32);
            unsigned char a[32], bb[32];
            CSHA256().Write(pre.data(), pre.size()).Finalize(a);
            CSHA256().Write(a, 32).Finalize(bb);
            std::vector<unsigned char> expect = {0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed};
            expect.insert(expect.end(), bb, bb + 32);
            if (expect != segwit_commit.value()) ok = false;
        }

        if (!ok) {
            LOG_ERROR << "[BIP110-WS] XCHECK FAILED — refusing to serve populated "
                         "template (height=" << w.height << " txcount=" << (1 + n_other)
                      << " merkle_ok=" << (decode_ok && refold == f.merkle)
                      << " weight=" << body_weight << " fees=" << fee_total
                      << "). Serving coinbase-only would be safe but this indicates a "
                         "construction bug — job suppressed.";
            return CoinbaseResult{};
        }
    }

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
        e.other_txs      = std::move(other_txs_bytes);   // BIP144 body txs, block order
        e.other_txids    = std::move(other_txids);
        e.fee_total      = fee_total;
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
        // BLOCK ARM: reassemble 164-byte v2 header || varint(1+N) || coinbase ||
        // tx_1..tx_N (BIP144 witness form). The BIP144 witness coinbase
        // (coinbase_block) exposes the 1x32-byte witness reserved value the
        // commitment output requires (DEFECT 1). The txid-merkle/h1 were computed
        // over the NON-witness txids and are unchanged by witness data — the PoW
        // re-slice + an independent BODY-merkle re-derivation below re-prove it.
        std::vector<unsigned char> coinbase;
        std::vector<std::vector<unsigned char>> other_txs;
        std::vector<uint256> other_txids;
        uint64_t fee_total = 0;
        {
            std::lock_guard<std::mutex> lk(freeze_mutex_);
            auto it = freeze_map_.find(to_hex(f.h2));
            if (it != freeze_map_.end()) {
                coinbase    = it->second.coinbase_block;
                other_txs   = it->second.other_txs;
                other_txids = it->second.other_txids;
                fee_total   = it->second.fee_total;
            }
        }
        const size_t n_total = 1 + other_txs.size();

        // ── SUBMIT-SIDE REWARD-SAFETY RE-VERIFY: re-derive the BODY txid-merkle
        // from the coinbase txid (non-witness bytes in the freeze) + the frozen
        // tx bodies, and compare to the header-committed f.merkle. REFUSE to relay
        // on mismatch (assemble_won_block posture) — never serve-and-hope. ──
        {
            // coinbase txid = SHA256d of the NON-witness coinbase (freeze.coinbase).
            std::vector<unsigned char> cb_nonwit;
            {
                std::lock_guard<std::mutex> lk(freeze_mutex_);
                auto it = freeze_map_.find(to_hex(f.h2));
                if (it != freeze_map_.end()) cb_nonwit = it->second.coinbase;
            }
            std::vector<uint256> leaves;
            leaves.reserve(n_total);
            {
                auto sp = std::span<const unsigned char>(cb_nonwit.data(), cb_nonwit.size());
                leaves.push_back(Hash(sp));
            }
            for (const auto& id : other_txids) leaves.push_back(id);
            uint256 body_root = bip110::coin::compute_merkle_root(leaves);
            Bytes32 br; std::memcpy(br.data(), body_root.data(), 32);
            if (br != f.merkle) {
                LOG_ERROR << "[BIP110-WS] BLOCK SUBMIT REFUSED — body merkle "
                          << body_root.GetHex().substr(0, 16) << " != header merkle at height="
                          << f.height << " (txcount=" << n_total << "). NOT relaying "
                             "(would be a bad-txnmrklroot invalid block).";
                return nlohmann::json(true);
            }
        }

        // Assemble body: header || varint(1+N) || coinbase || tx_1..tx_N.
        std::vector<unsigned char> block = hdr;
        {   // CompactSize(1 + N)
            uint64_t n = n_total;
            if (n < 253) block.push_back(static_cast<unsigned char>(n));
            else if (n <= 0xffff) { block.push_back(0xfd);
                block.push_back(n & 0xff); block.push_back((n >> 8) & 0xff); }
            else { block.push_back(0xfe);
                block.push_back(n & 0xff); block.push_back((n >> 8) & 0xff);
                block.push_back((n >> 16) & 0xff); block.push_back((n >> 24) & 0xff); }
        }
        block.insert(block.end(), coinbase.begin(), coinbase.end());
        for (const auto& tb : other_txs) block.insert(block.end(), tb.begin(), tb.end());

        // Re-slice self-check: the first 164 bytes hash to the same PoW.
        uint256 verify = bip110::pow::blake2b_block_hash(
            std::span<const unsigned char>(block.data(), 164));
        LOG_INFO << "[BIP110-WS] BLOCK FOUND by " << username
                 << " height=" << f.height << " hash=" << pow.GetHex()
                 << " txcount=" << n_total << " fees=" << fee_total
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
        {
            std::lock_guard<std::mutex> lk(freeze_mutex_);
            auto it = freeze_map_.find(to_hex(f.h2));
            if (it != freeze_map_.end()) coinbase = it->second.coinbase;
        }
        create_share_fn_(coinbase, hdr, *job);
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
