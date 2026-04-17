#pragma once

// Build a v16 DashShare template from a GBT + sharechain tip, producing the
// Stratum Job wire fields, the JobContext for submit validation, AND a
// pre-filled DashShare that the submit path will complete with the miner's
// extranonce2 / ntime / nonce.
//
// This is the glue between Phase 4 (stratum mining) and Phase 5 (share
// participation): at job creation we commit to all share metadata via
// ref_hash embedded in the coinbase's OP_RETURN; on submit we just slot in
// the miner-controlled fields and the share is ready for share_init_verify,
// tracker insertion, and broadcast.

#include "share.hpp"
#include "share_chain.hpp"
#include "share_check.hpp"
#include "share_tracker.hpp"
#include "share_types.hpp"
#include "coin/rpc_data.hpp"
#include "coinbase_builder.hpp"
#include "stratum.hpp"

#include <cstdint>
#include <cstring>
#include <random>
#include <span>
#include <string>
#include <vector>

#include <core/coin_params.hpp>
#include <core/hash.hpp>
#include <core/log.hpp>
#include <core/pack.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>
#include <btclibs/crypto/sha256.h>
#include <btclibs/util/strencodings.h>

namespace dash {
namespace share_builder {

struct BuiltJob {
    stratum::Job             job;
    stratum::JobContext      context;
    dash::coinbase::CoinbaseLayout coinbase;
    // The DashShare with everything fixed except the miner-controlled fields
    // (m_min_header.m_timestamp, m_min_header.m_nonce, m_last_txout_nonce).
    dash::DashShare          share_template;
    uint256                  ref_hash;
    uint32_t                 share_bits{0};
    double                   share_difficulty{0.0};
};

// Serialize identifier || share_data || share_info → hash_ref candidate.
// Must byte-exactly match share_check.hpp::share_init_verify's ref_stream.
inline std::vector<unsigned char> ref_stream_bytes(const dash::DashShare& share,
                                                   const core::CoinParams& params)
{
    PackStream ref;
    {
        auto hex = params.active_identifier_hex();
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            unsigned char b = static_cast<unsigned char>(
                std::stoul(hex.substr(i, 2), nullptr, 16));
            ref.write(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(&b), 1));
        }
    }
    // share_data
    ref << share.m_prev_hash;
    ref << share.m_coinbase;
    ref << share.m_coinbase_payload;
    ref << share.m_nonce;
    ref << share.m_pubkey_hash;
    ref << share.m_subsidy;
    ref << share.m_donation;
    { uint8_t si = static_cast<uint8_t>(share.m_stale_info); ref << si; }
    ::Serialize(ref, VarInt(share.m_desired_version));
    ref << share.m_payment_amount;
    ref << share.m_packed_payments;
    // share_info (non-share_data)
    ref << share.m_new_transaction_hashes;
    {
        uint64_t pair_count = share.m_transaction_hash_refs.size() / 2;
        ::Serialize(ref, VarInt(pair_count));
        for (auto& v : share.m_transaction_hash_refs)
            ::Serialize(ref, VarInt(v));
    }
    ref << share.m_far_share_hash;
    ref << share.m_max_bits;
    ref << share.m_bits;
    ref << share.m_timestamp;
    ref << share.m_absheight;
    ref << share.m_abswork;

    std::vector<unsigned char> out;
    out.reserve(ref.size());
    auto sp = ref.get_span();
    for (auto b : sp) out.push_back(static_cast<unsigned char>(b));
    return out;
}

// Extract SHA-256 intermediate state from a CSHA256 mid-stream and pack
// it into a HashLinkType. After Write()ing `prefix` (ending in `const_ending`)
// and stopping, the CSHA256 object holds:
//   .s[8]   — big-endian 32-bit words of current internal state
//   .buf    — up to 63 bytes of unprocessed tail (length == bytes % 64)
//   .bytes  — total bytes fed in so far
// extra_data is truncated by const_ending_len to match p2pool-dash's
// prefix_to_hash_link (data.py line 37):
//   extra_data = x.buf[:max(0, len(x.buf) - len(const_ending))]
// which is what check_hash_link's strict assertion at line 41 enforces.
inline dash::HashLinkType hash_link_from_csha256(const CSHA256& h,
                                                 size_t const_ending_len)
{
    dash::HashLinkType link;
    link.m_state.m_data.resize(32);
    for (int i = 0; i < 8; ++i) {
        link.m_state.m_data[i * 4 + 0] = static_cast<unsigned char>((h.s[i] >> 24) & 0xff);
        link.m_state.m_data[i * 4 + 1] = static_cast<unsigned char>((h.s[i] >> 16) & 0xff);
        link.m_state.m_data[i * 4 + 2] = static_cast<unsigned char>((h.s[i] >>  8) & 0xff);
        link.m_state.m_data[i * 4 + 3] = static_cast<unsigned char>((h.s[i] >>  0) & 0xff);
    }
    uint64_t pending = h.bytes % 64;
    uint64_t keep = (pending > const_ending_len) ? (pending - const_ending_len) : 0;
    link.m_extra_data.m_data.assign(h.buf, h.buf + keep);
    link.m_length = h.bytes;
    return link;
}

// Stream SHA-256 over `coinbase_bytes[0 : ref_hash_offset)` and capture the
// state. Exactly what check_hash_link expects to resume from. const_ending
// is the suffix (gentx_before_refhash) that the verifier will re-supply.
inline dash::HashLinkType compute_hash_link(
    const std::vector<unsigned char>& coinbase_bytes,
    size_t ref_hash_offset,
    size_t const_ending_len)
{
    CSHA256 h;
    if (ref_hash_offset > 0)
        h.Write(coinbase_bytes.data(), ref_hash_offset);
    return hash_link_from_csha256(h, const_ending_len);
}

// Copy uint288 low 128 bits into uint128 (m_abswork width).
inline uint128 work_u128(const uint288& work288)
{
    uint128 out;
    std::memcpy(out.data(), work288.data(), 16);
    return out;
}

// Convert compact nbits → uint256 target, using chain::bits_to_target so we
// match share_init_verify's PoW check semantics.
using chain::bits_to_target;

// Build the full Stratum Job + share template for a given GBT + miner +
// tracker tip + share target. Coinbase outputs are computed via
// coinbase::compute_dash_payouts (match to p2pool-dash's
// generate_transaction formula) so broadcast shares are byte-exact with
// what the peer regenerates during Share.check().
//
// miner_payouts is ignored (retained for ABI) — payouts are derived
// internally from work + miner_pubkey_hash.
inline BuiltJob build(const dash::coin::DashWorkData& work,
                      dash::ShareTracker& tracker,
                      const uint160& miner_pubkey_hash,
                      const std::vector<coinbase::MinerPayout>& /*miner_payouts_ignored*/,
                      const std::string& pool_tag,
                      const core::CoinParams& params,
                      uint32_t share_bits,
                      double   share_difficulty,
                      uint16_t donation_bps = 0,
                      uint32_t share_nonce  = 0)
{
    BuiltJob out;
    out.share_bits       = share_bits;
    out.share_difficulty = share_difficulty;

    // Random share_nonce if caller did not supply one.
    if (share_nonce == 0) {
        static thread_local std::mt19937_64 rng(std::random_device{}());
        share_nonce = static_cast<uint32_t>(rng());
    }

    // ── Fix the coinbase scriptSig first: BIP34 height + pool_tag ───────
    std::vector<unsigned char> coinbase_scriptSig;
    {
        auto h_push = dash::coinbase::push_bip34_height(work.m_height);
        coinbase_scriptSig.insert(coinbase_scriptSig.end(), h_push.begin(), h_push.end());
        coinbase_scriptSig.insert(coinbase_scriptSig.end(), pool_tag.begin(), pool_tag.end());
    }

    // ── Assemble the share template (everything except miner fields) ────
    dash::DashShare& s = out.share_template;
    s.m_min_header.m_version         = static_cast<uint64_t>(work.m_version);
    s.m_min_header.m_previous_block  = work.m_previous_block;
    s.m_min_header.m_bits            = work.m_bits;
    s.m_min_header.m_timestamp       = 0;                // miner will fill
    s.m_min_header.m_nonce           = 0;                // miner will fill

    s.m_prev_hash        = uint256::ZERO;                // filled below if tracker has tip
    s.m_coinbase.m_data  = std::move(coinbase_scriptSig);
    s.m_coinbase_payload.m_data = work.m_coinbase_payload;
    s.m_nonce            = share_nonce;
    s.m_pubkey_hash      = miner_pubkey_hash;
    s.m_subsidy          = work.m_coinbase_value;
    s.m_donation         = donation_bps;
    s.m_stale_info       = dash::StaleInfo::none;
    s.m_desired_version  = 16;
    s.m_payment_amount   = work.m_payment_amount;
    s.m_packed_payments.clear();
    s.m_packed_payments.reserve(work.m_packed_payments.size());
    for (const auto& p : work.m_packed_payments) {
        dash::PackedPayment pp;
        pp.m_payee  = p.payee;
        pp.m_amount = p.amount;
        s.m_packed_payments.push_back(std::move(pp));
    }

    // share_info (tx compression: MVP — coinbase-only shares).
    //
    // We could include the GBT's tx list in new_transaction_hashes, but
    // p2pool-dash requires each referenced tx hash to already be in its
    // known_txs_var (populated via its own dashd P2P subscription). Until
    // we implement remember_tx to ship tx bodies to peers ahead of shares,
    // we advertise an empty tx list — our share mines a coinbase-only
    // block. The assertion at p2pool-dash/data.py:340
    //   n == set(range(len(new_transaction_hashes)))
    // trivially holds for empty sets.
    s.m_new_transaction_hashes.clear();
    s.m_transaction_hash_refs.clear();
    s.m_far_share_hash         = uint256::ZERO;

    // max_bits: use pool's configured max_target as compact.
    s.m_max_bits  = chain::target_to_bits_upper_bound(params.max_target);
    if (s.m_max_bits == 0) s.m_max_bits = 0x1f00ffff;    // extreme fallback
    s.m_bits      = share_bits;
    s.m_timestamp = static_cast<uint32_t>(std::time(nullptr));

    // absheight / abswork: chain onto the current tip if available.
    auto heads = tracker.chain.get_heads();
    if (!heads.empty()) {
        uint256 tip_hash = heads.begin()->first;
        s.m_prev_hash = tip_hash;
        try {
            auto& parent_data = tracker.chain.get(tip_hash);
            parent_data.share.invoke([&](auto* p) {
                using S = std::remove_pointer_t<decltype(p)>;
                if constexpr (std::is_same_v<S, dash::DashShare>) {
                    s.m_absheight = p->m_absheight + 1;
                    uint288 work288 = chain::target_to_average_attempts(chain::bits_to_target(s.m_bits));
                    s.m_abswork = p->m_abswork + work_u128(work288);
                }
            });
        } catch (...) {
            s.m_absheight = 1;
            s.m_abswork   = work_u128(
                chain::target_to_average_attempts(chain::bits_to_target(s.m_bits)));
        }
    } else {
        s.m_absheight = 1;
        s.m_abswork   = work_u128(
            chain::target_to_average_attempts(chain::bits_to_target(s.m_bits)));
    }

    s.m_ref_merkle_link = dash::MerkleLink{};            // empty; ref_hash == hash_ref
    s.m_last_txout_nonce = 0;                            // miner fills
    // m_hash_link filled after coinbase is built (needs ref_hash_offset)
    s.m_merkle_link = dash::MerkleLink{};                // filled after merkle branches
    // contents['coinbase_payload'] on the p2pool-dash wire is the
    // VarStr-packed form (VarInt length prefix + payload bytes) — see
    // p2pool-dash/p2pool/data.py:278-289. The outer field's VarStrType
    // wraps that with a second length prefix. Feed the VarStr-packed form
    // here so check_hash_link's continuation byte stream matches the real
    // coinbase (which has a VarInt length between locktime and payload per
    // CBTX tx_type serialization).
    s.m_coinbase_payload_outer.m_data.clear();
    if (!work.m_coinbase_payload.empty()) {
        PackStream ps;
        BaseScript inner;
        inner.m_data = work.m_coinbase_payload;
        ps << inner;  // VarStrType serialization: VarInt length + bytes
        auto sp = ps.get_span();
        s.m_coinbase_payload_outer.m_data.resize(sp.size());
        for (size_t i = 0; i < sp.size(); ++i)
            s.m_coinbase_payload_outer.m_data[i] =
                static_cast<unsigned char>(sp[i]);
    }

    // ── ref_hash from share metadata ────────────────────────────────────
    auto ref_bytes = ref_stream_bytes(s, params);
    uint256 hash_ref = Hash(
        std::span<const unsigned char>(ref_bytes.data(), ref_bytes.size()));
    out.ref_hash = hash_ref;           // empty ref_merkle_link → ref_hash == hash_ref

    // ── Compute PPLNS outputs per p2pool-dash generate_transaction ─────
    //
    // Genesis / first 2 shares in chain: weights = {} (tracker has < 1
    // ancestor). The formula collapses to: 2 % → miner_pubkey_hash,
    // 98 % → DONATION (or 100 % → DONATION if miner IS donation addr).
    //
    // Non-genesis: TODO port p2pool's WeightsSkipList. Callers expecting
    // peer acceptance past the 2nd share in chain will currently hit
    // "gentx doesn't match hash_link" on p2pool-dash's check() because
    // our empty-weights distribution ignores ancestor miner scripts.
    std::map<std::vector<unsigned char>, uint64_t> weights;
    uint64_t total_weight = 0;
    auto tx_outs_ordered = dash::coinbase::compute_dash_payouts(
        work.m_coinbase_value, work.m_packed_payments,
        miner_pubkey_hash, weights, total_weight, params);

    // ── Build coinbase bytes with ref_hash embedded ─────────────────────
    out.coinbase = dash::coinbase::build(
        work, tx_outs_ordered, pool_tag, params, hash_ref);
    auto sp = dash::coinbase::split_coinb(out.coinbase);

    // ── Merkle branches ─────────────────────────────────────────────────
    // Since we advertise an empty new_transaction_hashes (coinbase-only
    // share, until remember_tx ships), the merkle tree the peer
    // reconstructs is just [None] → root == coinbase_txid. Our stratum
    // job must therefore also give the miner an empty branch list so the
    // header's merkle_root == coinbase_txid. Block submission on a full
    // hit will then be coinbase-only — missing fees but valid per
    // consensus.
    std::vector<uint256> layer;
    layer.push_back(uint256::ZERO);
    auto branches_raw = dash::coinbase::merkle_branches_raw(layer);

    // Fill in the remaining share_template fields that depend on layout.
    // const_ending = gentx_before_refhash (the canonical 37-byte suffix of
    // the coinbase prefix that the verifier will re-supply).
    auto gentx_before = dash::compute_gentx_before_refhash();
    s.m_hash_link = compute_hash_link(
        out.coinbase.bytes,
        out.coinbase.ref_hash_offset,
        gentx_before.size());
    s.m_merkle_link.m_branch = branches_raw;             // index always 0

    // ── Stratum Job ─────────────────────────────────────────────────────
    auto prev_chars = work.m_previous_block.GetChars();
    std::span<const unsigned char> prev_span(
        reinterpret_cast<const unsigned char*>(prev_chars.data()), 32);

    {
        static thread_local std::mt19937_64 rng(std::random_device{}());
        char buf[9];
        std::snprintf(buf, sizeof(buf), "%08x",
                      static_cast<uint32_t>(rng() & 0xffffffffu));
        out.job.job_id = buf;
    }
    out.job.prevhash_hex    = dash::coinbase::swap4_hex(prev_span);
    out.job.coinb1_hex      = sp.coinb1_hex;
    out.job.coinb2_hex      = sp.coinb2_hex;
    out.job.merkle_branches_hex = dash::coinbase::merkle_branches_hex(branches_raw);
    out.job.version_hex     = dash::coinbase::be_hex_u32(static_cast<uint32_t>(work.m_version));
    out.job.nbits_hex       = dash::coinbase::be_hex_u32(work.m_bits);
    out.job.ntime_hex       = dash::coinbase::be_hex_u32(static_cast<uint32_t>(std::time(nullptr)));
    out.job.clean_jobs      = true;
    out.job.share_difficulty = share_difficulty;

    // ── Stratum JobContext ──────────────────────────────────────────────
    out.context.job_id   = out.job.job_id;
    out.context.coinb1_bytes.assign(
        out.coinbase.bytes.begin(),
        out.coinbase.bytes.begin() + out.coinbase.nonce64_offset);
    out.context.coinb2_bytes.assign(
        out.coinbase.bytes.begin() + out.coinbase.nonce64_offset + dash::coinbase::EXTRANONCE2_SIZE,
        out.coinbase.bytes.end());
    out.context.merkle_branches_le.clear();
    out.context.merkle_branches_le.reserve(branches_raw.size());
    for (const auto& h : branches_raw) {
        auto c = h.GetChars();
        out.context.merkle_branches_le.emplace_back(c.begin(), c.end());
    }
    out.context.prev_hash_le.assign(prev_span.begin(), prev_span.end());
    out.context.version          = work.m_version;
    out.context.nbits            = work.m_bits;
    out.context.ntime            = static_cast<uint32_t>(std::time(nullptr));
    out.context.height           = work.m_height;
    out.context.share_difficulty = share_difficulty;
    // Coinbase-only blocks while remember_tx is not yet shipping tx bodies:
    // no other txs go into the block assembled at submit time.
    out.context.tx_data_hex.clear();

    return out;
}

// Complete a share template with the miner's submission values and run a
// sanity verify (no PoW check — caller already validated).
inline dash::DashShare finalize_from_submit(
    const dash::DashShare& tmpl,
    uint32_t miner_ntime,
    uint32_t miner_nonce,
    std::span<const unsigned char> extranonce2_bytes,
    const core::CoinParams& params)
{
    if (extranonce2_bytes.size() != dash::coinbase::EXTRANONCE2_SIZE)
        throw std::runtime_error("finalize_from_submit: bad extranonce2 length");
    dash::DashShare s = tmpl;
    s.m_min_header.m_timestamp = miner_ntime;
    s.m_min_header.m_nonce     = miner_nonce;

    // nonce64 reads as little-endian uint64 from the 8 bytes in OP_RETURN.
    uint64_t n64 = 0;
    for (size_t i = 0; i < 8; ++i)
        n64 |= (static_cast<uint64_t>(extranonce2_bytes[i]) << (8 * i));
    s.m_last_txout_nonce = n64;

    // Sanity roundtrip via share_init_verify (check_pow=false — caller
    // already verified PoW against the share target).
    s.m_hash = dash::share_init_verify(s, params, /*check_pow=*/false);
    return s;
}

} // namespace share_builder
} // namespace dash
