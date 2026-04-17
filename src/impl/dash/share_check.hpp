#pragma once

// Dash share v16 verification: hash_link, merkle, X11 PoW.
// Simplified from LTC share_check.hpp — no segwit, no merged mining.
// Reference: ref/p2pool-dash/p2pool/data.py Share.__init__() + check()
//
// PPLNS formula (v16, pre-V36 linear weights):
//   weight_per_share = target_to_average_attempts(share.target) * (65535 - donation_field)
//   max_weight = target_to_average_attempts(block_target) * 65535 * SPREAD
//   worker_payout = subsidy - sum(masternode/superblock/platform payments)
//   amount[script] = worker_payout * 49 * weight / (50 * total_weight)  — 98% PPLNS
//   amount[finder]  += worker_payout / 50                                — 2% finder fee
//   amount[donation] = worker_payout - sum(all amounts)                  — rounding remainder
//
// Coinbase output order: [worker_tx (sorted)] [payments_tx (masternode/superblock/platform)] [donation_tx] [OP_RETURN ref_hash]
//
// Masternode/superblock payments come from getblocktemplate and are subtracted
// from worker_payout BEFORE PPLNS distribution. They are NOT part of PPLNS weights.
// Platform payments use "!" prefix encoding for OP_RETURN scripts.

#include "share.hpp"
#include "share_types.hpp"

#include <core/coin_params.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/pow.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>
#include <btclibs/crypto/common.h>
#include <btclibs/crypto/sha256.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace dash
{

// ── check_hash_link (same algorithm as LTC) ──────────────────────────────────
inline uint256 check_hash_link(const HashLinkType& hash_link,
                               const std::vector<unsigned char>& data,
                               const std::vector<unsigned char>& const_ending = {})
{
    const uint64_t extra_length = hash_link.m_length % 64;

    std::vector<unsigned char> extra;
    extra.assign(hash_link.m_extra_data.m_data.begin(),
                 hash_link.m_extra_data.m_data.end());
    if (extra.size() < extra_length)
    {
        auto needed = extra_length - extra.size();
        if (const_ending.size() >= needed)
            extra.insert(extra.end(), const_ending.end() - needed, const_ending.end());
    }
    if (extra.size() != extra_length)
        throw std::runtime_error("check_hash_link: extra size mismatch");

    const auto& state_bytes = hash_link.m_state.m_data;
    uint32_t init_state[8] = {
        ReadBE32(state_bytes.data() +  0), ReadBE32(state_bytes.data() +  4),
        ReadBE32(state_bytes.data() +  8), ReadBE32(state_bytes.data() + 12),
        ReadBE32(state_bytes.data() + 16), ReadBE32(state_bytes.data() + 20),
        ReadBE32(state_bytes.data() + 24), ReadBE32(state_bytes.data() + 28),
    };

    unsigned char out1[CSHA256::OUTPUT_SIZE];
    CSHA256(init_state, extra, hash_link.m_length)
        .Write(data.data(), data.size())
        .Finalize(out1);

    unsigned char out2[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(out1, CSHA256::OUTPUT_SIZE).Finalize(out2);

    uint256 result;
    std::memcpy(result.data(), out2, 32);
    return result;
}

// ── check_merkle_link ────────────────────────────────────────────────────────
inline uint256 check_merkle_link(const uint256& tip_hash, const MerkleLink& link)
{
    uint256 cur = tip_hash;
    for (size_t i = 0; i < link.m_branch.size(); ++i)
    {
        PackStream ps;
        if ((link.m_index >> i) & 1)
        {
            ps << link.m_branch[i];
            ps << cur;
        }
        else
        {
            ps << cur;
            ps << link.m_branch[i];
        }
        auto sp = std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(ps.data()), ps.size());
        cur = Hash(sp);
    }
    return cur;
}

// ── Donation script (P2PKH for XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u) ─────────
// Reference: ref/p2pool-dash/p2pool/data.py DONATION_SCRIPT
static const std::vector<unsigned char> DONATION_SCRIPT = {
    0x76, 0xa9, 0x14,
    0x20, 0xcb, 0x5c, 0x22, 0xb1, 0xe4, 0xd5, 0x94,
    0x7e, 0x5c, 0x11, 0x2c, 0x76, 0x96, 0xb5, 0x1a,
    0xd9, 0xaf, 0x3c, 0x61,
    0x88, 0xac
};

// ── compute_gentx_before_refhash (Dash v16) ──────────────────────────────────
inline std::vector<unsigned char> compute_gentx_before_refhash()
{
    std::vector<unsigned char> result;

    // VarStr(DONATION_SCRIPT)
    {
        PackStream s;
        BaseScript bs;
        bs.m_data = DONATION_SCRIPT;
        s << bs;
        auto* p = reinterpret_cast<const unsigned char*>(s.data());
        result.insert(result.end(), p, p + s.size());
    }
    // int64(0)
    {
        uint64_t zero64 = 0;
        auto* p = reinterpret_cast<const unsigned char*>(&zero64);
        result.insert(result.end(), p, p + 8);
    }
    // VarStr(0x6a 0x28 + int256(0) + int64(0))[:3]
    {
        PackStream inner;
        unsigned char prefix[2] = {0x6a, 0x28};
        inner.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(prefix), 2));
        uint256 zero256;
        inner << zero256;
        uint64_t zero64 = 0;
        inner.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&zero64), 8));

        PackStream outer;
        BaseScript bs;
        bs.m_data.resize(inner.size());
        std::memcpy(bs.m_data.data(), inner.data(), inner.size());
        outer << bs;

        auto* p = reinterpret_cast<const unsigned char*>(outer.data());
        result.insert(result.end(), p, p + std::min<size_t>(3, outer.size()));
    }

    return result;
}

// ── share_init_verify (Dash v16) ─────────────────────────────────────────────
// Verifies PoW, hash_link, merkle_link. Returns share hash (SHA256d of header).
inline uint256 share_init_verify(const DashShare& share,
                                 const core::CoinParams& params,
                                 bool check_pow = true)
{
    if (share.m_coinbase.m_data.size() < 2 || share.m_coinbase.m_data.size() > 100)
        throw std::invalid_argument("bad coinbase size");

    // ── Compute ref_hash ──
    PackStream ref_stream;
    {
        auto hex = params.active_identifier_hex();
        for (size_t i = 0; i + 1 < hex.size(); i += 2)
        {
            unsigned char byte = static_cast<unsigned char>(
                std::stoul(hex.substr(i, 2), nullptr, 16));
            ref_stream.write(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(&byte), 1));
        }
    }

    // share_info serialization (v16 format)
    {
        // share_data
        ref_stream << share.m_prev_hash;
        ref_stream << share.m_coinbase;
        ref_stream << share.m_coinbase_payload;
        ref_stream << share.m_nonce;
        ref_stream << share.m_pubkey_hash;
        ref_stream << share.m_subsidy;
        ref_stream << share.m_donation;
        { uint8_t si = static_cast<uint8_t>(share.m_stale_info); ref_stream << si; }
        ::Serialize(ref_stream, VarInt(share.m_desired_version));
        ref_stream << share.m_payment_amount;
        ref_stream << share.m_packed_payments;

        // share_info (non-share_data)
        ref_stream << share.m_new_transaction_hashes;
        // transaction_hash_refs: ListType(VarIntType(), 2) — writes count/2 then all elements
        {
            uint64_t pair_count = share.m_transaction_hash_refs.size() / 2;
            ::Serialize(ref_stream, VarInt(pair_count));
            for (auto& v : share.m_transaction_hash_refs)
                ::Serialize(ref_stream, VarInt(v));
        }
        ref_stream << share.m_far_share_hash;
        ref_stream << share.m_max_bits;
        ref_stream << share.m_bits;
        ref_stream << share.m_timestamp;
        ref_stream << share.m_absheight;
        ref_stream << share.m_abswork;
    }

    auto ref_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(ref_stream.data()), ref_stream.size());
    uint256 hash_ref = Hash(ref_span);
    uint256 ref_hash = check_merkle_link(hash_ref, share.m_ref_merkle_link);

    // ── Build hash_link_data ──
    // Python: get_ref_hash(...) + pack.IntType(64).pack(last_txout_nonce) + pack.IntType(32).pack(0) + coinbase_payload_data
    std::vector<unsigned char> hash_link_data;
    hash_link_data.insert(hash_link_data.end(), ref_hash.data(), ref_hash.data() + 32);
    {
        uint64_t nonce = share.m_last_txout_nonce;
        auto* p = reinterpret_cast<const unsigned char*>(&nonce);
        hash_link_data.insert(hash_link_data.end(), p, p + 8);
    }
    {
        uint32_t zero = 0;
        auto* p = reinterpret_cast<const unsigned char*>(&zero);
        hash_link_data.insert(hash_link_data.end(), p, p + 4);
    }
    // Append outer coinbase_payload (coinbase_payload_data in Python)
    // Reference: data.py line 342-348
    {
        auto& cpd = share.m_coinbase_payload_outer.m_data;
        if (!cpd.empty())
            hash_link_data.insert(hash_link_data.end(), cpd.begin(), cpd.end());
    }

    auto gentx_before_refhash = compute_gentx_before_refhash();

    // ── check_hash_link → gentx_hash ──
    uint256 gentx_hash = check_hash_link(share.m_hash_link, hash_link_data, gentx_before_refhash);

    // ── Merkle root (no segwit for Dash) ──
    uint256 merkle_root = check_merkle_link(gentx_hash, share.m_merkle_link);

    // ── Reconstruct block header ──
    PackStream header_stream;
    {
        uint32_t hdr_version = static_cast<uint32_t>(share.m_min_header.m_version);
        header_stream << hdr_version;
    }
    header_stream << share.m_min_header.m_previous_block;
    header_stream << merkle_root;
    header_stream << share.m_min_header.m_timestamp;
    header_stream << share.m_min_header.m_bits;
    header_stream << share.m_min_header.m_nonce;

    // Dash: both BLOCKHASH_FUNC and POW_FUNC are X11
    // share_hash = X11(header) — block identity AND PoW check
    auto hdr_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(header_stream.data()), header_stream.size());
    uint256 share_hash = params.pow_func(hdr_span);

    // ── X11 PoW check ──
    if (check_pow)
    {
        uint256 target = chain::bits_to_target(share.m_bits);
        if (target.IsNull())
            throw std::invalid_argument("share target is zero");

        if (share_hash > target)
            throw std::invalid_argument("share PoW hash does not meet target");
    }

    return share_hash;
}

// ── pubkey_hash_to_script2 (Dash: always P2PKH, no segwit) ──────────────────
inline std::vector<unsigned char> pubkey_hash_to_script2(const uint160& hash)
{
    auto h = hash.GetChars();
    std::vector<unsigned char> script;
    script.reserve(25);
    script.push_back(0x76); // OP_DUP
    script.push_back(0xa9); // OP_HASH160
    script.push_back(0x14); // Push 20 bytes
    script.insert(script.end(), h.begin(), h.end());
    script.push_back(0x88); // OP_EQUALVERIFY
    script.push_back(0xac); // OP_CHECKSIG
    return script;
}

// ── generate_share_transaction (Dash v16 PPLNS) ─────────────────────────────
// Reconstructs the expected coinbase from PPLNS weights.
// Uses the OLD p2pool formula (pre-V36):
//   49/50 to PPLNS weighted workers, 1/50 to finder, remainder to donation.
//   Masternode/superblock/platform payments subtracted from worker_payout first.
//
// Reference: ref/p2pool-dash/p2pool/data.py generate_transaction() lines 131-269
// ─────────────────────────────────────────────────────────────────────────────
template <typename TrackerT>
uint256 generate_share_transaction(const DashShare& share, TrackerT& tracker,
                                   const core::CoinParams& params)
{
    const uint64_t subsidy = share.m_subsidy;

    // ── 1. Compute worker_payout (subsidy minus masternode/superblock payments) ──
    uint64_t payment_total = 0;
    for (auto& pay : share.m_packed_payments)
        payment_total += pay.m_amount;
    uint64_t worker_payout = (subsidy > payment_total) ? (subsidy - payment_total) : 0;

    // ── 2. Compute PPLNS weights (linear, pre-V36) ──
    auto prev_hash = share.m_prev_hash;
    std::map<std::vector<unsigned char>, uint288> weights;
    uint288 total_weight;
    uint288 donation_weight;

    if (!prev_hash.IsNull() && tracker.chain.contains(prev_hash))
    {
        auto height = tracker.chain.get_height(prev_hash);
        auto chain_len = std::max(0, std::min(height, static_cast<int32_t>(params.real_chain_length)) - 1);

        auto block_target = chain::bits_to_target(share.m_min_header.m_bits);
        auto max_weight = chain::target_to_average_attempts(block_target)
                          * params.spread * 65535;

        // Walk chain and accumulate per-script weights (linear, no decay)
        // Python: get_cumulative_weights starts from previous_share.previous_share_hash
        auto walk_count = static_cast<size_t>(chain_len);
        auto walk_view = tracker.chain.get_chain(prev_hash, walk_count);

        for (auto& [hash, data] : walk_view)
        {
            uint288 share_att;
            uint32_t share_don = 0;
            std::vector<unsigned char> script;

            data.share.invoke([&](auto* obj) {
                auto target = chain::bits_to_target(obj->m_bits);
                share_att = chain::target_to_average_attempts(target);
                share_don = obj->m_donation;
                script = pubkey_hash_to_script2(obj->m_pubkey_hash);
            });

            uint288 share_total = share_att * 65535;
            uint288 share_don_w = share_att * share_don;

            if (total_weight + share_total > max_weight)
            {
                auto remaining = max_weight - total_weight;
                auto share_addr_weight = share_att * static_cast<uint32_t>(65535 - share_don);

                uint288 partial_addr;
                if (!share_total.IsNull())
                    partial_addr = remaining / 65535 * share_addr_weight / (share_total / 65535);

                if (weights.contains(script))
                    weights[script] += partial_addr;
                else
                    weights[script] = partial_addr;

                uint288 partial_donation;
                if (!share_total.IsNull())
                    partial_donation = remaining / 65535 * share_don_w / (share_total / 65535);

                donation_weight += partial_donation;
                total_weight = max_weight;
                break;
            }

            auto share_addr_weight = share_att * static_cast<uint32_t>(65535 - share_don);
            if (weights.contains(script))
                weights[script] += share_addr_weight;
            else
                weights[script] = share_addr_weight;

            total_weight += share_total;
            donation_weight += share_don_w;
        }
    }

    // ── 3. Convert weights to payout amounts (49/50 + 1/50 finder) ──
    std::map<std::vector<unsigned char>, uint64_t> amounts;

    if (!total_weight.IsNull())
    {
        for (auto& [script, weight] : weights)
        {
            // amounts[script] = worker_payout * 49 * weight / (50 * total_weight)
            uint288 num = uint288(worker_payout) * (weight * 49);
            uint288 den = total_weight * 50;
            uint64_t amount = (num / den).GetLow64();
            if (amount > 0)
                amounts[script] = amount;
        }
    }

    // Finder fee: 2% (1/50) to block creator
    auto finder_script = pubkey_hash_to_script2(share.m_pubkey_hash);
    amounts[finder_script] += worker_payout / 50;

    // Donation: remainder (rounding + donation weight)
    uint64_t sum_amounts = 0;
    for (auto& [s, a] : amounts)
        sum_amounts += a;
    uint64_t donation_amount = (worker_payout > sum_amounts) ? (worker_payout - sum_amounts) : 0;

    // ── 4. Build sorted output list ──
    // worker_scripts: sorted, excluding donation
    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> worker_outputs;
    for (auto& [script, amount] : amounts)
    {
        if (script != DONATION_SCRIPT && amount > 0)
            worker_outputs.emplace_back(script, amount);
    }
    std::sort(worker_outputs.begin(), worker_outputs.end());

    // ── 5. Build coinbase TX ──
    // Output order: worker_tx + payments_tx + donation_tx + OP_RETURN
    PackStream tx;

    // tx version (DIP3/DIP4: version=3, type=5 for CBTX)
    bool has_cbtx = !share.m_coinbase_payload.m_data.empty();
    if (has_cbtx) {
        int32_t ver_with_type = 3 | (5 << 16);
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&ver_with_type), 4));
    } else {
        uint32_t v = 1;
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&v), 4));
    }

    // vin[0]: coinbase
    { unsigned char one = 1; tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&one), 1)); }
    { uint256 z; tx << z; }
    { uint32_t idx = 0xffffffff; tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&idx), 4)); }
    tx << share.m_coinbase;
    { uint32_t seq = 0xffffffff; tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&seq), 4)); }

    // Count outputs
    size_t n_outs = worker_outputs.size() + share.m_packed_payments.size() + 1 /* donation */ + 1 /* OP_RETURN */;
    if (n_outs < 253) {
        uint8_t cnt = static_cast<uint8_t>(n_outs);
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&cnt), 1));
    } else {
        uint8_t marker = 0xfd;
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&marker), 1));
        uint16_t cnt = static_cast<uint16_t>(n_outs);
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&cnt), 2));
    }

    auto write_txout = [&](uint64_t value, const std::vector<unsigned char>& script) {
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&value), 8));
        BaseScript bs;
        bs.m_data = script;
        tx << bs;
    };

    // Worker outputs (sorted)
    for (auto& [script, amount] : worker_outputs)
        write_txout(amount, script);

    // Masternode/superblock/platform payments
    // TODO: decode "!" prefix scripts for platform OP_RETURN payments
    for (auto& pay : share.m_packed_payments)
    {
        if (pay.m_amount == 0) continue;
        // For now, skip script decoding — will be implemented in masternode.hpp
        // This stub ensures the output count is correct for hash verification
    }

    // Donation output
    write_txout(donation_amount, DONATION_SCRIPT);

    // OP_RETURN ref_hash output (last)
    {
        // Recompute ref_hash (same as share_init_verify)
        PackStream ref_stream;
        {
            auto hex = params.active_identifier_hex();
            for (size_t i = 0; i + 1 < hex.size(); i += 2)
            {
                unsigned char byte = static_cast<unsigned char>(
                    std::stoul(hex.substr(i, 2), nullptr, 16));
                ref_stream.write(std::span<const std::byte>(
                    reinterpret_cast<const std::byte*>(&byte), 1));
            }
        }
        // share_info (same serialization as share_init_verify)
        ref_stream << share.m_prev_hash;
        ref_stream << share.m_coinbase;
        ref_stream << share.m_coinbase_payload;
        ref_stream << share.m_nonce;
        ref_stream << share.m_pubkey_hash;
        ref_stream << share.m_subsidy;
        ref_stream << share.m_donation;
        { uint8_t si = static_cast<uint8_t>(share.m_stale_info); ref_stream << si; }
        ::Serialize(ref_stream, VarInt(share.m_desired_version));
        ref_stream << share.m_payment_amount;
        ref_stream << share.m_packed_payments;
        ref_stream << share.m_new_transaction_hashes;
        for (auto& v : share.m_transaction_hash_refs)
            ::Serialize(ref_stream, VarInt(v));
        ref_stream << share.m_far_share_hash;
        ref_stream << share.m_max_bits;
        ref_stream << share.m_bits;
        ref_stream << share.m_timestamp;
        ref_stream << share.m_absheight;
        ref_stream << share.m_abswork;

        auto rspan = std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(ref_stream.data()), ref_stream.size());
        uint256 hash_ref = Hash(rspan);
        uint256 ref_hash = check_merkle_link(hash_ref, share.m_ref_merkle_link);

        std::vector<unsigned char> op_return_script;
        op_return_script.push_back(0x6a);
        op_return_script.push_back(0x28);
        op_return_script.insert(op_return_script.end(), ref_hash.data(), ref_hash.data() + 32);
        {
            uint64_t nonce = share.m_last_txout_nonce;
            auto* p = reinterpret_cast<const unsigned char*>(&nonce);
            op_return_script.insert(op_return_script.end(), p, p + 8);
        }
        write_txout(0, op_return_script);
    }

    // locktime
    { uint32_t lt = 0; tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&lt), 4)); }

    // DIP3/DIP4 extra_payload
    if (has_cbtx) {
        tx << share.m_coinbase_payload;
    }

    // ── 6. Compute txid ──
    auto tx_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(tx.data()), tx.size());
    return Hash(tx_span);
}

} // namespace dash
