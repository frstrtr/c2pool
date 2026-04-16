#pragma once

// Dash share v16 verification: hash_link, merkle, X11 PoW.
// Simplified from LTC share_check.hpp — no segwit, no merged mining.
// Reference: ref/p2pool-dash/p2pool/data.py Share.__init__() + check()

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
        // transaction_hash_refs as list of VarInt pairs
        for (auto& v : share.m_transaction_hash_refs)
            ::Serialize(ref_stream, VarInt(v));
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

    // share_hash = SHA256d(header) — block identity
    auto hdr_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(header_stream.data()), header_stream.size());
    uint256 share_hash = Hash(hdr_span);

    // ── X11 PoW check ──
    if (check_pow)
    {
        uint256 target = chain::bits_to_target(share.m_bits);
        if (target.IsNull())
            throw std::invalid_argument("share target is zero");

        uint256 pow_hash = params.pow_func(hdr_span);

        if (pow_hash > target)
            throw std::invalid_argument("share PoW hash does not meet target");
    }

    return share_hash;
}

} // namespace dash
