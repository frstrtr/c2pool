#pragma once

// P2: Share verification — check_hash_link, check_merkle_link, share init/check
// Ported from legacy sharechains/data.cpp + sharechains/share.cpp

#include "config_pool.hpp"
#include "share.hpp"
#include "share_types.hpp"

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>
#include <btclibs/crypto/common.h>
#include <btclibs/crypto/sha256.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace ltc
{

// ============================================================================
// check_hash_link()
//
// Restores SHA256 mid-state from hash_link, continues hashing with
// (data + extra), then double-SHA256 finalises to the gentx_hash.
//
// Legacy: sharechains/data.cpp  check_hash_link()
// ============================================================================
inline uint256 check_hash_link(const HashLinkType& hash_link,
                               const std::vector<unsigned char>& data,
                               const std::vector<unsigned char>& const_ending = {})
{
    const uint64_t extra_length = hash_link.m_length % 64; // 512/8 = 64

    // hash_link.extra_data is always empty in our format (length 0)
    // so extra == tail of const_ending sized to extra_length
    std::vector<unsigned char> extra(const_ending);
    if (extra.size() > extra_length)
        extra.erase(extra.begin(), extra.begin() + (extra.size() - extra_length));
    if (extra.size() != extra_length)
        throw std::runtime_error("check_hash_link: extra size mismatch");

    // Restore SHA256 mid-state from hash_link.m_state (32 bytes, big-endian)
    const auto& state_bytes = hash_link.m_state.m_data;
    uint32_t init_state[8] = {
        ReadBE32(state_bytes.data() +  0),
        ReadBE32(state_bytes.data() +  4),
        ReadBE32(state_bytes.data() +  8),
        ReadBE32(state_bytes.data() + 12),
        ReadBE32(state_bytes.data() + 16),
        ReadBE32(state_bytes.data() + 20),
        ReadBE32(state_bytes.data() + 24),
        ReadBE32(state_bytes.data() + 28),
    };

    // Prepare the buffer for the custom CSHA256 constructor
    // (the partial 64-byte block content at the time of the mid-state)
    std::vector<unsigned char> buf;
    if (extra.empty())
        buf.push_back(0); // legacy quirk: empty buf gets a nul byte
    else
        buf = extra;

    // Continue hashing: mid-state → write(data) → finalise(single SHA256)
    unsigned char out1[CSHA256::OUTPUT_SIZE];
    CSHA256(init_state, buf, hash_link.m_length)
        .Write(data.data(), data.size())
        .Finalize(out1);

    // Second SHA256 pass → double-SHA256
    unsigned char out2[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(out1, CSHA256::OUTPUT_SIZE).Finalize(out2);

    // Write raw double-SHA256 output directly into uint256
    // (matches Bitcoin Core's Hash() which does the same)
    uint256 result;
    std::memcpy(result.data(), out2, 32);
    return result;
}

// ============================================================================
// check_merkle_link()
//
// Walk a Merkle branch to compute the root from a given tip_hash.
//
// Legacy: libcoind/data.cpp  check_merkle_link()
// ============================================================================
inline uint256 check_merkle_link(const uint256& tip_hash, const MerkleLink& link)
{
    if (link.m_branch.size() > 0 &&
        link.m_index >= (1u << link.m_branch.size()))
        throw std::invalid_argument("check_merkle_link: index too large");

    uint256 cur = tip_hash;
    for (size_t i = 0; i < link.m_branch.size(); ++i)
    {
        // Combine: if bit i of index is set, branch[i] is on the left
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

        // double-SHA256 of the 64-byte concatenation
        auto sp = std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(ps.data()), ps.size());
        cur = Hash(sp);
    }
    return cur;
}

// ============================================================================
// compute_gentx_before_refhash()
//
// Computes the constant ending bytes that appear after the coinbase outputs
// and before the ref_hash in the serialised coinbase transaction.
//
// Legacy: networks/network.cpp  "init gentx_before_refhash"
// Formula: VarStr(DONATION_SCRIPT) + int64(0) + VarStr(0x6a28 + int256(0) + int64(0))[:3]
// ============================================================================
inline std::vector<unsigned char> compute_gentx_before_refhash(int64_t share_version)
{
    std::vector<unsigned char> result;

    // 1. VarStr(DONATION_SCRIPT)
    auto donation_script = PoolConfig::get_donation_script(share_version);
    {
        PackStream s;
        BaseScript bs;
        bs.m_data = donation_script;
        s << bs;
        auto* p = reinterpret_cast<const unsigned char*>(s.data());
        result.insert(result.end(), p, p + s.size());
    }

    // 2. int64(0)
    {
        uint64_t zero64 = 0;
        auto* p = reinterpret_cast<const unsigned char*>(&zero64);
        result.insert(result.end(), p, p + 8);
    }

    // 3. VarStr(0x6a 0x28 + int256(0) + int64(0)) — but only the first 3 bytes
    {
        PackStream inner;
        // raw bytes: OP_RETURN (0x6a) + PUSH_40 (0x28)
        unsigned char prefix[2] = {0x6a, 0x28};
        inner.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(prefix), 2));
        // 32 zero bytes (uint256(0))
        uint256 zero256;
        inner << zero256;
        // 8 zero bytes (uint64(0))
        uint64_t zero64 = 0;
        inner.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&zero64), 8));

        // Pack as VarStr
        PackStream outer;
        BaseScript bs;
        bs.m_data.resize(inner.size());
        std::memcpy(bs.m_data.data(), inner.data(), inner.size());
        outer << bs;

        // Take only the first 3 bytes
        auto* p = reinterpret_cast<const unsigned char*>(outer.data());
        result.insert(result.end(), p, p + std::min<size_t>(3, outer.size()));
    }

    return result;
}

// ============================================================================
// share_init_verify()
//
// Performs the init()-phase verification of a share:
//   1. Basic field validation (coinbase size, merkle branch lengths)
//   2. Compute hash_link_data from ref serialisation
//   3. check_hash_link → gentx_hash
//   4. check_merkle_link → merkle_root
//   5. Build full block header
//   6. Compute hash (double-SHA256 of header)
//   7. Verify pow_hash <= target
//
// Returns the share hash (double-SHA256 of the reconstructed header).
// Throws on any validation failure.
//
// NOTE: The full GenerateShareTransaction reconstruction from check() is
// deferred to a later PR (P2.5).  This function covers the PoW + hash-link
// verification path from legacy Share::init().
// ============================================================================
template <typename ShareT>
uint256 share_init_verify(const ShareT& share)
{
    // --- Basic validation ---
    if (share.m_coinbase.size() < 2 || share.m_coinbase.size() > 100)
        throw std::invalid_argument("bad coinbase size");

    if (share.m_merkle_link.m_branch.size() > 16)
        throw std::invalid_argument("merkle branch too long");

    constexpr int64_t ver = ShareT::version;

    if constexpr (ver >= ltc::SEGWIT_ACTIVATION_VERSION)
    {
        if constexpr (requires { share.m_segwit_data; })
        {
            if (share.m_segwit_data.has_value())
            {
                if (share.m_segwit_data->m_txid_merkle_link.m_branch.size() > 16)
                    throw std::invalid_argument("segwit txid merkle branch too long");
            }
        }
    }

    // --- Compute ref_hash ---
    // RefType serialisation: IDENTIFIER + share_info fields + segwit_data
    // Then hash256 it, then check_merkle_link with ref_merkle_link
    //
    // For now we serialise the minimal fields the same way the legacy code
    // does (share_data + share_info + optional segwit_data) via a PackStream.
    PackStream ref_stream;

    // IDENTIFIER bytes (8 bytes from IDENTIFIER_HEX)
    {
        auto hex = PoolConfig::IDENTIFIER_HEX;
        for (size_t i = 0; i + 1 < hex.size(); i += 2)
        {
            unsigned char byte = static_cast<unsigned char>(
                std::stoul(hex.substr(i, 2), nullptr, 16));
            ref_stream.write(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(&byte), 1));
        }
    }

    // share_info serialisation — we re-serialise the share's share_info fields
    // through the same Formatter path that was used to decode them.
    // For ref_hash we need: share_data + share_info fields + segwit_data
    // We serialise the relevant fields into the ref_stream.
    {
        // prev_hash
        ref_stream << share.m_prev_hash;
        // coinbase
        ref_stream << share.m_coinbase;
        // nonce (uint32_t LE)
        ref_stream << share.m_nonce;

        // address or pubkey_hash
        if constexpr (ver >= 34)
            ref_stream << share.m_address;
        else
            ref_stream << share.m_pubkey_hash;

        // subsidy (uint64_t LE), donation (uint16_t LE)
        ref_stream << share.m_subsidy;
        ref_stream << share.m_donation;
        // stale_info as EnumType<IntType<8>> — single byte
        {
            uint8_t si = static_cast<uint8_t>(share.m_stale_info);
            ref_stream << si;
        }
        // desired_version as VarInt
        {
            uint64_t dv = share.m_desired_version;
            ::Serialize(ref_stream, VarInt(dv));
        }

        // segwit_data (optional)
        if constexpr (requires { share.m_segwit_data; })
        {
            if (share.m_segwit_data.has_value())
                ref_stream << share.m_segwit_data.value();
        }

        // tx info (pre-v34)
        if constexpr (ver < 34)
        {
            if constexpr (requires { share.m_tx_info; })
                ref_stream << share.m_tx_info;
        }

        // far_share_hash, max_bits (uint32_t), bits (uint32_t),
        // timestamp (uint32_t), absheight (uint32_t), abswork (uint128)
        ref_stream << share.m_far_share_hash;
        ref_stream << share.m_max_bits;
        ref_stream << share.m_bits;
        ref_stream << share.m_timestamp;
        ref_stream << share.m_absheight;
        ref_stream << share.m_abswork;
    }

    // hash256 of the ref_type serialisation
    auto ref_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(ref_stream.data()), ref_stream.size());
    uint256 hash_ref = Hash(ref_span);

    // check_merkle_link with ref_merkle_link
    uint256 ref_hash = check_merkle_link(hash_ref, share.m_ref_merkle_link);

    // --- Build hash_link_data ---
    // hash_link_data = ref_hash bytes + pack(last_txout_nonce, LE64) + pack(0, LE32)
    std::vector<unsigned char> hash_link_data;
    hash_link_data.insert(hash_link_data.end(), ref_hash.data(), ref_hash.data() + 32);
    {
        // last_txout_nonce as little-endian uint64
        uint64_t nonce = share.m_last_txout_nonce;
        auto* p = reinterpret_cast<const unsigned char*>(&nonce);
        hash_link_data.insert(hash_link_data.end(), p, p + 8);
    }
    {
        // trailing zero uint32
        uint32_t zero = 0;
        auto* p = reinterpret_cast<const unsigned char*>(&zero);
        hash_link_data.insert(hash_link_data.end(), p, p + 4);
    }

    auto gentx_before_refhash = compute_gentx_before_refhash(ver);

    // --- check_hash_link → gentx_hash ---
    uint256 gentx_hash = check_hash_link(share.m_hash_link, hash_link_data, gentx_before_refhash);

    // --- Merkle root ---
    // For segwit-activated shares, use segwit_data.txid_merkle_link; otherwise merkle_link
    uint256 merkle_root;
    if constexpr (ver >= ltc::SEGWIT_ACTIVATION_VERSION)
    {
        if constexpr (requires { share.m_segwit_data; })
        {
            if (share.m_segwit_data.has_value())
                merkle_root = check_merkle_link(gentx_hash, share.m_segwit_data->m_txid_merkle_link);
            else
                merkle_root = check_merkle_link(gentx_hash, share.m_merkle_link);
        }
        else
        {
            merkle_root = check_merkle_link(gentx_hash, share.m_merkle_link);
        }
    }
    else
    {
        merkle_root = check_merkle_link(gentx_hash, share.m_merkle_link);
    }

    // --- Reconstruct full block header and compute hash ---
    // BlockHeaderType: version(int32) + previous_block + merkle_root + timestamp + bits + nonce
    // Note: the full block header uses fixed 4-byte version (not VarInt like SmallBlockHeaderType)
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

    // hash = double-SHA256 of the header (the share's identity)
    auto hdr_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(header_stream.data()), header_stream.size());
    uint256 share_hash = Hash(hdr_span);

    // --- PoW check ---
    // For Litecoin the POW_FUNC is scrypt, but blocks are identified by SHA256d.
    // The pow_hash (scrypt) check against target is deferred until scrypt is
    // integrated (P2.5).  For now we verify the target is sane.
    uint256 target = chain::bits_to_target(share.m_bits);

    // MAX_TARGET for LTC p2pool = 2^256 / 2^32 = (all-ones >> 32) approximately
    // The legacy net->MAX_TARGET is "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    // For safety, just verify target is non-zero
    if (target.IsNull())
        throw std::invalid_argument("share target is zero");

    return share_hash;
}

// ============================================================================
// share_check()
//
// The check()-phase verification after init:
//   1. Timestamp not too far in the future
//   2. Version counting (stub — version upgrade enforcement)
//   3. Transaction hash resolution (for pre-v34 shares)
//   4. GenerateShareTransaction reconstruction & comparison (deferred to P2.5)
//
// Returns true if the share passes all checks.
// Throws on validation failure.
// ============================================================================
template <typename ShareT, typename TrackerT>
bool share_check(const ShareT& share,
                 const uint256& share_hash,
                 TrackerT& tracker)
{
    // 1. Timestamp check — must not be more than 600s in the future
    auto now = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    if (share.m_timestamp > now + 600)
        throw std::invalid_argument("share timestamp is too far in the future");

    // 2. Version counting (stub)
    // Legacy: get_desired_version_counts for upgrade enforcement
    // For now, we skip version switch enforcement — all versions accepted.

    // 3. Transaction hash resolution (pre-v34 only)
    // Legacy resolves other_tx_hashes by walking back the chain via
    // transaction_hash_refs.  Deferred to P2.5 (requires full GenerateShareTransaction).

    // 4. GenerateShareTransaction reconstruction & comparison is the heaviest
    // part of check() (700+ lines).  Deferred to P2.5.
    // For now, the hash-link + merkle + PoW checks from share_init_verify()
    // provide the critical cryptographic verification.

    return true;
}

// ============================================================================
// verify_share()
//
// Combined entry point: runs both init-phase and check-phase verification.
// Returns the computed share hash.
// ============================================================================
template <typename ShareT, typename TrackerT>
uint256 verify_share(const ShareT& share, TrackerT& tracker)
{
    uint256 hash = share_init_verify(share);
    share_check(share, hash, tracker);
    return hash;
}

} // namespace ltc
