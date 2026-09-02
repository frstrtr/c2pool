// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
//
// share_identity.hpp — THE ONE CONSENSUS DELTA of the BIP-110 v36 sharechain lane
// versus every SHA256d lane (btc/ltc/dgb/bch).
//
// On a classic p2pool lane the share-hash / block-identity is:
//     merkle_root = check_merkle_link(gentx_hash, branches)   [SHA256d fold]
//     share_hash  = SHA256d( 80B header{version|prev|merkle|time|bits|nonce} )
// and PoW == share_hash because Bitcoin's block hash IS SHA256d(header).
//
// BIP-110 replaces the block hash with the BLAKE2b commitment pipeline over the
// 164-byte v2 header (bip110::pow::blake2b_block_hash, KAT-pinned vs live fork
// block 961640). tx HASHING is UNCHANGED — txids/merkle are still SHA256d — so
// steps 1-2 (gentx_hash midstate resume + merkle fold) are identical to the BTC
// lane. Only the FINAL header hash changes:
//     header_164 = min_header.to_full(merkle_root)   [reinsert merkle @ offset 36]
//     share_hash = pow_hash = bip110::pow::blake2b_block_hash(header_164)
// PoW == block-identity-hash still holds, so the p2pool share-hash/block-hash
// duality is preserved exactly: pow_hash <= bits_to_target(min_header.bits) marks
// a solved block, identical detection logic to the BTC lane.
//
// FAIL-CLOSED (decision card #6): a share whose min_header carries nonzero
// flags / clear_bits / xor_key is refused BEFORE it can reach the hash pipeline,
// at both mint and accept. Every live BIP-110 fork block is flags=0; the v2 hash
// pipeline itself throws on stage-5 flags 1-3, but we reject explicitly here so a
// hostile share cannot even be hashed.

#include "share_types.hpp"          // Bip110SmallBlockHeaderType
#include "../pow.hpp"               // bip110::pow::blake2b_block_hash
#include "../coin/block.hpp"        // bip110::coin::BlockHeaderType

#include <core/uint256.hpp>
#include <core/pack.hpp>

#include <span>
#include <stdexcept>

namespace bip110::pool
{

// Fail-closed guard on the miner-suppliable header risk fields. Throws
// std::invalid_argument (matches share_check's rejection convention) if any of
// flags / clear_bits / xor_key is nonzero. Call at BOTH mint and accept.
inline void check_header_fail_closed(const Bip110SmallBlockHeaderType& h)
{
    if (h.m_flags != 0)
        throw std::invalid_argument("bip110 share: nonzero min_header.flags (fail-closed, decision #6)");
    if (h.m_clear_bits != 0)
        throw std::invalid_argument("bip110 share: nonzero min_header.clear_bits (fail-closed, decision #6)");
    for (uint8_t b : h.m_xor_key)
        if (b != 0)
            throw std::invalid_argument("bip110 share: nonzero min_header.xor_key (fail-closed, decision #6)");
}

// Serialize the canonical 164-byte BIP-110 v2 header (coin::BlockHeaderType uses
// fixed u32 version + full field layout, matching bip110::pow::parse_header_v2).
inline PackStream serialize_full_header(const coin::BlockHeaderType& full)
{
    PackStream s;
    s << full;
    return s;
}

// The BIP-110 share-hash == block-identity hash. Reconstructs the full 164-byte
// v2 header from the share's small header + the SHA256d-reconstructed merkle root,
// then runs the BLAKE2b block-hash pipeline. This is the drop-in replacement for
// the BTC lane's `Hash(80B header)` at the share_check header-rebuild site.
//
// NOTE: does NOT itself run the fail-closed guard — callers (share_check) invoke
// check_header_fail_closed() first so the rejection reason is explicit and the
// hostile header never reaches blake2b. serialize_full_header of a flags!=0 header
// would in any case throw inside the pipeline (stage-5), a defence-in-depth twin.
inline uint256 compute_share_hash(const Bip110SmallBlockHeaderType& min_header,
                                  const uint256& merkle_root)
{
    coin::BlockHeaderType full = min_header.to_full(merkle_root);
    PackStream hs = serialize_full_header(full);
    auto sp = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(hs.data()), hs.size());
    return bip110::pow::blake2b_block_hash(sp);
}

// Overload for callers that already hold a full coin::BlockHeaderType (mint path
// builds the full header directly; the KAT pins against it).
inline uint256 compute_block_hash(const coin::BlockHeaderType& full)
{
    PackStream hs = serialize_full_header(full);
    auto sp = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(hs.data()), hs.size());
    return bip110::pow::blake2b_block_hash(sp);
}

} // namespace bip110::pool
