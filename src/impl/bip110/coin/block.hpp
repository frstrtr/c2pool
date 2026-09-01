// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include "transaction.hpp"

#include <core/uint256.hpp>
#include <core/pack_types.hpp>
#include <core/netaddress.hpp>

#include <array>
#include <cstdint>

namespace bip110
{

namespace coin
{

// BIP-110 v2 header flag: block version bit 31 (VERSION_HEADER_V2_FLAG,
// Knots primitives/block.h:25). Set at/after Blake2bHeight (961640).
static constexpr uint32_t VERSION_HEADER_V2_FLAG = 0x80000000u;

struct SmallBlockHeaderType
{
    uint64_t m_version {};
    uint256 m_previous_block{};
    uint32_t m_timestamp{};
    uint32_t m_bits{};
    uint32_t m_nonce{};

    C2POOL_SERIALIZE_METHODS(SmallBlockHeaderType) { READWRITE(VarInt(obj.m_version), obj.m_previous_block, obj.m_timestamp, obj.m_bits, obj.m_nonce); }

    SmallBlockHeaderType() {}

    void SetNull()
    {
        m_version = 0;
        m_previous_block.SetNull();
        m_timestamp = 0;
        m_bits = 0;
        m_nonce = 0;
    }

    bool IsNull() const
    {
        return (m_bits == 0);
    }
};

struct BlockHeaderType : SmallBlockHeaderType
{
    uint256 m_merkle_root;

    // ── BIP-110 v2 header extension (present iff version bit 31 set) ──────────
    // Field order + widths mirror Knots primitives/block.h:103-124 exactly. The
    // packed bytes flow verbatim into bip110::pow::blake2b_block_hash_v2, so any
    // width/order slip here silently breaks post-fork header parse (permanent
    // stall at 961639). Covered by the bip110 wire-deser KAT.
    uint32_t                   m_nonce2{0};
    uint32_t                   m_nonce3{0};
    std::array<uint8_t, 16>    m_extranonce{};   // u128
    uint32_t                   m_time_offset{0};
    uint16_t                   m_txcount{0};
    uint8_t                    m_flags{0};
    uint8_t                    m_clear_bits{0};
    std::array<uint8_t, 16>    m_xor_key{};      // u128
    int32_t                    m_height{0};
    uint256                    m_mm_rhs;         // u256

    bool is_v2() const { return (static_cast<uint32_t>(m_version) & VERSION_HEADER_V2_FLAG) != 0; }

    // Full block header uses fixed 4-byte int32 version (not VarInt like SmallBlockHeaderType).
    // For BIP-110 v2 headers (bit 31 set) the 84-byte extension follows the classic 80 bytes.
    template<typename Stream>
    void Serialize(Stream& s) const {
        uint32_t version32 = static_cast<uint32_t>(m_version);
        ::Serialize(s, version32);
        ::Serialize(s, m_previous_block);
        ::Serialize(s, m_merkle_root);
        ::Serialize(s, m_timestamp);
        ::Serialize(s, m_bits);
        ::Serialize(s, m_nonce);
        if (version32 & VERSION_HEADER_V2_FLAG) {
            ::Serialize(s, m_nonce2);
            ::Serialize(s, m_nonce3);
            for (uint8_t b : m_extranonce) ::Serialize(s, b);
            ::Serialize(s, m_time_offset);
            ::Serialize(s, m_txcount);
            ::Serialize(s, m_flags);
            ::Serialize(s, m_clear_bits);
            for (uint8_t b : m_xor_key) ::Serialize(s, b);
            ::Serialize(s, static_cast<uint32_t>(m_height));
            ::Serialize(s, m_mm_rhs);
        }
    }
    template<typename Stream>
    void Unserialize(Stream& s) {
        uint32_t version32;
        ::Unserialize(s, version32);
        m_version = version32;
        ::Unserialize(s, m_previous_block);
        ::Unserialize(s, m_merkle_root);
        ::Unserialize(s, m_timestamp);
        ::Unserialize(s, m_bits);
        ::Unserialize(s, m_nonce);
        if (version32 & VERSION_HEADER_V2_FLAG) {
            ::Unserialize(s, m_nonce2);
            ::Unserialize(s, m_nonce3);
            for (auto& b : m_extranonce) ::Unserialize(s, b);
            ::Unserialize(s, m_time_offset);
            ::Unserialize(s, m_txcount);
            ::Unserialize(s, m_flags);
            ::Unserialize(s, m_clear_bits);
            for (auto& b : m_xor_key) ::Unserialize(s, b);
            uint32_t h32;
            ::Unserialize(s, h32);
            m_height = static_cast<int32_t>(h32);
            ::Unserialize(s, m_mm_rhs);
        }
    }

    BlockHeaderType() : SmallBlockHeaderType() { }

    void SetNull()
    {
        SmallBlockHeaderType::SetNull();
        m_merkle_root.SetNull();
        m_nonce2 = 0; m_nonce3 = 0; m_extranonce.fill(0);
        m_time_offset = 0; m_txcount = 0; m_flags = 0; m_clear_bits = 0;
        m_xor_key.fill(0); m_height = 0; m_mm_rhs.SetNull();
    }

    bool IsNull() const
    {
        return (m_bits == 0);
    }

};

struct BlockType : BlockHeaderType
{
	std::vector<MutableTransaction> m_txs;

    template <typename Stream>
    void Serialize(Stream& s) const {
        BlockHeaderType::Serialize(s);
        ::Serialize(s, TX_WITH_WITNESS(m_txs));
    }

    template <typename Stream>
    void Unserialize(Stream& s) {
        BlockHeaderType::Unserialize(s);
        ::Unserialize(s, TX_WITH_WITNESS(m_txs));
    }

    BlockType() : BlockHeaderType() { }

    void SetNull()
    {
        BlockHeaderType::SetNull();
        m_txs.clear();
    }

    bool IsNull() const
    {
        return BlockHeaderType::IsNull();
    }
};

} // namespace coin

} // namespace bip110