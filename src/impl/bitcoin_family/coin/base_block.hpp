#pragma once

// Generic Bitcoin-family block header types.
// SmallBlockHeaderType: compact header for p2pool share serialization (VarInt version).
// BlockHeaderType: standard 80-byte block header (fixed uint32 version).
// BaseBlockType: block = header + transactions (no MWEB).
//
// LTC extends BaseBlockType with MWEB support (m_mweb_raw, HogEx).
// Dash, BTC, DOGE use BaseBlockType directly.

#include <core/uint256.hpp>
#include <core/pack_types.hpp>

#include <vector>

namespace bitcoin_family
{
namespace coin
{

struct SmallBlockHeaderType
{
    uint64_t m_version {};
    uint256 m_previous_block{};
    uint32_t m_timestamp{};
    uint32_t m_bits{};
    uint32_t m_nonce{};

    SERIALIZE_METHODS(SmallBlockHeaderType) { READWRITE(VarInt(obj.m_version), obj.m_previous_block, obj.m_timestamp, obj.m_bits, obj.m_nonce); }

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

    // Full block header uses fixed 4-byte int32 version (not VarInt like SmallBlockHeaderType)
    template<typename Stream>
    void Serialize(Stream& s) const {
        uint32_t version32 = static_cast<uint32_t>(m_version);
        ::Serialize(s, version32);
        ::Serialize(s, m_previous_block);
        ::Serialize(s, m_merkle_root);
        ::Serialize(s, m_timestamp);
        ::Serialize(s, m_bits);
        ::Serialize(s, m_nonce);
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
    }

    BlockHeaderType() : SmallBlockHeaderType() { }

    void SetNull()
    {
        SmallBlockHeaderType::SetNull();
        m_merkle_root.SetNull();
    }

    bool IsNull() const
    {
        return (m_bits == 0);
    }
};

} // namespace coin
} // namespace bitcoin_family
