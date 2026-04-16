#pragma once

#include "transaction.hpp"

#include <core/uint256.hpp>
#include <core/pack_types.hpp>
#include <core/netaddress.hpp>

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

struct BlockType : BlockHeaderType
{
	std::vector<MutableTransaction> m_txs;

    SERIALIZE_METHODS(BlockType) { READWRITE(AsBase<BlockHeaderType>(obj), TX_WITH_WITNESS(obj.m_txs)); }

    BlockType() : BlockHeaderType() { }

    void SetNull()
    {
        BlockHeaderType::SetNull();
    }

    bool IsNull() const
    {
        return BlockHeaderType::IsNull();
    }
};

} // namespace coin

} // namespace bitcoin_family