#pragma once

#include <btclibs/uint256.h>

#include <core/pack_types.hpp>
#include <core/netaddress.hpp>

namespace ltc
{

struct addr_type
{
    uint64_t m_services;
    NetService m_endpoint;

    SERIALIZE_METHODS(ltc::addr_type) { READWRITE(obj.m_services, obj.m_endpoint); }
};

struct BlockHeaderType
{
    int32_t m_version;
    uint256 m_previous_block;
    uint256 m_merkle_root;
    uint32_t m_timestamp;
    uint32_t m_bits;
    uint32_t m_nonce;

    SERIALIZE_METHODS(BlockHeaderType) { READWRITE(obj.m_version, obj.m_previous_block, obj.m_merkle_root, obj.m_timestamp, obj.m_bits, obj.m_bits); }

    void SetNull()
    {
        m_version = 0;
        m_previous_block.SetNull();
        m_merkle_root.SetNull();
        m_timestamp = 0;
        m_bits = 0;
        m_nonce = 0;
    }

    bool IsNull() const
    {
        return (m_bits == 0);
    }

};

} // namespace ltc