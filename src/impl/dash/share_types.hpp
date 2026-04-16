#pragma once

// Dash p2pool share v16 serialization types.
// Reference: ref/p2pool-dash/p2pool/data.py lines 68-127

#include <core/uint256.hpp>
#include <core/pack_types.hpp>
#include <core/pack.hpp>

namespace dash
{

enum StaleInfo : uint8_t
{
    none = 0,
    orphan = 253,
    doa = 254
};

// Merkle link (same as LTC but index is always 0 for Dash v16)
struct MerkleLink
{
    std::vector<uint256> m_branch;
    uint32_t m_index{0};

    SERIALIZE_METHODS(MerkleLink) { READWRITE(obj.m_branch); /* index always 0, not serialized */ }
};

// Hash link (same structure as LTC)
struct HashLinkType
{
    FixedStrType<32> m_state;
    BaseScript m_extra_data;  // VarStr
    uint64_t m_length;

    SERIALIZE_METHODS(HashLinkType) { READWRITE(obj.m_state, obj.m_extra_data, VarInt(obj.m_length)); }
};

// Packed payment entry (masternode/superblock/platform)
// payee: address string or "!<hex>" for script-encoded payments
// amount: satoshis
struct PackedPayment
{
    std::string m_payee;     // PossiblyNone('', VarStr)
    uint64_t m_amount{0};    // PossiblyNone(0, IntType(64))

    template <typename StreamType>
    void Serialize(StreamType& os) const
    {
        // PossiblyNone for payee: empty string = None
        BaseScript bs;
        bs.m_data.assign(m_payee.begin(), m_payee.end());
        ::Serialize(os, bs);
        ::Serialize(os, m_amount);
    }

    template <typename StreamType>
    void Unserialize(StreamType& is)
    {
        BaseScript bs;
        ::Unserialize(is, bs);
        m_payee.assign(bs.m_data.begin(), bs.m_data.end());
        ::Unserialize(is, m_amount);
    }
};

} // namespace dash
