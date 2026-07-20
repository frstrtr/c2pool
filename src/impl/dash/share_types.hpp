// SPDX-License-Identifier: AGPL-3.0-or-later
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

    C2POOL_SERIALIZE_METHODS(MerkleLink) { READWRITE(obj.m_branch); /* index always 0, not serialized */ }
};

// Hash link (same structure as LTC)
struct HashLinkType
{
    FixedStrType<32> m_state;
    BaseScript m_extra_data;  // VarStr
    uint64_t m_length;

    C2POOL_SERIALIZE_METHODS(HashLinkType) { READWRITE(obj.m_state, obj.m_extra_data, VarInt(obj.m_length)); }
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

// ═══════════════════════════════════════════════════════════════════════════
// V36 SHARED (Bucket-2 / category-2) serialization types.
//
// These are BYTE-FOR-BYTE COPIES of the cross-coin v36 share-format types that
// already live, duplicated per-coin, in src/impl/{ltc,dgb,bch,btc}/share_types.hpp
// (V36HashLinkType, MergedAddressEntry, MergedCoinbaseEntry, AbsworkV36Format,
// the param-based MerkleLink + MERKLE_LINK_SMALL). The v36 share revision has NO
// single shared header — every coin carries its own byte-identical copy and the
// ONLY shared symbol is core::version_gate::is_v36_active. DASH conforms to that
// established pattern here: the copies below MUST stay identical to the other
// coins (this is the whole v36-standardize-for-v37 goal — uniform structs). Any
// drift from the ltc/dgb/bch shape is a cross-coin consensus divergence.
//
// Kept in a nested `dash::v36` namespace so the param-based v36 MerkleLink does
// NOT collide with the pre-existing branch-only `dash::MerkleLink` used by the
// live v16 DashShare (which stays byte-unchanged). The two MerkleLink encodings
// are byte-equivalent for the share-level links (both emit just the branch
// vector: dash::MerkleLink never serializes index; dash::v36::MerkleLink under
// MERKLE_LINK_SMALL has allow_index=false, so index is likewise omitted).
//
// DASH is standalone X11 with NO AuxPoW child, so the MERGED-mining types
// (MergedAddressEntry / MergedCoinbaseEntry) are carried for STRUCTURAL
// uniformity only and are always populated EMPTY on a DASH v36 share — exactly
// how a non-merged ltc/dgb/bch coin populates them (empty vector => VarInt(0)).
namespace v36
{

struct MerkleLinkParams
{
    const bool allow_index;

    SER_PARAMS_OPFUNC
};

constexpr static MerkleLinkParams MERKLE_LINK_SMALL {.allow_index = false};
constexpr static MerkleLinkParams MERKLE_LINK_FULL  {.allow_index = true};

// Param-based MerkleLink (ltc/dgb/bch v36 shape). Under MERKLE_LINK_SMALL the
// index is NOT serialized (allow_index=false) — byte-identical to the branch-
// only encoding the live v16 dash::MerkleLink uses for the share-level links.
struct MerkleLink
{
    std::vector<uint256> m_branch;
    uint32_t m_index{0};

    MerkleLink() { }

    template<typename StreamType>
    void UnserializeMerkleLink(StreamType& s, const MerkleLinkParams& params)
    {
        s >> m_branch;
        if (params.allow_index)
            s >> m_index;
    }

    template<typename StreamType>
    void SerializeMerkleLink(StreamType& s, const MerkleLinkParams& params) const
    {
        s << m_branch;
        if (params.allow_index)
            s << m_index;
    }

    template <typename StreamType>
    inline void Serialize(StreamType& os) const
    {
        SerializeMerkleLink(os, os.GetParams());
    }

    template <typename StreamType>
    inline void Unserialize(StreamType& is)
    {
        UnserializeMerkleLink(is, is.GetParams());
    }
};

// V36 hash link — extra_data becomes VarStr (was FixedStr(0) pre-V36).
struct V36HashLinkType
{
    FixedStrType<32> m_state;
    BaseScript m_extra_data;     // VarStr in V36
    uint64_t m_length;

    C2POOL_SERIALIZE_METHODS(V36HashLinkType) { READWRITE(obj.m_state, obj.m_extra_data, VarInt(obj.m_length)); }
};

// V36 merged mining: per-chain address entry.
struct MergedAddressEntry
{
    uint32_t m_chain_id;
    BaseScript m_script;

    C2POOL_SERIALIZE_METHODS(MergedAddressEntry) { READWRITE(obj.m_chain_id, obj.m_script); }
};

// V36 merged mining: per-chain coinbase verification entry.
struct MergedCoinbaseEntry
{
    uint32_t m_chain_id;
    uint64_t m_coinbase_value;
    uint32_t m_block_height;
    FixedStrType<80> m_block_header;
    MerkleLink m_coinbase_merkle_link;
    BaseScript m_coinbase_script;  // V36: actual scriptSig (allows custom tags + THE state_root)

    template <typename StreamType>
    void Serialize(StreamType& os) const
    {
        ::Serialize(os, m_chain_id);
        ::Serialize(os, Using<CompactFormat>(m_coinbase_value));
        ::Serialize(os, Using<CompactFormat>(m_block_height));
        ::Serialize(os, m_block_header);
        ParamPackStream pstream{MERKLE_LINK_SMALL, os};
        ::Serialize(pstream, m_coinbase_merkle_link);
        ::Serialize(os, m_coinbase_script);
    }

    template <typename StreamType>
    void Unserialize(StreamType& is)
    {
        ::Unserialize(is, m_chain_id);
        ::Unserialize(is, Using<CompactFormat>(m_coinbase_value));
        ::Unserialize(is, Using<CompactFormat>(m_block_height));
        ::Unserialize(is, m_block_header);
        ParamPackStream pstream{MERKLE_LINK_SMALL, is};
        ::Unserialize(pstream, m_coinbase_merkle_link);
        ::Unserialize(is, m_coinbase_script);
    }
};

// V36: abswork is VarInt-encoded on the wire but stored as uint128.
struct AbsworkV36Format
{
    template <typename StreamType>
    static void Write(StreamType& os, const uint128& value)
    {
        WriteCompactSize(os, value.GetLow64());
    }

    template <typename StreamType>
    static void Read(StreamType& is, uint128& value)
    {
        value = uint128(ReadCompactSize(is, false));
    }
};

} // namespace v36

} // namespace dash