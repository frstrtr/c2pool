#pragma once

#include <core/uint256.hpp>
#include <core/pack_types.hpp>
#include <core/pack.hpp>

namespace ltc
{

const uint64_t SEGWIT_ACTIVATION_VERSION = 17;

constexpr bool is_segwit_activated(uint64_t version)
{
    return version >= SEGWIT_ACTIVATION_VERSION;
}

enum StaleInfo
{
    none = 0,
    orphan = 253,
    doa = 254
};

struct MerkleLinkParams
{
    const bool allow_index;

    SER_PARAMS_OPFUNC
};

constexpr static MerkleLinkParams MERKLE_LINK_SMALL {.allow_index = false};
constexpr static MerkleLinkParams MERKLE_LINK_FULL  {.allow_index = true};

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

struct SegwitData
{
    MerkleLink m_txid_merkle_link;
    uint256 m_wtxid_merkle_root;

    SegwitData() {}
    SegwitData(MerkleLink txid_merkle_link, uint256 wtxid) : m_txid_merkle_link(txid_merkle_link), m_wtxid_merkle_root(wtxid) { }

    SERIALIZE_METHODS(SegwitData) { READWRITE(MERKLE_LINK_SMALL(obj.m_txid_merkle_link), obj.m_wtxid_merkle_root); }
};

struct SegwitDataDefault
{
    static SegwitData get()
    {
        return SegwitData{{}, uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")};
    }
};

struct TxHashRefs
{
    uint64_t m_share_count;
    uint64_t m_tx_count;

    TxHashRefs() = default;
    TxHashRefs(uint64_t share, uint64_t tx) : m_share_count(share), m_tx_count(tx) {}

    SERIALIZE_METHODS(TxHashRefs) { READWRITE(VarInt(obj.m_share_count), VarInt(obj.m_tx_count)); }
};

struct ShareTxInfo
{
    std::vector<uint256> m_new_transaction_hashes;
    std::vector<TxHashRefs> m_transaction_hash_refs; //pack.ListType(pack.VarIntType(), 2)), # pairs of share_count, tx_count

    ShareTxInfo() = default;

    ShareTxInfo(const auto& new_tx_hashes, const auto& tx_hash_refs) 
        : m_new_transaction_hashes(new_tx_hashes), m_transaction_hash_refs(tx_hash_refs) { }

    SERIALIZE_METHODS(ShareTxInfo) { READWRITE(obj.m_new_transaction_hashes, obj.m_transaction_hash_refs); }
};

struct HashLinkType
{
    FixedStrType<32> m_state;      //pack.FixedStrType(32)
    // FixedStrType<0> m_extra_data; //pack.FixedStrType(0) # bit of a hack, but since the donation script is at the end, const_ending is long enough to always make this empty
    uint64_t m_length;        //pack.VarIntType()

    SERIALIZE_METHODS(HashLinkType) { READWRITE(obj.m_state, /*obj.m_extra_data,*/ VarInt(obj.m_length)); }
};

// V36 hash link — extra_data becomes VarStr (was FixedStr(0) pre-V36)
struct V36HashLinkType
{
    FixedStrType<32> m_state;
    BaseScript m_extra_data;     // VarStr in V36
    uint64_t m_length;

    SERIALIZE_METHODS(V36HashLinkType) { READWRITE(obj.m_state, obj.m_extra_data, VarInt(obj.m_length)); }
};

// V36 merged mining: per-chain address entry
struct MergedAddressEntry
{
    uint32_t m_chain_id;
    BaseScript m_script;

    SERIALIZE_METHODS(MergedAddressEntry) { READWRITE(VarInt(obj.m_chain_id), obj.m_script); }
};

// V36 merged mining: per-chain coinbase verification entry
struct MergedCoinbaseEntry
{
    uint32_t m_chain_id;
    uint64_t m_coinbase_value;
    uint32_t m_block_height;
    FixedStrType<80> m_block_header;
    MerkleLink m_coinbase_merkle_link;

    template <typename StreamType>
    void Serialize(StreamType& os) const
    {
        ::Serialize(os, Using<CompactFormat>(m_chain_id));
        ::Serialize(os, Using<CompactFormat>(m_coinbase_value));
        ::Serialize(os, Using<CompactFormat>(m_block_height));
        ::Serialize(os, m_block_header);
        ParamPackStream pstream{MERKLE_LINK_SMALL, os};
        ::Serialize(pstream, m_coinbase_merkle_link);
    }

    template <typename StreamType>
    void Unserialize(StreamType& is)
    {
        ::Unserialize(is, Using<CompactFormat>(m_chain_id));
        ::Unserialize(is, Using<CompactFormat>(m_coinbase_value));
        ::Unserialize(is, Using<CompactFormat>(m_block_height));
        ::Unserialize(is, m_block_header);
        ParamPackStream pstream{MERKLE_LINK_SMALL, is};
        ::Unserialize(pstream, m_coinbase_merkle_link);
    }
};

// V36: abswork is VarInt-encoded on the wire but stored as uint128
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

} // namespace ltc
