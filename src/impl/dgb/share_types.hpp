#pragma once

#include <core/uint256.hpp>
#include <core/pack_types.hpp>
#include <core/pack.hpp>
#include "config_pool.hpp"   // SSOT: PoolConfig::SEGWIT_ACTIVATION_VERSION

namespace dgb
{

// SSOT delegation (oracle = 17). Serialization/consensus gate sources from
// PoolConfig; no local literal. Symbol kept for share_check.hpp consumers.
inline constexpr uint32_t SEGWIT_ACTIVATION_VERSION = PoolConfig::SEGWIT_ACTIVATION_VERSION;

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

    friend bool operator==(const MerkleLink& l, const MerkleLink& r)
    {
        return l.m_branch == r.m_branch && l.m_index == r.m_index;
    }
    friend bool operator!=(const MerkleLink& l, const MerkleLink& r) { return !(l == r); }
};

struct SegwitData
{
    MerkleLink m_txid_merkle_link;
    uint256 m_wtxid_merkle_root;

    SegwitData() {}
    SegwitData(MerkleLink txid_merkle_link, uint256 wtxid) : m_txid_merkle_link(txid_merkle_link), m_wtxid_merkle_root(wtxid) { }

    friend bool operator==(const SegwitData& l, const SegwitData& r)
    {
        return l.m_txid_merkle_link == r.m_txid_merkle_link
            && l.m_wtxid_merkle_root == r.m_wtxid_merkle_root;
    }
    friend bool operator!=(const SegwitData& l, const SegwitData& r) { return !(l == r); }

    C2POOL_SERIALIZE_METHODS(SegwitData) { READWRITE(MERKLE_LINK_SMALL(obj.m_txid_merkle_link), obj.m_wtxid_merkle_root); }
};

struct SegwitDataDefault
{
    static SegwitData get()
    {
        // p2pool-merged-v36 PossiblyNoneType none_value (oracle @9903aab7
        // data.py:1680 v36 share_info_type, :702 pre-v36): the None segwit_data
        // record is dict(txid_merkle_link=dict(branch=[], index=0),
        // wtxid_merkle_root=2**256-1). The all-0xff wtxid root is the WIRE
        // sentinel ONLY — the witness-commitment path (data.py:1015/1019)
        // recomputes segwit_data fresh and non-None, so 0xff never reaches the
        // commitment calc. Read-side symmetry (sentinel -> nullopt) is restored
        // by SegwitDataPossiblyNone below, so a deserialized None share has
        // has_value()==false and the 0xff root is never fed to the commitment.
        uint256 none_root;
        none_root.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        return SegwitData{{}, none_root};
    }
};

// V36 segwit_data is p2pool's PossiblyNoneType: on the wire, None is the
// sentinel record from SegwitDataDefault::get() above. The core OptionalType<>
// only writes the default for a None value; it never maps the sentinel back to
// None on read, which (pre-fix) left a relayed/reconstructed None share carrying
// the all-0xff wtxid root and feeding a bogus witness commitment. This
// dgb-local formatter restores the symmetric round-trip — write default for
// nullopt, map the sentinel record back to nullopt on read — matching
// p2pool-merged-v36 @9903aab7. Fenced to src/impl/dgb/ (per-coin isolation).
struct SegwitDataPossiblyNone
{
    template <typename StreamType>
    static void Write(StreamType& os, const std::optional<SegwitData>& opt)
    {
        if (opt)
            os << *opt;
        else
            os << SegwitDataDefault::get();
    }

    template <typename StreamType>
    static void Read(StreamType& os, std::optional<SegwitData>& opt)
    {
        SegwitData result;
        os >> result;
        if (result == SegwitDataDefault::get())
            opt = std::nullopt;
        else
            opt = result;
    }
};

struct TxHashRefs
{
    uint64_t m_share_count;
    uint64_t m_tx_count;

    TxHashRefs() = default;
    TxHashRefs(uint64_t share, uint64_t tx) : m_share_count(share), m_tx_count(tx) {}

    C2POOL_SERIALIZE_METHODS(TxHashRefs) { READWRITE(VarInt(obj.m_share_count), VarInt(obj.m_tx_count)); }
};

struct ShareTxInfo
{
    std::vector<uint256> m_new_transaction_hashes;
    std::vector<TxHashRefs> m_transaction_hash_refs; //pack.ListType(pack.VarIntType(), 2)), # pairs of share_count, tx_count

    ShareTxInfo() = default;

    ShareTxInfo(const auto& new_tx_hashes, const auto& tx_hash_refs) 
        : m_new_transaction_hashes(new_tx_hashes), m_transaction_hash_refs(tx_hash_refs) { }

    C2POOL_SERIALIZE_METHODS(ShareTxInfo) { READWRITE(obj.m_new_transaction_hashes, obj.m_transaction_hash_refs); }
};

struct HashLinkType
{
    FixedStrType<32> m_state;      //pack.FixedStrType(32)
    // FixedStrType<0> m_extra_data; //pack.FixedStrType(0) # bit of a hack, but since the donation script is at the end, const_ending is long enough to always make this empty
    uint64_t m_length;        //pack.VarIntType()

    C2POOL_SERIALIZE_METHODS(HashLinkType) { READWRITE(obj.m_state, /*obj.m_extra_data,*/ VarInt(obj.m_length)); }
};

// V36 hash link (DGB-Scrypt; share format parity with p2pool-merged-v36) — extra_data becomes VarStr (was FixedStr(0) pre-V36)
struct V36HashLinkType
{
    FixedStrType<32> m_state;
    BaseScript m_extra_data;     // VarStr in V36
    uint64_t m_length;

    C2POOL_SERIALIZE_METHODS(V36HashLinkType) { READWRITE(obj.m_state, obj.m_extra_data, VarInt(obj.m_length)); }
};

// V36 merged mining: per-chain address entry
struct MergedAddressEntry
{
    uint32_t m_chain_id;
    BaseScript m_script;

    C2POOL_SERIALIZE_METHODS(MergedAddressEntry) { READWRITE(obj.m_chain_id, obj.m_script); }
};

// V36 merged mining: per-chain coinbase verification entry
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

} // namespace dgb
