#pragma once

#include <core/uint256.hpp>
#include <core/pack_types.hpp>
#include <core/pack.hpp>

namespace ltc
{

const uint64_t SEGWIT_ACTIVATION_VERSION = 40;

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

struct MerkleLink
{
    std::vector<uint256> m_branch;
    uint32_t m_index{0};

    MerkleLink() { }

    SERIALIZE_METHODS(MerkleLink) { READWRITE(obj.m_branch, obj.m_index); }
};

struct SegwitData
{
    MerkleLink m_txid_merkle_link;
    uint256 m_wtxid_merkle_root;

    SegwitData() {}
    SegwitData(MerkleLink txid_merkle_link, uint256 wtxid) : m_txid_merkle_link(txid_merkle_link), m_wtxid_merkle_root(wtxid) { }

    SERIALIZE_METHODS(SegwitData) { READWRITE(obj.m_txid_merkle_link, obj.m_wtxid_merkle_root); }
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

} // namespace ltc
