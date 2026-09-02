// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
//
// bip110::pool share wire types. Byte-format-identical to the v36 MergedMiningShare
// family already ported into the BTC lane (src/impl/btc/share_types.hpp), which is
// itself the port of the python fork p2pool-merged-v36 (p2pool/data.py). The ONE
// structural delta vs the BTC lane is Bip110SmallBlockHeaderType (below): the
// share's min_header carries the full BIP-110 v2 (BLAKE2b) header extension MINUS
// the 32-byte tx-merkle-root, which is reconstructed from coinbase+branches at
// verify time (see share_identity.hpp). Everything else — SegwitData zero-sentinel,
// MergedAddressEntry, MergedCoinbaseEntry, V36HashLinkType, AbsworkV36Format,
// StaleInfo — is copied verbatim so a python-fork bip110 lane can share ONE
// sharechain (decision card #1: v36 wire-genesis).

#include "../coin/block.hpp"   // bip110::coin::VERSION_HEADER_V2_FLAG + BlockHeaderType
#include "config_pool.hpp"     // SSOT: PoolConfig::SEGWIT_ACTIVATION_VERSION

#include <core/uint256.hpp>
#include <core/pack_types.hpp>
#include <core/pack.hpp>

#include <array>

namespace bip110::pool
{

constexpr bool is_segwit_activated(uint64_t version)
{
    return version >= PoolConfig::SEGWIT_ACTIVATION_VERSION;
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

    C2POOL_SERIALIZE_METHODS(SegwitData) { READWRITE(MERKLE_LINK_SMALL(obj.m_txid_merkle_link), obj.m_wtxid_merkle_root); }
};

struct SegwitDataDefault
{
    static SegwitData get()
    {
        // Sentinel matches p2pool's PossiblyNoneType sentinel:
        // dict(txid_merkle_link=dict(branch=[], index=0), wtxid_merkle_root=0).
        // (all-0xff would be read as a valid wtxid root -> different coinbase txid.)
        return SegwitData{{}, uint256()}; // zero = None sentinel
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
    std::vector<TxHashRefs> m_transaction_hash_refs;

    ShareTxInfo() = default;

    ShareTxInfo(const auto& new_tx_hashes, const auto& tx_hash_refs)
        : m_new_transaction_hashes(new_tx_hashes), m_transaction_hash_refs(tx_hash_refs) { }

    C2POOL_SERIALIZE_METHODS(ShareTxInfo) { READWRITE(obj.m_new_transaction_hashes, obj.m_transaction_hash_refs); }
};

struct HashLinkType
{
    FixedStrType<32> m_state;
    uint64_t m_length;

    C2POOL_SERIALIZE_METHODS(HashLinkType) { READWRITE(obj.m_state, VarInt(obj.m_length)); }
};

// V36 hash link — extra_data becomes VarStr (was FixedStr(0) pre-V36), because
// v36 gentx_before_refhash is only 35B so const_ending no longer swallows it.
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
    BaseScript m_coinbase_script;

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

// ============================================================================
// THE STRUCTURAL DELTA vs the BTC lane: the BIP-110 small block header.
// ============================================================================
// p2pool's "small block header" is the block header MINUS the tx-merkle-root (the
// share commits everything but the merkle root, which is reconstructed from the
// coinbase gentx + merkle branches). On the classic SHA256d chains that leaves the
// 5 classic fields {version, prev, time, bits, nonce}. On the BIP-110 v2 (BLAKE2b)
// chain the header is the 164-byte v2 header, so the small header must additionally
// carry the 84-byte v2 EXTENSION (nonce2..mm_rhs) — everything except the merkle
// root. Field order/width mirror bip110::coin::BlockHeaderType exactly (which
// mirrors Knots primitives/block.h:103-124); the ONLY omission is m_merkle_root.
//
// Wire encoding follows the p2pool small-header convention: version as VarInt
// (bit31 v2 flag preserved — a 5-byte varint), prev/time/bits/nonce as in the
// classic small header, then the v2 extension fixed-width in header byte order.
// to_full(merkle_root) reinserts the merkle root at offset 36 to reconstruct the
// canonical 164-byte coin::BlockHeaderType that BLAKE2b hashes (share_identity.hpp).
struct Bip110SmallBlockHeaderType
{
    uint64_t m_version{};
    uint256  m_previous_block{};
    uint32_t m_timestamp{};
    uint32_t m_bits{};
    uint32_t m_nonce{};

    // v2 extension (present iff version bit31 set). merkle_root DELIBERATELY absent.
    uint32_t                m_nonce2{0};
    uint32_t                m_nonce3{0};
    std::array<uint8_t, 16> m_extranonce{};   // u128
    uint32_t                m_time_offset{0};
    uint16_t                m_txcount{0};
    uint8_t                 m_flags{0};
    uint8_t                 m_clear_bits{0};
    std::array<uint8_t, 16> m_xor_key{};      // u128
    int32_t                 m_height{0};
    uint256                 m_mm_rhs{};         // u256

    Bip110SmallBlockHeaderType() {}

    bool is_v2() const
    {
        return (static_cast<uint32_t>(m_version) & coin::VERSION_HEADER_V2_FLAG) != 0;
    }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, Using<CompactFormat>(m_version));  // VarInt version (small-header convention)
        ::Serialize(s, m_previous_block);
        ::Serialize(s, m_timestamp);
        ::Serialize(s, m_bits);
        ::Serialize(s, m_nonce);
        if (is_v2())
        {
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

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, Using<CompactFormat>(m_version));
        ::Unserialize(s, m_previous_block);
        ::Unserialize(s, m_timestamp);
        ::Unserialize(s, m_bits);
        ::Unserialize(s, m_nonce);
        if (is_v2())
        {
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

    // Reconstruct the canonical full 164-byte BIP-110 v2 header by reinserting the
    // reconstructed tx-merkle-root at offset 36. This is the header that flows into
    // bip110::pow::blake2b_block_hash to produce the share-hash == block-identity.
    coin::BlockHeaderType to_full(const uint256& merkle_root) const
    {
        coin::BlockHeaderType h;
        h.m_version        = m_version;
        h.m_previous_block = m_previous_block;
        h.m_merkle_root    = merkle_root;
        h.m_timestamp      = m_timestamp;
        h.m_bits           = m_bits;
        h.m_nonce          = m_nonce;
        h.m_nonce2         = m_nonce2;
        h.m_nonce3         = m_nonce3;
        h.m_extranonce     = m_extranonce;
        h.m_time_offset    = m_time_offset;
        h.m_txcount        = m_txcount;
        h.m_flags          = m_flags;
        h.m_clear_bits     = m_clear_bits;
        h.m_xor_key        = m_xor_key;
        h.m_height         = m_height;
        h.m_mm_rhs         = m_mm_rhs;
        return h;
    }

    // Inverse of to_full: split a full coin::BlockHeaderType into the wire small
    // header (dropping the merkle root). Used at mint (PR-B) and in the identity KAT.
    static Bip110SmallBlockHeaderType from_full(const coin::BlockHeaderType& h)
    {
        Bip110SmallBlockHeaderType s;
        s.m_version        = h.m_version;
        s.m_previous_block = h.m_previous_block;
        s.m_timestamp      = h.m_timestamp;
        s.m_bits           = h.m_bits;
        s.m_nonce          = h.m_nonce;
        s.m_nonce2         = h.m_nonce2;
        s.m_nonce3         = h.m_nonce3;
        s.m_extranonce     = h.m_extranonce;
        s.m_time_offset    = h.m_time_offset;
        s.m_txcount        = h.m_txcount;
        s.m_flags          = h.m_flags;
        s.m_clear_bits     = h.m_clear_bits;
        s.m_xor_key        = h.m_xor_key;
        s.m_height         = h.m_height;
        s.m_mm_rhs         = h.m_mm_rhs;
        return s;
    }
};

} // namespace bip110::pool
