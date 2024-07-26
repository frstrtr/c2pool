#pragma once

#include "share_types.hpp"

#include <sharechain/sharechain.hpp>
#include <sharechain/share.hpp>
#include <core/pack_types.hpp>
#include <core/netaddress.hpp>
#include <core/uint256.hpp>

namespace ltc
{

// min_header [small_block_header_type]
//
// share_info_type:
//   share_data:
//      prev_hash
//      coinbase
//      nonce
//      address[>=34] or pubkey_hash[<34]
//      subsidy
//      donation
//      stale_info
//      desired_version
//      
//      segwit_data [if segwit_activated]
//      
//      if version < 34:
//           new_transaction_hashes
//           transaction_hash_refs
//       
//      far_share_hash
//      max_bits
//      bits
//      timestamp
//      absheight
//      abswork
//
// ref_merkle_link
// last_txout_nonce
// hash_link
// merkle_link

template <int64_t Version>
struct BaseShare : chain::BaseShare<uint256, Version>
{
    // prev_hash
    std::vector<unsigned char> m_coinbase; // coinbase
    uint32_t m_nonce; // nonce
    // [ ]address[>=34] or [x]pubkey_hash[<34]
    uint64_t m_subsidy; // subsidy
    uint16_t m_donation; // donation
    ltc::StaleInfo m_stale_info; // stale_info
    uint64_t m_desired_version; // desired_version
    //
    // [ ] segwit_data [if segwit_activated]
    //
    uint256 m_far_share_hash; // far_share_hash
    uint32_t m_max_bits;// max_bits;   bitcoin_data.FloatingIntegerType()
    uint32_t m_bits;    // bits;       bitcoin_data.FloatingIntegerType()
    uint32_t m_timestamp; // timestamp
    uint32_t m_absheight; // absheight
    uint128 m_abswork; // abswork

    // ref_merkle_link
    MerkleLink m_ref_merkle_link;
    // last_txout_nonce
    uint64_t m_last_txout_nonce;
    // hash_link
    HashLinkType m_hash_link;
    // merkle_link
    MerkleLink m_merkle_link;

    NetService peer_addr; // WHERE?

    BaseShare() {}
    BaseShare(const uint256& hash, const uint256& prev_hash) : chain::BaseShare<uint256, Version>(hash, prev_hash) {}

};

struct Share : BaseShare<17>
{
    uint160 m_pubkey_hash;
    std::optional<SegwitData> m_segwit_data;
    ltc::ShareTxInfo m_tx_info; // new_transaction_hashes; transaction_hash_refs

    Share() {}
    Share(const uint256& hash, const uint256& prev_hash) : BaseShare<17>(hash, prev_hash) {}

};

struct Formatter
{
    SHARE_FORMATTER()
    {
    // share_info_type:
        READWRITE(
            obj->m_prev_hash,
            obj->m_coinbase,
            obj->m_nonce
        );
        
        if constexpr (version >= 34)
        {
            // TODO: address
        } else
        {
            READWRITE(obj->m_pubkey_hash); // pubkey_hash
        }

        READWRITE(
            obj->m_subsidy,
            obj->m_donation,
            Using<EnumType<IntType<8>>>(obj->m_stale_info),
            VarInt(obj->m_desired_version)
        );

        if constexpr (is_segwit_activated(version))
        {
            READWRITE(Optional(obj->m_segwit_data, SegwitDataDefault));
        }

        if constexpr (version < 34)
        {
            READWRITE(obj->m_tx_info);
        }

        READWRITE(
            obj->m_far_share_hash,
            obj->m_max_bits,
            obj->m_bits,
            obj->m_timestamp,
            obj->m_absheight,
            obj->m_abswork
        );

    // ref_merkle_link
        READWRITE(
            MERKLE_LINK_SMALL(obj->m_ref_merkle_link)
        );
    // last_txout_nonce
        READWRITE(obj->m_last_txout_nonce);
    // hash_link
        READWRITE(obj->m_hash_link);
    // merkle_link
        READWRITE(
            MERKLE_LINK_SMALL(obj->m_merkle_link)
        );
    }
};

using ShareType = chain::ShareVariants<Formatter, Share>;

template <typename StreamType>
inline ShareType load(int64_t version, StreamType& is, NetService peer_addr)
{
    auto share = ShareType::load(version, is);
    share.ACTION({ obj->peer_addr = peer_addr; });
    return share;
}

struct ShareHasher
{
    // this used to call `GetCheapHash()` in uint256, which was later moved; the
    // cheap hash function simply calls ReadLE64() however, so the end result is
    // identical
    size_t operator()(const uint256& hash) const 
    {
        return hash.GetLow64();
    }
};

class ShareIndex : public chain::ShareIndex<uint256, ShareType, ShareHasher, ShareIndex>
{
    using base_index = chain::ShareIndex<uint256, ShareType, ShareHasher, ShareIndex>;

public:
    ShareIndex() : base_index() {}
    template <typename ShareT> ShareIndex(ShareT* share) : base_index(share)
    {

    }

protected:
    void add(ShareIndex* index) override
    {
        // plus
    }

    void sub(ShareIndex* index) override
    {
        // minus
    }
};

struct ShareChain : chain::ShareChain<ShareIndex>
{

};

} // namespace ltc

