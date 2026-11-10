// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include "coin/block.hpp"
#include "share_types.hpp"

#include <sharechain/sharechain.hpp>
#include <sharechain/share.hpp>
#include <core/pack_types.hpp>
#include <core/netaddress.hpp>
#include <core/uint256.hpp>
#include <core/target_utils.hpp>

#include <map>
#include <vector>
#include <chrono>

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
    coin::SmallBlockHeaderType m_min_header;
    // prev_hash
    BaseScript m_coinbase;              // coinbase
    uint32_t m_nonce{0};                // nonce
    // [x]address[>=34] or [x]pubkey_hash[<34]
    uint64_t m_subsidy{0};              // subsidy
    uint16_t m_donation{0};             // donation
    ltc::StaleInfo m_stale_info{ltc::StaleInfo::none}; // stale_info
    uint64_t m_desired_version{0};      // desired_version
    //
    // [x] segwit_data [if segwit_activated]
    //
    uint256 m_far_share_hash;           // far_share_hash
    uint32_t m_max_bits{0};             // max_bits;   bitcoin_data.FloatingIntegerType()
    uint32_t m_bits{0};                 // bits;       bitcoin_data.FloatingIntegerType()
    uint32_t m_timestamp{0};            // timestamp
    uint32_t m_absheight{0};            // absheight
    uint128 m_abswork;                  // abswork

    // ref_merkle_link
    MerkleLink m_ref_merkle_link;
    // last_txout_nonce
    uint64_t m_last_txout_nonce{0};
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

struct NewShare : BaseShare<33>
{
    uint160 m_pubkey_hash;
    std::optional<SegwitData> m_segwit_data;
    ltc::ShareTxInfo m_tx_info; // new_transaction_hashes; transaction_hash_refs

    NewShare() {}
    NewShare(const uint256& hash, const uint256& prev_hash) : BaseShare<33>(hash, prev_hash) {}
};

namespace types
{

struct DataSegwitShare
{
    BaseScript m_address; // Todo (check): VarStrType
    std::optional<SegwitData> m_segwit_data;
};

} // namespace types

struct SegwitMiningShare : BaseShare<34>, types::DataSegwitShare
{
    SegwitMiningShare() {}
    SegwitMiningShare(const uint256& hash, const uint256& prev_hash) : BaseShare<34>(hash, prev_hash) {}
};

struct PaddingBugfixShare : BaseShare<35>, types::DataSegwitShare
{
    PaddingBugfixShare() {}
    PaddingBugfixShare(const uint256& hash, const uint256& prev_hash) : BaseShare<35>(hash, prev_hash) {}
};

// The V36 share and its flag-day successor, share version 3601
// (FLAG_DAY_SHARE_VERSION): the same fields and the same wire bytes; only the
// type number of the share message differs. A share whose timestamp is at or
// after the flag day (PoolConfig::v3601_activation_time()) must be a 3601
// share and one before it must not (share_check.hpp flag_day_problem); 3601
// shares resolve their merged payouts by the per-share rule
// (share_tracker.hpp merged_weights_delta). Neither the share hash nor its
// generation transaction commits to the type number, so the flag-day rule is
// what binds a share to exactly one of the two.
inline constexpr int64_t FLAG_DAY_SHARE_VERSION = 3601;

template <int64_t V>
struct MergedMiningShareT : BaseShare<V>
{
    uint160 m_pubkey_hash;
    uint8_t m_pubkey_type{0};                                    // 0=P2PKH, 1=P2WPKH, 2=P2SH
    std::optional<SegwitData> m_segwit_data;
    std::vector<MergedAddressEntry> m_merged_addresses;          // empty = none
    std::vector<MergedCoinbaseEntry> m_merged_coinbase_info;     // empty = none
    uint256 m_merged_payout_hash;                                // zero = none
    V36HashLinkType m_hash_link;                                 // shadows BaseShare::m_hash_link
    BaseScript m_message_data;                                   // empty = none

    MergedMiningShareT() {}
    MergedMiningShareT(const uint256& hash, const uint256& prev_hash) : BaseShare<V>(hash, prev_hash) {}

    // The same share under the other type number (36 <-> 3601): every field,
    // wire and transient (merged_aux_hardening_test.cpp checks the bytes).
    template <int64_t W>
        requires(W != V)
    explicit MergedMiningShareT(const MergedMiningShareT<W>& o) : BaseShare<V>(o.m_hash, o.m_prev_hash)
    {
        this->m_pow_hash = o.m_pow_hash;
        this->m_min_header = o.m_min_header;
        this->m_coinbase = o.m_coinbase;
        this->m_nonce = o.m_nonce;
        this->m_subsidy = o.m_subsidy;
        this->m_donation = o.m_donation;
        this->m_stale_info = o.m_stale_info;
        this->m_desired_version = o.m_desired_version;
        this->m_far_share_hash = o.m_far_share_hash;
        this->m_max_bits = o.m_max_bits;
        this->m_bits = o.m_bits;
        this->m_timestamp = o.m_timestamp;
        this->m_absheight = o.m_absheight;
        this->m_abswork = o.m_abswork;
        this->m_ref_merkle_link = o.m_ref_merkle_link;
        this->m_last_txout_nonce = o.m_last_txout_nonce;
        static_cast<BaseShare<V>&>(*this).m_hash_link = static_cast<const BaseShare<W>&>(o).m_hash_link;
        this->m_merkle_link = o.m_merkle_link;
        this->peer_addr = o.peer_addr;
        m_pubkey_hash = o.m_pubkey_hash;
        m_pubkey_type = o.m_pubkey_type;
        m_segwit_data = o.m_segwit_data;
        m_merged_addresses = o.m_merged_addresses;
        m_merged_coinbase_info = o.m_merged_coinbase_info;
        m_merged_payout_hash = o.m_merged_payout_hash;
        m_hash_link = o.m_hash_link;
        m_message_data = o.m_message_data;
    }
};

using MergedMiningShare = MergedMiningShareT<36>;
using MergedMiningShareV3601 = MergedMiningShareT<FLAG_DAY_SHARE_VERSION>;

struct Formatter
{
    SHARE_FORMATTER()
    {
    // small_block_header_type:
        READWRITE(obj->m_min_header);
    // share_info_type:
        READWRITE(
            obj->m_prev_hash,
            obj->m_coinbase,
            obj->m_nonce
        );
        
        // Address handling — version-dependent
        if constexpr (version >= 36)
        {
            READWRITE(obj->m_pubkey_hash);   // IntType(160)
            READWRITE(obj->m_pubkey_type);   // IntType(8)
        }
        else if constexpr (version >= 34)
        {
            READWRITE(obj->m_address);
        }
        else
        {
            READWRITE(obj->m_pubkey_hash);   // pubkey_hash
        }

        // Subsidy — V36 uses VarInt, others use fixed uint64
        if constexpr (version >= 36)
        {
            READWRITE(VarInt(obj->m_subsidy));
        }
        else
        {
            READWRITE(obj->m_subsidy);
        }

        READWRITE(
            obj->m_donation,
            Using<EnumType<IntType<8>>>(obj->m_stale_info),
            VarInt(obj->m_desired_version)
        );

        if constexpr (is_segwit_activated(version))
        {
            READWRITE(Optional(obj->m_segwit_data, SegwitDataDefault));
        }

        // V36: merged_addresses (after segwit_data, before far_share_hash)
        if constexpr (version >= 36)
        {
            READWRITE(obj->m_merged_addresses);
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
            obj->m_absheight
        );

        // Abswork — V36 uses VarInt-encoded uint64, others use fixed uint128
        if constexpr (version >= 36)
        {
            READWRITE(Using<AbsworkV36Format>(obj->m_abswork));
        }
        else
        {
            READWRITE(obj->m_abswork);
        }

        // V36: merged_coinbase_info + merged_payout_hash (after abswork)
        if constexpr (version >= 36)
        {
            READWRITE(obj->m_merged_coinbase_info);
            READWRITE(obj->m_merged_payout_hash);
        }

    // ref_merkle_link
        READWRITE(
            MERKLE_LINK_SMALL(obj->m_ref_merkle_link)
        );
    // last_txout_nonce
        READWRITE(obj->m_last_txout_nonce);
    // hash_link (V36: V36HashLinkType with extra_data; others: HashLinkType)
        READWRITE(obj->m_hash_link);
    // merkle_link
        READWRITE(
            MERKLE_LINK_SMALL(obj->m_merkle_link)
        );

        // V36: message_data (at the end)
        if constexpr (version >= 36)
        {
            READWRITE(obj->m_message_data);
        }
    }
};

using ShareType = chain::ShareVariants<Formatter, Share, NewShare, SegwitMiningShare, PaddingBugfixShare, MergedMiningShare,
                                        MergedMiningShareV3601>;

inline ShareType load_share(chain::RawShare& rshare, NetService peer_addr)
{
    auto stream = rshare.contents.as_stream();
    auto share = ShareType::load(rshare.type, stream);
    share.ACTION({ obj->peer_addr = peer_addr; });
    return share;
}

template <typename StreamType>
inline ShareType load_share(int64_t version, StreamType& is, NetService peer_addr)
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
    // Per-share fields (NOT accumulated — each share stores only its own values).
    // Accumulated values are computed on-the-fly by walking m_shares[tail].
    uint288 work;       // target_to_average_attempts(bits)
    uint288 min_work;   // target_to_average_attempts(max_bits)

    // Per-share metadata
    int64_t time_seen{0};
    int32_t naughty{0};
    bool is_block_solution{false};  // pow_hash <= block_target (set during init_verify)
    uint256 pow_hash;               // scrypt hash, cached at reception (for block scan)

    ShareIndex() : base_index(), work(0), min_work(0) {}

    template <typename ShareT> ShareIndex(ShareT* share) : base_index(share)
    {
        work = chain::target_to_average_attempts(chain::bits_to_target(share->m_bits));
        min_work = chain::target_to_average_attempts(chain::bits_to_target(share->m_max_bits));
        time_seen = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
};

struct ShareChain : chain::ShareChain<ShareIndex>
{

};

} // namespace ltc