// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
//
// bip110::pool::MergedMiningShare — the v36 (decayed-PPLNS + P2SH donation +
// MergedMiningShare-family) share for the BIP-110 wire-genesis sharechain.
//
// This is a v36-GENESIS chain: no v17/v33/v34/v35 legacy share ever exists on
// this wire (decision card #1). So unlike the BTC lane (which carries the whole
// Share/NewShare/SegwitMiningShare/PaddingBugfixShare/MergedMiningShare ladder for
// interop with the live jtoomim/SPB v35 chain), bip110's ShareVariants holds
// MergedMiningShare<36> ONLY, and the Formatter carries only the v36 branch. The
// wire byte-format of the v36 share is IDENTICAL to the BTC lane's MergedMiningShare
// (so a python-fork bip110 lane shares ONE sharechain) EXCEPT the min_header, which
// is Bip110SmallBlockHeaderType (share_types.hpp) — the 164B v2 header minus merkle.

#include "share_types.hpp"
#include "config_pool.hpp"

#include <sharechain/sharechain.hpp>
#include <sharechain/share.hpp>
#include <core/pack_types.hpp>
#include <core/netaddress.hpp>
#include <core/uint256.hpp>
#include <core/target_utils.hpp>

#include <optional>
#include <vector>
#include <chrono>

namespace bip110::pool
{

// Share layout (v36):
//   min_header [Bip110SmallBlockHeaderType — 164B v2 header MINUS merkle]
//   share_info:
//     prev_hash, coinbase, nonce,
//     pubkey_hash[160], pubkey_type[8],
//     subsidy[VarInt], donation[u16], stale_info[enum u8], desired_version[VarInt],
//     segwit_data [Optional, zero-sentinel],
//     merged_addresses [list],
//     far_share_hash, max_bits, bits, timestamp, absheight,
//     abswork [VarInt-encoded],
//     merged_coinbase_info [list], merged_payout_hash,
//   ref_merkle_link, last_txout_nonce, hash_link[V36HashLinkType], merkle_link,
//   message_data [Optional, at END]

struct MergedMiningShare : chain::BaseShare<uint256, 36>
{
    // small block header (v2, minus merkle)
    Bip110SmallBlockHeaderType m_min_header;

    // share_data
    BaseScript m_coinbase;
    uint32_t   m_nonce{0};
    uint160    m_pubkey_hash;
    uint8_t    m_pubkey_type{0};        // 0=P2PKH, 1=P2WPKH, 2=P2SH
    uint64_t   m_subsidy{0};
    uint16_t   m_donation{0};
    StaleInfo  m_stale_info{StaleInfo::none};
    uint64_t   m_desired_version{0};

    std::optional<SegwitData>         m_segwit_data;
    std::vector<MergedAddressEntry>   m_merged_addresses;   // empty = none

    uint256    m_far_share_hash;
    uint32_t   m_max_bits{0};
    uint32_t   m_bits{0};
    uint32_t   m_timestamp{0};
    uint32_t   m_absheight{0};
    uint128    m_abswork{0};

    std::vector<MergedCoinbaseEntry>  m_merged_coinbase_info; // empty = none
    uint256    m_merged_payout_hash;                          // zero = none

    // ref_merkle_link, last_txout_nonce, hash_link, merkle_link
    MerkleLink       m_ref_merkle_link;
    uint64_t         m_last_txout_nonce{0};
    V36HashLinkType  m_hash_link;
    MerkleLink       m_merkle_link;

    BaseScript m_message_data;   // empty = none (serialized at END)

    NetService peer_addr;

    MergedMiningShare() {}
    MergedMiningShare(const uint256& hash, const uint256& prev_hash)
        : chain::BaseShare<uint256, 36>(hash, prev_hash) {}
};

struct Formatter
{
    SHARE_FORMATTER()
    {
        // small_block_header_type (v2 minus merkle)
        READWRITE(obj->m_min_header);

        // share_info_type
        READWRITE(
            obj->m_prev_hash,
            obj->m_coinbase,
            obj->m_nonce
        );

        // v36 address commitment: pubkey_hash[160] + pubkey_type[8]
        READWRITE(obj->m_pubkey_hash);
        READWRITE(obj->m_pubkey_type);

        // v36 subsidy is VarInt-encoded
        READWRITE(VarInt(obj->m_subsidy));

        READWRITE(
            obj->m_donation,
            Using<EnumType<IntType<8>>>(obj->m_stale_info),
            VarInt(obj->m_desired_version)
        );

        // segwit_data — v36 >= SEGWIT_ACTIVATION (4) => always present, zero-sentinel None
        READWRITE(Optional(obj->m_segwit_data, SegwitDataDefault));

        // v36 merged_addresses (after segwit_data, before far_share_hash)
        READWRITE(obj->m_merged_addresses);

        READWRITE(
            obj->m_far_share_hash,
            obj->m_max_bits,
            obj->m_bits,
            obj->m_timestamp,
            obj->m_absheight
        );

        // v36 abswork — VarInt-encoded uint64 stored as uint128
        READWRITE(Using<AbsworkV36Format>(obj->m_abswork));

        // v36 merged_coinbase_info + merged_payout_hash (after abswork)
        READWRITE(obj->m_merged_coinbase_info);
        READWRITE(obj->m_merged_payout_hash);

        // ref_merkle_link
        READWRITE(MERKLE_LINK_SMALL(obj->m_ref_merkle_link));
        // last_txout_nonce
        READWRITE(obj->m_last_txout_nonce);
        // hash_link (V36HashLinkType with VarStr extra_data)
        READWRITE(obj->m_hash_link);
        // merkle_link
        READWRITE(MERKLE_LINK_SMALL(obj->m_merkle_link));

        // v36 message_data (at the END)
        READWRITE(obj->m_message_data);
    }
};

// v36-genesis chain: MergedMiningShare is the ONLY variant that ever exists.
using ShareType = chain::ShareVariants<Formatter, MergedMiningShare>;

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
    size_t operator()(const uint256& hash) const
    {
        return hash.GetLow64();
    }
};

class ShareIndex : public chain::ShareIndex<uint256, ShareType, ShareHasher, ShareIndex>
{
    using base_index = chain::ShareIndex<uint256, ShareType, ShareHasher, ShareIndex>;

public:
    uint288 work;       // target_to_average_attempts(bits)
    uint288 min_work;   // target_to_average_attempts(max_bits)

    int64_t time_seen{0};
    int32_t naughty{0};
    bool    is_block_solution{false};  // pow_hash <= block_target (set during init_verify)
    uint256 pow_hash;                  // BLAKE2b block-identity hash, cached at reception

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

} // namespace bip110::pool
