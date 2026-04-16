#pragma once

// Dash p2pool Share v16.
// Reference: ref/p2pool-dash/p2pool/data.py Share class (lines 68-127)

#include "share_types.hpp"
#include <impl/bitcoin_family/coin/base_block.hpp>
#include <sharechain/share.hpp>

#include <core/uint256.hpp>
#include <core/pack_types.hpp>

#include <optional>
#include <string>
#include <vector>

namespace dash
{

// Dash Share v16 — inherits from BaseShare<uint256, 16>
// Wire format: [VarInt type=16][VarStr packed_contents]
struct DashShare : chain::BaseShare<uint256, 16>
{
    // === min_header (SmallBlockHeaderType) ===
    bitcoin_family::coin::SmallBlockHeaderType m_min_header;

    // === share_data ===
    uint256 m_prev_hash;            // previous_share_hash (PossiblyNone)
    BaseScript m_coinbase;          // VarStr, 2-100 bytes
    BaseScript m_coinbase_payload;  // PossiblyNone('', VarStr) — DIP3/DIP4 CBTX
    uint32_t m_nonce{0};            // share nonce (not block nonce)
    uint160 m_pubkey_hash;          // miner's pubkey hash
    uint64_t m_subsidy{0};          // block reward
    uint16_t m_donation{0};         // donation percentage (bps)
    StaleInfo m_stale_info{StaleInfo::none};
    uint64_t m_desired_version{16};
    uint64_t m_payment_amount{0};   // total masternode payment amount
    std::vector<PackedPayment> m_packed_payments; // masternode/superblock/platform

    // === share_info (non-share_data fields) ===
    std::vector<uint256> m_new_transaction_hashes;
    std::vector<uint64_t> m_transaction_hash_refs; // pairs: [share_count, tx_count]
    uint256 m_far_share_hash;       // PossiblyNone
    uint32_t m_max_bits{0};
    uint32_t m_bits{0};
    uint32_t m_timestamp{0};
    uint32_t m_absheight{0};
    uint128 m_abswork;

    // === Remaining share fields ===
    MerkleLink m_ref_merkle_link;
    uint64_t m_last_txout_nonce{0};
    HashLinkType m_hash_link;
    MerkleLink m_merkle_link;
    BaseScript m_coinbase_payload_outer; // PossiblyNone('', VarStr) — outer coinbase_payload

    // Identity hash (computed, not serialized)
    uint256 m_hash;
};

} // namespace dash
