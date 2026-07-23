// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Dash p2pool Share v16.
// Reference: ref/p2pool-dash/p2pool/data.py Share class (lines 68-127)

#include "share_types.hpp"
#include <impl/bitcoin_family/coin/base_block.hpp>
#include <sharechain/share.hpp>

#include <core/netaddress.hpp>
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
    // Outer coinbase_payload — PossiblyNone('', VarStr) on the wire. The VALUE
    // is the oracle's coinbase_payload_data = VarStrType().pack(raw_payload)
    // (data.py:277-289), i.e. m_data holds [compactsize(len raw)][raw], NOT the
    // bare payload; Share.__init__ appends it verbatim to the hash_link data.
    BaseScript m_coinbase_payload_outer;

    // Identity hash (computed, not serialized)
    uint256 m_hash;

    // Ingestion metadata — the peer we learned this share from. Not part
    // of the on-wire format; populated in load_share so the dashboard /
    // audit trail can show which peer gossiped each share (matches LTC
    // share.hpp's NetService peer_addr field).
    NetService peer_addr;
};

// ═══════════════════════════════════════════════════════════════════════════
// DASH v36 share (wire-type 36) — PHASE A: DEFINED + PARSEABLE, DORMANT.
//
// Byte-standardized to the cross-coin v36 share shape (the v36-standardize-for-
// v37 goal: uniform structs). The STANDARDIZED PREFIX (min_header .. message_data)
// is byte-for-byte the NON-SEGWIT v36 layout — i.e. the BCH v36 MergedMiningShare
// shape (src/impl/bch/share.hpp), which is the LTC/DGB v36 layout MINUS the
// Optional(segwit_data) slot. BCH is the reference here (not LTC/DGB directly)
// because DASH, like BCH, is non-segwit: BCH's SEGWIT_ACTIVATION_VERSION==0 makes
// is_segwit_activated(36) false, so a non-segwit v36 coin OMITS segwit_data. This
// is the ESTABLISHED cross-coin convention, NOT a DASH divergence.
//
// Field categories (operator 3-bucket / v36-standardize model):
//   * SHARED / STANDARDIZED (Bucket-2, byte-identical cross-coin): min_header,
//     prev_hash, coinbase, nonce, pubkey_hash + pubkey_type, subsidy(VarInt),
//     donation, stale_info, desired_version(VarInt) [THE version-vote], the merged
//     fields (merged_addresses / merged_coinbase_info / merged_payout_hash — held
//     EMPTY/INERT since DASH is standalone X11 with no AuxPoW child, exactly as a
//     non-merged ltc/dgb/bch coin populates them), far_share_hash, max_bits, bits,
//     timestamp, absheight, abswork(AbsworkV36Format), ref_merkle_link,
//     last_txout_nonce, hash_link(V36HashLinkType), merkle_link, message_data.
//   * DASH-SPECIFIC SUFFIX (Bucket-3 / coin-specific, the FLAGGED divergence):
//     coinbase_payload, payment_amount, packed_payments, coinbase_payload_outer.
//     DASH masternode / DIP4-CbTx consensus data with NO cross-coin equivalent;
//     required so Phase C can reconstruct+verify a real DASH coinbase from the
//     share (a non-merged coin has no analogue). Appended AFTER the standardized
//     message_data so the ENTIRE standardized prefix stays byte-identical to
//     bch/ltc/dgb. See the design note + PR body for the review decision.
//
// The version-vote (m_desired_version) is what #774's AutoRatchet reads to
// activate; Phase A only DEFINES this type (dormant, unminted). current_share_version
// stays 16, so nothing mints a v36 share and the live 1700 accept path is
// byte-unchanged (Phase C flips activation via the ratchet, NOT here).
struct DashV36Share : chain::BaseShare<uint256, 36>
{
    // ── min_header (SmallBlockHeaderType — coin block header, standardized) ──
    bitcoin_family::coin::SmallBlockHeaderType m_min_header;

    // ── share_data (STANDARDIZED v36) ──
    // NOTE: m_prev_hash is inherited from chain::BaseShare<uint256,36>.
    BaseScript m_coinbase;          // coinbase scriptSig (VarStr)
    uint32_t m_nonce{0};            // share nonce
    uint160 m_pubkey_hash;          // v36 address (IntType(160))
    uint8_t m_pubkey_type{0};       // v36: 0=P2PKH, 1=P2WPKH, 2=P2SH (DASH always 0/P2PKH)
    uint64_t m_subsidy{0};          // v36: VarInt-encoded
    uint16_t m_donation{0};         // donation (bps)
    StaleInfo m_stale_info{StaleInfo::none};
    uint64_t m_desired_version{36}; // THE version-vote (VarInt)

    // v36 merged-mining address entries — EMPTY/INERT on DASH (no AuxPoW child).
    std::vector<v36::MergedAddressEntry> m_merged_addresses;

    // ── share_info (non-share_data, STANDARDIZED v36) ──
    uint256 m_far_share_hash;
    uint32_t m_max_bits{0};
    uint32_t m_bits{0};
    uint32_t m_timestamp{0};
    uint32_t m_absheight{0};
    uint128 m_abswork;              // v36: AbsworkV36Format (VarInt low64) on the wire

    // v36 merged-mining coinbase verification — EMPTY/INERT on DASH.
    std::vector<v36::MergedCoinbaseEntry> m_merged_coinbase_info;
    uint256 m_merged_payout_hash;   // zero = none (INERT on DASH)

    // ── remaining STANDARDIZED v36 share fields ──
    v36::MerkleLink m_ref_merkle_link;
    uint64_t m_last_txout_nonce{0};
    v36::V36HashLinkType m_hash_link;   // v36: state + extra_data(VarStr) + length(VarInt)
    v36::MerkleLink m_merkle_link;
    BaseScript m_message_data;          // v36 messaging hook — EMPTY on DASH in Phase A (Phase B)

    // ── DASH-SPECIFIC SUFFIX (FLAGGED divergence — see struct header) ──
    BaseScript m_coinbase_payload;          // DIP3/DIP4 CBTX inner (PossiblyNone '', VarStr)
    uint64_t m_payment_amount{0};           // total masternode payment amount
    std::vector<PackedPayment> m_packed_payments; // masternode/superblock/platform
    BaseScript m_coinbase_payload_outer;    // outer coinbase_payload_data (appended to hash_link)

    // ── carried-but-UNSERIALIZED members (v36 wire omits tx_info; kept so a
    //    future promotion into the live variant matches DashShare's field
    //    surface for the shared generic-invoke call sites in node.cpp) ──
    std::vector<uint256> m_new_transaction_hashes;
    std::vector<uint64_t> m_transaction_hash_refs;

    // Ingestion metadata — not on the wire (parity with DashShare::peer_addr).
    NetService peer_addr;

    DashV36Share() {}
    DashV36Share(const uint256& hash, const uint256& prev_hash)
        : chain::BaseShare<uint256, 36>(hash, prev_hash) {}
};

} // namespace dash