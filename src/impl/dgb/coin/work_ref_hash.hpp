// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ============================================================================
// work_ref_hash.hpp — prospective-work RefHashParams assembler (SSOT).
//
// The per-connection Stratum coinbase a miner hashes commits, in its OP_RETURN,
// to a p2pool ref_hash for the prospective NEXT share. That ref_hash is produced
// by dgb::compute_ref_hash_for_work() (share_check.hpp) — the EXACT primitive
// the share verifier uses — which takes a dgb::RefHashParams. Until now every
// caller had to hand-populate that ~25-field struct, duplicating, field for
// field, how share_check.hpp create_local_share() / create_local_share_v35()
// populate the ref preimage: the same payout-script -> (pubkey_hash, pubkey_type)
// classification, the same V35 address derivation, the same V36-vs-V35
// conditionals on version_gate::is_v36_active. Two hand-rolled copies of that
// mapping is exactly the kind of drift a Stratum-emitted OP_RETURN cannot
// survive (a 1-field divergence -> a ref the verifier never reproduces).
//
// make_work_ref_hash_params() is the single tracker-free assembler that lifts
// that field-for-field mapping out of create_local_share() so the per-connection
// coinbase producer can DELEGATE to it instead of re-deriving the fields. It
// adds NO new consensus decisions: every field is forwarded from a caller-
// supplied snapshot, and every conditional is a verbatim copy of the mint path.
//
// Sources, field by field (share_check.hpp anchors):
//   * payout-identity classification (P2PKH=0 / P2WPKH=1 / P2SH=2 / fallback):
//     create_local_share() and create_local_share_v35(). Identical byte tests;
//     lifted verbatim into classify_payout_identity() below.
//   * V35 address (VarStr) := pubkey_hash_to_address(pubkey_hash, type, params):
//     create_local_share_v35().
//   * V36 carries pubkey_hash+pubkey_type+VarInt(subsidy)+merged_addresses+
//     AbsworkV36Format(abswork)+merged_coinbase_info+merged_payout_hash+
//     message_data; V35 carries address+fixed-uint64 subsidy+fixed-uint128
//     abswork and NONE of the merged/message fields. The conditionals live in
//     compute_ref_hash_for_work() itself (is_v36_active()/>=34 branches), so the
//     assembled params produce the verifier ref_hash by construction.
//
// Tracker-free: the caller does the lock-safe tracker walk (absheight / abswork
// / far_share_hash / timestamp-clip / merged_payout_hash, and the FROZEN
// template-time values) off the work-gen thread and passes the resolved
// snapshot in. This header only assembles + forwards.
//
// Pure header-only; KAT'd against the verifier ref_hash in
// test/share_test.cpp (WorkRefHashAssembler.*).
// ============================================================================

#include <impl/dgb/share_check.hpp>   // dgb::RefHashParams, compute_ref_hash_for_work,
                                       // pubkey_hash_to_address, SegwitData, version_gate
#include <impl/dgb/share_types.hpp>   // SegwitData, MergedAddressEntry, MergedCoinbaseEntry

#include <core/coin_params.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

namespace dgb::coin
{

// Resolved payout identity for the ref preimage. A verbatim lift of the
// scriptPubKey classification in create_local_share() / create_local_share_v35()
// (P2PKH 25B 76a914..88ac -> 0; P2SH 23B a914..87 -> 2; P2WPKH 22B 0014.. -> 1;
// else first-20-bytes fallback -> 0). The byte tests and the 20-byte source
// offsets are identical to both mint paths.
struct PayoutIdentity
{
    uint160 pubkey_hash;
    uint8_t pubkey_type{0};
};

inline PayoutIdentity classify_payout_identity(
    const std::vector<unsigned char>& payout_script)
{
    PayoutIdentity id;
    id.pubkey_hash.SetNull();
    id.pubkey_type = 0;

    if (payout_script.size() >= 20) {
        if (payout_script.size() == 25 &&
            payout_script[0] == 0x76 && payout_script[1] == 0xa9 &&
            payout_script[2] == 0x14 && payout_script[23] == 0x88 &&
            payout_script[24] == 0xac) {
            // P2PKH: 76 a9 14 <hash160> 88 ac
            std::memcpy(id.pubkey_hash.data(), payout_script.data() + 3, 20);
            id.pubkey_type = 0;
        } else if (payout_script.size() == 23 &&
                   payout_script[0] == 0xa9 && payout_script[1] == 0x14 &&
                   payout_script[22] == 0x87) {
            // P2SH: a9 14 <hash160> 87
            std::memcpy(id.pubkey_hash.data(), payout_script.data() + 2, 20);
            id.pubkey_type = 2;
        } else if (payout_script.size() == 22 &&
                   payout_script[0] == 0x00 && payout_script[1] == 0x14) {
            // P2WPKH: 00 14 <witness_program> (raw bytes, no LE reversal)
            std::memcpy(id.pubkey_hash.data(), payout_script.data() + 2, 20);
            id.pubkey_type = 1;
        } else {
            // Fallback: first 20 bytes as P2PKH
            std::memcpy(id.pubkey_hash.data(), payout_script.data(), 20);
            id.pubkey_type = 0;
        }
    }
    return id;
}

// Prospective-work snapshot for one connection's NEXT share. Every field is the
// SAME value create_local_share() writes into the share before serialising the
// ref preimage — resolved upstream by the caller (lock-safe tracker walk +
// template-time freeze). No tracker/chain handle here.
struct WorkRefHashInputs
{
    int64_t  share_version{36};                 // 35 or 36 (selects ref format)
    uint64_t desired_version{36};

    uint256  prev_share;
    std::vector<unsigned char> coinbase_scriptSig; // share.m_coinbase.m_data
    uint32_t share_nonce{0};                       // share.m_nonce

    std::vector<unsigned char> payout_script;      // scriptPubKey -> identity/address
    uint64_t subsidy{0};
    uint16_t donation{50};
    uint8_t  stale_info{0};

    // Segwit field: PossiblyNoneType in p2pool — when has_segwit is false the
    // ref preimage still carries the (empty branch, zero root) placeholder for
    // ver >= SEGWIT_ACTIVATION_VERSION (see compute_ref_hash_for_work()).
    bool       has_segwit{false};
    SegwitData segwit_data;

    // V36-only fields (ignored on V35 by the ref format conditionals).
    std::vector<MergedAddressEntry>  merged_addresses;
    std::vector<MergedCoinbaseEntry> merged_coinbase_info;
    uint256  merged_payout_hash;
    BaseScript message_data;                       // PossiblyNoneType(b'', VarStr)

    // Chain-position snapshot (FROZEN at template time by the caller).
    uint256  far_share_hash;
    uint32_t max_bits{0};
    uint32_t bits{0};
    uint32_t timestamp{0};
    uint32_t absheight{0};
    uint128  abswork;
};

// Assemble a complete dgb::RefHashParams for the prospective share. Field for
// field this matches what create_local_share() / create_local_share_v35() feed
// into the ref preimage; the V36/V35 split is handled by
// compute_ref_hash_for_work()'s own conditionals, so we populate BOTH the
// (pubkey_hash, pubkey_type) and the V35 address: the unused one is simply not
// serialised for that version. The returned params, passed to
// compute_ref_hash_for_work(), reproduce the verifier ref_hash bit-for-bit.
inline RefHashParams make_work_ref_hash_params(
    const WorkRefHashInputs& in, const core::CoinParams& params)
{
    RefHashParams p;
    p.share_version       = in.share_version;
    p.desired_version     = in.desired_version;
    p.prev_share          = in.prev_share;
    p.coinbase_scriptSig  = in.coinbase_scriptSig;
    p.share_nonce         = in.share_nonce;
    p.subsidy             = in.subsidy;
    p.donation            = in.donation;
    p.stale_info          = in.stale_info;

    const auto id = classify_payout_identity(in.payout_script);
    p.pubkey_hash         = id.pubkey_hash;
    p.pubkey_type         = id.pubkey_type;
    // V35 ref preimage uses the address string (VarStr) instead of pubkey_hash;
    // derive it the same way create_local_share_v35() does so the V35 ref_hash
    // matches. Harmless on V36 (not serialised there).
    {
        std::string addr = pubkey_hash_to_address(id.pubkey_hash, id.pubkey_type, params);
        p.address.assign(addr.begin(), addr.end());
    }

    p.has_segwit          = in.has_segwit;
    p.segwit_data         = in.segwit_data;

    p.merged_addresses    = in.merged_addresses;
    p.merged_coinbase_info= in.merged_coinbase_info;
    p.merged_payout_hash  = in.merged_payout_hash;
    p.message_data        = in.message_data;

    p.far_share_hash      = in.far_share_hash;
    p.max_bits            = in.max_bits;
    p.bits                = in.bits;
    p.timestamp           = in.timestamp;
    p.absheight           = in.absheight;
    p.abswork             = in.abswork;

    return p;
}

} // namespace dgb::coin