// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Dash share chain types: ShareType variant, ShareIndex, ShareChain.
// Uses the generic sharechain infrastructure from c2pool/sharechain/.
// Only v16 shares exist for Dash.

#include "share.hpp"
#include "share_types.hpp"

#include <sharechain/share.hpp>
#include <sharechain/sharechain.hpp>
#include <core/target_utils.hpp>
#include <core/version_gate.hpp>   // SSOT: core::version_gate::is_v36_active

#include <chrono>

namespace dash
{

// DoS-cap for resize() inputs read from the wire as VarInt(uint64_t), which
// uses ReadCompactSize(false) (range_check disabled — see core/pack_types.hpp).
// A malformed peer can send a 9-byte VarInt of UINT64_MAX, and an unguarded
// resize() then throws std::length_error("vector::_M_default_append") and
// kills the process via the top-level catch in main_dash.cpp:4453. Cap to
// values comfortably above any legitimate share but well below allocator
// max_size — exceeding the cap throws ios_base::failure, which the share
// parser catches cleanly without process exit.
//
// MAX_PAYMENTS_PER_SHARE: legitimate shares carry one entry per payee in
// the PPLNS window plus MN payouts. Real-world: ~10-50. Cap: 10000.
//
// MAX_TX_HASH_REF_PAIRS: one pair per non-coinbase tx in the block. A Dash
// block holds ~few hundred tx; even worst-case dust is ~10000. Cap: 100000.
inline constexpr uint64_t MAX_PAYMENTS_PER_SHARE   = 10000;
inline constexpr uint64_t MAX_TX_HASH_REF_PAIRS    = 100000;

// ── Formatter for v16 share serialization ────────────────────────────────────

struct DashFormatter
{
    // Full v16 share wire deserialization.
    // Reference: ref/p2pool-dash/p2pool/data.py Share.share_type (lines 108-122)
    //
    // Wire order:
    //   min_header (SmallBlockHeaderType)
    //   share_info { share_data { prev_hash, coinbase, coinbase_payload, nonce,
    //     pubkey_hash, subsidy, donation, stale_info, desired_version,
    //     payment_amount, packed_payments },
    //     new_tx_hashes, tx_hash_refs, far_share_hash,
    //     max_bits, bits, timestamp, absheight, abswork }
    //   ref_merkle_link { branch, index(0-width) }
    //   last_txout_nonce
    //   hash_link { state, extra_data, length }
    //   merkle_link { branch, index(0-width) }
    //   coinbase_payload (outer, PossiblyNone)

    template <typename StreamType, typename ShareT>
    static void Read(StreamType& is, ShareT* share)
    {
        // V36 shares (wire-type 36, dash::DashV36Share) use the standardized
        // cross-coin v36 layout. Compile-time dispatch: the v16 body below is
        // instantiated ONLY for DashShare (version 16), so it stays byte-
        // unchanged; the v36 body is instantiated ONLY for DashV36Share.
        if constexpr (core::version_gate::is_v36_active(ShareT::version))
        {
            ReadV36(is, share);
            return;
        }
        else
        {
        // ── min_header ──
        is >> share->m_min_header;

        // ── share_data ──
        is >> share->m_prev_hash;           // PossiblyNone(0, IntType(256))
        is >> share->m_coinbase;            // VarStr
        is >> share->m_coinbase_payload;    // PossiblyNone('', VarStr)
        is >> share->m_nonce;               // uint32
        is >> share->m_pubkey_hash;         // uint160
        is >> share->m_subsidy;             // uint64
        is >> share->m_donation;            // uint16
        {
            uint8_t si;
            is >> si;
            share->m_stale_info = static_cast<dash::StaleInfo>(si);
        }
        { uint64_t dv; ::Unserialize(is, VarInt(dv)); share->m_desired_version = dv; }
        is >> share->m_payment_amount;      // uint64

        // packed_payments: ListType(ComposedType([payee(PossiblyNone VarStr), amount(PossiblyNone uint64)]))
        {
            uint64_t count;
            ::Unserialize(is, VarInt(count));
            if (count > MAX_PAYMENTS_PER_SHARE) {
                throw std::ios_base::failure("packed_payments count exceeds cap");
            }
            share->m_packed_payments.resize(count);
            for (uint64_t i = 0; i < count; ++i) {
                BaseScript payee_bs;
                is >> payee_bs;
                share->m_packed_payments[i].m_payee.assign(
                    payee_bs.m_data.begin(), payee_bs.m_data.end());
                is >> share->m_packed_payments[i].m_amount;
            }
        }

        // ── share_info (non-share_data) ──
        is >> share->m_new_transaction_hashes;  // ListType(IntType(256))

        // transaction_hash_refs: ListType(VarIntType(), 2) — count of PAIRS, then count*2 VarInts
        {
            uint64_t pair_count;
            ::Unserialize(is, VarInt(pair_count));
            if (pair_count > MAX_TX_HASH_REF_PAIRS) {
                throw std::ios_base::failure("tx_hash_refs pair_count exceeds cap");
            }
            // pair_count is now <= MAX_TX_HASH_REF_PAIRS, so * 2 cannot overflow.
            share->m_transaction_hash_refs.resize(pair_count * 2);
            for (uint64_t i = 0; i < pair_count * 2; ++i) {
                uint64_t v;
                ::Unserialize(is, VarInt(v));
                share->m_transaction_hash_refs[i] = v;
            }
        }

        is >> share->m_far_share_hash;      // PossiblyNone(0, IntType(256))
        is >> share->m_max_bits;            // FloatingInteger (uint32)
        is >> share->m_bits;                // FloatingInteger (uint32)
        is >> share->m_timestamp;           // uint32
        is >> share->m_absheight;           // uint32
        is >> share->m_abswork;             // uint128

        // ── ref_merkle_link ──
        is >> share->m_ref_merkle_link.m_branch;  // ListType(IntType(256))
        // index is IntType(0) — zero-width, not serialized, always 0
        share->m_ref_merkle_link.m_index = 0;

        // ── last_txout_nonce ──
        is >> share->m_last_txout_nonce;    // uint64

        // ── hash_link ──
        is >> share->m_hash_link;           // {state(FixedStr32), extra_data(VarStr), length(VarInt)}

        // ── merkle_link ──
        is >> share->m_merkle_link.m_branch;
        share->m_merkle_link.m_index = 0;   // IntType(0) — always 0

        // ── coinbase_payload (outer) ──
        is >> share->m_coinbase_payload_outer;  // PossiblyNone('', VarStr)
        } // else (v16)
    }

    template <typename StreamType, typename ShareT>
    static void Write(StreamType& os, const ShareT* share)
    {
        if constexpr (core::version_gate::is_v36_active(ShareT::version))
        {
            WriteV36(os, share);
            return;
        }
        else
        {
        os << share->m_min_header;
        os << share->m_prev_hash;
        os << share->m_coinbase;
        os << share->m_coinbase_payload;
        os << share->m_nonce;
        os << share->m_pubkey_hash;
        os << share->m_subsidy;
        os << share->m_donation;
        { uint8_t si = static_cast<uint8_t>(share->m_stale_info); os << si; }
        ::Serialize(os, VarInt(share->m_desired_version));
        os << share->m_payment_amount;
        {
            uint64_t count = share->m_packed_payments.size();
            ::Serialize(os, VarInt(count));
            for (auto& pay : share->m_packed_payments) {
                BaseScript bs;
                bs.m_data.assign(pay.m_payee.begin(), pay.m_payee.end());
                os << bs;
                os << pay.m_amount;
            }
        }
        os << share->m_new_transaction_hashes;
        {
            uint64_t pair_count = share->m_transaction_hash_refs.size() / 2;
            ::Serialize(os, VarInt(pair_count));
            for (auto& v : share->m_transaction_hash_refs)
                ::Serialize(os, VarInt(v));
        }
        os << share->m_far_share_hash;
        os << share->m_max_bits;
        os << share->m_bits;
        os << share->m_timestamp;
        os << share->m_absheight;
        os << share->m_abswork;
        os << share->m_ref_merkle_link.m_branch;
        os << share->m_last_txout_nonce;
        os << share->m_hash_link;
        os << share->m_merkle_link.m_branch;
        os << share->m_coinbase_payload_outer;
        } // else (v16)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // V36 (wire-type 36) read/write — STANDARDIZED cross-coin non-segwit v36
    // layout (the bch/ltc/dgb MergedMiningShare shape MINUS segwit_data) plus
    // the DASH-specific suffix. Field ORDER and ENCODINGS mirror the BCH v36
    // Formatter (src/impl/bch/share.hpp) byte-for-byte for the standardized
    // prefix; the suffix (coinbase_payload / payment_amount / packed_payments /
    // coinbase_payload_outer) rides AFTER message_data. Pinned by the byte-
    // parity + round-trip KATs in test/test_dash_v36_share.cpp.
    // ═══════════════════════════════════════════════════════════════════════
    template <typename StreamType, typename ShareT>
    static void ReadV36(StreamType& is, ShareT* share)
    {
        // ── min_header ──
        is >> share->m_min_header;

        // ── share_data (standardized v36) ──
        is >> share->m_prev_hash;           // PossiblyNone(0, IntType(256))
        is >> share->m_coinbase;            // VarStr
        is >> share->m_nonce;               // uint32
        is >> share->m_pubkey_hash;         // v36 address: IntType(160)
        is >> share->m_pubkey_type;         // v36: IntType(8)
        { uint64_t sub; ::Unserialize(is, VarInt(sub)); share->m_subsidy = sub; } // v36: VarInt
        is >> share->m_donation;            // uint16
        { uint8_t si; is >> si; share->m_stale_info = static_cast<dash::StaleInfo>(si); }
        { uint64_t dv; ::Unserialize(is, VarInt(dv)); share->m_desired_version = dv; } // version-vote

        // NO segwit_data (non-segwit coin — BCH convention).

        // v36 merged_addresses (empty/inert on DASH).
        is >> share->m_merged_addresses;

        // NO tx_info (only serialized for version < 34).

        is >> share->m_far_share_hash;      // PossiblyNone(0, IntType(256))
        is >> share->m_max_bits;            // uint32
        is >> share->m_bits;                // uint32
        is >> share->m_timestamp;           // uint32
        is >> share->m_absheight;           // uint32
        ::Unserialize(is, Using<v36::AbsworkV36Format>(share->m_abswork)); // v36: VarInt low64

        // v36 merged_coinbase_info + merged_payout_hash (empty/zero-inert on DASH).
        is >> share->m_merged_coinbase_info;
        is >> share->m_merged_payout_hash;

        // ref_merkle_link (MERKLE_LINK_SMALL — index omitted).
        { ParamPackStream ps{v36::MERKLE_LINK_SMALL, is}; ::Unserialize(ps, share->m_ref_merkle_link); }

        is >> share->m_last_txout_nonce;    // uint64
        is >> share->m_hash_link;           // V36HashLinkType

        { ParamPackStream ps{v36::MERKLE_LINK_SMALL, is}; ::Unserialize(ps, share->m_merkle_link); }

        is >> share->m_message_data;        // v36 messaging hook (empty on DASH Phase A)

        // ── DASH-specific suffix (FLAGGED divergence) ──
        is >> share->m_coinbase_payload;    // PossiblyNone('', VarStr)
        is >> share->m_payment_amount;      // uint64
        {
            uint64_t count;
            ::Unserialize(is, VarInt(count));
            if (count > MAX_PAYMENTS_PER_SHARE)
                throw std::ios_base::failure("packed_payments count exceeds cap");
            share->m_packed_payments.resize(count);
            for (uint64_t i = 0; i < count; ++i) {
                BaseScript payee_bs;
                is >> payee_bs;
                share->m_packed_payments[i].m_payee.assign(
                    payee_bs.m_data.begin(), payee_bs.m_data.end());
                is >> share->m_packed_payments[i].m_amount;
            }
        }
        is >> share->m_coinbase_payload_outer; // PossiblyNone('', VarStr)
    }

    template <typename StreamType, typename ShareT>
    static void WriteV36(StreamType& os, const ShareT* share)
    {
        os << share->m_min_header;
        os << share->m_prev_hash;
        os << share->m_coinbase;
        os << share->m_nonce;
        os << share->m_pubkey_hash;
        os << share->m_pubkey_type;
        ::Serialize(os, VarInt(share->m_subsidy));
        os << share->m_donation;
        { uint8_t si = static_cast<uint8_t>(share->m_stale_info); os << si; }
        ::Serialize(os, VarInt(share->m_desired_version));
        os << share->m_merged_addresses;
        os << share->m_far_share_hash;
        os << share->m_max_bits;
        os << share->m_bits;
        os << share->m_timestamp;
        os << share->m_absheight;
        ::Serialize(os, Using<v36::AbsworkV36Format>(share->m_abswork));
        os << share->m_merged_coinbase_info;
        os << share->m_merged_payout_hash;
        { ParamPackStream ps{v36::MERKLE_LINK_SMALL, os}; ::Serialize(ps, share->m_ref_merkle_link); }
        os << share->m_last_txout_nonce;
        os << share->m_hash_link;
        { ParamPackStream ps{v36::MERKLE_LINK_SMALL, os}; ::Serialize(ps, share->m_merkle_link); }
        os << share->m_message_data;
        // ── DASH-specific suffix (FLAGGED divergence) ──
        os << share->m_coinbase_payload;
        os << share->m_payment_amount;
        {
            uint64_t count = share->m_packed_payments.size();
            ::Serialize(os, VarInt(count));
            for (auto& pay : share->m_packed_payments) {
                BaseScript bs;
                bs.m_data.assign(pay.m_payee.begin(), pay.m_payee.end());
                os << bs;
                os << pay.m_amount;
            }
        }
        os << share->m_coinbase_payload_outer;
    }
};

// ── ShareType: variant containing only v16 ───────────────────────────────────
// For Dash, there's only one share version (v16).

using ShareType = chain::ShareVariants<DashFormatter, DashShare>;

// ── PHASE A: v36 share-type dispatch (DORMANT) ───────────────────────────────
// The live `ShareType` above is DELIBERATELY left as {DashShare} only, so the
// live accept / mint / store / send paths (node.cpp) stay byte-unchanged and
// keep compiling — several consume the share via generic-invoke lambdas that
// call DashShare-concrete helpers (e.g. share_init_verify(const DashShare&) at
// node.cpp:64). Promoting DashV36Share into the live variant requires guarding
// those call sites with `if constexpr (std::is_same_v<share_t, DashShare>)`, and
// is the FIRST wiring step of Phase B/C — NOT Phase A.
//
// This SEPARATE variant proves the v36 wire type round-trips through the REAL
// chain::ShareVariants dispatch machinery (load map keyed by version 36 ->
// DashV36Share, DashFormatter::ReadV36/WriteV36). It is what the round-trip KAT
// exercises. Nothing mints a v36 share (current_share_version stays 16), so the
// type is parseable/mintable-in-principle yet dormant until Phase-C activation.
using V36ShareType = chain::ShareVariants<DashFormatter, DashV36Share>;

// ── Load share from wire format ──────────────────────────────────────────────

inline ShareType load_share(chain::RawShare& rshare, NetService peer_addr)
{
    auto stream = rshare.contents.as_stream();
    auto share = ShareType::load(rshare.type, stream);
    // Propagate ingestion source to the share so the dashboard / audit
    // trail can show which peer gossiped it. Matches LTC share.hpp:260.
    share.ACTION({ obj->peer_addr = peer_addr; });
    return share;
}

// PHASE A v36 load helper (dispatch-by-version-36). Mirrors load_share but over
// the dormant V36ShareType variant; used by the round-trip KAT.
inline V36ShareType load_v36_share(chain::RawShare& rshare, NetService peer_addr)
{
    auto stream = rshare.contents.as_stream();
    auto share = V36ShareType::load(rshare.type, stream);
    share.ACTION({ obj->peer_addr = peer_addr; });
    return share;
}

// ── ShareHasher ──────────────────────────────────────────────────────────────

struct ShareHasher
{
    size_t operator()(const uint256& hash) const
    {
        return hash.GetLow64();
    }
};

// ── ShareIndex: per-share metadata in the chain ──────────────────────────────

class ShareIndex : public chain::ShareIndex<uint256, ShareType, ShareHasher, ShareIndex>
{
    using base_index = chain::ShareIndex<uint256, ShareType, ShareHasher, ShareIndex>;

public:
    uint288 work;
    uint288 min_work;

    // Per-share metadata (btc::ShareIndex parity — additive, dash-fenced).
    // Populated during share verify / reception; defaults keep KATs hermetic.
    int64_t time_seen{0};
    int32_t naughty{0};
    bool is_block_solution{false};  // pow_hash <= block_target (set during init_verify)
    uint256 pow_hash;               // X11 hash, cached at reception (for block scan)

    ShareIndex() : base_index(), work(0), min_work(0) {}

    template <typename ShareT> ShareIndex(ShareT* share) : base_index(share)
    {
        work = chain::target_to_average_attempts(chain::bits_to_target(share->m_bits));
        min_work = chain::target_to_average_attempts(chain::bits_to_target(share->m_max_bits));
        time_seen = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
};

// ── ShareChain ───────────────────────────────────────────────────────────────

struct ShareChain : chain::ShareChain<ShareIndex>
{
};

} // namespace dash