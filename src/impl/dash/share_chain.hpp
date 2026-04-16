#pragma once

// Dash share chain types: ShareType variant, ShareIndex, ShareChain.
// Uses the generic sharechain infrastructure from c2pool/sharechain/.
// Only v16 shares exist for Dash.

#include "share.hpp"
#include "share_types.hpp"

#include <sharechain/share.hpp>
#include <sharechain/sharechain.hpp>
#include <core/target_utils.hpp>

#include <chrono>

namespace dash
{

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
    }

    template <typename StreamType, typename ShareT>
    static void Write(StreamType& os, const ShareT* share)
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
    }
};

// ── ShareType: variant containing only v16 ───────────────────────────────────
// For Dash, there's only one share version (v16).

using ShareType = chain::ShareVariants<DashFormatter, DashShare>;

// ── Load share from wire format ──────────────────────────────────────────────

inline ShareType load_share(chain::RawShare& rshare, NetService peer_addr)
{
    auto stream = rshare.contents.as_stream();
    auto share = ShareType::load(rshare.type, stream);
    // TODO: set peer_addr on the share
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
    int64_t time_seen{0};

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
