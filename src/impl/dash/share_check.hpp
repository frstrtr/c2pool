// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Dash share v16 verification: hash_link, merkle, X11 PoW.
// Simplified from LTC share_check.hpp — no segwit, no merged mining.
// Reference: ref/p2pool-dash/p2pool/data.py Share.__init__() + check()
// Future-timestamp bound (private/isolated v36 profile only; public v16 has
// none, oracle parity) — see check_share_timestamp_bound.
// v36 share verification (DashV36Share; private/isolated v36 sharechain only;
// the public network never loads a type-36 share) — see the
// "DASH v36 share verification" section below share_init_verify(DashShare).
// Share-type admission (which wire type a chain accepts) — see
// check_share_type_admitted.
// v36 generation transaction (DashV36Share; same scope): see the
// "DASH v36 generation transaction" section at the end of this file. v36 formula:
//   window  = decayed PPLNS from the PARENT over CHAIN_LENGTH shares (pplns_v36.hpp)
//   amounts = worker_payout * weight / total_weight (full weight, NO finder fee),
//             remainder to params.donation_script_func(36), donation >= 1 sat.
//
// PPLNS formula (v16, pre-V36 linear weights):
//   weight_per_share = target_to_average_attempts(share.target) * (65535 - donation_field)
//   max_weight = target_to_average_attempts(block_target) * 65535 * SPREAD
//   worker_payout = subsidy - sum(masternode/superblock/platform payments)
//   amount[script] = worker_payout * 49 * weight / (50 * total_weight)  — 98% PPLNS
//   amount[finder]  += worker_payout / 50                                — 2% finder fee
//   amount[donation] = worker_payout - sum(all amounts)                  — rounding remainder
//
// Coinbase output order: [worker_tx (sorted)] [payments_tx (masternode/superblock/platform)] [donation_tx] [OP_RETURN ref_hash]
//
// Masternode/superblock payments come from getblocktemplate and are subtracted
// from worker_payout BEFORE PPLNS distribution. They are NOT part of PPLNS weights.
// Platform payments use "!" prefix encoding for OP_RETURN scripts.

#include "share.hpp"
#include "share_types.hpp"
#include "version_negotiation.hpp"   // dash::version_negotiation:: accept-path version gate
#include "coin/gentx_coinbase.hpp"   // dash::coin::GentxCoinbase (won-block reconstruct SSOT hand-off)
#include "config_pool.hpp"            // dash::SharechainConfig::share_profile() (future-timestamp gate)
#include "share_messages.hpp"         // v36 message_data validation (authority_pubkeys, validate_message_data)
#include "pplns_v36.hpp"              // v36 PPLNS window + amounts rule (CumulativeWeights, compute_v36_amounts)

#include <core/coin_params.hpp>
#include <core/donation.hpp>          // cross-coin COMBINED_DONATION_SCRIPT SSOT (Bucket-2)
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/pow.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>
#include <btclibs/base58.h>
#include <btclibs/crypto/common.h>
#include <btclibs/crypto/sha256.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

namespace dash
{

// ── check_hash_link (same algorithm as LTC) ──────────────────────────────────
// Templated over the hash-link type: the v16 dash::HashLinkType and the v36
// dash::v36::V36HashLinkType carry the same members (state, VarStr extra_data,
// length), so both shares fold through this ONE body.
template <typename HashLinkT>
inline uint256 check_hash_link(const HashLinkT& hash_link,
                               const std::vector<unsigned char>& data,
                               const std::vector<unsigned char>& const_ending = {})
{
    const uint64_t extra_length = hash_link.m_length % 64;

    std::vector<unsigned char> extra;
    extra.assign(hash_link.m_extra_data.m_data.begin(),
                 hash_link.m_extra_data.m_data.end());
    if (extra.size() < extra_length)
    {
        auto needed = extra_length - extra.size();
        if (const_ending.size() >= needed)
            extra.insert(extra.end(), const_ending.end() - needed, const_ending.end());
    }
    if (extra.size() != extra_length)
        throw std::runtime_error("check_hash_link: extra size mismatch");

    const auto& state_bytes = hash_link.m_state.m_data;
    uint32_t init_state[8] = {
        ReadBE32(state_bytes.data() +  0), ReadBE32(state_bytes.data() +  4),
        ReadBE32(state_bytes.data() +  8), ReadBE32(state_bytes.data() + 12),
        ReadBE32(state_bytes.data() + 16), ReadBE32(state_bytes.data() + 20),
        ReadBE32(state_bytes.data() + 24), ReadBE32(state_bytes.data() + 28),
    };

    unsigned char out1[CSHA256::OUTPUT_SIZE];
    CSHA256(init_state, extra, hash_link.m_length)
        .Write(data.data(), data.size())
        .Finalize(out1);

    unsigned char out2[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(out1, CSHA256::OUTPUT_SIZE).Finalize(out2);

    uint256 result;
    std::memcpy(result.data(), out2, 32);
    return result;
}

// ── check_merkle_link ────────────────────────────────────────────────────────
// Templated over the link type: dash::MerkleLink (v16) and dash::v36::MerkleLink
// (v36) carry the same members (branch, index); ONE body for both.
template <typename MerkleLinkT>
inline uint256 check_merkle_link(const uint256& tip_hash, const MerkleLinkT& link)
{
    uint256 cur = tip_hash;
    for (size_t i = 0; i < link.m_branch.size(); ++i)
    {
        PackStream ps;
        if ((link.m_index >> i) & 1)
        {
            ps << link.m_branch[i];
            ps << cur;
        }
        else
        {
            ps << cur;
            ps << link.m_branch[i];
        }
        auto sp = std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(ps.data()), ps.size());
        cur = Hash(sp);
    }
    return cur;
}

// ── Donation script (P2PKH for XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u) ─────────
// Reference: ref/p2pool-dash/p2pool/data.py DONATION_SCRIPT
static const std::vector<unsigned char> DONATION_SCRIPT = {
    0x76, 0xa9, 0x14,
    0x20, 0xcb, 0x5c, 0x22, 0xb1, 0xe4, 0xd5, 0x94,
    0x7e, 0x5c, 0x11, 0x2c, 0x76, 0x96, 0xb5, 0x1a,
    0xd9, 0xaf, 0x3c, 0x61,
    0x88, 0xac
};

// ── v36 unified cross-coin donation P2SH (Bucket-2 standardization, operator
//    FLAG6 2026-06-17) ─────────────────────────────────────────────────────
// Sourced from the cross-coin SSOT core::donation::COMBINED_DONATION_SCRIPT so
// DASH cannot drift from btc/bch/dgb/ltc — this is the v36-native SHARED shape
// (Bucket-2), NOT a DASH isolation primitive, so it must stay byte-identical to
// the other coins. Was a hand-copied local literal; this rewire is value-
// invariant (proven by DashConformanceCombinedDonation.MatchesCrossCoinSSOT).
// P2SH wrapping the 1-of-2 (forrestv + c2pool dev key) redeem script; selected
// for v36+ shares, while pre-v36 shares keep the DASH-specific P2PKH
// DONATION_SCRIPT above (Bucket-3, per-coin keep-for-soak).
static const std::vector<unsigned char> COMBINED_DONATION_SCRIPT(
    core::donation::COMBINED_DONATION_SCRIPT.begin(),
    core::donation::COMBINED_DONATION_SCRIPT.end());

// ── compute_gentx_before_refhash ─────────────────────────────────────────────
// General form (LTC compute_gentx_before_refhash(share_version, params)
// semantics): the gentx const_ending for a given donation script. The v16 path
// uses DONATION_SCRIPT (zero-argument form below, identical bytes); the v36
// verifier passes params.donation_script_func(36), which is the same P2PKH
// DONATION_SCRIPT on the private/isolated v36 sharechain.
inline std::vector<unsigned char> compute_gentx_before_refhash(
    const std::vector<unsigned char>& donation_script)
{
    std::vector<unsigned char> result;

    // VarStr(donation_script)
    {
        PackStream s;
        BaseScript bs;
        bs.m_data = donation_script;
        s << bs;
        auto* p = reinterpret_cast<const unsigned char*>(s.data());
        result.insert(result.end(), p, p + s.size());
    }
    // int64(0)
    {
        uint64_t zero64 = 0;
        auto* p = reinterpret_cast<const unsigned char*>(&zero64);
        result.insert(result.end(), p, p + 8);
    }
    // VarStr(0x6a 0x28 + int256(0) + int64(0))[:3]
    {
        PackStream inner;
        unsigned char prefix[2] = {0x6a, 0x28};
        inner.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(prefix), 2));
        uint256 zero256;
        inner << zero256;
        uint64_t zero64 = 0;
        inner.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&zero64), 8));

        PackStream outer;
        BaseScript bs;
        bs.m_data.resize(inner.size());
        std::memcpy(bs.m_data.data(), inner.data(), inner.size());
        outer << bs;

        auto* p = reinterpret_cast<const unsigned char*>(outer.data());
        result.insert(result.end(), p, p + std::min<size_t>(3, outer.size()));
    }

    return result;
}

// Dash v16 const_ending: VarStr(DONATION_SCRIPT) || int64(0) || 3 bytes.
inline std::vector<unsigned char> compute_gentx_before_refhash()
{
    return compute_gentx_before_refhash(DONATION_SCRIPT);
}

// ── check_share_target_valid (Dash v16) ─────────────────────────────
// Conformance with p2pool-dash oracle data.py Share.__init__:
//     if self.target > net.MAX_TARGET: raise PeerMisbehavingError('share target invalid')
// The claimed share target must be no easier than the network share-diff floor
// (params.max_target == net.MAX_TARGET); a zero target is likewise invalid. This is
// a structural validity guard on share_info['bits'], independent of the PoW check.
// v36 3-bucket: the GUARD is v36-native SHARED validation (Bucket 2 — cross-coin
// identical); only the per-coin max_target constant differs (a consensus param, not
// an isolation primitive).
inline void check_share_target_valid(const uint256& target, const core::CoinParams& params)
{
    if (target.IsNull())
        throw std::invalid_argument("share target is zero");
    if (target > params.max_target)
        throw std::invalid_argument("share target invalid");
}

// ── Future-timestamp bound (private/isolated v36 sharechain only) ────────────
// Port of the LTC rule (ltc/share_check.hpp share_check step 1; oracle
// p2pool-merged-v36 data.py Share.check()): a share whose timestamp is more
// than 600 s ahead of the local clock is rejected. The public v16 network has
// NO such rule — the p2pool-dash oracle (data.py check()) does not carry it —
// so it is gated on SharechainConfig::share_profile().future_timestamp_bound,
// which is true only on the private/isolated v36 profile (custom --network-id).
//
// A pure function of (timestamp, now) with no chain context, so it is the first
// statement of share_init_verify: the earliest point every DASH share passes
// (node receive, tracker verify / persisted re-verify, admit_share, producer
// self-check). Typed over uint32_t rather than a share type so the v36 share
// verifier reuses it unchanged. `now` is injectable for deterministic tests.
inline constexpr uint32_t SHARE_TIMESTAMP_FUTURE_BOUND_SECS = 600;

// The local clock in the same units/width as a share timestamp (LTC expression).
inline uint32_t share_clock_now()
{
    return static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

// Throws the LTC error text when `enabled` and share_timestamp > now + 600.
// The sum is taken in 64 bits so a `now` near UINT32_MAX cannot wrap and turn
// the bound into a reject-everything rule (LTC adds in uint32).
inline void check_share_timestamp_bound(uint32_t share_timestamp, uint32_t now, bool enabled)
{
    if (!enabled)
        return;
    if (static_cast<uint64_t>(share_timestamp) >
        static_cast<uint64_t>(now) + SHARE_TIMESTAMP_FUTURE_BOUND_SECS)
        throw std::invalid_argument("share timestamp is too far in the future");
}

// The one place the per-network profile is read for this rule.
inline bool future_timestamp_bound_active()
{
    return SharechainConfig::share_profile().future_timestamp_bound;
}

// Per-verify scratch globals (btc::share_check parity — additive, dash-fenced).
// share_init_verify caches the share header X11 hash and whether it also met the
// block target, so attempt_verify / the tracker can fire block callbacks without
// recomputing X11. thread_local: each verify thread keeps its own last-result.
inline thread_local bool g_last_init_is_block = false;
inline thread_local uint256 g_last_pow_hash;  // X11 hash of the share header
// gentx txid the share's hash_link commits to (the coinbase the miner actually
// hashed). Cached by share_init_verify so the accept path can compare it against
// the PPLNS-recomputed expected coinbase (verify_payout_commitment, Phase 3)
// WITHOUT re-deriving the ref_hash / hash_link a second time. Same-thread,
// same-call contract as g_last_pow_hash: read it immediately after the
// share_init_verify that produced it, on the same thread.
inline thread_local uint256 g_last_gentx_hash;

// ── Share-type admission ─────────────────────────────────────────────────────
// A DASH sharechain admits exactly ONE wire type: the share version it mints,
// CoinParams::current_share_version. Public network: 16 (p2pool-dash). Private/
// isolated v36 sharechain: 16 until the flip slice sets current_share_version to
// 36, then 36 — so a v16 share is not admitted on the v36 chain (and a v36 share
// is not admitted on a chain still minting v16) with no further code. A single
// knob arms "mint 36" and "reject 16" together: the flip MUST set
// current_share_version, not only the mint type, or this gate does not arm.
// A type-36 share never reaches this check on the public network: load_share
// (share_chain.hpp) throws on it first, exactly as before the v36 type existed.
// current_share_version == 0 (a default-constructed CoinParams, e.g. a KAT
// tracker) means "not configured" and admits the DASH baseline, v16 — the only
// type such a tracker ever verified. Throws std::invalid_argument.
inline void check_share_type_admitted(int64_t wire_type, const core::CoinParams& params)
{
    const int64_t admitted = params.current_share_version != 0
        ? static_cast<int64_t>(params.current_share_version)
        : DashShare::version;
    if (wire_type != admitted)
        throw std::invalid_argument(
            "share type v" + std::to_string(wire_type) +
            " not admitted: this sharechain speaks v" + std::to_string(admitted));
}

// ── share_init_verify (Dash v16) ─────────────────────────────────────────────
// Verifies PoW, hash_link, merkle_link. Returns share hash (SHA256d of header).
inline uint256 share_init_verify(const DashShare& share,
                                 const core::CoinParams& params,
                                 bool check_pow = true)
{
    // Future-timestamp bound: no-op on the public v16 network; now+600 on the
    // private/isolated v36 profile. First, before any hashing (cheapest reject).
    check_share_timestamp_bound(share.m_timestamp, share_clock_now(),
                                future_timestamp_bound_active());

    if (share.m_coinbase.m_data.size() < 2 || share.m_coinbase.m_data.size() > 100)
        throw std::invalid_argument("bad coinbase size");

    // ── Share target validity (oracle: target > MAX_TARGET → "share target invalid") ──
    // Unconditional — NOT gated by check_pow, matching p2pool-dash Share.__init__.
    check_share_target_valid(chain::bits_to_target(share.m_bits), params);

    // ── Compute ref_hash ──
    PackStream ref_stream;
    {
        auto hex = params.active_identifier_hex();
        for (size_t i = 0; i + 1 < hex.size(); i += 2)
        {
            unsigned char byte = static_cast<unsigned char>(
                std::stoul(hex.substr(i, 2), nullptr, 16));
            ref_stream.write(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(&byte), 1));
        }
    }

    // share_info serialization (v16 format)
    {
        // share_data
        ref_stream << share.m_prev_hash;
        ref_stream << share.m_coinbase;
        ref_stream << share.m_coinbase_payload;
        ref_stream << share.m_nonce;
        ref_stream << share.m_pubkey_hash;
        ref_stream << share.m_subsidy;
        ref_stream << share.m_donation;
        { uint8_t si = static_cast<uint8_t>(share.m_stale_info); ref_stream << si; }
        ::Serialize(ref_stream, VarInt(share.m_desired_version));
        ref_stream << share.m_payment_amount;
        ref_stream << share.m_packed_payments;

        // share_info (non-share_data)
        ref_stream << share.m_new_transaction_hashes;
        // transaction_hash_refs: ListType(VarIntType(), 2) — writes count/2 then all elements
        {
            uint64_t pair_count = share.m_transaction_hash_refs.size() / 2;
            ::Serialize(ref_stream, VarInt(pair_count));
            for (auto& v : share.m_transaction_hash_refs)
                ::Serialize(ref_stream, VarInt(v));
        }
        ref_stream << share.m_far_share_hash;
        ref_stream << share.m_max_bits;
        ref_stream << share.m_bits;
        ref_stream << share.m_timestamp;
        ref_stream << share.m_absheight;
        ref_stream << share.m_abswork;
    }

    auto ref_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(ref_stream.data()), ref_stream.size());
    uint256 hash_ref = Hash(ref_span);
    uint256 ref_hash = check_merkle_link(hash_ref, share.m_ref_merkle_link);

    // ── Build hash_link_data ──
    // Python: get_ref_hash(...) + pack.IntType(64).pack(last_txout_nonce) + pack.IntType(32).pack(0) + coinbase_payload_data
    std::vector<unsigned char> hash_link_data;
    hash_link_data.insert(hash_link_data.end(), ref_hash.data(), ref_hash.data() + 32);
    {
        uint64_t nonce = share.m_last_txout_nonce;
        auto* p = reinterpret_cast<const unsigned char*>(&nonce);
        hash_link_data.insert(hash_link_data.end(), p, p + 8);
    }
    {
        uint32_t zero = 0;
        auto* p = reinterpret_cast<const unsigned char*>(&zero);
        hash_link_data.insert(hash_link_data.end(), p, p + 4);
    }
    // Append outer coinbase_payload (coinbase_payload_data in Python).
    // Oracle data.py:277-289: the outer contents['coinbase_payload'] VALUE is
    // coinbase_payload_data = pack.VarStrType().pack(raw_payload) — i.e. the
    // VarStr-PACKED payload ([compactsize(len)][payload]) — and Share.__init__
    // (data.py:346-348) appends that value VERBATIM to the check_hash_link
    // data (b"" when None). On the wire the PossiblyNone(b'', VarStr) outer
    // layer adds one MORE compactsize prefix around the value, so
    // DashFormatter's single READWRITE(m_data) strip leaves m_data holding
    // exactly the oracle field value: [compactsize(len raw)][raw]. Append it
    // RAW. (#412 correctly established that the compactsize prefix belongs in
    // this data — but re-serializing m_data as a VarStr added a SECOND prefix
    // on top of the one m_data already carries, diverging gentx_hash from the
    // oracle on every real DIP4 CbTx share. The share-producer slice pins the
    // corrected framing: producer KATs in test_dash_share_producer.cpp,
    // updated oracle anchors in test_dash_share_hash_link.cpp.)
    // PRESERVE the empty branch: the oracle appends nothing (b"") when the
    // payload is None/empty, NOT a 0x00.
    {
        auto& cpd = share.m_coinbase_payload_outer.m_data;
        if (!cpd.empty())
            hash_link_data.insert(hash_link_data.end(), cpd.begin(), cpd.end());
    }

    auto gentx_before_refhash = compute_gentx_before_refhash();

    // ── check_hash_link → gentx_hash ──
    uint256 gentx_hash = check_hash_link(share.m_hash_link, hash_link_data, gentx_before_refhash);
    g_last_gentx_hash = gentx_hash;  // cache for the Phase-3 payout-commitment gate

    // ── Merkle root (no segwit for Dash) ──
    uint256 merkle_root = check_merkle_link(gentx_hash, share.m_merkle_link);

    // ── Reconstruct block header ──
    PackStream header_stream;
    {
        uint32_t hdr_version = static_cast<uint32_t>(share.m_min_header.m_version);
        header_stream << hdr_version;
    }
    header_stream << share.m_min_header.m_previous_block;
    header_stream << merkle_root;
    header_stream << share.m_min_header.m_timestamp;
    header_stream << share.m_min_header.m_bits;
    header_stream << share.m_min_header.m_nonce;

    // Dash: both BLOCKHASH_FUNC and POW_FUNC are X11
    // share_hash = X11(header) — block identity AND PoW check
    auto hdr_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(header_stream.data()), header_stream.size());
    uint256 share_hash = params.pow_func(hdr_span);
    g_last_pow_hash = share_hash;  // cache for attempt_verify merged/block check

    // Block detection: a share whose X11 hash also meets the BLOCK target
    // (min_header.m_bits, from GBT — far harder than the share target) IS a
    // solved block. Mirrors btc::share_check. Computed even when check_pow is
    // off so the tracker can still fire the won-block path in tests.
    {
        uint256 block_target = chain::bits_to_target(share.m_min_header.m_bits);
        g_last_init_is_block = (!block_target.IsNull() && share_hash <= block_target);
    }

    // ── X11 PoW check ──
    if (check_pow)
    {
        uint256 target = chain::bits_to_target(share.m_bits);
        if (share_hash > target)
            throw std::invalid_argument("share PoW hash does not meet target");
    }

    return share_hash;
}

// ═══════════════════════════════════════════════════════════════════════════
// DASH v36 share verification (DashV36Share, wire-type 36)
//
// Private/isolated DASH v36 sharechain only (custom --network-id). The live
// ShareType holds DashV36Share, but only the isolated profile's load_share ever
// instantiates one (the public network throws on wire type 36 at load), and the
// accept path admits it only once the chain speaks v36
// (check_share_type_admitted). The public v16 verifier above is byte-unchanged.
//
// The v36 ref stream (ref_type preimage) is the cross-coin v36 share_info
// shape — the LTC v36 ref stream (ltc/share_check.hpp share_init_verify) minus
// the segwit_data slot (non-segwit coin, the BCH convention) and minus tx_info
// (v >= 34) — followed by the DASH-specific suffix (coinbase_payload,
// payment_amount, packed_payments) AFTER message_data. That is the DashV36Share
// wire order (DashFormatter::WriteV36) with the non-ref fields removed:
// ref_merkle_link, last_txout_nonce, hash_link and merkle_link are share-level
// link fields (never in share_info), and coinbase_payload_outer is hash_link
// DATA (appended after the ref_hash, as on v16), not ref-stream content.
//
// ONE builder, serialize_v36_ref_share_info, is used by the verifier here and
// by the producer (share_producer.hpp compute_ref_hash(params, DashV36Share)),
// so the two cannot drift.
// ═══════════════════════════════════════════════════════════════════════════

// The 8 IDENTIFIER bytes (params.active_identifier_hex(), hex-decoded) that
// open every ref stream. Same loop as the v16 verifier; used by the v36 path.
inline void append_identifier_bytes(PackStream& os, const core::CoinParams& params)
{
    const std::string hex = params.active_identifier_hex();
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
    {
        unsigned char byte = static_cast<unsigned char>(
            std::stoul(hex.substr(i, 2), nullptr, 16));
        os.write(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(&byte), 1));
    }
}

// v36 share_info serialization for the ref stream (field order and encodings
// of DashFormatter::WriteV36, minus the non-ref fields; see section header).
inline void serialize_v36_ref_share_info(PackStream& os, const DashV36Share& s)
{
    // ── share_data (standardized v36) ──
    os << s.m_prev_hash;                                   // PossiblyNone(0, IntType(256))
    os << s.m_coinbase;                                    // VarStr
    os << s.m_nonce;                                       // uint32
    os << s.m_pubkey_hash;                                 // v36 address: IntType(160)
    os << s.m_pubkey_type;                                 // v36: IntType(8)
    ::Serialize(os, VarInt(s.m_subsidy));                  // v36: VarInt
    os << s.m_donation;                                    // uint16
    { uint8_t si = static_cast<uint8_t>(s.m_stale_info); os << si; }  // EnumType<IntType<8>>
    { uint64_t dv = s.m_desired_version; ::Serialize(os, VarInt(dv)); } // version-vote
    // NO segwit_data (non-segwit coin).
    os << s.m_merged_addresses;                            // v36 (empty/inert on DASH)
    // NO tx_info (only for share version < 34).

    // ── share_info (standardized v36) ──
    os << s.m_far_share_hash;                              // PossiblyNone(0, IntType(256))
    os << s.m_max_bits;
    os << s.m_bits;
    os << s.m_timestamp;
    os << s.m_absheight;
    ::Serialize(os, Using<v36::AbsworkV36Format>(s.m_abswork));  // v36: VarInt low64
    os << s.m_merged_coinbase_info;                        // v36 (empty/inert on DASH)
    os << s.m_merged_payout_hash;                          // v36 (zero/inert on DASH)

    // ── v36 message_data: PossiblyNone(b'', VarStr) — empty => 0x00 ──
    os << s.m_message_data;

    // ── DASH-specific suffix, AFTER message_data (DashV36Share wire order) ──
    os << s.m_coinbase_payload;                            // PossiblyNone('', VarStr)
    os << s.m_payment_amount;                              // uint64
    {
        uint64_t count = s.m_packed_payments.size();
        ::Serialize(os, VarInt(count));
        for (const auto& pay : s.m_packed_payments)
        {
            BaseScript bs;
            bs.m_data.assign(pay.m_payee.begin(), pay.m_payee.end());
            os << bs;                                      // VarStr payee
            os << pay.m_amount;                            // uint64
        }
    }
}

// identifier || v36 share_info — the exact bytes hashed into the ref_hash.
inline std::vector<unsigned char> v36_ref_stream_bytes(const core::CoinParams& params,
                                                       const DashV36Share& s)
{
    PackStream os;
    append_identifier_bytes(os, params);
    serialize_v36_ref_share_info(os, s);
    const auto* p = reinterpret_cast<const unsigned char*>(os.data());
    return std::vector<unsigned char>(p, p + os.size());
}

// ref_hash = check_merkle_link(sha256d(ref stream), ref_merkle_link).
inline uint256 compute_v36_ref_hash(const core::CoinParams& params, const DashV36Share& s)
{
    const auto bytes = v36_ref_stream_bytes(params, s);
    return check_merkle_link(Hash(std::span<const unsigned char>(bytes.data(), bytes.size())),
                             s.m_ref_merkle_link);
}

// hash_link data: ref_hash || LE64(last_txout_nonce) || LE32(0) || outer
// coinbase_payload VALUE appended raw (nothing when empty). Same framing as the
// v16 verifier (see the coinbase_payload_outer note in share_init_verify above).
inline std::vector<unsigned char> v36_hash_link_data(const uint256& ref_hash,
                                                     uint64_t last_txout_nonce,
                                                     const BaseScript& coinbase_payload_outer)
{
    std::vector<unsigned char> out;
    out.insert(out.end(), ref_hash.data(), ref_hash.data() + 32);
    {
        const auto* p = reinterpret_cast<const unsigned char*>(&last_txout_nonce);
        out.insert(out.end(), p, p + 8);
    }
    {
        uint32_t zero = 0;
        const auto* p = reinterpret_cast<const unsigned char*>(&zero);
        out.insert(out.end(), p, p + 4);
    }
    const auto& cpd = coinbase_payload_outer.m_data;
    if (!cpd.empty())
        out.insert(out.end(), cpd.begin(), cpd.end());
    return out;
}

// Largest message_data blob an honest producer can emit: the encryption header
// (49) plus the MAX_TOTAL_MESSAGE_BYTES inner cap that create_message_data
// enforces. Anything larger is rejected before any HMAC / ECDSA work.
inline constexpr size_t MAX_MESSAGE_DATA_WIRE_BYTES =
    ENCRYPTION_HEADER_SIZE + MAX_TOTAL_MESSAGE_BYTES;

// message_data validation for a v36 share. Empty is valid (no messages).
// Otherwise the blob must decrypt under one of `keys`, carry at least one
// well-formed message, and every message must be ECDSA-signed by the key that
// opened the envelope (validate_message_data). Throws on reject.
inline void check_v36_message_data(const BaseScript& message_data,
                                   std::span<const AuthorityPubkey* const> keys)
{
    if (message_data.m_data.empty())
        return;
    if (message_data.m_data.size() > MAX_MESSAGE_DATA_WIRE_BYTES)
        throw std::invalid_argument("share message_data exceeds MAX_TOTAL_MESSAGE_BYTES");
    const std::string err = validate_message_data(message_data.m_data, keys);
    if (!err.empty())
        throw std::invalid_argument("share " + err);
}

// The one place the per-network profile is read for message authority: the
// maintainer key alone on the private/isolated v36 sharechain, the public
// 2-key set otherwise.
inline std::span<const AuthorityPubkey* const> active_message_authority()
{
    return authority_pubkeys(SharechainConfig::share_profile().maintainer_only_authority);
}

// ── share_init_verify (Dash v36) ─────────────────────────────────────────────
// Same checks, same order as the v16 verifier: future-timestamp bound, coinbase
// size, target validity, ref_hash + hash_link + merkle, X11 PoW; then the v36
// message_data validation LAST (after the PoW gate, so an unmined share costs
// no HMAC / ECDSA work; still before any chain-relative check). Returns the
// share hash (X11 of the rebuilt header). `message_authority` is injectable so
// the positive signed-message path is testable; production uses the overload
// below, which passes active_message_authority().
inline uint256 share_init_verify(const DashV36Share& share,
                                 const core::CoinParams& params,
                                 bool check_pow,
                                 std::span<const AuthorityPubkey* const> message_authority)
{
    check_share_timestamp_bound(share.m_timestamp, share_clock_now(),
                                future_timestamp_bound_active());

    if (share.m_coinbase.m_data.size() < 2 || share.m_coinbase.m_data.size() > 100)
        throw std::invalid_argument("bad coinbase size");

    check_share_target_valid(chain::bits_to_target(share.m_bits), params);

    // ── ref_hash → hash_link → gentx_hash ──
    const uint256 ref_hash = compute_v36_ref_hash(params, share);
    const auto hash_link_data =
        v36_hash_link_data(ref_hash, share.m_last_txout_nonce, share.m_coinbase_payload_outer);
    const uint256 gentx_hash = check_hash_link(
        share.m_hash_link, hash_link_data,
        compute_gentx_before_refhash(params.donation_script_func(36)));
    g_last_gentx_hash = gentx_hash;

    // ── merkle root (no segwit) ──
    const uint256 merkle_root = check_merkle_link(gentx_hash, share.m_merkle_link);

    // ── block header → X11 ──
    PackStream header_stream;
    {
        uint32_t hdr_version = static_cast<uint32_t>(share.m_min_header.m_version);
        header_stream << hdr_version;
    }
    header_stream << share.m_min_header.m_previous_block;
    header_stream << merkle_root;
    header_stream << share.m_min_header.m_timestamp;
    header_stream << share.m_min_header.m_bits;
    header_stream << share.m_min_header.m_nonce;

    auto hdr_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(header_stream.data()), header_stream.size());
    const uint256 share_hash = params.pow_func(hdr_span);
    g_last_pow_hash = share_hash;
    {
        uint256 block_target = chain::bits_to_target(share.m_min_header.m_bits);
        g_last_init_is_block = (!block_target.IsNull() && share_hash <= block_target);
    }

    if (check_pow)
    {
        uint256 target = chain::bits_to_target(share.m_bits);
        if (share_hash > target)
            throw std::invalid_argument("share PoW hash does not meet target");
    }

    check_v36_message_data(share.m_message_data, message_authority);

    return share_hash;
}

inline uint256 share_init_verify(const DashV36Share& share,
                                 const core::CoinParams& params,
                                 bool check_pow = true)
{
    return share_init_verify(share, params, check_pow, active_message_authority());
}

// ── decode_payee_script: "!" prefix → raw hex script, else → address_to_script2
// Reference: ref/p2pool-dash/p2pool/data.py lines 189-217
// "!" is not in base58 alphabet, used as prefix for raw hex-encoded scripts
inline std::vector<unsigned char> decode_payee_script(
    const std::string& payee, uint8_t address_version, uint8_t p2sh_version)
{
    if (payee.empty())
        return {};

    if (payee[0] == '!') {
        // Raw hex script: "!6a28..." → decode hex after "!"
        std::vector<unsigned char> script;
        auto hex = payee.substr(1);
        script.reserve(hex.size() / 2);
        for (size_t i = 0; i + 1 < hex.size(); i += 2)
            script.push_back(static_cast<unsigned char>(
                std::stoul(hex.substr(i, 2), nullptr, 16)));
        return script;
    }

    // Regular base58 address → P2PKH or P2SH script
    std::vector<unsigned char> decoded;
    if (DecodeBase58Check(payee, decoded, 21) && decoded.size() == 21) {
        uint8_t ver = decoded[0];
        if (ver == address_version) {
            // P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
            std::vector<unsigned char> script = {0x76, 0xa9, 0x14};
            script.insert(script.end(), decoded.begin() + 1, decoded.end());
            script.push_back(0x88);
            script.push_back(0xac);
            return script;
        }
        if (ver == p2sh_version) {
            // P2SH: OP_HASH160 <20> OP_EQUAL
            std::vector<unsigned char> script = {0xa9, 0x14};
            script.insert(script.end(), decoded.begin() + 1, decoded.end());
            script.push_back(0x87);
            return script;
        }
    }

    return {};
}

// ── pubkey_hash_to_script2 (Dash: always P2PKH, no segwit) ──────────────────
inline std::vector<unsigned char> pubkey_hash_to_script2(const uint160& hash)
{
    auto h = hash.GetChars();
    std::vector<unsigned char> script;
    script.reserve(25);
    script.push_back(0x76); // OP_DUP
    script.push_back(0xa9); // OP_HASH160
    script.push_back(0x14); // Push 20 bytes
    script.insert(script.end(), h.begin(), h.end());
    script.push_back(0x88); // OP_EQUALVERIFY
    script.push_back(0xac); // OP_CHECKSIG
    return script;
}
// ============================================================================
// Normalize a parent chain script to merged chain P2PKH script.
//
// P2WPKH (00 14 <hash>) → P2PKH (76 a9 14 <hash> 88 ac)  [same pubkey_hash]
// P2PKH  (76 a9 14 <hash> 88 ac) → passed through
// P2SH   (a9 14 <hash> 87)       → P2SH (passed through)
// P2WSH  (00 20 <hash>)          → empty (unconvertible)
// P2TR   (51 20 <key>)           → empty (unconvertible)
//
// Returns empty vector for unconvertible scripts (Tier 3: redistributed).
// Matches Python data.py:build_canonical_merged_coinbase() conversion logic.
// ============================================================================
inline std::vector<unsigned char> normalize_script_for_merged(
    const std::vector<unsigned char>& script)
{
    // P2PKH (25 bytes: 76 a9 14 <20> 88 ac) — already correct
    if (script.size() == 25 && script[0] == 0x76 && script[1] == 0xa9 &&
        script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac)
        return script;

    // P2WPKH (22 bytes: 00 14 <20>) — convert to P2PKH using same hash
    if (script.size() == 22 && script[0] == 0x00 && script[1] == 0x14)
    {
        std::vector<unsigned char> p2pkh;
        p2pkh.reserve(25);
        p2pkh.push_back(0x76); // OP_DUP
        p2pkh.push_back(0xa9); // OP_HASH160
        p2pkh.push_back(0x14); // PUSH 20
        p2pkh.insert(p2pkh.end(), script.begin() + 2, script.end()); // <hash160>
        p2pkh.push_back(0x88); // OP_EQUALVERIFY
        p2pkh.push_back(0xac); // OP_CHECKSIG
        return p2pkh;
    }

    // P2SH (23 bytes: a9 14 <20> 87) — pass through (DOGE supports P2SH)
    if (script.size() == 23 && script[0] == 0xa9 && script[1] == 0x14 &&
        script[22] == 0x87)
        return script;

    // P2WSH (34 bytes: 00 20 <32>) or P2TR (34 bytes: 51 20 <32>) — unconvertible
    return {};
}

// MERGED: prefix for weight map keys — matches p2pool's 'MERGED:' + hex string.
// Keeps Tier 1/1.5 (explicit DOGE script) keys separate from raw LTC script keys
// in the same weight map, preventing V35+V36 weight collapse for the same miner.
// 7 bytes: 0x4d 0x45 0x52 0x47 0x45 0x44 0x3a = "MERGED:"
inline constexpr std::array<unsigned char, 7> MERGED_KEY_PREFIX = {
    0x4d, 0x45, 0x52, 0x47, 0x45, 0x44, 0x3a
};

// Prepend MERGED: prefix to a script for use as a weight map key.
inline std::vector<unsigned char> make_merged_key(
    const std::vector<unsigned char>& script)
{
    std::vector<unsigned char> key;
    key.reserve(MERGED_KEY_PREFIX.size() + script.size());
    key.insert(key.end(), MERGED_KEY_PREFIX.begin(), MERGED_KEY_PREFIX.end());
    key.insert(key.end(), script.begin(), script.end());
    return key;
}

// Check if a weight key has the MERGED: prefix.
inline bool is_merged_key(const std::vector<unsigned char>& key)
{
    return key.size() > MERGED_KEY_PREFIX.size() &&
           std::equal(MERGED_KEY_PREFIX.begin(), MERGED_KEY_PREFIX.end(),
                      key.begin());
}

// Strip MERGED: prefix, returning the raw script bytes.
// Caller must check is_merged_key() first.
inline std::vector<unsigned char> strip_merged_key(
    const std::vector<unsigned char>& key)
{
    return std::vector<unsigned char>(
        key.begin() + MERGED_KEY_PREFIX.size(), key.end());
}

// Resolve a weight map key to a DOGE-compatible scriptPubKey.
// MERGED:-prefixed keys: strip prefix, use directly (already a DOGE script).
// Raw keys: autoconvert (P2WPKH→P2PKH, P2PKH/P2SH pass through).
// Returns empty if unconvertible (P2WSH, P2TR, etc.).
inline std::vector<unsigned char> resolve_merged_payout_script(
    const std::vector<unsigned char>& key)
{
    if (is_merged_key(key))
        return strip_merged_key(key);
    return normalize_script_for_merged(key);
}


// ── get_share_script: full scriptPubKey from a share variant ─────────────────
// DASH is always-P2PKH (no segwit, no v34/v35 address-string form): the payout
// script is pubkey_hash_to_script2(m_pubkey_hash). Mirrors btc::get_share_script
// (share_check.hpp) as the share-layer helper the ShareTracker PPLNS walk needs.
inline std::vector<unsigned char> get_share_script(const auto* obj)
{
    return pubkey_hash_to_script2(obj->m_pubkey_hash);
}

// ── generate_share_transaction (Dash v16 PPLNS) ─────────────────────────────
// Reconstructs the expected coinbase from PPLNS weights.
// Uses the OLD p2pool formula (pre-V36):
//   49/50 to PPLNS weighted workers, 1/50 to finder, remainder to donation.
//   Masternode/superblock/platform payments subtracted from worker_payout first.
//
// Reference: ref/p2pool-dash/p2pool/data.py generate_transaction() lines 131-269
// ─────────────────────────────────────────────────────────────────────────────
//
// out_gentx (optional, default null): when non-null it is filled with the
// regenerated coinbase's non-witness BYTES + its txid (== the returned hash),
// so the won-block reconstructor (reconstruct_won_block.hpp) reuses this ONE
// KAT-proven coinbase byte path instead of re-implementing the DIP3/DIP4 CbTx
// assembly. PURELY ADDITIVE: every existing caller passes nothing (nullptr),
// the coinbase bytes are already built here regardless, and the returned txid
// is byte-identical with or without the out-param -- no accept-path behavior,
// PPLNS math, or committed-txid comparison changes. Mirrors dgb's out_gentx.
template <typename TrackerT>
uint256 generate_share_transaction(const DashShare& share, TrackerT& tracker,
                                   const core::CoinParams& params,
                                   dash::coin::GentxCoinbase* out_gentx = nullptr)
{
    const uint64_t subsidy = share.m_subsidy;

    // ── 1. Compute worker_payout (subsidy minus masternode/superblock payments) ──
    uint64_t payment_total = 0;
    for (auto& pay : share.m_packed_payments)
        payment_total += pay.m_amount;
    uint64_t worker_payout = (subsidy > payment_total) ? (subsidy - payment_total) : 0;

    // ── 2. Compute PPLNS weights (linear, pre-V36) ──
    auto prev_hash = share.m_prev_hash;
    std::map<std::vector<unsigned char>, uint288> weights;
    uint288 total_weight;
    uint288 donation_weight;

    if (!prev_hash.IsNull() && tracker.chain.contains(prev_hash))
    {
        // Oracle (ref/p2pool-dash data.py:181): the PPLNS window starts at
        // previous_share.previous_share_hash -- the GRANDPARENT of the share
        // being built -- NOT at prev_hash itself. Walking from prev_hash shifts
        // the whole window one share toward the tip: it wrongly INCLUDES the
        // direct parent and DROPS the deepest share, so the recomputed coinbase
        // pays a different set of scripts than the producer / oracle mint. This
        // divergence stayed latent because generate_share_transaction had ZERO
        // instantiations before the payout-commitment gate wired it into the
        // accept path; the producer (share_producer.hpp build_share ->
        // get_cumulative_weights) always walked from the grandparent, so the two
        // MUST agree here or a node self-rejects its own freshly-minted shares
        // (invariant c). get_acc_height + start-at-grandparent + the
        // min(max_shares, height) clamp mirror build_share exactly.
        uint256 grandparent;
        tracker.chain.get_share(prev_hash).invoke([&](auto* obj) {
            grandparent = obj->m_prev_hash;
        });

        auto height = tracker.chain.get_acc_height(prev_hash);
        auto chain_len = std::max(0, std::min(height, static_cast<int32_t>(params.real_chain_length)) - 1);

        auto block_target = chain::bits_to_target(share.m_min_header.m_bits);
        auto max_weight = chain::target_to_average_attempts(block_target)
                          * params.spread * 65535;

        // Walk from the grandparent, accumulating per-script weights (linear, no
        // decay). Clamp the count at the grandparent's own height so get_chain
        // never walks past genesis (mirrors get_cumulative_weights'
        // min(max_shares, height) clamp). Iterate by value: ChainView::operator*
        // yields a prvalue pair<hash, chain_data&>, so `auto&` will not bind.
        size_t walk_count = 0;
        if (!grandparent.IsNull() && tracker.chain.contains(grandparent))
            walk_count = static_cast<size_t>(std::min(
                chain_len, tracker.chain.get_acc_height(grandparent)));
        auto walk_view = tracker.chain.get_chain(grandparent, walk_count);

        for (auto [hash, data] : walk_view)
        {
            uint288 share_att;
            uint32_t share_don = 0;
            std::vector<unsigned char> script;

            data.share.invoke([&](auto* obj) {
                auto target = chain::bits_to_target(obj->m_bits);
                share_att = chain::target_to_average_attempts(target);
                share_don = obj->m_donation;
                script = pubkey_hash_to_script2(obj->m_pubkey_hash);
            });

            uint288 share_total = share_att * 65535;
            uint288 share_don_w = share_att * share_don;

            if (total_weight + share_total > max_weight)
            {
                auto remaining = max_weight - total_weight;
                auto share_addr_weight = share_att * static_cast<uint32_t>(65535 - share_don);

                uint288 partial_addr;
                if (!share_total.IsNull())
                    partial_addr = remaining / 65535 * share_addr_weight / (share_total / 65535);

                if (weights.contains(script))
                    weights[script] += partial_addr;
                else
                    weights[script] = partial_addr;

                uint288 partial_donation;
                if (!share_total.IsNull())
                    partial_donation = remaining / 65535 * share_don_w / (share_total / 65535);

                donation_weight += partial_donation;
                total_weight = max_weight;
                break;
            }

            auto share_addr_weight = share_att * static_cast<uint32_t>(65535 - share_don);
            if (weights.contains(script))
                weights[script] += share_addr_weight;
            else
                weights[script] = share_addr_weight;

            total_weight += share_total;
            donation_weight += share_don_w;
        }
    }

    // ── 3. Convert weights to payout amounts (49/50 + 1/50 finder) ──
    std::map<std::vector<unsigned char>, uint64_t> amounts;

    if (!total_weight.IsNull())
    {
        for (auto& [script, weight] : weights)
        {
            // amounts[script] = worker_payout * 49 * weight / (50 * total_weight)
            uint288 num = uint288(worker_payout) * (weight * 49);
            uint288 den = total_weight * 50;
            uint64_t amount = (num / den).GetLow64();
            if (amount > 0)
                amounts[script] = amount;
        }
    }

    // Finder fee: 2% (1/50) to block creator
    auto finder_script = pubkey_hash_to_script2(share.m_pubkey_hash);
    amounts[finder_script] += worker_payout / 50;

    // Donation: any pre-existing DONATION_SCRIPT-keyed amount MERGED with the
    // leftover (rounding + donation weight). This mirrors BOTH authors exactly:
    //   - producer  share_producer.hpp: amounts[donation_script] += (worker_payout - sum)
    //   - oracle    ref/p2pool-dash data.py:223:
    //                 amounts[DONATION_SCRIPT] = amounts.get(DONATION_SCRIPT,0) + worker_payout - sum(...)
    //     (both then emit amounts[DONATION_SCRIPT] as the single donation txout).
    //
    // Reachability: DASH's DONATION_SCRIPT is P2PKH (hash160 20cb5c22...,
    // address XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u), so pubkey_hash_to_script2 of a
    // share whose m_pubkey_hash == that hash160 collides with DONATION_SCRIPT and
    // the finder-fee / PPLNS-weight amount lands in amounts[DONATION_SCRIPT].
    // The previous code subtracted that amount inside sum_amounts, dropped it
    // from worker_outputs, and emitted ONLY the residual -- so the reconstructed
    // coinbase was low by exactly that amount, its txid diverged from the
    // committed gentx_hash, and a VALID share was falsely rejected. Because
    // p2pool-dash (the shared sharechain) and our own producer both preserve it,
    // that was a cross-impl FORK (F11): our nodes orphaned shares the network
    // accepted. Folding it back in makes the reconstruction byte-identical to
    // both authors. Non-colliding shares are unaffected (no DONATION_SCRIPT key
    // in amounts -> donation_amount == residual, exactly as before).
    uint64_t sum_amounts = 0;
    for (auto& [s, a] : amounts)
        sum_amounts += a;
    uint64_t residual = (worker_payout > sum_amounts) ? (worker_payout - sum_amounts) : 0;
    auto don_it = amounts.find(DONATION_SCRIPT);
    uint64_t donation_amount = (don_it != amounts.end() ? don_it->second : 0) + residual;

    // ── 4. Build sorted output list ──
    // worker_scripts: sorted, excluding donation
    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> worker_outputs;
    for (auto& [script, amount] : amounts)
    {
        if (script != DONATION_SCRIPT && amount > 0)
            worker_outputs.emplace_back(script, amount);
    }
    std::sort(worker_outputs.begin(), worker_outputs.end());

    // ── 5. Build coinbase TX ──
    // Output order: worker_tx + payments_tx + donation_tx + OP_RETURN
    PackStream tx;

    // tx version (DIP3/DIP4: version=3, type=5 for CBTX)
    bool has_cbtx = !share.m_coinbase_payload.m_data.empty();
    if (has_cbtx) {
        int32_t ver_with_type = 3 | (5 << 16);
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&ver_with_type), 4));
    } else {
        uint32_t v = 1;
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&v), 4));
    }

    // vin[0]: coinbase
    { unsigned char one = 1; tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&one), 1)); }
    { uint256 z; tx << z; }
    { uint32_t idx = 0xffffffff; tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&idx), 4)); }
    tx << share.m_coinbase;
    { uint32_t seq = 0xffffffff; tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&seq), 4)); }

    // Count outputs
    size_t n_outs = worker_outputs.size() + share.m_packed_payments.size() + 1 /* donation */ + 1 /* OP_RETURN */;
    if (n_outs < 253) {
        uint8_t cnt = static_cast<uint8_t>(n_outs);
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&cnt), 1));
    } else {
        uint8_t marker = 0xfd;
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&marker), 1));
        uint16_t cnt = static_cast<uint16_t>(n_outs);
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&cnt), 2));
    }

    auto write_txout = [&](uint64_t value, const std::vector<unsigned char>& script) {
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&value), 8));
        BaseScript bs;
        bs.m_data = script;
        tx << bs;
    };

    // Worker outputs (sorted)
    for (auto& [script, amount] : worker_outputs)
        write_txout(amount, script);

    // Masternode/superblock/platform payments
    for (auto& pay : share.m_packed_payments)
    {
        if (pay.m_amount == 0) continue;
        auto pay_script = decode_payee_script(
            pay.m_payee, params.address_version, params.address_p2sh_version);
        if (!pay_script.empty())
            write_txout(pay.m_amount, pay_script);
    }

    // Donation output
    write_txout(donation_amount, DONATION_SCRIPT);

    // OP_RETURN ref_hash output (last)
    {
        // Recompute ref_hash (same as share_init_verify)
        PackStream ref_stream;
        {
            auto hex = params.active_identifier_hex();
            for (size_t i = 0; i + 1 < hex.size(); i += 2)
            {
                unsigned char byte = static_cast<unsigned char>(
                    std::stoul(hex.substr(i, 2), nullptr, 16));
                ref_stream.write(std::span<const std::byte>(
                    reinterpret_cast<const std::byte*>(&byte), 1));
            }
        }
        // share_info (same serialization as share_init_verify)
        ref_stream << share.m_prev_hash;
        ref_stream << share.m_coinbase;
        ref_stream << share.m_coinbase_payload;
        ref_stream << share.m_nonce;
        ref_stream << share.m_pubkey_hash;
        ref_stream << share.m_subsidy;
        ref_stream << share.m_donation;
        { uint8_t si = static_cast<uint8_t>(share.m_stale_info); ref_stream << si; }
        ::Serialize(ref_stream, VarInt(share.m_desired_version));
        ref_stream << share.m_payment_amount;
        ref_stream << share.m_packed_payments;
        ref_stream << share.m_new_transaction_hashes;
        // transaction_hash_refs: ListType(VarIntType(), 2) -- writes count/2 then
        // all elements. MUST match share_init_verify byte-for-byte or the
        // recomputed ref_hash (hence the OP_RETURN and the gentx txid) diverges
        // from what the share committed to. The pair_count VarInt was previously
        // omitted here -- invisible while generate_share_transaction had no
        // instantiations, fatal once the payout-commitment gate compares txids.
        {
            uint64_t pair_count = share.m_transaction_hash_refs.size() / 2;
            ::Serialize(ref_stream, VarInt(pair_count));
            for (auto& v : share.m_transaction_hash_refs)
                ::Serialize(ref_stream, VarInt(v));
        }
        ref_stream << share.m_far_share_hash;
        ref_stream << share.m_max_bits;
        ref_stream << share.m_bits;
        ref_stream << share.m_timestamp;
        ref_stream << share.m_absheight;
        ref_stream << share.m_abswork;

        auto rspan = std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(ref_stream.data()), ref_stream.size());
        uint256 hash_ref = Hash(rspan);
        uint256 ref_hash = check_merkle_link(hash_ref, share.m_ref_merkle_link);

        std::vector<unsigned char> op_return_script;
        op_return_script.push_back(0x6a);
        op_return_script.push_back(0x28);
        op_return_script.insert(op_return_script.end(), ref_hash.data(), ref_hash.data() + 32);
        {
            uint64_t nonce = share.m_last_txout_nonce;
            auto* p = reinterpret_cast<const unsigned char*>(&nonce);
            op_return_script.insert(op_return_script.end(), p, p + 8);
        }
        write_txout(0, op_return_script);
    }

    // locktime
    { uint32_t lt = 0; tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&lt), 4)); }

    // DIP3/DIP4 extra_payload
    if (has_cbtx) {
        tx << share.m_coinbase_payload;
    }

    // ── 6. Compute txid ──
    auto tx_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(tx.data()), tx.size());
    uint256 gentx_txid = Hash(tx_span);

    // Additive: expose the coinbase BYTES + txid for the won-block reconstructor.
    // Existing callers pass nullptr and are byte-for-byte unaffected.
    if (out_gentx) {
        out_gentx->bytes.assign(tx_span.begin(), tx_span.end());
        out_gentx->txid = gentx_txid;
    }

    return gentx_txid;
}

// === verify_payout_commitment (Dash accept-path step 3: trustless PPLNS payout) ===
// THE KEYSTONE cross-node-safety gate. Before this, dash's share-accept path
// (share_init_verify) verified only PoW / hash_link / merkle / target -- it NEVER
// checked that a peer's coinbase actually pays the PPLNS window. A malicious peer
// could submit a share with valid PoW whose coinbase pays ONLY itself; it would
// be ACCEPTED, corrupting PPLNS and stealing rewards. This is the port of the
// LTC/btc/dgb "GENTX-MISMATCH" guard (src/impl/ltc/share_check.hpp:1813-1834):
// recompute the expected coinbase from the on-chain PPLNS weights + the share's
// own fields (generate_share_transaction), then require its txid to equal the
// gentx_hash the share's hash_link actually committed to (what the miner hashed).
//
// Oracle: ref/p2pool-dash/p2pool/data.py Share.check() -- gentx =
// generate_transaction(...); assert coinbase commits to gentx. Uses the SHARE's
// own version/fields, so the recompute is byte-identical to the p2pool-dash mint.
//
// INVARIANTS (proven by test_dash_payout_commitment KATs):
//   (a) a share whose coinbase pays the WRONG set (e.g. only the submitter) has a
//       committed gentx_hash != the PPLNS-recomputed expected txid  -> REJECTED.
//   (b) a share whose coinbase pays the CORRECT PPLNS window matches -> ACCEPTED.
//   (c) our own locally-minted shares are NOT self-rejected: the producer
//       (share_producer.hpp build_share -> get_cumulative_weights, walking from
//       the grandparent) and this recompute (generate_share_transaction, same
//       grandparent walk) compute the SAME expected coinbase, so the equality
//       holds for every share this node mints.
//
// gentx_hash is the value share_init_verify cached in g_last_gentx_hash (read it
// on the SAME thread immediately after the share_init_verify that produced it),
// or any equivalently-derived committed txid. Throws std::invalid_argument on a
// mismatch (attempt_verify logs e.what() and drops the share); returns normally
// when the coinbase commitment is correct. No-op until the parent is in-chain,
// since the PPLNS walk needs the ancestor window (matches ltc share_check, which
// only runs the gentx compare when tracker.chain.contains(prev_hash)).
template <typename TrackerT>
inline void verify_payout_commitment(const DashShare& share, TrackerT& tracker,
                                     const core::CoinParams& params,
                                     const uint256& gentx_hash)
{
    if (share.m_prev_hash.IsNull() || !tracker.chain.contains(share.m_prev_hash))
        return;  // genesis / parent not yet in chain -- no PPLNS window to bind

    uint256 expected_gentx = generate_share_transaction(share, tracker, params);
    if (expected_gentx != gentx_hash)
        throw std::invalid_argument(
            "GENTX-MISMATCH: coinbase does not commit to the expected PPLNS payout"
            " (expected " + expected_gentx.ToString().substr(0, 16) +
            " committed " + gentx_hash.ToString().substr(0, 16) + ")");
}

// One sharechain, one share type: a share must be the same TYPE as its parent
// (oracle data.py:382, `type(self) is type(previous)`; a type change is only
// ever a SUCCESSOR switch, and DASH has none). Rejects a v16 share on a v36
// parent and a v36 share on a v16 parent, so a mixed-type chain cannot form on
// either profile. Throws std::invalid_argument.
template <typename WantT, typename ChainT>
inline void check_parent_share_type(ChainT& chain, const uint256& prev_hash)
{
    chain.get_share(prev_hash).invoke([&](auto* parent) {
        using ParentT = std::remove_pointer_t<decltype(parent)>;
        if constexpr (!std::is_same_v<ParentT, WantT>)
            throw std::invalid_argument(
                "mixed share types on one sharechain: v" + std::to_string(WantT::version) +
                " share on a v" + std::to_string(ParentT::version) + " parent");
    });
}

// === verify_version_transition (Dash accept-path step 2: mint<->accept coupling) ===
// Gates which shares the accept path ADMITS at a share-VERSION boundary, closing
// the gap where dash had the version_negotiation primitives KAT-proven in
// isolation but ZERO accept-path consumers (btc/dgb carry this coupling live).
// Composes the already-pinned primitives into the enforcement a node runs on
// every incoming share, mirroring the cross-coin STANDARD shape in
// src/impl/btc/auto_ratchet.hpp::validate_version_switch (60% successor guard)
// and src/impl/btc/share_tracker.hpp::should_punish_version (95% obsolescence)
// so the v37 unification is a clean migration, not a per-coin v36 dialect.
//
// Oracle: ref/p2pool-dash/p2pool/data.py Share.check() lines 384-393 (the
// SUCCESSOR confirmed-state guard). DELIBERATE Bucket-2 standardization: that
// older-oracle branch is DORMANT (Share.SUCCESSOR=None, data.py:71) and, where
// it would fire, gated on 85%-WEIGHTED votes (data.py:392 sum*85//100 over the
// WEIGHTED get_desired_version_counts, data.py:690-691). We standardize to the
// v36/v37 shape -- 60% WEIGHTED successor guard + 95% WEIGHTED v36 activation --
// identical to the btc/dgb live coupling and to the cross-coin standard the
// fleet is converging on for v37. Throws std::invalid_argument on a disallowed
// switch; returns normally when the share is admissible.
template <typename ChainT>
inline void verify_version_transition(const DashShare& share, ChainT& chain,
                                      uint64_t chain_length)
{
    namespace vn = dash::version_negotiation;

    const uint256 prev_hash = share.m_prev_hash;
    if (prev_hash.IsNull() || !chain.contains(prev_hash))
        return;  // genesis / unknown parent -- nothing to gate against

    // Same share type as the parent (no-op on the public network, whose chain
    // only ever holds DashShare).
    check_parent_share_type<DashShare>(chain, prev_hash);

    // Predecessor desired_version (single-share window reuse; no new chain API).
    auto prev_counts = vn::get_desired_version_counts(chain, prev_hash, 1);
    if (prev_counts.empty())
        return;
    const uint64_t prev_version = prev_counts.begin()->first;
    const uint64_t this_version = share.m_desired_version;

    // Not a boundary: a share matching its parent's version was valid when it was
    // minted and is always admitted (data.py:382 type(self) is type(previous)).
    if (this_version == prev_version)
        return;

    const bool have_history =
        chain.get_height(prev_hash) >= static_cast<int64_t>(chain_length);

    // (a) Obsolescence gate -- once v36 holds >= 95% of the WEIGHTED signaling in
    // the CHAIN_LENGTH lookbehind, a pre-v36 share is stale and rejected. Mirrors
    // btc should_punish_version; consumes the WEIGHTED tally (work.py v36_active).
    if (this_version < 36 && have_history)
    {
        auto weights = vn::get_desired_version_weights(chain, prev_hash, chain_length);
        if (vn::v36_active(weights))
            throw std::invalid_argument(
                "share version too old -- v36 has 95%+ weighted activation");
    }

    // (b) SUCCESSOR confirmed-state guard on an UPGRADE boundary: requires both
    // CHAIN_LENGTH history and >= 60% WEIGHTED successor votes in the [9/10..10/10]
    // tail window. data.py:385-393 (standardized 85%-weighted -> 60%-weighted, matching btc share_check.hpp:1781).
    if (this_version > prev_version)
    {
        auto win = vn::negotiation_window(chain, prev_hash, chain_length);
        if (!win)
            throw std::invalid_argument("version switch without enough history");
        auto weights =
            vn::get_desired_version_weights(chain, win->start_hash, win->dist);
        if (!vn::successor_switch_allowed(weights, this_version))
            throw std::invalid_argument(
                "version switch without enough hash power upgraded");
    }
    // Downgrade by AutoRatchet deactivation (this_version < prev_version, not v36-
    // obsolete) is permitted, matching btc validate_version_switch. No gate.
}

// v36 (private/isolated v36 sharechain): the chain is v36 from genesis, so there
// is no version boundary to gate. A genesis v36 share (null / unknown parent) and
// a v36 share on a v36 parent are admitted without any desired_version vote; the
// vote is still tallied (dashboard / AutoRatchet) but never gates admission here.
// Only the share-type rule applies. No successor to v36 exists yet.
template <typename ChainT>
inline void verify_version_transition(const DashV36Share& share, ChainT& chain,
                                      uint64_t /*chain_length*/)
{
    const uint256 prev_hash = share.m_prev_hash;
    if (prev_hash.IsNull() || !chain.contains(prev_hash))
        return;  // genesis v36 / unknown parent
    check_parent_share_type<DashV36Share>(chain, prev_hash);
}


// === verify_share (Dash accept-path COMBINED entry) ==========================
// The single entry a Dash node runs on every incoming share, mirroring
// src/impl/btc/share_check.hpp::verify_share. Composes the two accept phases:
//   Phase 1 (init): share_init_verify -- PoW (X11), hash_link, merkle, target.
//                   CPU-heavy, so a node offloads it to a thread pool (cf.
//                   src/impl/dgb/node.cpp:356 two-phase split) and passes
//                   verify_init=false here when Phase 1 already ran.
//   Phase 2 (chain-context gate): verify_version_transition -- the share-
//                   VERSION boundary admit/reject gate. THIS closes the
//                   enforcement hole: verify_version_transition was KAT-proven
//                   in isolation but had ZERO accept-path consumers, so the v36
//                   obsolescence (95% weighted) + successor (60% weighted)
//                   guards never ran on a real admission path. verify_share is
//                   that consumer; the wired KAT drives the 7 boundary cases
//                   through HERE, not the orphan primitive.
// Bucket-2 structural standardization: same compose shape as btc verify_share,
// so the v37 unification is a clean migration, not a per-coin v36 dialect.
// Returns the Phase-1 share hash (null when verify_init=false). The dashd-RPC
// submitblock fallback is unaffected -- this gates SHARE admission, not block
// submission.
// Both live share types (share.hpp is_live_share); each phase overload-resolves
// on the share type. The share-type admission gate runs first.
template <typename ShareT, typename ChainT>
    requires is_live_share<ShareT>
inline uint256 verify_share(const ShareT& share, ChainT& chain,
                            uint64_t chain_length, const core::CoinParams& params,
                            bool verify_init = true, bool check_pow = true)
{
    check_share_type_admitted(ShareT::version, params);
    uint256 hash;
    if (verify_init)
        hash = share_init_verify(share, params, check_pow);   // Phase 1
    verify_version_transition(share, chain, chain_length);    // Phase 2 (wired gate)
    return hash;
}

// ═══════════════════════════════════════════════════════════════════════════
// DASH v36 generation transaction (DashV36Share, wire-type 36)
//
// Private/isolated DASH v36 sharechain only (custom --network-id). Reached from
// the accept path (share_tracker.hpp attempt_verify) for an admitted v36 share;
// nothing mints a v36 share until the flip slice. Every v16 function above is
// byte-unchanged; the v36 arm is new overloads.
//
// ONE coinbase assembler, build_v36_gentx, is used by the verifier
// (generate_share_transaction(DashV36Share) below) and by the producer
// (share_producer.hpp build_share_v36 / build_gentx_v36), so a node's own v36
// share always passes its own payout-commitment check. The payout math inside
// it is compute_v36_amounts (pplns_v36.hpp) over payout::v36_worker_amount
// (payout_muldiv.hpp) — the same helper the stratum coinbase builder's v36 arm
// uses.
//
// v36 coinbase (no external oracle mints a DASH v36 share; the rules are the
// LTC / p2pool-v36 port with the DASH masternode layer kept from v16):
//   worker_payout = subsidy - Σ(EMITTED payments)       (amount > 0, decodable payee;
//                                                        the oracle / producer rule)
//   weights       = v36_pplns_window(parent)             (decayed, CHAIN_LENGTH, no cap)
//   amounts       = compute_v36_amounts(weights, worker_payout, donation_script)
//   donation_script = params.donation_script_func(36)    (P2PKH DONATION_SCRIPT on the
//                                                        private/isolated profile)
//   outputs       = [miners, script-byte order, amount > 0] [payments, template order]
//                   [donation, always, >= 1 sat when worker_payout > 0]
//                   [OP_RETURN 0x6a 0x28 ref_hash || LE64(last_txout_nonce), value 0]
//   tx layout     = the v16 dash tx_type layout (version/type int16 pair {3,5} +
//                   VarStr(extra_payload) iff coinbase_payload is non-empty).
// Daemonless coinbase-only: a v36 share carries no tx refs; the gentx depends
// only on the share's own fields and the sharechain.
// ═══════════════════════════════════════════════════════════════════════════

// The v36 coinbase bytes, the hash_link prefix cut and the txid.
struct V36Gentx
{
    std::vector<unsigned char> bytes;   // full serialized coinbase tx
    size_t prefix_len{0};               // hash_link prefix cut (bytes before ref_hash || nonce || locktime)
    uint256 txid;                       // sha256d(bytes)
};

// payments_tx for a v36 coinbase: template order, amount > 0 and a payee that
// decodes to a non-empty script (decode_payee_script returns empty for an empty
// payee, an old-protocol "script:" form and an invalid address). Returns the
// emitted outputs and their total — ONLY emitted payments reduce the worker
// payout (the v16 producer / compute_dash_payouts rule; the v16 verifier's
// subtract-all rule is not carried into v36).
inline std::pair<std::vector<std::pair<std::vector<unsigned char>, uint64_t>>, uint64_t>
v36_payments_tx(const std::vector<PackedPayment>& packed_payments, const core::CoinParams& params)
{
    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> out;
    uint64_t emitted = 0;
    for (const auto& pay : packed_payments)
    {
        if (pay.m_amount == 0)
            continue;
        auto script = decode_payee_script(pay.m_payee, params.address_version,
                                          params.address_p2sh_version);
        if (script.empty())
            continue;
        if (emitted > std::numeric_limits<uint64_t>::max() - pay.m_amount)
            throw std::invalid_argument("v36 gentx: payment total overflows");
        emitted += pay.m_amount;
        out.emplace_back(std::move(script), pay.m_amount);
    }
    return {std::move(out), emitted};
}

// THE v36 coinbase assembler (verifier AND producer). `coinbase_payload` is the
// RAW inner DIP4 CbTx payload (empty -> plain version-1 tx).
inline V36Gentx build_v36_gentx(const std::vector<unsigned char>& coinbase_script_sig,
                                const std::vector<unsigned char>& coinbase_payload,
                                uint64_t subsidy,
                                const std::vector<PackedPayment>& packed_payments,
                                const CumulativeWeights& w,
                                const uint256& ref_hash,
                                uint64_t last_txout_nonce,
                                const core::CoinParams& params)
{
    using Script = std::vector<unsigned char>;

    auto [payments_tx, emitted_payments] = v36_payments_tx(packed_payments, params);
    const uint64_t worker_payout = (subsidy > emitted_payments) ? (subsidy - emitted_payments) : 0;

    const Script donation_script = params.donation_script_func(36);
    const V36Amounts a = compute_v36_amounts(w.weights, w.total_weight, worker_payout,
                                             donation_script);
    {
        uint64_t check = a.donation_amount;
        for (const auto& [s, v] : a.amounts)
            check += v;
        if (check != worker_payout)
            throw std::runtime_error("build_v36_gentx: amounts do not sum to worker_payout");
    }

    V36Gentx out;
    auto& b = out.bytes;
    auto put_le = [&](uint64_t v, int n) {
        for (int i = 0; i < n; ++i)
            b.push_back(static_cast<unsigned char>((v >> (8 * i)) & 0xff));
    };
    auto put_varint = [&](uint64_t v) {
        PackStream ps;
        ::Serialize(ps, VarInt(v));
        const auto* p = reinterpret_cast<const unsigned char*>(ps.data());
        b.insert(b.end(), p, p + ps.size());
    };
    auto put_varstr = [&](const Script& s) {
        put_varint(s.size());
        b.insert(b.end(), s.begin(), s.end());
    };
    auto put_txout = [&](uint64_t value, const Script& script) {
        put_le(value, 8);
        put_varstr(script);
    };

    const bool has_cbtx = !coinbase_payload.empty();
    put_le(has_cbtx ? 3u : 1u, 2);                       // version int16
    put_le(has_cbtx ? 5u : 0u, 2);                       // type int16 (5 = CbTx)

    put_varint(1);                                       // one coinbase input
    for (int i = 0; i < 32; ++i) b.push_back(0x00);      //   prev hash 0
    put_le(0xffffffffu, 4);                              //   prev index 2^32-1
    put_varstr(coinbase_script_sig);                     //   scriptSig
    put_le(0xffffffffu, 4);                              //   sequence

    put_varint(a.amounts.size() + payments_tx.size() + 1 /*donation*/ + 1 /*OP_RETURN*/);
    for (const auto& [script, amount] : a.amounts)       // script-byte order, amount > 0
        put_txout(amount, script);
    for (const auto& [script, amount] : payments_tx)     // template order
        put_txout(amount, script);
    put_txout(a.donation_amount, donation_script);       // always; last before OP_RETURN
    {
        Script op_ret;
        op_ret.reserve(2 + 32 + 8);
        op_ret.push_back(0x6a);
        op_ret.push_back(0x28);
        op_ret.insert(op_ret.end(), ref_hash.data(), ref_hash.data() + 32);
        for (int i = 0; i < 8; ++i)
            op_ret.push_back(static_cast<unsigned char>((last_txout_nonce >> (8 * i)) & 0xff));
        put_txout(0, op_ret);
    }

    put_le(0, 4);                                        // lock_time

    size_t payload_varstr_size = 0;
    if (has_cbtx)
    {
        const size_t before = b.size();
        put_varstr(coinbase_payload);                    // extra_payload VarStr
        payload_varstr_size = b.size() - before;
    }

    // prefix = bytes[: -(payload VarStr) - 32 ref_hash - 8 nonce - 4 locktime]
    out.prefix_len = b.size() - payload_varstr_size - 44;
    out.txid = Hash(std::span<const unsigned char>(b.data(), b.size()));
    return out;
}

// The v36 window for `prev_hash`, through the tracker's cached form when the
// tracker provides one (the live ShareTracker, whose cache think() primes from
// the ring buffer under the same key), otherwise the free rule over
// tracker.chain. Both evaluate v36_pplns_window.
template <typename TrackerT>
inline CumulativeWeights v36_window_for(TrackerT& tracker, const uint256& prev_hash)
{
    if constexpr (requires { tracker.v36_pplns_window(prev_hash); })
        return tracker.v36_pplns_window(prev_hash);
    else
        return v36_pplns_window(tracker.chain, prev_hash);
}

// ── generate_share_transaction (Dash v36) ────────────────────────────────────
// The expected coinbase of a v36 share, from the sharechain and the share's own
// fields; returns its txid. out_gentx (optional) receives the bytes + txid for
// the won-block reconstructor, as on v16.
template <typename TrackerT>
uint256 generate_share_transaction(const DashV36Share& share, TrackerT& tracker,
                                   const core::CoinParams& params,
                                   dash::coin::GentxCoinbase* out_gentx = nullptr)
{
    const CumulativeWeights w = v36_window_for(tracker, share.m_prev_hash);
    const uint256 ref_hash = compute_v36_ref_hash(params, share);
    const V36Gentx g = build_v36_gentx(share.m_coinbase.m_data, share.m_coinbase_payload.m_data,
                                       share.m_subsidy, share.m_packed_payments, w, ref_hash,
                                       share.m_last_txout_nonce, params);
    if (out_gentx)
    {
        out_gentx->bytes = g.bytes;
        out_gentx->txid = g.txid;
    }
    return g.txid;
}

// ── verify_payout_commitment (Dash v36) ──────────────────────────────────────
// Same gate, same message as the v16 overload: the txid the share's hash_link
// committed to (share_init_verify's g_last_gentx_hash) must equal the expected
// v36 coinbase. No-op while the parent is not in the chain.
template <typename TrackerT>
inline void verify_payout_commitment(const DashV36Share& share, TrackerT& tracker,
                                     const core::CoinParams& params,
                                     const uint256& gentx_hash)
{
    if (share.m_prev_hash.IsNull() || !tracker.chain.contains(share.m_prev_hash))
        return;  // genesis / parent not yet in chain -- no PPLNS window to bind

    uint256 expected_gentx = generate_share_transaction(share, tracker, params);
    if (expected_gentx != gentx_hash)
        throw std::invalid_argument(
            "GENTX-MISMATCH: coinbase does not commit to the expected PPLNS payout"
            " (expected " + expected_gentx.ToString().substr(0, 16) +
            " committed " + gentx_hash.ToString().substr(0, 16) + ")");
}

} // namespace dash
