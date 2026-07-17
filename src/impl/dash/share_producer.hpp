// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ============================================================================
// share_producer.hpp — DASH producer-side share construction (mint campaign
// slice 1/3): prospective share_info assembly, ref_hash / hash_link producers,
// oracle retarget, gentx byte assembly and the full DashShare build with a
// MANDATORY self-verify against the in-tree verifier (share_check.hpp).
//
// ORACLE: github.com/frstrtr/p2pool-dash (master, python2). Every function
// below is a hand-trace of the oracle source; citations are to p2pool/data.py
// (share machinery), p2pool/dash/data.py (coin serialization / FloatingInteger)
// and p2pool/networks/dash.py (consensus constants). The live network is the
// pre-v36 v16 lineage: a share whose bytes diverge from what the oracle's
// Share.__init__/check() reproduce is rejected — and a PoW-invalid
// reconstruction is a PeerMisbehavingError (BAN). Byte parity is therefore a
// HARD constraint on every function in this header.
//
// Structure mirrors the DGB mint campaign (src/impl/dgb/run_loop_mint.hpp +
// src/impl/dgb/coin/work_ref_hash.hpp): pure, tracker-free cores where
// possible; thin ChainT-templated wrappers for the chain-position walks.
// NOTHING here is wired into --run or stratum (slices 2-3 do the binding via
// DASHWorkSource::MintShareFn / PplnsWeightsFn).
//
// DELIBERATE divergences from EXISTING in-tree code (all oracle-conform, see
// the per-function notes; these are the review hotspots):
//   1. Retarget: ShareTracker::compute_share_target carries a v36 emergency
//      time-decay (share_tracker.hpp "Step 3") that does NOT exist in the
//      p2pool-dash oracle. The mint path must not use it — compute_share_target
//      below is the oracle formula only (data.py:137-145).
//   2. PPLNS weights window: the oracle starts the cumulative-weights walk at
//      previous_share.previous_share_hash (data.py:181), i.e. the GRANDPARENT
//      of the share being built. share_check.hpp::generate_share_transaction
//      walks from prev_hash itself — off by one vs the oracle. The producer
//      implements the oracle window.
//   3. worker_payout: the oracle subtracts only payments actually EMITTED as
//      outputs (valid payee, amount > 0 — data.py:191-218); the verifier
//      subtracts every packed_payments amount unconditionally. The producer
//      implements the oracle rule.
// ============================================================================

#include "share.hpp"
#include "share_types.hpp"
#include "share_chain.hpp"   // dash::ShareHasher (tx-ref dedup map)
#include "share_check.hpp"   // DONATION_SCRIPT, decode_payee_script, pubkey_hash_to_script2,
                             // check_merkle_link, check_hash_link, compute_gentx_before_refhash,
                             // share_init_verify

#include <core/coin_params.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>
#include <btclibs/crypto/common.h>
#include <btclibs/crypto/sha256.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <map>
#include <span>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace dash::producer
{

// ── small helpers ────────────────────────────────────────────────────────────

// math.clip(x, (low, high)) — p2pool/util/math.py:40. Low bound wins first.
template <typename T>
inline T clip(const T& x, const T& low, const T& high)
{
    if (x < low) return low;
    if (x > high) return high;
    return x;
}

// uint288 -> uint128 truncation (mod 2^128), for the oracle's
// "% 2**128" abswork accumulation (data.py:245). Hex-based so attempts
// above 2^64 (unrealistically hard shares) still accumulate exactly.
inline uint128 low128(const uint288& v)
{
    const std::string hex = v.GetHex();              // 72 hex chars, big-endian
    uint128 out;
    out.SetHex(hex.substr(hex.size() - 32));         // low 128 bits
    return out;
}

// Append the raw bytes of a PackStream to a byte vector.
inline void append_stream(std::vector<unsigned char>& out, PackStream& s)
{
    auto* p = reinterpret_cast<const unsigned char*>(s.data());
    out.insert(out.end(), p, p + s.size());
}

// ── 1a. Oracle retarget (data.py:135-145 + networks/dash.py) ─────────────────
//
//   if height < net.TARGET_LOOKBEHIND (100):
//       pre_target3 = net.MAX_TARGET
//   else:
//       aps = get_pool_attempts_per_second(tracker, prev, 100, min_work=True, integer=True)
//       pre_target  = 2**256//(net.SHARE_PERIOD*aps) - 1  if aps else 2**256-1
//       pre_target2 = clip(pre_target, (prev.max_target*9//10, prev.max_target*11//10))
//       pre_target3 = clip(pre_target2, (net.MIN_TARGET (=0), net.MAX_TARGET))
//   max_bits = FloatingInteger.from_target_upper_bound(pre_target3)
//   bits     = FloatingInteger.from_target_upper_bound(clip(desired_target,
//                                          (pre_target3//30, pre_target3)))
//
// NO emergency time-decay: the oracle has none (that step is a p2pool-v36-ism
// present in ShareTracker::compute_share_target and MUST NOT be used to mint).
// chain::target_to_bits_upper_bound is mantissa-TRUNCATING, matching the
// oracle's FloatingInteger.from_target_upper_bound (dash/data.py:44-50) —
// pinned by the DashShareProducerRetarget KATs.

struct ShareTarget
{
    uint32_t max_bits{0};
    uint32_t bits{0};
};

// Pure core over explicit inputs. have_lookbehind == (height(prev) >=
// TARGET_LOOKBEHIND); aps is the already-floored integer attempts/second on
// the min_work basis (integer=True).
inline ShareTarget compute_share_target_pure(bool have_lookbehind,
                                             const uint288& aps,
                                             const uint256& prev_max_target,
                                             const uint256& desired_target,
                                             uint32_t share_period,
                                             const uint256& max_target)
{
    uint256 pre_target3;

    if (!have_lookbehind)
    {
        pre_target3 = max_target;
    }
    else
    {
        // pre_target — exact big-int: 2**256//(SHARE_PERIOD*aps) - 1
        uint288 pre_target;
        if (aps.IsNull())
        {
            // 2**256 - 1
            pre_target.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        }
        else
        {
            uint288 two_256;
            two_256.SetHex("10000000000000000000000000000000000000000000000000000000000000000");
            uint288 divisor = aps * share_period;
            pre_target = two_256 / divisor;
            // Python: q - 1. q == 0 gives -1 there; the subsequent lower clip
            // to prev.max_target*9//10 maps both -1 and 0 to the same result
            // (the clip low bound), so saturating at 0 is value-identical.
            if (!pre_target.IsNull())
                pre_target = pre_target - uint288(1);
        }

        // pre_target2 = clip(pre_target, prev.max_target*9//10, *11//10)
        uint288 lo, hi;
        {
            uint288 pm;
            pm.SetHex(prev_max_target.GetHex());
            lo = pm * 9;  lo = lo / 10;
            hi = pm * 11; hi = hi / 10;
        }
        uint288 pre_target2 = clip(pre_target, lo, hi);

        // pre_target3 = clip(pre_target2, MIN_TARGET=0, MAX_TARGET)
        uint288 max_288;
        max_288.SetHex(max_target.GetHex());
        if (pre_target2 > max_288)
            pre_target3 = max_target;
        else
            pre_target3.SetHex(pre_target2.GetHex());
    }

    ShareTarget out;
    out.max_bits = chain::target_to_bits_upper_bound(pre_target3);

    // bits = from_target_upper_bound(clip(desired, pre_target3//30, pre_target3))
    // pre_target3 stays FULL precision here (not re-derived from the compact).
    const uint256 bits_lo = pre_target3 / 30;
    out.bits = chain::target_to_bits_upper_bound(
        clip(desired_target, bits_lo, pre_target3));
    return out;
}

// get_pool_attempts_per_second — data.py:643-653, min_work=True, integer=True.
//   near = prev; far = nth_parent(prev, dist-1)
//   attempts = delta(near, far).min_work; time = near.ts - far.ts (<=0 -> 1)
//   return attempts // time
// Mirrors ShareTracker::get_pool_attempts_per_second but is the mint-path SSOT
// (tracker-free, no diagnostics); the time span is int64 — the oracle's exact
// unbounded-int subtraction — where the tracker copy clamps through int32.
template <typename ChainT>
inline uint288 pool_attempts_per_second(ChainT& chain, const uint256& prev_hash,
                                        int32_t dist)
{
    if (dist < 2 || !chain.contains(prev_hash))
        return uint288(0);
    // Boundary guard: the oracle only calls this with height >= dist (the
    // TARGET_LOOKBEHIND gate). Enforce it HERE too so no future caller can
    // receive a silently-wrong span from the skip list's exhaust fallback.
    if (chain.get_acc_height(prev_hash) < dist)
        return uint288(0);
    const uint256 far_hash = chain.get_nth_parent_via_skip(prev_hash, dist - 1);
    if (far_hash.IsNull() || !chain.contains(far_hash))
        return uint288(0);

    auto delta = chain.get_delta(prev_hash, far_hash);
    const uint288 attempts = delta.min_work;

    uint32_t near_ts = 0, far_ts = 0;
    chain.get_share(prev_hash).invoke([&](auto* obj) { near_ts = obj->m_timestamp; });
    chain.get_share(far_hash).invoke([&](auto* obj) { far_ts = obj->m_timestamp; });
    int64_t time_span = static_cast<int64_t>(near_ts) - static_cast<int64_t>(far_ts);
    if (time_span <= 0)
        time_span = 1;
    return attempts / uint288(static_cast<uint64_t>(time_span));
}

// Chain wrapper: resolve height / aps / prev max_target off the live chain.
template <typename ChainT>
inline ShareTarget compute_share_target(ChainT& chain, const uint256& prev_hash,
                                        const uint256& desired_target,
                                        const core::CoinParams& params)
{
    const uint256 max_target = params.max_target;

    if (prev_hash.IsNull() || !chain.contains(prev_hash))
        return compute_share_target_pure(false, uint288(0), uint256(),
                                         desired_target,
                                         static_cast<uint32_t>(params.share_period),
                                         max_target);

    const int32_t height = chain.get_acc_height(prev_hash);
    if (height < static_cast<int32_t>(params.target_lookbehind))
        return compute_share_target_pure(false, uint288(0), uint256(),
                                         desired_target,
                                         static_cast<uint32_t>(params.share_period),
                                         max_target);

    const uint288 aps = pool_attempts_per_second(
        chain, prev_hash, static_cast<int32_t>(params.target_lookbehind));

    uint256 prev_max_target;
    chain.get_share(prev_hash).invoke([&](auto* obj) {
        prev_max_target = chain::bits_to_target(obj->m_max_bits);
    });

    return compute_share_target_pure(true, aps, prev_max_target, desired_target,
                                     static_cast<uint32_t>(params.share_period),
                                     max_target);
}

// ── 1b. Timestamp clip (data.py:238-241) ─────────────────────────────────────
// clip(desired, (prev.timestamp + 1, prev.timestamp + 2*SHARE_PERIOD - 1));
// no previous share -> desired unchanged.
inline uint32_t clip_timestamp(uint32_t desired, bool has_prev, uint32_t prev_ts,
                               uint32_t share_period)
{
    if (!has_prev)
        return desired;
    const uint32_t lo = prev_ts + 1;
    const uint32_t hi = prev_ts + 2 * share_period - 1;
    return clip(desired, lo, hi);
}

// ── 1c. far_share_hash (data.py:235) ─────────────────────────────────────────
//   None if last is None and height < 99 else tracker.get_nth_parent_hash(prev, 99)
// Guarded manual walk: 99 prev-pointer hops from prev; falling off the tracked
// chain yields null — the value the oracle's PossiblyNone(0) packs for the
// genesis-parent (None) at exactly height == 99.
template <typename ChainT>
inline uint256 compute_far_share_hash(ChainT& chain, const uint256& prev_hash)
{
    if (prev_hash.IsNull() || !chain.contains(prev_hash))
        return uint256();
    if (chain.get_acc_height(prev_hash) < 99)
        return uint256();
    uint256 cur = prev_hash;
    for (int i = 0; i < 99; ++i)
    {
        auto* idx = chain.get_index(cur);
        if (!idx)
            return uint256();
        cur = idx->tail;
        if (cur.IsNull() || !chain.contains(cur))
            return uint256();   // walked past the tracked tail -> oracle None
    }
    return cur;
}

// ── 1d. Transaction forwarding refs (data.py:147-170) ────────────────────────
//
//   past_shares = get_chain(prev, min(height, 100))       # prev at i == 0
//   tx_hash_to_this[tx_hash] = [1+i, j]  (first-seen wins)  # share_count, tx_count
//   for tx_hash in desired: known -> that pair; else new -> [0, len(new)-1]
//
// share_count is the distance from the share being BUILT (itself 0), hence
// the 1+i offset. The oracle __init__ asserts share_count < 110 on receive
// (data.py:337); walking min(height, 100) parents keeps 1+i <= 100.
struct TxRefs
{
    std::vector<uint256>  new_transaction_hashes;
    std::vector<uint64_t> transaction_hash_refs;    // flattened [share_count, tx_count] pairs
    std::vector<uint256>  other_transaction_hashes; // the job's tx set, template order
};

template <typename ChainT>
inline TxRefs assemble_tx_refs(ChainT& chain, const uint256& prev_hash,
                               const std::vector<uint256>& desired_tx_hashes)
{
    TxRefs out;

    std::unordered_map<uint256, std::pair<uint64_t, uint64_t>, ShareHasher> tx_hash_to_this;
    if (!prev_hash.IsNull() && chain.contains(prev_hash))
    {
        const int32_t height = chain.get_acc_height(prev_hash);
        const uint64_t count = static_cast<uint64_t>(std::min<int32_t>(height, 100));
        uint64_t i = 0;
        for (auto [hash, data] : chain.get_chain(prev_hash, count))
        {
            data.share.invoke([&](auto* obj) {
                for (uint64_t j = 0; j < obj->m_new_transaction_hashes.size(); ++j)
                {
                    const uint256& h = obj->m_new_transaction_hashes[j];
                    tx_hash_to_this.try_emplace(h, 1 + i, j);   // first-seen wins
                }
            });
            ++i;
        }
    }

    for (const auto& tx_hash : desired_tx_hashes)
    {
        auto it = tx_hash_to_this.find(tx_hash);
        if (it != tx_hash_to_this.end())
        {
            out.transaction_hash_refs.push_back(it->second.first);
            out.transaction_hash_refs.push_back(it->second.second);
        }
        else
        {
            out.new_transaction_hashes.push_back(tx_hash);
            out.transaction_hash_refs.push_back(0);
            out.transaction_hash_refs.push_back(out.new_transaction_hashes.size() - 1);
        }
        out.other_transaction_hashes.push_back(tx_hash);
    }
    return out;
}

// ── 1e. Cumulative PPLNS weights, ORACLE window (data.py:181-184) ────────────
//
//   weights, total, donation = tracker.get_cumulative_weights(
//       previous_share.previous_share_hash,            # the GRANDPARENT
//       max(0, min(height, REAL_CHAIN_LENGTH) - 1),
//       65535*SPREAD*target_to_average_attempts(block_target))
//
// Linear walk equivalent of the oracle WeightsSkipList (data.py:456-491):
// per share delta {script: att*(65535-donation)}, att*65535 toward the grand
// total, att*donation toward the donation pool; the overshooting share is
// included PARTIALLY with the oracle's exact integer division order
// (data.py:478-481). NOTE the window START — the in-tree verifier
// (generate_share_transaction) walks from prev itself; the oracle walks from
// prev.prev. The producer implements the oracle.
struct CumulativeWeights
{
    std::map<std::vector<unsigned char>, uint288> weights;
    uint288 total_weight;      // grand total INCLUDING donation weight
    uint288 donation_weight;
};

template <typename ChainT>
inline CumulativeWeights get_cumulative_weights(ChainT& chain,
                                                const uint256& start_hash,
                                                int32_t max_shares,
                                                const uint288& desired_weight)
{
    CumulativeWeights out;
    if (start_hash.IsNull() || !chain.contains(start_hash) || max_shares <= 0)
        return out;

    const int32_t height = chain.get_acc_height(start_hash);
    const uint64_t count =
        static_cast<uint64_t>(std::min<int32_t>(max_shares, height));

    for (auto [hash, data] : chain.get_chain(start_hash, count))
    {
        uint288 att;
        uint32_t don = 0;
        std::vector<unsigned char> script;
        data.share.invoke([&](auto* obj) {
            att = chain::target_to_average_attempts(chain::bits_to_target(obj->m_bits));
            don = obj->m_donation;
            script = pubkey_hash_to_script2(obj->m_pubkey_hash);
        });

        const uint288 share_total = att * 65535u;                       // toward grand total
        const uint288 share_addr_w = att * static_cast<uint32_t>(65535 - don);
        const uint288 share_don_w = att * don;

        if (out.total_weight + share_total > desired_weight)
        {
            // Partial inclusion — oracle apply_delta (data.py:478-481):
            //   new_w = (desired-total1)//65535 * w2 // (total2//65535)
            const uint288 remaining = desired_weight - out.total_weight;
            uint288 partial_addr, partial_don;
            if (!share_total.IsNull())
            {
                partial_addr = remaining / 65535u * share_addr_w / (share_total / 65535u);
                partial_don  = remaining / 65535u * share_don_w  / (share_total / 65535u);
            }
            out.weights[script] += partial_addr;
            out.donation_weight += partial_don;
            out.total_weight = desired_weight;
            break;
        }

        out.weights[script] += share_addr_w;
        out.total_weight += share_total;
        out.donation_weight += share_don_w;
    }
    return out;
}

// ── Prospective share_info ───────────────────────────────────────────────────

// Job-time inputs the caller resolves from (live tip, miner identity, GBT
// work template DashWorkData, vardiff). All values explicit — no tracker
// access happens beyond what generate_prospective_share_info walks itself.
struct ProducerJobInputs
{
    uint256 prev_share_hash;                      // live sharechain tip (null for genesis)
    std::vector<unsigned char> coinbase_scriptSig; // share_data['coinbase'], 2..100 bytes
    std::vector<unsigned char> coinbase_payload;   // RAW DIP4 CbTx extra payload ('' -> none)
    uint32_t share_nonce{0};                       // share_data['nonce']
    uint160  pubkey_hash;                          // miner identity (P2PKH basis)
    uint64_t subsidy{0};                           // GBT coinbasevalue (all fees known)
    uint16_t donation{0};                          // share_data['donation'] (per-miner --give-author)
    StaleInfo stale_info{StaleInfo::none};
    uint64_t desired_version{16};
    uint64_t payment_amount{0};                    // GBT masternode/superblock total
    std::vector<PackedPayment> packed_payments;    // GBT payment list (template order)
    std::vector<uint256> desired_tx_hashes;        // GBT tx set (template order)
    uint32_t desired_timestamp{0};
    uint256  desired_target;                       // vardiff target (pre-clip)
};

// The assembled share_info + the job tx set the merkle_link derives from.
struct ProspectiveShareInfo
{
    // share_data
    uint256 prev_hash;
    std::vector<unsigned char> coinbase;
    std::vector<unsigned char> coinbase_payload;   // RAW payload
    uint32_t nonce{0};
    uint160  pubkey_hash;
    uint64_t subsidy{0};
    uint16_t donation{0};
    StaleInfo stale_info{StaleInfo::none};
    uint64_t desired_version{16};
    uint64_t payment_amount{0};
    std::vector<PackedPayment> packed_payments;

    // share_info proper
    std::vector<uint256>  new_transaction_hashes;
    std::vector<uint64_t> transaction_hash_refs;
    uint256  far_share_hash;
    uint32_t max_bits{0};
    uint32_t bits{0};
    uint32_t timestamp{0};
    uint32_t absheight{0};
    uint128  abswork;

    // job context (NOT serialized into the ref preimage)
    std::vector<uint256> other_transaction_hashes;
};

// Full prospective assembly at job time — the producer half of the oracle's
// generate_transaction() (data.py:132-246) up to and including share_info.
template <typename ChainT>
inline ProspectiveShareInfo generate_prospective_share_info(
    ChainT& chain, const core::CoinParams& params, const ProducerJobInputs& in)
{
    ProspectiveShareInfo info;

    info.prev_hash        = in.prev_share_hash;
    info.coinbase         = in.coinbase_scriptSig;
    info.coinbase_payload = in.coinbase_payload;
    info.nonce            = in.share_nonce;
    info.pubkey_hash      = in.pubkey_hash;
    info.subsidy          = in.subsidy;      // all template fees known -> unchanged (data.py:172-179)
    info.donation         = in.donation;
    info.stale_info       = in.stale_info;
    info.desired_version  = in.desired_version;
    info.payment_amount   = in.payment_amount;
    info.packed_payments  = in.packed_payments;

    // Retarget (oracle formula — see compute_share_target notes).
    const ShareTarget st =
        compute_share_target(chain, in.prev_share_hash, in.desired_target, params);
    info.max_bits = st.max_bits;
    info.bits     = st.bits;

    // Tx forwarding refs over the past min(height, 100) shares.
    TxRefs refs = assemble_tx_refs(chain, in.prev_share_hash, in.desired_tx_hashes);
    info.new_transaction_hashes  = std::move(refs.new_transaction_hashes);
    info.transaction_hash_refs   = std::move(refs.transaction_hash_refs);
    info.other_transaction_hashes = std::move(refs.other_transaction_hashes);

    // far_share_hash ancestor walk.
    info.far_share_hash = compute_far_share_hash(chain, in.prev_share_hash);

    // timestamp clip + absheight/abswork accumulation off the previous share.
    bool has_prev = !in.prev_share_hash.IsNull() && chain.contains(in.prev_share_hash);
    uint32_t prev_ts = 0, prev_absheight = 0;
    uint128 prev_abswork;
    if (has_prev)
    {
        chain.get_share(in.prev_share_hash).invoke([&](auto* obj) {
            prev_ts        = obj->m_timestamp;
            prev_absheight = obj->m_absheight;
            prev_abswork   = obj->m_abswork;
        });
    }
    info.timestamp = clip_timestamp(in.desired_timestamp, has_prev, prev_ts,
                                    static_cast<uint32_t>(params.share_period));

    // absheight = (prev + 1) % 2^32; abswork = (prev + ata(bits.target)) % 2^128
    // (data.py:244-245). base_uint addition already wraps at the type width.
    info.absheight = prev_absheight + 1;
    info.abswork = prev_abswork +
        low128(chain::target_to_average_attempts(chain::bits_to_target(info.bits)));

    return info;
}

// ── 2. ref_hash producer ─────────────────────────────────────────────────────

// Serialize share_info exactly as the v16 ref preimage expects it — field for
// field the layout share_init_verify / DashFormatter consume (share_info_type,
// data.py:81-106). MUST stay byte-identical to the verifier's ref_stream
// assembly in share_check.hpp (KAT: ProducerRefStreamEqualsVerifierMirror).
inline void serialize_share_info(PackStream& os, const ProspectiveShareInfo& info)
{
    os << info.prev_hash;                              // PossiblyNone(0, IntType(256))
    { BaseScript bs; bs.m_data = info.coinbase; os << bs; }              // VarStr
    { BaseScript bs; bs.m_data = info.coinbase_payload; os << bs; }      // PossiblyNone('', VarStr)
    os << info.nonce;
    os << info.pubkey_hash;
    os << info.subsidy;
    os << info.donation;
    { uint8_t si = static_cast<uint8_t>(info.stale_info); os << si; }
    { uint64_t dv = info.desired_version; ::Serialize(os, VarInt(dv)); }
    os << info.payment_amount;
    {
        uint64_t count = info.packed_payments.size();
        ::Serialize(os, VarInt(count));
        for (const auto& pay : info.packed_payments)
        {
            BaseScript bs;
            bs.m_data.assign(pay.m_payee.begin(), pay.m_payee.end());
            os << bs;
            os << pay.m_amount;
        }
    }
    os << info.new_transaction_hashes;                 // ListType(IntType(256))
    {
        // ListType(VarIntType(), 2): PAIR count, then all elements
        uint64_t pair_count = info.transaction_hash_refs.size() / 2;
        ::Serialize(os, VarInt(pair_count));
        for (uint64_t v : info.transaction_hash_refs)
            ::Serialize(os, VarInt(v));
    }
    os << info.far_share_hash;                         // PossiblyNone(0, IntType(256))
    os << info.max_bits;
    os << info.bits;
    os << info.timestamp;
    os << info.absheight;
    os << info.abswork;
}

// get_ref_hash (data.py:296-301): sha256d(ref_type.pack({identifier,
// share_info})) folded through the ref merkle link. The producer uses an
// EMPTY ref_merkle_link (data.py:285: dict(branch=[], index=0)).
inline uint256 compute_ref_hash(const core::CoinParams& params,
                                const ProspectiveShareInfo& info,
                                const MerkleLink& ref_merkle_link = MerkleLink{})
{
    PackStream ref_stream;
    {
        const std::string hex = params.active_identifier_hex();
        for (size_t i = 0; i + 1 < hex.size(); i += 2)
        {
            unsigned char byte = static_cast<unsigned char>(
                std::stoul(hex.substr(i, 2), nullptr, 16));
            ref_stream.write(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(&byte), 1));
        }
    }
    serialize_share_info(ref_stream, info);

    auto sp = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(ref_stream.data()), ref_stream.size());
    return check_merkle_link(Hash(sp), ref_merkle_link);
}

// ── gentx byte assembly (data.py:187-268 + dash/data.py tx_type) ─────────────

struct GentxResult
{
    std::vector<unsigned char> bytes;   // full serialized coinbase tx
    size_t prefix_len{0};               // hash_link prefix cut (data.py:280)
    uint256 txid;                       // sha256d(bytes)
};

// Build the FULL oracle coinbase for the prospective share.
//   Output order: worker_tx (sorted, no donation) || payments_tx (template
//   order, valid payees, amount>0) || donation_tx || OP_RETURN(ref_hash ||
//   last_txout_nonce).
//   worker_payout = subsidy - Σ(EMITTED payments)   (oracle rule, data.py:187-218)
//   amounts[s]        = worker_payout*49*weight // (50*total_weight)
//   amounts[finder]  += worker_payout // 50
//   amounts[DONATION] = existing + worker_payout - Σ(amounts)   (data.py:220-223)
// tx serialization is the oracle dash tx_type: version int16 + type int16,
// coinbase input, outputs, lock_time, then VarStr(extra_payload) iff
// version>=3 and type!=0 (dash/data.py:96-114).
inline GentxResult build_gentx(const ProspectiveShareInfo& info,
                               const CumulativeWeights& w,
                               const uint256& ref_hash,
                               uint64_t last_txout_nonce,
                               const core::CoinParams& params)
{
    using Script = std::vector<unsigned char>;
    const Script donation_script(DONATION_SCRIPT.begin(), DONATION_SCRIPT.end());

    // payments_tx — template order; skip empty/'script:'/undecodable payees and
    // zero amounts; ONLY emitted payments reduce worker_payout (oracle rule).
    std::vector<std::pair<Script, uint64_t>> payments_tx;
    uint64_t emitted_payments = 0;
    for (const auto& pay : info.packed_payments)
    {
        if (pay.m_amount == 0 || pay.m_payee.empty())
            continue;
        if (pay.m_payee.rfind("script:", 0) == 0)
            continue;                                   // old-protocol form, skipped (data.py:204-206)
        Script s = decode_payee_script(pay.m_payee, params.address_version,
                                       params.address_p2sh_version);
        if (s.empty())
            continue;                                   // invalid address, skipped (data.py:209-214)
        payments_tx.emplace_back(std::move(s), pay.m_amount);
        emitted_payments += pay.m_amount;
    }
    const uint64_t worker_payout =
        (info.subsidy > emitted_payments) ? (info.subsidy - emitted_payments) : 0;

    // PPLNS amounts (exact integer division order; uint288 intermediates).
    std::map<Script, uint64_t> amounts;
    if (!w.total_weight.IsNull())
    {
        for (const auto& [script, weight] : w.weights)
        {
            const uint288 num = uint288(worker_payout) * (weight * 49u);
            const uint288 den = w.total_weight * 50u;
            const uint64_t amount = (num / den).GetLow64();
            amounts[script] = amount;                    // 0-amounts dropped at emit
        }
    }
    const Script finder_script = pubkey_hash_to_script2(info.pubkey_hash);
    amounts[finder_script] += worker_payout / 50;        // 2% block finder

    // amounts[DONATION] = existing + worker_payout - Σ(all amounts) — the
    // existing weight-derived donation entry is PRESERVED (oracle
    // amounts.get(DONATION_SCRIPT, 0) + ...), unlike the verifier's rebuild.
    {
        uint64_t sum = 0;
        for (const auto& [s, a] : amounts) sum += a;
        if (sum > worker_payout)
            throw std::runtime_error("build_gentx: amounts exceed worker_payout");
        amounts[donation_script] += (worker_payout - sum);
    }

    // worker_tx: sorted scripts (std::map order == python sorted(str)),
    // excluding DONATION, dropping zero amounts (data.py:228-229).
    std::vector<std::pair<Script, uint64_t>> worker_tx;
    for (const auto& [script, amount] : amounts)
    {
        if (script == donation_script || amount == 0)
            continue;
        worker_tx.emplace_back(script, amount);
    }

    // ── serialize (oracle dash tx_type layout) ──
    GentxResult out;
    auto& b = out.bytes;
    auto put_le = [&](uint64_t v, int n) {
        for (int i = 0; i < n; ++i)
            b.push_back(static_cast<unsigned char>((v >> (8 * i)) & 0xff));
    };
    auto put_varint = [&](uint64_t v) {
        PackStream ps; ::Serialize(ps, VarInt(v)); append_stream(b, ps);
    };
    auto put_varstr = [&](const Script& s) {
        put_varint(s.size());
        b.insert(b.end(), s.begin(), s.end());
    };
    auto put_txout = [&](uint64_t value, const Script& script) {
        put_le(value, 8);
        put_varstr(script);
    };

    const bool has_cbtx = !info.coinbase_payload.empty();
    // version int16 + type int16 (dash/data.py:97-98): {3,5} for DIP4 CbTx.
    put_le(has_cbtx ? 3u : 1u, 2);
    put_le(has_cbtx ? 5u : 0u, 2);

    // tx_ins: one coinbase input (data.py:251-255).
    put_varint(1);
    for (int i = 0; i < 32; ++i) b.push_back(0x00);      // previous_output None -> hash 0
    put_le(0xffffffffu, 4);                              //                     -> index 2^32-1
    put_varstr(info.coinbase);                           // scriptSig
    put_le(0xffffffffu, 4);                              // sequence None -> 2^32-1

    // tx_outs.
    put_varint(worker_tx.size() + payments_tx.size() + 1 /*donation*/ + 1 /*OP_RETURN*/);
    for (const auto& [script, amount] : worker_tx)
        put_txout(amount, script);
    for (const auto& [script, amount] : payments_tx)
        put_txout(amount, script);
    put_txout(amounts[donation_script], donation_script);
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
        put_varstr(info.coinbase_payload);               // extra_payload VarStr
        payload_varstr_size = b.size() - before;
    }

    // prefix = packed_gentx[:-payload_varstr_size - 32 - 8 - 4] (data.py:280)
    if (b.size() < payload_varstr_size + 44)
        throw std::runtime_error("build_gentx: tx shorter than known tail");
    out.prefix_len = b.size() - payload_varstr_size - 44;

    auto sp = std::span<const unsigned char>(b.data(), b.size());
    out.txid = Hash(sp);
    return out;
}

// ── 3. hash_link midstate producer (data.py:34-37) ───────────────────────────
//
//   def prefix_to_hash_link(prefix, const_ending=''):
//       assert prefix.endswith(const_ending)
//       x = sha256(prefix)
//       return dict(state=x.state, extra_data=x.buf[:max(0,len(x.buf)-len(const_ending))],
//                   length=x.length//8)
//
// Inverse of dash::check_hash_link: captures the SHA256 midstate after the
// gentx prefix so a submitted solve folds into the gentx txid. Mirrors
// dgb::prefix_to_hash_link (share_check.hpp) on the dash HashLinkType.
inline HashLinkType prefix_to_hash_link(const std::vector<unsigned char>& prefix,
                                        const std::vector<unsigned char>& const_ending)
{
    // Oracle asserts prefix.endswith(const_ending) — a producer bug otherwise.
    if (prefix.size() < const_ending.size() ||
        !std::equal(const_ending.rbegin(), const_ending.rend(), prefix.rbegin()))
        throw std::runtime_error("prefix_to_hash_link: prefix does not end with const_ending");

    CSHA256 hasher;
    hasher.Write(prefix.data(), prefix.size());

    HashLinkType out;
    out.m_state.m_data.resize(32);
    for (int i = 0; i < 8; ++i)
        WriteBE32(out.m_state.m_data.data() + i * 4, hasher.s[i]);

    const size_t bufsize = hasher.bytes % 64;
    const size_t extra_len =
        (bufsize > const_ending.size()) ? (bufsize - const_ending.size()) : 0;
    out.m_extra_data.m_data.assign(hasher.buf, hasher.buf + extra_len);
    out.m_length = hasher.bytes;
    return out;
}

// ── merkle link for the share (data.py:288) ──────────────────────────────────
// calculate_merkle_link([None] + other_transaction_hashes, 0): the branch for
// the coinbase slot. Siblings along the index-0 path never involve slot 0
// itself, so a zero placeholder is byte-safe. Odd layers duplicate their last
// element (dash/data.py:189-207).
// Same reduction as dash::coinbase::merkle_branches_raw (coinbase_builder.hpp)
// — kept local so this consensus header does not pull the coinbase builder's
// transaction/GBT-JSON dependency tree; equality between the two walks is
// drift-fenced by the MerkleLinkMatchesCoinbaseBuilder KAT.
inline MerkleLink calculate_merkle_link_index0(const std::vector<uint256>& other_tx_hashes)
{
    MerkleLink link;
    link.m_index = 0;
    if (other_tx_hashes.empty())
        return link;

    std::vector<uint256> layer;
    layer.reserve(1 + other_tx_hashes.size());
    layer.emplace_back();                       // coinbase placeholder (never a sibling)
    layer.insert(layer.end(), other_tx_hashes.begin(), other_tx_hashes.end());

    while (layer.size() > 1)
    {
        link.m_branch.push_back(layer[1]);
        if (layer.size() % 2 == 1)
            layer.push_back(layer.back());
        std::vector<uint256> next;
        next.reserve(layer.size() / 2);
        for (size_t i = 0; i + 1 < layer.size(); i += 2)
        {
            std::vector<unsigned char> buf(64);
            std::memcpy(buf.data(),      layer[i].data(),     32);
            std::memcpy(buf.data() + 32, layer[i + 1].data(), 32);
            auto sp = std::span<const unsigned char>(buf.data(), buf.size());
            next.push_back(Hash(sp));
        }
        layer.swap(next);
    }
    return link;
}

// ── 4. DashShare build + MANDATORY self-verify ───────────────────────────────
//
// The oracle get_share closure (data.py:270-292): min_header (solved header
// sans merkle_root) + share_info + empty ref_merkle_link + last_txout_nonce +
// hash_link over the gentx prefix + merkle_link over the job tx set + the
// outer coinbase_payload.
//
// OUTER coinbase_payload semantics (BYTE-PARITY CRITICAL): the oracle stores
// pack.VarStrType().pack(raw_payload) — the VarStr-PACKED payload — as the
// field VALUE (data.py:277-289), then appends that value VERBATIM to the
// hash_link data (data.py:346-348). On the wire the PossiblyNone(b'',VarStr)
// outer layer adds one more length prefix. m_coinbase_payload_outer.m_data
// therefore carries the VarStr-packed payload (compactsize || raw), matching
// what DashFormatter reads off a live oracle share, and share_init_verify
// appends it verbatim (share_check.hpp).
//
// The self-verify is NOT optional: the built share is pushed through the
// in-tree verifier (share_init_verify — ref_hash, hash_link fold, merkle,
// header reconstruction, X11) and the producer-side gentx txid is
// cross-checked against the verifier's check_hash_link fold. Any mismatch
// throws — a share that fails here must never reach the wire.
struct BuiltShare
{
    DashShare share;      // fully populated, m_hash set to the X11 share hash
    uint256   gentx_hash; // sha256d of the produced coinbase
    uint256   ref_hash;   // PPLNS OP_RETURN commitment
};

template <typename ChainT>
inline BuiltShare build_share(ChainT& chain,
                              const core::CoinParams& params,
                              const ProspectiveShareInfo& info,
                              const bitcoin_family::coin::SmallBlockHeaderType& min_header,
                              uint64_t last_txout_nonce,
                              bool check_pow = true)
{
    BuiltShare out;

    // Oracle weights window: start at prev.prev with max(0, min(height, RCL)-1)
    // shares, capped at 65535*SPREAD*ata(block_target) (data.py:181-184).
    CumulativeWeights weights;
    if (!info.prev_hash.IsNull() && chain.contains(info.prev_hash))
    {
        uint256 grandparent;
        chain.get_share(info.prev_hash).invoke([&](auto* obj) {
            grandparent = obj->m_prev_hash;
        });
        const int32_t height = chain.get_acc_height(info.prev_hash);
        const int32_t max_shares = std::max<int32_t>(
            0, std::min<int32_t>(height, static_cast<int32_t>(params.real_chain_length)) - 1);
        const uint256 block_target = chain::bits_to_target(min_header.m_bits);
        const uint288 desired_weight =
            chain::target_to_average_attempts(block_target) * params.spread * 65535u;
        weights = get_cumulative_weights(chain, grandparent, max_shares, desired_weight);
    }

    out.ref_hash = compute_ref_hash(params, info);
    GentxResult gentx = build_gentx(info, weights, out.ref_hash, last_txout_nonce, params);
    out.gentx_hash = gentx.txid;

    DashShare& s = out.share;
    s.m_min_header = min_header;

    s.m_prev_hash        = info.prev_hash;
    s.m_coinbase         = BaseScript(info.coinbase);
    s.m_coinbase_payload = BaseScript(info.coinbase_payload);
    s.m_nonce            = info.nonce;
    s.m_pubkey_hash      = info.pubkey_hash;
    s.m_subsidy          = info.subsidy;
    s.m_donation         = info.donation;
    s.m_stale_info       = info.stale_info;
    s.m_desired_version  = info.desired_version;
    s.m_payment_amount   = info.payment_amount;
    s.m_packed_payments  = info.packed_payments;

    s.m_new_transaction_hashes = info.new_transaction_hashes;
    s.m_transaction_hash_refs  = info.transaction_hash_refs;
    s.m_far_share_hash         = info.far_share_hash;
    s.m_max_bits               = info.max_bits;
    s.m_bits                   = info.bits;
    s.m_timestamp              = info.timestamp;
    s.m_absheight              = info.absheight;
    s.m_abswork                = info.abswork;

    s.m_ref_merkle_link = MerkleLink{};                  // data.py:285
    s.m_last_txout_nonce = last_txout_nonce;
    {
        std::vector<unsigned char> prefix(
            gentx.bytes.begin(), gentx.bytes.begin() + gentx.prefix_len);
        s.m_hash_link = prefix_to_hash_link(prefix, compute_gentx_before_refhash());
    }
    s.m_merkle_link = calculate_merkle_link_index0(info.other_transaction_hashes);

    // Outer payload: the VarStr-PACKED raw payload, or empty for none
    // (data.py:275-279 — see the semantics note above).
    if (!info.coinbase_payload.empty())
    {
        PackStream ps;
        BaseScript raw; raw.m_data = info.coinbase_payload;
        ps << raw;                                       // [compactsize][payload]
        s.m_coinbase_payload_outer.m_data.assign(
            reinterpret_cast<const unsigned char*>(ps.data()),
            reinterpret_cast<const unsigned char*>(ps.data()) + ps.size());
    }

    // ── MANDATORY self-verify ──
    // (1) The verifier's hash_link fold over our hash_link must reproduce the
    //     produced gentx txid exactly (producer/checker cross-check).
    {
        std::vector<unsigned char> hld;
        hld.insert(hld.end(), out.ref_hash.data(), out.ref_hash.data() + 32);
        for (int i = 0; i < 8; ++i)
            hld.push_back(static_cast<unsigned char>((last_txout_nonce >> (8 * i)) & 0xff));
        for (int i = 0; i < 4; ++i)
            hld.push_back(0x00);
        hld.insert(hld.end(), s.m_coinbase_payload_outer.m_data.begin(),
                   s.m_coinbase_payload_outer.m_data.end());
        const uint256 folded =
            check_hash_link(s.m_hash_link, hld, compute_gentx_before_refhash());
        if (folded != gentx.txid)
            throw std::runtime_error(
                "build_share: hash_link fold does not reproduce gentx txid");
    }
    // (2) Full in-tree verifier pass (ref_hash recompute, merkle, header
    //     reconstruction, share-target validity, X11 — and the PoW check when
    //     the caller submits a real solve).
    s.m_hash = share_init_verify(s, params, check_pow);

    return out;
}

} // namespace dash::producer
