// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/settle/xmr_coinbase.cpp  --  W5-XMR coinbase settlement rule
//
// AUTHORED clean for c2pool (AGPL-3.0). No third-party code is copied into this
// file; the crypto lives in the vendored/wrapped coin layer (BSD-3).
//
// PROVENANCE -- the deterministic tx-secret-key trick (REFERENCE, not a port).
//   The idea that a pool coinbase can be a *pure function of consensus data* --
//   so every node re-derives the SAME tx secret key r, the SAME one-time output
//   keys, and rejects any byte mismatch -- is Monero p2pool's, and p2pool is the
//   fielded existence proof for "every node computes the same coinbase":
//     * SChernykh/p2pool  src/pool_block.cpp
//         PoolBlock::get_tx_keys()          entropy = "tx_secret_key" || seed ||
//                                           monero_block_id -> generate_keys_
//                                           deterministic(pub, sec, entropy)
//         PoolBlock::calculate_tx_key_seed() seed = keccak("tx_key_seed" ||
//                                           mainchain data (nonce/extra-nonce
//                                           zeroed) || sidechain data)
//     * SChernykh/p2pool  src/side_chain.cpp
//         SideChain::split_reward()         integer proportional split, running
//                                           truncation, Sum == reward exactly
//         SideChain::get_shares()           one output per distinct wallet
//         SideChain::verify()               re-derives every output key and
//                                           rejects "pays out to a wrong wallet
//                                           at index i"
//         (p2pool is GPL-3.0; it is combinable into this AGPL-3.0 work under
//          AGPLv3 §13. Nothing above is copied -- this file RE-EXPRESSES the
//          pattern with v37's own inputs: the "seed" is v37's lane_commitment
//          / owed_digest, NOT a chain of inherited sidechain seeds; the split
//          is v37's K_fair oldest-owed-first accrual, NOT PPLNS proportional;
//          there are no uncles. The Monero primitive names below are
//          monero-project's BSD-3 crypto, reached through the coin-layer
//          wrappers.)
//   Monero-core symbols this rule targets (monero-project/monero):
//     cryptonote_tx_utils.cpp  construct_miner_tx / get_transaction_prefix_hash
//                              / calculate_transaction_hash
//     cryptonote_basic  tx_extra_merge_mining_tag {depth, merkle_root}
//     blockchain.cpp  validate_miner_transaction  ("coinbase transaction
//                     doesn't use full amount of block reward", exact since
//                     HF_VERSION_EXACT_COINBASE); unlock_time == height +
//                     CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW (=60).
// ---------------------------------------------------------------------------
#include "impl/xmr/settle/xmr_coinbase.hpp"

#include "impl/xmr/coin/xmr_keccak_midstate.hpp"  // KeccakMidstate (keccak256)

#include <algorithm>
#include <cstring>

namespace v37 {
namespace xmr {
namespace settle {

using ::xmr::coin::BlobWriter;
using ::xmr::coin::KeccakMidstate;

// ---------------------------------------------------------------------------
const char* to_string(BuildError e) {
    switch (e) {
        case BuildError::None:               return "none";
        case BuildError::CarrotFence:        return "CARROT_FENCE: major_version > pre-CARROT max";
        case BuildError::ZeroBudget:         return "zero budget (base_reward + fees == 0)";
        case BuildError::FixedExceedsBudget: return "fixed outputs exceed budget";
        case BuildError::CapTooSmall:        return "output_cap too small for fixed + sink";
        case BuildError::BadSinkDescriptor:  return "residual_sink is not a valid XMR ref";
        case BuildError::BadPayeeDescriptor: return "a payee is not a valid XMR ref";
        case BuildError::DerivationFailed:   return "ec derivation failed (bad point/scalar)";
    }
    return "unknown";
}

// ---------------------------------------------------------------------------
// Structural XMR-ref check (kind is XMR_STD/XMR_SUB, payload is 64 B). The full
// prime-order/torsion check is the descriptor canon's job at admission
// (v37::xmr::xmr_ref_valid); W5 re-checks only kind+width so a mis-kinded ref
// can never be fed into ECDH derivation.
static bool xmr_ref_shape_ok(const ::v37::ScriptRef& r) {
    return ::v37::xmr::is_xmr_kind(r.kind) &&
           r.payload.size() == ::v37::xmr::XMR_PAYLOAD_LEN;
}

// ---------------------------------------------------------------------------
std::vector<CoinbaseOutput> allocate_exact_sum(const CoinbaseInputs& in,
                                               BuildError* err) {
    auto fail = [&](BuildError e) -> std::vector<CoinbaseOutput> {
        if (err) *err = e;
        return {};
    };

    const std::uint64_t budget = in.budget();
    if (budget == 0) return fail(BuildError::ZeroBudget);

    // Sum of mandated fixed outputs (dev/donation/finder). Each is a real output.
    std::uint64_t fixed_sum = 0;
    for (const auto& f : in.fixed) {
        // budget fits in u64 and fixed_sum <= budget by the check below, so this
        // running sum cannot overflow once we bail on the first excess.
        if (f.amount > budget - fixed_sum) return fail(BuildError::FixedExceedsBudget);
        fixed_sum += f.amount;
    }

    // Need room for every fixed output plus at least the sink slot.
    if (in.fixed.size() + 1 > static_cast<std::size_t>(in.output_cap))
        return fail(BuildError::CapTooSmall);

    const std::size_t cap_owed =
        static_cast<std::size_t>(in.output_cap) - in.fixed.size() - 1;

    // K_fair order: oldest-owed-first (first_eligible asc), then identity_key asc
    // as a total, deterministic tiebreak. stable_sort so equal keys keep input
    // order (belt-and-braces; the identity tiebreak already makes it total).
    std::vector<OwedEntry> sorted = in.owed;
    std::stable_sort(sorted.begin(), sorted.end(),
        [](const OwedEntry& a, const OwedEntry& b) {
            if (a.first_eligible != b.first_eligible)
                return a.first_eligible < b.first_eligible;
            return std::memcmp(a.identity.data(), b.identity.data(),
                               a.identity.size()) < 0;
        });

    std::vector<CoinbaseOutput> res;
    res.reserve(sorted.size() + in.fixed.size() + 1);

    // ---- owed pass: pay oldest-owed-first out of (budget - fixed) ----
    std::uint64_t remaining = budget - fixed_sum;
    for (const auto& e : sorted) {
        if (res.size() >= cap_owed) break;   // cap reached -> rest carries
        if (remaining == 0) break;           // budget exhausted -> rest carries
        if (e.owed < in.h_min) continue;     // below payout floor -> carry, no output
        std::uint64_t amt = std::min(e.owed, remaining);
        // Final partial below the payout floor: don't emit a sub-h_min owed
        // output; stop and let the residual sink absorb `remaining`.
        if (amt < in.h_min) break;
        CoinbaseOutput o;
        o.pay = e.pay;
        o.identity = e.identity;
        o.amount = amt;
        o.role = CoinbaseOutput::Role::Owed;
        res.push_back(std::move(o));
        remaining -= amt;
    }

    // ---- fixed mandated outputs (declared order) ----
    for (const auto& f : in.fixed) {
        CoinbaseOutput o;
        o.pay = f.pay;
        o.identity = f.identity;
        o.amount = f.amount;
        o.role = CoinbaseOutput::Role::Fixed;
        res.push_back(std::move(o));
    }

    // ---- residual sink: absorbs unallocated budget + any rounding. NO BURN.
    // residual == budget - fixed_sum - Sum(owed paid) == `remaining`.
    const std::uint64_t residual = remaining;
    if (residual > 0) {
        CoinbaseOutput s;
        s.pay = in.residual_sink;
        s.identity = in.residual_sink_identity;
        s.amount = residual;
        s.role = CoinbaseOutput::Role::Sink;
        res.push_back(std::move(s));
    }

    // Invariants: non-empty, and exact-sum (this is CONS-1 for the XMR lane).
    // (residual==0 only when owed/fixed already consume the full budget, so res
    // is still non-empty; residual==budget when nothing else pays, so the sink
    // carries it.)
    if (err) *err = BuildError::None;
    return res;
}

// ---------------------------------------------------------------------------
bool derive_tx_secret_key(const CoinbaseInputs& in, SecretKey& r_out) {
    // FENCE: pre-CARROT derivation only.
    if (!::v37::xmr::xmr_precarrot_ok(in.monero_major_version)) return false;

    // preimage = domain || major || chain_id(LE32) || lane_commitment(32)
    //            || prev_id(32) || varint(height)
    // (p2pool pattern: "tx_secret_key" || seed || monero_block_id. Here `seed`
    //  is the v37 lane_commitment and `monero_block_id` is prev_id, so a
    //  different owed set OR a different Monero parent forces a different r --
    //  exactly p2pool's re-derivation on a prev_id change.)
    BlobWriter w;
    w.put_bytes(TXKEY_DOMAIN, sizeof(TXKEY_DOMAIN) - 1);  // drop the NUL
    w.put_byte(in.monero_major_version);
    w.put_u32_le(in.chain_id);
    w.put_bytes(in.lane_commitment.data(), in.lane_commitment.size());
    w.put_key(in.prev_id);
    w.put_varint(in.height);

    // H_s == keccak256 then reduce mod l -> a canonical (sc_check-clean) scalar,
    // so its bytes are a valid tx secret key. (coin layer over crypto.cpp
    // hash_to_scalar.)
    EcScalar s;
    ::xmr::coin::hash_to_scalar(w.bytes().data(), w.size(), s);
    std::memcpy(r_out.data(), s.data(), 32);
    return true;
}

// ---------------------------------------------------------------------------
bool derive_output(const SecretKey& r, const ::v37::ScriptRef& pay,
                   std::size_t vout_index, PublicKey& P_out, ViewTag& vt_out) {
    // -----------------------------------------------------------------------
    // PRE-CARROT coinbase-output derivation. See the fence banner in the header.
    // -----------------------------------------------------------------------
    if (!xmr_ref_shape_ok(pay)) return false;

    // spend B = payload[0..32), view A = payload[32..64)  (XMR_STD: B||A;
    // XMR_SUB: sub-spend D_i || main-view A -- same ECDH math either way).
    PublicKey B, A;
    std::memcpy(B.data(), pay.payload.data(), 32);
    std::memcpy(A.data(), pay.payload.data() + 32, 32);

    ::xmr::coin::KeyDerivation D;
    if (!::xmr::coin::generate_key_derivation(A, r, D)) return false;   // D = 8*r*A
    if (!::xmr::coin::derive_public_key(D, vout_index, B, P_out)) return false; // P = H_s(D||i)G + B
    ::xmr::coin::derive_view_tag(D, vout_index, vt_out);               // vt = H("view_tag"||D||i)[0]
    return true;
}

// ---------------------------------------------------------------------------
Hash256 mm_commitment_root(std::uint32_t chain_id,
                           const ::v37::bytes32& lane_commitment) {
    // Single v37 leaf under the 0x03 merge-mining root:
    //   mm_root = keccak256(domain || chain_id(LE32) || lane_commitment).
    // For a multi-aux tree (e.g. hosting Tari), this hash is one LEAF and the
    // 0x03 root becomes the Merkle root over all aux-chain leaves -- that
    // generalization (leaf slotting, depth, branch) belongs to the template/
    // aux leg (OQ-X4). Here depth = 0, root == leaf.
    unsigned char cid[4] = {
        static_cast<unsigned char>(chain_id & 0xff),
        static_cast<unsigned char>((chain_id >> 8) & 0xff),
        static_cast<unsigned char>((chain_id >> 16) & 0xff),
        static_cast<unsigned char>((chain_id >> 24) & 0xff),
    };
    KeccakMidstate m;
    m.absorb(MM_LEAF_DOMAIN, sizeof(MM_LEAF_DOMAIN) - 1);
    m.absorb(cid, 4);
    m.absorb(lane_commitment.data(), lane_commitment.size());
    return m.finalize_copy();
}

// ---------------------------------------------------------------------------
std::vector<unsigned char> assemble_tx_extra(const PublicKey& R,
                                             const std::vector<unsigned char>& extra_nonce,
                                             const Hash256& mm_root) {
    BlobWriter w;
    // 0x01 tx pubkey R = r*G.
    w.put_byte(::xmr::coin::TX_EXTRA_TAG_PUBKEY);
    w.put_key(R);
    // 0x02 extra-nonce (per-worker; padded upstream to keep miner_tx weight
    // invariant to amount-varint length, p2pool style). Omitted if empty.
    if (!extra_nonce.empty()) {
        w.put_byte(::xmr::coin::TX_EXTRA_TAG_NONCE);
        w.put_varint(extra_nonce.size());
        w.put_bytes(extra_nonce.data(), extra_nonce.size());
    }
    // 0x03 merge-mining tag = length-prefixed { varint(depth) || merkle_root[32] }
    // (monero-project tx_extra_merge_mining_tag). depth = 0 for the single leaf.
    BlobWriter inner;
    inner.put_varint(0);          // depth
    inner.put_key(mm_root);       // merkle_root
    w.put_byte(::xmr::coin::TX_EXTRA_TAG_MERGE_MINING);
    w.put_varint(inner.size());
    w.put_bytes(inner.bytes().data(), inner.size());

    return std::vector<unsigned char>(w.bytes());
}

// ---------------------------------------------------------------------------
BuiltCoinbase build_coinbase(const CoinbaseInputs& in) {
    BuiltCoinbase out;
    out.budget = in.budget();

    // ---- FENCE FIRST ----
    if (!::v37::xmr::xmr_precarrot_ok(in.monero_major_version)) {
        out.error = BuildError::CarrotFence;
        out.detail = to_string(out.error);
        return out;
    }

    // ---- structural payee validation (kind + width; torsion is upstream) ----
    if (!xmr_ref_shape_ok(in.residual_sink)) {
        out.error = BuildError::BadSinkDescriptor;
        out.detail = to_string(out.error);
        return out;
    }
    for (const auto& e : in.owed) {
        if (!xmr_ref_shape_ok(e.pay)) {
            out.error = BuildError::BadPayeeDescriptor;
            out.detail = to_string(out.error);
            return out;
        }
    }
    for (const auto& f : in.fixed) {
        if (!xmr_ref_shape_ok(f.pay)) {
            out.error = BuildError::BadPayeeDescriptor;
            out.detail = to_string(out.error);
            return out;
        }
    }

    // ---- exact-sum allocation ----
    BuildError aerr = BuildError::None;
    out.outputs = allocate_exact_sum(in, &aerr);
    if (out.outputs.empty()) {
        out.error = aerr;
        out.detail = to_string(aerr);
        return out;
    }

    // ---- deterministic tx secret key r and R = r*G ----
    if (!derive_tx_secret_key(in, out.r)) {   // fence already passed
        out.error = BuildError::DerivationFailed;
        out.detail = "derive_tx_secret_key";
        return out;
    }
    if (!::xmr::coin::secret_key_to_public_key(out.r, out.R)) {
        out.error = BuildError::DerivationFailed;
        out.detail = "secret_key_to_public_key (r*G)";
        return out;
    }

    // ---- per-output one-time key + view tag (index = canonical vout index) ----
    for (std::size_t i = 0; i < out.outputs.size(); ++i) {
        if (!derive_output(out.r, out.outputs[i].pay, i,
                           out.outputs[i].one_time_key, out.outputs[i].view_tag)) {
            out.error = BuildError::DerivationFailed;
            out.detail = "derive_output at vout " + std::to_string(i);
            return out;
        }
    }

    // ---- tx_extra: 0x01 R || 0x02 nonce || 0x03 MM(mm_root) ----
    out.mm_root = mm_commitment_root(in.chain_id, in.lane_commitment);
    out.tx_extra = assemble_tx_extra(out.R, in.extra_nonce, out.mm_root);

    // ---- serialize the coinbase tx prefix and hash it ----
    std::vector<std::uint64_t> amounts;
    std::vector<PublicKey>     keys;
    std::vector<ViewTag>       vtags;
    amounts.reserve(out.outputs.size());
    keys.reserve(out.outputs.size());
    vtags.reserve(out.outputs.size());
    for (const auto& o : out.outputs) {
        amounts.push_back(o.amount);
        keys.push_back(o.one_time_key);
        vtags.push_back(o.view_tag);
    }

    std::vector<unsigned char> head = ::xmr::coin::write_coinbase_prefix_head(
        in.height, amounts.data(), keys.data(), vtags.data(), out.outputs.size());

    BlobWriter w;
    w.put_bytes(head.data(), head.size());
    w.put_varint(out.tx_extra.size());               // tx_extra length varint
    w.put_bytes(out.tx_extra.data(), out.tx_extra.size());
    out.prefix = std::vector<unsigned char>(w.bytes());

    out.prefix_hash = ::xmr::coin::tx_prefix_hash(out.prefix);
    out.coinbase_tx_hash = ::xmr::coin::coinbase_tx_hash(out.prefix_hash);

    out.ok = true;
    out.error = BuildError::None;
    return out;
}

// ---------------------------------------------------------------------------
MatchResult canonical_coinbase_matches(const CoinbaseInputs& in,
                                       const ReceivedCoinbase& got) {
    BuiltCoinbase want = build_coinbase(in);
    if (!want.ok)
        return {false, IDX_BUILD, std::string("rebuild failed: ") + want.detail};

    // tx pubkey R.
    if (want.R != got.R)
        return {false, IDX_R, "tx pubkey R mismatch"};

    // output count (all three parallel arrays must agree with our list).
    const std::size_t n = want.outputs.size();
    if (got.amounts.size() != n || got.keys.size() != n || got.view_tags.size() != n)
        return {false, IDX_COUNT, "output count mismatch"};

    // per-output amount / one-time key / view tag -- first divergence wins.
    for (std::size_t i = 0; i < n; ++i) {
        if (want.outputs[i].amount != got.amounts[i])
            return {false, static_cast<int>(i), "amount mismatch"};
        if (want.outputs[i].one_time_key != got.keys[i])
            return {false, static_cast<int>(i), "pays out to a wrong wallet at index i"};
        if (want.outputs[i].view_tag.tag != got.view_tags[i].tag)
            return {false, static_cast<int>(i), "view tag mismatch"};
    }

    // whole tx_extra (catches a divergent commitment or extra-nonce).
    if (want.tx_extra != got.tx_extra)
        return {false, IDX_EXTRA, "tx_extra (commitment/nonce) mismatch"};

    return {true, -1, ""};
}

// ---------------------------------------------------------------------------
std::uint32_t weight_aware_output_cap(std::uint64_t median_block_weight,
                                      std::uint64_t reserved_nonminer_weight,
                                      std::uint32_t wire_cap) {
    // Penalty-free block-weight zone: the 100-block median, floored at the
    // long-term-median minimum (~300000 B, monero-project
    // CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 -- pin the exact constant in
    // X6). Staying <= the zone means zero reward penalty; above it the reward
    // is cut quadratically, so exceeding it is self-limiting, not forbidden.
    constexpr std::uint64_t LONG_TERM_MIN_ZONE = 300000;
    const std::uint64_t zone = std::max(median_block_weight, LONG_TERM_MIN_ZONE);

    // Coinbase fixed overhead: version + unlock_time + txin_gen + tx_extra
    // (0x01 pubkey 33 + 0x02 nonce ~16 + 0x03 MM tag ~36) ~= 90 B; round up.
    constexpr std::uint64_t COINBASE_FIXED = 128;

    std::uint64_t avail = 0;
    if (zone > reserved_nonminer_weight + COINBASE_FIXED)
        avail = zone - reserved_nonminer_weight - COINBASE_FIXED;
    const std::uint64_t by_weight = avail / XMR_OUTPUT_SIZE_BYTES;

    std::uint64_t c = std::min<std::uint64_t>(by_weight, wire_cap);
    if (c < 1) c = 1;   // always room for at least the residual sink
    if (c > 0xffffffffull) c = 0xffffffffull;
    return static_cast<std::uint32_t>(c);
}

} // namespace settle
} // namespace xmr
} // namespace v37
