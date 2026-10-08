// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_receipt_admission.hpp
// Path B, slice S2 (thin): self-carried receipts and LEGALLY DEAD.
//
// On top of the S1 carrier sharechain this module adds exactly two things:
//
//   1. Self-carried receipts. A carrier may carry in its carried list one or
//      more earlier receipts OF ITS OWN PAYEE that lost the ordering race.
//      carried_root becomes non-zero (the per-carrier Merkle over the carried
//      ids in canonical order), folded into receipts_root exactly as
//      pathb_ratchet_state.hpp specifies. The admission predicate
//      "carried payee == carrier payee" (self_carried_ok) is SLICE-LOCAL: a
//      foreign payee is STRIKE in S2; the predicate is not in the canon or
//      HELLO and is lifted when open carriage of others lands in S3.
//
//   2. LEGALLY DEAD. freshness 0 <= h(r) - h(tip) <= Fresh [K07], read from the
//      receipt and its own bound tip only (never the placing chain); liveness
//      live(r) <=> h(r) >= H(min(q - 1, own position)) at delta = 1 [K05], with
//      the height record H taken over CARRIERS of the placing chain, by chain
//      data only, NO clock. A dead receipt is placed and deduplicated but
//      tagged weight 0; it is counted for dedup and never credited.
//
// window_root and mmr_root stay the S1 zero stubs (admission asserts both == 0).
// The payout window, the bin fold / seal, buckets, the MMR, the exact split and
// the emission base reward are all S3; none is built here. Receipts are PLACED
// and TAGGED live/dead but NOT CREDITED (crediting is the S3 window).
//
// Admission order of S2.3 (cheap first, RandomX last): the canonical coinbase
// check (#12) runs strictly BEFORE RandomX (#15); a non-canonical coinbase is a
// BAN decided before RandomX is ever invoked.
//
// The canonical coinbase of S1 / S2 is the STUB: one output of the whole reward
// R to the receipt's own payee, its one-time key derived once per (tip, P_r).
// The real hf-16 split of R over window(tip, v) replaces only the leaf
// construction in S3; the admission order (#12 before #15) is unchanged.
//
// Header-only. Not included by any running component; included by its KATs only.
// Pulls Keccak (xmr_coin) and the v37 sha256d; link xmr_coin.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include "impl/xmr/coin/xmr_keccak_midstate.hpp"  // ::xmr::coin::keccak256
#include "sharechain/v37/v37_hash.hpp"            // ::v37::sha256d

#include "pathb_params.hpp"
#include "pathb_ratchet_state.hpp"  // receipts_root fold, check_carrier_fold, rs_root, kNoCarriedRoot
#include "pathb_wire_v3.hpp"        // HashingBlob, ReceiptBodyV3, encode_hashing_blob, kExtraNonceBytes

namespace c2pool::xmr::pathb {

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------
inline Hash32 keccak256_hash(const std::vector<std::uint8_t>& pre) {
    const ::xmr::coin::Hash256 h = ::xmr::coin::keccak256(pre.data(), pre.size());
    Hash32 out{};
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = h.data()[i];
    return out;
}

inline Hash32 sha256d_pair(const Hash32& a, const Hash32& b) {
    std::vector<std::uint8_t> pre;
    pre.reserve(2 * kHashBytes);
    pre.insert(pre.end(), a.begin(), a.end());
    pre.insert(pre.end(), b.begin(), b.end());
    return ::v37::sha256d(pre);
}

// ---------------------------------------------------------------------------
// receipt_id (S2.4): id = keccak256(hashing_blob)
// ---------------------------------------------------------------------------
inline Hash32 receipt_id(const HashingBlob& blob) {
    std::vector<std::uint8_t> bytes;
    encode_hashing_blob(blob, bytes);
    return keccak256_hash(bytes);
}

inline Hash32 receipt_id(const ReceiptBodyV3& r) { return receipt_id(r.blob); }

// ---------------------------------------------------------------------------
// freshness (S2.3 #6, K07): 0 <= h(r) - h(tip) <= Fresh
// Read from the receipt and its own bound tip only, NEVER the placing chain.
// Out of range is REFUSE (no strike token; cheaper than parsing misbehaviour).
// ---------------------------------------------------------------------------
enum class FreshVerdict : std::uint8_t { Fresh, Refuse };

inline FreshVerdict freshness(std::uint64_t h_r, std::uint64_t h_tip, std::uint64_t fresh_max) {
    const std::int64_t d = static_cast<std::int64_t>(h_r) - static_cast<std::int64_t>(h_tip);
    return (d >= 0 && d <= static_cast<std::int64_t>(fresh_max)) ? FreshVerdict::Fresh : FreshVerdict::Refuse;
}

// ---------------------------------------------------------------------------
// open bin (S2.4 open_at, S2.3 #7, K04): H(x) < b + F
// Carried receipt: x = pos(c) - 1 (the carrier's parent), b = h(r) (origin bin).
// H(x) >= b + F is a SEALED bin: carriage into it is STRIKE.
// ---------------------------------------------------------------------------
inline bool open_at(std::uint64_t record_at_x, std::uint64_t origin_bin, std::uint64_t open_bins) {
    if (origin_bin > UINT64_MAX - open_bins) return true;  // b + F cannot overflow; always open
    return record_at_x < origin_bin + open_bins;
}

// ---------------------------------------------------------------------------
// LEGALLY DEAD (S2.4 own_pos / live, S2.3 #17, K05 delta = 1)
//
//   own_pos(chain, r) = pos(tip) + 1  (the position the receipt competed for;
//     the transitive off-chain-tip walk is bounded by the defensive fuel
//     F x 12, a consequence of the open bin, applied by the chain walk).
//   live(chain, r, q) = h(r) >= H(min(q - 1, own_pos)), H over CARRIERS of the
//     placing chain. delta = 1 is the "q - 1". q is the placing carrier
//     position. A placed receipt never raises H (F3): only carriers do.
//
// Chain data only. No clock input appears in this path.
// ---------------------------------------------------------------------------
inline std::uint64_t own_pos(std::uint64_t pos_tip) { return pos_tip + 1; }

// K05 liveness_delta (ruling 11'): a HELLO lane rule of this slice, not yet a
// LaneParams field. delta = 1 judges the work against the record of the very
// position it competed for.
inline constexpr std::uint64_t kLivenessDelta = 1;

// H is a record-height lookup by CARRIER position on the placing chain.
// Threshold position = min(q - 1, own_pos + (delta - 1)); at delta = 1 this is
// min(q - 1, own_pos). Exposed with delta for the delta-3 control vector only.
template <class RecordAt>
inline bool live_at_delta(std::uint64_t h_r, std::uint64_t q, std::uint64_t p_own, std::uint64_t delta,
                          RecordAt&& record_at) {
    const std::uint64_t q_minus_1 = q > 0 ? q - 1 : 0;
    const std::uint64_t own_shift = p_own + (delta - 1);
    const std::uint64_t threshold_pos = std::min(q_minus_1, own_shift);
    return h_r >= record_at(threshold_pos);
}

// The consensus liveness rule: delta = 1 (K05).
template <class RecordAt>
inline bool live(std::uint64_t h_r, std::uint64_t q, std::uint64_t p_own, RecordAt&& record_at) {
    return live_at_delta(h_r, q, p_own, kLivenessDelta, std::forward<RecordAt>(record_at));
}

// A placed receipt's tag: live => full weight, dead => weight 0 (never credited;
// still counted for dedup and adds 0 to a vote window).
enum class LiveTag : std::uint8_t { Live, Dead };

inline LiveTag live_tag(bool is_live) { return is_live ? LiveTag::Live : LiveTag::Dead; }

// ---------------------------------------------------------------------------
// Carried-list canonical order (S2.4 carried_order_ok, S2.3 #14, D2.5)
// Key: (origin bin = h(r) ascending, then sha256d(id || parent_id)); parent_id
// is the carrier's parent id (one value for the whole list). Strictly
// increasing (card 2d not accepted; the order key stays, ruling 27 K-11).
// ---------------------------------------------------------------------------
struct CarriedKey {
    std::uint64_t origin_bin = 0;  // h(r)
    Hash32 id{};
};

inline Hash32 carried_tiebreak(const Hash32& id, const Hash32& parent_id) {
    return sha256d_pair(id, parent_id);
}

inline bool carried_key_less(const CarriedKey& a, const CarriedKey& b, const Hash32& parent_id) {
    if (a.origin_bin != b.origin_bin) return a.origin_bin < b.origin_bin;
    return carried_tiebreak(a.id, parent_id) < carried_tiebreak(b.id, parent_id);
}

inline bool carried_order_ok(std::span<const CarriedKey> list, const Hash32& parent_id) {
    for (std::size_t i = 1; i < list.size(); ++i)
        if (!carried_key_less(list[i - 1], list[i], parent_id)) return false;  // strictly increasing
    return true;
}

// ---------------------------------------------------------------------------
// Self-carriage predicate (S2.4 self_carried_ok; SLICE-LOCAL, lifted in S3)
// Every carried receipt's payee identity == the carrier's own payee; a foreign
// payee is STRIKE. Never reaches the canon or HELLO (it would contradict C36
// and appendix A3).
// ---------------------------------------------------------------------------
inline bool self_carried_ok(std::span<const Hash32> carried_payees, const Hash32& carrier_payee) {
    for (const Hash32& p : carried_payees)
        if (p != carrier_payee) return false;
    return true;
}

// ---------------------------------------------------------------------------
// carried_root (S2.2): the Merkle root over the carried ids in canonical order.
//   leaves  = the carried ids (as-is; the canonical order of carried_order_ok)
//   node    = sha256d(left || right)
//   a lone node at a level is promoted unchanged
//   one leaf  -> its root is that id
//   empty     -> the zero stub (kNoCarriedRoot); this is the S1 case
// S2 is the first slice to compute a non-zero carried_root; this is its
// implementation of record. carried_root is a component of receipts_root
// (pathb_ratchet_state.hpp carrier_receipts_root); it is a DIFFERENT object
// from mmr_root (the sealed-bin accumulator), which stays the S1 zero stub.
// ---------------------------------------------------------------------------
inline Hash32 carried_root(std::span<const Hash32> ids) {
    if (ids.empty()) return kNoCarriedRoot;
    std::vector<Hash32> level(ids.begin(), ids.end());
    while (level.size() > 1) {
        std::vector<Hash32> next;
        next.reserve((level.size() + 1) / 2);
        for (std::size_t i = 0; i < level.size(); i += 2) {
            if (i + 1 < level.size())
                next.push_back(sha256d_pair(level[i], level[i + 1]));
            else
                next.push_back(level[i]);  // promote lone node
        }
        level.swap(next);
    }
    return level.front();
}

// receipts_root of a carrier carrying `ids` on a tip whose ratchet state is
// s_tip: the fold sha256d("c2pool-v37-carry" || carried_root(ids) || rs_root).
inline Hash32 carrier_receipts_root_over(std::span<const Hash32> ids, const RatchetState& s_tip) {
    return carrier_receipts_root(carried_root(ids), s_tip);
}

// Carrier fold admission (S2.3 #14 tail): the carrier's receipts_root against
// carried_root(ids) folded with the verifier's own S at pos(tip). STRIKE on a
// mismatch. A carried or pending receipt's own fold is never compared.
inline FoldVerdict check_carried_fold(const Hash32& receipts_root, std::span<const Hash32> ids,
                                      const RatchetState& s_tip) {
    return check_carrier_fold(receipts_root, carried_root(ids), s_tip);
}

// ---------------------------------------------------------------------------
// Stub coinbase (S2.3 #12): one output of R to the receipt's payee.
// The canonical leaf-0 (coinbase tx) commitment is keccak256 over the canonical
// bytes of the single-output stub; the one-time output key is derived ONCE per
// (tip, P_r). Admission folds the canonical leaf over the receipt's branch and
// compares with the hashing blob's tree_root; a mismatch is a BAN decided
// before RandomX. The full hf-16 split replaces only the leaf in S3.
// ---------------------------------------------------------------------------
inline constexpr std::string_view kStubKeyDomain = "c2pool-v37-cb-key";
inline constexpr std::string_view kStubCbDomain = "c2pool-v37-cb-stub";

// The one-time output key of the single stub output, derived once per (tip, P_r)
// and the payee it pays.
inline Hash32 stub_output_key(const Hash32& tip, const Hash32& p_r, const Hash32& payee_identity) {
    std::vector<std::uint8_t> pre(kStubKeyDomain.begin(), kStubKeyDomain.end());
    pre.insert(pre.end(), tip.begin(), tip.end());
    pre.insert(pre.end(), p_r.begin(), p_r.end());
    pre.insert(pre.end(), payee_identity.begin(), payee_identity.end());
    return keccak256_hash(pre);
}

// leaf-0 of the canonical one-output stub coinbase: domain || R || output_key ||
// extra_nonce || mm_root. Changing R, the payee (through output_key) or any
// side_data_v3 field (through mm_root) changes the leaf.
inline Hash32 canonical_stub_leaf(std::uint64_t reward_total, const Hash32& output_key,
                                  const std::array<std::uint8_t, kExtraNonceBytes>& extra_nonce,
                                  const Hash32& mm_root) {
    std::vector<std::uint8_t> pre(kStubCbDomain.begin(), kStubCbDomain.end());
    for (std::size_t i = 0; i < sizeof(reward_total); ++i)
        pre.push_back(static_cast<std::uint8_t>(reward_total >> (8 * i)));
    pre.insert(pre.end(), output_key.begin(), output_key.end());
    pre.insert(pre.end(), extra_nonce.begin(), extra_nonce.end());
    pre.insert(pre.end(), mm_root.begin(), mm_root.end());
    return keccak256_hash(pre);
}

// Monero tree path for leaf index 0 (the coinbase; "no path bits"): the
// keccak256 left-fold of the leaf over the branch.
inline Hash32 tree_root_fold(const Hash32& leaf0, std::span<const Hash32> branch) {
    Hash32 h = leaf0;
    for (const Hash32& b : branch) {
        std::vector<std::uint8_t> pre;
        pre.reserve(2 * kHashBytes);
        pre.insert(pre.end(), h.begin(), h.end());
        pre.insert(pre.end(), b.begin(), b.end());
        h = keccak256_hash(pre);
    }
    return h;
}

// The canonical stub coinbase leaf a receipt on (tip, P_r) MUST commit: one
// output of r.reward_total to r's payee, with the per-(tip, P_r) key, and the
// receipt's own mm_root (side_data_v3).
inline Hash32 canonical_stub_leaf_of(const ReceiptBodyV3& r, const Hash32& tip, const Hash32& p_r,
                                     const Hash32& mm_root) {
    const Hash32 key = stub_output_key(tip, p_r, r.side.payee);
    return canonical_stub_leaf(r.reward_total, key, r.extra_nonce, mm_root);
}

inline Hash32 canonical_stub_leaf_of(const ReceiptBodyV3& r, const Hash32& tip, const Hash32& p_r) {
    return canonical_stub_leaf_of(r, tip, p_r, mm_root_of(r.side).value_or(Hash32{}));
}

// Admission #12: the receipt's committed coinbase (tree_root folded over the
// branch from leaf 0) equals the canonical stub coinbase. false is a BAN.
inline bool canonical_coinbase_ok(const ReceiptBodyV3& r, const Hash32& tip, const Hash32& p_r) {
    const std::optional<Hash32> mm = mm_root_of(r.side);
    if (!mm) return false;
    const Hash32 leaf = canonical_stub_leaf_of(r, tip, p_r, *mm);
    return tree_root_fold(leaf, std::span<const Hash32>(r.branch)) == r.blob.tree_root;
}

// ---------------------------------------------------------------------------
// Zero-stub invariant (S2.3 #13): window_root == 0 and mmr_root == 0. A
// non-zero stub is STRIKE (unchanged from S1; the real roots are S3).
// ---------------------------------------------------------------------------
inline bool zero_stubs_ok(const SideDataV3& s) {
    return detail::is_zero(s.window_root) && detail::is_zero(s.mmr_root);
}

// ---------------------------------------------------------------------------
// Dedup set (S2.3 #8; the replay guard, ruling 27 K-10). One set per chain /
// branch of the ids placed in open bins (carriers + placed receipts). An id
// placed twice is a DUPLICATE (pending) or a STRIKE (carried). Rewinding frees
// the abandoned placements.
// ---------------------------------------------------------------------------
class PlacedSet {
public:
    bool contains(const Hash32& id) const { return placed_.count(id) != 0; }
    // Returns true iff the id was newly placed (not already present).
    bool place(const Hash32& id) { return placed_.insert(id).second; }
    void unplace(const Hash32& id) { placed_.erase(id); }
    std::size_t size() const { return placed_.size(); }

private:
    std::set<Hash32> placed_;
};

// ---------------------------------------------------------------------------
// Admission order (S2.3): the resolution stages (#3 tip, #5 P_r / served ctx,
// #15 seed) and the cheap-coinbase-then-RandomX tail (#12 before #15).
// ---------------------------------------------------------------------------
enum class AdmitVerdict : std::uint8_t {
    Strike,         // a parsing / consensus misbehaviour (#1b, #2, #4, #7 carried, #9, #11, #13, #14)
    Refuse,         // not misbehaviour (#6 freshness, #7 pending)
    Defer,          // waiting on chain / context / seed (#3, #5, #15 SeedMissing) - never a strike
    Duplicate,      // an already-placed pending id (#8)
    Ban,            // a served bad context block (#5), a non-canonical coinbase (#12), bad PoW (#15)
    AdmitCarrier,   // placed as a carrier
    AdmitPending,   // placed pending
};

// #3 / #5: resolution of the tip, P_r and seed before the cheap checks.
enum class Resolve : std::uint8_t {
    Ready,            // tip held + verified, P_r resolved, seed present
    DeferUnknownTip,  // #3: tip not held / not verified -> DEFER + fetch
    DeferUnknownPr,   // #5: P_r not on a verified branch -> DEFER + fetch
    DeferSeedMissing, // #15: RandomX seed missing -> DEFER
    BanBadCtx,        // #5: a served context block failed its branch PoW -> BAN the server
};

// A defer / ban resolution carries NO strike.
inline AdmitVerdict admit_resolution(Resolve r) {
    switch (r) {
        case Resolve::Ready: return AdmitVerdict::AdmitCarrier;  // the caller continues the cheap checks
        case Resolve::DeferUnknownTip:
        case Resolve::DeferUnknownPr:
        case Resolve::DeferSeedMissing: return AdmitVerdict::Defer;
        case Resolve::BanBadCtx: return AdmitVerdict::Ban;
    }
    return AdmitVerdict::Defer;
}

struct TailResult {
    AdmitVerdict verdict = AdmitVerdict::Strike;
    bool randomx_called = false;  // observable: #15 runs only after #12 admits
};

// The admission tail: #12 (canonical coinbase) strictly BEFORE #15 (RandomX).
// A non-canonical coinbase is a BAN decided before RandomX is ever invoked.
template <class RandomXOk>
inline TailResult admit_coinbase_then_randomx(bool coinbase_ok, RandomXOk&& randomx_ok) {
    if (!coinbase_ok) return {AdmitVerdict::Ban, false};  // #12 BAN; RandomX NOT called
    const bool pow_ok = randomx_ok();                      // #15
    return {pow_ok ? AdmitVerdict::AdmitCarrier : AdmitVerdict::Ban, true};
}

}  // namespace c2pool::xmr::pathb
