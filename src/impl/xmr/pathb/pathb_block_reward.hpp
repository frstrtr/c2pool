// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_block_reward.hpp
// Path B: the split amount R of a template (S2.2 reward_total; C48; INV-13).
//
//   R = Monero's reward for a child of P_r at the block's final weight
//     = reward_for_child(Z(P_r), w, B(P_r)) + F
//   B(P_r) = the base reward of a child of P_r (no fees, no penalty), Z(P_r)
//   = Monero's effective median for that child, F = the selected fees, w = T
//   + c (T = the selected transactions' weight, c = the coinbase size).
//   B(A_t) is never an input here (it feeds W_max, f_spend, merge-back, OUT).
//
//   reward_for_child(median, w, B, hf) = get_block_reward with B given:
//     median = max(median, min_block_weight(hf))
//     median >= 2^32           -> refused
//     w <= median              -> B
//     w >  2 x median          -> refused
//     otherwise                -> floor(floor(B x ((2 median - w) w) / median) / median)
//   (2 median - w) w <= median^2 < 2^64 (u64); B x that in 128 bits.
//
//   coinbase_weight_hf16(h, amounts): the hf-16 Path B miner tx size (a v2
//     coinbase has no RingCT data: weight = size), from the amounts alone:
//     varint(2) | varint(h + 60) | varint(1) | 0xff | varint(h) | varint(n)
//     | n x (varint(q_i) | 0x03 | key[32] | view_tag[1]) | varint(74) | PBX1[74]
//     | rct type 0x00.
//
//   fit_reward(Z, T, B, F, hf, cw): the fixed point c = cw(R(c)), R(c) =
//     reward_for_child(Z, T + c, B) + F; c_0 = cw(B + F); c_{k+1} =
//     cw(R(c_k)) until c_{k+1} = c_k (Fixed) or a value repeats
//     (NoFixedPoint). With T + cw(B + F) <= Z the first step is the fixed
//     point and R = B + F.
//
//   Template selection (selection policy; the bound is checked on the final
//   set):
//     select_no_penalty  walk the candidates in the source's order with
//       running T, F; include i iff T + w_i + cw_up <= Z; then the exact
//       cw(B + F) of the final set, dropping the last included while
//       T + cw > Z. cw_up = the coinbase size with every amount at the
//       varint length of B + F_all.
//     select_penalty_fill  (behind --pathb-penalty-fill, default off): the
//       no-penalty set, then the following candidates while T + w_i + cw_up
//       <= 2 Z (penalty zone); fit_reward on the whole set; no fixed point:
//       drop the last penalty-zone candidate and repeat.
//
// Integer functions only. Header-only. Not included by any running component;
// included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <span>
#include <string_view>
#include <vector>

#include "impl/xmr/coin/xmr_blob.hpp"               // TX_VERSION_2, TXIN_GEN, TXOUT_TO_TAGGED_KEY, MINER_REWARD_UNLOCK_TIME
#include "impl/xmr/native/consensus/xmr_weight.hpp"  // min_block_weight

#include "pathb_emission.hpp"  // kHf16
#include "pathb_params.hpp"
#include "pathb_pbx1.hpp"      // pbx1_size
#include "pathb_wide.hpp"      // wide::u128

namespace c2pool::xmr::pathb {

// The median bound of reward_for_child: the u64 range of Monero's multiplicand
// (2 median - w) w <= median^2.
inline constexpr std::uint64_t kRewardMedianLimit = std::uint64_t{1} << 32;

// Monero's reward for a child of base B at weight w over `median`; nullopt:
// refused (w > 2 median, or median >= 2^32).
inline std::optional<std::uint64_t> reward_for_child(std::uint64_t median, std::uint64_t w, std::uint64_t base,
                                                     std::uint8_t hf) noexcept {
    const std::uint64_t zone = ::c2pool::xmr::native::min_block_weight(hf);
    if (median < zone) median = zone;
    if (median >= kRewardMedianLimit) return std::nullopt;
    if (w <= median) return base;
    if (w > 2 * median) return std::nullopt;
    const std::uint64_t multiplicand = (2 * median - w) * w;
    const wide::u128 product = static_cast<wide::u128>(base) * multiplicand;
    const wide::u128 r = product / median / median;
    return static_cast<std::uint64_t>(r);  // r <= B (multiplicand <= median^2)
}

// ---------------------------------------------------------------------------
// The hf-16 coinbase size from its amounts
// ---------------------------------------------------------------------------
inline constexpr std::uint64_t kTxinGenBytes = kU8Bytes;          // 0xff
inline constexpr std::uint64_t kTaggedOutputFixedBytes = kU8Bytes + kHashBytes + kU8Bytes;  // 0x03 | key | view tag
inline constexpr std::uint64_t kRctTypeNullBytes = kU8Bytes;      // RCTTypeNull
inline constexpr std::uint64_t kCoinbaseVinCount = 1;

inline std::uint64_t coinbase_weight_hf16(std::uint64_t h, std::span<const std::uint64_t> amounts) noexcept {
    const std::uint64_t extra = pbx1_size(kHf16, 1);
    std::uint64_t w = varint_len(::xmr::coin::TX_VERSION_2) + varint_len(h + ::xmr::coin::MINER_REWARD_UNLOCK_TIME)
                      + varint_len(kCoinbaseVinCount) + kTxinGenBytes + varint_len(h) + varint_len(amounts.size());
    for (const std::uint64_t a : amounts) w += varint_len(a) + kTaggedOutputFixedBytes;
    w += varint_len(extra) + extra + kRctTypeNullBytes;
    return w;
}

// ---------------------------------------------------------------------------
// fit_reward
// ---------------------------------------------------------------------------
// cw(R): the coinbase size at reward R; nullopt: no coinbase at R.
using CoinbaseSize = std::function<std::optional<std::uint64_t>(std::uint64_t R)>;

enum class FitStatus : std::uint8_t {
    Fixed,         // c = cw(R(c)): the template's R and coinbase size
    NoFixedPoint,  // a value repeated before a fixed point
    Refused,       // B + F overflows, w > 2 Z, or cw has no value
};

struct FitResult {
    FitStatus status = FitStatus::Refused;
    std::uint64_t reward = 0;    // R
    std::uint64_t coinbase = 0;  // c
    std::uint64_t steps = 0;
};

inline FitResult fit_reward(std::uint64_t z, std::uint64_t t, std::uint64_t base, std::uint64_t fees, std::uint8_t hf,
                            const CoinbaseSize& cw) {
    FitResult out;
    if (base > UINT64_MAX - fees) return out;
    std::optional<std::uint64_t> c = cw(base + fees);
    std::set<std::uint64_t> seen;
    while (c) {
        ++out.steps;
        if (*c > UINT64_MAX - t) return out;
        const std::optional<std::uint64_t> r = reward_for_child(z, t + *c, base, hf);
        if (!r || *r > UINT64_MAX - fees) return out;
        const std::uint64_t R = *r + fees;
        const std::optional<std::uint64_t> next = cw(R);
        if (!next) return out;
        if (*next == *c) {
            out.status = FitStatus::Fixed;
            out.reward = R;
            out.coinbase = *c;
            return out;
        }
        if (!seen.insert(*c).second) {
            out.status = FitStatus::NoFixedPoint;
            return out;
        }
        c = next;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Template selection
// ---------------------------------------------------------------------------
struct TxCandidate {
    std::uint64_t weight = 0;  // w_i
    std::uint64_t fee = 0;     // f_i (the transaction's own txnFee)
};

struct TxSelection {
    bool ok = false;                 // false: no template (a status alarm; the previous template kept)
    std::vector<std::size_t> picked;  // candidate indices, source order
    std::uint64_t T = 0;             // the selected weight
    std::uint64_t F = 0;             // the selected fees
    std::uint64_t reward = 0;        // R
    std::uint64_t coinbase = 0;      // c; w = T + c
    std::size_t penalty_zone = 0;    // picked candidates past the no-penalty set
};

namespace br_detail {

inline bool add_ok(std::uint64_t a, std::uint64_t b) noexcept { return a <= UINT64_MAX - b; }

}  // namespace br_detail

// The no-penalty fill (the default): R = B + F, w = T + cw(R) <= Z.
inline TxSelection select_no_penalty(std::span<const TxCandidate> cands, std::uint64_t base, std::uint64_t z,
                                     std::uint64_t cw_up, const CoinbaseSize& cw) {
    TxSelection s;
    for (std::size_t i = 0; i < cands.size(); ++i) {
        const TxCandidate& c = cands[i];
        if (!br_detail::add_ok(s.T, c.weight) || !br_detail::add_ok(s.T + c.weight, cw_up)) continue;
        if (s.T + c.weight + cw_up > z || !br_detail::add_ok(s.F, c.fee)) continue;
        s.T += c.weight;
        s.F += c.fee;
        s.picked.push_back(i);
    }
    for (;;) {
        if (!br_detail::add_ok(base, s.F)) return s;
        const std::optional<std::uint64_t> c = cw(base + s.F);
        if (!c) return s;
        if (br_detail::add_ok(s.T, *c) && s.T + *c <= z) {
            s.ok = true;
            s.reward = base + s.F;
            s.coinbase = *c;
            return s;
        }
        if (s.picked.empty()) return s;  // cw(B) > Z with no transaction
        const TxCandidate& last = cands[s.picked.back()];
        s.T -= last.weight;
        s.F -= last.fee;
        s.picked.pop_back();
    }
}

// The penalty-zone fill (policy, --pathb-penalty-fill).
inline constexpr std::string_view kPenaltyFillFlag = "--pathb-penalty-fill";

inline TxSelection select_penalty_fill(std::span<const TxCandidate> cands, std::uint64_t base, std::uint64_t z,
                                       std::uint8_t hf, std::uint64_t cw_up, const CoinbaseSize& cw) {
    TxSelection s = select_no_penalty(cands, base, z, cw_up, cw);
    if (!s.ok) return s;
    const TxSelection plain = s;
    const std::set<std::size_t> taken(s.picked.begin(), s.picked.end());
    const std::uint64_t limit = z > UINT64_MAX / 2 ? UINT64_MAX : 2 * z;
    std::vector<std::size_t> zone_ids;
    std::uint64_t T = s.T, F = s.F;
    for (std::size_t i = 0; i < cands.size(); ++i) {
        if (taken.count(i) != 0) continue;
        const TxCandidate& c = cands[i];
        if (!br_detail::add_ok(T, c.weight) || !br_detail::add_ok(T + c.weight, cw_up)) continue;
        if (T + c.weight + cw_up > limit || !br_detail::add_ok(F, c.fee)) continue;
        T += c.weight;
        F += c.fee;
        zone_ids.push_back(i);
    }
    while (!zone_ids.empty()) {
        const FitResult f = fit_reward(z, T, base, F, hf, cw);
        if (f.status == FitStatus::Fixed) {
            TxSelection out = plain;
            for (std::size_t i : zone_ids) out.picked.push_back(i);
            std::sort(out.picked.begin(), out.picked.end());
            out.T = T;
            out.F = F;
            out.reward = f.reward;
            out.coinbase = f.coinbase;
            out.penalty_zone = zone_ids.size();
            return out;
        }
        const TxCandidate& last = cands[zone_ids.back()];
        T -= last.weight;
        F -= last.fee;
        zone_ids.pop_back();
    }
    return plain;
}

}  // namespace c2pool::xmr::pathb
