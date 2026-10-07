// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_retarget.hpp
// Path B carrier retarget (K01 T, K02 d_min, K03 N_rt and g*).
//
//   m_rt = ceil(T x g_den / (DIFFICULTY_TARGET_V2 x (g_num - g_den)))        (9 at T 10, g* 101/100)
//
//   d_at(chain, k), the difficulty of the carrier at position k >= 1 (genesis
//   is position 0 and is never in a window), from the carriers at positions
//   [lo, k - 1], lo = max(1, k - N_rt), oldest first:
//     n      = k - lo; n = 0 -> d_min
//     W      = sum of d over the window                                  (128 bit, < N_rt x 2^64)
//     dh     = H(k - 1) - H(lo)                                          (record heights)
//     dh_eff = max(dh, m_rt)
//     raw    = floor((W x T) / (DIFFICULTY_TARGET_V2 x dh_eff))          (product first, 256 bit;
//                                                                         one division, rounding down)
//     d      = min(2^64 - 1, max(d_min, raw))                            (floor d_min, then the u64
//                                                                         range as a value)
//   No per-step bound. No timestamp is an input.
//
//   record_H(c) = max(H(parent), h(c)), carriers only; a carrier needs
//   h(c) >= H(parent).
//
//   A lane that starts with a predecessor's carriers (epoch change) starts
//   with the window of the predecessor's newest N_rt carriers; a lane without
//   one starts with an empty window (d_min).
//
// Header-only. Not included by any running component.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <span>

#include "impl/xmr/native/contracts/types.hpp"  // U128, u128_add, u128_less

#include "pathb_params.hpp"

namespace c2pool::xmr::pathb {

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------
inline constexpr std::uint64_t kU64Max = std::numeric_limits<std::uint64_t>::max();

// Every product below stays inside u64.
inline constexpr bool retarget_params_valid(const LaneParams& p) noexcept {
    return p.carrier_interval_s > 0 && p.d_min > 0 && p.retarget_span > 0 && p.retarget_growth_den > 0
           && p.retarget_growth_num > p.retarget_growth_den
           && p.carrier_interval_s <= kU64Max / p.retarget_growth_den
           && p.retarget_growth_num - p.retarget_growth_den <= kU64Max / DIFFICULTY_TARGET_V2;
}

// m_rt = ceil(T x g_den / (DIFFICULTY_TARGET_V2 x (g_num - g_den))). Precondition: retarget_params_valid(p).
inline constexpr std::uint64_t retarget_min_span(const LaneParams& p) noexcept {
    return ceil_div(p.carrier_interval_s * p.retarget_growth_den,
                    DIFFICULTY_TARGET_V2 * (p.retarget_growth_num - p.retarget_growth_den));
}

// ---------------------------------------------------------------------------
// Window entries and record heights
// ---------------------------------------------------------------------------
struct RetargetEntry {
    std::uint64_t d = 0;  // carrier difficulty
    std::uint64_t H = 0;  // record height through this carrier

    friend bool operator==(const RetargetEntry&, const RetargetEntry&) = default;
};

inline constexpr std::uint64_t record_height(std::uint64_t parent_record, std::uint64_t h) noexcept {
    return std::max(parent_record, h);
}

inline constexpr bool carrier_height_admissible(std::uint64_t parent_record, std::uint64_t h) noexcept {
    return h >= parent_record;
}

// ---------------------------------------------------------------------------
// 256-bit helpers (no 128-bit builtin)
// ---------------------------------------------------------------------------
namespace rt_wide {

using U128 = ::c2pool::xmr::native::U128;

inline constexpr unsigned kLimbBits = std::numeric_limits<std::uint64_t>::digits;
inline constexpr unsigned kHalfBits = kLimbBits / 2;
inline constexpr std::uint64_t kHalfMask = (std::uint64_t{1} << kHalfBits) - 1;
inline constexpr std::size_t kLimbs = 4;

struct U256 {
    std::array<std::uint64_t, kLimbs> w{};  // little-endian limbs

    friend bool operator==(const U256&, const U256&) = default;
};

inline constexpr U128 u128_sub(const U128& a, const U128& b) noexcept {
    U128 r{};
    r.lo = a.lo - b.lo;
    r.hi = a.hi - b.hi - (a.lo < b.lo ? 1u : 0u);
    return r;
}

inline constexpr U128 mul_64x64(std::uint64_t a, std::uint64_t b) noexcept {
    const std::uint64_t a0 = a & kHalfMask, a1 = a >> kHalfBits;
    const std::uint64_t b0 = b & kHalfMask, b1 = b >> kHalfBits;
    const std::uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
    const std::uint64_t mid = (p00 >> kHalfBits) + (p01 & kHalfMask) + (p10 & kHalfMask);
    U128 r{};
    r.lo = (p00 & kHalfMask) | (mid << kHalfBits);
    r.hi = p11 + (p01 >> kHalfBits) + (p10 >> kHalfBits) + (mid >> kHalfBits);
    return r;
}

inline constexpr U256 mul_u128_u64(const U128& a, std::uint64_t b) noexcept {
    const U128 lo = mul_64x64(a.lo, b);
    const U128 hi = mul_64x64(a.hi, b);
    U256 r{};
    r.w[0] = lo.lo;
    r.w[1] = lo.hi + hi.lo;
    r.w[2] = hi.hi + (r.w[1] < lo.hi ? 1u : 0u);
    return r;
}

// floor(n / d), d != 0. Remainder kept in 128 bits with the shifted-out bit.
inline constexpr U256 div_u256_u128(const U256& n, const U128& d) noexcept {
    U256 q{};
    U128 r{};
    for (std::size_t i = kLimbs * kLimbBits; i-- > 0;) {
        const bool carry = (r.hi >> (kLimbBits - 1)) != 0;
        r.hi = (r.hi << 1) | (r.lo >> (kLimbBits - 1));
        r.lo = (r.lo << 1) | ((n.w[i / kLimbBits] >> (i % kLimbBits)) & 1u);
        if (carry || !::c2pool::xmr::native::u128_less(r, d)) {
            r = u128_sub(r, d);
            q.w[i / kLimbBits] |= std::uint64_t{1} << (i % kLimbBits);
        }
    }
    return q;
}

inline constexpr bool fits_u64(const U256& v) noexcept { return (v.w[1] | v.w[2] | v.w[3]) == 0; }

}  // namespace rt_wide

// ---------------------------------------------------------------------------
// The retarget
// ---------------------------------------------------------------------------

// d from the window size n, its work W and its record-height span dh.
// Precondition: retarget_params_valid(p).
inline constexpr std::uint64_t retarget_from(const LaneParams& p, std::size_t n, const rt_wide::U128& W,
                                             std::uint64_t dh) noexcept {
    if (n == 0) return p.d_min;
    const std::uint64_t dh_eff = std::max(dh, retarget_min_span(p));
    const rt_wide::U256 num = rt_wide::mul_u128_u64(W, p.carrier_interval_s);
    const rt_wide::U128 den = rt_wide::mul_64x64(DIFFICULTY_TARGET_V2, dh_eff);
    const rt_wide::U256 raw = rt_wide::div_u256_u128(num, den);
    if (!rt_wide::fits_u64(raw)) return kU64Max;  // raw >= 2^64 > d_min
    return std::max(p.d_min, raw.w[0]);
}

// d for the carrier after `chain` (carriers oldest first, genesis excluded):
// the window is its newest N_rt entries. Precondition: record heights do not
// decrease along `chain`.
inline std::uint64_t retarget(const LaneParams& p, std::span<const RetargetEntry> chain) noexcept {
    const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(chain.size(), p.retarget_span));
    const std::span<const RetargetEntry> win = chain.subspan(chain.size() - n);
    rt_wide::U128 W{};
    for (const RetargetEntry& e : win) W = ::c2pool::xmr::native::u128_add(W, rt_wide::U128{e.d, 0});
    const std::uint64_t dh = n == 0 || win.back().H < win.front().H ? 0 : win.back().H - win.front().H;
    return retarget_from(p, n, W, dh);
}

// ---------------------------------------------------------------------------
// Rolling window of one chain: the newest N_rt carriers and their work.
// ---------------------------------------------------------------------------
class RetargetWindow {
public:
    explicit RetargetWindow(const LaneParams& p) : p_(p) {}

    // A window that starts from a predecessor's carriers (oldest first); the
    // newest N_rt are kept.
    RetargetWindow(const LaneParams& p, std::span<const RetargetEntry> predecessor) : p_(p) {
        for (const RetargetEntry& e : predecessor) push(e);
    }

    const LaneParams& params() const noexcept { return p_; }
    std::size_t size() const noexcept { return entries_.size(); }
    bool empty() const noexcept { return entries_.empty(); }
    const std::deque<RetargetEntry>& entries() const noexcept { return entries_; }
    const rt_wide::U128& work() const noexcept { return work_; }
    std::uint64_t newest_record() const noexcept { return entries_.empty() ? 0 : entries_.back().H; }

    std::uint64_t height_span() const noexcept {
        if (entries_.empty() || entries_.back().H < entries_.front().H) return 0;
        return entries_.back().H - entries_.front().H;
    }

    // d of the next carrier.
    std::uint64_t next_difficulty() const noexcept { return retarget_from(p_, entries_.size(), work_, height_span()); }

    // Append a carrier (d, record height); the oldest leaves when N_rt are held.
    void push(const RetargetEntry& e) {
        entries_.push_back(e);
        work_ = ::c2pool::xmr::native::u128_add(work_, rt_wide::U128{e.d, 0});
        while (entries_.size() > p_.retarget_span) {
            work_ = rt_wide::u128_sub(work_, rt_wide::U128{entries_.front().d, 0});
            entries_.pop_front();
        }
    }

    // Append the next carrier at template height h: d = next_difficulty(),
    // record height max(newest record, h). Returns d.
    std::uint64_t extend(std::uint64_t h) {
        const std::uint64_t d = next_difficulty();
        push(RetargetEntry{d, entries_.empty() ? h : record_height(entries_.back().H, h)});
        return d;
    }

private:
    LaneParams p_;
    std::deque<RetargetEntry> entries_;
    rt_wide::U128 work_{};
};

}  // namespace c2pool::xmr::pathb
