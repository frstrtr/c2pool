// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// Derived in approach from monero-project/monero src/ringct/multiexp.cc
// (BSD-3-Clause, Straus). See PROVENANCE.md in this directory.
// ---------------------------------------------------------------------------
#include "xmr_multiexp.hpp"

#include <cstddef>

namespace c2pool::xmr::native::rct {
namespace {

constexpr std::size_t WINDOW_BITS   = 4;
constexpr std::size_t WINDOW_VALUES = 1u << WINDOW_BITS;   // 16: digits 0..15
constexpr std::size_t N_WINDOWS     = 256 / WINDOW_BITS;   // 64

// Odd-and-even multiples 1P..15P of one point, in the `cached` form ge_add
// wants. Index 0 is unused so a digit indexes the table directly.
struct PointTable {
    ge_cached m[WINDOW_VALUES];
};

void build_table(const ge_p3& p, PointTable& t) {
    ge_p3 acc = p;
    ge_p3_to_cached(&t.m[1], &acc);
    for (std::size_t k = 2; k < WINDOW_VALUES; ++k) {
        ge_p1p1 sum;
        ge_add(&sum, &acc, &t.m[1]);
        ge_p1p1_to_p3(&acc, &sum);
        ge_p3_to_cached(&t.m[k], &acc);
    }
}

// The 4-bit digit of `s` at window `w`, counting w = 0 as the MOST significant
// window. Scalars are little-endian, so window w lives in byte 31 - w/2.
inline std::uint8_t digit_at(const Key& s, std::size_t w) noexcept {
    const std::size_t  byte = 31 - (w >> 1);
    const std::uint8_t v    = s[byte];
    return (w & 1) ? static_cast<std::uint8_t>(v & 0x0f)
                   : static_cast<std::uint8_t>(v >> 4);
}

} // namespace

Key multiexp(const std::vector<MultiexpTerm>& terms) {
    // Skip zero-scalar terms up front: in a batch of proofs of different sizes
    // most of the padded generator slots are zero, and a table for them is
    // 15 point additions thrown away.
    std::vector<const MultiexpTerm*> live;
    live.reserve(terms.size());
    for (const MultiexpTerm& t : terms)
        if (!scalar_is_zero(t.scalar)) live.push_back(&t);

    if (live.empty()) return identity();

    std::vector<PointTable> tables(live.size());
    for (std::size_t i = 0; i < live.size(); ++i)
        build_table(live[i]->point, tables[i]);

    ge_p3 acc = ge_p3_identity;
    bool  acc_is_identity = true;

    for (std::size_t w = 0; w < N_WINDOWS; ++w) {
        if (!acc_is_identity) {
            // acc <<= 4
            for (std::size_t d = 0; d < WINDOW_BITS; ++d) {
                ge_p1p1 dbl;
                ge_p3_dbl(&dbl, &acc);
                ge_p1p1_to_p3(&acc, &dbl);
            }
        }
        for (std::size_t i = 0; i < live.size(); ++i) {
            const std::uint8_t d = digit_at(live[i]->scalar, w);
            if (d == 0) continue;
            ge_p1p1 sum;
            ge_add(&sum, &acc, &tables[i].m[d]);
            ge_p1p1_to_p3(&acc, &sum);
            acc_is_identity = false;
        }
    }

    return point_encode(acc);
}

} // namespace c2pool::xmr::native::rct
