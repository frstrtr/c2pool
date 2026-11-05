// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/pathb_kat_lane.hpp
// Helpers for the S3b-1b KATs: lane carriers and placements in a BinStore, and
// an in-memory IMoneroRows (the follower's rows by id, the anchor bundle's rows
// by height, RowWeights by id) read through FollowerBranchView.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <exception>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_bin_store.hpp"
#include "impl/xmr/pathb/pathb_branch_follower.hpp"
#include "impl/xmr/pathb/pathb_window_chain.hpp"
#include "pathb_kat_branch_view.hpp"  // block_id
#include "pathb_kat_check.hpp"

namespace pathb_kat {

namespace pb = ::c2pool::xmr::pathb;

// A part that throws (a broken invariant) fails by name instead of aborting the KAT.
template <class Body>
inline void run_part(const std::string& name, Body&& body) {
    try {
        body();
    } catch (const std::exception& e) {
        check(false, name + ": exception " + e.what());
    }
}

// distinct ids: tag byte, then a counter (LE64).
inline pb::Hash32 idn(std::uint8_t tag, std::uint64_t n) {
    pb::Hash32 h{};
    h[0] = tag;
    for (int i = 0; i < 8; ++i) h[1 + i] = static_cast<std::uint8_t>(n >> (8 * i));
    return h;
}

inline pb::Placement rcpt(const pb::Hash32& id, std::uint64_t bin, std::uint64_t p_own, const pb::Hash32& payee,
                          std::uint64_t work, std::uint16_t p = 0, std::uint16_t ga = 0,
                          const pb::Hash32& owner = pb::Hash32{}) {
    pb::Placement x;
    x.id = id;
    x.bin = bin;
    x.p_own = p_own;
    x.payee = payee;
    x.owner = owner;
    x.p = p;
    x.give_author_bp = ga;
    x.work = work;
    return x;
}

// add + ingest + seal (+ best); every verdict appended to *v.
inline bool extend(pb::BinStore& s, const pb::Hash32& id, const pb::Hash32& parent, std::uint64_t h,
                   const std::vector<pb::Placement>& pls, bool best, std::vector<pb::Ingest>* v = nullptr) {
    if (s.add_carrier(id, parent, h) != pb::AddVerdict::Added) return false;
    for (const pb::Placement& x : pls) {
        const std::optional<pb::Ingest> r = s.ingest(id, x);
        if (!r) return false;
        if (v) v->push_back(*r);
    }
    if (!s.seal(id)) return false;
    if (best && s.switch_best(id) != pb::SwitchVerdict::Switched) return false;
    return true;
}

inline pb::RowWeights rw(std::uint64_t agc, std::uint64_t z, std::uint64_t ltem, std::uint8_t hf = 16) {
    pb::RowWeights w;
    w.agc_after = agc;
    w.z_child = z;
    w.ltem_child = ltem;
    w.m_child = std::min(z, ltem);
    w.hf_child = hf;
    return w;
}

// A fully emitted supply: B(A) = the tail 6e11.
inline constexpr std::uint64_t kTailAgc = 18446000000000000000ull;

// The follower's rows in memory.
class KatMoneroRows final : public pb::IMoneroRows {
public:
    std::map<pb::Hash32, pb::BranchBlock> rows;            // anchor row and above, main and alt
    std::map<std::uint64_t, pb::BranchBlock> below;        // anchor bundle rows by height (<= anchor)
    std::map<pb::Hash32, pb::RowWeights> w;
    pb::BranchBlock anchor_row{};
    pb::Hash32 tip{};

    std::optional<pb::BranchBlock> block(const pb::Hash32& id) const override {
        auto it = rows.find(id);
        if (it == rows.end()) return std::nullopt;
        return it->second;
    }
    std::optional<pb::BranchBlock> block_at_or_below_anchor(std::uint64_t height) const override {
        auto it = below.find(height);
        if (it == below.end()) return std::nullopt;
        return it->second;
    }
    std::optional<pb::RowWeights> weights(const pb::Hash32& id) const override {
        auto it = w.find(id);
        if (it == w.end()) return std::nullopt;
        return it->second;
    }
    pb::BranchBlock anchor() const override { return anchor_row; }
    pb::Hash32 main_tip() const override { return tip; }

    // The anchor (tag, a) on prev id block_id(tag, a - 1), with the bundle's
    // rows for heights a - n_below .. a (timestamp ts0 + 120 h, difficulty diff
    // per block) and its RowWeights.
    pb::Hash32 seed_anchor(std::uint8_t tag, std::uint64_t a, std::uint64_t n_below, std::uint64_t ts0,
                           std::uint64_t diff, const std::optional<pb::RowWeights>& weights) {
        pb::U128 cum{};
        const std::uint64_t lo = a > n_below ? a - n_below : 0;
        for (std::uint64_t h = lo; h <= a; ++h) {
            cum = ::c2pool::xmr::native::u128_add(cum, pb::U128{diff, 0});
            pb::BranchBlock b;
            b.height = h;
            b.timestamp = ts0 + 120 * h;
            b.cumulative_difficulty = cum;
            below[h] = b;
        }
        anchor_row = below[a];
        anchor_row.id = block_id(tag, a);
        anchor_row.prev_id = a > 0 ? block_id(tag, a - 1) : pb::Hash32{};
        rows[anchor_row.id] = anchor_row;
        if (weights) w[anchor_row.id] = *weights;
        tip = anchor_row.id;
        return anchor_row.id;
    }

    // Row (tag, h) on parent; main_tip follows when `main`.
    pb::Hash32 add(std::uint8_t tag, std::uint64_t h, const pb::Hash32& parent, std::uint64_t ts, std::uint64_t diff,
                   const std::optional<pb::RowWeights>& weights, bool main = true) {
        pb::BranchBlock b;
        b.id = block_id(tag, h);
        b.prev_id = parent;
        b.height = h;
        b.timestamp = ts;
        b.cumulative_difficulty =
                ::c2pool::xmr::native::u128_add(rows.at(parent).cumulative_difficulty, pb::U128{diff, 0});
        rows[b.id] = b;
        if (weights) w[b.id] = *weights;
        if (main) tip = b.id;
        return b.id;
    }
};

// A Monero chain 0 .. top on tag (genesis = the anchor at 0), difficulty diff,
// 120 s apart, RowWeights weights_of(h) after each row.
template <class WeightsOf>
inline KatMoneroRows monero_chain(std::uint8_t tag, std::uint64_t top, std::uint64_t diff, WeightsOf&& weights_of) {
    KatMoneroRows m;
    pb::Hash32 parent = m.seed_anchor(tag, 0, 0, 1600000000ull, diff, weights_of(std::uint64_t{0}));
    for (std::uint64_t h = 1; h <= top; ++h)
        parent = m.add(tag, h, parent, 1600000000ull + 120 * h, diff, weights_of(h));
    return m;
}

}  // namespace pathb_kat
