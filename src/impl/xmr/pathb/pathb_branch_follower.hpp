// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_branch_follower.hpp
// Path B, slice S3b-1b: the Monero inputs of a window read from the follower,
// by id on every branch it holds. [C41, C28, M-03, M-04, M-06, M-07; K11d]
//
//   RowWeights      the follower's weight state right after a row is connected
//                   (or seeded as the anchor): agc_after, z_child = the
//                   effective median for a child, ltem_child = the long-term
//                   effective median for a child, m_child = min(z_child,
//                   ltem_child) (the fee median M, R-14), hf_child.
//   snapshot_after_connect(state, row)
//                   RowWeights of the state whose tip is row; nullopt otherwise.
//   encode / decode RowWeights (33 B) and a table of them by row id (the
//                   follower snapshot part; decoders fail closed).
//   IMoneroRows     the follower's rows by id (main and alt, the anchor row and
//                   above), the anchor bundle's difficulty rows by height at or
//                   below the anchor, RowWeights by id, the anchor row, the
//                   main tip.
//   FollowerBranchView (IBranchView)
//                   block(id): a held row; a parent walk below the anchor goes
//                     on by height through the anchor bundle's rows (node-local
//                     ids below the anchor's parent; nothing at or below the
//                     anchor reorgs);
//                   weights_at(id): WeightInputs{ base_reward_at(agc_after,
//                     hf_child), M = m_child, Z = z_child, reserve 0 }; none ->
//                     select_window_inputs DEFERs (MissingWeights);
//                   window_inputs(P_t, v): every input read at P_t's branch.
//
// Genesis (I-4): when h(P_t) < K_A, A_t is the genesis row and agc_after is the
// genesis row's own already_generated_coins (the genesis coinbase).
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <vector>

#include "impl/xmr/native/chain/xmr_consensus_state.hpp"  // ConsensusState, ChainRow

#include "pathb_branch.hpp"
#include "pathb_emission.hpp"
#include "pathb_params.hpp"

namespace c2pool::xmr::pathb {

// ---------------------------------------------------------------------------
// RowWeights: the follower's weight state after a row, for a child of it.
// ---------------------------------------------------------------------------
struct RowWeights {
    std::uint64_t agc_after = 0;   // already_generated_coins after the row
    std::uint64_t z_child = 0;     // effective median weight for a child (Z)
    std::uint64_t m_child = 0;     // fee median for a child: min(z_child, ltem_child) (M, R-14)
    std::uint64_t ltem_child = 0;  // long-term effective median for a child
    std::uint8_t hf_child = 0;     // major version of a child

    friend bool operator==(const RowWeights&, const RowWeights&) = default;
};

// The RowWeights of `st` right after `row` was connected (or seeded): the
// state's tip must be the row.
inline std::optional<RowWeights> snapshot_after_connect(const ::c2pool::xmr::native::ConsensusState& st,
                                                        const ::c2pool::xmr::native::ChainRow& row) {
    const ::c2pool::xmr::native::ChainRow* tip = st.tip();
    if (tip == nullptr || !(tip->id == row.id) || tip->height != row.height) return std::nullopt;
    RowWeights w;
    w.agc_after = st.already_generated_coins();
    w.hf_child = st.next_major_version();
    w.z_child = st.effective_median_weight();
    w.ltem_child = st.long_term_effective_median();
    w.m_child = std::min(w.z_child, w.ltem_child);
    return w;
}

// ---------------------------------------------------------------------------
// Codec: u64 agc_after | u64 z_child | u64 m_child | u64 ltem_child | u8 hf_child
// (LE, 33 B); the decoder requires m_child == min(z_child, ltem_child) and
// hf_child != 0. Table: u32 n | n x (id[32] | RowWeights[33]), ids strictly
// ascending, no trailing bytes.
// ---------------------------------------------------------------------------
inline constexpr std::size_t kRowWeightsBytes = 4 * sizeof(std::uint64_t) + 1;

namespace detail_rw {
inline void put_u64(std::vector<std::uint8_t>& out, std::uint64_t x) {
    for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i) out.push_back(static_cast<std::uint8_t>(x >> (8 * i)));
}
inline std::uint64_t get_u64(std::span<const std::uint8_t> in, std::size_t o) {
    std::uint64_t x = 0;
    for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i) x |= std::uint64_t{in[o + i]} << (8 * i);
    return x;
}
}  // namespace detail_rw

inline void encode_row_weights(const RowWeights& w, std::vector<std::uint8_t>& out) {
    detail_rw::put_u64(out, w.agc_after);
    detail_rw::put_u64(out, w.z_child);
    detail_rw::put_u64(out, w.m_child);
    detail_rw::put_u64(out, w.ltem_child);
    out.push_back(w.hf_child);
}

inline std::optional<RowWeights> decode_row_weights(std::span<const std::uint8_t> in) {
    if (in.size() != kRowWeightsBytes) return std::nullopt;
    RowWeights w;
    w.agc_after = detail_rw::get_u64(in, 0);
    w.z_child = detail_rw::get_u64(in, 8);
    w.m_child = detail_rw::get_u64(in, 16);
    w.ltem_child = detail_rw::get_u64(in, 24);
    w.hf_child = in[32];
    if (w.hf_child == 0 || w.m_child != std::min(w.z_child, w.ltem_child)) return std::nullopt;
    return w;
}

inline std::vector<std::uint8_t> encode_row_weights_table(const std::map<Hash32, RowWeights>& t) {
    std::vector<std::uint8_t> out;
    out.reserve(4 + t.size() * (kHashBytes + kRowWeightsBytes));
    const std::uint32_t n = static_cast<std::uint32_t>(t.size());
    for (std::size_t i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>(n >> (8 * i)));
    for (const auto& [id, w] : t) {
        out.insert(out.end(), id.begin(), id.end());
        encode_row_weights(w, out);
    }
    return out;
}

inline std::optional<std::map<Hash32, RowWeights>> decode_row_weights_table(std::span<const std::uint8_t> in) {
    constexpr std::size_t rec = kHashBytes + kRowWeightsBytes;
    if (in.size() < 4) return std::nullopt;
    std::uint32_t n = 0;
    for (std::size_t i = 0; i < 4; ++i) n |= std::uint32_t{in[i]} << (8 * i);
    if ((in.size() - 4) % rec != 0 || (in.size() - 4) / rec != n) return std::nullopt;
    std::map<Hash32, RowWeights> t;
    Hash32 prev{};
    for (std::size_t k = 0; k < n; ++k) {
        const std::size_t o = 4 + k * rec;
        Hash32 id{};
        std::copy_n(in.begin() + static_cast<std::ptrdiff_t>(o), kHashBytes, id.begin());
        if (k > 0 && !(prev < id)) return std::nullopt;
        const std::optional<RowWeights> w = decode_row_weights(in.subspan(o + kHashBytes, kRowWeightsBytes));
        if (!w) return std::nullopt;
        t.emplace(id, *w);
        prev = id;
    }
    return t;
}

// ---------------------------------------------------------------------------
// The follower's rows, as the view reads them.
// ---------------------------------------------------------------------------
class IMoneroRows {
public:
    virtual ~IMoneroRows() = default;
    // A connected row by id, main or alt: the anchor row and every row above it.
    virtual std::optional<BranchBlock> block(const Hash32& id) const = 0;
    // The anchor bundle's difficulty rows by height, at or below the anchor
    // (timestamp, cumulative difficulty; ids are not part of the bundle).
    virtual std::optional<BranchBlock> block_at_or_below_anchor(std::uint64_t height) const = 0;
    // RowWeights recorded after a connected row (the anchor row: at seed).
    virtual std::optional<RowWeights> weights(const Hash32& id) const = 0;
    // The anchor row (height, id, prev_id).
    virtual BranchBlock anchor() const = 0;
    // The follower's main tip.
    virtual Hash32 main_tip() const = 0;
};

// Node-local ids of the anchor bundle's rows below the anchor's parent: 24
// bytes 0xff, then the height (LE64).
inline Hash32 below_anchor_id(std::uint64_t height) {
    Hash32 id;
    id.fill(0xff);
    for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i)
        id[kHashBytes - sizeof(std::uint64_t) + i] = static_cast<std::uint8_t>(height >> (8 * i));
    return id;
}

inline std::optional<std::uint64_t> below_anchor_height(const Hash32& id) {
    for (std::size_t i = 0; i < kHashBytes - sizeof(std::uint64_t); ++i)
        if (id[i] != 0xff) return std::nullopt;
    std::uint64_t h = 0;
    for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i)
        h |= std::uint64_t{id[kHashBytes - sizeof(std::uint64_t) + i]} << (8 * i);
    return h;
}

class FollowerBranchView final : public IBranchView {
public:
    explicit FollowerBranchView(const IMoneroRows& rows) : rows_(rows) {}

    std::optional<BranchBlock> block(const Hash32& id) const override {
        if (std::optional<BranchBlock> b = rows_.block(id)) return b;
        const BranchBlock a = rows_.anchor();
        std::optional<std::uint64_t> h;
        if (a.height > 0 && id == a.prev_id) {
            h = a.height - 1;
        } else if (const std::optional<std::uint64_t> x = below_anchor_height(id); x && *x + 1 < a.height) {
            h = x;
        }
        if (!h) return std::nullopt;
        const std::optional<BranchBlock> r = rows_.block_at_or_below_anchor(*h);
        if (!r) return std::nullopt;
        BranchBlock out;
        out.id = id;
        out.height = *h;
        out.prev_id = *h == 0 ? Hash32{} : below_anchor_id(*h - 1);
        out.timestamp = r->timestamp;
        out.cumulative_difficulty = r->cumulative_difficulty;
        return out;
    }

    std::optional<WeightInputs> weights_at(const Hash32& id) const override {
        const std::optional<RowWeights> w = rows_.weights(id);
        if (!w) return std::nullopt;
        return WeightInputs{base_reward_at(w->agc_after, w->hf_child), w->m_child, w->z_child, 0};
    }

    // The window inputs of a tip whose Monero parent is p_t at version v: every
    // input read on the branch ending at p_t (C41).
    BranchStatus window_inputs(const Hash32& p_t, std::uint8_t v, WindowInputs& out) const {
        return select_window_inputs(*this, p_t, v, out);
    }

    Hash32 main_tip() const { return rows_.main_tip(); }

private:
    const IMoneroRows& rows_;
};

}  // namespace c2pool::xmr::pathb
