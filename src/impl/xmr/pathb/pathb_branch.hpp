// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_branch.hpp
// Path B: Monero inputs of a tip's window, read on the branch that ends at
// P_t = prev_id(tip), by parent links only:
//   h(t)    = height(P_t) + 1
//   D_net   = Monero next_difficulty for a child of P_t, over the blocks at
//             heights [max(1, h(P_t) + 1 - DIFFICULTY_BLOCKS_COUNT), h(P_t)]
//             of that branch, oldest first
//   A_t     = the ancestor of P_t at depth min(CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, h(P_t))
//             on that branch
//   B, M, Z, reserve = the follower's weight inputs after A_t
// A missing block, missing weight inputs or a view whose parent links and
// heights disagree yields Defer with the id to fetch. There is no other
// outcome than Selected and Defer.
//
// Pulls Boost (vendored difficulty); link xmr_coin.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <optional>
#include <vector>

#include "impl/xmr/native/consensus/xmr_difficulty.hpp"  // next_difficulty_from_window, DIFFICULTY_BLOCKS_COUNT, U128

#include "pathb_params.hpp"

namespace c2pool::xmr::pathb {

using U128 = ::c2pool::xmr::native::U128;

static_assert(DIFFICULTY_WINDOW == ::c2pool::xmr::native::DIFFICULTY_WINDOW);
static_assert(DIFFICULTY_LAG == ::c2pool::xmr::native::DIFFICULTY_LAG);
static_assert(DIFFICULTY_BLOCKS_COUNT == ::c2pool::xmr::native::DIFFICULTY_BLOCKS_COUNT);

struct BranchBlock {
    Hash32 id{};
    Hash32 prev_id{};
    std::uint64_t height = 0;
    std::uint64_t timestamp = 0;
    U128 cumulative_difficulty{};
};

// The follower's weight inputs after a block.
struct WeightInputs {
    std::uint64_t base_reward = 0;  // B: base reward of a child, no fees, no penalty
    std::uint64_t fee_median = 0;   // M
    std::uint64_t zone = 0;         // Z
    std::uint64_t reserve = 0;      // coinbase transaction reserve

    friend bool operator==(const WeightInputs&, const WeightInputs&) = default;
};

// Read-only view of the Monero blocks a node holds, on every branch, by id.
class IBranchView {
public:
    virtual ~IBranchView() = default;
    virtual std::optional<BranchBlock> block(const Hash32& id) const = 0;
    virtual std::optional<WeightInputs> weights_at(const Hash32& id) const = 0;
};

enum class BranchVerdict : std::uint8_t { Selected, Defer };

enum class DeferReason : std::uint8_t {
    None,
    MissingBlock,    // `missing` is the block id to fetch
    MissingWeights,  // `missing` is the block whose weight inputs are absent
    Inconsistent,    // `missing` is a parent id whose height does not follow its child
};

struct BranchStatus {
    BranchVerdict verdict = BranchVerdict::Defer;
    DeferReason reason = DeferReason::None;
    Hash32 missing{};

    bool selected() const noexcept { return verdict == BranchVerdict::Selected; }
};

namespace detail {
inline BranchStatus defer(DeferReason r, const Hash32& id) noexcept {
    return BranchStatus{BranchVerdict::Defer, r, id};
}
inline BranchStatus selected() noexcept { return BranchStatus{BranchVerdict::Selected, DeferReason::None, {}}; }

inline BranchStatus fetch(const IBranchView& v, const Hash32& id, BranchBlock& out) {
    std::optional<BranchBlock> b = v.block(id);
    if (!b) return defer(DeferReason::MissingBlock, id);
    if (b->id != id) return defer(DeferReason::Inconsistent, id);
    out = *b;
    return selected();
}

inline BranchStatus parent_of(const IBranchView& v, const BranchBlock& child, BranchBlock& out) {
    if (child.height == 0) return defer(DeferReason::Inconsistent, child.prev_id);
    BranchBlock p;
    if (BranchStatus s = fetch(v, child.prev_id, p); !s.selected()) return s;
    if (p.height + 1 != child.height) return defer(DeferReason::Inconsistent, child.prev_id);
    out = p;
    return selected();
}
}  // namespace detail

// The ancestor of `from` reached by `steps` parent links.
inline BranchStatus ancestor_on_branch(const IBranchView& v, const Hash32& from, std::uint64_t steps,
                                       BranchBlock& out) {
    BranchBlock b;
    if (BranchStatus s = detail::fetch(v, from, b); !s.selected()) return s;
    for (std::uint64_t i = 0; i < steps; ++i) {
        BranchBlock p;
        if (BranchStatus s = detail::parent_of(v, b, p); !s.selected()) return s;
        b = p;
    }
    out = b;
    return detail::selected();
}

struct DifficultyWindowRows {
    std::vector<std::uint64_t> timestamps;
    std::vector<U128> cumulative_difficulties;
};

// Rows of the difficulty window for a child of `parent`, oldest first.
inline BranchStatus difficulty_window_for_child(const IBranchView& v, const Hash32& parent,
                                                DifficultyWindowRows& out) {
    BranchBlock b;
    if (BranchStatus s = detail::fetch(v, parent, b); !s.selected()) return s;
    const std::uint64_t count = std::min(b.height, DIFFICULTY_BLOCKS_COUNT);
    DifficultyWindowRows rows;
    rows.timestamps.reserve(count);
    rows.cumulative_difficulties.reserve(count);
    for (std::uint64_t i = 0; i < count; ++i) {
        rows.timestamps.push_back(b.timestamp);
        rows.cumulative_difficulties.push_back(b.cumulative_difficulty);
        if (i + 1 < count) {
            BranchBlock p;
            if (BranchStatus s = detail::parent_of(v, b, p); !s.selected()) return s;
            b = p;
        }
    }
    std::reverse(rows.timestamps.begin(), rows.timestamps.end());
    std::reverse(rows.cumulative_difficulties.begin(), rows.cumulative_difficulties.end());
    out = std::move(rows);
    return detail::selected();
}

// D_net: Monero next_difficulty for a child of `parent` at hard-fork version hf_child.
inline BranchStatus dnet_for_child(const IBranchView& v, const Hash32& parent, std::uint8_t hf_child, U128& out) {
    DifficultyWindowRows rows;
    if (BranchStatus s = difficulty_window_for_child(v, parent, rows); !s.selected()) return s;
    out = ::c2pool::xmr::native::next_difficulty_from_window(
            rows.timestamps, rows.cumulative_difficulties,
            ::c2pool::xmr::native::difficulty_target_seconds(hf_child));
    return detail::selected();
}

struct WindowInputs {
    Hash32 p_t{};
    std::uint64_t p_t_height = 0;
    std::uint64_t tip_height = 0;  // h(t)
    U128 d_net{};
    Hash32 a_t{};
    std::uint64_t a_t_height = 0;
    WeightInputs weights{};
};

// Window inputs of a tip whose Monero parent is p_t.
inline BranchStatus select_window_inputs(const IBranchView& v, const Hash32& p_t, std::uint8_t hf_child,
                                         WindowInputs& out) {
    BranchBlock p;
    if (BranchStatus s = detail::fetch(v, p_t, p); !s.selected()) return s;
    WindowInputs w;
    w.p_t = p.id;
    w.p_t_height = p.height;
    w.tip_height = p.height + 1;
    if (BranchStatus s = dnet_for_child(v, p_t, hf_child, w.d_net); !s.selected()) return s;
    BranchBlock a;
    const std::uint64_t depth = std::min(CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, p.height);
    if (BranchStatus s = ancestor_on_branch(v, p_t, depth, a); !s.selected()) return s;
    std::optional<WeightInputs> wi = v.weights_at(a.id);
    if (!wi) return detail::defer(DeferReason::MissingWeights, a.id);
    w.a_t = a.id;
    w.a_t_height = a.height;
    w.weights = *wi;
    out = w;
    return detail::selected();
}

}  // namespace c2pool::xmr::pathb
