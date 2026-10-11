// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/c2pool/v37/xmr/pathb/pathb_template_select.hpp
// The template's transaction selection, one function called by
// PathbNode::make_template and by the follow-only template record:
//   select_template(cands, B(P_r), Z(P_r), hf, h, w, penalty_fill)
//     TxCandidate per candidate (the source's order); F_all = the fees of
//     every candidate; the coinbase outputs: one output of R when w is null
//     or holds no window payee (the finder alone), else hf16_outputs(R, w);
//     cw(R) = coinbase_weight_hf16(h, the amounts); cw_up = the coinbase size
//     with every amount at R_up = B + F_all; select_no_penalty, or
//     select_penalty_fill when penalty_fill (--pathb-penalty-fill).
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "impl/xmr/pathb/pathb_block_reward.hpp"
#include "impl/xmr/pathb/pathb_coinbase_split.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"

namespace c2pool::xmr::pathb {

// A candidate transaction of the template (the source's order): its hash,
// weight and fee read from its own bytes.
struct TemplateTx {
    Hash32 hash{};
    std::uint64_t weight = 0;
    std::uint64_t fee = 0;
};

// w == nullptr: one output of R (the empty-window shape).
inline TxSelection select_template(std::span<const TemplateTx> cands, std::uint64_t base, std::uint64_t z,
                                   std::uint8_t hf, std::uint64_t h, const Window* w, bool penalty_fill) {
    std::vector<TxCandidate> tc;
    tc.reserve(cands.size());
    std::uint64_t f_all = 0;
    for (const TemplateTx& c : cands) {
        tc.push_back(TxCandidate{c.weight, c.fee});
        f_all = f_all > UINT64_MAX - c.fee ? UINT64_MAX : f_all + c.fee;
    }
    const bool one_output = w == nullptr || w->empty_finder_only;
    const std::size_t n_out = one_output ? 1 : w->weight.size();
    const std::uint64_t r_up = base > UINT64_MAX - f_all ? UINT64_MAX : base + f_all;
    const std::uint64_t cw_up = coinbase_weight_hf16(h, std::vector<std::uint64_t>(n_out, r_up));
    const CoinbaseSize cw = [w, one_output, h](std::uint64_t R) -> std::optional<std::uint64_t> {
        std::vector<std::uint64_t> a;
        if (one_output) {
            a.push_back(R);
        } else {
            for (const SplitOutput& o : hf16_outputs(R, *w)) a.push_back(o.amount);
            if (a.empty()) return std::nullopt;
        }
        return coinbase_weight_hf16(h, a);
    };
    return penalty_fill ? select_penalty_fill(tc, base, z, hf, cw_up, cw) : select_no_penalty(tc, base, z, cw_up, cw);
}

}  // namespace c2pool::xmr::pathb
