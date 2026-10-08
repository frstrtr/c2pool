// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_base_reward_kat (pathb_emission.hpp, pathb_branch.hpp, C28, M-04): B(A)
// from the emission state already_generated_coins at the anchor A_t; the mainnet
// tail = 6e11; a pre-tail anchor pays its full emission; B(A) is monotone in the
// supply. Through select_window_inputs: B(A_t) is the weight input read at A_t
// (60 below P_t); an anchor whose weight inputs are absent -> DEFER
// (MissingWeights, the anchor id, no B(A) invented); weight inputs above A_t are
// not read.
// ---------------------------------------------------------------------------
#include <cstdint>

#include "impl/xmr/pathb/pathb_branch.hpp"
#include "impl/xmr/pathb/pathb_emission.hpp"
#include "pathb_kat_branch_view.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

constexpr std::uint8_t kMain = 0x4d;

// main 0..top; already_generated_coins after block h = agc0 + h x 10^13.
KatBranchView chain(std::uint64_t top, std::uint64_t agc0) {
    KatBranchView v;
    pb::Hash32 parent{};
    for (std::uint64_t h = 0; h <= top; ++h)
        parent = v.add(kMain, h, parent, 1600000000ull + 120 * h, 1000 + h, agc0 + h * 10000000000000ull, 300000,
                       300000);
    return v;
}

}  // namespace

int main() {
    // mainnet tail: a fully-emitted supply pays the floor 6e11 (0.6 XMR).
    check(pb::base_reward_at(18446744073000000000ull, 16) == pb::kTailBaseReward
                  && pb::kTailBaseReward == 600000000000ull,
          "mainnet tail B(A) == 6e11");

    // pre-tail: B(A) above the tail and monotone in the supply.
    {
        const std::uint64_t agc = 1000000000000000ull;  // ~1e15 piconero emitted
        const std::uint64_t B = pb::base_reward_at(agc, 16);
        check(B == 35182464740199ull, "pre-tail B(1e15) == 35,182,464,740,199");
        check(pb::base_reward_at(agc + 500000000000000ull, 16) < B, "B(A) monotone: more supply -> smaller base");
    }

    // regtest at a low height, fees 0: B(A_t) from emission, R = its own base.
    check(pb::base_reward_at(/*agc=*/0, 16) == ((~std::uint64_t{0}) >> 19), "regtest genesis B(A) == MONEY_SUPPLY >> 19");

    // ---- B(A_t) through select_window_inputs ----
    const KatBranchView v = chain(100, 0);
    {
        pb::WindowInputs w;
        const pb::BranchStatus s = pb::select_window_inputs(v, block_id(kMain, 100), 16, w);
        check(s.selected(), "P_t = main 100: window inputs selected");
        check(w.a_t == block_id(kMain, 40) && w.a_t_height == 40, "A_t = main 40 (60 below P_t)");
        check(w.weights.base_reward == 35183609149378ull, "B(A_t) == base_reward_at(agc 4e14) == 35,183,609,149,378");
    }
    {
        // a fully-emitted supply at the anchor: B(A_t) == the tail 6e11.
        const KatBranchView t = chain(100, 18446000000000000000ull);
        pb::WindowInputs w;
        check(pb::select_window_inputs(t, block_id(kMain, 100), 16, w).selected()
                      && w.weights.base_reward == 600000000000ull,
              "tail anchor: B(A_t) == 6e11");
    }
    {
        // chain start: P_t below K_A -> A_t = genesis, B(A_t) at agc 0.
        pb::WindowInputs w;
        check(pb::select_window_inputs(v, block_id(kMain, 30), 16, w).selected() && w.a_t == block_id(kMain, 0)
                      && w.weights.base_reward == 35184372088831ull,
              "P_t = main 30: A_t = genesis, B(A_t) == 35,184,372,088,831");
    }

    // ---- an anchor WITHOUT weight inputs -> DEFER (nothing invented) ----
    {
        KatBranchView d = v;
        d.weights.erase(block_id(kMain, 40));
        pb::WindowInputs w;
        w.weights.base_reward = 123;
        const pb::BranchStatus s = pb::select_window_inputs(d, block_id(kMain, 100), 16, w);
        check(!s.selected() && s.verdict == pb::BranchVerdict::Defer && s.reason == pb::DeferReason::MissingWeights
                      && s.missing == block_id(kMain, 40),
              "anchor without weight inputs -> DEFER MissingWeights naming A_t");
        check(w.weights.base_reward == 123 && w.a_t == pb::Hash32{}, "DEFER leaves B(A) uncomputed");
    }

    // ---- weight inputs are read at A_t only ----
    {
        KatBranchView d = v;
        for (std::uint64_t h = 41; h <= 100; ++h) d.weights.erase(block_id(kMain, h));
        pb::WindowInputs w;
        check(pb::select_window_inputs(d, block_id(kMain, 100), 16, w).selected()
                      && w.weights.base_reward == 35183609149378ull,
              "no weight inputs above A_t: selected, B(A_t) unchanged");
    }

    return finish("v37_xmr_base_reward_kat");
}
