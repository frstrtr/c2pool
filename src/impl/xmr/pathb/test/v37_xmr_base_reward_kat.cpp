// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_base_reward_kat (pathb_emission.hpp, C28, M-04): B(A) from the emission
// state already_generated_coins at the anchor A_t; the mainnet tail = 6e11; a
// pre-tail anchor pays its full emission; B(A) is monotone in the supply; an
// anchor WITHOUT already_generated_coins -> DEFER (no B(A) is invented).
// ---------------------------------------------------------------------------
#include <cstdint>
#include <optional>

#include "impl/xmr/pathb/pathb_emission.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

// DEFER model: an anchor carries already_generated_coins; without it there is no
// window input, so B(A) cannot be computed and admission DEFERs.
struct Anchor {
    std::optional<std::uint64_t> already_generated_coins;
};
static bool base_reward_or_defer(const Anchor& a, std::uint8_t hf, std::uint64_t& B_out) {
    if (!a.already_generated_coins) return false;  // DEFER
    B_out = pb::base_reward_at(*a.already_generated_coins, hf);
    return true;
}

int main() {
    // mainnet tail: a fully-emitted supply pays the floor 6e11 (0.6 XMR).
    {
        std::uint64_t B = 0;
        Anchor a{std::optional<std::uint64_t>(18446744073000000000ull)};  // agc near MONEY_SUPPLY
        check(base_reward_or_defer(a, 16, B), "anchor with agc -> B(A) computed");
        check(B == pb::kTailBaseReward && B == 600000000000ull, "mainnet tail B(A) == 6e11");
    }

    // pre-tail: a receipt is admitted with R = its own base (no R-versus-B refusal).
    {
        const std::uint64_t agc = 1000000000000000ull;  // ~1e15 piconero emitted
        const std::uint64_t B = pb::base_reward_at(agc, 16);
        // B = (2^64-1 - agc) >> 19, well above the tail at this supply.
        check(B > pb::kTailBaseReward, "pre-tail B(A) above the tail");
        const std::uint64_t B_more = pb::base_reward_at(agc + 500000000000000ull, 16);
        check(B_more < B, "B(A) monotone: more supply -> smaller base");
    }

    // regtest at a low height, fees 0: B(A_t) from emission, R = its own base.
    {
        const std::uint64_t B = pb::base_reward_at(/*agc=*/0, 16);
        check(B == ((~std::uint64_t{0}) >> 19), "regtest genesis B(A) == MONEY_SUPPLY >> 19");
    }

    // an anchor WITHOUT already_generated_coins -> DEFER (nothing invented).
    {
        std::uint64_t B = 123;
        Anchor a{std::nullopt};
        check(!base_reward_or_defer(a, 16, B), "anchor without agc -> DEFER");
        check(B == 123, "DEFER leaves B(A) uncomputed");
    }

    return finish("v37_xmr_base_reward_kat");
}
