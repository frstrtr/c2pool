// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_ring_rule.hpp
// Path B roundabouts, slice C-3: the ring rule of a compiled epoch whose
// payment_groups (K17) is not 1. Test builds only (V37_XMR_RING_TEST_EPOCHS):
// a release build holds no ring rule.
//
//   depth_max  the deepest ring the epoch may reach (unset: nullopt)
//   step_max   the largest depth change at one K step (unset: nullopt)
//
// Every field is unset when value-initialised; ring_rules_valid refuses an
// unset field of an epoch whose K17 is not 1.
//
// Header-only.
// ---------------------------------------------------------------------------
#pragma once

#ifndef V37_XMR_RING_TEST_EPOCHS
#error "pathb_ring_rule.hpp is built only with V37_XMR_RING_TEST_EPOCHS (test builds; never in a release)"
#endif

#include <cstdint>
#include <optional>

namespace c2pool::xmr::pathb {

// A K step changes the depth by at least one level.
inline constexpr std::uint8_t kRingStepMin = 1;

struct RingRule {
    std::optional<std::uint8_t> depth_max;
    std::optional<std::uint8_t> step_max;

    friend bool operator==(const RingRule&, const RingRule&) = default;
};

}  // namespace c2pool::xmr::pathb
