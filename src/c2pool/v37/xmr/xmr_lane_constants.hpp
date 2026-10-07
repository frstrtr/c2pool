// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_lane_constants.hpp
//
// XMR lane constants shared by the node configuration and the stratum
// listener. Header-only, no dependencies.
// ===========================================================================
#pragma once

#include <cstdint>

namespace c2pool::v37n::xmr {

// k: the raindrop floor is share_diff / 2^k, the job difficulty the node serves
// every miner; the lane credits every hash below it at the floor's work
// (SubthresholdGate mode 2, Count).
inline constexpr std::uint32_t kXmrDropsFloorShift = 6;

// T: the lane's target carrier interval, seconds (canon C11).
inline constexpr std::uint32_t kXmrTargetIntervalS = 10;

}  // namespace c2pool::v37n::xmr
