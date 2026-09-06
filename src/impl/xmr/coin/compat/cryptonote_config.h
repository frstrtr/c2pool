// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/coin/compat/cryptonote_config.h
//
// AUTHORED, minimal stand-in for monero-project's `src/cryptonote_config.h`,
// supplying ONLY the difficulty-window constants the vendored reference oracle
// `../vendor/difficulty.cpp` reads (DIFFICULTY_WINDOW / _CUT / _LAG). Monero's
// real cryptonote_config.h is ~250 network/protocol macros the oracle does not
// need; pulling it whole would drag the monerod config surface into the lane.
//
// Values are the canonical Monero mainnet constants (unchanged since the CN
// v2 difficulty algo). They are consensus-inert for the XMR SETTLEMENT lane:
// the lane never RETARGETS Monero — it re-checks a solved block against the
// difficulty monerod already reported (check_hash), so only check_hash* is on
// the hot path. next_difficulty()/these window constants are compiled purely so
// the vendored TU builds intact as the check_hash cross-check oracle.
// ---------------------------------------------------------------------------
#ifndef C2POOL_XMR_COMPAT_CRYPTONOTE_CONFIG_H
#define C2POOL_XMR_COMPAT_CRYPTONOTE_CONFIG_H

// Monero mainnet difficulty-algorithm window (src/cryptonote_config.h upstream).
#define DIFFICULTY_TARGET_V2                        120  // seconds/block, post-CNv2
#define DIFFICULTY_TARGET_V1                         60  // seconds/block, pre-CNv2
#define DIFFICULTY_WINDOW                           720  // blocks sampled
#define DIFFICULTY_LAG                               15  // blocks
#define DIFFICULTY_CUT                               60  // outliers trimmed each side
#define DIFFICULTY_BLOCKS_COUNT (DIFFICULTY_WINDOW + DIFFICULTY_LAG)

#endif // C2POOL_XMR_COMPAT_CRYPTONOTE_CONFIG_H
