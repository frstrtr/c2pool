// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/contracts/outputs.hpp
//
// The two chain-derived views the txpool's INPUT-consensus step needs and which
// no other contract already exposed:
//
//   * IRingMemberSource -- resolve a ring's absolute global-output offsets into
//     (one-time public key, amount commitment) pairs, so the CLSAG signature
//     can be checked against real, chain-known members. This is the surface the
//     original C3 header said could not be built "without the global output
//     set"; it is what the ChainOutputSet (built from connected blocks above
//     the anchor) and, optionally, a daemon's get_outs, implement.
//   * ISpentKeyImageView -- is this key image already spent ON THE CHAIN (not
//     merely in another pool entry)? This is the GLOBAL double-spend check, as
//     opposed to the pool-local KeyImageConflict the pool already did.
//
// Both are read-only, const, and take bytes an unauthenticated peer chose, so
// every method is a query that returns a verdict and never throws. A null
// source is a legal state (a node below its anchor with no daemon armed): the
// txpool then treats every ring as unresolved and fails closed, exactly as it
// fails closed when non-input verification is disabled.
//
// Wave-0 contract family: header-only, STL + the shared value types only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <vector>

#include "types.hpp"

namespace c2pool::xmr::native {

// OutputRecord is defined in types.hpp (BlockTxEvent carries a vector of them).

// Resolve ring members. `amount` is the input's amount (0 for every RCT input;
// carried so a future pre-RCT path is expressible). `absolute_offsets` are the
// ring's key-offsets already de-relativised (running sum), ascending. On
// success `out` has one record per offset, in the same order. Returns false if
// ANY offset is unknown to this source (beyond its frontier, or below its
// anchor) -- the caller must then fail closed (RingUnresolved), never admit.
class IRingMemberSource {
public:
    virtual ~IRingMemberSource() = default;
    virtual bool resolve(std::uint64_t amount,
                         const std::vector<std::uint64_t>& absolute_offsets,
                         std::vector<OutputRecord>&        out) const = 0;
};

// Global spent-key-image view. True iff `ki` has been spent by a transaction in
// a block this view has connected. A false answer from a source that does not
// reach back to the key image's real spend height is NOT proof of not-spent;
// the txpool composes this with the ring source's coverage so a false answer is
// only trusted where the source's window actually covers the spend.
class ISpentKeyImageView {
public:
    virtual ~ISpentKeyImageView() = default;
    virtual bool is_spent(const Hash& ki) const = 0;
};

} // namespace c2pool::xmr::native
