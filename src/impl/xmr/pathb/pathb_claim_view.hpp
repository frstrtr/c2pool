// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_claim_view.hpp
// Path B, slice S3b-4a: the claim extension point of admission (ClaimView).
//
//   A full node passes no ClaimView (claims == nullptr): every basis is
//   Computed, every copy is judged, every leaf it sealed from its own
//   placements and every `at` it has bound are servable, no state rests on
//   claims. No other implementation is in this slice.
//   Basis of a row's inputs:
//     Computed     bound by a check this node computed, or the node's own
//     ClaimLeaf    a leaf adopted from a served bucket enters
//     ClaimSpan    span state or the retarget prefix enters
//     NotComputed  the row is not run
//   A computed Mismatch on a ClaimLeaf / ClaimSpan basis: local alarm + DEFER,
//   no strike token, no BAN, RandomX not called on its account.
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>

#include "pathb_params.hpp"  // Hash32

namespace c2pool::xmr::pathb {

enum class Basis : std::uint8_t { Computed, ClaimLeaf, ClaimSpan, NotComputed };

// The input classes the admission rows ask about.
enum class RowClass : std::uint8_t {
    Epoch,      // S1.3 #2, S2.3 #4: rules_epoch against epoch_at
    Retarget,   // S1.3 #8, S2.3 #11: t_origin == d_at
    Coinbase,   // S1.3 #9, S2.3 #12: the canonical coinbase over window(tip, v)
    Roots,      // S2.3 #13: window_root, mmr_root at the tip
    Fold,       // S1.3 #10: the carrier fold over S(parent)
    OriginBin,  // S2.3 #7: the H records of the placing chain
    Dedup,      // S2.3 #8: the placements of the placing chain
    Live,       // S2.3 #17 on the placing chain
    Walk        // S2.3 #3: the values a walk takes on a path it cannot bind
};

struct ClaimView {
    virtual ~ClaimView() = default;
    // The basis of the inputs row class k reads for a body whose tip is `tip`,
    // judged at position x = pos(tip) + 1.
    virtual Basis basis(RowClass k, const Hash32& tip, std::uint64_t x) const = 0;
    // Whether a side header's own S1.3 #9 can bind it at this node; NotComputed: it binds nothing.
    virtual Basis header_binding(const Hash32& id, const Hash32& header_digest) const = 0;
    // Whether a copy of an object (frame or receipt digest) that arrived from
    // `peer` is judged now; false: DEFER, no token (CopyDeferred).
    virtual bool judge_copy(std::uint64_t peer, const Hash32& object_digest) const = 0;
    // The serve side: whether the leaf of bin b, and buckets for this at header, may be served.
    virtual bool leaf_servable(std::uint64_t bin) const = 0;
    virtual bool at_servable(const Hash32& at_id, const Hash32& at_digest) const = 0;
    // Whether the node's state rests on claims at all.
    virtual bool rests_on_claims() const = 0;
};

// The basis a row reads: Computed at a full node (claims == nullptr).
inline Basis basis_of(const ClaimView* claims, RowClass k, const Hash32& tip, std::uint64_t x) {
    return claims == nullptr ? Basis::Computed : claims->basis(k, tip, x);
}

// A claim basis (ClaimLeaf / ClaimSpan).
inline constexpr bool is_claim_basis(Basis b) noexcept { return b == Basis::ClaimLeaf || b == Basis::ClaimSpan; }

}  // namespace c2pool::xmr::pathb
