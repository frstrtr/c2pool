// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// Derived in approach from monero-project/monero src/ringct/multiexp.cc
// (BSD-3-Clause, Straus). See PROVENANCE.md in this directory.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/rct/xmr_multiexp.hpp
//
// Multi-scalar multiplication: sum(scalar_i * point_i) over a few hundred to a
// few thousand terms. Bulletproof+ verification is one such sum compared
// against the identity, so this is where nearly all of the verifier's time
// goes.
//
// WHY A PORT AND NOT A COPY. Upstream carries three paths -- naive, Straus with
// an optional precomputed cache, and Pippenger -- plus the cached-generator
// machinery that keeps the 2048 Bulletproof+ generator tables alive across
// calls, and a boost mutex guarding them. That machinery pays for itself in a
// node verifying every transaction of every block. A pool verifies its own
// relay backlog, a few hundred transactions between blocks, so this file
// implements the ONE path that matters -- Straus with 4-bit windows, tables
// built per call -- and leaves the caches out. Two consequences worth stating
// plainly: verification here is several times slower than monerod's, and there
// is no cache lifetime to get wrong.
//
// The window is 4 bits: 64 windows over a 256-bit scalar, 15 table entries per
// point. Terms whose scalar is zero are skipped entirely, which is what makes a
// batch of mixed-size proofs cost what its largest member costs rather than
// what the padding suggests.
// ---------------------------------------------------------------------------
#pragma once

#include <vector>

#include "xmr_rct_ops.hpp"

namespace c2pool::xmr::native::rct {

// One term of the sum. The point is kept in p3 form because every producer
// already has it that way (a decoded proof element, a cofactor-cleared
// commitment, a cached generator) and re-encoding it would be pure loss.
struct MultiexpTerm {
    Key   scalar{};
    ge_p3 point{};

    MultiexpTerm() = default;
    MultiexpTerm(const Key& s, const ge_p3& p) : scalar(s), point(p) {}
};

// sum(scalar_i * point_i), encoded. An empty input is the identity.
Key multiexp(const std::vector<MultiexpTerm>& terms);

} // namespace c2pool::xmr::native::rct
