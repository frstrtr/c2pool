// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/parity/xmr_tip_observer.hpp
//
// C6: the tip-observer SEAM, on its own.
//
// It was declared at the bottom of xmr_parity_sources.hpp, next to its two
// concrete implementations. That was the right place while both of them were
// the only callers -- and the wrong one as soon as something else wanted to
// DECORATE the seam, because xmr_parity_sources.hpp reaches C2c's chain view
// and therefore drags the whole vendored consensus link (keccak, the difficulty
// retarget, boost multiprecision) behind one pure virtual function.
//
// So the interface moves here and nothing else does. xmr_parity_sources.hpp
// includes this file and keeps every name it exported, so no consumer changes;
// what the split buys is that M4's PerturbingTipObserver -- a decorator that
// needs the seam and nothing under it -- stays STL-only, and so does its KAT.
//
// A tip EVENT says something moved; the oracle then ASKS both sides what they
// see. That indirection is what lets one side be an RPC round trip and the
// other a struct read without either knowing about the other.
//
// SCOPE FENCE: src/impl/xmr/ only.
// ---------------------------------------------------------------------------
#pragma once

#include "impl/xmr/native/parity/xmr_parity_types.hpp"

namespace c2pool::xmr::native::parity {

class ITipObserver {
public:
    virtual ~ITipObserver() = default;
    virtual ArmObservation observe() = 0;
};

} // namespace c2pool::xmr::native::parity
