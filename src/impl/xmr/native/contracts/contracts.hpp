// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/contracts/contracts.hpp
//
// Umbrella include for the Wave 0 contracts family. Including this header must
// stay cheap: everything under contracts/ is header-only, STL plus the existing
// lane value types, and free of transport, crypto and threading dependencies.
// If that ever stops being true, the fence this family exists to provide is
// gone -- see the CONTRACT NOTE in relay.hpp and the WHAT IS NOT HERE note in
// anchor.hpp for the two places it was tested.
// ---------------------------------------------------------------------------
#pragma once

#include "types.hpp"
#include "anchor.hpp"
#include "chain_index.hpp"
#include "fetcher.hpp"
#include "serving.hpp"
#include "txpool.hpp"
#include "broadcast.hpp"
#include "miner_data.hpp"
#include "relay.hpp"
#include "parity.hpp"
