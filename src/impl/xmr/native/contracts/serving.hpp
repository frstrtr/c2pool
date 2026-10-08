// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/contracts/serving.hpp
//
// C2 -> C1, io-thread read side (D-2). This exists because of the state_normal
// trap: a monerod peer relays blocks and transactions to us only while it
// considers us synced AND we answer its own chain/objects requests. A node that
// advertises a tip and then refuses to serve it is dropped in ~20 s and
// silently starves.
//
// Latency contract: every method is called ON THE IO THREAD, must be O(1) or
// O(log n) against the retained window, and must NEVER block on the verify
// thread. Implementations serve from the retained rows (D-9: 2048) plus the C5
// retained-block book; anything outside that window returns nullopt, which the
// caller turns into a clean disconnect rather than a lie.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "types.hpp"

namespace c2pool::xmr::native {

class IChainServing {
public:
    virtual ~IChainServing() = default;

    // What we advertise in HANDSHAKE / TIMED_SYNC. current_height is tip + 1,
    // top_version comes from the vendored hard-fork table (fenced), and
    // pruning_seed is 0: we never claim to serve a pruning stripe.
    virtual PeerSyncData our_sync_data() const = 0;

    virtual bool have_block(const Hash&) const = 0;

    // Our own locator: last 10 ids, then powers of two back, ending at genesis.
    virtual std::vector<Hash> locator() const = 0;

    // Answer REQUEST_CHAIN (2006) from the retained window. nullopt means "no
    // common id inside the window": the caller closes the peer instead of
    // sending a misleading supplement.
    virtual std::optional<ChainEntry> find_supplement(
            const std::vector<Hash>& peer_locator) const = 0;

    // Answer REQUEST_GET_OBJECTS (2003) from the retained window or the C5
    // retained-block book. nullopt = we do not have it (goes into `missed`).
    virtual std::optional<BlockEntry> get_block_entry(const Hash&,
                                                      bool prune) const = 0;
};

} // namespace c2pool::xmr::native
