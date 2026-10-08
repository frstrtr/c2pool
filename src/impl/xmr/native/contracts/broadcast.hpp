// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/contracts/broadcast.hpp
//
// C1 -> C5 (D-10): the outbound notify port. C1 implements it and posts to the
// io thread; C5 owns the retained-block book, not C1.
//
// WHAT THE CALLER PASSES IS THE MESSAGE BODY, NOT A FRAME. The implementation
// writes the 33-byte levin bucket header around it (LevinLink::send_notify ->
// make_notify). Passing an already-framed buffer produces a doubly-framed
// notification that every Monero peer answers with
//   portable_storage: wrong binary format - signature mismatch
// and drops -- with the peers-written count still reading perfectly, because
// the bytes DID reach the socket. C5 shipped exactly that bug until a live
// monerod said so; the parameter is named `body` here for that reason.
//
// broadcast_notify() returns the number of peers the body was actually written
// to, and it counts ONLY handshaked peers in state_normal. That number is the
// input to the never-silent-drop rule: a found block that reached zero peers
// and had no daemon arm is a loud failure, never a shrug. It is a DELIVERY
// count and never an acceptance: no peer answers an unsolicited notification.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <vector>

#include "types.hpp"

namespace c2pool::xmr::native {

// Handler installed by C5 to answer a peer asking for the transactions it is
// missing from a fluffy block we pushed (REQUEST_FLUFFY_MISSING_TX, 2009).
// Fills `reply_2008` with the NOTIFY_NEW_FLUFFY_BLOCK message BODY (the caller
// frames it, same rule as broadcast_notify) and returns true, or returns false
// to decline.
using FluffyMissingHandler = std::function<bool(const PeerRef&,
                                                const Hash&                       block_id,
                                                std::uint64_t                     height,
                                                const std::vector<std::uint64_t>& tx_indices,
                                                std::vector<std::uint8_t>&        reply_2008)>;

class IBroadcastPort {
public:
    virtual ~IBroadcastPort() = default;

    // Send to every handshaked peer in state_normal. `body` is the epee message
    // body; the implementation frames it. Returns the count written.
    virtual std::size_t broadcast_notify(std::uint32_t             cmd,
                                         std::vector<std::uint8_t> body) = 0;

    // Send to one peer, same body-not-frame contract. False when the peer is
    // gone or not writable.
    virtual bool send_notify(const PeerRef&,
                             std::uint32_t             cmd,
                             std::vector<std::uint8_t> body) = 0;

    virtual void set_fluffy_missing_handler(FluffyMissingHandler) = 0;

    virtual std::size_t peer_count() const = 0;

    // ASN hint -> peer count, for the eclipse guard (at least 8 outbound peers
    // over at least 3 distinct ASNs before the daemon may be demoted).
    virtual std::map<std::uint32_t, std::size_t> peers_by_asn() const = 0;
};

} // namespace c2pool::xmr::native
