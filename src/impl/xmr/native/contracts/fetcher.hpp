// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/contracts/fetcher.hpp
//
// C2 -> C1: the request side. Implemented by the levin client, called from the
// C2 verify thread; the client serialises and writes on the io thread, so every
// method here is "post and return" and never blocks on the socket.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "types.hpp"

namespace c2pool::xmr::native {

// D-3 (pinned): monerod drops a GET_OBJECTS request carrying more ids than
// CURRENCY_PROTOCOL_MAX_OBJECT_REQUEST_COUNT. C2 plans spans of up to
// MAX_SPAN_IDS and C1 chunks each span into requests of at most
// MAX_OBJECT_REQUEST_IDS ids, reassembling per span.
inline constexpr std::size_t MAX_OBJECT_REQUEST_IDS = 100;
inline constexpr std::size_t MAX_SPAN_IDS           = 2048;

// Back-pressure (D-3): outstanding spans per peer and in total.
inline constexpr std::size_t MAX_SPANS_PER_PEER = 2;
inline constexpr std::size_t MAX_SPANS_TOTAL    = 8;

class IChainFetcher {
public:
    virtual ~IChainFetcher() = default;

    // REQUEST_CHAIN (2006). `locator` is the standard last-10 + powers-of-two
    // walk and MUST end with the genesis id.
    virtual bool request_chain(const PeerRef&,
                               std::vector<Hash> locator,
                               bool              prune) = 0;

    // REQUEST_GET_OBJECTS (2003). `ids` may exceed MAX_OBJECT_REQUEST_IDS: the
    // implementation chunks it. D-4 pins prune=true for sync and completion.
    virtual bool request_objects(const PeerRef&,
                                 std::vector<Hash> ids,
                                 bool              prune) = 0;

    // REQUEST_FLUFFY_MISSING_TX (2009), D-5: complete a fluffy block whose tx
    // hashes are not all in the pool. Bodies come back FULL and are also
    // offered to the txpool.
    virtual bool request_fluffy_missing(const PeerRef&,
                                        const Hash&                block_id,
                                        std::uint64_t              height,
                                        std::vector<std::uint64_t> tx_indices) = 0;

    // Score a peer down / ban it. PeerFault::BadPow is a 24 h ban on its own.
    virtual void penalize(const PeerRef&, PeerFault, const std::string& why) = 0;

    // Currently handshaked peers and their last advertised sync data, so C2 can
    // pick sync sources and compute the cohort height.
    virtual std::vector<std::pair<PeerRef, PeerSyncData>> peers() const = 0;
};

} // namespace c2pool::xmr::native
