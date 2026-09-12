// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/contracts/fakes/fake_fetcher.hpp
//
// Compiling fake for IChainFetcher. It also DOES the D-3 chunking, so a test
// can assert that no request it recorded carries more than
// MAX_OBJECT_REQUEST_IDS ids -- the property that keeps monerod from dropping
// our GET_OBJECTS outright.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "../fetcher.hpp"

namespace c2pool::xmr::native::fakes {

class FakeFetcher final : public IChainFetcher {
public:
    struct ChainReq   { PeerRef peer; std::vector<Hash> locator; bool prune; };
    struct ObjectsReq { PeerRef peer; std::vector<Hash> ids; bool prune; };
    struct FluffyReq  { PeerRef peer; Hash block_id; std::uint64_t height;
                        std::vector<std::uint64_t> indices; };
    struct Penalty    { PeerRef peer; PeerFault fault; std::string why; };

    std::vector<ChainReq>   chain_requests;
    std::vector<ObjectsReq> object_requests;   // already chunked
    std::vector<FluffyReq>  fluffy_requests;
    std::vector<Penalty>    penalties;

    std::vector<std::pair<PeerRef, PeerSyncData>> peer_table;

    bool accept = true;   // flip to false to simulate a write-side refusal

    bool request_chain(const PeerRef& p, std::vector<Hash> locator, bool prune) override {
        if (!accept) return false;
        chain_requests.push_back({p, std::move(locator), prune});
        return true;
    }

    bool request_objects(const PeerRef& p, std::vector<Hash> ids, bool prune) override {
        if (!accept) return false;
        // D-3: chunk into requests of at most MAX_OBJECT_REQUEST_IDS ids.
        for (std::size_t i = 0; i < ids.size(); i += MAX_OBJECT_REQUEST_IDS) {
            const std::size_t n = (ids.size() - i < MAX_OBJECT_REQUEST_IDS)
                                ? (ids.size() - i) : MAX_OBJECT_REQUEST_IDS;
            object_requests.push_back({p, std::vector<Hash>(ids.begin() + static_cast<long>(i),
                                                           ids.begin() + static_cast<long>(i + n)),
                                       prune});
        }
        return true;
    }

    bool request_fluffy_missing(const PeerRef& p, const Hash& block_id,
                                std::uint64_t height,
                                std::vector<std::uint64_t> tx_indices) override {
        if (!accept) return false;
        fluffy_requests.push_back({p, block_id, height, std::move(tx_indices)});
        return true;
    }

    void penalize(const PeerRef& p, PeerFault f, const std::string& why) override {
        penalties.push_back({p, f, why});
    }

    std::vector<std::pair<PeerRef, PeerSyncData>> peers() const override {
        return peer_table;
    }

    // True when every recorded objects request honours the D-3 cap.
    bool chunking_ok() const {
        for (const auto& r : object_requests)
            if (r.ids.size() > MAX_OBJECT_REQUEST_IDS) return false;
        return true;
    }
};

} // namespace c2pool::xmr::native::fakes
