// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/relay/xmr_relay_peerstore.hpp   (RELAY-DISCOVERY)
//
// PERSISTENT PEER STORAGE for the XMR relay: the relay's PeerBook
// (xmr_relay_peerbook.hpp) on disk as a core::AddrStore (src/core/addr_store,
// the same JSON store the v36 coins keep their addrs in). Implemented in
// xmr_relay_peerstore.cpp inside a small static library that links core, so
// the daemon TU and the stdlib-only relay KATs never see core's include paths
// (the xmr_web_dashboard pattern, src/c2pool/CMakeLists.txt).
//
// One file per pool id + network: <data-dir>/relay_peers_<net>_<pool-tag 16 hex>.json
// (a book can therefore only ever answer FB_GETADDR with peers of ITS pool).
// core::AddrValue carries: m_first_seen / m_last_seen = PeerRecord's, and
// m_service = the relay flags  bit 0 GOOD | bits 8..15 consecutive dial failures.
// ===========================================================================
#pragma once

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "xmr_relay_peerbook.hpp"

namespace c2pool::v37n::xmr::relay {

inline constexpr std::uint64_t kPeerSvcGood = 1ull << 0;
inline std::uint64_t peer_service_of(const PeerRecord& r) {
    return (r.good ? kPeerSvcGood : 0) | (static_cast<std::uint64_t>(std::min<std::uint32_t>(r.fails, 255)) << 8);
}
inline void peer_service_apply(std::uint64_t svc, PeerRecord& r) {
    r.good = (svc & kPeerSvcGood) != 0;
    r.fails = static_cast<std::uint32_t>((svc >> 8) & 0xff);
}

inline std::string peerstore_file_name(std::uint8_t network, const std::string& pool_hex) {   // lane_tag[0..8) || pool_genesis[0..8), hex
    return "relay_peers_" + std::to_string(network) + "_" + pool_hex.substr(0, 16) + ".json";
}

// Load every record of the store at `path` (created empty if absent). false +
// why on a store that cannot be opened (the node then starts with an empty book).
bool peerstore_load(const std::string& path, std::vector<PeerRecord>& out, std::string* why = nullptr);
// Replace the store at `path` with `v` (atomic temp + rename).
bool peerstore_save(const std::string& path, const std::vector<PeerRecord>& v, std::string* why = nullptr);

} // namespace c2pool::v37n::xmr::relay
