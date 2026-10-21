// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/node/xmr_sync_telemetry.hpp
//
// The native follower's sync telemetry as text: one status line (the chain
// requests and their answers, the want lists, the parks, the own-fork guard)
// and the edge lines (no progress, progress resumed, a chain answer whose
// content changed). Formatting only; nothing here decides anything.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

#include "impl/xmr/native/chain/xmr_chain_index.hpp"
#include "impl/xmr/native/node/xmr_sync_driver.hpp"

namespace c2pool::xmr::native::rt {

inline std::string sync_hex16(const Hash& h) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (std::size_t i = 0; i < 8 && i < h.size(); ++i) {
        s.push_back(d[h[i] >> 4]);
        s.push_back(d[h[i] & 15]);
    }
    return s;
}

// "native-sync: ..." -- the status line. now_ms is the clock the own-fork
// guard is driven with (its tracking age).
inline std::string format_native_sync(const SyncDriver::Stats& d, const ChainIndex::SyncTelemetry& x,
                                      std::uint64_t now_ms) {
    const auto u = [](std::uint64_t v) { return static_cast<unsigned long long>(v); };
    char own[128];
    if (x.own_fork_tracking) {
        const std::string common = x.peers_common ? std::to_string(*x.peers_common) : std::string("-");
        std::snprintf(own, sizeof own, "base %llu common %s age %llus", u(x.own_fork_base_h), common.c_str(),
                      u(now_ms >= x.own_fork_since_ms ? (now_ms - x.own_fork_since_ms) / 1000 : 0));
    } else {
        std::snprintf(own, sizeof own, "-");
    }
    char buf[1024];
    std::snprintf(buf, sizeof buf,
                  "native-sync: tip=%llu:%s synced=%d peer=%s peer_h=%llu chain_req=%llu answered=%llu refused=%llu "
                  "timeouts=%llu quiet=%llu want=%zu detached=%zu refetch=%zu refetch_req=%llu refetch_refused=%llu "
                  "bodies_req=%llu parked=%llu unsolicited=%llu unproven_bytes=%llu stalled=%d(%llus) "
                  "own_fork=%s abandoned=%llu on_abandoned=%llu last_answer=%llu/%zu/%zu/%zu/%zu",
                  u(x.tip_height), sync_hex16(x.tip_id).c_str(), x.synced ? 1 : 0,
                  d.target.empty() ? "-" : d.target.c_str(), u(d.best_peer_height ? d.best_peer_height - 1 : 0),
                  u(d.chain_requests), u(x.chain_entries), u(x.chain_entries_refused), u(d.chain_timeouts),
                  u(d.chain_quiet_waits), x.want, x.detached, x.refetch_list, u(d.refetch_requests),
                  u(d.refetch_refused), u(d.bodies_refetch_requests), u(x.parked), u(x.unsolicited),
                  u(x.unproven_bytes), d.stalled ? 1 : 0, u(d.stall_ms / 1000), own, u(x.abandoned),
                  u(x.on_abandoned_refused), u(x.last_answer.split), x.last_answer.ids, x.last_answer.held,
                  x.last_answer.wanted, x.last_answer.detached);
    return buf;
}

// The edge line of a no-progress raise or clear (Stats::stalled changed).
inline std::string format_native_sync_stall(const SyncDriver::Stats& d, const ChainIndex::SyncTelemetry& x) {
    const auto u = [](std::uint64_t v) { return static_cast<unsigned long long>(v); };
    char buf[512];
    if (d.stalled)
        std::snprintf(buf, sizeof buf,
                      "[native-sync] NO PROGRESS: peer %s claims more work (height %llu); our height %llu has not "
                      "moved for %llu s with %llu chain answers; want=%zu detached=%zu parked=%llu unsolicited=%llu",
                      d.target.empty() ? "-" : d.target.c_str(), u(d.best_peer_height ? d.best_peer_height - 1 : 0),
                      u(x.tip_height), u(d.stall_ms / 1000), u(d.stall_answers), x.want, x.detached, u(x.parked),
                      u(x.unsolicited));
    else
        std::snprintf(buf, sizeof buf, "[native-sync] progress resumed: tip %llu:%s", u(x.tip_height),
                      sync_hex16(x.tip_id).c_str());
    return buf;
}

// The edge line of a chain answer whose content changed.
inline std::string format_native_sync_answer(const ChainIndex::ChainAnswer& a) {
    char buf[256];
    std::snprintf(buf, sizeof buf, "[native-sync] chain answer from %s: split %llu, %zu ids: %zu held, %zu wanted (%zu detached)",
                  a.peer.c_str(), static_cast<unsigned long long>(a.split), a.ids, a.held, a.wanted, a.detached);
    return buf;
}

}  // namespace c2pool::xmr::native::rt
