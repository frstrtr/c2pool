// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/c2pool/v37/xmr/pathb/pathb_status.hpp
// The status lines serve_pathb and serve_follow_only share, formatted from
// injected values (one line each, no newline):
//   good-citizen:            the selector's pool, its choice, the violations
//   txpool:                  the relay gate, the warm latch, the complement
//                            rounds, the pool's counters
//   wire RPC to monerod:     TOTAL = node + tip-poll + pool-other, the
//                            template path's daemon pumps, the failures
//   rpc_on_find_path=        template pumps + pool transport; off-path parity
// An absent pool transport reports 0 for its counters.
//
// Header-only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace c2pool::xmr::pathb {

struct KeptStatusValues {
    // good-citizen
    bool good_citizen_on = false;
    std::size_t citizen_pool_n = 0;
    std::size_t citizen_chosen_n = 0;
    std::uint64_t good_citizen_violations = 0;
    // txpool
    bool txpool_gate_open = false;
    bool txpool_tip_known = false;
    bool txpool_warm = false;
    std::string txpool_warm_why;  // "complement" / "timeout" / ""
    std::uint64_t txpool_warm_after_ms = 0;
    std::uint64_t complement_requests_out = 0;
    std::uint64_t complement_answers_in = 0;
    std::uint64_t complement_rounds = 0;
    std::uint64_t complement_txs = 0;
    std::uint64_t pool_count = 0;
    std::uint64_t pool_accepted = 0;
    std::uint64_t pool_duplicates = 0;
    std::uint64_t pool_rejected = 0;
    std::uint64_t pool_rejected_not_synced = 0;
    std::uint64_t pool_rejected_member_locked = 0;
    std::uint64_t pool_unresolved_ring = 0;
    std::uint64_t pool_rejected_key_image_spent = 0;
    std::uint64_t pool_rejected_already_mined = 0;
    std::uint64_t pool_tip_seated = 0;
    // wire RPC
    std::uint64_t node_rpc = 0;             // the native node's own monerod client
    std::uint64_t template_daemon_pumps = 0;  // the template path's daemon resolves
    std::uint64_t pool_tip_poll_rpc = 0;    // the pool transport's tip poll (0: no transport)
    std::uint64_t pool_other_rpc = 0;       // the pool transport's other calls (0: no transport)
    std::uint64_t pool_transport_rpc = 0;   // the pool transport's calls (0: no transport)
    std::uint64_t node_rpc_failures = 0;
    std::uint64_t pool_rpc_failures = 0;
    // find path
    std::string arm_order;  // "daemon-first" / "p2p-first"
};

namespace status_detail {
[[gnu::format(printf, 1, 2)]] inline std::string fmt(const char* f, ...) {
    va_list ap;
    va_start(ap, f);
    va_list ap2;
    va_copy(ap2, ap);
    const int n = std::vsnprintf(nullptr, 0, f, ap);
    va_end(ap);
    std::string s;
    if (n > 0) {
        std::vector<char> b(static_cast<std::size_t>(n) + 1);
        std::vsnprintf(b.data(), b.size(), f, ap2);
        s.assign(b.data(), static_cast<std::size_t>(n));
    }
    va_end(ap2);
    return s;
}
inline unsigned long long u(std::uint64_t v) { return static_cast<unsigned long long>(v); }
}  // namespace status_detail

inline std::string good_citizen_line(const KeptStatusValues& v) {
    using status_detail::u;
    return status_detail::fmt("  good-citizen: %s pool=%zu chosen=%zu violations=%llu", v.good_citizen_on ? "on" : "off",
                              v.citizen_pool_n, v.citizen_chosen_n, u(v.good_citizen_violations));
}

inline std::string txpool_line(const KeptStatusValues& v) {
    using status_detail::u;
    return status_detail::fmt(
            "  txpool: gate=%d tip_known=%d warm=%d(%s %llums) complement req=%llu ans=%llu "
            "admitted_rounds=%llu txs=%llu | count=%llu accepted=%llu dup=%llu rejected=%llu "
            "not_synced=%llu member_locked=%llu unresolved=%llu ki_spent=%llu already_mined=%llu "
            "tip_seated=%llu",
            v.txpool_gate_open ? 1 : 0, v.txpool_tip_known ? 1 : 0, v.txpool_warm ? 1 : 0,
            v.txpool_warm_why.empty() ? "-" : v.txpool_warm_why.c_str(), u(v.txpool_warm_after_ms),
            u(v.complement_requests_out), u(v.complement_answers_in), u(v.complement_rounds), u(v.complement_txs),
            u(v.pool_count), u(v.pool_accepted), u(v.pool_duplicates), u(v.pool_rejected), u(v.pool_rejected_not_synced),
            u(v.pool_rejected_member_locked), u(v.pool_unresolved_ring), u(v.pool_rejected_key_image_spent),
            u(v.pool_rejected_already_mined), u(v.pool_tip_seated));
}

inline std::string wire_rpc_line(const KeptStatusValues& v) {
    using status_detail::u;
    return status_detail::fmt(
            "  wire RPC to monerod: TOTAL=%llu = template-path %llu "
            "+ node(parity+submit) %llu + tip-poll %llu + pool-other %llu"
            " [failures node=%llu pool=%llu]",
            u(v.node_rpc + v.pool_tip_poll_rpc + v.pool_other_rpc), u(v.template_daemon_pumps), u(v.node_rpc),
            u(v.pool_tip_poll_rpc), u(v.pool_other_rpc), u(v.node_rpc_failures), u(v.pool_rpc_failures));
}

inline std::string find_path_line(const KeptStatusValues& v) {
    using status_detail::u;
    return status_detail::fmt("  arm-order=%s rpc_on_find_path=%llu "
                              "(template %llu + pool-transport %llu) | off-path parity=%llu",
                              v.arm_order.c_str(), u(v.template_daemon_pumps + v.pool_transport_rpc),
                              u(v.template_daemon_pumps), u(v.pool_transport_rpc), u(v.node_rpc));
}

// The four lines in the order master prints them.
inline std::vector<std::string> kept_status_lines(const KeptStatusValues& v) {
    return {good_citizen_line(v), txpool_line(v), wire_rpc_line(v), find_path_line(v)};
}

}  // namespace c2pool::xmr::pathb
