// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// RELAY-BOOTSTRAP -- the built-in receipt-relay bootstrap list of c2pool-v37-xmr.
//
// Same pattern as v36's PoolConfig::DEFAULT_BOOTSTRAP_HOSTS
// (src/impl/bch/config_pool.hpp): a compiled-in, per-network list of public
// pool nodes. Here each entry is a relay HOST:PORT, because the relay port is
// part of the address. The list is the one in docs/xmr-lane/BOOTSTRAP-NODES.md;
// a node is added by a PR that changes both.
//
// Behaviour (main_v37_xmr.cpp): when the receipt relay is ON (--relay-listen
// or --relay-peer), the node dials this network's defaults IN ADDITION to its
// --relay-peer values; --no-relay-bootstrap drops the defaults. A default that
// is already a --relay-peer is not dialled twice, and a default that is this
// node itself (its port is the --relay-listen port and its host is the listen
// host or one of this machine's addresses) is skipped. An unreachable default
// is redialled with the relay's normal 1..60 s backoff, never fatal. With the
// relay OFF nothing is dialled (the daemon stays byte-identical to before).
// No wire change: with --relay-discovery on (the default) the list feeds
// RelayOptions::seeds (book candidates, good after HELLO, handed out in
// FB_ADDR); with --relay-discovery off it feeds RelayOptions::peers.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace c2pool::v37n::xmr::relay {

// The relay port of the public pool nodes.
inline constexpr std::uint16_t kBootstrapRelayPort = 59321;

// Mainnet: the pool's public nodes (docs/xmr-lane/BOOTSTRAP-NODES.md).
inline const std::vector<std::string> DEFAULT_BOOTSTRAP_HOSTS_MAINNET = {
    "109.123.238.32:59321",
    "158.220.92.171:59321",
};

// network byte as RelayOptions::network: 0 mainnet, 1 testnet, 2 stagenet, 3 regtest.
// Only mainnet ships defaults; stagenet/testnet/regtest pools name their peers.
inline const std::vector<std::string>& default_bootstrap_hosts(std::uint8_t network) {
    static const std::vector<std::string> kNone;
    return network == 0 ? DEFAULT_BOOTSTRAP_HOSTS_MAINNET : kNone;
}

// HOST:PORT -> (host, port); the last ':' splits, so a bare IPv6 host is not supported.
inline bool bootstrap_split(const std::string& s, std::string& host, std::uint16_t& port) {
    const auto c = s.rfind(':');
    if (c == std::string::npos || c == 0 || c + 1 >= s.size()) return false;
    unsigned long v = 0;
    for (std::size_t i = c + 1; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') return false;
        v = v * 10 + static_cast<unsigned long>(s[i] - '0');
        if (v > 65535) return false;
    }
    if (v == 0) return false;
    host = s.substr(0, c);
    port = static_cast<std::uint16_t>(v);
    return true;
}

struct BootstrapPick {
    std::vector<std::string> use;       // defaults to dial (in list order)
    std::vector<std::string> self;      // defaults skipped as this node itself
    std::vector<std::string> dup;       // defaults skipped as already a --relay-peer
};

// Pure: which of this network's defaults the node dials.
//   listen     : the --relay-listen value ("" = not listening)
//   local_ips  : this machine's addresses (numeric strings; the caller gathers them)
inline BootstrapPick resolve_bootstrap(std::uint8_t network, bool no_bootstrap,
                                       const std::vector<std::string>& explicit_peers,
                                       const std::string& listen,
                                       const std::vector<std::string>& local_ips) {
    BootstrapPick p;
    if (no_bootstrap) return p;
    std::string lh; std::uint16_t lp = 0;
    const bool listening = !listen.empty() && bootstrap_split(listen, lh, lp);
    for (const auto& d : default_bootstrap_hosts(network)) {
        bool is_dup = false;
        for (const auto& e : explicit_peers) if (e == d) { is_dup = true; break; }
        if (is_dup) { p.dup.push_back(d); continue; }
        std::string dh; std::uint16_t dp = 0;
        bool is_self = false;
        if (listening && bootstrap_split(d, dh, dp) && dp == lp) {
            if (dh == lh) is_self = true;
            for (const auto& ip : local_ips) if (ip == dh) { is_self = true; break; }
        }
        (is_self ? p.self : p.use).push_back(d);
    }
    return p;
}

// RC7 integration (#1819 x #1820): where the picked defaults go. Discovery ON:
// RelayOptions::seeds (book candidates, dialed by discovery, GOOD after an
// accepted HELLO, then handed out in FB_ADDR). Discovery OFF (no book): the
// permanent dial targets RelayOptions::peers. Returns how many were routed.
inline std::size_t route_bootstrap(const std::vector<std::string>& use, bool discovery,
                                   std::vector<std::pair<std::string, std::uint16_t>>& seeds,
                                   std::vector<std::pair<std::string, std::uint16_t>>& peers) {
    std::size_t n = 0;
    for (const auto& d : use) {
        std::string h; std::uint16_t pt = 0;
        if (!bootstrap_split(d, h, pt)) continue;
        (discovery ? seeds : peers).emplace_back(h, pt);
        ++n;
    }
    return n;
}

}  // namespace c2pool::v37n::xmr::relay
