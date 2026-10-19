// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/net_addr_ban.hpp
//
// Address keys and a bounded ban table for the v37 TCP listeners (the XMR
// receipt relay transport and the XMR stratum listener). Network policy only:
// no lane state, nothing here decides consensus.
//
//   addr_key_of()  one key per IPv4 address and per IPv6 /64 prefix; an
//                  IPv4-mapped IPv6 address keys as its IPv4 address. 0 = no
//                  key: 127.0.0.1, ::1, every other IPv6 address whose first
//                  byte is 0, and any other address family. A connection with
//                  no key is never banned by address and is not counted
//                  against a per-address limit (a local proxy or several
//                  local nodes share 127.0.0.1).
//                  Every non-zero key is >= kAddrKeyMin (its top byte is
//                  non-zero), so a caller may keep per-connection ids below
//                  kAddrKeyMin in the same key space.
//   AddrBanTable   key -> ban expiry, checked on lookup, bounded in size. The
//                  caller passes the time, so the table reads no clock.
// ===========================================================================
#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>

namespace c2pool::v37n::net {

using AddrKey = std::uint64_t;

inline constexpr AddrKey kAddrV4Tag  = 0xFFFFFFFF00000000ull;   // IPv4 keys: tag | address (host order)
inline constexpr AddrKey kAddrKeyMin = 1ull << 56;             // every non-zero key is >= this

inline bool is_addr_key(AddrKey k) { return k >= kAddrKeyMin; }

// IPv4 address in host byte order -> key (0 for 127.0.0.1).
inline AddrKey addr_key_v4(std::uint32_t host_order) {
    if (host_order == 0x7F000001u) return 0;
    return kAddrV4Tag | host_order;
}

// The 16 bytes of an IPv6 address -> key of its /64 (0 when the first byte is 0,
// which covers ::1; an IPv4-mapped address keys as IPv4).
inline AddrKey addr_key_v6(const std::uint8_t b[16]) {
    static const std::uint8_t kMapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    if (std::memcmp(b, kMapped, sizeof kMapped) == 0) {
        const std::uint32_t v4 = (static_cast<std::uint32_t>(b[12]) << 24) | (static_cast<std::uint32_t>(b[13]) << 16) |
                                 (static_cast<std::uint32_t>(b[14]) << 8) | static_cast<std::uint32_t>(b[15]);
        return addr_key_v4(v4);
    }
    if (b[0] == 0) return 0;
    AddrKey k = 0;
    for (int i = 0; i < 8; ++i) k = (k << 8) | b[i];
    return k;
}

inline AddrKey addr_key_of(const sockaddr* sa) {
    if (!sa) return 0;
    if (sa->sa_family == AF_INET) {
        sockaddr_in a{};
        std::memcpy(&a, sa, sizeof a);
        return addr_key_v4(ntohl(a.sin_addr.s_addr));
    }
    if (sa->sa_family == AF_INET6) {
        sockaddr_in6 a{};
        std::memcpy(&a, sa, sizeof a);
        return addr_key_v6(a.sin6_addr.s6_addr);
    }
    return 0;
}

// Dotted / hex text of a key, for logs ("-" for 0).
inline std::string addr_key_str(AddrKey k) {
    char b[48];
    if (!k) return "-";
    if ((k & kAddrV4Tag) == kAddrV4Tag) {
        const auto v = static_cast<std::uint32_t>(k);
        std::snprintf(b, sizeof b, "%u.%u.%u.%u", v >> 24, (v >> 16) & 255u, (v >> 8) & 255u, v & 255u);
    } else {
        std::snprintf(b, sizeof b, "%x:%x:%x:%x::/64", static_cast<unsigned>(k >> 48), static_cast<unsigned>((k >> 32) & 0xffffu),
                      static_cast<unsigned>((k >> 16) & 0xffffu), static_cast<unsigned>(k & 0xffffu));
    }
    return b;
}

// key -> ban expiry. Thread-safe. A ban of a key already banned keeps the later
// expiry. Full: expired entries are dropped first, then the entry that expires
// soonest.
class AddrBanTable {
public:
    using TimePoint = std::chrono::steady_clock::time_point;
    static constexpr std::size_t kDefaultMax = 65536;

    explicit AddrBanTable(std::size_t max_entries = kDefaultMax) : m_max(max_entries ? max_entries : 1) {}

    // false for key 0 (nothing recorded).
    bool ban(AddrKey key, TimePoint now, TimePoint until) {
        if (!key) return false;
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_bans.find(key);
        if (it != m_bans.end()) {
            if (until > it->second) it->second = until;
            return true;
        }
        if (m_bans.size() >= m_max) {
            for (auto e = m_bans.begin(); e != m_bans.end();) e = (e->second <= now) ? m_bans.erase(e) : std::next(e);
            while (m_bans.size() >= m_max) {
                auto soonest = m_bans.begin();
                for (auto e = m_bans.begin(); e != m_bans.end(); ++e) if (e->second < soonest->second) soonest = e;
                m_bans.erase(soonest);
            }
        }
        m_bans.emplace(key, until);
        return true;
    }
    bool banned(AddrKey key, TimePoint now) {
        if (!key) return false;
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_bans.find(key);
        if (it == m_bans.end()) return false;
        if (now < it->second) return true;
        m_bans.erase(it);
        return false;
    }
    std::size_t size() const { std::lock_guard<std::mutex> lk(m_mtx); return m_bans.size(); }

private:
    std::size_t m_max;
    mutable std::mutex m_mtx;
    std::unordered_map<AddrKey, TimePoint> m_bans;
};

} // namespace c2pool::v37n::net
