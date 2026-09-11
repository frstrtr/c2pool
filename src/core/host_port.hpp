// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace core {

// #965 Phase-2: IPv6-aware "host[:port]" parser.
//
// Replaces the naive rfind(':') / find(':') splits scattered across the HTTP,
// stratum, web and RPC config paths. Those splits leave the brackets in the
// host for "[2a00::1]:9999" and mangle a bare IPv6 literal (which contains many
// colons) into a bogus host+port. Forms handled:
//
//   "host"          -> { "host",     nullopt }
//   "host:port"     -> { "host",     port    }   (exactly one colon)
//   "1.2.3.4:port"  -> { "1.2.3.4",  port    }
//   "[::1]"         -> { "::1",      nullopt }   (brackets stripped)
//   "[::1]:port"    -> { "::1",      port    }
//   "2a00::1"       -> { "2a00::1",  nullopt }   (>=2 colons, unbracketed = v6)
//
// A port is accepted only if it is all digits in 1..65535; otherwise the port
// is nullopt and the host keeps the pre-colon portion (single-colon case) or
// the whole literal (bare-v6 case). Never throws; callers apply their own
// default/override when port is nullopt.
struct HostPort
{
    std::string           host;   // brackets stripped for [v6] forms
    std::optional<uint16_t> port; // nullopt when absent or unparsable
};

inline std::optional<uint16_t> parse_port_str(std::string_view v)
{
    if (v.empty()) return std::nullopt;
    unsigned long val = 0;
    const char* b = v.data();
    const char* e = b + v.size();
    auto [p, ec] = std::from_chars(b, e, val);
    if (ec != std::errc{} || p != e || val < 1 || val > 65535)
        return std::nullopt;
    return static_cast<uint16_t>(val);
}

inline HostPort parse_host_port(std::string_view s)
{
    HostPort r;

    if (!s.empty() && s.front() == '[')
    {
        const auto rb = s.find(']');
        if (rb == std::string_view::npos)
        {
            r.host = std::string(s.substr(1));  // malformed, best-effort
            return r;
        }
        r.host = std::string(s.substr(1, rb - 1));
        const auto rest = s.substr(rb + 1);
        if (rest.size() >= 2 && rest.front() == ':')
            r.port = parse_port_str(rest.substr(1));
        return r;
    }

    const auto first = s.find(':');
    if (first == std::string_view::npos)
    {
        r.host = std::string(s);  // bare host, no port
        return r;
    }
    if (first == s.rfind(':'))
    {
        // exactly one colon -> host:port
        r.host = std::string(s.substr(0, first));
        r.port = parse_port_str(s.substr(first + 1));
        return r;
    }
    // >=2 colons, unbracketed -> bare IPv6 literal, no port
    r.host = std::string(s);
    return r;
}

}  // namespace core
