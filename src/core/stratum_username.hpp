// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Pure parsers for the stratum login (mining.authorize username) field.
// Kept free of StratumSession state so the exact production code is what the
// unit tests exercise (test/test_stratum_username.cpp).
//
// Login grammar handled here:
//   ADDR+<pseudo_diff>                 fixed pseudoshare difficulty
//   ADDR/<share_diff>                  per-miner share difficulty (p2pool
//                                      "ADDR/diff", work.py get_user_details)
//   ADDR/CHAIN_ID:ADDR[/CHAIN_ID:ADDR] explicit merged-chain addresses
//   ADDR.worker / ADDR_worker          worker name (stripped before "/")
// "/<share_diff>" and "/CHAIN_ID:ADDR" tokens may be mixed in any order.

#include <cctype>
#include <cmath>
#include <cstdint>
#include <map>
#include <optional>
#include <sstream>
#include <string>

namespace core::stratum_username {

// Parse a miner-supplied difficulty. Returns a value only for a finite number
// > 0 that consumes the whole string. "0", negatives, "inf" and "nan" (all
// accepted by std::stod) set NO target. Hex floats ("0x10") are rejected too:
// p2pool's float() does not take them.
inline std::optional<double> parse_positive_finite_diff(const std::string& s)
{
    if (s.empty())
        return std::nullopt;
    for (char c : s) {
        if (!(std::isdigit(static_cast<unsigned char>(c)) || c == '.' ||
              c == 'e' || c == 'E' || c == '+' || c == '-'))
            return std::nullopt;
    }
    try {
        size_t used = 0;
        double v = std::stod(s, &used);
        if (used != s.size() || !std::isfinite(v) || v <= 0.0)
            return std::nullopt;
        return v;
    } catch (...) {
        return std::nullopt;
    }
}

// Strip a trailing "+N" from username. The suffix is removed whenever it is
// non-empty; the difficulty is returned only if parse_positive_finite_diff
// accepts it.
inline std::optional<double> strip_fixed_diff_suffix(std::string& username)
{
    auto plus_pos = username.rfind('+');
    if (plus_pos == std::string::npos || plus_pos + 1 >= username.size())
        return std::nullopt;
    std::string diff_str = username.substr(plus_pos + 1);
    username = username.substr(0, plus_pos);
    return parse_positive_finite_diff(diff_str);
}

// True when the text after the last '/' is a valid "/<share_diff>" token.
inline bool ends_with_slash_diff(const std::string& username)
{
    auto slash_pos = username.rfind('/');
    if (slash_pos == std::string::npos)
        return false;
    return parse_positive_finite_diff(username.substr(slash_pos + 1)).has_value();
}

// Strip a worker name ("ADDR.rig" / "ADDR_rig", Python compat) and return
// it ("" if none). The worker is always after the last address, so search
// from the end; a separator at index <= 20 is part of an address.
// A dot inside a fractional "/<diff>" tail ("ADDR/1.5", "ADDR/98:DOGE/0.5")
// is not a worker: when the last "/" token is a valid diff, only dots before
// that "/" are candidates. The dot-strip removes just the ".worker" segment
// (up to the next "/"), so "ADDR.rig/1024" gives ADDR/1024 + worker "rig".
// "ADDR/1.5.rig" still strips ".rig" (the tail "1.5.rig" is not a diff).
inline std::string strip_worker_suffix(std::string& username)
{
    std::string worker;
    auto dot_pos = username.rfind('.');
    if (ends_with_slash_diff(username)) {
        auto slash_pos = username.rfind('/');
        dot_pos = slash_pos == 0 ? std::string::npos : username.rfind('.', slash_pos - 1);
    }
    if (dot_pos != std::string::npos && dot_pos > 20) {
        auto seg_end = username.find('/', dot_pos);
        if (seg_end == std::string::npos)
            seg_end = username.size();
        worker = username.substr(dot_pos + 1, seg_end - dot_pos - 1);
        username.erase(dot_pos, seg_end - dot_pos);
    }
    auto underscore_pos = username.rfind('_');
    if (underscore_pos != std::string::npos && underscore_pos > 20) {
        if (worker.empty())
            worker = username.substr(underscore_pos + 1);
        username = username.substr(0, underscore_pos);
    }
    return worker;
}

struct SlashParse {
    bool had_slash = false;
    std::map<uint32_t, std::string> merged_addresses;  // CHAIN_ID -> ADDR
    std::optional<double> share_diff;                  // "/<diff>" token
};

// Split "PRIMARY/tok/tok..." at the first '/'. username keeps PRIMARY.
// "CHAIN_ID:ADDR" tokens fill merged_addresses; a colon-less token that is a
// valid difficulty fills share_diff (last one wins); anything else is ignored.
inline SlashParse parse_slash_tokens(std::string& username)
{
    SlashParse out;
    auto slash_pos = username.find('/');
    if (slash_pos == std::string::npos)
        return out;
    out.had_slash = true;
    std::string remainder = username.substr(slash_pos + 1);
    username = username.substr(0, slash_pos);
    std::istringstream ss(remainder);
    std::string token;
    while (std::getline(ss, token, '/')) {
        auto colon = token.find(':');
        if (colon == std::string::npos) {
            if (auto d = parse_positive_finite_diff(token))
                out.share_diff = d;
            continue;
        }
        if (colon > 0 && colon + 1 < token.size()) {
            try {
                uint32_t chain_id = static_cast<uint32_t>(std::stoul(token.substr(0, colon)));
                out.merged_addresses[chain_id] = token.substr(colon + 1);
            } catch (...) {}
        }
    }
    return out;
}

} // namespace core::stratum_username
