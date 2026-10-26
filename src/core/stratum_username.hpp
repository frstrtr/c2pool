// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Pure parsers for the stratum login (mining.authorize username) field.
// Kept free of StratumSession state so the exact production code is what the
// unit tests exercise (test/test_stratum_username.cpp).
//
// Login grammar handled here (worker-suffix stripping stays in the session):
//   ADDR+<pseudo_diff>                 fixed pseudoshare difficulty
//   ADDR/<share_diff>                  per-miner share difficulty (p2pool
//                                      "ADDR/diff", work.py get_user_details)
//   ADDR/CHAIN_ID:ADDR[/CHAIN_ID:ADDR] explicit merged-chain addresses
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
