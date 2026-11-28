// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Pure parsers for the stratum login (mining.authorize username) field.
// Kept free of StratumSession state so the exact production code is what the
// unit tests exercise (test/test_stratum_username.cpp).
//
// Login grammar handled here (p2pool work.py get_user_details, which splits
// the login with re.split('([+/])')): the text before the first '+' or '/'
// is the user; each "+X" or "/X" after it is one parameter, X running to the
// next '+' or '/'. The parameters come in any order and number; of each kind
// the last valid one wins (p2pool keeps the previous value when one is not a
// number).
//   +<pseudo_diff>      fixed pseudoshare difficulty (internal units, as
//                       p2pool's difficulty_to_target(float(N)))
//   /<share_diff>       per-miner share difficulty (p2pool desired_share_target)
//   /CHAIN_ID:ADDR      explicit merged-chain address (c2pool; p2pool ignores
//                       the token)
// The user is ADDR, ADDR_worker or ADDR.worker: '_' wins over '.', the
// address is the text before the first separator and the worker the text up
// to the next one (user.split(sep)[0] and [1]). In the comma form
// "PRIMARY,MERGED" each address has its own worker suffix
// (p2pool-merged-v36 splits at the comma first); a '|', ';' or ' ' after a
// worker suffix is part of the worker, as in p2pool, and splits the login
// only when no suffix comes before it ("L|D", "L|D.rig").
// A "+N" or "/N" value is taken only where p2pool's float() and
// difficulty_to_target take it, and only when finite and > 0.

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <utility>

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

// A login difficulty ("+N", "/N"): parse_positive_finite_diff, and one p2pool's
// difficulty_to_target does not raise on (its int() of
// (0xffff0000 * 2**192 + 1) / N overflows for N below ~1e-241). The same
// condition as chain::difficulty_to_target(N).has_value(). One not taken is
// skipped: an earlier value stays (p2pool's try/except around each).
inline std::optional<double> parse_login_diff(const std::string& s)
{
    const auto d = parse_positive_finite_diff(s);
    if (d && !std::isfinite(std::ldexp(65535.0, 208) / *d))
        return std::nullopt;
    return d;
}

// Remove every "+X" parameter from username, leaving the user and the "/X"
// parameters in their order ("ADDR+1024/512" -> "ADDR/512"). Returns the last
// X that parse_login_diff accepts (p2pool: each "+X" it takes replaces the
// previous one; one it does not take is ignored).
inline std::optional<double> strip_fixed_diff_suffix(std::string& username)
{
    std::optional<double> diff;
    size_t at = username.find_first_of("+/");
    std::string kept = username.substr(0, at);
    while (at != std::string::npos) {
        const size_t end = username.find_first_of("+/", at + 1);
        const std::string param = username.substr(at + 1, end == std::string::npos ? std::string::npos
                                                                                     : end - at - 1);
        if (username[at] == '+') {
            if (auto d = parse_login_diff(param))
                diff = d;
        } else {
            kept += '/';
            kept += param;
        }
        at = end;
    }
    username = std::move(kept);
    return diff;
}

// The separators of the two-address forms, in the order they are tried; the
// first one found past index 20 (inside a payout address) splits the login
// (strip_worker_suffix decides it, Login::merged_sep carries it).
inline size_t find_merged_separator(const std::string& user)
{
    for (char sep : {',', '|', ';', ' '}) {
        const auto pos = user.find(sep);
        if (pos != std::string::npos && pos > 20)
            return pos;
    }
    return std::string::npos;
}

// p2pool work.py get_user_details: '_' wins over '.'; the address is the text
// before the first separator, the worker the text up to the next one
// ("ADDR.a.b" -> ADDR, "a"; "ADDR_a.b" -> ADDR, "a.b"). No address has a '.'
// or a '_': where p2pool's address keeps a '.' ("ADDR.a_b": "ADDR.a", which
// is no address), it is cut at that '.' too, so the payout address is ADDR.
inline std::string split_worker(std::string& addr)
{
    const char sep = addr.find('_') != std::string::npos ? '_' : '.';
    const size_t first = addr.find(sep);
    if (first == std::string::npos)
        return {};
    const size_t next = addr.find(sep, first + 1);
    std::string worker = addr.substr(first + 1, next == std::string::npos ? std::string::npos
                                                                          : next - first - 1);
    addr.erase(first);
    if (const auto dot = addr.find('.'); dot != std::string::npos)
        addr.erase(dot);
    return worker;
}

// p2pool-merged-v36 get_user_details for the merged address of
// "PRIMARY,MERGED": the worker after its first '.', else after its first '_';
// the address the text before the first of either.
inline std::string split_merged_worker(std::string& addr)
{
    std::string worker;
    if (const auto dot = addr.find('.'); dot != std::string::npos) {
        worker = addr.substr(dot + 1);
        addr.erase(dot);
    }
    if (const auto us = addr.find('_'); us != std::string::npos) {
        if (worker.empty())
            worker = addr.substr(us + 1);
        addr.erase(us);
    }
    return worker;
}

// Strip the worker name from the user part of username (the text before the
// first '+' or '/'; the parameters after it are kept) and return it ("" if
// none). The comma form "PRIMARY,MERGED" (the comma past index 20, as
// StratumSession::parse_address_separators splits it): each address loses
// its own suffix, the merged address's worker first, as p2pool-merged-v36
// reads it; *first_had_worker tells whether PRIMARY had one (p2pool tests
// the swapped order "MERGED_CHAIN_ADDR,PARENT_ADDR" on PRIMARY with its
// suffix, which is never an address, so then it never swaps). Any other
// login: the p2pool rule on the whole user, a '|', ';' or ' ' after the
// suffix kept in the worker ("L.rig|D": L, worker "rig|D").
// *merged_sep is where the stripped user splits into its two addresses
// (npos: one address), decided here once: the comma form at its comma,
// whatever the first address is cut to (".x,D" splits at index 0), any other
// at find_merged_separator of the stripped user.
inline std::string strip_worker_suffix(std::string& username, bool* first_had_worker = nullptr,
                                       size_t* merged_sep = nullptr)
{
    const size_t user_end = std::min(username.find_first_of("+/"), username.size());
    std::string user = username.substr(0, user_end);
    std::string worker;
    bool had = false;
    size_t split_at = std::string::npos;
    if (const size_t sep = find_merged_separator(user); sep != std::string::npos && user[sep] == ',') {
        std::string primary = user.substr(0, sep);
        std::string merged = user.substr(sep + 1);
        worker = split_merged_worker(merged);
        had = primary.find_first_of("._") != std::string::npos;
        std::string primary_worker = split_worker(primary);
        if (worker.empty())
            worker = std::move(primary_worker);
        split_at = primary.size();
        user = primary + ',' + merged;
    } else {
        worker = split_worker(user);
        split_at = find_merged_separator(user);
    }
    if (first_had_worker)
        *first_had_worker = had;
    if (merged_sep)
        *merged_sep = split_at;
    username = user + username.substr(user_end);
    return worker;
}

// "d=N" in the mining.authorize password (params[1]), the common pool
// convention for a start difficulty: the whole password, or one of its
// key=value tokens separated by ',' or ';' ("x,d=4096", "d=4096;x"). N is in
// WIRE units (what the miner sees in mining.set_difficulty). The last "d="
// token decides: `diff` is its value when parse_positive_finite_diff accepts
// it; `bad` is set when that token is present but its value is not (garbage,
// "0", negative, "inf", "nan", empty).
struct PasswordDiff {
    std::optional<double> diff;
    bool bad = false;
};

inline PasswordDiff parse_password_start_diff(const std::string& password)
{
    auto trim = [](const std::string& s) {
        const char* ws = " \t\r\n";
        const auto b = s.find_first_not_of(ws);
        if (b == std::string::npos)
            return std::string();
        return s.substr(b, s.find_last_not_of(ws) - b + 1);
    };
    PasswordDiff out;
    size_t start = 0;
    while (start <= password.size()) {
        size_t end = password.find_first_of(",;", start);
        if (end == std::string::npos)
            end = password.size();
        const std::string token = password.substr(start, end - start);
        const auto eq = token.find('=');
        if (eq != std::string::npos) {
            const std::string key = trim(token.substr(0, eq));
            if (key == "d" || key == "D") {
                out.diff = parse_positive_finite_diff(trim(token.substr(eq + 1)));
                out.bad = !out.diff.has_value();
            }
        }
        start = end + 1;
    }
    return out;
}

struct SlashParse {
    bool had_slash = false;
    std::map<uint32_t, std::string> merged_addresses;  // CHAIN_ID -> ADDR
    std::optional<double> share_diff;                  // "/<diff>" token
    std::string worker;                                // from "CHAIN_ID:ADDR.worker"
};

// Split "PRIMARY/tok/tok..." at the first '/'. username keeps PRIMARY.
// "CHAIN_ID:ADDR" tokens fill merged_addresses (a worker suffix on ADDR is
// cut off as from a user, the last one kept in worker); a colon-less token
// that parse_login_diff takes as a whole fills share_diff (last one wins, as
// p2pool's float() of the token: "1024.rig" is none); anything else is
// ignored.
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
            if (auto d = parse_login_diff(token))
                out.share_diff = d;
            continue;
        }
        if (colon > 0 && colon + 1 < token.size()) {
            try {
                uint32_t chain_id = static_cast<uint32_t>(std::stoul(token.substr(0, colon)));
                std::string addr = token.substr(colon + 1);
                std::string worker = split_worker(addr);
                if (addr.empty())
                    continue;
                out.merged_addresses[chain_id] = std::move(addr);
                if (!worker.empty())
                    out.worker = std::move(worker);
            } catch (...) {}
        }
    }
    return out;
}

// The whole login, as StratumSession::handle_authorize reads it.
struct Login {
    std::string user;                   // PRIMARY, or PRIMARY<sep>MERGED (a two-address form)
    std::string worker;                 // the user's, else a merged token's
    std::optional<double> pseudo_diff;  // "+N"
    SlashParse slash;                   // "/N" and "/CHAIN_ID:ADDR"
    // The comma form's first address had a worker suffix: its second address
    // is a merged address or nothing, never the parent one of a swapped pair
    // (strip_worker_suffix).
    bool first_had_worker = false;
    // Where user splits into its two addresses (npos: one address), as
    // strip_worker_suffix decided it; StratumSession::parse_address_separators
    // splits there.
    size_t merged_sep = std::string::npos;
};

inline Login parse_login(std::string username)
{
    Login l;
    l.pseudo_diff = strip_fixed_diff_suffix(username);
    l.worker = strip_worker_suffix(username, &l.first_had_worker, &l.merged_sep);
    l.slash = parse_slash_tokens(username);
    if (l.worker.empty())
        l.worker = l.slash.worker;
    l.user = std::move(username);
    return l;
}

} // namespace core::stratum_username
