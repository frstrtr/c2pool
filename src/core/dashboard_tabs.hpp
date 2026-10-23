// SPDX-License-Identifier: AGPL-3.0-or-later
// dashboard_tabs.hpp — the #926 dashboard coin-switcher tab set.
//
// Builds the tab list the dashboard's #pool-tabs strip renders, in the shape
// v37 will use (v37_dashboard_tab.hpp, #1541): one record per coin with
// {coin, symbol, active, location}.
//
//   * coin     — lowercase lane key (e.g. "ltc"). Join key, compared verbatim.
//   * symbol   — uppercase display ticker (e.g. "LTC").
//   * active   — true for exactly the coin this dashboard is serving (the
//                node's primary coin). Rendered as the highlighted tab.
//   * location — where the tab navigates to, or null when it has nowhere to
//                go. The primary tab is "/" (this dashboard). A local
//                secondary coin (e.g. DOGE merged-mined on an LTC node) is
//                null: there is no same-origin anchor for it yet, so the
//                renderer draws a non-clickable label, never a dead link.
//                A configured sibling (--dashboard-peer SYM=URL) is its URL.
//
// Sources, in tab order:
//   1. this node's own coins from /api/node_topology (primary first, then
//      the local secondaries in topology order);
//   2. operator-configured sibling dashboards, in config order.
//
// Honesty rules: no coin is ever invented from a hardcoded list. An entry with
// an empty symbol or an unusable URL yields NO tab (never a dead tab). A peer
// whose symbol is already a local coin is dropped (the local tab wins), and a
// repeated peer symbol keeps only its first entry.
//
// Display-only: touches no share, payout, or consensus state.

#pragma once

#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace core {

struct DashboardPeer {
    std::string symbol;  // uppercase ticker
    std::string url;     // absolute http(s) URL of the sibling dashboard
};

namespace dashboard_tabs_detail {

inline std::string to_upper(std::string s) {
    for (auto& c : s)
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 32);
    return s;
}

inline std::string to_lower(std::string s) {
    for (auto& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    return s;
}

// 1..16 ASCII letters/digits. Anything else is not a ticker.
inline bool valid_symbol(const std::string& s) {
    if (s.empty() || s.size() > 16) return false;
    for (char c : s) {
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
        if (!ok) return false;
    }
    return true;
}

// Absolute http(s) URL with a non-empty host, printable ASCII, and none of
// the characters that could break out of an href attribute. The scheme is
// split off first and checked on its own, then the "//" and the authority.
// This is a shape check for a link the operator configured; it makes no
// trust or authentication decision.
inline bool valid_url(const std::string& u) {
    const auto colon = u.find(':');
    if (colon == std::string::npos) return false;
    const std::string scheme = u.substr(0, colon);
    if (scheme != "http" && scheme != "https") return false;
    if (u.size() < colon + 3 || u[colon + 1] != '/' || u[colon + 2] != '/')
        return false;
    const std::string rest = u.substr(colon + 3);
    if (rest.empty() || rest[0] == '/' || rest[0] == ':' || rest[0] == '?' || rest[0] == '#')
        return false;
    for (char c : u) {
        if (c <= 0x20 || c >= 0x7f) return false;
        if (c == '"' || c == '\'' || c == '<' || c == '>' || c == '\\' || c == '`') return false;
    }
    return true;
}

}  // namespace dashboard_tabs_detail

// Parse one "SYM=URL" peer spec (the --dashboard-peer / dashboard_peers form).
// Returns nullopt for anything malformed; the caller skips it.
inline std::optional<DashboardPeer> parse_dashboard_peer(const std::string& spec) {
    using namespace dashboard_tabs_detail;
    auto eq = spec.find('=');
    if (eq == std::string::npos) return std::nullopt;
    std::string sym = spec.substr(0, eq);
    std::string url = spec.substr(eq + 1);
    if (!valid_symbol(sym) || !valid_url(url)) return std::nullopt;
    return DashboardPeer{to_upper(sym), url};
}

// Pure: topology is the /api/node_topology payload ({coins:[{coin, primary}]}).
// Returns {"tabs": [ {coin, symbol, active, location}, ... ]}.
inline nlohmann::json build_dashboard_tabs(const nlohmann::json& topology,
                                           const std::vector<DashboardPeer>& peers) {
    using namespace dashboard_tabs_detail;
    nlohmann::json tabs = nlohmann::json::array();
    std::vector<std::string> seen;  // uppercase symbols already emitted
    auto taken = [&](const std::string& sym) {
        for (const auto& s : seen) if (s == sym) return true;
        return false;
    };
    auto push = [&](const std::string& sym, bool active, nlohmann::json location) {
        tabs.push_back({{"coin", to_lower(sym)},
                        {"symbol", sym},
                        {"active", active},
                        {"location", std::move(location)}});
        seen.push_back(sym);
    };

    // Local coins: primary first, then secondaries, each in topology order.
    if (topology.is_object() && topology.contains("coins") && topology["coins"].is_array()) {
        const auto& coins = topology["coins"];
        for (int pass = 0; pass < 2; ++pass) {
            const bool want_primary = (pass == 0);
            for (const auto& c : coins) {
                if (!c.is_object() || !c.contains("coin") || !c["coin"].is_string()) continue;
                const bool is_primary = c.contains("primary") && c["primary"].is_boolean()
                                        && c["primary"].get<bool>();
                if (is_primary != want_primary) continue;
                std::string raw = c["coin"].get<std::string>();
                if (!valid_symbol(raw)) continue;
                std::string sym = to_upper(raw);
                if (taken(sym)) continue;
                // Only one tab can be the page you are on.
                const bool active = is_primary && pass == 0 &&
                                    (tabs.empty() || !tabs[0]["active"].get<bool>());
                push(sym, active, active ? nlohmann::json("/") : nlohmann::json(nullptr));
            }
        }
    }

    // Configured siblings: re-validated here so a hand-built vector cannot
    // smuggle in a dead or unsafe link.
    for (const auto& p : peers) {
        if (!valid_symbol(p.symbol) || !valid_url(p.url)) continue;
        std::string sym = to_upper(p.symbol);
        if (taken(sym)) continue;
        push(sym, false, p.url);
    }

    return nlohmann::json{{"tabs", std::move(tabs)}};
}

}  // namespace core
