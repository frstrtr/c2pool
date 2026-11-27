// SPDX-License-Identifier: AGPL-3.0-or-later
// Every coin binary wires the MiningInterface hooks the web-static pages read.
//
// A hook the binary never sets leaves its endpoint on the core default: an
// empty document or {"error": ...}. That is how /web/share/<hash> answered
// "share not found" for every share on BTC and BCH while share.html linked to
// it from every explorer cell. This scans each binary's wiring source (comments
// stripped) for a setter call on its MiningInterface or WebServer: mi->set_x(,
// <name>mi->set_x(, get_mining_interface()->set_x(, web_server.set_x( /
// web_server->set_x(. A work source's setter of the same name does not count.
//
// Known gaps are listed per binary; they are reported, not failed, until that
// binary's lane wires them (then drop the entry).

#include <gtest/gtest.h>

#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

#ifndef C2POOL_SRC_ROOT
#error "C2POOL_SRC_ROOT must be defined for the source-wiring KAT"
#endif

namespace {

namespace fs = std::filesystem;

std::string slurp(const fs::path& p)
{
    std::ifstream f(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

// C++ source with // and /* */ comments blanked out; string, character and
// raw string literals are kept as they are.
std::string strip_comments(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    std::size_t i = 0;
    const std::size_t n = s.size();
    while (i < n) {
        const char c = s[i];
        if (c == '/' && i + 1 < n && s[i + 1] == '/') {
            while (i < n && s[i] != '\n') ++i;
        } else if (c == '/' && i + 1 < n && s[i + 1] == '*') {
            i += 2;
            while (i + 1 < n && !(s[i] == '*' && s[i + 1] == '/')) {
                if (s[i] == '\n') out += '\n';
                ++i;
            }
            i += 2;
        } else if (c == 'R' && i + 1 < n && s[i + 1] == '"'
                   && (i == 0 || !(std::isalnum(static_cast<unsigned char>(s[i - 1])) || s[i - 1] == '_'))) {
            const std::size_t open = s.find('(', i + 2);
            if (open == std::string::npos) { out += s.substr(i); break; }
            const std::string close = ")" + s.substr(i + 2, open - (i + 2)) + "\"";
            const std::size_t end = s.find(close, open + 1);
            const std::size_t stop = (end == std::string::npos) ? n : end + close.size();
            out += s.substr(i, stop - i);
            i = stop;
        } else if (c == '"' || c == '\'') {
            out += c;
            ++i;
            while (i < n && s[i] != c) {
                if (s[i] == '\\' && i + 1 < n) { out += s[i]; ++i; }
                if (s[i] == '\n') break;   // not a literal after all
                out += s[i];
                ++i;
            }
            if (i < n) { out += s[i]; ++i; }
        } else {
            out += c;
            ++i;
        }
    }
    return out;
}

bool is_ident(char c)
{
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
}

// A call of `hook` on a MiningInterface or WebServer receiver: `<x>mi->`,
// `<x>mi.`, `get_mining_interface()->`, `web_server.` or `web_server->`.
bool sets_hook(const std::string& code, const std::string& hook)
{
    for (std::size_t pos = code.find(hook); pos != std::string::npos;
         pos = code.find(hook, pos + hook.size())) {
        const std::size_t after = pos + hook.size();
        if (pos == 0 || is_ident(code[pos - 1])) continue;
        if (after < code.size() && is_ident(code[after])) continue;
        std::size_t j = after;
        while (j < code.size() && std::isspace(static_cast<unsigned char>(code[j]))) ++j;
        if (j >= code.size() || code[j] != '(') continue;

        std::size_t k = pos;
        while (k > 0 && std::isspace(static_cast<unsigned char>(code[k - 1]))) --k;
        if (k >= 2 && code[k - 2] == '-' && code[k - 1] == '>') k -= 2;
        else if (k >= 1 && code[k - 1] == '.') k -= 1;
        else continue;
        while (k > 0 && std::isspace(static_cast<unsigned char>(code[k - 1]))) --k;

        static const std::string gmi = "get_mining_interface()";
        if (k >= gmi.size() && code.compare(k - gmi.size(), gmi.size(), gmi) == 0)
            return true;
        const std::size_t end = k;
        while (k > 0 && is_ident(code[k - 1])) --k;
        const std::string id = code.substr(k, end - k);
        if (id == "web_server" || (id.size() >= 2 && id.compare(id.size() - 2, 2, "mi") == 0))
            return true;
    }
    return false;
}

struct Binary {
    std::string name;
    std::vector<std::string> sources;        // under src/
    bool has_mining_node;                    // web MI backed by a live IMiningNode (LTC)
    std::set<std::string> known_gaps;
};

// Read by every dashboard page (dashboard.html, share.html, miner.html,
// miners.html, stratum.html, loading.html).
const std::vector<std::string> kRequiredHooks = {
    "set_best_share_hash_fn",    // /web/best_share_hash, /web/sync_status
    "set_sharechain_stats_fn",   // /global_stats, /version_signaling, /v36_status, /miner_stats
    "set_sharechain_window_fn",  // /sharechain/window (explorer grid, share.html treemap)
    "set_sharechain_tip_fn",     // /sharechain/tip, /sharechain/stream
    "set_sharechain_delta_fn",   // /sharechain/delta
    "set_share_lookup_fn",       // /web/share/<hash> (share.html)
    "set_pool_hashrate_fn",      // /global_stats, graphs
    "set_peer_info_fn",          // /peer_list, /local_stats peers
    "set_node_topology_fn",      // /api/node_topology
    "set_coin_sync_status_fn",   // /broadcaster_status, /local_stats
    "set_block_verify_fn",       // /recent_blocks, /luck_stats confirmations
};

// Read on a binary whose web MI has no IMiningNode: there refresh_work() never
// fills the template the core payout, block-value and stratum paths use.
const std::vector<std::string> kNoMiningNodeHooks = {
    "set_current_payouts_fn",    // /current_payouts, /current_merged_payouts
    "set_coin_work_fn",          // /local_stats block value, network difficulty
    "set_stratum_workers_fn",    // /stratum_stats, /local_stats miners, worker graphs
};

const std::vector<Binary> kBinaries = {
    {"ltc",    {"c2pool/main_ltc.cpp"}, true, {}},
    {"dash",   {"c2pool/main_dash.cpp"}, false, {}},
    {"btc",    {"c2pool/main_btc.cpp"}, false, {}},
    {"bch",    {"c2pool/main_bch.cpp", "impl/bch/pool_entrypoint.hpp"}, false, {}},
    {"bip110", {"c2pool/main_bip110.cpp"}, false, {}},
    // DGB: its lane is rewriting main_dgb.cpp; these stay on the core default
    // until it lands them.
    {"dgb",    {"c2pool/main_dgb.cpp"}, false,
        {"set_best_share_hash_fn", "set_sharechain_delta_fn", "set_share_lookup_fn",
         "set_current_payouts_fn", "set_coin_work_fn", "set_stratum_workers_fn"}},
};

std::string wiring_code(const Binary& b)
{
    std::string code;
    for (const auto& rel : b.sources) {
        const std::string text = slurp(fs::path(C2POOL_SRC_ROOT) / rel);
        EXPECT_FALSE(text.empty()) << "cannot read src/" << rel;
        code += strip_comments(text);
        code += '\n';
    }
    return code;
}

} // namespace

TEST(DashboardHookWiring, CommentStripKeepsCodeOnly)
{
    const std::string src =
        "// mi->set_share_lookup_fn(x);\n"
        "/* mi->set_sharechain_tip_fn( */\n"
        "auto s = \"// not a comment\"; mi->set_sharechain_window_fn([]{});\n"
        "auto r = R\"(/* raw */)\"; work_source->set_best_share_hash_fn(f);\n";
    const std::string code = strip_comments(src);
    EXPECT_FALSE(sets_hook(code, "set_share_lookup_fn"));
    EXPECT_FALSE(sets_hook(code, "set_sharechain_tip_fn"));
    EXPECT_TRUE(sets_hook(code, "set_sharechain_window_fn"));
    EXPECT_FALSE(sets_hook(code, "set_best_share_hash_fn"));   // a work source's, not the MI's
    EXPECT_NE(code.find("\"// not a comment\""), std::string::npos);
    EXPECT_NE(code.find("R\"(/* raw */)\""), std::string::npos);
    EXPECT_TRUE(sets_hook("web_server.get_mining_interface()->set_share_lookup_fn(", "set_share_lookup_fn"));
    EXPECT_TRUE(sets_hook("cache_mi->set_block_verify_fn(", "set_block_verify_fn"));
    EXPECT_TRUE(sets_hook("web_server.set_best_share_hash_fn(", "set_best_share_hash_fn"));
}

TEST(DashboardHookWiring, EveryBinaryWiresTheDashboardHooks)
{
    for (const auto& b : kBinaries) {
        const std::string code = wiring_code(b);
        std::vector<std::string> hooks = kRequiredHooks;
        if (!b.has_mining_node)
            hooks.insert(hooks.end(), kNoMiningNodeHooks.begin(), kNoMiningNodeHooks.end());
        for (const auto& h : hooks) {
            const bool wired = sets_hook(code, h);
            if (b.known_gaps.count(h)) {
                if (wired)
                    std::cout << "[dashboard-hooks] " << b.name << " now wires " << h
                              << ": drop it from the known gaps\n";
                else
                    std::cout << "[dashboard-hooks] known gap: " << b.name << " " << h << "\n";
                continue;
            }
            EXPECT_TRUE(wired) << b.name << " does not wire " << h
                               << " (its endpoint serves the core default)";
        }
    }
}

// The known gaps name only hooks the scan checks, so an entry cannot outlive
// a renamed hook unnoticed.
TEST(DashboardHookWiring, KnownGapsAreCheckedHooks)
{
    std::set<std::string> all(kRequiredHooks.begin(), kRequiredHooks.end());
    all.insert(kNoMiningNodeHooks.begin(), kNoMiningNodeHooks.end());
    for (const auto& b : kBinaries)
        for (const auto& h : b.known_gaps)
            EXPECT_TRUE(all.count(h)) << b.name << " known gap " << h << " is not a checked hook";
}
