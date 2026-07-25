// SPDX-License-Identifier: AGPL-3.0-or-later
// LaunchCommand — Qt-free core that assembles the per-coin (PerCoinRun)
// c2pool command line from plain parameters.
//
// Kept deliberately independent of Qt (std::string / std::vector only) so
// the ★ reward-safety invariant can be unit-tested WITHOUT a display,
// QApplication, or the widget stack:
//
//   With the embedded opt-ins OFF (their default), the generated argv for
//   ANY coin NEVER contains --coin-p2p-connect or --embedded-mainnet, and
//   the default parent-daemon link is the reward-SAFE --coin-rpc arm.
//
// PageLaunch fills PerCoinParams from the form + the active CoinProfile and
// calls build_percoin_argv(); this file is where the ordering and the
// embedded-arm gating actually live. See test/test_reward_safe_launch.cpp.

#pragma once

#include <cstdio>
#include <string>
#include <vector>

namespace c2pool_qt {

struct PerCoinParams {
    std::string binary;       ///< e.g. "./build/bin/c2pool-dash"
    std::string subcommand;   ///< "--run" / "--pool" / ""

    std::string dataDir;      ///< --data-dir PATH (empty ⇒ omit)

    bool testnet = false;
    bool supportsTestnetFlag = false;  ///< binary accepts --testnet

    // Reward-SAFE parent-daemon RPC arm.
    std::string coinRpcFlag;  ///< "--coin-rpc" (empty ⇒ binary has no endpoint override, e.g. BCH)
    std::string rpcHost;
    int         rpcPort = 0;
    std::string rpcAuthFlag;  ///< "--coin-rpc-auth" / "--rpc-conf"
    std::string confPath;     ///< creds file PATH (rpcpassword stays off argv)

    int stratumPort = 0;      ///< --stratum PORT (0 ⇒ omit / disabled)

    bool        supportsWebPort = false;
    int         webPort = 0;  ///< --web-port PORT
    std::string webHost;      ///< --web-host ADDR (omit when default 0.0.0.0)

    std::string              sharechainPortFlag; ///< "--listen"/"--sharechain-port"/"--p2p-port"
    int                      sharechainPort = 0;
    std::vector<std::string> addnodes;           ///< --addnode HOST:PORT (repeatable)

    // Payout / fee / donation.
    std::string payoutAddress;    ///< --node-owner-address ADDR
    double      fee = 0.0;        ///< -f PCT
    double      giveAuthor = 0.0; ///< --give-author PCT
    std::string redistribute;     ///< --redistribute MODE (omit when "pplns")

    std::string messageBlob;      ///< --message-blob-hex HEX

    // ── ★ Embedded reward-UNSAFE arm — OPT-IN, default OFF ────────────────
    bool                     embeddedP2p = false;      ///< gate for --coin-p2p-connect
    std::vector<std::string> embeddedP2pPeers;         ///< HOST:PORT peers
    bool                     embeddedMainnet = false;  ///< --embedded-mainnet (DASH)
};

/// Assemble the argv (binary first). The embedded reward-UNSAFE flags are
/// appended ONLY when their opt-in bools are true — this is the single
/// choke point that enforces the reward-safe default.
inline std::vector<std::string> build_percoin_argv(const PerCoinParams& p)
{
    std::vector<std::string> a;
    auto trimmed = [](const std::string& s) {
        const auto b = s.find_first_not_of(" \t\r\n");
        if (b == std::string::npos) return std::string();
        const auto e = s.find_last_not_of(" \t\r\n");
        return s.substr(b, e - b + 1);
    };
    auto fmtPct = [](double v) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%.2f", v);
        return std::string(buf);
    };

    a.push_back(trimmed(p.binary));
    if (!p.subcommand.empty()) a.push_back(p.subcommand);

    if (!trimmed(p.dataDir).empty()) { a.push_back("--data-dir"); a.push_back(trimmed(p.dataDir)); }

    if (p.testnet && p.supportsTestnetFlag) a.push_back("--testnet");

    // Reward-SAFE RPC arm (endpoint carries no secret; creds via conf file).
    if (!p.coinRpcFlag.empty() && !trimmed(p.rpcHost).empty() && p.rpcPort > 0) {
        a.push_back(p.coinRpcFlag);
        a.push_back(trimmed(p.rpcHost) + ":" + std::to_string(p.rpcPort));
    }
    if (!p.rpcAuthFlag.empty() && !trimmed(p.confPath).empty()) {
        a.push_back(p.rpcAuthFlag);
        a.push_back(trimmed(p.confPath));
    }

    if (p.stratumPort > 0) { a.push_back("--stratum"); a.push_back(std::to_string(p.stratumPort)); }

    if (p.supportsWebPort && p.webPort > 0) {
        a.push_back("--web-port");
        a.push_back(std::to_string(p.webPort));
        const std::string wh = trimmed(p.webHost);
        if (!wh.empty() && wh != "0.0.0.0") { a.push_back("--web-host"); a.push_back(wh); }
    }

    if (!p.sharechainPortFlag.empty() && p.sharechainPort > 0) {
        a.push_back(p.sharechainPortFlag);
        a.push_back(std::to_string(p.sharechainPort));
    }
    for (const auto& n : p.addnodes) {
        const std::string t = trimmed(n);
        if (!t.empty()) { a.push_back("--addnode"); a.push_back(t); }
    }

    if (!trimmed(p.payoutAddress).empty()) {
        a.push_back("--node-owner-address");
        a.push_back(trimmed(p.payoutAddress));
    }
    if (p.fee > 0.0)        { a.push_back("-f"); a.push_back(fmtPct(p.fee)); }
    if (p.giveAuthor > 0.0) { a.push_back("--give-author"); a.push_back(fmtPct(p.giveAuthor)); }
    if (!p.redistribute.empty() && p.redistribute != "pplns") {
        a.push_back("--redistribute");
        a.push_back(p.redistribute);
    }
    if (!trimmed(p.messageBlob).empty()) {
        a.push_back("--message-blob-hex");
        a.push_back(trimmed(p.messageBlob));
    }

    // ── ★ Embedded reward-UNSAFE arm — appended ONLY when opted in ────────
    if (p.embeddedP2p) {
        for (const auto& peer : p.embeddedP2pPeers) {
            const std::string t = trimmed(peer);
            if (!t.empty()) { a.push_back("--coin-p2p-connect"); a.push_back(t); }
        }
    }
    if (p.embeddedMainnet) a.push_back("--embedded-mainnet");

    return a;
}

/// Join an argv into a single shell-preview string (space-separated).
inline std::string join_argv(const std::vector<std::string>& a)
{
    std::string out;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (i) out += ' ';
        out += a[i];
    }
    return out;
}

} // namespace c2pool_qt
