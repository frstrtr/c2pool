// SPDX-License-Identifier: AGPL-3.0-or-later
// LaunchCommand — Qt-free core that assembles the per-coin (PerCoinRun)
// c2pool command line from plain parameters.
//
// Kept deliberately independent of Qt (std::string / std::vector only) so the
// ★ reward-safety invariant can be unit-tested WITHOUT a display, QApplication,
// or the widget stack. See test/test_reward_safe_launch.cpp.
//
// Every flag SPELLING is resolved from the node's parameter catalog
// (ParamCatalogView → src/core/param_catalog.inc), keyed by (binary, canonical
// param). This has two consequences that matter:
//
//   1. A flag is emitted for a binary ONLY when the catalog carries an alias row
//      for that binary — so the panel can NEVER emit a flag the target binary
//      rejects (BCH has no money flags; DGB/BCH spell "add peer" as
//      --sharechain-addnode, not --addnode; DGB/BCH/BTC bind the web port as a
//      combined --http [HOST:]PORT). This is the fix for the launch-failure class
//      where every PerCoinRun coin was fed the DASH flag spellings verbatim.
//
//   2. ★ REWARD SAFETY. The panel only ASSEMBLES argv; it never carries a
//      reward decision — the node's own good-citizen defaults do. The default
//      DASH launch is a bare `--run` (daemonless cut mode): with no dashd arm
//      the node keeps its serving levers ON (embedded-mainnet + serve defaults
//      per good_citizen_defaults.hpp), so the panel does NOT emit
//      --embedded-mainnet for that default. The dashd/coin-RPC arm
//      (--coin-rpc + --coin-rpc-auth) is emitted ONLY behind an explicit
//      "attach external dashd" opt-in (PerCoinParams::externalDaemonRpc) — on
//      DASH both --coin-rpc AND --coin-rpc-auth re-arm dashd, so auth alone is
//      also gated. The embedded --coin-p2p-connect / coin-magic knobs stay
//      opt-in (transport / explicit gate-lift, not "reward-UNSAFE"). The author
//      donation is left to the binary default (0.1% / BTC 0.5%) unless the
//      operator explicitly sets it; --give-author 0 is emitted ONLY behind an
//      explicit opt-in ack, never as a default for a public node.
//      validate_percoin() no longer refuses a daemonless DASH launch (that is
//      the intended default) — it only checks launchability of an attached arm.

#pragma once

#include "ParamCatalogView.hpp"

#include <cstdio>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace c2pool_qt {

using c2pool::catalog::Bin;
using c2pool::catalog::AliasStyle;

struct PerCoinParams {
    Bin         bin = Bin::BIN_DASH;   ///< which per-coin binary (catalog key)
    std::string binary;                ///< e.g. "./build/bin/c2pool-dash"
    std::string subcommand;            ///< "--run" / "--pool" / ""

    std::string dataDir;               ///< meta.data_dir PATH (empty ⇒ omit)

    bool testnet = false;              ///< network.testnet (emitted iff the bin has the alias)
    bool regtest = false;              ///< network.regtest

    // Parent-daemon RPC arm. Host+port ⇒ daemon_rpc.endpoint (DASH --coin-rpc /
    // BTC --bitcoind) or daemon_rpc.submit_endpoint (DGB --coin-rpc). confPath ⇒
    // daemon_rpc.auth_file (--coin-rpc-auth / --rpc-conf). The rpcpassword NEVER
    // touches argv — it is read from the coin's .conf.
    std::string rpcHost;
    int         rpcPort = 0;
    std::string confPath;

    // Explicit opt-in to the dashd/coin-RPC arm (--coin-rpc + --coin-rpc-auth).
    // DASH: default OFF = daemonless cut mode (bare --run, node's good-citizen
    // serving defaults). Consulted for BIN_DASH only; DGB/BCH keep their existing
    // endpoint/auth emission (this flag is forced true for them by the marshaller).
    bool        externalDaemonRpc = false;

    int         stratumPort = 0;       ///< stratum.bind PORT (0 ⇒ omit)

    int         webPort = 0;           ///< web.port (0 ⇒ omit)
    std::string webHost;               ///< web.host / combined --http host

    int                      sharechainPort = 0;   ///< sharechain.listen
    std::vector<std::string> addnodes;             ///< sharechain.addnodes (repeatable)

    // Payout / fee / donation (money.*). Reward-safe tri-state on give-author.
    std::string payoutAddress;                 ///< money.node_owner_address
    double      fee = 0.0;                      ///< money.node_owner_fee_pct (emit iff > 0)
    bool        giveAuthorSet = false;          ///< operator explicitly overrides the binary default
    double      giveAuthor = 0.0;               ///< money.give_author_pct value
    bool        giveAuthorExplicitZeroAck = false; ///< required to emit an explicit 0
    std::string redistribute;                   ///< money.redistribute (omit when "pplns")

    std::string messageBlob;                    ///< global.message_blob_hex

    // ── DGB/BCH deeper run-loop controls (PR-1) ──────────────────────────────
    bool        coinP2pDiscover = false;   ///< coin_p2p.discover (transport, reward-neutral)
    bool        noP2pRelay = false;        ///< sharechain.no_p2p_relay
    std::string bchAnchor;                 ///< embedded.anchor (BCH cold-start ABLA floor)

    // ── ★ Embedded coin-network transport / explicit gate-lift — OPT-IN, OFF ──
    // (DASH defaults ON daemonless: with no dashd arm the node already runs the
    //  embedded arm with --embedded-mainnet, so these only pin peers or force the
    //  flag explicitly — needed only when dashd is attached, where it is OFF.)
    bool                     embeddedP2p = false;      ///< coin_p2p.connect (DASH --coin-p2p-connect / BCH --peer)
    std::vector<std::string> embeddedP2pPeers;         ///< HOST:PORT peers
    bool                     embeddedMainnet = false;  ///< embedded.mainnet (DASH)
    std::string              coinDaemon;               ///< coin_p2p.producer_target (DGB --coin-daemon)
    std::string              coinMagic;                ///< coin_p2p.magic (DASH --coin-p2p-magic / DGB --coin-magic)
    std::string              coinGenesis;              ///< network.coin_genesis (DGB)
};

namespace detail {

inline std::string trim(const std::string& s)
{
    const auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return std::string();
    const auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

inline std::string fmt_pct(double v)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.2f", v);
    return std::string(buf);
}

// Append "<spelling> <value>" iff the binary has an alias for `canon` and the
// value is non-empty. A canon with no alias for this binary emits NOTHING —
// the single mechanism that stops a wrong-binary flag from being generated.
inline void emit_value(std::vector<std::string>& a, Bin bin,
                       const char* canon, const std::string& value)
{
    if (value.empty()) return;
    auto s = catview::spelling_for(bin, canon);
    if (!s) return;
    a.push_back(s->first);
    a.push_back(value);
}

// Append a bare "<spelling>" flag iff the binary has an alias for `canon`.
inline void emit_flag(std::vector<std::string>& a, Bin bin, const char* canon)
{
    auto s = catview::spelling_for(bin, canon);
    if (!s) return;
    a.push_back(s->first);
}

} // namespace detail

/// Launchability precheck. Returns "" when the params are launchable, else a
/// human-readable reason PageLaunch surfaces and refuses on. Nothing here may
/// refuse a daemonless DASH launch — bare `--run` (no dashd arm) is the intended
/// default cut mode. The ONLY DASH check is that an explicitly-requested external
/// dashd attach actually carries a HOST:PORT to attach to.
inline std::string validate_percoin(const PerCoinParams& p)
{
    if (p.bin == Bin::BIN_DASH && p.externalDaemonRpc) {
        const bool haveRpc = !detail::trim(p.rpcHost).empty() && p.rpcPort > 0;
        if (!haveRpc) {
            return "External dashd attach is ticked but no RPC HOST:PORT is set. "
                   "Set the RPC host/port for --coin-rpc, or untick 'Attach external "
                   "dashd' to run daemonless (the default).";
        }
    }
    return "";
}

/// Assemble the argv (binary first). The embedded coin-network transport /
/// explicit gate-lift flags (DASH defaults ON daemonless) are appended ONLY when
/// their opt-in bools are true — the single choke point that keeps the default
/// argv minimal.
inline std::vector<std::string> build_percoin_argv(const PerCoinParams& p)
{
    using detail::trim;
    using detail::fmt_pct;
    using detail::emit_value;
    using detail::emit_flag;

    std::vector<std::string> a;
    const Bin bin = p.bin;

    a.push_back(trim(p.binary));
    if (!p.subcommand.empty()) a.push_back(p.subcommand);

    emit_value(a, bin, "meta.data_dir", trim(p.dataDir));

    if (p.testnet) emit_flag(a, bin, "network.testnet");
    if (p.regtest) emit_flag(a, bin, "network.regtest");

    // Parent-daemon RPC arm. daemon_rpc.endpoint (DASH --coin-rpc / BTC
    // --bitcoind) where the bin has it; else daemon_rpc.submit_endpoint
    // (DGB --coin-rpc). BCH has neither and links creds only via --rpc-conf.
    //
    // On DASH the whole arm is gated behind the explicit external-dashd opt-in:
    // both --coin-rpc AND --coin-rpc-auth re-arm dashd (main_dash.cpp:1191-1192),
    // so auth alone must NOT leak out and silently leave daemonless cut mode. For
    // every other binary the arm emits as before.
    const bool rpcArm = (bin != Bin::BIN_DASH) || p.externalDaemonRpc;
    if (rpcArm && !trim(p.rpcHost).empty() && p.rpcPort > 0) {
        const std::string ep = trim(p.rpcHost) + ":" + std::to_string(p.rpcPort);
        if (catview::spelling_for(bin, "daemon_rpc.endpoint"))
            emit_value(a, bin, "daemon_rpc.endpoint", ep);
        else
            emit_value(a, bin, "daemon_rpc.submit_endpoint", ep);
    }
    if (rpcArm)
        emit_value(a, bin, "daemon_rpc.auth_file", trim(p.confPath));

    if (p.stratumPort > 0)
        emit_value(a, bin, "stratum.bind", std::to_string(p.stratumPort));

    // web.port — combined --http [HOST:]PORT for DGB/BCH/BTC; separate
    // --web-port / --web-host for DASH/LTC.
    if (p.webPort > 0) {
        auto webS = catview::spelling_for(bin, "web.port");
        if (webS) {
            const std::string wh = trim(p.webHost);
            const std::string port = std::to_string(p.webPort);
            if (webS->second == AliasStyle::VALUE_HOSTPORT_COMBINED) {
                const std::string v =
                    (!wh.empty() && wh != "0.0.0.0") ? wh + ":" + port : port;
                a.push_back(webS->first);
                a.push_back(v);
            } else {
                a.push_back(webS->first);
                a.push_back(port);
                if (!wh.empty() && wh != "0.0.0.0")
                    emit_value(a, bin, "web.host", wh);
            }
        }
    }

    if (p.sharechainPort > 0)
        emit_value(a, bin, "sharechain.listen", std::to_string(p.sharechainPort));
    for (const auto& n : p.addnodes) {
        const std::string t = trim(n);
        if (!t.empty()) emit_value(a, bin, "sharechain.addnodes", t);
    }

    if (p.coinP2pDiscover) emit_flag(a, bin, "coin_p2p.discover");
    if (p.noP2pRelay)      emit_flag(a, bin, "sharechain.no_p2p_relay");
    emit_value(a, bin, "embedded.anchor", trim(p.bchAnchor));

    // ── Money (only where the catalog carries the alias for this binary) ──────
    emit_value(a, bin, "money.node_owner_address", trim(p.payoutAddress));
    if (p.fee > 0.0)
        emit_value(a, bin, "money.node_owner_fee_pct", fmt_pct(p.fee));

    // ★ give-author tri-state (F6). Default = OMIT ⇒ the binary default applies
    // (DASH/LTC/BIP110 0.1%, BTC 0.5%). An explicit value is emitted only when
    // the operator overrode it, and an explicit ZERO ONLY behind an ack — never
    // a silent --give-author 0 for a public node.
    if (p.giveAuthorSet) {
        if (p.giveAuthor > 0.0)
            emit_value(a, bin, "money.give_author_pct", fmt_pct(p.giveAuthor));
        else if (p.giveAuthorExplicitZeroAck)
            emit_value(a, bin, "money.give_author_pct", fmt_pct(0.0));
    }

    {
        const std::string rd = trim(p.redistribute);
        if (!rd.empty() && rd != "pplns")
            emit_value(a, bin, "money.redistribute", rd);
    }

    emit_value(a, bin, "global.message_blob_hex", trim(p.messageBlob));

    // ── ★ Embedded coin-network transport / explicit gate-lift — opt-in only ──
    // (DASH defaults ON daemonless; these pin peers / force the flag explicitly.)
    if (p.embeddedP2p) {
        for (const auto& peer : p.embeddedP2pPeers) {
            const std::string t = trim(peer);
            if (!t.empty()) emit_value(a, bin, "coin_p2p.connect", t);
        }
        emit_value(a, bin, "coin_p2p.producer_target", trim(p.coinDaemon));
        emit_value(a, bin, "coin_p2p.magic", trim(p.coinMagic));
        emit_value(a, bin, "network.coin_genesis", trim(p.coinGenesis));
    }
    if (p.embeddedMainnet) emit_flag(a, bin, "embedded.mainnet");

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

// ── Legacy (`c2pool --net …`) operation mode ──────────────────────────────────
// The unified binary's mode combo. Order matches the LegacyUnified mode combo in
// PageLaunch. The flag SPELLING is resolved from the catalog (BIN_LTC mode
// aliases in param_catalog.inc) so the panel can never drift from the node — the
// same Qt-free seam the reward test proves. `Integrated` emits --integrated
// explicitly (harmless; the binary default is integrated anyway); `Solo` MUST
// emit --solo (a legacy "solo" that emitted nothing silently produced an
// integrated PPLNS node). Returns "" only if the catalog has no alias.
enum class LegacyMode { Integrated = 0, Sharechain = 1, Solo = 2, Custodial = 3, Standalone = 4 };

inline std::string legacy_mode_flag(LegacyMode m)
{
    const char* canon = nullptr;
    switch (m) {
        case LegacyMode::Integrated: canon = "meta.mode_integrated"; break;
        case LegacyMode::Sharechain: canon = "meta.mode_sharechain"; break;
        case LegacyMode::Solo:       canon = "meta.mode_solo";       break;
        case LegacyMode::Custodial:  canon = "meta.mode_custodial";  break;
        case LegacyMode::Standalone: canon = "meta.mode_standalone"; break;
    }
    if (!canon) return std::string();
    auto s = catview::spelling_for(Bin::BIN_LTC, canon);
    return s ? s->first : std::string();
}

} // namespace c2pool_qt
