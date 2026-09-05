// SPDX-License-Identifier: AGPL-3.0-or-later
// CoinProfiles — single source of truth for the launch page's per-coin
// knowledge. Keeps c2pool-qt coin-generic (profile-driven) rather than
// hard-coding LTC/BTC/DOGE assumptions in PageLaunch.
//
// c2pool ships TWO distinct launch CLIs and this table records which one
// each coin uses, plus the binary name, daemon label, algo and default
// RPC ports so the launch form and the generated command line stay
// correct across coins:
//
//   • CliFamily::LegacyUnified — the unified `c2pool` binary
//     (src/c2pool/main_ltc.cpp) that selects the chain with `--net
//     litecoin|bitcoin|dogecoin|digibyte` and uses the Python-p2pool-
//     compatible flags (--p2pool-port / -w / --web-port /
//     --coind-address / --coind-rpc-port / --rpcuser / --rpcpassword).
//     Used for litecoin, bitcoin and dogecoin here.
//
//   • CliFamily::PerCoinRun — the dedicated per-coin binaries
//     (c2pool-dash / c2pool-dgb / c2pool-bch) whose run-loop is stood up
//     with a subcommand (`--run` or `--pool`) and whose parent-daemon
//     link is the reward-SAFE RPC arm: `--coin-rpc HOST:PORT` +
//     `--coin-rpc-auth PATH` (or `--rpc-conf PATH` for BCHN). The
//     rpcpassword NEVER touches argv — it is read from the coin's .conf.
//
// ★ REWARD SAFETY: the embedded coin-network arm (`--coin-p2p-connect`
//   and `--embedded-mainnet`) is reward-UNSAFE until validated and is
//   NEVER emitted by default. PageLaunch only emits it from an explicit,
//   default-OFF "Advanced / embedded (opt-in, reward-unsafe)" control.
//   See the DASH hotel incident: an unguarded embedded arm produced
//   reward-unsafe blocks. The default per-coin launch is the dashd-RPC
//   arm.
//
// This header mirrors the coin-generic, profile-driven approach the web
// dashboard/explorer already use (see CoinBridge's descriptor table):
// adding a coin is a table row, not a code edit scattered across the UI.

#pragma once

#include <core/param_catalog.hpp>   // c2pool::catalog::Bin (per-coin binary key)

#include <QLatin1String>
#include <QString>

namespace c2pool_qt {

enum class CliFamily {
    LegacyUnified,  ///< unified `c2pool` binary, chain via --net
    PerCoinRun,     ///< dedicated per-coin binary, run-loop subcommand
};

/// Per-coin launch profile. One row per supported chain; PageLaunch reads
/// everything it needs to build a correct, reward-safe command line from
/// this struct instead of branching on the chain string ad hoc.
struct CoinProfile {
    QString symbol;         ///< canonical chain id (matches --net value / CoinBridge)
    QString displayLabel;   ///< human label for combos/groups
    QString binary;         ///< default binary path (e.g. "c2pool", "c2pool-dash")
    QString daemonLabel;    ///< parent daemon name (litecoind / dashd / …)
    QString algoLabel;      ///< PoW algo, for display
    QString addressFlavor;  ///< short payout-address hint for the form

    CliFamily cli;          ///< which launch CLI family this coin uses
    QString   subcommand;   ///< PerCoinRun run-loop subcommand ("--run"/"--pool"); empty for legacy

    /// Which node binary this coin maps to in the parameter catalog
    /// (src/core/param_catalog.inc). LaunchCommand keys every flag spelling on
    /// this so the panel emits ONLY flags the target binary accepts. For the
    /// LegacyUnified `c2pool --net …` coins it records the closest catalog binary
    /// (unused on that path, which builds the Python-p2pool-compatible argv).
    c2pool::catalog::Bin bin;

    // Parent-daemon RPC link (PerCoinRun). For LegacyUnified these are the
    // --coind-rpc-port defaults; PageLaunch maps them to the right flag.
    int rpcPortMainnet;
    int rpcPortTestnet;

    // PerCoinRun flag vocabulary — recorded per coin so PageLaunch never
    // emits a flag the target binary does not accept.
    QString coinRpcFlag;        ///< endpoint override flag ("--coin-rpc"); empty if unsupported (BCH)
    QString rpcAuthFlag;        ///< creds-file flag ("--coin-rpc-auth" / "--rpc-conf")
    QString confHint;           ///< placeholder path for the creds file
    QString sharechainPortFlag; ///< sharechain P2P listen flag ("--listen"/"--sharechain-port"/"--p2p-port"); empty if none
    bool supportsTestnetFlag;   ///< binary accepts --testnet
    bool supportsWebPort;       ///< binary accepts --web-port / --http-port

    // Suggested miner-facing / dashboard ports for PerCoinRun coins.
    int stratumPortDefault;
    int webPortDefault;

    bool masternodePayee;   ///< coin pays a masternode/founder split (DASH) — surfaced as a note
    bool experimental;      ///< PerCoinRun binary still stabilising (DGB/BCH) — surfaced as a note

    // NOTE: this table no longer carries base58 version bytes. AddressValidator
    // reads the accepted version bytes / bech32 HRPs straight from the node
    // registry (src/impl/<coin>/address_encoding.hpp — the same
    // <coin>::address_acceptance() the stratum money-path uses, issue #961), so
    // the UI check can never drift from the node. See AddressValidator.hpp.
};

/// Ordered profile table. Order drives the chain combo. DASH is first-class.
inline const CoinProfile* coinProfiles(int& countOut)
{
    static const CoinProfile kProfiles[] = {
        // ── LegacyUnified: unified `c2pool` binary, chain via --net ──────────
        {"litecoin", "Litecoin", "c2pool", "litecoind", "Scrypt",
         "L… / M… (P2PKH/P2SH)",
         CliFamily::LegacyUnified, "", c2pool::catalog::Bin::BIN_LTC,
         9332, 19332,
         "", "", "", "", false, true,
         0, 0, false, false},
        {"bitcoin", "Bitcoin", "c2pool", "bitcoind", "SHA-256d",
         "1… / bc1… (P2PKH/bech32)",
         CliFamily::LegacyUnified, "", c2pool::catalog::Bin::BIN_BTC,
         8332, 18332,
         "", "", "", "", false, true,
         0, 0, false, false},
        {"dogecoin", "Dogecoin", "c2pool", "dogecoind", "Scrypt (AuxPoW)",
         "D… (P2PKH)",
         CliFamily::LegacyUnified, "", c2pool::catalog::Bin::BIN_LTC,
         22555, 44555,
         "", "", "", "", false, true,
         0, 0, false, false},

        // ── PerCoinRun: dedicated per-coin binaries ──────────────────────────
        // DASH — X11, masternode-payee coin, dashd parent. Default launch is
        // the reward-SAFE dashd-RPC arm; embedded P2P is opt-in only.
        {"dash", "Dash", "c2pool-dash", "dashd", "X11",
         "X… / 7… (P2PKH/P2SH)",
         CliFamily::PerCoinRun, "--run", c2pool::catalog::Bin::BIN_DASH,
         9998, 19998,
         "--coin-rpc", "--coin-rpc-auth", "~/.dashcore/dash.conf",
         "--listen", /*testnet*/ true, /*webPort*/ true,
         3333, 8080, /*masternode*/ true, /*experimental*/ false},

        // DigiByte — multi-algo (Scrypt here), digibyted parent. No --testnet
        // flag (mainnet/regtest only) and no --web-port on this binary.
        {"digibyte", "DigiByte", "c2pool-dgb", "digibyted", "Scrypt",
         "D… / S… (P2PKH/P2SH)",
         CliFamily::PerCoinRun, "--run", c2pool::catalog::Bin::BIN_DGB,
         14024, 14025,
         "--coin-rpc", "--coin-rpc-auth", "~/.digibyte/digibyte.conf",
         "--sharechain-port", /*testnet*/ false, /*webPort*/ false,
         5022, 0, /*masternode*/ false, /*experimental*/ true},

        // Bitcoin Cash — BCHN parent. Uses `--pool`, creds via --rpc-conf
        // (no --coin-rpc endpoint override), --p2p-port for the sharechain.
        {"bitcoincash", "Bitcoin Cash", "c2pool-bch", "bitcoind (BCHN)", "SHA-256d",
         "1… / q… (legacy/cashaddr)",
         CliFamily::PerCoinRun, "--pool", c2pool::catalog::Bin::BIN_BCH,
         8332, 18332,
         "", "--rpc-conf", "~/.bitcoin/bitcoin.conf",
         "--p2p-port", /*testnet*/ true, /*webPort*/ false,
         3333, 0, /*masternode*/ false, /*experimental*/ true},
    };
    countOut = static_cast<int>(sizeof(kProfiles) / sizeof(kProfiles[0]));
    return kProfiles;
}

/// Look up a profile by chain symbol; returns litecoin (index 0) for an
/// unknown symbol so callers always get a usable profile.
inline const CoinProfile& coinProfile(const QString& symbol)
{
    int n = 0;
    const CoinProfile* p = coinProfiles(n);
    for (int i = 0; i < n; ++i) {
        if (symbol == p[i].symbol) return p[i];
    }
    return p[0];
}

} // namespace c2pool_qt
