// SPDX-License-Identifier: AGPL-3.0-or-later
// test_reward_safe_launch — ★ #1 acceptance criterion.
//
// Proves the per-coin launch command core (LaunchCommand.hpp), driven by the
// node parameter catalog (ParamCatalogView → src/core/param_catalog.inc):
//   • the default DASH command is a bare `--run` (DAEMONLESS cut mode): it never
//     emits the dashd arm (--coin-rpc / --coin-rpc-auth) nor the embedded knobs
//     (--coin-p2p-connect / --peer / --embedded-mainnet / --coin-magic) unless
//     their explicit opt-ins are set;
//   • the dashd arm appears only when externalDaemonRpc is ticked — and on DASH
//     --coin-rpc-auth alone (auth without the attach opt-in) must NOT leak out;
//   • leaves the author donation to the binary default unless explicitly set, and
//     emits --give-author 0 ONLY behind an explicit ack (never a silent zero);
//   • emits, for EACH binary, only flag spellings the catalog carries for that
//     binary — so BCH argv has none of -f/--give-author/--node-owner-address/
//     --redistribute/--message-blob-hex/--addnode/--coin-rpc, DGB uses
//     --sharechain-addnode and --http, etc.;
//   • the legacy operation-mode flag resolves via the catalog — "solo" MUST emit
//     --solo (never nothing, which silently ran an integrated PPLNS node);
//   • validate_percoin only refuses an external-dashd attach with no RPC endpoint
//     — never a daemonless DASH launch (that is the intended default).
//
// Qt-free: builds and runs with a plain C++17 compiler (no display).
//
// Exit: 0 = all pass, 1 = a reward-safety assertion failed.

#include "../src/LaunchCommand.hpp"
#include "../src/ParamCatalogView.hpp"

#include <cstdio>
#include <string>
#include <vector>

using c2pool_qt::PerCoinParams;
using c2pool_qt::build_percoin_argv;
using c2pool_qt::join_argv;
using c2pool_qt::validate_percoin;
using c2pool_qt::legacy_mode_flag;
using c2pool_qt::LegacyMode;
using Bin = c2pool::catalog::Bin;

namespace {

int failures = 0;

bool contains(const std::vector<std::string>& a, const std::string& flag)
{
    for (const auto& s : a) if (s == flag) return true;
    return false;
}

void check(bool cond, const char* what)
{
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what);
    if (!cond) ++failures;
}

// Reverse catalog lookup: is `spelling` a real alias of `bin` in the catalog?
bool aliasInCatalog(Bin bin, const std::string& spelling)
{
    for (const auto& r : c2pool_qt::catview::rows())
        for (const auto& a : r.aliases)
            if (a.binary == bin && a.spelling == spelling) return true;
    return false;
}

// Every flag-looking token in argv (a "-"/"--" token, not argv[0], not a value)
// must be a catalog alias for that binary — the F4 anti-drift gate.
void checkEveryFlagInCatalog(Bin bin, const std::vector<std::string>& argv,
                             const char* label)
{
    bool ok = true;
    std::string bad;
    for (std::size_t i = 1; i < argv.size(); ++i) {   // skip argv[0] (binary path)
        const std::string& t = argv[i];
        if (t.size() >= 2 && t[0] == '-' && (t[1] == '-' || (t[1] >= 'a' && t[1] <= 'z'))) {
            if (!aliasInCatalog(bin, t)) { ok = false; bad = t; break; }
        }
    }
    if (!ok) std::printf("     offending flag: %s\n", bad.c_str());
    check(ok, label);
}

PerCoinParams dashDefault()
{
    PerCoinParams p;
    p.bin = Bin::BIN_DASH;
    p.binary = "./build/bin/c2pool-dash";
    p.subcommand = "--run";
    // The form always populates the RPC host/port (127.0.0.1:9998) — the
    // regression-relevant shape. With externalDaemonRpc=false (the default,
    // daemonless cut mode) the dashd arm must STILL be omitted.
    p.rpcHost = "127.0.0.1";
    p.rpcPort = 9998;                 // dashd mainnet RPC (populated, but unused)
    p.confPath = "";                  // blank ⇒ dashd default conf, off argv
    p.externalDaemonRpc = false;      // daemonless default (no dashd attach)
    p.stratumPort = 3333;
    p.webPort = 8080;
    p.webHost = "0.0.0.0";
    p.sharechainPort = 9339;
    // embeddedP2p / embeddedMainnet default false
    return p;
}

PerCoinParams bchDefault()
{
    PerCoinParams p;
    p.bin = Bin::BIN_BCH;
    p.binary = "./build/bin/c2pool-bch";
    p.subcommand = "--pool";
    p.confPath = "/home/u/.bitcoin/bitcoin.conf";
    // BCH has no endpoint/submit_endpoint alias — set an RPC host/port anyway to
    // prove neither --coin-rpc nor the HOST:PORT leaks onto BCH argv.
    p.rpcHost = "127.0.0.1";
    p.rpcPort = 8332;
    p.stratumPort = 3333;
    p.webPort = 8083;
    p.webHost = "0.0.0.0";
    p.sharechainPort = 9348;
    p.addnodes = {"1.2.3.4:9348"};
    // BCH has no money surface — set money fields anyway to prove they are dropped.
    p.payoutAddress = "bitcoincash:qexample";
    p.fee = 1.0;
    p.giveAuthorSet = true; p.giveAuthor = 0.5;
    p.redistribute = "fee";
    p.messageBlob = "deadbeef";
    return p;
}

PerCoinParams dgbDefault()
{
    PerCoinParams p;
    p.bin = Bin::BIN_DGB;
    p.binary = "./build/bin/c2pool-dgb";
    p.subcommand = "--run";
    p.rpcHost = "127.0.0.1";
    p.rpcPort = 14022;
    p.stratumPort = 5022;
    p.webPort = 5023;
    p.webHost = "0.0.0.0";
    p.sharechainPort = 5024;
    p.addnodes = {"5.6.7.8:5024"};
    p.payoutAddress = "DExampleDgbAddress";
    p.redistribute = "boost:70,donate:30";
    return p;
}

} // namespace

int main()
{
    std::printf("test_reward_safe_launch\n");

    // 1) DASH default command is DAEMONLESS (bare --run) — no dashd/embedded arm.
    {
        const auto argv = build_percoin_argv(dashDefault());
        const std::string cmd = join_argv(argv);
        std::printf("DASH default: %s\n", cmd.c_str());
        check(!contains(argv, "--coin-rpc"),
              "DASH default omits --coin-rpc (daemonless; RPC arm is opt-in)");
        check(!contains(argv, "--coin-rpc-auth"), "DASH default omits --coin-rpc-auth");
        check(!contains(argv, "--coin-daemon"), "DASH default omits --coin-daemon");
        check(!contains(argv, "--coin-p2p-connect"), "DASH default omits --coin-p2p-connect");
        check(!contains(argv, "--embedded-mainnet"),
              "DASH default omits --embedded-mainnet (node default ON when daemonless)");
        check(!contains(argv, "--coin-magic") && !contains(argv, "--coin-p2p-magic"),
              "DASH default omits coin-magic override");
        check(!contains(argv, "--give-author"),
              "DASH default omits --give-author (0.1%% binary default preserved)");
        check(validate_percoin(dashDefault()).empty(),
              "DASH default (daemonless) is launchable");
        check(cmd == "./build/bin/c2pool-dash --run --stratum 3333 --web-port 8080 --listen 9339",
              "DASH default golden argv is exactly the daemonless bare --run form");
        check(cmd.find("rpcpassword") == std::string::npos,
              "DASH default carries no rpcpassword on argv");
        checkEveryFlagInCatalog(Bin::BIN_DASH, argv, "DASH default: every flag is a catalog alias");
    }

    // 1b) DASH dashd attach opt-in emits the RPC arm; auth alone must NOT.
    {
        // externalDaemonRpc ON ⇒ --coin-rpc HOST:PORT present.
        PerCoinParams p = dashDefault();
        p.externalDaemonRpc = true;
        {
            const auto argv = build_percoin_argv(p);
            check(contains(argv, "--coin-rpc") && contains(argv, "127.0.0.1:9998"),
                  "DASH attach opt-in emits --coin-rpc 127.0.0.1:9998");
        }
        // With a conf path too ⇒ --coin-rpc-auth present.
        p.confPath = "/x/dash.conf";
        {
            const auto argv = build_percoin_argv(p);
            check(contains(argv, "--coin-rpc-auth"),
                  "DASH attach opt-in + conf path emits --coin-rpc-auth");
        }
        // ★ auth path set but attach OFF ⇒ NO --coin-rpc-auth (auth alone re-arms
        // dashd on DASH, main_dash.cpp:1191 — it must stay behind the opt-in).
        p.externalDaemonRpc = false;
        {
            const auto argv = build_percoin_argv(p);
            check(!contains(argv, "--coin-rpc-auth") && !contains(argv, "--coin-rpc"),
                  "DASH conf path with attach OFF emits neither --coin-rpc-auth nor --coin-rpc");
        }
    }

    // 2) Embedded arm appears ONLY when explicitly opted in.
    {
        PerCoinParams p = dashDefault();
        p.embeddedP2p = true;
        p.embeddedP2pPeers = {"127.0.0.1:9999"};
        p.embeddedMainnet = true;
        const auto argv = build_percoin_argv(p);
        check(contains(argv, "--coin-p2p-connect"), "opt-in ⇒ --coin-p2p-connect present");
        check(contains(argv, "--embedded-mainnet"), "opt-in ⇒ --embedded-mainnet present");
    }

    // 3) Opt-in checkbox ON but no peers ⇒ still no --coin-p2p-connect.
    {
        PerCoinParams p = dashDefault();
        p.embeddedP2p = true;   // checkbox ticked, peer list empty
        const auto argv = build_percoin_argv(p);
        check(!contains(argv, "--coin-p2p-connect"),
              "opt-in with empty peer list emits no --coin-p2p-connect");
    }

    // 4) ★ give-author tri-state (F6) — never a silent zero.
    {
        PerCoinParams p = dashDefault();
        // (a) default: not set ⇒ omitted.
        check(!contains(build_percoin_argv(p), "--give-author"),
              "give-author: default OMITS the flag (binary default applies)");
        // (b) 0 without ack ⇒ still omitted (never a forced zero).
        p.giveAuthor = 0.0; p.giveAuthorSet = false; p.giveAuthorExplicitZeroAck = false;
        {
            const auto argv = build_percoin_argv(p);
            const std::string cmd = join_argv(argv);
            check(cmd.find("--give-author 0") == std::string::npos,
                  "give-author: 0 without ack never emits --give-author 0");
        }
        // (c) explicit 0 WITH ack ⇒ --give-author 0.00.
        p.giveAuthor = 0.0; p.giveAuthorExplicitZeroAck = true;
        p.giveAuthorSet = (p.giveAuthor > 0.0) || p.giveAuthorExplicitZeroAck;
        {
            const auto argv = build_percoin_argv(p);
            check(contains(argv, "--give-author") && contains(argv, "0.00"),
                  "give-author: explicit 0 + ack emits --give-author 0.00");
        }
        // (d) positive value ⇒ emitted.
        p.giveAuthor = 0.5; p.giveAuthorExplicitZeroAck = false;
        p.giveAuthorSet = true;
        {
            const auto argv = build_percoin_argv(p);
            check(contains(argv, "--give-author") && contains(argv, "0.50"),
                  "give-author: explicit 0.50 emits --give-author 0.50");
        }
    }

    // 5) ★ Daemonless guard INVERTED — bare --run is the allowed default.
    {
        PerCoinParams p = dashDefault();
        p.rpcHost = ""; p.rpcPort = 0;              // blank RPC, attach OFF
        check(validate_percoin(p).empty(),
              "DASH blank RPC + attach OFF ⇒ validate_percoin ALLOWS (daemonless)");
        // Attach ticked but no endpoint ⇒ launchability refusal (not reward).
        p.externalDaemonRpc = true;
        check(!validate_percoin(p).empty(),
              "DASH attach ON + blank RPC host ⇒ validate_percoin REFUSES (launchability)");
        // Attach ticked WITH an endpoint ⇒ allowed.
        p.rpcHost = "127.0.0.1"; p.rpcPort = 9998;
        check(validate_percoin(p).empty(),
              "DASH attach ON + RPC HOST:PORT ⇒ allowed");
    }

    // 6) BCH default: reward-safe AND carries none of the money/DASH flags it rejects.
    {
        const auto argv = build_percoin_argv(bchDefault());
        const std::string cmd = join_argv(argv);
        std::printf("BCH default: %s\n", cmd.c_str());
        check(!contains(argv, "--coin-p2p-connect") && !contains(argv, "--peer")
                  && !contains(argv, "--embedded-mainnet"),
              "BCH default omits embedded reward-unsafe flags");
        check(contains(argv, "--rpc-conf"), "BCH default uses --rpc-conf creds arm");
        // F4: BCH now HAS a money surface (--fee / --give-author / --node-owner-address,
        // W-MONEY). bchDefault() sets fee=1.0, giveAuthor=0.5, payoutAddress, so those
        // three are emitted (catalog-driven). BCH still has NO --redistribute /
        // --message-blob-hex alias, so those stay dropped even when set.
        check(contains(argv, "--fee") && contains(argv, "--give-author")
                  && contains(argv, "--node-owner-address")
                  && !contains(argv, "--redistribute") && !contains(argv, "--message-blob-hex"),
              "BCH emits its money surface (--fee/--give-author/--node-owner-address), drops redistribute/message-blob");
        check(!contains(argv, "--addnode") && contains(argv, "--sharechain-addnode"),
              "BCH uses --sharechain-addnode (not DASH's --addnode)");
        check(contains(argv, "--http"), "BCH binds web via combined --http");
        // A4: BCH has no endpoint/submit alias — an RPC host/port is silently
        // dropped, so neither --coin-rpc nor the HOST:PORT may appear.
        check(!contains(argv, "--coin-rpc") && !contains(argv, "127.0.0.1:8332"),
              "BCH argv omits --coin-rpc and the RPC HOST:PORT (no endpoint alias)");
        checkEveryFlagInCatalog(Bin::BIN_BCH, argv, "BCH default: every flag is a catalog alias");
    }

    // 7) DGB default: --sharechain-addnode, --http combined, hybrid redistribute, no author fee.
    {
        const auto argv = build_percoin_argv(dgbDefault());
        const std::string cmd = join_argv(argv);
        std::printf("DGB default: %s\n", cmd.c_str());
        check(!contains(argv, "--addnode") && contains(argv, "--sharechain-addnode"),
              "DGB uses --sharechain-addnode (not --addnode)");
        check(contains(argv, "--http"), "DGB binds web via combined --http");
        check(!contains(argv, "-f") && !contains(argv, "--give-author"),
              "DGB default omits --fee/--give-author (surface exists but dgbDefault sets neither)");
        check(contains(argv, "--redistribute") && contains(argv, "boost:70,donate:30"),
              "DGB emits hybrid --redistribute SPEC");
        check(contains(argv, "--node-owner-address"),
              "DGB emits --node-owner-address (it has that surface)");
        checkEveryFlagInCatalog(Bin::BIN_DGB, argv, "DGB default: every flag is a catalog alias");
    }

    // 8) --http HOST:PORT combined form when a non-default web host is set (DGB).
    {
        PerCoinParams p = dgbDefault();
        p.webHost = "10.0.0.5";
        const auto argv = build_percoin_argv(p);
        check(contains(argv, "10.0.0.5:5023"),
              "DGB --http emits combined HOST:PORT when web host is non-default");
    }

    // 9) ★ E2 — legacy operation-mode flag resolves via the catalog. A "solo"
    //    that emitted nothing silently ran an integrated PPLNS node; it MUST
    //    emit --solo now. Each spelling must be a real BIN_LTC catalog alias.
    {
        check(legacy_mode_flag(LegacyMode::Solo) == "--solo",
              "legacy_mode_flag(Solo) == --solo");
        check(legacy_mode_flag(LegacyMode::Sharechain) == "--sharechain",
              "legacy_mode_flag(Sharechain) == --sharechain");
        check(legacy_mode_flag(LegacyMode::Integrated) == "--integrated",
              "legacy_mode_flag(Integrated) == --integrated");
        check(legacy_mode_flag(LegacyMode::Custodial) == "--custodial",
              "legacy_mode_flag(Custodial) == --custodial");
        check(legacy_mode_flag(LegacyMode::Standalone) == "--standalone",
              "legacy_mode_flag(Standalone) == --standalone");
        check(aliasInCatalog(Bin::BIN_LTC, "--solo")
                  && aliasInCatalog(Bin::BIN_LTC, "--sharechain")
                  && aliasInCatalog(Bin::BIN_LTC, "--integrated")
                  && aliasInCatalog(Bin::BIN_LTC, "--custodial")
                  && aliasInCatalog(Bin::BIN_LTC, "--standalone"),
              "every legacy mode flag is a real BIN_LTC catalog alias");
    }

    // 10) ★ A4 — the catalog fact the BCH widget gating relies on: c2pool-bch
    //     carries NO endpoint/submit/message alias, so those form fields would
    //     silently drop and must be disabled. Post-W-MONEY it DOES carry the
    //     money payout / author-fee / owner-fee surface (but still no redistribute).
    {
        using c2pool_qt::catview::spelling_for;
        auto bchHas = [](const char* c) {
            return spelling_for(Bin::BIN_BCH, c).has_value();
        };
        check(!bchHas("daemon_rpc.endpoint") && !bchHas("daemon_rpc.submit_endpoint"),
              "BCH catalog has no RPC endpoint alias (host/port disabled)");
        check(bchHas("money.node_owner_address"),
              "BCH catalog has node_owner_address (payout field enabled by W-MONEY)");
        check(bchHas("money.give_author_pct") && bchHas("money.node_owner_fee_pct")
                  && !bchHas("money.redistribute"),
              "BCH catalog has author-fee / owner-fee surface (W-MONEY) but still no redistribute");
        check(!bchHas("global.message_blob_hex"),
              "BCH catalog has no message-blob alias (message field disabled)");
    }

    std::printf(failures == 0 ? "ALL PASS\n" : "FAILURES: %d\n", failures);
    return failures == 0 ? 0 : 1;
}
