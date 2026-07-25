// SPDX-License-Identifier: AGPL-3.0-or-later
// test_reward_safe_launch — ★ #1 acceptance criterion.
//
// Proves the per-coin launch command core NEVER emits the reward-UNSAFE
// embedded arm (--coin-p2p-connect / --embedded-mainnet) by default, and
// that the default parent-daemon link is the reward-SAFE --coin-rpc arm.
// Qt-free: builds and runs with a plain C++17 compiler (no display).
//
// Mirrors PageLaunch's DASH default (dashd-RPC arm, embedded opt-ins OFF).
//
// Exit: 0 = all pass, 1 = a reward-safety assertion failed.

#include "../src/LaunchCommand.hpp"

#include <cstdio>
#include <string>
#include <vector>

using c2pool_qt::PerCoinParams;
using c2pool_qt::build_percoin_argv;
using c2pool_qt::join_argv;

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

// The DASH default profile as PageLaunch fills it: reward-SAFE dashd-RPC
// arm, embedded opt-ins OFF.
PerCoinParams dashDefault()
{
    PerCoinParams p;
    p.binary = "./build/bin/c2pool-dash";
    p.subcommand = "--run";
    p.testnet = false;
    p.supportsTestnetFlag = true;
    p.coinRpcFlag = "--coin-rpc";
    p.rpcHost = "127.0.0.1";
    p.rpcPort = 9998;                 // dashd mainnet RPC
    p.rpcAuthFlag = "--coin-rpc-auth";
    p.confPath = "";                  // blank ⇒ dashd default conf, off argv
    p.stratumPort = 3333;
    p.supportsWebPort = true;
    p.webPort = 8080;
    p.webHost = "0.0.0.0";
    p.sharechainPortFlag = "--listen";
    p.sharechainPort = 9339;
    // embeddedP2p / embeddedMainnet default false
    return p;
}

} // namespace

int main()
{
    std::printf("test_reward_safe_launch\n");

    // 1) DASH default command is reward-SAFE.
    {
        const auto argv = build_percoin_argv(dashDefault());
        const std::string cmd = join_argv(argv);
        std::printf("DASH default: %s\n", cmd.c_str());
        check(!contains(argv, "--coin-p2p-connect"),
              "DASH default omits --coin-p2p-connect");
        check(!contains(argv, "--embedded-mainnet"),
              "DASH default omits --embedded-mainnet");
        check(contains(argv, "--coin-rpc"),
              "DASH default uses reward-safe --coin-rpc arm");
        check(argv.size() >= 2 && argv[0] == "./build/bin/c2pool-dash"
                  && argv[1] == "--run",
              "DASH default invokes c2pool-dash --run");
        // No secret ever on argv.
        check(cmd.find("rpcpassword") == std::string::npos
                  && cmd.find("--rpcpassword") == std::string::npos,
              "DASH default carries no rpcpassword on argv");
    }

    // 2) Embedded arm appears ONLY when explicitly opted in.
    {
        PerCoinParams p = dashDefault();
        p.embeddedP2p = true;
        p.embeddedP2pPeers = {"127.0.0.1:9999"};
        p.embeddedMainnet = true;
        const auto argv = build_percoin_argv(p);
        check(contains(argv, "--coin-p2p-connect"),
              "opt-in ⇒ --coin-p2p-connect present");
        check(contains(argv, "--embedded-mainnet"),
              "opt-in ⇒ --embedded-mainnet present");
    }

    // 3) Opt-in checkbox ON but no peers ⇒ still no --coin-p2p-connect.
    {
        PerCoinParams p = dashDefault();
        p.embeddedP2p = true;   // checkbox ticked, peer list empty
        const auto argv = build_percoin_argv(p);
        check(!contains(argv, "--coin-p2p-connect"),
              "opt-in with empty peer list emits no --coin-p2p-connect");
    }

    // 4) BCH default (creds via --rpc-conf, no --coin-rpc endpoint) stays safe.
    {
        PerCoinParams p;
        p.binary = "./build/bin/c2pool-bch";
        p.subcommand = "--pool";
        p.supportsTestnetFlag = true;
        p.coinRpcFlag = "";            // BCH has no endpoint override
        p.rpcAuthFlag = "--rpc-conf";
        p.confPath = "/home/u/.bitcoin/bitcoin.conf";
        p.stratumPort = 3333;
        const auto argv = build_percoin_argv(p);
        std::printf("BCH default: %s\n", join_argv(argv).c_str());
        check(!contains(argv, "--coin-p2p-connect")
                  && !contains(argv, "--embedded-mainnet"),
              "BCH default omits embedded reward-unsafe flags");
        check(contains(argv, "--rpc-conf"),
              "BCH default uses --rpc-conf creds arm");
    }

    std::printf(failures == 0 ? "ALL PASS\n" : "FAILURES: %d\n", failures);
    return failures == 0 ? 0 : 1;
}
