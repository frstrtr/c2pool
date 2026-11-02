// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Inject scheduler — the operator command line of the headless runner
// c2wallet-qt-schedd (slice S2), Qt-free so the KATs drive every subcommand
// against a fake node. The binary's main() only supplies the Qt Network
// transport, the clock, stdout/stderr and signal-aware sleeping.
//
//   c2wallet-qt-schedd [--queue PATH] [--node-url URL] [--token-file PATH]
//                      [--poll-sec N] <command> [options]
//
// Commands: init, add, list, show, pause, resume, rm, requeue, retry,
// set-max-fee, arm-policy (alias set-arm-policy), ack-alerts, status, run,
// and the Scan & Plan commands scan, plan, preflight, watch (scan/ScanCli).
// usage_text() is the reference. Rules the parser enforces:
//   * there is no --token VALUE in any spelling (argv is world-readable): the
//     token is only ever read from the 0600 --token-file by the runner;
//   * --node-url must be loopback http (Config.hpp);
//   * auto-arm consent is recorded only by `arm-policy --auto-arm yes
//     --consent "<text>"` (timestamped in the queue file); nothing defaults
//     to it, and auto-disarm stays off unless given explicitly;
//   * a child waits for its parents' finality; --allow-unconfirmed-parent is
//     the only way to let a mempool parent fire it;
//   * edits refuse a queue file owned by another user (the runner, its owner,
//     must be able to read the file back after the atomic rename).

#include "Clock.hpp"
#include "NodeApi.hpp"

#include "../scan/RpcApi.hpp"

#include <cstdint>
#include <functional>
#include <iosfwd>
#include <memory>
#include <string>
#include <vector>

namespace c2w::companion::sched::cli {

inline constexpr int kExitOk = 0;
inline constexpr int kExitAttention = 1; // an operation was refused, or `status` needs attention
inline constexpr int kExitUsage = 2;     // usage or configuration error
inline constexpr int kExitQueue = 3;     // queue file unreadable or invalid
inline constexpr int kExitLock = 4;      // another runner holds the queue (run)

struct Env {
    std::ostream* out = nullptr;
    std::ostream* err = nullptr;
    const Clock* clock = nullptr;
    // Build the node transport for a validated loopback URL (QtNodeApi in the
    // daemon, a scripted fake in the KATs).
    std::function<std::unique_ptr<NodeApi>(const std::string& url, std::string& why)> make_api;
    // Wait up to `ms` between ticks; return early once a stop was requested.
    std::function<void(int64_t ms)> sleep_ms;
    std::function<bool()> stop_requested;
    // Used when --queue is not given (see default_queue_path()).
    std::string default_queue_path;
    // Scan & Plan (scan/ScanCli): the dashd JSON-RPC transport for a validated
    // loopback URL and a 0600 credentials file (QtRpcApi in the daemon and the
    // GUI, a scripted fake in the KATs); empty: the dashd source is refused.
    std::function<std::unique_ptr<scan::RpcApi>(const std::string& url, const std::string& auth_file, std::string& why)>
        make_rpc;
    // The node transport for GET /api/utxo/scan: a long timeout (the node may
    // take up to 120 s) and aborted on stop_requested (the operator's cancel).
    // Empty: make_api. The scan commands poll stop_requested as their cancel.
    std::function<std::unique_ptr<NodeApi>(const std::string& url, std::string& why)> make_scan_api;
};

// $XDG_DATA_HOME/c2wallet-qt/companion/queue.json when XDG_DATA_HOME is an
// absolute path, else <home of the effective uid from passwd>/.local/share/...
// (the passwd home, not $HOME, so `sudo -u c2pool` lands on c2pool's queue).
std::string default_queue_path();

const char* usage_text();

// Run one command line (argv without the program name). Returns the exit code.
int run(const std::vector<std::string>& args, Env& env);

} // namespace c2w::companion::sched::cli
