// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Scan & Plan (companion, slice S-C) — the operator commands of
// c2wallet-qt-schedd: scan, plan, preflight, watch, and the --preflight option
// of add. Qt-free (the transports come from sched::cli::Env), key-free, and
// they never sign, arm or submit: scan / plan write files for the offline
// signer, preflight checks a signed pair, watch raises a maturity alert, and
// add (the scheduler's own command) queues a pair the operator brings back.
//
//   c2wallet-qt-schedd [global options] scan --address ADDR [--address ADDR]...
//       [--source dashd|c2pool|both] [--dashd-url URL --dashd-auth-file PATH]
//       [--allow-single-source] [--out NAME] [--overwrite] [--emit-c2wu
//       [--derivation-index I]] [--testnet] [PLAN OPTIONS]
//   ... plan --utxos FILE [--out NAME] [--overwrite] [--emit-c2wu ...] [PLAN OPTIONS]
//   ... plan --stage2 --utxos S1.utxos.json --scanplan S1.scanplan.json
//       --stage1-hex S1.hex [--landing-height H] [--out NAME] [--overwrite]
//   ... preflight --hex FILE [--manifest FILE] [--utxos FILE] [--scanplan FILE]
//       [--source dashd|c2pool|both|none] [--dashd-url URL --dashd-auth-file PATH]
//       [--no-validate] [--force "<reason>"]
//   ... watch --address ADDR... [SOURCE OPTIONS] [--min-mature N] [--min-value DUFFS]
//       [--min-conf N] [--dust-floor N] [--state FILE] [--once] [--interval-blocks N]
//   ... add ... --preflight [the preflight options above]
//
// PLAN OPTIONS: --mode consolidate|collateral, --fee-mode inject|relay,
// --fee-rate N (relay, 1..100 duffs/B), --destination ADDR
// --destination-confirm ADDR (typed twice), --target-height H, --min-conf N,
// --dust-floor N, --max-inputs N, --input-limit N,
// --key-encoding unknown|compressed|uncompressed, --gov-hash HEX,
// --change-address ADDR.
//
// The dashd credentials are read from the 0600 file at use; any option that
// would carry them by value (--dashd-auth, --dashd-password, --rpcpassword,
// --rpcauth, --rpcuser) is a usage error. --dashd-url and --node-url are
// loopback http only (a remote daemon is reached with ssh -L).

#include "../sched/Config.hpp"
#include "../sched/SchedCli.hpp"

#include <optional>
#include <string>
#include <vector>

namespace c2w::companion::scan::cli {

bool is_scan_command(const std::string& cmd); // scan | plan | preflight | watch

// One scan command line (`v[0]` is the command). Exit codes as sched::cli.
int run(const std::vector<std::string>& v, sched::cli::Env& env, const sched::CliOverrides& g,
        const std::string& queue_path);

const char* usage_text();

// add --preflight: the preflight options of an add command line, split from
// the add options proper.
struct AddPreflight {
    bool requested = false;
    std::vector<std::string> args; // "preflight" syntax, without --hex / --manifest
};
bool split_add_preflight(const std::vector<std::string>& add_args, std::vector<std::string>& rest,
                         AddPreflight& pf, std::string& why);

// Run it on the pair add is about to queue. Returns sched::cli::kExitOk on a
// pass (forced_reason set when --force turned a refusal into a warning),
// kExitAttention on a refusal, kExitUsage on a usage error. The report goes to
// env.out.
int preflight_for_add(const AddPreflight& pf, const std::string& hex_text, const std::optional<std::string>& manifest_text,
                      sched::cli::Env& env, const sched::CliOverrides& g, const std::string& queue_path,
                      std::string& forced_reason, std::string& summary);

} // namespace c2w::companion::scan::cli
