// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Scan & Plan (companion) — the preflight of a signed pair right before it is
// queued (design §4.2, after signing / before add). Key-free; it reads the
// offline signer's <name>.hex + <name>.manifest.json and asks the live
// sources, it never signs, arms or submits.
//
//   (a) structure: every line a finished signed tx within the node caps whose
//       txid is the manifest's (preflight_raw_tx), the hex file bound to the
//       manifest by sha256, each tx's inputs the manifest's inputs;
//   (b) reconciliation: with the export the plan was made from, every manifest
//       input is an export row with equal value, script, height and coinbase
//       flag; with the scan-plan sidecar, the sidecar is bound to that export
//       and each signed tx, its scriptSigs blanked, is the planned unsigned tx
//       (unsigned sha256d = the sidecar's);
//   (c) still unspent: every input is still unspent with its value and script
//       at the current tip — gettxout on dashd, the /api/utxo/scan rows on the
//       node, both when both are configured;
//   (d) dry run: POST /api/tx-inject/validate (node slice N3) per tx when the
//       node offers it — 404 / 503 / a reply without "dry_run" is a NOTICE
//       ("the node has no dry-run route"), the checks above still stand.
//
// Refusals that --force "<reason>" can turn into warnings (the reason is
// journaled with the queued items): a dry-run cause, a plan-digest mismatch,
// and an UNKNOWN — a chosen source that could not answer (the still-unspent
// check failed to run: transport, auth, a bad reply; the dry run got no
// answer, an HTTP 403, or a reply that is not a dry run). Never forceable: a
// structural failure, a reconciliation failure, a spent or changed input, a
// dry run that echoes another txid. A 404 / 503 dry-run route (an older node,
// or one without the dry run wired) is a notice. The PASS line names the
// checks that ran.
//
// A stage-2 manifest (maturity.screen_tip_hash "projected:<h>") spends outputs
// of txs that may not be mined yet: an input missing from the sources is then
// a notice (the scheduler holds the tx behind --after-parent), and the dry run
// is skipped (the node cannot resolve an unmined parent's output).

#include "ScanTypes.hpp"
#include "SourceDashd.hpp"

#include "../sched/NodeApi.hpp"

#include "../../secure/SecureString.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace c2w::companion::scan {

inline constexpr const char* kValidateRoute = "/api/tx-inject/validate";

// One raw tx's inputs and outputs, and the sha256d (display order) of the same
// tx with every scriptSig emptied — for a legacy tx that is the unsigned tx
// the signer signed. Refuses a segwit or truncated tx and trailing bytes.
struct TxIO {
    std::vector<Outpoint> inputs;
    std::vector<std::pair<int64_t, std::string>> outputs; // value, scriptPubKey hex
    std::string unsigned_sha256d;
};
bool parse_tx_io(const std::string& raw_hex, TxIO& out, std::string& why);

struct PreflightInput {
    std::string hex_text;                      // <name>.hex
    std::string manifest_text;                 // <name>.manifest.json
    std::optional<std::string> utxos_text;     // <name>.utxos.json the plan was made from
    std::optional<std::string> scanplan_text;  // <name>.scanplan.json
};

struct PreflightOptions {
    bool testnet = false;
    bool validate = true;          // (d) when a node is given
    std::string force_reason;      // non-empty: forceable refusals become warnings
    ScanOptions scan;              // cancel, retries (c2pool scan)
};

struct PreflightReport {
    bool ok = false;
    bool forced = false;
    std::vector<std::string> lines;     // what was checked, in order
    std::vector<std::string> notices;   // checks that could not run (no route, projected heights)
    std::vector<std::string> warnings;  // forced refusals, transient node states
    std::vector<std::string> refusals;
    std::vector<std::string> ran;       // "a", "b", "c", "d": the checks that ran
    std::string text() const;           // all of the above, one per line
};

// `dashd` / `c2pool` / `node` may be null (that source or the dry run is not
// configured). `token` is the node's control token for the dry run (null:
// skipped with a notice).
PreflightReport run_preflight(const PreflightInput& in, const PreflightOptions& opt, SourceDashd* dashd,
                              UtxoSource* c2pool, sched::NodeApi* node, const c2w::secure::SecureString* token);

} // namespace c2w::companion::scan
