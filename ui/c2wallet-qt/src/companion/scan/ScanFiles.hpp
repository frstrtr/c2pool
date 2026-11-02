// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Scan & Plan (companion) — the files a scan writes (design §3.5).
//
//   <name>.utxos.json     c2wallet-utxo-export/1, the signer's intake #1. The
//                         bytes are exactly those tools/export_utxos.py writes
//                         (json.dump(doc, indent=1), no trailing newline): the
//                         same keys in the same order, integers only.
//   <name>.scanplan.json  c2wallet-scan-plan/1 (new), ADVISORY: bound to the
//                         export by its sha256; pre-fills the signer's controls
//                         and carries the digests the signer compares its own
//                         plan against. Deterministic (fixed key order, 2-space
//                         indent, trailing newline), no secrets, no timestamps.
//   <name>.c2wu.hex       optional: one M5-A UnsignedContainer per batch (the
//                         generic Air-Gap route), one hex per line.
//   <name>.report.txt     the human report: counts, totals, the ETA table, the
//                         planner summary, the fee advice and the exact
//                         c2wallet-qt-schedd add lines expected after signing.

#include "Classifier.hpp"
#include "Planner.hpp"
#include "ScanTypes.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace c2w::companion::scan {

inline constexpr const char* kScanPlanSchema = "c2wallet-scan-plan/1";

// The export file. Throws ScanRefusal(kNothingToExport) for an import without
// rows (the signer refuses an empty list).
std::string write_export_v1(const c2w::dash::UtxoImport& imp);

// What the node said about itself, for the fee-mode advice (#4). Unknown
// fields stay nullopt; the advice then says it could not decide.
struct NodePosture {
    std::optional<bool> armed;             // /api/tx-inject-status enabled
    std::optional<bool> utxo_full_serving; // utxo.mode == full && state == serving
    std::optional<int64_t> pool_free_bytes;
};

struct FeeAdvice {
    std::string fee_mode;                  // "inject-zero-fee" | "relay" | "" (undecided)
    std::string reason;
    NodePosture posture;
};

// inject-zero-fee when the node is armed, serves the full UTXO set and its pool
// has room for every batch; otherwise relay, naming the first unmet condition.
FeeAdvice advise_fee_mode(const NodePosture& node, const ScanPlan& plan);

// Review L2: the classification and the plan must come from one PlanParams
// (classify_params_of); throws ScanRefusal(kBadParams) naming every field that
// differs. Both writers below call it, so neither file can contradict itself.
void check_one_param_set(const Classification& cls, const ScanPlan& plan);

// The sidecar. `utxos_file` is the exact text written to <name>.utxos.json
// (its sha256 binds the two files). A stage-2 intake (tip hash
// "projected:<h>") is marked source.heights_projected, and every batch that
// spends unmined outputs batches[].heights_projected.
std::string write_scan_plan(const ScanResult& scan, const Classification& cls, const ScanPlan& plan,
                            const std::string& utxos_file, const FeeAdvice& advice);

// The report. `name` is the file stem the operator chose (<name>.hex /
// <name>.manifest.json are what the signer will write).
std::string write_report(const ScanResult& scan, const Classification& cls, const ScanPlan& plan,
                         const FeeAdvice& advice, const std::string& name);

// One UnsignedContainer hex per stage-1 batch, built through Produce from the
// same plan. The container's embedded unsigned tx must equal the batch's
// unsigned bytes (checked). `derivation_index`, when given, adds the hint
// "m/44'/5'/0'/0/<i>" (testnet: coin type 1') to every input. Empty + err on a
// refusal (a stage-2 batch, a container over 100 kB).
std::vector<std::string> emit_c2wu(const ScanPlan& plan, std::optional<uint32_t> derivation_index, std::string& err);

} // namespace c2w::companion::scan
