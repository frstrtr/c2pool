// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Scan & Plan (companion) — the planner wrapper (design §3.4).
//
// The companion plans with the SIGNER's own code (plan_sweep and the target
// re-screen from the key-free c2wallet-dash-plan library) and the signer's own
// path through it (DashInjectModel's plan step): re-screen the export at the
// target height, keep the N oldest mature inputs when input_limit is set, then
// plan_sweep over mature + immature + dust with the same defaults. From the
// same <name>.utxos.json and the same parameters the offline signer therefore
// derives byte-identical unsigned txs; the sidecar carries their digests so the
// signer can compare its own plan (it never trusts them).
//
// Shapes:
//   consolidate  one or more independent batches (disjoint inputs, no
//                dependency between them).
//   collateral   the governance collateral (1 DASH OP_RETURN burn + change to
//                the change address), inject mode (zero fee) only: every
//                mature input in one tx, sorted by outpoint, the byte layout of
//                plan_collateral's sweep_all branch. When that one tx would
//                exceed the node's inject caps (1000 inputs / 100000 B) the
//                plan has TWO STAGES: stage 1 consolidates (to the funding
//                address, possibly several batches), stage 2 is the collateral
//                spending the stage-1 outputs (depends_on every stage-1 batch).
//                Stage 2 cannot be built before the stage-1 txids exist: after
//                stage 1 is signed, stage2_export() writes its intake.
//
// Plan identity: plan_id = sha256 over a canonical text of the network, the
// address, the tip, every parameter and the sorted planned outpoints; the same
// scan at the same tip with the same parameters reproduces every digest.

#include "Classifier.hpp"
#include "ScanTypes.hpp"

#include "../../family/bitcoin/dash/InjectCaps.hpp"
#include "../../family/bitcoin/dash/SweepPlan.hpp"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace c2w::companion::scan {

enum class PlanMode : uint8_t { Consolidate, Collateral };
const char* plan_mode_name(PlanMode m);              // "consolidate" | "collateral"
const char* fee_mode_name(c2w::dash::FeeMode m);     // "inject-zero-fee" | "relay"
const char* key_encoding_name(c2w::dash::PubkeyEncoding e); // "unknown" | "compressed" | "uncompressed"

struct PlanParams {
    PlanMode mode = PlanMode::Consolidate;
    c2w::dash::FeeMode fee_mode = c2w::dash::FeeMode::InjectOnlyZeroFee;
    int64_t fee_rate_per_byte = 0;        // relay: [1, 100]
    std::string destination;              // consolidate; empty => the funding address
    int64_t target_height = 0;            // 0 => tip + 2
    int64_t min_confirmations = c2w::dash::kDefaultMinConf;
    int64_t dust_floor = 1000;
    size_t max_inputs_per_tx = 0;         // consolidate; 0 => the node cap (600 recommended for margin)
    size_t input_limit = 0;               // 0 => every mature input; N => the N oldest
    c2w::dash::PubkeyEncoding key_encoding = c2w::dash::PubkeyEncoding::Unknown;
    std::string gov_hash;                 // collateral: the 64-hex display hash `gobject check` prints
    std::string change_address;           // collateral; empty => the funding address
};

struct PlannedBatch {
    int index = 0;                        // 1-based
    std::vector<int> depends_on;          // batch indices whose outputs this one spends
    std::vector<c2w::dash::Utxo> inputs;  // empty for a stage-2 batch (txids unknown yet)
    size_t vin = 0;
    int64_t value_out = 0;                // sum of the outputs
    int64_t fee = 0;
    size_t est_signed_bytes = 0;
    std::vector<uint8_t> unsigned_tx;     // empty for a stage-2 batch
    std::vector<std::pair<int64_t, std::vector<uint8_t>>> outputs;
    std::string unsigned_sha256d;         // display order; empty for a stage-2 batch
    std::string inputs_sha256;            // over the sorted "txid:vout\n" lines; empty for stage 2
};

struct ScanPlan {
    std::string address;
    bool testnet = false;
    int64_t tip_height = 0;
    std::string tip_hash;
    PlanParams params;                    // resolved: target_height and max_inputs_per_tx filled in
    std::string destination;              // resolved destination (consolidate) / change address (collateral)
    std::string plan_id;
    std::vector<PlannedBatch> batches;    // stage 1 first, then a stage-2 batch when two_stage
    bool two_stage = false;
    int64_t total_in = 0;                 // over the planned (stage-1) inputs
    int64_t total_fee = 0;
    int64_t safe_from_height = 0;         // over the planned inputs; 0 = unknown
    int64_t youngest_input_height = 0;
    size_t not_selected = 0;              // mature, left out by input_limit
    std::string summary;                  // the planner's dry-run summary
    std::vector<std::string> warnings;
};

// sha256 over the sorted "txid:vout\n" lines (lowercase hex).
std::string inputs_digest(const std::vector<c2w::dash::Utxo>& inputs);

// Plan `exportable` (Classification::exportable, i.e. exactly what the export
// file carries). Throws ScanRefusal(kPlanRefused) with the planner's own text
// on any refusal (nothing mature, a bad destination, a relay rate outside
// [1, 100], insufficient funds for a collateral, ...), kUnsupported for a relay
// collateral (the signer plans that one itself).
ScanPlan make_plan(const c2w::dash::UtxoImport& exportable, const PlanParams& params);

// The stage-2 intake of a two-stage collateral, written once stage 1 is
// signed: one row per stage-1 batch (output 0 of txid i, its value_out, the
// funding P2PKH, coinbase false). Stage 1 has not landed when this is written,
// so the rows are dated at `landing_height`, the height stage 1 is expected in
// (tip_height = height = landing_height, confirmations 1, no tip hash): the
// signer's maturity rule for a non-coinbase input is then met one block later,
// and the scheduler holds the stage-2 tx behind --after-parent anyway.
// Returns the c2wallet-utxo-export/1 text. Throws ScanRefusal on a plan that
// is not two-stage or a txid list that does not match stage 1.
std::string stage2_export(const ScanPlan& plan, const std::vector<std::string>& stage1_txids,
                          int64_t landing_height);

} // namespace c2w::companion::scan
