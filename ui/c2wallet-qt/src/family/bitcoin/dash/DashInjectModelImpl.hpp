// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Private state of DashInjectModel, shared by its two translation units:
// DashInjectModel.cpp (c2wallet-dash-common, btclibs closure) and
// DashInjectSign.cpp (c2wallet-dash-tx, dashscript closure). std-only — it must
// not pull either vendored header tree. Not part of the page's interface.

#include "DashInjectModel.hpp"

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace c2w::dash {

struct DashInjectModel::Impl {
    bool testnet = false;
    InjectStage stage = InjectStage::Empty;

    // 1. import
    UtxoImport imp;
    // 2. screen
    ScreenParams screen_params;
    TargetScreen screen;
    // 3. plan
    PlanParams plan_params;
    std::optional<SweepBatchPlan> sweep;
    std::optional<CollateralPlan> coll;
    std::vector<Utxo> chosen;      // the mature inputs offered to the planner
    size_t not_selected = 0;       // mature, left out by input_limit
    // 4. key — the only secret the model holds
    std::unique_ptr<FoundKey> key;
    KeySource key_source = KeySource::Mnemonic;
    std::string key_path;          // public: kept for the manifest after the key is wiped
    bool key_compressed = true;
    size_t keys_wiped = 0;
    // 5. gate + outputs
    bool reviewed = false;
    bool burn_ack = false;
    std::string typed;
    std::vector<SignedTx> signed_txs;
    std::string inject_file;
    std::string manifest;
    std::string sign_card;

    void wipe_key();
    void clear_gate();
    // Keep the stages up to and including `keep`; drop everything after it.
    void drop_after(InjectStage keep);
    void require(InjectStage at_least, const char* what) const;
    // Run the planner over the screened inputs with the given key encoding. On
    // success replaces the plan; on a refusal the previous plan is untouched.
    void run_plan(PubkeyEncoding enc);
    // After signing: cross-check every signed tx against the plan (txid, size,
    // estimate, outputs, relay fee floor), emit the hex file, build the
    // manifest and the sign card, and move to Signed. Throws DashAbort on any
    // disagreement, emitting nothing.
    void finish_signed(std::vector<SignedTx> txs);
};

} // namespace c2w::dash
