// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// DashInjectModel — the std-only, Qt-free state machine behind PageDashInject
// (c2wallet-qt slice 2, design §4). The page is a thin binding; everything that
// touches money lives here so c2wallet-dash-test can KAT it without Qt.
//
//   1 import   UTXO JSON (export v1 / dashd getaddressutxos / insight) -> Imported
//   2 screen   maturity at a target landing height                    -> Screened
//   3 plan     consolidate (zero-fee or relay) or governance collateral -> Planned
//   4 key      mnemonic / WIF / BIP38 / descriptor / JSON keystore,
//              bound on BOTH the address and hash160(pub)            -> KeyBound
//   5 sign     reviewed + literal SPEND (+ burn box for collateral);
//              sign, re-verify every tx independently, wipe the key,
//              emit <name>.hex + <name>.manifest.json                 -> Signed
//
// No stage can be skipped: each call throws DashAbort unless the previous stage
// is done. Any earlier stage re-run drops everything after it, the key
// included; a refused call leaves the model at the stage before it. The key
// lives only in a FoundKey (zeroizing SecureBytes) inside the model and is
// destroyed on sign (whether or not signing succeeds), on any re-import,
// re-screen or re-plan, on reset() and on destruction. Nothing the model
// returns (cards, summary, manifest, hex file, error messages) carries a secret.
//
// Split across the two DASH closures like the builders it drives: everything
// but sign() is in c2wallet-dash-common (DashInjectModel.cpp); sign() calls the
// signers and lives in c2wallet-dash-tx (DashInjectSign.cpp). This header is
// std-only, so the Qt page includes it without either vendored header tree.

#include "CollateralTx.hpp"
#include "InjectCaps.hpp"
#include "KeyScan.hpp"
#include "SweepTx.hpp"
#include "UtxoIntake.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace c2w::dash {

enum class InjectStage : uint8_t { Empty, Imported, Screened, Planned, KeyBound, Signed };
const char* inject_stage_name(InjectStage s);

enum class OutputMode : uint8_t { Consolidate, Collateral };

enum class KeySource : uint8_t { Mnemonic, Wif, Bip38, Descriptor, JsonKeystore };
const char* key_source_name(KeySource s);

inline constexpr int64_t kDefaultTargetOffset = 2;     // target landing height = tip + 2
inline constexpr int64_t kDefaultPageDustFloor = 1000; // duffs
inline constexpr const char* kSpendWord = "SPEND";     // the literal confirmation

struct ScreenParams {
    int64_t target_height = 0;                    // 0 => tip + kDefaultTargetOffset
    int64_t min_confirmations = kDefaultMinConf;  // coinbase/unknown never below 100
    int64_t dust_floor = kDefaultPageDustFloor;
};

struct PlanParams {
    OutputMode mode = OutputMode::Consolidate;
    FeeMode fee_mode = FeeMode::InjectOnlyZeroFee;
    int64_t fee_rate_per_byte = 0;   // Relay only: [kMinRelayFeePerByte, kMaxRelayFeePerByte]
    std::string destination;         // Consolidate; empty => the funding address
    size_t max_inputs_per_tx = 0;    // Consolidate split knob; 0 => the node cap
    size_t input_limit = 0;          // 0 => every mature input; N => the N oldest (lowest height)
    std::string gov_hash_display;    // Collateral: the 64-hex hash `gobject check` prints
    std::string change_address;      // Collateral; empty => the funding address
};

// The secret inputs of stage 4. The caller owns (and wipes) these strings; the
// model copies a secret only into zeroizing storage or short-lived locals it
// wipes.
struct KeyInput {
    KeySource source = KeySource::Mnemonic;
    std::string secret;      // mnemonic | WIF | "6P..." | descriptor | keystore JSON
    std::string passphrase;  // BIP39 / BIP38 passphrase; keystore: used for a mnemonic
                             // that carries none of its own
    KeyScanRange range;      // mnemonic and keystore scans; descriptor: indices 0..indices-1
};

// Load a key in any supported format and bind it to `funding_address` (see
// bind_found_key). Throws DashAbort — whose message never quotes the secret —
// when the input does not decode or no key in it controls the address.
FoundKey load_funding_key(const KeyInput& in, const std::string& funding_address, bool testnet);

// The binding every key passes before it may sign: key.address equals the
// funding address, hash160(key.pub) equals the address's decoded hash160, and
// an independent re-encode of that hash160 reproduces the address.
void bind_found_key(const FoundKey& key, const std::string& funding_address, bool testnet);

class DashInjectModel {
public:
    explicit DashInjectModel(bool testnet = false);
    ~DashInjectModel();
    DashInjectModel(const DashInjectModel&) = delete;
    DashInjectModel& operator=(const DashInjectModel&) = delete;

    bool testnet() const;
    InjectStage stage() const;

    // ── 1. import (any stage) ──────────────────────────────────────────────
    // `tip_height` is required for a bare getaddressutxos array, optional for
    // insight, and must be 0 for export v1 (which carries its own). A non-empty
    // `expected_address` must equal the address the rows pay.
    void import_utxos(const std::string& json, int64_t tip_height = 0,
                      const std::string& expected_address = {});
    const UtxoImport& utxo_import() const;
    std::string import_card() const;

    // ── 2. maturity screen at a target landing height (>= Imported) ────────
    void rescreen(const ScreenParams& params);
    const TargetScreen& target_screen() const;
    std::string screen_card() const;

    // ── 3. plan (>= Screened) ──────────────────────────────────────────────
    void plan(const PlanParams& params);
    const PlanParams& plan_params() const;
    std::string plan_summary() const;
    size_t planned_tx_count() const;
    int64_t planned_fee() const;
    bool destination_is_external() const;
    int64_t plan_safe_from_height() const;
    const SweepBatchPlan* sweep_plan() const;        // consolidate only, else nullptr
    const CollateralPlan* collateral_plan() const;   // collateral only, else nullptr

    // ── 4. key (>= Planned) ────────────────────────────────────────────────
    // Replaces any key held; re-plans with the key's pubkey encoding so the
    // signed-size estimate (and a relay fee) is exact for it.
    void load_key(const KeyInput& in);
    bool has_key() const;
    std::string key_card() const;
    size_t keys_wiped() const;   // sentinel: how many held keys this model destroyed

    // ── 5. review gate, sign, export (KeyBound) ────────────────────────────
    void set_gate(bool reviewed, bool burn_acknowledged, const std::string& typed_word);
    bool armed() const;          // reviewed && typed == "SPEND" && (burn box for collateral)
    void sign();                 // c2wallet-dash-tx (DashInjectSign.cpp)
    const std::vector<SignedTx>& signed_txs() const;
    const std::string& inject_file() const;    // <name>.hex: one raw tx per line
    const std::string& manifest_json() const;  // <name>.manifest.json
    std::string sign_card() const;

    void reset();

    struct Impl; // DashInjectModelImpl.hpp

private:
    std::unique_ptr<Impl> p_;
};

} // namespace c2w::dash
