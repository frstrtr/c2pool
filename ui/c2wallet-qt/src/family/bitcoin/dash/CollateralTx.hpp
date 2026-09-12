// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// DASH governance-proposal collateral transaction builder (design §4.1.1).
// Port of frstrtr/dash-proposal-collateral dash_collateral_tx.py: a FIXED
// OP_RETURN-burn template, not a generic spend —
//   output 0 = 1.00000000 DASH -> OP_RETURN <collateral_hash>  (proof-of-burn)
//   output 1 = change -> the funding address
// coins selected largest-first, coinbase outputs below the maturity floor
// skipped, foreign scriptPubKeys rejected.
//
// The signing itself REUSES the M3-A Signer (legacy SIGHASH_ALL / RFC6979 /
// low-S / DER + per-input self-verify through the vendored interpreter + the
// oversize refusal) — this module contributes only the DASH-specific assembly.
// Its .cpp is the one TU that pulls the vendored dashscript closure; it stays
// off the btclibs closure and reaches the address/key/hash helpers through
// their std-only headers.
//
// The security posture of the reference tool is preserved in library form:
// plan_collateral() is the always-first dry-run (summary, no key, no signing),
// and sign_collateral() will not sign unless `confirm_spend` is explicitly true
// — the typed-SPEND gate expressed as a flag, never an auto-sign.

#include "KeyScan.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace c2w::dash {

// duffs per DASH; the governance fee is 1 DASH (governance/object.h:30).
inline constexpr int64_t kCoin = 100000000;
inline constexpr int64_t kGovernanceProposalFee = 1 * kCoin;
inline constexpr int64_t kDustDuffs = 5460;
inline constexpr int64_t kDefaultFeeRate = 1000; // duffs/kB (Dash min relay)
inline constexpr int64_t kDefaultMinConf = 101;  // funding UTXOs are often coinbase

struct Utxo {
    std::string txid;                // display-order hex
    uint32_t vout = 0;
    int64_t satoshis = 0;
    int64_t confirmations = 0;
    std::string script_pubkey_hex;   // optional; validated against the funding script when present
};

struct CollateralPlan {
    std::array<uint8_t, 32> gov_hash_internal{};
    std::string gov_hash_display;
    std::vector<uint8_t> op_return_script; // 6a20 || 32 bytes
    std::vector<Utxo> selected;
    int64_t total_in = 0;
    int64_t fee = 0;
    int64_t change = 0;
    std::string funding_address;
    std::string change_address;
    bool testnet = false;
    std::string summary; // human-readable dry-run summary (public data only)
};

struct SignedTx {
    std::string hex;   // raw signed transaction hex — the only secret-free artifact
    std::string txid;  // display-order txid
    size_t size = 0;
};

// The gobject params + funding/UTXO inputs for one collateral tx.
struct CollateralRequest {
    std::string funding_address;
    std::string change_address;      // empty => the funding address
    std::string parent_hash_hex = std::string(64, '0');
    int32_t revision = 1;
    int64_t time_ = 0;
    std::string data_hex;
    std::string expected_hash_display; // optional cross-check; empty => skip
    std::vector<Utxo> utxos;
    int64_t fee_rate = kDefaultFeeRate;
    int64_t min_confirmations = kDefaultMinConf;
    bool testnet = false;
};

// Compute the collateral hash, select coins, and produce the dry-run summary.
// Signs nothing and needs no key. Throws DashAbort on a wrong network / bad
// address, an --expected-hash mismatch, a foreign UTXO scriptPubKey, or
// insufficient mature funds.
CollateralPlan plan_collateral(const CollateralRequest& req);

// Build + sign the planned tx with `key`, self-verify every input through the
// vendored interpreter, refuse on oversize, and return the signed hex. Throws
// DashAbort unless `confirm_spend` is true (the typed-SPEND gate), if the key's
// address is not the funding address, or if any input fails self-verify.
SignedTx sign_collateral(const CollateralPlan& plan, const FoundKey& key, bool confirm_spend);

} // namespace c2w::dash
