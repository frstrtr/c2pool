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
//
// Two fee regimes (FeeMode). Relay is the classic tool: a fee from fee_rate and
// largest-first coin selection. InjectOnlyZeroFee is the port of
// build_collateral_unsigned.py: every mature UTXO goes in (sweep_all), change
// takes everything above the 1 DASH burn, and the fee is exactly 0, so Dash Core
// peers will not relay it and only a c2pool node's own block (inject / pin lane)
// carries it. A zero fee is refused unless that mode is chosen explicitly, and
// an inject plan is held to the node's caps (InjectCaps.hpp): it is refused,
// never split, when it would not fit one inject tx.

#include "InjectCaps.hpp"
#include "KeyScan.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace c2w::dash {

// duffs per DASH; the governance fee is 1 DASH (governance/object.h:30).
inline constexpr int64_t kCoin = 100000000;
inline constexpr int64_t kGovernanceProposalFee = 1 * kCoin;
inline constexpr int64_t kMaxMoney = 21000000 * kCoin; // Dash Core amount.h MAX_MONEY
inline constexpr int64_t kDustDuffs = 5460;
inline constexpr int64_t kDefaultFeeRate = 1000; // duffs/kB (Dash min relay)
inline constexpr int64_t kDefaultMinConf = 101;  // funding UTXOs are often coinbase
inline constexpr int64_t kCoinbaseMaturity = 100; // consensus COINBASE_MATURITY

// Relay: a relayable tx paying fee_rate. InjectOnlyZeroFee: fee exactly 0, for
// the c2pool inject / pin lane only (Dash Core peers will not relay it).
enum class FeeMode : uint8_t { Relay, InjectOnlyZeroFee };

struct Utxo {
    std::string txid;                // display-order hex
    uint32_t vout = 0;
    int64_t satoshis = 0;
    int64_t confirmations = 0;
    std::string script_pubkey_hex;   // validated against the funding script when present;
                                     // REQUIRED in inject mode, with sweep_all, and for SweepTx
    // nullopt => treated as coinbase (min_confirmations applies); false => one
    // confirmation is enough; true => min_confirmations, never below kCoinbaseMaturity.
    std::optional<bool> coinbase = std::nullopt;
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

    FeeMode fee_mode = FeeMode::Relay;
    std::vector<Utxo> skipped_immature;  // below the maturity floor; listed with "matures in N"
    size_t skipped_dust = 0;             // below dust_floor; listed in the summary
    size_t est_signed_bytes = 0;         // worst case for the request's key_encoding
    std::vector<uint8_t> unsigned_tx;    // the exact bytes sign_collateral will sign (blank scriptSigs)
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

    FeeMode fee_mode = FeeMode::Relay;
    // Direct mode: the 64-hex display hash from `gobject prepare` / `gobject
    // check`. parent/revision/time_/data_hex are then optional; when time_ or
    // data_hex is also given, the hash derived from them must equal this one.
    std::string gov_hash_display;
    bool sweep_all = false;             // every mature UTXO in; REQUIRED for InjectOnlyZeroFee
    bool preserve_input_order = false;  // sweep_all: keep request order; default sorts by
                                        // (display txid, vout)
    int64_t dust_floor = 0;             // UTXOs below this many duffs are left out (counted, listed)
    PubkeyEncoding key_encoding = PubkeyEncoding::Unknown; // signed-size estimate only
};

// Compute the collateral hash, select coins, and produce the dry-run summary.
// Signs nothing and needs no key. Throws DashAbort on a wrong network / bad
// address, an --expected-hash mismatch, a foreign UTXO scriptPubKey, or
// insufficient mature funds. Also, for the fee modes: a zero fee_rate in Relay
// mode; InjectOnlyZeroFee with a non-zero fee_rate or without sweep_all; a
// missing scriptPubKey or a duplicate outpoint in inject mode or with
// sweep_all; a direct hash that is not 64 hex or disagrees with the hash
// derived from time_/data_hex; every UTXO immature or dust; and, in inject mode
// or with sweep_all, a tx over the node caps (est. signed bytes or inputs) —
// refused, never split.
CollateralPlan plan_collateral(const CollateralRequest& req);

// Build + sign the planned tx with `key`, self-verify every input through the
// vendored interpreter, refuse on oversize, and return the signed hex. Throws
// DashAbort unless `confirm_spend` is true (the typed-SPEND gate), if the key's
// address is not the funding address or its hash160 is not the funding script's,
// if the bytes about to be signed differ from plan.unsigned_tx, if a zero-fee
// plan is not marked InjectOnlyZeroFee, or if any input fails self-verify. An
// inject plan's signed size is re-checked against the node cap after signing.
SignedTx sign_collateral(const CollateralPlan& plan, const FoundKey& key, bool confirm_spend);

} // namespace c2w::dash
