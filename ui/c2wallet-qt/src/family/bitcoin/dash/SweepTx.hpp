// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Zero-fee SWEEP / consolidation builder for c2pool tx injection — the C++ port
// of the reference c2wallet.py sign / sign-batch flow plus the planning half it
// left to hand-built unsigned hex. Every mature UTXO of one P2PKH funding
// address is spent to one destination (the funding address by default) with a
// fee of exactly 0, split greedily into as few txs as the node's inject caps
// allow (InjectCaps.hpp). Dash Core peers do not relay a zero-fee tx; the output
// file is for --embedded-tx-inject-hex / --pin-local-tx-hex on a c2pool node,
// whose own block carries it.
//
// Split across the two DASH closures like the collateral builder:
//   plan_sweep, emit_inject_file, serialize_unsigned_legacy_tx and
//     est_signed_size are key-free and live in c2wallet-dash-common (SweepTx.cpp);
//   sign_sweep, sign_external_unsigned and verify_signed_funding_tx sign or
//     verify through the M3-A signer and live in c2wallet-dash-tx (SweepSign.cpp).
// This header is std-only, so either side (and a Qt page) can include it.
//
// Every refusal throws DashAbort and emits nothing. A signing call is
// all-or-nothing: if any tx fails, no tx is returned.

#include "CollateralTx.hpp"
#include "InjectCaps.hpp"
#include "KeyScan.hpp"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace c2w::dash {

struct SweepRequest {
    std::string funding_address;
    std::string destination_address;    // empty => the funding address
    std::vector<Utxo> utxos;            // every one must carry its scriptPubKey
    int64_t min_confirmations = kDefaultMinConf;
    int64_t dust_floor = 0;             // UTXOs below this many duffs are left out
    bool testnet = false;
    bool preserve_input_order = false;  // default sorts by (display txid, vout)
    size_t max_inputs_per_tx = caps::kMaxInjectInputs;  // may only tighten the cap
    size_t max_tx_bytes = caps::kMaxInjectTxBytes;      // may only tighten the cap
    PubkeyEncoding key_encoding = PubkeyEncoding::Unknown;
};

struct SweepTxPlan {
    std::vector<Utxo> inputs;
    int64_t value_out = 0;               // == sum of inputs: the fee is 0 by construction
    std::vector<uint8_t> dest_spk;
    std::vector<uint8_t> unsigned_tx;    // the exact bytes sign_sweep signs
    size_t est_signed_bytes = 0;
};

struct SweepBatchPlan {
    std::vector<SweepTxPlan> txs;
    int64_t total_in = 0;
    size_t skipped_immature = 0;
    size_t skipped_dust = 0;
    std::string funding_address;
    std::string destination_address;
    bool testnet = false;
    std::string summary;                 // dry-run summary (public data only)
};

// Screen the UTXOs (strict: scriptPubKey required and must pay the funding
// address, no duplicate outpoint), drop dust and immature ones (listed in the
// summary), order them, and split greedily so every tx stays within
// min(max_inputs_per_tx, kMaxInjectInputs) inputs and min(max_tx_bytes,
// kMaxInjectTxBytes) estimated signed bytes. More txs than one node's inject
// pool holds at once is a WARNING in the summary, not a refusal.
SweepBatchPlan plan_sweep(const SweepRequest& req);

// Sign every planned tx with ONE key, self-verify every input (finalize), and
// re-check the signed size against the node cap. Refuses unless confirm_spend,
// if the key is not the funding key, if a planned tx is not zero-fee or its
// bytes are not the planned ones.
std::vector<SignedTx> sign_sweep(const SweepBatchPlan& plan, const FoundKey& key,
                                 bool confirm_spend);

// python c2wallet.py sign / sign-batch parity: sign operator-supplied unsigned
// legacy txs whose every input pays `funding_address`. ALL blobs are parsed and
// validated before the key is touched: refused for bad hex, a segwit
// serialization, trailing bytes, a special-tx type or a version other than 2, a
// scriptSig already present, an input sequence with bit 31 clear (BIP68 opt-in,
// which the node's inject gate refuses), no outputs, or over the input/output
// caps. Legacy sighash commits no input amounts, so none are needed.
std::vector<SignedTx> sign_external_unsigned(const std::vector<std::string>& raw_hexes,
                                             const std::string& funding_address,
                                             bool testnet,
                                             const FoundKey& key,
                                             bool confirm_spend);

// Independent re-verification of a signed tx whose every input spends the
// funding P2PKH: re-parse, re-serialize byte-exact, and run every scriptSig
// through the vendored interpreter. Throws DashAbort on the first failure.
void verify_signed_funding_tx(const std::string& signed_hex,
                              const std::string& funding_address,
                              bool testnet);

// The c2pool loader file (== artifact::SignedContainer::emit): one lowercase raw
// tx hex per line, each '\n'-terminated, no header. Refuses an empty list or a
// line that is not lowercase even-length hex.
std::string emit_inject_file(const std::vector<SignedTx>& txs);

// Serialize the unsigned (blank scriptSig) legacy tx every DASH builder signs:
// version 2, every input at sequence kSequenceFinal, locktime 0.
std::vector<uint8_t> serialize_unsigned_legacy_tx(
    const std::vector<Utxo>& inputs,
    const std::vector<std::pair<int64_t, std::vector<uint8_t>>>& outputs);

// Worst-case signed size of an unsigned P2PKH-input tx (see InjectCaps.hpp).
size_t est_signed_size(size_t unsigned_bytes, size_t n_inputs, PubkeyEncoding encoding);

} // namespace c2w::dash
