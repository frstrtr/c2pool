// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// c2wallet-qt COMPANION (ONLINE, KEY-FREE) — Family-A funding-data intake
// (design docs/design/c2wallet-qt.md §5.2 "companion" + §5.4 Family-A unsigned
// artifact).
//
// This is the ONLINE side of the two-machine model, the opposite of the
// network-incapable signer: it MARSHALS PUBLIC funding data (UTXOs/prevouts +
// scriptPubKeys + amounts + target outputs + coin/network) into the M5-A
// UnsignedContainer to hand across the air gap. It NEVER holds or touches a
// private key — no CKey, no signing, no secp256k1. The unsigned tx it builds is
// inert bytes until the offline signer (a SEPARATE, key-bearing binary) signs.

#include "TransferContainer.hpp" // c2w::artifact::UnsignedContainer / UnsignedInput / SighashAlgebra
#include "Digest.hpp"            // c2w::artifact::Bytes / Hash32 / from_hex / to_hex

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace c2w::companion {

using c2w::artifact::Bytes;
using c2w::artifact::Hash32;
using c2w::artifact::SighashAlgebra;

// One funding UTXO the online side knows about (all PUBLIC data). The offline
// signer needs the scriptPubKey + amount to pick and commit the sighash; the
// derivation hint tells it which key to derive. NO secret is present.
struct FundingInput {
    // Stored in INTERNAL (tx-serialization) byte order to match
    // UnsignedInput.prevout_txid. from_json() accepts the DISPLAY (block-
    // explorer, byte-reversed) txid hex and reverses it on ingest.
    Hash32      prevout_txid{};
    uint32_t    prevout_index = 0;
    Bytes       script_pubkey;
    int64_t     amount = 0; // satoshis
    std::string derivation_hint;
    uint32_t    sequence = 0xffffffffu;
};

// A target output (script-defined; the online side already encoded the address
// into a scriptPubKey via the M2-A construct core).
struct TargetOutput {
    int64_t value = 0; // satoshis
    Bytes   script_pubkey;
};

// The complete online-side funding description for one unsigned tx.
struct FundingData {
    std::string    coin;                 // "btc","dash","ltc",...
    uint32_t       network_version = 0;  // network version-byte selector
    SighashAlgebra algebra = SighashAlgebra::Legacy;
    int32_t        tx_version = 2;
    uint32_t       locktime = 0;
    std::string    preflight_verdict;    // optional c2pool pre-flight verdict
    std::vector<FundingInput>  inputs;
    std::vector<TargetOutput>  outputs;

    // Parse a funding JSON document (the JSON/CLI intake path). Schema:
    //   {
    //     "coin":"btc", "network_version":0, "algebra":"legacy|bip143|bip341",
    //     "tx_version":2, "locktime":0, "preflight_verdict":"ok",
    //     "inputs":[ {"txid":"<display hex>","vout":0,
    //                 "script_pubkey":"<hex>","amount":100000,
    //                 "derivation":"m/84'/0'/0'/0/0","sequence":4294967295 } ],
    //     "outputs":[ {"amount":90000,"script_pubkey":"<hex>"} ]
    //   }
    // "txid" is DISPLAY (byte-reversed) hex and is reversed to internal order.
    // Returns nullopt + err on malformed input.
    static std::optional<FundingData> from_json(const std::string& s, std::string& err);
};

// Serialize the UNSIGNED legacy tx bytes (empty scriptSigs), classic type=0,
// standard Bitcoin/Dash serialization:
//   int32 version(LE) | varint(vin) | per-input{ txid[32 internal] |
//   vout u32(LE) | varint(0) empty-scriptSig | sequence u32(LE) } |
//   varint(vout) | per-output{ value i64(LE) | varint(scriptlen) | script } |
//   uint32 locktime(LE)
// PURE marshalling of public data — NO keys. The offline signer parses these
// bytes (CMutableTransaction >> op) and fills in the scriptSigs/witnesses.
Bytes serialize_unsigned_tx(const FundingData& fd);

} // namespace c2w::companion
