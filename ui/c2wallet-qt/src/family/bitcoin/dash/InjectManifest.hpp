// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// The `<name>.manifest.json` that travels across the air gap next to the signed
// `<name>.hex` (slice-2 design §4.7). PUBLIC data only: txids, sizes, inputs,
// the maturity screen, the fee, the node requirements and the hex file's
// digests. It never carries a secret, and it carries no timestamp: the
// air-gapped machine's clock is not trusted, so the online side records the
// receipt time. The output is deterministic (fixed key order, no floats).
//
// std-only header; the .cpp sits on the btclibs closure (CSHA256 for the
// digests), in c2wallet-dash-common.

#include "CollateralTx.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace c2w::dash {

inline constexpr const char* kInjectManifestSchema = "c2wallet-inject-manifest/1";

struct ManifestOutput {
    int64_t value = 0;
    std::string script_hex;
    std::string kind;        // "p2pkh" | "op_return"
    std::string address;     // p2pkh only
};

struct ManifestTx {
    std::string txid;        // display order
    size_t size = 0;         // actual signed bytes
    size_t est_signed_bytes = 0;
    int64_t value_out = 0;   // sum of the outputs
    int64_t fee = 0;
    std::vector<ManifestOutput> outputs;
    std::vector<Utxo> inputs;
};

struct ManifestData {
    bool testnet = false;
    std::string mode;               // "consolidate" | "collateral"
    FeeMode fee_mode = FeeMode::InjectOnlyZeroFee;
    int64_t fee_rate_per_byte = 0;  // relay only
    std::string funding_address;
    std::string destination;        // consolidate: the output address; collateral: the change address
    std::string gov_hash;           // collateral only; empty => null
    std::string hex_file;           // the exact bytes written to <name>.hex
    std::vector<ManifestTx> txs;
    // maturity screen
    std::string intake_source;
    int64_t screen_tip_height = 0;
    std::string screen_tip_hash;
    int64_t target_height = 0;
    int64_t min_confirmations = 0;
    int64_t youngest_input_height = 0;  // 0 => null
    int64_t safe_from_height = 0;       // 0 => null
    // what the plan left out
    std::vector<Utxo> immature;         // confirmations as of target_height
    size_t dust_count = 0;
    int64_t dust_floor = 0;
    size_t not_selected = 0;            // mature but left out by input_limit
    // the key (public description only)
    std::string key_source;
    std::string key_path;
    std::string key_encoding;           // "compressed" | "uncompressed"
};

// sha256 of the bytes, lowercase hex in natural order (what `sha256sum` prints).
std::string sha256_hex(const std::string& bytes);
// sha256d of the bytes, display order (byte-reversed, like a txid).
std::string sha256d_display_hex(const std::string& bytes);

// The manifest JSON. Throws DashAbort on an empty tx list or an empty hex file.
std::string build_inject_manifest(const ManifestData& d);

} // namespace c2w::dash
