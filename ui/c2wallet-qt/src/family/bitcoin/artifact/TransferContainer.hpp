// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// M5-A Family-A air-gap transfer artifacts (design docs/design/c2wallet-qt.md
// §5.4 "Transfer format & the c2pool validation seam", Family A part).
//
// This module MARSHALS already-signed / unsigned bytes across the gap; it does
// NOT sign (that is the M3-A/M4-A signer core). Two public artifacts:
//
//   * UnsignedContainer (online -> offline): a PSBT-like, raw-hex-superset
//     container carrying the unsigned tx bytes + per-input
//     {prevout, scriptPubKey, amount, derivation hint} + coin id + network
//     version bytes (so the OFFLINE signer picks legacy vs BIP143 vs BIP341
//     algebra) + an optional c2pool pre-flight verdict.
//
//   * SignedContainer (offline -> online): EXACTLY the format c2pool's loaders
//     already consume — ONE raw signed tx hex PER LINE (the --pin-local-tx-hex
//     / --embedded-tx-inject-hex format proven at block 2518186). No PSBT
//     finalization online; c2pool takes finished bytes.

#include "Digest.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace c2w::artifact {

// The 100 kB oversize ceiling (§5.4 / §4.1) — refused for every artifact, and
// it is what bounds the QR frame count.
static constexpr size_t MAX_TRANSFER_BYTES = 100000;

// Which sighash algebra the offline signer must select for this coin/tx. The
// network version bytes travel too (network_version), but the explicit tag
// removes any guesswork for the signer.
enum class SighashAlgebra : uint8_t {
    Legacy = 0, // SigVersion::BASE
    Bip143 = 1, // segwit v0
    Bip341 = 2, // taproot
};

// Per-input metadata the offline signer needs but cannot recover from the
// unsigned tx bytes alone (design §5.4 Family-A unsigned artifact).
struct UnsignedInput {
    Hash32      prevout_txid{};       // internal (tx-serialization) byte order
    uint32_t    prevout_index = 0;
    Bytes       script_pubkey;        // the prevout's scriptPubKey
    int64_t     amount = 0;           // satoshis (BIP143/341 commit to this)
    std::string derivation_hint;      // e.g. "m/84'/0'/0'/0/0"; may be empty
};

// PSBT-like container: a binary, typed-record blob (magic + version + TLV
// records) that is then hex-encoded, so the whole artifact is one raw-hex
// string that EMBEDS the unsigned tx bytes verbatim — a "raw-hex superset".
struct UnsignedContainer {
    std::string                coin;              // coin id, e.g. "dash","btc","ltc"
    uint32_t                   network_version = 0; // network version bytes selector
    SighashAlgebra             algebra = SighashAlgebra::Legacy;
    Bytes                      unsigned_tx;       // raw unsigned tx bytes
    std::vector<UnsignedInput> inputs;
    std::string                preflight_verdict; // optional c2pool pre-flight verdict

    // Serialize to the hex artifact. Empty string if the encoded artifact would
    // exceed MAX_TRANSFER_BYTES (oversize refusal); `err` set in that case.
    std::string to_hex(std::string& err) const;

    // Parse an artifact produced by to_hex(). std::nullopt + `err` on any
    // malformed / truncated / bad-magic input.
    static std::optional<UnsignedContainer> from_hex(const std::string& hex, std::string& err);

    // sha256d of the unsigned tx bytes, rendered as a display txid — the
    // cross-gap comparison value (design §5.4: "Both sides show sha256d").
    std::string unsigned_txid_display() const {
        return sha256d_display(unsigned_tx);
    }
};

bool operator==(const UnsignedInput& a, const UnsignedInput& b);
bool operator==(const UnsignedContainer& a, const UnsignedContainer& b);

// Signed container (offline -> online): the c2pool loader format verbatim.
// The loader (c2pool/main_dash.cpp, --pin-local-tx-hex / --embedded-tx-inject-
// hex) is: ONE TRANSACTION PER LINE, intra-line whitespace stripped, blank
// lines skipped, odd hex length => the WHOLE file refused (all-or-nothing).
struct SignedContainer {
    std::vector<std::string> tx_hexes; // one raw signed tx hex each

    // Emit exactly one raw hex per line, each '\n'-terminated. This is the byte
    // format the c2pool loader consumes.
    std::string emit() const;

    // Parse mirroring the c2pool loader EXACTLY (whitespace strip, skip empty,
    // reject odd length as an all-or-nothing failure). Also refuses a single tx
    // whose byte length exceeds MAX_TRANSFER_BYTES. std::nullopt + `err` on
    // failure.
    static std::optional<SignedContainer> parse(const std::string& text, std::string& err);

    // sha256d display txid of each carried tx (cross-gap comparison list).
    std::vector<std::string> txid_displays() const;
};

} // namespace c2w::artifact
