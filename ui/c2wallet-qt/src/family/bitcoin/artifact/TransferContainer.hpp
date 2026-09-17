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
//
// M6 slice-2c additions (backward-compatible, additive records only — the 2a
// records 0x01..0x10 are byte-for-byte unchanged, so a 2a parser reads a 2c
// container and simply skips the new record types):
//
//   * GAP-3 R_DIGEST (0x06): a sha256 over ALL preceding container bytes,
//     appended LAST by to_hex() and, WHEN PRESENT, verified by from_hex()
//     (which REFUSES on mismatch). from_hex ALSO enforces that the digest is
//     the LAST record -- any record or byte after it REFUSES the parse -- and
//     rejects a duplicate singleton record (R_COIN/R_NETVER/R_ALGEBRA/R_UTX/
//     R_VERDICT). So the guarantee is exact: a digest that verifies is the last
//     record, hence it covers every meaningful byte -- no bytes can hide past
//     it and no field can be silently overwritten by a later duplicate. It
//     closes the 2a "a mutated output value is only caught by the human eye"
//     hole: a single flipped byte anywhere now fails the parse. Old parsers
//     skip record 0x06 (forward-compat), so this does NOT break already-merged
//     2a consumers; a container carrying no digest still parses, with the
//     parsed `has_digest` flag left false so the UI can say so.
//   * GAP-4 R_INPUT_SCRIPT (0x11): carries the P2SH/P2WSH redeem/witness (or
//     tapleaf) script the offline Sign tab needs for script inputs — e.g. the
//     LTC+DOGE P2MS-in-P2SH donation pattern — so the operator no longer has to
//     paste it by hand. Additive; the 2a per-input record (0x10) is unchanged.

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

// GAP-4 (slice-2c): the redeem / witness / tapleaf script an input needs to be
// signed, carried in-band so the offline signer does not depend on the operator
// pasting it. `kind` selects which script slot it fills.
enum class InputScriptKind : uint8_t {
    Redeem  = 0, // P2SH redeemScript
    Witness = 1, // P2WSH witnessScript
    Tapleaf = 2, // taproot leaf script (reserved; slice-2a signer is not taproot-script)
};

struct InputScript {
    uint64_t        input_index = 0; // index into UnsignedContainer::inputs
    InputScriptKind kind = InputScriptKind::Redeem;
    Bytes           script;          // the redeem/witness/tapleaf script bytes
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
    std::vector<InputScript>   input_scripts;     // GAP-4 (slice-2c); may be empty
    std::string                preflight_verdict; // optional c2pool pre-flight verdict

    // GAP-3 (slice-2c) parse metadata: set true by from_hex() ONLY when an
    // R_DIGEST record was present, verified, AND the last record. NOT part of
    // container identity, so it is excluded from operator==.
    bool                       has_digest = false;

    // Serialize to the hex artifact. Empty string if the encoded artifact would
    // exceed MAX_TRANSFER_BYTES (oversize refusal); `err` set in that case.
    // Appends the GAP-3 R_DIGEST record last.
    std::string to_hex(std::string& err) const;

    // Parse an artifact produced by to_hex(). std::nullopt + `err` on any
    // malformed / truncated / bad-magic input, or on a GAP-3 R_DIGEST mismatch.
    static std::optional<UnsignedContainer> from_hex(const std::string& hex, std::string& err);

    // sha256d of the unsigned tx bytes, rendered as a display txid — the
    // cross-gap comparison value (design §5.4: "Both sides show sha256d").
    std::string unsigned_txid_display() const {
        return sha256d_display(unsigned_tx);
    }

    // GAP-4: the script carried for `input_index` with `kind`, or nullopt if
    // none is present. The offline Sign path uses this for script inputs.
    std::optional<Bytes> script_for_input(uint64_t input_index, InputScriptKind kind) const;
};

bool operator==(const UnsignedInput& a, const UnsignedInput& b);
bool operator==(const InputScript& a, const InputScript& b);
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
