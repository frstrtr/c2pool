// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// GAP-1 — the std-only FACADE over the Family-A signing core.
//
// WHY THIS EXISTS (the G3 header-tree collision): the signer library pulls the
// vendored `dashscript` header tree (its own <uint256.h>, <hash.h>,
// <compat/endian.h>, <script/*>), while the hdkeys / convert libraries pull
// c2pool's `btclibs` tree (which ALSO defines <uint256.h>, <hash.h>,
// compat/endian.h). The two trees cannot meet in one translation unit. The
// Qt page TUs (PageBuildTx, PageSign) must include the btclibs-side headers
// (hdkeys/Address, convert, artifact) — so they must NEVER include a dashscript
// header. This facade is that boundary: its declarations use ONLY std types +
// c2w::secure::SecureBytes/Bytes + the (std-only) artifact UnsignedContainer, so
// a page can drive the signer through it without ever seeing a dashscript
// header. Its .cpp (compiled INSIDE the c2wallet-signer library) is the only
// place the two worlds are bridged, and it includes ONLY the dashscript tree.
//
// This mirrors the proven c2wallet-dash-tx / c2wallet-dash-common two-lib
// pattern (family/bitcoin/dash): static-archive symbol resolution is lazy, so
// the trees collide at the header level, never at the object level.

#include "family/bitcoin/artifact/TransferContainer.hpp"  // UnsignedContainer (std-only)
#include "secure/SecureString.hpp"                          // SecureBytes (std-only)

#include <cstdint>
#include <string>
#include <vector>

namespace c2w::sign {

using Bytes = std::vector<uint8_t>;

// scriptPubKey shape — the SELECTOR for the signing algebra (threat-model T-13:
// the SPK is the selector, never the container's self-declared type).
enum class SpkType { P2PK, P2PKH, P2WPKH, P2SH, P2WSH, P2TR, Unknown };
const char* spk_type_str(SpkType t);

// Classify a scriptPubKey by its exact byte template. std-only (byte pattern
// match) so a page can call it directly.
SpkType classify_spk(const Bytes& spk);

// ── parse_unsigned (GAP-2) ──────────────────────────────────────────────────
struct InputView {
    SpkType     type = SpkType::Unknown;
    int64_t     amount = 0;              // satoshis (from the container metadata)
    std::string prevout_txid_display;    // byte-reversed hex (explorer/txid form)
    uint32_t    prevout_index = 0;
    std::string derivation_hint;
    Bytes       script_pubkey;
    std::string spk_hex;
};
struct OutputView {
    int64_t     value = 0;
    Bytes       script_pubkey;
    std::string spk_hex;
};
struct TxView {
    bool                    ok = false;
    std::string             error;
    int32_t                 version = 0;
    uint32_t                locktime = 0;
    std::vector<InputView>  inputs;
    std::vector<OutputView> outputs;
    int64_t                 sum_in = 0;
    int64_t                 sum_out = 0;
    int64_t                 fee = 0;      // sum_in - sum_out (may be negative => unbalanced)
    size_t                  serialized_size = 0;
};

// Deserialize the container's unsigned tx and CROSS-CHECK it against the
// container metadata (GAP-2): asserts byte-exact re-serialize == unsigned_tx,
// empty scriptSigs, vin count == inputs count, and each prevout {txid,index}
// matches. `ok=false` + `error` on any mismatch (K1 refuse-malformed).
TxView parse_unsigned(const c2w::artifact::UnsignedContainer& c);

// ── sign_and_verify ─────────────────────────────────────────────────────────
// One private key bound to one input. `script` carries the redeemScript /
// witnessScript for genuine P2SH / P2WSH inputs (multisig or arbitrary inner);
// it is empty for the key-derivable single-key types (the facade derives the
// P2WPKH scriptCode / P2SH-P2WPKH redeemScript from `pub`). Multiple entries
// with the same `index` are the cosigners of one multisig input.
struct KeyForInput {
    size_t              index = 0;
    secure::SecureBytes sk;      // 32-byte private scalar (move-only, zeroizing)
    Bytes               pub;     // serialized pubkey (33 / 65)
    Bytes               script;  // redeem/witnessScript, or empty
};

struct SignOptions {
    int     sighash = 0x01;               // SIGHASH_ALL default (baseline)
    bool    absurd_fee_confirmed = false; // must be true to sign a fee > absurd_fee_sats
    int64_t absurd_fee_sats = 10'000'000; // T-4 ceiling; default 0.1 unit (see default_absurd_fee_sats)
};

struct SignOutcome {
    bool                     ok = false;
    std::string              error;
    std::string              signed_tx;     // full signed tx hex (with witness)
    std::string              txid_display;  // authoritative txid (non-witness), reversed hex
    std::string              wtxid_display; // sha256d of the FULL bytes, reversed (==txid for legacy)
    std::vector<std::string> warnings;
};

// A fee strictly greater than this (0.1 whole unit at 8 decimals) is refused
// unless SignOptions::absurd_fee_confirmed (threat-model T-4). This is the BTC
// baseline; per-coin ceilings come from default_absurd_fee_sats (a flat 0.1
// unit would trip on every normal DOGE / DGB transaction, whose unit is cheap).
inline constexpr int64_t kAbsurdFeeSats = 10'000'000;

// Per-coin absurd-fee ceiling (satoshis). Ticker is matched case-insensitively;
// a "-t" testnet suffix is ignored. Unknown coins fall back to kAbsurdFeeSats.
int64_t default_absurd_fee_sats(const std::string& coin);

// True when `coin` is BCH (mainnet or testnet). BCH needs SIGHASH_FORKID, which
// slice-2a does not implement — signing a BCH tx with the legacy/BIP143 algebra
// would be invalid on BCH yet REPLAYABLE on BTC for a pre-fork UTXO.
bool coin_is_bch(const std::string& coin);

// Sign every input for which a key was supplied, then MANDATORY finalize
// self-verify (per-input VerifyScript / BIP143 / BIP341) before emit (T-5),
// re-derive and cross-check the txid, and refuse on unbalanced / absurd-fee /
// oversize. `keys` is consumed (SecureBytes is move-only). Nothing is emitted on
// any refusal path.
SignOutcome sign_and_verify(const c2w::artifact::UnsignedContainer& c,
                            std::vector<KeyForInput>&& keys,
                            const SignOptions& opt);

} // namespace c2w::sign
