// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Family-A (Bitcoin-script) SIGNING core — phases M3-A + M4-A (#193).
// Design docs/design/c2wallet-qt.md §4.1 (spend matrix + "Wrapped & nested
// scripts") and §5.3 (self-verify-before-emit; RFC6979/low-S/DER; oversize).
//
// Scope: legacy (SigVersion::BASE) + BIP143 segwit-v0 (P2WPKH/P2WSH and their
// P2SH-nested forms) + wrapped/nested spend + PSBT-style multi-party combine
// (M3-A); PLUS BIP341/342 taproot — P2TR key-path + script-path, multi-leaf
// tap trees, and OP_CHECKSIGADD tapscript multisig (M4-A).
//
// Reuse, never re-implement (design §2.4): the vendored dashscript CScript +
// EvalScript/VerifyScript + legacy SignatureHash (SigVersion::BASE); the
// vendored SHA/RIPEMD/Hash; system libsecp256k1 for ECDSA AND Schnorr
// (schnorrsig + extrakeys). NEW here: the BIP143 v0 preimage (Bip143.*), the
// witness (de)serialization, the wrapping / combine assembly, and the full
// BIP341/342 taproot module (Taproot.*).

#include "Scripts.hpp"
#include "Taproot.hpp"

#include <primitives/transaction.h>
#include <script/interpreter.h> // SIGHASH_*, SCRIPT_VERIFY_*
#include <script/script.h>
#include <uint256.h>

#include <secure/SecureString.hpp>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace c2w::signer {

using Witness = std::vector<Bytes>;

// SIGHASH_DEFAULT (BIP341) — 0x00, absent from the Dash-era interpreter header.
static constexpr int SIGHASH_DEFAULT = 0x00;

// §5.4 / §4.1: the 100 kB oversize ceiling — refused for EVERY type.
static constexpr size_t MAX_TX_SIZE = 100000;

struct SelfVerifyResult {
    bool ok = false;
    std::string error;
};

class Signer {
public:
    explicit Signer(int32_t version = 2, uint32_t locktime = 0);

    size_t add_input(const uint256& prevhash, uint32_t n, int64_t amount,
                     const CScript& scriptPubKey, uint32_t sequence = 0xffffffffu);
    void   add_output(int64_t value, const CScript& scriptPubKey);

    // ── sighash producers (public so partial-sign/combine flows can collect
    //    per-cosigner digests without exposing keys) ──────────────────────────
    // Legacy = the vendored dashscript SignatureHash (SigVersion::BASE). Sets a
    // warning (and reproduces the constant 0x00..01 digest) on the classic
    // SIGHASH_SINGLE bug when base==SINGLE and nIn >= n_outputs.
    uint256 legacy_sighash(size_t nIn, const CScript& scriptCode, int nHashType);
    uint256 bip143_sighash_for(size_t nIn, const CScript& scriptCode,
                               int64_t amount, int nHashType);

    // ── taproot sighash (BIP341/342): commits to ALL spent outputs' amounts +
    //    scriptPubKeys via sha_amounts/sha_scriptpubkeys (§4.1). ext=0 key-path,
    //    ext=1 script-path (tapleaf_h required). ──────────────────────────────
    uint256 taproot_sighash_keypath(size_t nIn, int nHashType);
    uint256 taproot_sighash_scriptpath(size_t nIn, int nHashType, const uint256& tapleaf_h);

    // sig = strict-DER(RFC6979,low-S) ‖ 1-byte hashtype.
    Bytes make_legacy_sig(size_t nIn, const CScript& scriptCode,
                          const secure::SecureBytes& sk, int nHashType = SIGHASH_ALL);
    Bytes make_bip143_sig(size_t nIn, const CScript& scriptCode, int64_t amount,
                          const secure::SecureBytes& sk, int nHashType = SIGHASH_ALL);

    // Taproot key-path: sign with the TWEAKED key d' = d + taptweak(P ‖ root),
    // even-Y normalising both P and Q (BIP341, §4.1). `merkle_root` is null for
    // a key-path-only output. 64-byte sig for SIGHASH_DEFAULT, else 65 (with the
    // explicit hashtype byte). BIP340 deterministic nonce (fixed aux) — no RNG.
    Bytes make_taproot_keypath_sig(size_t nIn, const secure::SecureBytes& d,
                                   const uint256* merkle_root, int nHashType = SIGHASH_DEFAULT);
    // Taproot script-path: BIP340 Schnorr over the UNTWEAKED leaf key (§4.1).
    Bytes make_taproot_scriptpath_sig(size_t nIn, const CScript& leaf, uint8_t leafver,
                                      const secure::SecureBytes& leaf_key,
                                      int nHashType = SIGHASH_DEFAULT);

    void set_scriptsig(size_t nIn, const CScript& s);
    void set_witness(size_t nIn, const Witness& w);

    // ── per-input self-verify through the vendored interpreter ────────────────
    // Legacy inputs run VerifyScript (independent re-derivation of the sighash —
    // a wrong sighash fails). Segwit-v0 inputs run the vendored EvalScript with
    // the BIP143 checker over the witness stack (P2SH-nested handled). Taproot
    // inputs run the minimal BIP341/342 verifier (Taproot.*) — the vendored
    // interpreter is BASE-only, so a taproot spend is checked by re-deriving the
    // sighash and Schnorr-verifying via libsecp256k1 (§5.3 self-verify).
    SelfVerifyResult verify_input(size_t nIn) const;

    // Self-verify EVERY input, then refuse on oversize. Returns false + fills
    // `err` (nothing emitted) if any input fails verify or the tx exceeds
    // MAX_TX_SIZE. On success `out` holds the final signed tx bytes.
    bool finalize(Bytes& out, std::string& err) const;

    Bytes   serialize(bool with_witness) const;
    uint256 txid() const; // dSHA256 of the non-witness serialization
    bool    has_witness() const;

    const std::vector<std::string>& warnings() const { return warnings_; }

    // Combine (PSBT-style): order collected partial sigs by their pubkey's
    // position in `pubkeys` — CHECKMULTISIG scans top-down with no backtrack, so
    // sig order MUST match pubkey order (§4.1). `partials` = (pubkey, sig‖type).
    static std::vector<Bytes> order_multisig_sigs(
        const std::vector<Bytes>& pubkeys,
        const std::vector<std::pair<Bytes, Bytes>>& partials);

    // Assembly of the CHECKMULTISIG satisfaction with the leading NULLDUMMY
    // empty push (design §4.1: an empty push, NOT OP_1). Sigs already ordered.
    static CScript multisig_scriptsig(const std::vector<Bytes>& ordered_sigs,
                                      const CScript* redeem = nullptr);
    static Witness multisig_witness(const std::vector<Bytes>& ordered_sigs,
                                    const CScript& witnessScript);

    CMutableTransaction&       tx()       { return tx_; }
    const CMutableTransaction& tx() const { return tx_; }

private:
    struct Prevout { CScript spk; int64_t amount; };
    std::vector<SpentOutput> spent_outputs() const; // all prevouts (for BIP341)

    CMutableTransaction        tx_;
    std::vector<Prevout>       prevouts_;
    std::vector<Witness>       witnesses_;
    std::vector<std::string>   warnings_;
};

} // namespace c2w::signer
