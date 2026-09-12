// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Family-A (Bitcoin-script) SIGNING core — phase M3-A (#193).
// Design docs/design/c2wallet-qt.md §4.1 (spend matrix + "Wrapped & nested
// scripts") and §5.3 (self-verify-before-emit; RFC6979/low-S/DER; oversize).
//
// Scope: legacy (SigVersion::BASE) + BIP143 segwit-v0 (P2WPKH/P2WSH and their
// P2SH-nested forms) + wrapped/nested spend + PSBT-style multi-party combine.
// Taproot (BIP341/342) is deliberately OUT — that is M4-A.
//
// Reuse, never re-implement (design §2.4): the vendored dashscript CScript +
// EvalScript/VerifyScript + legacy SignatureHash (SigVersion::BASE); the
// vendored SHA/RIPEMD/Hash; system libsecp256k1 for ECDSA. NEW here: the BIP143
// v0 preimage (Bip143.*), the witness (de)serialization, and the wrapping /
// combine assembly (§4.1 "new constructor code").

#include "Scripts.hpp"

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

    // sig = strict-DER(RFC6979,low-S) ‖ 1-byte hashtype.
    Bytes make_legacy_sig(size_t nIn, const CScript& scriptCode,
                          const secure::SecureBytes& sk, int nHashType = SIGHASH_ALL);
    Bytes make_bip143_sig(size_t nIn, const CScript& scriptCode, int64_t amount,
                          const secure::SecureBytes& sk, int nHashType = SIGHASH_ALL);

    void set_scriptsig(size_t nIn, const CScript& s);
    void set_witness(size_t nIn, const Witness& w);

    // ── per-input self-verify through the vendored interpreter ────────────────
    // Legacy inputs run VerifyScript (independent re-derivation of the sighash —
    // a wrong sighash fails). Segwit-v0 inputs run the vendored EvalScript with
    // the BIP143 checker over the witness stack (P2SH-nested handled).
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

    CMutableTransaction        tx_;
    std::vector<Prevout>       prevouts_;
    std::vector<Witness>       witnesses_;
    std::vector<std::string>   warnings_;
};

} // namespace c2w::signer
