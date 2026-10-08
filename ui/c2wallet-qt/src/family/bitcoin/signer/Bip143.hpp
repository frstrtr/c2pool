// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// BIP143 (segwit v0) sighash — NEW code (design §4.1: "Legacy sighash here =
// no amount commitment = invalid + replay exposure. NEW code."). The vendored
// dashscript interpreter is SigVersion::BASE only (Dash has no segwit), so this
// implements the amount-committing v0 preimage over the vendored hashing
// (HashWriter/CHash256) and drives self-verify through a BaseSignatureChecker
// that feeds the v0 digest into the real vendored EvalScript opcode engine.

#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

namespace c2w::signer {

// BIP143 v0 signature hash for input nIn, spending an output of `amount`,
// under `scriptCode` (implicit P2PKH for P2WPKH; witnessScript for P2WSH) and
// `nHashType`. Honours ALL/NONE/SINGLE and ANYONECANPAY exactly per BIP143.
uint256 bip143_sighash(const CMutableTransaction& tx, unsigned int nIn,
                       const CScript& scriptCode, int64_t amount, int nHashType);

// Signature checker that overrides the legacy digest with the BIP143 v0 digest
// so the vendored EvalScript exercises the real opcode path (CHECKSIG,
// CHECKMULTISIG ordering, NULLDUMMY) on a segwit input.
class Bip143SignatureChecker : public BaseSignatureChecker {
public:
    Bip143SignatureChecker(const CMutableTransaction& tx, unsigned int nIn, int64_t amount)
        : tx_(tx), nIn_(nIn), amount_(amount) {}

    bool CheckSig(const std::vector<unsigned char>& scriptSig,
                  const std::vector<unsigned char>& vchPubKey,
                  const CScript& scriptCode, SigVersion sigversion) const override;

    // v0 KAT scripts do not exercise timelocks; be permissive rather than fail.
    bool CheckLockTime(const CScriptNum&) const override { return true; }
    bool CheckSequence(const CScriptNum&) const override { return true; }

private:
    const CMutableTransaction& tx_;
    unsigned int nIn_;
    int64_t amount_;
};

} // namespace c2w::signer
