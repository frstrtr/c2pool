// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Bip143.hpp"

#include <hash.h>
#include <pubkey.h>

namespace c2w::signer {

// SIGHASH base type (low 5 bits) + ANYONECANPAY (0x80). SIGHASH_ALL/NONE/SINGLE
// come from the vendored interpreter header.
static inline uint256 dsha_prevouts(const CMutableTransaction& tx)
{
    HashWriter ss{};
    for (const auto& in : tx.vin) ss << in.prevout;
    return ss.GetHash(); // double-SHA256
}
static inline uint256 dsha_sequences(const CMutableTransaction& tx)
{
    HashWriter ss{};
    for (const auto& in : tx.vin) ss << in.nSequence;
    return ss.GetHash();
}
static inline uint256 dsha_outputs_all(const CMutableTransaction& tx)
{
    HashWriter ss{};
    for (const auto& out : tx.vout) ss << out;
    return ss.GetHash();
}
static inline uint256 dsha_output_one(const CTxOut& out)
{
    HashWriter ss{};
    ss << out;
    return ss.GetHash();
}

uint256 bip143_sighash(const CMutableTransaction& tx, unsigned int nIn,
                       const CScript& scriptCode, int64_t amount, int nHashType)
{
    const bool anyonecanpay = (nHashType & SIGHASH_ANYONECANPAY) != 0;
    const int base = nHashType & 0x1f;

    uint256 hashPrevouts, hashSequence, hashOutputs; // default all-zero

    if (!anyonecanpay)
        hashPrevouts = dsha_prevouts(tx);

    if (!anyonecanpay && base != SIGHASH_SINGLE && base != SIGHASH_NONE)
        hashSequence = dsha_sequences(tx);

    if (base != SIGHASH_SINGLE && base != SIGHASH_NONE) {
        hashOutputs = dsha_outputs_all(tx);
    } else if (base == SIGHASH_SINGLE && nIn < tx.vout.size()) {
        hashOutputs = dsha_output_one(tx.vout[nIn]);
    }
    // else hashOutputs stays zero (incl. the SINGLE out-of-range case; BIP143
    // fixed the legacy bug — the v0 digest just commits to a zero hashOutputs).

    const int32_t nVersion = (int32_t)tx.nVersion; // nType==0 for a Bitcoin tx
    HashWriter ss{};
    ss << nVersion;
    ss << hashPrevouts;
    ss << hashSequence;
    ss << tx.vin[nIn].prevout;
    ss << scriptCode;
    ss << amount;
    ss << tx.vin[nIn].nSequence;
    ss << hashOutputs;
    ss << (uint32_t)tx.nLockTime;
    ss << (uint32_t)nHashType;
    return ss.GetHash();
}

bool Bip143SignatureChecker::CheckSig(const std::vector<unsigned char>& vchSigIn,
                                      const std::vector<unsigned char>& vchPubKey,
                                      const CScript& scriptCode, SigVersion /*sigversion*/) const
{
    if (vchSigIn.empty()) return false;
    std::vector<unsigned char> vchSig(vchSigIn);
    const int nHashType = vchSig.back();
    vchSig.pop_back();

    const uint256 sighash = bip143_sighash(tx_, nIn_, scriptCode, amount_, nHashType);

    CPubKey pubkey(vchPubKey.begin(), vchPubKey.end());
    if (!pubkey.IsValid()) return false;
    return pubkey.Verify(sighash, vchSig);
}

} // namespace c2w::signer
