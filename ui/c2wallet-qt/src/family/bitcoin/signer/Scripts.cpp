// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Scripts.hpp"

#include <hash.h>
#include <crypto/sha256.h>
#include <crypto/ripemd160.h>

#include <stdexcept>

namespace c2w::signer {

Bytes sha256(const Bytes& x)
{
    Bytes out(32);
    CSHA256().Write(x.data(), x.size()).Finalize(out.data());
    return out;
}

Bytes hash160(const Bytes& x)
{
    uint8_t sha[32];
    CSHA256().Write(x.data(), x.size()).Finalize(sha);
    Bytes out(20);
    CRIPEMD160().Write(sha, 32).Finalize(out.data());
    return out;
}

CScript push_data(const Bytes& data)
{
    CScript s;
    s << data;
    return s;
}

CScript p2pk(const Bytes& pubkey)
{
    CScript s;
    s << pubkey << OP_CHECKSIG;
    return s;
}

CScript p2pkh_from_h160(const Bytes& h160v)
{
    CScript s;
    s << OP_DUP << OP_HASH160 << h160v << OP_EQUALVERIFY << OP_CHECKSIG;
    return s;
}

CScript p2pkh(const Bytes& pubkey)
{
    return p2pkh_from_h160(hash160(pubkey));
}

CScript p2sh(const CScript& redeemScript)
{
    Bytes rs(redeemScript.begin(), redeemScript.end());
    CScript s;
    s << OP_HASH160 << hash160(rs) << OP_EQUAL;
    return s;
}

CScript p2ms(int m, const std::vector<Bytes>& pubkeys)
{
    if (m < 1 || m > (int)pubkeys.size() || pubkeys.size() > 20)
        throw std::runtime_error("p2ms: bad m/n");
    CScript s;
    s << CScriptNum(m);
    for (const auto& pk : pubkeys) s << pk;
    s << CScriptNum((int)pubkeys.size()) << OP_CHECKMULTISIG;
    return s;
}

CScript p2wpkh_program_from_h160(const Bytes& h160v)
{
    CScript s;
    s << OP_0 << h160v;
    return s;
}

CScript p2wpkh(const Bytes& compressed_pubkey)
{
    if (compressed_pubkey.size() != 33)
        throw std::runtime_error("p2wpkh: compressed key required (WITNESS_PUBKEYTYPE)");
    return p2wpkh_program_from_h160(hash160(compressed_pubkey));
}

CScript p2wsh_program_from_h256(const Bytes& h256v)
{
    CScript s;
    s << OP_0 << h256v;
    return s;
}

CScript p2wsh(const CScript& witnessScript)
{
    Bytes ws(witnessScript.begin(), witnessScript.end());
    return p2wsh_program_from_h256(sha256(ws));
}

CScript p2wpkh_scriptcode(const Bytes& compressed_pubkey)
{
    // BIP143: the scriptCode of a P2WPKH is 0x1976a914{20-byte-pubkey-hash}88ac.
    return p2pkh_from_h160(hash160(compressed_pubkey));
}

} // namespace c2w::signer
