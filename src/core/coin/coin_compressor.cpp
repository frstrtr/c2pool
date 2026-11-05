// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Port of Dash Core v23.1.7 src/compressor.cpp and the Coin::Serialize half
// of src/coins.h; see coin_compressor.hpp and src/core/crypto/VENDOR.md.

#include "coin_compressor.hpp"

#include <secp256k1.h>

#include <cassert>
#include <cstring>

namespace core::coin {

namespace {

// script.h opcodes used by the special forms.
constexpr unsigned char OP_DUP = 0x76;
constexpr unsigned char OP_HASH160 = 0xa9;
constexpr unsigned char OP_EQUAL = 0x87;
constexpr unsigned char OP_EQUALVERIFY = 0x88;
constexpr unsigned char OP_CHECKSIG = 0xac;

/** CPubKey uses secp256k1_context_static; a NONE context answers the same
 *  parse/serialize calls and exists in every libsecp256k1 the build accepts. */
const secp256k1_context* secp_ctx()
{
    static const secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    return ctx;
}

/** CPubKey::IsFullyValid for a 65-byte 0x04 key. */
bool pubkey_fully_valid(const unsigned char* vch, size_t len)
{
    secp256k1_pubkey pubkey;
    return secp256k1_ec_pubkey_parse(secp_ctx(), &pubkey, vch, len) == 1;
}

/** CPubKey::Decompress of a 33-byte compressed key into 65 bytes. */
bool pubkey_decompress(const unsigned char (&in)[33], unsigned char (&out)[65])
{
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(secp_ctx(), &pubkey, in, 33))
        return false;
    size_t publen = 65;
    secp256k1_ec_pubkey_serialize(secp_ctx(), out, &publen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    return publen == 65;
}

/*
 * These check for scripts for which a special case with a shorter encoding is defined.
 * They are implemented separately from the CScript test, as these test for exact byte
 * sequence correspondences, and are more strict. For example, IsToPubKey also verifies
 * whether the public key is valid (as invalid ones cannot be represented in compressed
 * form).
 */

bool IsToKeyID(const std::vector<unsigned char>& script, unsigned char (&hash)[20])
{
    if (script.size() == 25 && script[0] == OP_DUP && script[1] == OP_HASH160
                            && script[2] == 20 && script[23] == OP_EQUALVERIFY
                            && script[24] == OP_CHECKSIG) {
        std::memcpy(hash, &script[3], 20);
        return true;
    }
    return false;
}

bool IsToScriptID(const std::vector<unsigned char>& script, unsigned char (&hash)[20])
{
    if (script.size() == 23 && script[0] == OP_HASH160 && script[1] == 20
                            && script[22] == OP_EQUAL) {
        std::memcpy(hash, &script[2], 20);
        return true;
    }
    return false;
}

/** On true, `pubkey` holds the 33 or 65 key bytes. */
bool IsToPubKey(const std::vector<unsigned char>& script, std::vector<unsigned char>& pubkey)
{
    if (script.size() == 35 && script[0] == 33 && script[34] == OP_CHECKSIG
                            && (script[1] == 0x02 || script[1] == 0x03)) {
        pubkey.assign(script.begin() + 1, script.begin() + 34);
        return true;
    }
    if (script.size() == 67 && script[0] == 65 && script[66] == OP_CHECKSIG
                            && script[1] == 0x04) {
        pubkey.assign(script.begin() + 1, script.begin() + 66);
        return pubkey_fully_valid(pubkey.data(), pubkey.size()); // if not fully valid, a case that would not be compressible
    }
    return false;
}

} // namespace

const char* codec_status_name(CodecStatus s)
{
    switch (s) {
    case CodecStatus::ok: return "ok";
    case CodecStatus::truncated: return "truncated";
    case CodecStatus::varint_overflow: return "varint-overflow";
    case CodecStatus::bad_pubkey: return "bad-pubkey";
    case CodecStatus::oversized_script: return "oversized-script";
    case CodecStatus::bad_amount: return "bad-amount";
    }
    return "unknown";
}

bool CompressScript(const std::vector<unsigned char>& script, CompressedScript& out)
{
    unsigned char keyID[20];
    if (IsToKeyID(script, keyID)) {
        out.resize(21);
        out[0] = 0x00;
        std::memcpy(&out[1], keyID, 20);
        return true;
    }
    unsigned char scriptID[20];
    if (IsToScriptID(script, scriptID)) {
        out.resize(21);
        out[0] = 0x01;
        std::memcpy(&out[1], scriptID, 20);
        return true;
    }
    std::vector<unsigned char> pubkey;
    if (IsToPubKey(script, pubkey)) {
        out.resize(33);
        std::memcpy(&out[1], &pubkey[1], 32);
        if (pubkey[0] == 0x02 || pubkey[0] == 0x03) {
            out[0] = pubkey[0];
            return true;
        } else if (pubkey[0] == 0x04) {
            out[0] = 0x04 | (pubkey[64] & 0x01);
            return true;
        }
    }
    return false;
}

unsigned int GetSpecialScriptSize(unsigned int nSize)
{
    if (nSize == 0 || nSize == 1)
        return 20;
    if (nSize == 2 || nSize == 3 || nSize == 4 || nSize == 5)
        return 32;
    return 0;
}

bool DecompressScript(std::vector<unsigned char>& script, unsigned int nSize, const CompressedScript& in)
{
    switch(nSize) {
    case 0x00:
        script.resize(25);
        script[0] = OP_DUP;
        script[1] = OP_HASH160;
        script[2] = 20;
        std::memcpy(&script[3], in.data(), 20);
        script[23] = OP_EQUALVERIFY;
        script[24] = OP_CHECKSIG;
        return true;
    case 0x01:
        script.resize(23);
        script[0] = OP_HASH160;
        script[1] = 20;
        std::memcpy(&script[2], in.data(), 20);
        script[22] = OP_EQUAL;
        return true;
    case 0x02:
    case 0x03:
        script.resize(35);
        script[0] = 33;
        script[1] = nSize;
        std::memcpy(&script[2], in.data(), 32);
        script[34] = OP_CHECKSIG;
        return true;
    case 0x04:
    case 0x05: {
        unsigned char vch[33] = {};
        vch[0] = nSize - 2;
        std::memcpy(&vch[1], in.data(), 32);
        unsigned char pubkey[65];
        if (!pubkey_decompress(vch, pubkey))
            return false;
        script.resize(67);
        script[0] = 65;
        std::memcpy(&script[1], pubkey, 65);
        script[66] = OP_CHECKSIG;
        return true;
    }
    }
    return false;
}

// Amount compression:
// * If the amount is 0, output 0
// * first, divide the amount (in base units) by the largest power of 10 possible; call the exponent e (e is max 9)
// * if e<9, the last digit of the resulting number cannot be 0; store it as d, and drop it (divide by 10)
//   * call the result n
//   * output 1 + 10*(9*n + d - 1) + e
// * if e==9, we only know the resulting number is not zero, so output 1 + 10*(n - 1) + 9
// (this is decodable, as d is in [1-9] and e is in [0-9])

uint64_t CompressAmount(uint64_t n)
{
    if (n == 0)
        return 0;
    int e = 0;
    while (((n % 10) == 0) && e < 9) {
        n /= 10;
        e++;
    }
    if (e < 9) {
        int d = (n % 10);
        assert(d >= 1 && d <= 9);
        n /= 10;
        return 1 + (n*9 + d - 1)*10 + e;
    } else {
        return 1 + (n - 1)*10 + 9;
    }
}

uint64_t DecompressAmount(uint64_t x)
{
    // x = 0  OR  x = 1+10*(9*n + d - 1) + e  OR  x = 1+10*(n - 1) + 9
    if (x == 0)
        return 0;
    x--;
    // x = 10*(9*n + d - 1) + e
    int e = x % 10;
    x /= 10;
    uint64_t n = 0;
    if (e < 9) {
        // x = 9*n + d - 1
        int d = (x % 9) + 1;
        x /= 9;
        // x = n
        n = x*10 + d;
    } else {
        n = x+1;
    }
    while (e) {
        n *= 10;
        e--;
    }
    return n;
}

void SerializeCompressedScript(std::vector<unsigned char>& os, const std::vector<unsigned char>& script)
{
    CompressedScript compr;
    if (CompressScript(script, compr)) {
        os.insert(os.end(), compr.begin(), compr.end());
        return;
    }
    unsigned int nSize = static_cast<unsigned int>(script.size()) + nSpecialScripts;
    WriteVarInt(os, nSize);
    os.insert(os.end(), script.begin(), script.end());
}

void SerializeCoreCoin(std::vector<unsigned char>& os, const Coin& coin)
{
    assert(coin.height < (uint32_t{1} << 31));
    assert(coin.value >= 0);
    uint32_t code = coin.height * uint32_t{2} + (coin.coinbase ? 1u : 0u);
    WriteVarInt(os, code);
    WriteVarInt(os, CompressAmount(static_cast<uint64_t>(coin.value)));
    SerializeCompressedScript(os, coin.scriptPubKey.m_data);
}

} // namespace core::coin
