// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Port of Dash Core v23.1.7 src/compressor.{h,cpp}, the Coin codec of
// src/coins.h (Coin::Serialize / Coin::Unserialize) and the VARINT /
// CompactSize primitives of src/serialize.h that they use. See
// src/core/crypto/VENDOR.md for the upstream tag and commit.
//
// This is the per-coin codec of a Core `dumptxoutset` file (and of Core's
// chainstate values): VARINT(nHeight*2 + fCoinBase), then the TxOut through
// TxOutCompression = VARINT(CompressAmount(nValue)) + ScriptCompression.
//
// Changes against upstream: free functions in core::coin over
// std::vector<unsigned char> scripts (no CScript / prevector / CPubKey);
// the pubkey checks call libsecp256k1 directly, exactly as CPubKey does;
// readers return a status instead of throwing; the Unser paths that Core
// tolerates silently (a 0x04/0x05 point that does not decompress, an
// oversized raw script that Core swaps for OP_RETURN) are reported to the
// caller, which decides (a UTXO-set reader refuses both: Core never stores
// either).

#pragma once

#include "utxo.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>
#include <vector>

namespace core::coin {

// ─── serialize.h primitives ─────────────────────────────────────────────────

/** Bitcoin/Dash `WriteVarInt` (VarIntMode::DEFAULT): MSB base-128, every
 *  continuation group offset by one. Not core::coin::write_varint (LEB128). */
template <typename I>
inline void WriteVarInt(std::vector<unsigned char>& os, I n)
{
    static_assert(std::is_unsigned<I>::value, "Unsigned type required with mode DEFAULT.");
    unsigned char tmp[(sizeof(n) * 8 + 6) / 7];
    int len = 0;
    while (true) {
        tmp[len] = (n & 0x7F) | (len ? 0x80 : 0x00);
        if (n <= 0x7F)
            break;
        n = (n >> 7) - 1;
        len++;
    }
    do {
        os.push_back(tmp[len]);
    } while (len--);
}

/** Bitcoin/Dash `WriteCompactSize`. */
inline void WriteCompactSize(std::vector<unsigned char>& os, uint64_t nSize)
{
    if (nSize < 253) {
        os.push_back(static_cast<unsigned char>(nSize));
    } else if (nSize <= std::numeric_limits<uint16_t>::max()) {
        os.push_back(253);
        for (int i = 0; i < 2; ++i) os.push_back(static_cast<unsigned char>(nSize >> (8 * i)));
    } else if (nSize <= std::numeric_limits<uint32_t>::max()) {
        os.push_back(254);
        for (int i = 0; i < 4; ++i) os.push_back(static_cast<unsigned char>(nSize >> (8 * i)));
    } else {
        os.push_back(255);
        for (int i = 0; i < 8; ++i) os.push_back(static_cast<unsigned char>(nSize >> (8 * i)));
    }
}

/** Outcome of a read from a byte stream. */
enum class CodecStatus {
    ok,
    truncated,       // the stream ended inside the item
    varint_overflow, // ReadVarInt(): size too large (Core throws)
    bad_pubkey,      // special script 0x04/0x05 whose point does not decompress
    oversized_script,// raw script > MAX_SCRIPT_SIZE (Core reads it as OP_RETURN)
    bad_amount,      // decompressed amount does not fit a non-negative CAmount
};

const char* codec_status_name(CodecStatus s);

/** Bitcoin/Dash `ReadVarInt<Stream, VarIntMode::DEFAULT, I>`. The Stream is any
 *  object with `bool read(unsigned char* dst, size_t n)` (false = the stream
 *  ended). Core's two "size too large" throws become varint_overflow. */
template <typename Stream, typename I>
inline CodecStatus ReadVarInt(Stream& is, I& out)
{
    static_assert(std::is_unsigned<I>::value, "Unsigned type required with mode DEFAULT.");
    I n = 0;
    while (true) {
        unsigned char chData;
        if (!is.read(&chData, 1))
            return CodecStatus::truncated;
        if (n > (std::numeric_limits<I>::max() >> 7))
            return CodecStatus::varint_overflow;
        n = (n << 7) | (chData & 0x7F);
        if (chData & 0x80) {
            if (n == std::numeric_limits<I>::max())
                return CodecStatus::varint_overflow;
            n++;
        } else {
            out = n;
            return CodecStatus::ok;
        }
    }
}

/** A Stream over a byte range (KATs, single records). */
struct SpanStream {
    const unsigned char* data{nullptr};
    size_t size{0};
    size_t pos{0};
    bool read(unsigned char* dst, size_t n)
    {
        if (n > size - pos) return false;
        std::memcpy(dst, data + pos, n);
        pos += n;
        return true;
    }
    bool skip(size_t n)
    {
        if (n > size - pos) return false;
        pos += n;
        return true;
    }
    bool eof() const { return pos == size; }
};

// ─── compressor.h / compressor.cpp ──────────────────────────────────────────

/** script.h MAX_SCRIPT_SIZE. */
inline constexpr unsigned int MAX_SCRIPT_SIZE = 10000;

/** ScriptCompression::nSpecialScripts. */
inline constexpr unsigned int nSpecialScripts = 6;

/** Core keeps this in a prevector<33>; the largest compressed form is 33 bytes. */
using CompressedScript = std::vector<unsigned char>;

/** compressor.cpp CompressScript: the six special forms (P2PKH, P2SH, P2PK
 *  compressed 02/03, P2PK uncompressed 04 as 04|parity — only for a key
 *  libsecp256k1 parses, CPubKey::IsFullyValid). False = not special. */
bool CompressScript(const std::vector<unsigned char>& script, CompressedScript& out);

/** compressor.cpp GetSpecialScriptSize. */
unsigned int GetSpecialScriptSize(unsigned int nSize);

/** compressor.cpp DecompressScript (0x04/0x05 through libsecp256k1, as
 *  CPubKey::Decompress). False = nSize is not special or the point is not
 *  on the curve; `script` is then left unchanged. */
bool DecompressScript(std::vector<unsigned char>& script, unsigned int nSize, const CompressedScript& in);

/** compressor.cpp CompressAmount. @pre 0 <= nAmount <= MAX_MONEY. */
uint64_t CompressAmount(uint64_t nAmount);

/** compressor.cpp DecompressAmount. */
uint64_t DecompressAmount(uint64_t nAmount);

/** ScriptCompression::Ser. */
void SerializeCompressedScript(std::vector<unsigned char>& os, const std::vector<unsigned char>& script);

/** ScriptCompression::Unser. On oversized_script the payload has been skipped
 *  and `script` holds the single OP_RETURN Core puts in its place. */
template <typename Stream>
inline CodecStatus UnserializeCompressedScript(Stream& s, std::vector<unsigned char>& script)
{
    unsigned int nSize = 0;
    if (auto st = ReadVarInt(s, nSize); st != CodecStatus::ok)
        return st;
    if (nSize < nSpecialScripts) {
        CompressedScript vch(GetSpecialScriptSize(nSize), 0x00);
        if (!s.read(vch.data(), vch.size()))
            return CodecStatus::truncated;
        if (!DecompressScript(script, nSize, vch))
            return CodecStatus::bad_pubkey;
        return CodecStatus::ok;
    }
    nSize -= nSpecialScripts;
    if (nSize > MAX_SCRIPT_SIZE) {
        // Overly long script, replace with a short invalid one
        script.assign(1, 0x6a /* OP_RETURN */);
        if (!s.skip(nSize))
            return CodecStatus::truncated;
        return CodecStatus::oversized_script;
    }
    script.resize(nSize);
    if (nSize > 0 && !s.read(script.data(), nSize))
        return CodecStatus::truncated;
    return CodecStatus::ok;
}

// ─── coins.h Coin codec ─────────────────────────────────────────────────────

/** Coin::Serialize: VARINT(uint32 nHeight*2 + fCoinBase), then
 *  TxOutCompression (VARINT(CompressAmount(nValue)), ScriptCompression).
 *  @pre coin.height < 2^31, 0 <= coin.value. The pegout flag is not part of
 *  the Core codec and is not written. */
void SerializeCoreCoin(std::vector<unsigned char>& os, const Coin& coin);

/** Coin::Unserialize. On success `coin` carries value, script, height and
 *  coinbase; pegout = false. */
template <typename Stream>
inline CodecStatus UnserializeCoreCoin(Stream& s, Coin& coin)
{
    uint32_t code = 0;
    if (auto st = ReadVarInt(s, code); st != CodecStatus::ok)
        return st;
    coin.height = code >> 1;
    coin.coinbase = (code & 1) != 0;
    coin.pegout = false;
    uint64_t v = 0;
    if (auto st = ReadVarInt(s, v); st != CodecStatus::ok)
        return st;
    const uint64_t amount = DecompressAmount(v);
    if (amount > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
        return CodecStatus::bad_amount;
    coin.value = static_cast<int64_t>(amount);
    coin.scriptPubKey.m_data.clear();
    return UnserializeCompressedScript(s, coin.scriptPubKey.m_data);
}

/** script.h CScript::IsUnspendable: OP_RETURN first, or larger than
 *  MAX_SCRIPT_SIZE. Core never stores such an output in its UTXO set. */
inline bool IsUnspendableScript(const std::vector<unsigned char>& script)
{
    return (!script.empty() && script[0] == 0x6a) || script.size() > MAX_SCRIPT_SIZE;
}

} // namespace core::coin
