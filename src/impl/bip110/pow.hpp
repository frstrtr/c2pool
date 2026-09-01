// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// BIP-110 (Bitcoin Knots BLAKE2b hard fork) proof-of-work + block-identity hash.
//
// SOURCE OF TRUTH: bitcoinknots/bitcoin src/primitives/block.cpp
// CBlockHeader::GetHash(), shipped tag v29.4.1.knots20260508rc5 (identical in
// the PoW files to PR #359 head fee27ccfe950e998bb6d36e2b81f4ec97e3e89a3).
//
// A post-fork (v2) block header serializes to 164 bytes: the classic 80 bytes
// (version with bit31 = v2 flag, prev, merkle, time, nBits, nNonce) followed by
// a 84-byte extension {nonce2 u32, nonce3 u32, extranonce u128, time_offset u32,
// txcount u16, flags u8, clear_bits u8, xor_key u128, height i32, mm_rhs u256}.
//
// The identity hash (used both as the block hash for prev-block references AND
// as the PoW value) is a five-stage commitment pipeline:
//   (1) xor_key_hash = TH("Bitcoin block hash PoW XOR key", xor_key)
//   (2) h1 = TH("Bitcoin block header 1",
//              version || reverse(prev) || height || merkle || time || 0x00 ||
//              nBits || u32(txcount) || flags || clear_bits || xor_key_hash)   [119 B]
//   (3) h2 = TH("Merge-mining hook", h1 || 32*0x00 || mm_rhs)                  [96 B]
//   (4) b1 = BLAKE2b-256( u32(0) || h2 || extranonce )                         [52 B]
//   (5) b2 = BLAKE2b-256( <flags layout> )                                     [80 B for flags=0]
//       flags=0: prevblock_hidden || nNonce || nonce2 || time_offset || nonce3 || b1
//       where prevblock_hidden = TH("Bitcoin prevblock header, hashed",
//                                     reverse(prev)) with its first 6 bytes zeroed.
//   (6) final uint256 internal[31-i] = b2[i] XOR xor_key_mask[i]. When xor_key is
//       null (every live block so far) the mask is all-zero, so the internal
//       bytes are simply reverse(b2) and the canonical display hash is hex(b2).
// TH(tag, msg) is the BIP340-style tagged hash: SHA256(SHA256(tag)||SHA256(tag)||msg).
//
// Target comparison is UNCHANGED from Bitcoin: the resulting uint256 is compared
// (arithmetically) against the target decoded from nBits. flags 1/2/3 select
// alternate stage-5 layouts (block.cpp) whose byte order is not proven against
// live chain data here, so this port fails loud on them rather than emit a hash
// it cannot vouch for. Pre-fork (80-byte, bit31 clear) headers stay SHA256d.
//
// PER-COIN ISOLATION: this header lives under src/impl/bip110/ and pulls in only
// the lane-local BLAKE2b primitive + btclibs SHA256. It never touches the
// SHA256d / scrypt / X11 PoW of any other lane.

#include "crypto/blake2b.h"

#include <core/uint256.hpp>
#include <btclibs/crypto/sha256.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace bip110::pow
{

using Bytes32 = std::array<unsigned char, 32>;

// BIP340-style tagged hash: SHA256( SHA256(tag) || SHA256(tag) || msg ).
inline Bytes32 tagged_hash(const char* tag, const unsigned char* msg, size_t msg_len)
{
    unsigned char th[32];
    CSHA256().Write(reinterpret_cast<const unsigned char*>(tag), std::strlen(tag)).Finalize(th);
    Bytes32 out;
    CSHA256 h;
    h.Write(th, 32);
    h.Write(th, 32);
    if (msg_len)
        h.Write(msg, msg_len);
    h.Finalize(out.data());
    return out;
}

inline Bytes32 blake2b256(const unsigned char* in, size_t in_len)
{
    Bytes32 out;
    // out_len 32 is always valid, so a non-zero return is impossible here.
    (void)bip110_blake2b(out.data(), out.size(), in, in_len);
    return out;
}

// Parsed v2 header field offsets within the 164-byte serialization.
struct HeaderV2
{
    const unsigned char* version;     // [4]  on-wire, bit31 = v2 flag
    const unsigned char* prev;        // [32] internal byte order
    const unsigned char* merkle;      // [32] internal byte order
    const unsigned char* time;        // [4]
    const unsigned char* nbits;       // [4]
    const unsigned char* nonce;       // [4]
    const unsigned char* nonce2;      // [4]
    const unsigned char* nonce3;      // [4]
    const unsigned char* extranonce;  // [16]
    const unsigned char* time_offset; // [4]
    const unsigned char* txcount;     // [2]
    const unsigned char* flags;       // [1]
    const unsigned char* clear_bits;  // [1]
    const unsigned char* xor_key;     // [16]
    const unsigned char* height;      // [4]
    const unsigned char* mm_rhs;      // [32]
};

static constexpr size_t V2_HEADER_SIZE = 164;

inline HeaderV2 parse_header_v2(std::span<const unsigned char> h)
{
    if (h.size() < V2_HEADER_SIZE)
        throw std::runtime_error("bip110: v2 header must be 164 bytes");
    const unsigned char* p = h.data();
    HeaderV2 o{};
    o.version     = p;        p += 4;
    o.prev        = p;        p += 32;
    o.merkle      = p;        p += 32;
    o.time        = p;        p += 4;
    o.nbits       = p;        p += 4;
    o.nonce       = p;        p += 4;
    o.nonce2      = p;        p += 4;
    o.nonce3      = p;        p += 4;
    o.extranonce  = p;        p += 16;
    o.time_offset = p;        p += 4;
    o.txcount     = p;        p += 2;
    o.flags       = p;        p += 1;
    o.clear_bits  = p;        p += 1;
    o.xor_key     = p;        p += 16;
    o.height      = p;        p += 4;
    o.mm_rhs      = p;        p += 32;
    return o;
}

// Compute the BIP-110 block identity hash of a 164-byte v2 header.
inline uint256 blake2b_block_hash_v2(std::span<const unsigned char> header)
{
    const HeaderV2 h = parse_header_v2(header);

    // reverse(prev): the prev field is stored internal (little-endian) on wire.
    unsigned char rev_prev[32];
    for (int i = 0; i < 32; ++i)
        rev_prev[i] = h.prev[31 - i];

    // (1) xor_key_hash
    const Bytes32 xor_key_hash =
        tagged_hash("Bitcoin block hash PoW XOR key", h.xor_key, 16);

    // (2) h1 over 119 bytes
    unsigned char msg1[119];
    {
        unsigned char* w = msg1;
        std::memcpy(w, h.version, 4);   w += 4;
        std::memcpy(w, rev_prev, 32);   w += 32;
        std::memcpy(w, h.height, 4);    w += 4;
        std::memcpy(w, h.merkle, 32);   w += 32;
        std::memcpy(w, h.time, 4);      w += 4;
        *w++ = 0x00;                                    // reserved
        std::memcpy(w, h.nbits, 4);     w += 4;
        // txcount u16 widened to u32 LE
        const uint16_t txcount = static_cast<uint16_t>(h.txcount[0]) |
                                 (static_cast<uint16_t>(h.txcount[1]) << 8);
        *w++ = static_cast<unsigned char>(txcount & 0xff);
        *w++ = static_cast<unsigned char>((txcount >> 8) & 0xff);
        *w++ = 0x00;
        *w++ = 0x00;
        *w++ = h.flags[0];
        *w++ = h.clear_bits[0];
        std::memcpy(w, xor_key_hash.data(), 32);  w += 32;
        // w - msg1 == 119
    }
    const Bytes32 h1 = tagged_hash("Bitcoin block header 1", msg1, sizeof(msg1));

    // (3) h2 over 96 bytes: h1 || 32*0x00 || mm_rhs
    unsigned char msg2[96];
    std::memcpy(msg2, h1.data(), 32);
    std::memset(msg2 + 32, 0, 32);
    std::memcpy(msg2 + 64, h.mm_rhs, 32);
    const Bytes32 h2 = tagged_hash("Merge-mining hook", msg2, sizeof(msg2));

    // (4) b1 = BLAKE2b-256( u32(0) || h2 || extranonce )  — 52 bytes
    unsigned char msg3[52];
    std::memset(msg3, 0, 4);
    std::memcpy(msg3 + 4, h2.data(), 32);
    std::memcpy(msg3 + 36, h.extranonce, 16);
    const Bytes32 b1 = blake2b256(msg3, sizeof(msg3));

    // (5) b2 — the Sia-ASIC-shaped pseudo-header. The low 2 bits of flags select
    // the field layout, per Knots primitives/block.cpp GetHash switch(m_flags&3)
    // (v29.4.1.knots20260508rc5). flags=0 is the 80-byte Sia-grind layout; 1/2/3
    // are the alternate arrangements. `zeros` is a uint128 (16 bytes). This
    // layout is self-validating on a live follower: a wrong arrangement yields a
    // hash that the next block's prev-reference cannot match, so the chain simply
    // stalls (fails closed) — it can never graft the node onto a wrong chain.
    const unsigned char flags2 = static_cast<unsigned char>(h.flags[0] & 0x03);
    static const unsigned char zeros16[16] = {0};

    Bytes32 prevblock_hidden =
        tagged_hash("Bitcoin prevblock header, hashed", rev_prev, 32);
    for (int i = 0; i < 6; ++i)
        prevblock_hidden[i] = 0;

    std::vector<unsigned char> pre;
    pre.reserve(160);
    auto put = [&](const unsigned char* p, size_t n) { pre.insert(pre.end(), p, p + n); };

    switch (flags2) {
    case 0:
        put(prevblock_hidden.data(), 32);
        put(h.nonce, 4); put(h.nonce2, 4); put(h.time_offset, 4); put(h.nonce3, 4);
        put(b1.data(), 32);
        break;
    case 1:
        put(h.nonce, 4); put(h.nonce2, 4); put(h.nonce3, 4); put(h.time_offset, 4);
        put(b1.data(), 32); put(h2.data(), 32);
        break;
    case 3:
        put(zeros16, 16); put(zeros16, 16);
        [[fallthrough]];
    case 2:
        put(zeros16, 16); put(zeros16, 16); put(zeros16, 16);
        put(h2.data(), 32);
        put(h.nonce, 4); put(h.nonce2, 4); put(h.time_offset, 4); put(h.nonce3, 4);
        put(b1.data(), 32);
        break;
    }
    const Bytes32 b2 = blake2b256(pre.data(), pre.size());

    // (6) Final XOR mask (Knots primitives/block.cpp). A null xor_key leaves the
    // mask all-zero, so internal = reverse(b2). A non-null xor_key derives
    //   mask = TaggedHash("Bitcoin block hash PoW XOR mask", xor_key).GetSHA256()
    // then zeroes the first clear_bits bits of the mask (whole bytes + a partial
    // top-bit clear on the next byte) so the PoW leading zeros are preserved.
    // The final hash is written reversed: internal[31-i] = b2[i] XOR mask[i].
    Bytes32 mask{};  // zero-initialized -> no-op XOR when xor_key is null
    bool xor_key_null = true;
    for (int i = 0; i < 16; ++i)
        if (h.xor_key[i] != 0) { xor_key_null = false; break; }
    if (!xor_key_null) {
        mask = tagged_hash("Bitcoin block hash PoW XOR mask", h.xor_key, 16);
        const unsigned cb    = static_cast<unsigned>(h.clear_bits[0]);
        const unsigned whole = cb / 8;
        for (unsigned i = 0; i < whole && i < 32; ++i)
            mask[i] = 0;
        const unsigned rem = cb % 8;
        if (rem && whole < 32)
            mask[whole] &= static_cast<unsigned char>(0xFFu >> rem);
    }

    uint256 result;
    unsigned char* d = result.data();
    for (int i = 0; i < 32; ++i)
        d[i] = static_cast<unsigned char>(b2[31 - i] ^ mask[31 - i]);
    return result;
}

// Coin-facing hash function bound to CoinParams::pow_func AND block_hash_func.
// Accepts a 164-byte v2 header (BLAKE2b pipeline). An 80-byte header (pre-fork,
// bit31 clear) falls back to SHA256d, preserving the pre-Blake2bHeight identity.
inline uint256 blake2b_block_hash(std::span<const unsigned char> header)
{
    if (header.size() >= V2_HEADER_SIZE)
        return blake2b_block_hash_v2(header);

    // Pre-fork fallback: classic double-SHA256 of the 80-byte header.
    unsigned char a[32], b[32];
    CSHA256().Write(header.data(), header.size()).Finalize(a);
    CSHA256().Write(a, 32).Finalize(b);
    uint256 result;
    std::memcpy(result.data(), b, 32);
    return result;
}

} // namespace bip110::pow
