// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// BIP-110 Stratum-v1 BLAKE2b pseudo-header SSOT.
//
// This header is the SINGLE fold shared by the M2 work-shape KAT
// (src/c2pool/bip110_m2_workshape_kat.cpp) and the live work source
// (src/impl/bip110/stratum/work_source.cpp). It maps the 164-byte v2 header
// (src/impl/bip110/pow.hpp) onto the Stratum-v1 BLAKE2b work-shape that stock
// Sia BLAKE2b ASICs already speak (the mapping BIP-110 was designed for; the
// Knots DATUM Gateway reference bridge, datum_stratum.c / datum_pow.c, uses the
// identical field order).
//
// THE Sv1 BLAKE2b WORK-SHAPE (all offsets/orders proven against live fork block
// 961640 by the M2 KAT):
//   h1 = TH("Bitcoin block header 1", <119 B: version||rev(prev)||height||
//           merkle||time||0x00||nBits||u32(txcount)||flags||clear_bits||
//           TH("Bitcoin block hash PoW XOR key", xor_key)>)
//   h2 = TH("Merge-mining hook", h1 || 32*0x00 || mm_rhs)
//   root = BLAKE2b256( u32(0) || h2 || m_extranonce[16] )     (52-byte preimage)
//   b2   = BLAKE2b256( prevblock_hidden(32) || nNonce(4) || m_nonce2(4) ||
//                      m_time_offset(4) || m_nonce3(4) || root(32) )  (80 B)
//   final display hash = reverse(b2)  (xor_key == 0 on every live block)
//
// Stratum-v1 mapping (flags == 0, profile 0):
//   * mining.notify coinb1 = u32(0) || h2 || u32(0) || u32(0)      (44 bytes)
//     (== the 52-byte root preimage MINUS the trailing 8 rolled extranonce
//      bytes). coinb2 = "" and the merkle-branch array is LITERALLY empty; the
//      miner's coinb1 || extranonce1(4) || extranonce2(4) == the 52-byte root
//      preimage, and BLAKE2b256 of that IS the merkle root (no SHA256d fold).
//   * m_extranonce[16] = 8*0x00 || extranonce1(4) || extranonce2(4). The 4 zero
//     bytes after u32(0) are the header's own m_extranonce top-4; the next 4 are
//     the gateway-baked lead of the 12-byte extranonce (0 here); en1/en2 roll
//     the last 8. Core Stratum assigns extranonce1=4 B, extranonce2_size=4 B.
//   * mining.submit nonce (8-B hex): low4 -> nNonce, high4 -> m_nonce2.
//     mining.submit ntime (8-B hex): low4 -> wire time area, high4 -> m_nonce3.
//     A 4-B nonce/ntime rolls only nNonce / the wire time (m_nonce2/m_nonce3 0).
//     R2: this split is PINNED by the KAT (a wrong split = 100% reject), never
//     by review.
//
// Because the committed height + txcount + flags are folded INTO h1 (hence h2,
// hence coinb1), the coinbase/height/txcount are FROZEN at job-build time and
// cannot be filled at submit like a Bitcoin coinbase. rebuild_header_v2() below
// re-materialises the exact 164-byte header from the frozen fields plus the
// miner's rolled nonce/extranonce, so the work source recomputes the PoW
// independently and never trusts a miner-reported hash.
//
// PER-COIN ISOLATION: lives under src/impl/bip110/, pulls in only the lane-local
// bip110::pow pipeline. No other lane is touched.

#include "../pow.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace bip110::stratum
{

using Bytes32 = std::array<unsigned char, 32>;

// Everything committed into h1/h2 at job-build time. Nothing here can change at
// submit — the miner only rolls nNonce/m_nonce2/m_nonce3/m_time_offset and the
// last 8 extranonce bytes. prev/merkle are stored in internal (little-endian,
// on-wire) byte order, exactly as they sit in the 164-byte header.
struct HeaderFreeze
{
    std::array<unsigned char, 4>  version{};      // on-wire, bit31 = v2 flag
    Bytes32                        prev{};         // internal order
    Bytes32                        merkle{};       // internal order (== coinbase root here)
    std::array<unsigned char, 4>  time{};         // wire time area
    std::array<unsigned char, 4>  nbits{};
    uint16_t                       txcount{1};     // coinbase-only => 1
    unsigned char                  flags{0};       // MUST be 0 for M2 (profile 0)
    unsigned char                  clear_bits{0};  // MUST be 0 for M2
    std::array<unsigned char, 16> xor_key{};       // MUST be all-zero for M2
    uint32_t                       height{0};
    Bytes32                        mm_rhs{};        // merge-mining rhs (0 for solo BIP-110)
    // Derived at compute_h1_h2():
    Bytes32                        h1{};
    Bytes32                        h2{};
    Bytes32                        prevblock_hidden{};  // TH(...rev(prev)) top-6 zeroed
    bool                           derived{false};
};

// Recompute h1, h2 and prevblock_hidden from the frozen fields. Byte-identical
// to the internal computation in bip110::pow::blake2b_block_hash_v2 (enforced by
// the KAT's full-header rehash), so the h2 placed on the wire coinb1 matches the
// h2 pow.hpp derives from the reassembled header.
inline void compute_h1_h2(HeaderFreeze& f)
{
    if (f.flags != 0 || f.clear_bits != 0)
        throw std::runtime_error("bip110 M2: flags/clear_bits must be 0 (profile 0)");
    for (unsigned char b : f.xor_key)
        if (b != 0) throw std::runtime_error("bip110 M2: xor_key must be null");

    unsigned char rev_prev[32];
    for (int i = 0; i < 32; ++i) rev_prev[i] = f.prev[31 - i];

    const pow::Bytes32 xkh = pow::tagged_hash("Bitcoin block hash PoW XOR key", f.xor_key.data(), 16);

    unsigned char msg1[119];
    {
        unsigned char* w = msg1;
        std::memcpy(w, f.version.data(), 4); w += 4;
        std::memcpy(w, rev_prev, 32);        w += 32;
        w[0] = static_cast<unsigned char>(f.height & 0xff);          // height as 4 LE bytes
        w[1] = static_cast<unsigned char>((f.height >> 8) & 0xff);
        w[2] = static_cast<unsigned char>((f.height >> 16) & 0xff);
        w[3] = static_cast<unsigned char>((f.height >> 24) & 0xff);
        w += 4;
        std::memcpy(w, f.merkle.data(), 32); w += 32;
        std::memcpy(w, f.time.data(), 4);    w += 4;
        *w++ = 0x00;
        std::memcpy(w, f.nbits.data(), 4);   w += 4;
        *w++ = static_cast<unsigned char>(f.txcount & 0xff);
        *w++ = static_cast<unsigned char>((f.txcount >> 8) & 0xff);
        *w++ = 0x00;
        *w++ = 0x00;
        *w++ = f.flags;
        *w++ = f.clear_bits;
        std::memcpy(w, xkh.data(), 32);      w += 32;
        // w - msg1 == 119
    }
    const pow::Bytes32 h1 = pow::tagged_hash("Bitcoin block header 1", msg1, sizeof(msg1));

    unsigned char msg2[96];
    std::memcpy(msg2, h1.data(), 32);
    std::memset(msg2 + 32, 0, 32);
    std::memcpy(msg2 + 64, f.mm_rhs.data(), 32);
    const pow::Bytes32 h2 = pow::tagged_hash("Merge-mining hook", msg2, sizeof(msg2));

    pow::Bytes32 pbh = pow::tagged_hash("Bitcoin prevblock header, hashed", rev_prev, 32);
    for (int i = 0; i < 6; ++i) pbh[i] = 0;

    std::memcpy(f.h1.data(),  h1.data(), 32);
    std::memcpy(f.h2.data(),  h2.data(), 32);
    std::memcpy(f.prevblock_hidden.data(), pbh.data(), 32);
    f.derived = true;
}

// prevblock_hidden = TH("Bitcoin prevblock header, hashed", rev(prev)) with the
// first 6 bytes zeroed. Depends ONLY on prev, so the work source can compute the
// current-tip wire prevhash without a full freeze (DOA / clean_jobs detection).
inline Bytes32 prevblock_hidden_from_prev(const Bytes32& prev_internal)
{
    unsigned char rev_prev[32];
    for (int i = 0; i < 32; ++i) rev_prev[i] = prev_internal[31 - i];
    pow::Bytes32 pbh = pow::tagged_hash("Bitcoin prevblock header, hashed", rev_prev, 32);
    for (int i = 0; i < 6; ++i) pbh[i] = 0;
    Bytes32 out; std::memcpy(out.data(), pbh.data(), 32); return out;
}

// The 52-byte BLAKE2b merkle-root preimage: u32(0) || h2 || m_extranonce[16].
// m_extranonce[16] == 8*0x00 || en1(4) || en2(4).
inline std::array<unsigned char, 16> make_extranonce16(
    const std::array<unsigned char, 4>& en1, const std::array<unsigned char, 4>& en2)
{
    std::array<unsigned char, 16> ex{};
    // ex[0..7] stay 0 (m_extranonce top-4 + gateway-baked lead-4)
    std::memcpy(ex.data() + 8,  en1.data(), 4);
    std::memcpy(ex.data() + 12, en2.data(), 4);
    return ex;
}

inline Bytes32 compute_root(const Bytes32& h2, const std::array<unsigned char, 16>& extranonce16)
{
    unsigned char msg3[52];
    std::memset(msg3, 0, 4);
    std::memcpy(msg3 + 4,  h2.data(), 32);
    std::memcpy(msg3 + 36, extranonce16.data(), 16);
    const pow::Bytes32 b = pow::blake2b256(msg3, sizeof(msg3));
    Bytes32 out; std::memcpy(out.data(), b.data(), 32); return out;
}

// The mining.notify coinb1: u32(0) || h2 || u32(0) || u32(0) (44 bytes). The
// miner appends extranonce1(4) || extranonce2(4) to reach the 52-byte preimage.
inline std::vector<unsigned char> wire_coinb1_bytes(const Bytes32& h2)
{
    std::vector<unsigned char> c;
    c.reserve(44);
    c.insert(c.end(), 4, 0x00);                     // u32(0)
    c.insert(c.end(), h2.begin(), h2.end());        // h2
    c.insert(c.end(), 8, 0x00);                     // m_extranonce lead 8 (4 hdr + 4 gateway)
    return c;                                        // 4 + 32 + 8 == 44
}

// Recover h2 from a wire coinb1 (the SSOT the work source uses to key its
// freeze-map and to self-check that emission == verification).
inline Bytes32 parse_h2_from_wire_coinb1(std::span<const unsigned char> coinb1)
{
    if (coinb1.size() < 36)
        throw std::runtime_error("bip110 M2: coinb1 too short to hold h2");
    Bytes32 h2;
    std::memcpy(h2.data(), coinb1.data() + 4, 32);
    return h2;
}

// Re-materialise the full 164-byte v2 header from the frozen fields plus the
// miner's rolled nonce/extranonce. nonce8/ntime8 are 8-byte big-endian buffers:
//   nonce8: [0..3] high -> m_nonce2, [4..7] low -> nNonce
//   ntime8: [0..3] high -> m_nonce3, [4..7] low -> wire time area
// (i.e. an 8-byte submit hex "HHHHHHHHLLLLLLLL" splits low4/high4). A 4-byte
// submit fills only the low half; the high half stays whatever the caller
// zero-initialised. en1/en2 are the 4-byte extranonce halves.
inline std::vector<unsigned char> rebuild_header_v2(
    const HeaderFreeze& f,
    const std::array<unsigned char, 4>& en1,
    const std::array<unsigned char, 4>& en2,
    const std::array<unsigned char, 8>& nonce8,
    const std::array<unsigned char, 8>& ntime8)
{
    if (!f.derived)
        throw std::runtime_error("bip110 M2: rebuild_header_v2 before compute_h1_h2");

    const auto extranonce16 = make_extranonce16(en1, en2);

    std::vector<unsigned char> h;
    h.reserve(pow::V2_HEADER_SIZE);
    auto put = [&](const unsigned char* p, size_t n) { h.insert(h.end(), p, p + n); };

    put(f.version.data(), 4);
    put(f.prev.data(), 32);
    put(f.merkle.data(), 32);
    // time (wire time area) = ntime8 low 4 bytes, big-endian -> little-endian wire
    unsigned char t[4]  = { ntime8[7], ntime8[6], ntime8[5], ntime8[4] };
    put(t, 4);
    put(f.nbits.data(), 4);
    // nNonce = nonce8 low 4 (BE) -> LE wire
    unsigned char nn[4] = { nonce8[7], nonce8[6], nonce8[5], nonce8[4] };
    put(nn, 4);
    // m_nonce2 = nonce8 high 4 (BE) -> LE wire
    unsigned char n2[4] = { nonce8[3], nonce8[2], nonce8[1], nonce8[0] };
    put(n2, 4);
    // m_nonce3 = ntime8 high 4 (BE) -> LE wire
    unsigned char n3[4] = { ntime8[3], ntime8[2], ntime8[1], ntime8[0] };
    put(n3, 4);
    put(extranonce16.data(), 16);
    // m_time_offset = 0 (no time-roll in M2; R3)
    unsigned char zero4[4] = {0,0,0,0};
    put(zero4, 4);
    unsigned char tc[2] = { static_cast<unsigned char>(f.txcount & 0xff),
                            static_cast<unsigned char>((f.txcount >> 8) & 0xff) };
    put(tc, 2);
    put(&f.flags, 1);
    put(&f.clear_bits, 1);
    put(f.xor_key.data(), 16);
    unsigned char he[4] = { static_cast<unsigned char>(f.height & 0xff),
                            static_cast<unsigned char>((f.height >> 8) & 0xff),
                            static_cast<unsigned char>((f.height >> 16) & 0xff),
                            static_cast<unsigned char>((f.height >> 24) & 0xff) };
    put(he, 4);
    put(f.mm_rhs.data(), 32);
    // h.size() == 164
    return h;
}

// hex helpers (lower-case, no 0x) — shared by the KAT and the work source.
inline std::string to_hex(std::span<const unsigned char> b)
{
    static const char* H = "0123456789abcdef";
    std::string s; s.reserve(b.size() * 2);
    for (unsigned char c : b) { s += H[c >> 4]; s += H[c & 0xf]; }
    return s;
}

inline std::vector<unsigned char> from_hex(const std::string& s)
{
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    std::vector<unsigned char> o; o.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        o.push_back(static_cast<unsigned char>((nib(s[i]) << 4) | nib(s[i + 1])));
    return o;
}

} // namespace bip110::stratum
