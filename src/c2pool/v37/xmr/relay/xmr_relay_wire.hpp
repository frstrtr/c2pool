// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/relay/xmr_relay_wire.hpp
//
// The kept Family-B relay frames of the Path B relay node (on the carrier_net.hpp
// CarrierPeerNode framing [u32 LE len][frame]; the first byte is the opcode):
//
//     0x43 FB_GETCTX     ask for Monero blocks by id (u8 n <= 8 ids)
//     0x44 FB_CTX        one Monero block blob (<= 512 KiB) or none
//     0x48 FB_PING       keepalive probe (u64 nonce)
//     0x49 FB_PONG       its echo (same nonce)
//     0x4a / 0x4b        reserved
//     0x4c FB_GETADDR    ask for relay addresses of this pool
//     0x4d FB_ADDR       the answer: <= 256 x (family, ip, port, last_seen)
//
// Path B's own frames (HELLO 0x40, FB_RECEIPTS 0x41, family C 0x50-0x55) are in
// impl/xmr/pathb/pathb_relay_wire.hpp. Every integer is little-endian; every
// decoder is total and bounded.
// ===========================================================================
#pragma once

#include <arpa/inet.h>   // inet_pton / inet_ntop
#include <netinet/in.h>
#include <sys/socket.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <sharechain/v37/v37_hash.hpp>             // ::v37::bytes32
#include "impl/xmr/coin/xmr_keccak_midstate.hpp"   // ::xmr::coin::keccak256

namespace c2pool::v37n::xmr::relay {

using u8  = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using bytes32 = ::v37::bytes32;

inline constexpr u8  FB_GETCTX    = 0x43;
inline constexpr u8  FB_CTX       = 0x44;
inline constexpr u8  FB_PING      = 0x48;
inline constexpr u8  FB_PONG      = 0x49;
// 0x4a / 0x4b are reserved: never reuse them here.
inline constexpr u8  FB_GETADDR   = 0x4c;
inline constexpr u8  FB_ADDR      = 0x4d;
inline constexpr u8  kFbVersion   = 0x01;

inline constexpr std::size_t kCtxMaxIds             = 8;                 // ids per FB_GETCTX
inline constexpr std::size_t kCtxHeader             = 1 + 1 + 4 + 32 + 4; // op ver chain id len

// ── little-endian helpers ───────────────────────────────────────────────────
namespace le {
inline void put16(std::vector<u8>& b, u16 v) { b.push_back(u8(v)); b.push_back(u8(v >> 8)); }
inline void put32(std::vector<u8>& b, u32 v) { for (int i = 0; i < 4; ++i) b.push_back(u8(v >> (8 * i))); }
inline void put64(std::vector<u8>& b, u64 v) { for (int i = 0; i < 8; ++i) b.push_back(u8(v >> (8 * i))); }
inline void putb(std::vector<u8>& b, const bytes32& h) { b.insert(b.end(), h.begin(), h.end()); }
inline u16 get16(const u8* p) { return u16(p[0] | (u16(p[1]) << 8)); }
inline u32 get32(const u8* p) { u32 v = 0; for (int i = 0; i < 4; ++i) v |= u32(p[i]) << (8 * i); return v; }
inline u64 get64(const u8* p) { u64 v = 0; for (int i = 0; i < 8; ++i) v |= u64(p[i]) << (8 * i); return v; }
inline bytes32 getb(const u8* p) { bytes32 h; std::memcpy(h.data(), p, 32); return h; }
} // namespace le

inline bytes32 keccak_bytes(const std::vector<u8>& v) {
    const auto h = ::xmr::coin::keccak256(v.data(), v.size());
    bytes32 out; std::memcpy(out.data(), h.data(), 32); return out;
}

// ── FB_GETCTX (0x43) / FB_CTX (0x44) ───────────────────────────────────────
//   GETCTX : u8 0x43 ; u8 ver ; u32 chain_id ; u8 n (1..8) ; n x id(32)
//   CTX    : u8 0x44 ; u8 ver ; u32 chain_id ; id(32) ; u32 len (<= 512 KiB) ; blob
inline std::vector<u8> encode_getctx(u32 chain_id, const std::vector<bytes32>& ids) {
    if (ids.empty() || ids.size() > kCtxMaxIds) return {};
    std::vector<u8> f; f.reserve(7 + 32 * ids.size());
    f.push_back(FB_GETCTX); f.push_back(kFbVersion); le::put32(f, chain_id);
    f.push_back(static_cast<u8>(ids.size()));
    for (const auto& id : ids) le::putb(f, id);
    return f;
}
inline bool decode_getctx(const std::vector<u8>& f, u32& chain_id, std::vector<bytes32>& ids, std::string* why = nullptr) {
    auto bad = [&](const char* m) { if (why) *why = m; return false; };
    if (f.size() < 7) return bad("getctx: short");
    if (f[0] != FB_GETCTX) return bad("getctx: wrong opcode");
    if (f[1] != kFbVersion) return bad("getctx: unknown version");
    chain_id = le::get32(f.data() + 2);
    const std::size_t n = f[6];
    if (n == 0 || n > kCtxMaxIds) return bad("getctx: n out of range (1..8)");
    if (f.size() != 7 + 32 * n) return bad("getctx: wrong length");
    ids.clear();
    for (std::size_t i = 0; i < n; ++i) ids.push_back(le::getb(f.data() + 7 + 32 * i));
    return true;
}
// cap: the blob cap (P-13: blob_cap_ctx(hf, Z), the caller's).
inline std::vector<u8> encode_ctx(u32 chain_id, const bytes32& id, const std::vector<u8>& blob, std::size_t cap) {
    if (blob.size() > cap || blob.size() > UINT32_MAX) return {};
    std::vector<u8> f; f.reserve(kCtxHeader + blob.size());
    f.push_back(FB_CTX); f.push_back(kFbVersion); le::put32(f, chain_id); le::putb(f, id);
    le::put32(f, static_cast<u32>(blob.size()));
    f.insert(f.end(), blob.begin(), blob.end());
    return f;
}
inline bool decode_ctx(const std::vector<u8>& f, u32& chain_id, bytes32& id, std::vector<u8>& blob, std::size_t cap,
                       std::string* why = nullptr) {
    auto bad = [&](const char* m) { if (why) *why = m; return false; };
    if (f.size() < kCtxHeader) return bad("ctx: short");
    if (f[0] != FB_CTX) return bad("ctx: wrong opcode");
    if (f[1] != kFbVersion) return bad("ctx: unknown version");
    chain_id = le::get32(f.data() + 2);
    id = le::getb(f.data() + 6);
    const std::size_t len = le::get32(f.data() + 38);
    if (len > cap) return bad("ctx: blob over the cap");
    if (f.size() != kCtxHeader + len) return bad("ctx: wrong length");
    blob.assign(f.begin() + static_cast<std::ptrdiff_t>(kCtxHeader), f.end());
    return true;
}

// ── FB_PING (0x48) / FB_PONG (0x49): keepalive ──────────────────────────────
//   PING : u8 0x48 ; u8 ver ; u64 nonce      (10 B)
//   PONG : u8 0x49 ; u8 ver ; u64 nonce      (10 B, the PING nonce echoed)
inline constexpr std::size_t kPingBytes = 1 + 1 + 8;
inline std::vector<u8> encode_ping(u8 op, u64 nonce) {
    if (op != FB_PING && op != FB_PONG) return {};
    std::vector<u8> f; f.reserve(kPingBytes);
    f.push_back(op); f.push_back(kFbVersion); le::put64(f, nonce);
    return f;
}
inline bool decode_ping(const std::vector<u8>& f, u8& op, u64& nonce, std::string* why = nullptr) {
    auto bad = [&](const char* m) { if (why) *why = m; return false; };
    if (f.size() != kPingBytes) return bad("ping: wrong length");
    if (f[0] != FB_PING && f[0] != FB_PONG) return bad("ping: wrong opcode");
    if (f[1] != kFbVersion) return bad("ping: unknown version");
    op = f[0];
    nonce = le::get64(f.data() + 2);
    return true;
}

// ── FB_GETADDR (0x4c) / FB_ADDR (0x4d): relay addresses of this pool ─────────
//   GETADDR : u8 0x4c ; u8 ver ; u32 chain_id ; u16 want (1..256)          (8 B)
//   ADDR    : u8 0x4d ; u8 ver ; u32 chain_id ; u16 n (0..256) ; n x entry
//   entry   : u8 family (4|6) ; ip 16 B (IPv4 = 4 B + 12 zero B) ; u16 port (!= 0) ; u64 last_seen (unix s)
inline constexpr std::size_t kAddrMaxEntries  = 256;
inline constexpr std::size_t kGetAddrBytes    = 1 + 1 + 4 + 2;
inline constexpr std::size_t kAddrHeader      = 1 + 1 + 4 + 2;
inline constexpr std::size_t kAddrEntryBytes  = 1 + 16 + 2 + 8;
inline constexpr std::size_t kAddrMaxFrame    = kAddrHeader + kAddrMaxEntries * kAddrEntryBytes;
inline constexpr u8          kAddrFamV4 = 4, kAddrFamV6 = 6;

struct AddrEntry {
    u8 family = kAddrFamV4;
    std::array<u8, 16> ip{};
    u16 port = 0;
    u64 last_seen = 0;
    bool operator==(const AddrEntry&) const = default;
};

// "a.b.c.d" / IPv6 literal -> entry. false on anything else (no DNS here).
inline bool addr_entry_of(const std::string& host, u16 port, u64 last_seen, AddrEntry& e) {
    e = AddrEntry{}; e.port = port; e.last_seen = last_seen;
    in_addr a4{};
    if (::inet_pton(AF_INET, host.c_str(), &a4) == 1) { e.family = kAddrFamV4; std::memcpy(e.ip.data(), &a4, 4); return port != 0; }
    in6_addr a6{};
    if (::inet_pton(AF_INET6, host.c_str(), &a6) == 1) { e.family = kAddrFamV6; std::memcpy(e.ip.data(), &a6, 16); return port != 0; }
    return false;
}
inline std::string addr_host(const AddrEntry& e) {
    char b[INET6_ADDRSTRLEN] = {0};
    if (e.family == kAddrFamV4) ::inet_ntop(AF_INET, e.ip.data(), b, sizeof b);
    else ::inet_ntop(AF_INET6, e.ip.data(), b, sizeof b);
    return b;
}
// Publicly routable? false for unspecified, loopback, RFC1918, CGNAT, link-local,
// multicast / reserved (v4) and ::, ::1, fc00::/7, fe80::/10, ff00::/8, v4-mapped
// private (v6). A private address is never handed to a public peer.
inline bool addr_routable(const AddrEntry& e) {
    const u8* p = e.ip.data();
    auto v4 = [](const u8* q) {
        if (q[0] == 0 || q[0] == 10 || q[0] == 127 || q[0] >= 224) return false;
        if (q[0] == 169 && q[1] == 254) return false;
        if (q[0] == 172 && (q[1] & 0xf0) == 16) return false;
        if (q[0] == 192 && q[1] == 168) return false;
        if (q[0] == 100 && (q[1] & 0xc0) == 64) return false;
        return true;
    };
    if (e.family == kAddrFamV4) return v4(p);
    static const u8 mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    if (std::memcmp(p, mapped, 12) == 0) return v4(p + 12);
    bool zero15 = true;
    for (int i = 0; i < 15; ++i) zero15 = zero15 && p[i] == 0;
    if (zero15 && (p[15] == 0 || p[15] == 1)) return false;          // :: and ::1
    if ((p[0] & 0xfe) == 0xfc) return false;                          // fc00::/7
    if (p[0] == 0xfe && (p[1] & 0xc0) == 0x80) return false;          // fe80::/10
    if (p[0] == 0xff) return false;                                   // multicast
    return true;
}

inline std::vector<u8> encode_getaddr(u32 chain_id, u16 want) {
    if (want == 0 || want > kAddrMaxEntries) return {};
    std::vector<u8> f; f.reserve(kGetAddrBytes);
    f.push_back(FB_GETADDR); f.push_back(kFbVersion); le::put32(f, chain_id); le::put16(f, want);
    return f;
}
inline bool decode_getaddr(const std::vector<u8>& f, u32& chain_id, u16& want, std::string* why = nullptr) {
    auto bad = [&](const char* m) { if (why) *why = m; return false; };
    if (f.size() != kGetAddrBytes) return bad("getaddr: wrong length");
    if (f[0] != FB_GETADDR) return bad("getaddr: wrong opcode");
    if (f[1] != kFbVersion) return bad("getaddr: unknown version");
    chain_id = le::get32(f.data() + 2);
    want = le::get16(f.data() + 6);
    if (want == 0 || want > kAddrMaxEntries) return bad("getaddr: want out of range");
    return true;
}
inline std::vector<u8> encode_addr(u32 chain_id, const std::vector<AddrEntry>& v) {
    if (v.size() > kAddrMaxEntries) return {};
    std::vector<u8> f; f.reserve(kAddrHeader + v.size() * kAddrEntryBytes);
    f.push_back(FB_ADDR); f.push_back(kFbVersion); le::put32(f, chain_id); le::put16(f, static_cast<u16>(v.size()));
    for (const auto& e : v) {
        if ((e.family != kAddrFamV4 && e.family != kAddrFamV6) || e.port == 0) return {};
        f.push_back(e.family);
        if (e.family == kAddrFamV4) { f.insert(f.end(), e.ip.begin(), e.ip.begin() + 4); f.insert(f.end(), 12, 0); }
        else f.insert(f.end(), e.ip.begin(), e.ip.end());
        le::put16(f, e.port); le::put64(f, e.last_seen);
    }
    return f;
}
inline bool decode_addr(const std::vector<u8>& f, u32& chain_id, std::vector<AddrEntry>& out, std::string* why = nullptr) {
    auto bad = [&](const char* m) { if (why) *why = m; return false; };
    out.clear();
    if (f.size() < kAddrHeader || f.size() > kAddrMaxFrame) return bad("addr: wrong length");
    if (f[0] != FB_ADDR) return bad("addr: wrong opcode");
    if (f[1] != kFbVersion) return bad("addr: unknown version");
    chain_id = le::get32(f.data() + 2);
    const std::size_t n = le::get16(f.data() + 6);
    if (n > kAddrMaxEntries) return bad("addr: too many entries");
    if (f.size() != kAddrHeader + n * kAddrEntryBytes) return bad("addr: length != n entries");
    out.reserve(n);
    const u8* p = f.data() + kAddrHeader;
    for (std::size_t i = 0; i < n; ++i, p += kAddrEntryBytes) {
        AddrEntry e;
        e.family = p[0];
        if (e.family != kAddrFamV4 && e.family != kAddrFamV6) { out.clear(); return bad("addr: unknown family"); }
        std::memcpy(e.ip.data(), p + 1, 16);
        if (e.family == kAddrFamV4)
            for (int k = 4; k < 16; ++k) if (e.ip[k] != 0) { out.clear(); return bad("addr: ipv4 padding not zero"); }
        e.port = le::get16(p + 17);
        if (e.port == 0) { out.clear(); return bad("addr: port 0"); }
        e.last_seen = le::get64(p + 19);
        out.push_back(e);
    }
    return true;
}

} // namespace c2pool::v37n::xmr::relay
