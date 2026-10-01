// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// GAP-2 KAT helpers: a synthetic, byte-exact Monero block whose coinbase has the
// v37 lane shape (0x01 R | 0x02 [extra_nonce | (rbind) | pad | V37C tail] |
// 0x03 MM root), deterministic payees (valid ed25519 points), and a tiny check
// harness. Test-only.
#pragma once

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <c2pool/v37/xmr/relay/xmr_relay_wire.hpp>
#include <c2pool/v37/xmr/relay/xmr_receipt_mint.hpp>
#include "impl/xmr/coin/xmr_blob.hpp"
#include "impl/xmr/coin/xmr_derivation.hpp"

namespace gap2test {

using namespace c2pool::v37n::xmr::relay;

struct Checker {
    int pass = 0, fail = 0;
    void operator()(bool ok, const std::string& what) {
        if (ok) ++pass; else ++fail;
        std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what.c_str());
        std::fflush(stdout);
    }
    int done(const char* name) const {
        std::printf("== %s: %s (%d/%d passed) ==\n", name, fail ? "FAIL" : "OK", pass, pass + fail);
        return fail ? 1 : 0;
    }
};

inline void put_varint(std::vector<u8>& b, std::uint64_t v) {
    while (v >= 0x80) { b.push_back(static_cast<u8>((v & 0x7f) | 0x80)); v >>= 7; }
    b.push_back(static_cast<u8>(v));
}

inline bytes32 b32_of(u8 seed) { bytes32 b{}; for (int i = 0; i < 32; ++i) b[i] = static_cast<u8>(seed * 31 + i * 7 + 1); return b; }

// A valid XMR_STD payee from a label (s*G for spend and view, like the daemon's owed-demo keys).
inline ::v37::ScriptRef payee_of(const std::string& label) {
    std::array<std::uint8_t, 32> B{}, A{};
    for (int k = 0; k < 2; ++k) {
        const std::string d = (k ? "gap2-view#" : "gap2-spend#") + label;
        ::xmr::coin::EcScalar es{};
        ::xmr::coin::hash_to_scalar(d.data(), d.size(), es);
        ::xmr::coin::SecretKey sk{}; std::memcpy(sk.data(), es.data(), 32);
        ::xmr::coin::PublicKey pk{};
        (void)::xmr::coin::secret_key_to_public_key(sk, pk);
        std::memcpy(k ? A.data() : B.data(), pk.data(), 32);
    }
    return ::v37::xmr::make_xmr_std(B, A);
}

inline SideDataV2 side_for(const ::v37::ScriptRef& payee, u32 chain, u64 share_diff, u16 give_author = 0) {
    SideDataV2 s;
    s.t_lo = share_diff; s.identity = ::v37::xmr::xmr_identity_key(payee); s.chain_id = chain; s.give_author = give_author;
    return s;
}

struct SynthBlock {
    std::vector<u8> full_blob;      // header | miner_tx | varint n | n hashes   (nonce field = 0)
    std::vector<u8> hashing_blob;   // header | tree_root | varint(n+1)         (nonce field = 0)
    std::size_t     nonce_offset = 0;
    bytes32         prev_id{};
    std::uint64_t   height = 0;
};

// rbind: when non-null, the 0x02 payload is [extra_nonce | rbind | pad | V37C tail]
// (the SEAM-1 layout); else [extra_nonce | pad | V37C tail] (today's template).
inline SynthBlock make_block(std::uint64_t height, const bytes32& prev_id, std::uint32_t extra_nonce,
                             const bytes32* rbind, std::size_t n_other_tx, u8 salt) {
    SynthBlock sb; sb.prev_id = prev_id; sb.height = height;
    std::vector<u8> hdr;
    put_varint(hdr, 16); put_varint(hdr, 16); put_varint(hdr, 1700000000ull + height);
    hdr.insert(hdr.end(), prev_id.begin(), prev_id.end());
    sb.nonce_offset = hdr.size();
    for (int i = 0; i < 4; ++i) hdr.push_back(0);
    // miner_tx prefix
    std::vector<u8> pre;
    put_varint(pre, 2); put_varint(pre, height + 60); put_varint(pre, 1); pre.push_back(0xff); put_varint(pre, height);
    put_varint(pre, 1); put_varint(pre, 600000000000ull + salt); pre.push_back(0x03);
    const bytes32 k = b32_of(static_cast<u8>(salt + 3)); pre.insert(pre.end(), k.begin(), k.end()); pre.push_back(0x5a);
    std::vector<u8> extra;
    extra.push_back(0x01); { const bytes32 R = b32_of(static_cast<u8>(salt + 9)); extra.insert(extra.end(), R.begin(), R.end()); }
    std::vector<u8> nonce;
    for (int i = 0; i < 4; ++i) nonce.push_back(static_cast<u8>(extra_nonce >> (8 * i)));
    if (rbind) nonce.insert(nonce.end(), rbind->begin(), rbind->end());
    for (int i = 0; i < 3; ++i) nonce.push_back(0);                          // weight padding
    const char tail[4] = {'V', '3', '7', 'C'}; nonce.insert(nonce.end(), tail, tail + 4);
    for (int i = 0; i < 8; ++i) nonce.push_back(static_cast<u8>(i + 1));      // P
    { const bytes32 sp = b32_of(static_cast<u8>(salt + 17)); nonce.insert(nonce.end(), sp.begin(), sp.end()); }
    extra.push_back(0x02); put_varint(extra, nonce.size()); extra.insert(extra.end(), nonce.begin(), nonce.end());
    extra.push_back(0x03); extra.push_back(0x21); extra.push_back(0x00);
    { const bytes32 mm = b32_of(static_cast<u8>(salt + 23)); extra.insert(extra.end(), mm.begin(), mm.end()); }
    put_varint(pre, extra.size()); pre.insert(pre.end(), extra.begin(), extra.end());
    // leaves
    std::vector<::xmr::coin::Hash256> leaves;
    leaves.push_back(::xmr::coin::coinbase_tx_hash(::xmr::coin::tx_prefix_hash(pre)));
    std::vector<bytes32> others;
    for (std::size_t i = 0; i < n_other_tx; ++i) {
        bytes32 h = b32_of(static_cast<u8>(salt + 40 + i));
        others.push_back(h);
        ::xmr::coin::Hash256 hh; std::memcpy(hh.data(), h.data(), 32); leaves.push_back(hh);
    }
    const auto root = ::xmr::coin::tree_root(leaves);
    sb.full_blob = hdr;
    sb.full_blob.insert(sb.full_blob.end(), pre.begin(), pre.end());
    sb.full_blob.push_back(0x00);   // rct_type RCTTypeNull
    put_varint(sb.full_blob, others.size());
    for (const auto& h : others) sb.full_blob.insert(sb.full_blob.end(), h.begin(), h.end());
    sb.hashing_blob = hdr;
    sb.hashing_blob.insert(sb.hashing_blob.end(), root.data(), root.data() + 32);
    put_varint(sb.hashing_blob, leaves.size());
    return sb;
}

inline std::vector<u8> with_nonce(const SynthBlock& sb, std::uint32_t nonce) {
    std::vector<u8> h = sb.hashing_blob;
    for (int i = 0; i < 4; ++i) h[sb.nonce_offset + i] = static_cast<u8>(nonce >> (8 * i));
    return h;
}

// Mint a relay receipt for `payee` on a fresh synthetic block.
inline bool mint_on(const SynthBlock& sb, std::uint32_t nonce, const ::v37::ScriptRef& payee, u32 chain,
                    u64 share_diff, FbReceipt& out, std::string* why = nullptr, u16 give_author = 0) {
    return mint_receipt(sb.full_blob, with_nonce(sb, nonce), side_for(payee, chain, share_diff, give_author), payee, out, why);
}

inline std::string hex(const std::vector<u8>& v) {
    static const char* d = "0123456789abcdef";
    std::string s; for (u8 b : v) { s.push_back(d[b >> 4]); s.push_back(d[b & 15]); } return s;
}
inline std::string hex(const bytes32& v) { return hex(std::vector<u8>(v.begin(), v.end())); }

} // namespace gap2test
