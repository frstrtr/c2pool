// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/relay/xmr_address.hpp   (GAP-2 stage 1)
//
// Monero base58 address -> XMR payout ScriptRef (XMR_STD / XMR_SUB). The
// stratum layer hands the minter the miner's raw login address; the receipt it
// mints must name a payee REF, so the address boundary is crossed here, once.
//
// Monero base58 (monero-project src/common/base58.cpp): the payload is cut into
// 8-byte blocks, each encoded as 11 characters (a short tail block uses
// encoded_block_sizes[len]); every block is a big-endian integer. The decoded
// payload is varint(prefix) || spend_pub(32) || view_pub(32) [|| payment_id(8)
// for integrated] || checksum(4), checksum = keccak256(everything before)[0..4).
// Network prefixes (cryptonote_config.h):
//     mainnet  18 std / 19 integrated / 42 subaddress   (also regtest/FAKECHAIN)
//     testnet  53     / 54            / 63
//     stagenet 24     / 25            / 36
// An integrated address pays its (spend, view) pair (the payment id is not a
// coinbase concept). The point validity check (ed25519 + torsion) is NOT done
// here: the ref goes through ::v37::xmr::xmr_ref_valid at admission like every
// other payee.
// ===========================================================================
#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include <sharechain/v37/v37_descriptor_xmr.hpp>
#include "impl/xmr/coin/xmr_keccak_midstate.hpp"

namespace c2pool::v37n::xmr::relay {

namespace b58 {
inline constexpr char kAlphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
inline constexpr int  kEncodedBlockSizes[] = {0, 2, 3, 5, 6, 7, 9, 10, 11};
inline constexpr int  kFullBlock = 8, kFullEncoded = 11;

inline int digit(char c) {
    for (int i = 0; i < 58; ++i) if (kAlphabet[i] == c) return i;
    return -1;
}
// Decode one encoded block of `n` chars into `out_len` bytes (big-endian).
inline bool decode_block(const char* s, int n, int out_len, std::uint8_t* out) {
    unsigned __int128 v = 0;
    for (int i = 0; i < n; ++i) {
        const int d = digit(s[i]);
        if (d < 0) return false;
        v = v * 58 + static_cast<unsigned>(d);
    }
    if (out_len < 8 && (v >> (8 * out_len)) != 0) return false;   // overflow for a short block
    if (v >> 64) return false;
    const std::uint64_t x = static_cast<std::uint64_t>(v);
    for (int i = 0; i < out_len; ++i) out[out_len - 1 - i] = static_cast<std::uint8_t>(x >> (8 * i));
    return true;
}
inline std::optional<std::vector<std::uint8_t>> decode(const std::string& s) {
    const std::size_t full = s.size() / kFullEncoded, rem = s.size() % kFullEncoded;
    int rem_bytes = -1;
    for (int i = 0; i <= kFullBlock; ++i) if (static_cast<std::size_t>(kEncodedBlockSizes[i]) == rem) rem_bytes = i;
    if (rem_bytes < 0) return std::nullopt;
    std::vector<std::uint8_t> out(full * kFullBlock + static_cast<std::size_t>(rem_bytes));
    for (std::size_t b = 0; b < full; ++b)
        if (!decode_block(s.data() + b * kFullEncoded, kFullEncoded, kFullBlock, out.data() + b * kFullBlock))
            return std::nullopt;
    if (rem_bytes > 0 &&
        !decode_block(s.data() + full * kFullEncoded, static_cast<int>(rem), rem_bytes, out.data() + full * kFullBlock))
        return std::nullopt;
    return out;
}
} // namespace b58

struct DecodedAddress {
    std::uint64_t prefix = 0;
    bool subaddress = false, integrated = false;
    std::array<std::uint8_t, 32> spend{}, view{};
    ::v37::ScriptRef ref() const {
        return subaddress ? ::v37::xmr::make_xmr_sub(spend, view) : ::v37::xmr::make_xmr_std(spend, view);
    }
};

// Decode + checksum-check. Any network's prefix is accepted (the caller pins the
// network if it cares); nullopt on a malformed / checksum-failing string.
inline std::optional<DecodedAddress> decode_address(const std::string& addr) {
    const auto raw = b58::decode(addr);
    if (!raw || raw->size() < 1 + 64 + 4) return std::nullopt;
    const auto& b = *raw;
    // checksum
    const auto h = ::xmr::coin::keccak256(b.data(), b.size() - 4);
    if (std::memcmp(h.data(), b.data() + b.size() - 4, 4) != 0) return std::nullopt;
    // varint prefix
    std::size_t pos = 0; std::uint64_t pfx = 0; int shift = 0;
    for (;;) {
        if (pos >= b.size() || shift > 56) return std::nullopt;
        const std::uint8_t c = b[pos++];
        pfx |= static_cast<std::uint64_t>(c & 0x7f) << shift;
        if (!(c & 0x80)) break;
        shift += 7;
    }
    DecodedAddress d; d.prefix = pfx;
    switch (pfx) {
        case 18: case 53: case 24: break;
        case 19: case 54: case 25: d.integrated = true; break;
        case 42: case 63: case 36: d.subaddress = true; break;
        default: return std::nullopt;
    }
    const std::size_t body = b.size() - 4 - pos;
    if (body != (d.integrated ? 72u : 64u)) return std::nullopt;
    std::memcpy(d.spend.data(), b.data() + pos, 32);
    std::memcpy(d.view.data(), b.data() + pos + 32, 32);
    return d;
}

// XMR-WEB: the inverse of decode_address, for DISPLAY only (the dashboard
// names a ledger payee by the address its ScriptRef was learned from). Builds
// varint(prefix) || spend || view || keccak256(...)[0..4) in Monero base58.
inline std::string encode_address(std::uint64_t prefix, const std::uint8_t* spend32, const std::uint8_t* view32) {
    std::vector<std::uint8_t> b;
    for (std::uint64_t v = prefix;;) {
        const std::uint8_t c = static_cast<std::uint8_t>(v & 0x7f);
        v >>= 7;
        if (v) { b.push_back(c | 0x80); } else { b.push_back(c); break; }
    }
    b.insert(b.end(), spend32, spend32 + 32);
    b.insert(b.end(), view32, view32 + 32);
    const auto h = ::xmr::coin::keccak256(b.data(), b.size());
    b.insert(b.end(), h.data(), h.data() + 4);
    std::string out;
    for (std::size_t off = 0; off < b.size(); off += b58::kFullBlock) {
        const int n = static_cast<int>(std::min<std::size_t>(b58::kFullBlock, b.size() - off));
        std::uint64_t v = 0;
        for (int i = 0; i < n; ++i) v = (v << 8) | b[off + i];
        std::string blk(static_cast<std::size_t>(b58::kEncodedBlockSizes[n]), b58::kAlphabet[0]);
        for (int i = static_cast<int>(blk.size()) - 1; i >= 0 && v; --i) { blk[i] = b58::kAlphabet[v % 58]; v /= 58; }
        out += blk;
    }
    return out;
}

// A payout ScriptRef (XMR_STD / XMR_SUB, 64-byte payload) as its address under
// the given network prefixes; "" for any other ref (e.g. the RAW sentinel).
inline std::string address_of(const ::v37::ScriptRef& r, std::uint64_t std_prefix, std::uint64_t sub_prefix) {
    if (r.payload.size() != 64) return {};
    if (r.kind == ::v37::xmr::XMR_STD) return encode_address(std_prefix, r.payload.data(), r.payload.data() + 32);
    if (r.kind == ::v37::xmr::XMR_SUB) return encode_address(sub_prefix, r.payload.data(), r.payload.data() + 32);
    return {};
}

} // namespace c2pool::v37n::xmr::relay
