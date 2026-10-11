// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/c2pool/v37/xmr/pathb/pathb_policy.hpp
// The node policy helpers of the stratum and the start line (no ledger):
//   ExactPct / parse_pct_exact   a percentage from text, integers only
//   pct_to_bp                    round-half-up basis points, clamped to 10000
//   give_author_u16              round-half-up of 65535 x pct / 100
//   decode_xmr_address           CryptoNote base58, the keccak checksum and
//                                the network byte; standard and subaddress
//   payee_refusal                a login payee: XMR_STD only (a subaddress or
//                                an integrated address is refused)
// Moved here from xmr_fee_model.hpp, which re-exports them unchanged.
//
// Header-only.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <sharechain/v37/v37_descriptor_xmr.hpp>  // ScriptRef, make_xmr_std

#include "impl/xmr/coin/xmr_keccak_midstate.hpp"  // ::xmr::coin::keccak256

namespace c2pool::xmr::pathb::policy {

// ---------------------------------------------------------------------------
// Percentages from text, integers only (DIGITS[.DIGITS], at most 9 decimals)
// ---------------------------------------------------------------------------
struct ExactPct {
    std::uint64_t num = 0;
    std::uint64_t den = 1;
    bool ok = false;
};

inline constexpr std::size_t kPctMaxDecimals = 9;
inline constexpr std::uint64_t kPctIntLimit = 1000000000ull;
inline constexpr std::uint32_t kBasisPointsMax = 10000;
inline constexpr std::uint32_t kGiveAuthorScale = 65535;

inline ExactPct parse_pct_exact(const std::string& t) {
    ExactPct r;
    std::size_t i = 0, int_digits = 0, frac_digits = 0;
    std::uint64_t num = 0, den = 1;
    for (; i < t.size() && t[i] >= '0' && t[i] <= '9'; ++i, ++int_digits) {
        if (num > kPctIntLimit) return r;
        num = num * 10 + static_cast<std::uint64_t>(t[i] - '0');
    }
    if (i < t.size() && t[i] == '.') {
        for (++i; i < t.size() && t[i] >= '0' && t[i] <= '9'; ++i, ++frac_digits) {
            if (frac_digits == kPctMaxDecimals) return r;
            num = num * 10 + static_cast<std::uint64_t>(t[i] - '0');
            den *= 10;
        }
        if (frac_digits == 0) return r;
    }
    if (i != t.size() || int_digits == 0) return r;
    r.num = num;
    r.den = den;
    r.ok = true;
    return r;
}

// round-half-up(10000 x num / (100 x den)) basis points, clamped to [0, 10000].
inline std::uint32_t pct_to_bp(const ExactPct& p) {
    if (!p.ok || p.num == 0) return 0;
    const unsigned __int128 v = (static_cast<unsigned __int128>(p.num) * 200u + p.den) / (2u * p.den);
    return static_cast<std::uint32_t>(v > kBasisPointsMax ? kBasisPointsMax : v);
}

// round-half-up(65535 x num / (100 x den)), clamped to [0, 65535].
inline std::uint16_t give_author_u16(const ExactPct& p) {
    if (!p.ok || p.num == 0) return 0;
    const unsigned __int128 n = static_cast<unsigned __int128>(kGiveAuthorScale) * p.num * 2 + 100u * p.den;
    const unsigned __int128 d = static_cast<unsigned __int128>(200u) * p.den;
    const unsigned __int128 v = n / d;
    return static_cast<std::uint16_t>(v > kGiveAuthorScale ? kGiveAuthorScale : v);
}

// ---------------------------------------------------------------------------
// Monero addresses
// ---------------------------------------------------------------------------
// Monero address network bytes (cryptonote_config.h).
inline constexpr std::uint64_t kPrefixMainnetStd = 18, kPrefixMainnetInt = 19, kPrefixMainnetSub = 42;
inline constexpr std::uint64_t kPrefixTestnetStd = 53, kPrefixTestnetInt = 54, kPrefixTestnetSub = 63;
inline constexpr std::uint64_t kPrefixStagenetStd = 24, kPrefixStagenetInt = 25, kPrefixStagenetSub = 36;

namespace addr_detail {
inline constexpr char kAlphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
inline constexpr int kAlphabetSize = 58;
inline constexpr int kEncSizes[9] = {0, 2, 3, 5, 6, 7, 9, 10, 11};
inline constexpr std::size_t kFullBlockChars = 11;
inline constexpr std::size_t kFullBlockBytes = 8;
inline constexpr std::size_t kChecksumBytes = 4;

inline int digit_of(char c) {
    for (int i = 0; i < kAlphabetSize; ++i)
        if (kAlphabet[i] == c) return i;
    return -1;
}

inline bool decode_block(const char* s, std::size_t n, std::vector<std::uint8_t>& out) {
    int res = -1;
    for (int i = 0; i < 9; ++i)
        if (kEncSizes[i] == static_cast<int>(n)) {
            res = i;
            break;
        }
    if (res <= 0) return false;
    unsigned __int128 num = 0;
    for (std::size_t i = 0; i < n; ++i) {
        const int d = digit_of(s[i]);
        if (d < 0) return false;
        num = num * kAlphabetSize + static_cast<unsigned>(d);
        if (num >> 64) return false;
    }
    if (res < static_cast<int>(kFullBlockBytes) && (num >> (8 * res)) != 0) return false;
    for (int i = res - 1; i >= 0; --i) out.push_back(static_cast<std::uint8_t>(num >> (8 * i)));
    return true;
}
}  // namespace addr_detail

inline bool cn_base58_decode(const std::string& s, std::vector<std::uint8_t>& out) {
    out.clear();
    const std::size_t full = s.size() / addr_detail::kFullBlockChars, rem = s.size() % addr_detail::kFullBlockChars;
    for (std::size_t i = 0; i < full; ++i)
        if (!addr_detail::decode_block(s.data() + addr_detail::kFullBlockChars * i, addr_detail::kFullBlockChars, out))
            return false;
    if (rem && !addr_detail::decode_block(s.data() + addr_detail::kFullBlockChars * full, rem, out)) return false;
    return true;
}

inline constexpr std::size_t kKeyBytes = 32;

struct DecodedAddress {
    bool ok = false;
    std::string why;
    std::uint64_t prefix = 0;
    bool subaddress = false;
    std::array<std::uint8_t, kKeyBytes> spend{};  // B (or D_i for a subaddress)
    std::array<std::uint8_t, kKeyBytes> view{};   // A (or C_i for a subaddress)
    // The XMR_STD payout reference. Only meaningful when ok && !subaddress (a
    // subaddress encodes (D_i, C_i); its main view key is not in the address).
    ::v37::ScriptRef ref() const { return ::v37::xmr::make_xmr_std(spend, view); }
};

// A standard address or a subaddress; an integrated address is refused (a
// payment id has no place in a coinbase payee). The keccak checksum and the
// varint network byte are verified.
inline DecodedAddress decode_xmr_address(const std::string& addr) {
    DecodedAddress d;
    std::vector<std::uint8_t> raw;
    if (!cn_base58_decode(addr, raw)) {
        d.why = "not CryptoNote base58";
        return d;
    }
    std::uint64_t pfx = 0;
    std::size_t i = 0;
    unsigned shift = 0;
    for (;; ++i) {
        if (i >= raw.size() || shift > 63) {
            d.why = "truncated varint prefix";
            return d;
        }
        pfx |= static_cast<std::uint64_t>(raw[i] & 0x7f) << shift;
        shift += 7;
        if (!(raw[i] & 0x80)) {
            ++i;
            break;
        }
    }
    if (raw.size() != i + 2 * kKeyBytes + addr_detail::kChecksumBytes) {
        d.why = "wrong length " + std::to_string(raw.size()) + " (integrated address or garbage)";
        return d;
    }
    const ::xmr::coin::Hash256 h = ::xmr::coin::keccak256(raw.data(), raw.size() - addr_detail::kChecksumBytes);
    if (std::memcmp(h.data(), raw.data() + raw.size() - addr_detail::kChecksumBytes, addr_detail::kChecksumBytes) != 0) {
        d.why = "checksum mismatch";
        return d;
    }
    switch (pfx) {
        case kPrefixMainnetStd:
        case kPrefixTestnetStd:
        case kPrefixStagenetStd: d.subaddress = false; break;
        case kPrefixMainnetSub:
        case kPrefixTestnetSub:
        case kPrefixStagenetSub: d.subaddress = true; break;
        default: d.why = "unsupported network byte " + std::to_string(pfx); return d;
    }
    d.prefix = pfx;
    std::memcpy(d.spend.data(), raw.data() + i, kKeyBytes);
    std::memcpy(d.view.data(), raw.data() + i + kKeyBytes, kKeyBytes);
    d.ok = true;
    return d;
}

// A login payee: "" = an XMR_STD address; else the refusal (a subaddress, an
// integrated address, or not an address).
inline std::string payee_refusal(const DecodedAddress& d) {
    if (!d.ok) return "payee: " + d.why;
    if (d.subaddress) return "payee: a subaddress is not a payee (standard addresses only)";
    return {};
}

}  // namespace c2pool::xmr::pathb::policy
