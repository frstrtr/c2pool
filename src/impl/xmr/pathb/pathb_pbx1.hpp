// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_pbx1.hpp
// PBX1: the coinbase tx_extra of a Path B template. Monero tags only, in
// Monero order:
//   hf < HF_VERSION_CARROT:   01 R_tx[32] | 02 04 extra_nonce[4] | 03 21 00 mm_root[32]       74 B
//   hf >= 17, n == 1:         01 D_e[32]  | 02 04 extra_nonce[4] | 03 21 00 mm_root[32]       74 B
//   hf >= 17, n >= 2:         04 varint(n) D_e[32 x n] | 02 04 extra_nonce[4] | 03 21 00 mm_root[32]
//                                                                                  42 + V(n) + 32 n B
// 0x01 TX_EXTRA_TAG_PUBKEY, 0x02 TX_EXTRA_NONCE, 0x03 TX_EXTRA_MERGE_MINING_TAG,
// 0x04 TX_EXTRA_TAG_ADDITIONAL_PUBKEYS; merge-mining depth 0; n <= FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS.
// The decoder accepts exactly these byte forms and nothing else.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "impl/xmr/coin/xmr_blob.hpp"   // TX_EXTRA_TAG_* (Monero tx_extra.h)

#include "pathb_wire_v3.hpp"

namespace c2pool::xmr::pathb {

inline constexpr std::uint8_t TX_EXTRA_TAG_PUBKEY = ::xmr::coin::TX_EXTRA_TAG_PUBKEY;
inline constexpr std::uint8_t TX_EXTRA_NONCE = ::xmr::coin::TX_EXTRA_TAG_NONCE;
inline constexpr std::uint8_t TX_EXTRA_MERGE_MINING_TAG = ::xmr::coin::TX_EXTRA_TAG_MERGE_MINING;
inline constexpr std::uint8_t TX_EXTRA_TAG_ADDITIONAL_PUBKEYS = ::xmr::coin::TX_EXTRA_TAG_ADDITIONAL_PUBKEYS;

// Merge-mining tag depth (lane format: no merge mining).
inline constexpr std::uint64_t kMergeMiningDepth = 0;
// Merge-mining field payload: varint depth || root.
inline constexpr std::uint64_t kMergeMiningFieldBytes = varint_len(kMergeMiningDepth) + kHashBytes;

enum class Pbx1Error : std::uint8_t {
    None = 0,
    OverCap,
    Truncated,
    KeyTag,              // first field is not the form for this hf
    KeyCount,            // additional-pubkey count < 2 or above FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS
    NonceTag,
    NonceLength,
    MergeMiningTag,
    MergeMiningLength,
    MergeMiningDepth,
    Trailing,
    Unencodable,
};

struct Pbx1 {
    std::vector<Hash32> keys;  // hf < 17: { R_tx }; hf >= 17: D_e in output order
    std::array<std::uint8_t, kExtraNonceBytes> extra_nonce{};
    Hash32 mm_root{};

    friend bool operator==(const Pbx1&, const Pbx1&) = default;
};

inline constexpr bool pbx1_carrot(std::uint8_t hf) noexcept { return hf >= HF_VERSION_CARROT; }

// Largest key count the format admits at this hf.
inline constexpr std::uint64_t pbx1_max_keys(std::uint8_t hf) noexcept {
    return pbx1_carrot(hf) ? FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS : 1;
}

// Byte size of the PBX1 extra for n keys.
inline constexpr std::uint64_t pbx1_size(std::uint8_t hf, std::uint64_t n) noexcept {
    const std::uint64_t keys = (!pbx1_carrot(hf) || n == 1)
                                       ? kU8Bytes + kHashBytes
                                       : kU8Bytes + varint_len(n) + n * kHashBytes;
    const std::uint64_t nonce = kU8Bytes + varint_len(kExtraNonceBytes) + kExtraNonceBytes;
    const std::uint64_t mm = kU8Bytes + varint_len(kMergeMiningFieldBytes) + kMergeMiningFieldBytes;
    return keys + nonce + mm;
}

inline Pbx1Error encode_pbx1(std::uint8_t hf, const Pbx1& x, std::vector<std::uint8_t>& out) {
    const std::uint64_t n = x.keys.size();
    if (n == 0 || n > pbx1_max_keys(hf)) return Pbx1Error::Unencodable;
    if (n == 1) {
        out.push_back(TX_EXTRA_TAG_PUBKEY);
        detail::put_hash(out, x.keys.front());
    } else {
        out.push_back(TX_EXTRA_TAG_ADDITIONAL_PUBKEYS);
        detail::put_varint(out, n);
        for (const Hash32& k : x.keys) detail::put_hash(out, k);
    }
    out.push_back(TX_EXTRA_NONCE);
    detail::put_varint(out, kExtraNonceBytes);
    out.insert(out.end(), x.extra_nonce.begin(), x.extra_nonce.end());
    out.push_back(TX_EXTRA_MERGE_MINING_TAG);
    detail::put_varint(out, kMergeMiningFieldBytes);
    detail::put_varint(out, kMergeMiningDepth);
    detail::put_hash(out, x.mm_root);
    return Pbx1Error::None;
}

inline Pbx1Error decode_pbx1(std::uint8_t hf, const std::uint8_t* data, std::size_t len, Pbx1& out) {
    if (len > pbx1_size(hf, pbx1_max_keys(hf))) return Pbx1Error::OverCap;
    BlobReader r(data, len);
    Pbx1 v;
    std::uint8_t tag = 0;
    if (!r.read_byte(tag)) return Pbx1Error::Truncated;
    if (tag == TX_EXTRA_TAG_PUBKEY) {
        v.keys.resize(1);
        if (!detail::get_hash(r, v.keys.front())) return Pbx1Error::Truncated;
    } else if (tag == TX_EXTRA_TAG_ADDITIONAL_PUBKEYS && pbx1_carrot(hf)) {
        std::uint64_t n = 0;
        if (!r.read_count(n, pbx1_max_keys(hf), kHashBytes)) {
            return r.error() == ::c2pool::xmr::native::BlobError::CountTooLarge ? Pbx1Error::KeyCount
                                                                                 : Pbx1Error::Truncated;
        }
        if (n < 2) return Pbx1Error::KeyCount;
        v.keys.resize(n);
        for (Hash32& k : v.keys)
            if (!detail::get_hash(r, k)) return Pbx1Error::Truncated;
    } else {
        return Pbx1Error::KeyTag;
    }

    std::uint64_t field = 0;
    if (!r.read_byte(tag)) return Pbx1Error::Truncated;
    if (tag != TX_EXTRA_NONCE) return Pbx1Error::NonceTag;
    if (!r.read_varint(field)) return Pbx1Error::Truncated;
    if (field != kExtraNonceBytes) return Pbx1Error::NonceLength;
    if (!r.read_bytes(v.extra_nonce.data(), v.extra_nonce.size())) return Pbx1Error::Truncated;

    if (!r.read_byte(tag)) return Pbx1Error::Truncated;
    if (tag != TX_EXTRA_MERGE_MINING_TAG) return Pbx1Error::MergeMiningTag;
    if (!r.read_varint(field)) return Pbx1Error::Truncated;
    if (field != kMergeMiningFieldBytes) return Pbx1Error::MergeMiningLength;
    if (!r.read_varint(field)) return Pbx1Error::Truncated;
    if (field != kMergeMiningDepth) return Pbx1Error::MergeMiningDepth;
    if (!detail::get_hash(r, v.mm_root)) return Pbx1Error::Truncated;

    if (r.remaining() != 0) return Pbx1Error::Trailing;
    out = std::move(v);
    return Pbx1Error::None;
}

}  // namespace c2pool::xmr::pathb
