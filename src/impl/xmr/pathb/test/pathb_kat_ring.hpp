// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/pathb_kat_ring.hpp
// Shared by the ring KATs (pathb_ring.hpp): the TEST tags, generated
// identities, and the one entry into pathb_ring.hpp. Every rule a ring KAT
// hands over passes admissible(): a rule carrying the ruled tag is refused here
// and nothing is computed, so every golden of these KATs is under a TEST tag.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "impl/xmr/pathb/pathb_ring.hpp"
#include "pathb_kat_check.hpp"
#include "sharechain/v37/v37_hash.hpp"

namespace pathb_kat::ring {

namespace pb = ::c2pool::xmr::pathb;

// TEST tags. Neither is the ruled tag; each differs from it in byte 0.
inline constexpr std::string_view kTestKeyTag{"v37-ring-c2-test-key"};  // the ring key
inline constexpr std::string_view kTestIdTag{"v37-ring-c2-test-id"};    // generated identities

inline std::vector<std::uint8_t> bytes_of(std::string_view s) { return std::vector<std::uint8_t>(s.begin(), s.end()); }

inline void put_u64_le(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (std::size_t i = 0; i < sizeof(v); ++i) out.push_back(static_cast<std::uint8_t>(v >> (pb::kRingBitsPerByte * i)));
}

// A generated identity: sha256d(kTestIdTag || u64 LE c).
inline pb::Hash32 gen_id(std::uint64_t c) {
    std::vector<std::uint8_t> pre = bytes_of(kTestIdTag);
    put_u64_le(pre, c);
    return ::v37::sha256d(pre);
}

// Generated key material: sha256d(kTestIdTag || name || u64 LE c).
inline pb::Hash32 gen_part(std::string_view name, std::uint64_t c) {
    std::vector<std::uint8_t> pre = bytes_of(kTestIdTag);
    pre.insert(pre.end(), name.begin(), name.end());
    put_u64_le(pre, c);
    return ::v37::sha256d(pre);
}

inline std::string hx(const pb::Hash32& h) { return hex(h.data(), h.size()); }
inline std::string hx(const std::vector<std::uint8_t>& v) { return hex(v.data(), v.size()); }

inline bool is_ruled_tag(const std::vector<std::uint8_t>& tag) { return tag == bytes_of(pb::kRingTagRuled); }

// A rule under the TEST key tag.
inline pb::RingKeyRule test_rule(pb::Membership m = pb::Membership::MinerPayee,
                                 pb::RingBinding b = pb::RingBinding::ChainIdLe32) {
    pb::RingKeyRule r;
    r.tag = bytes_of(kTestKeyTag);
    r.binding = b;
    r.membership = m;
    return r;
}

inline pb::RingBindingValue chain(std::uint32_t chain_id) {
    pb::RingBindingValue v;
    v.chain_id = chain_id;
    return v;
}

// The one entry into pathb_ring.hpp: the ruled tag is refused, nothing computed.
inline bool admissible(const pb::RingKeyRule& r) { return !is_ruled_tag(r.tag); }

inline std::optional<std::vector<std::uint8_t>> preimage_of(const pb::RingKeyRule& r, const pb::RingBindingValue& v,
                                                            const pb::Hash32& x) {
    if (!admissible(r)) return std::nullopt;
    return pb::ring_key_preimage(r, v, x);
}
inline std::optional<pb::Hash32> key_of(const pb::RingKeyRule& r, const pb::RingBindingValue& v, const pb::Hash32& x) {
    if (!admissible(r)) return std::nullopt;
    return pb::ring_key(r, v, x);
}
inline std::optional<pb::RingId> ring_entry(const pb::RingKeyRule& r, const pb::RingBindingValue& v,
                                            const pb::WinEntry& e, std::uint8_t d) {
    if (!admissible(r)) return std::nullopt;
    return pb::ring_of_entry(r, v, e, d);
}
inline std::optional<pb::RingId> ring_row(const pb::RingKeyRule& r, const pb::RingBindingValue& v,
                                          const pb::BucketRow& row, std::uint8_t d) {
    if (!admissible(r)) return std::nullopt;
    return pb::ring_of_row(r, v, row, d);
}
inline std::optional<pb::RingId> ring_payee(const pb::RingKeyRule& r, const pb::RingBindingValue& v,
                                            const pb::Hash32& payee, std::uint8_t d) {
    if (!admissible(r)) return std::nullopt;
    return pb::ring_of_payee(r, v, payee, d);
}

inline bool is_ring(const std::optional<pb::RingId>& r, std::uint8_t depth, std::size_t index) {
    return r && r->depth == depth && r->index == index;
}

}  // namespace pathb_kat::ring
