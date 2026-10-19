// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/pathb_kat_bodies.hpp
// Receipt bodies for the Path B codec KATs.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <vector>

#include "impl/xmr/pathb/pathb_wire_v3.hpp"
#include "pathb_kat_check.hpp"

namespace pathb_kat {

namespace pb = ::c2pool::xmr::pathb;

// The side data whose bytes and mm_root are pinned by gen_pathb_golden.py.
inline pb::SideDataV3 golden_side() {
    pb::SideDataV3 s;
    s.version = 3;
    s.pool_id = seq32(0x01);
    s.rules_epoch = 0x0201u;
    s.ballot = 0x0403u;
    s.payee = seq32(0x40);
    s.t_origin = 0x0807060504030201ull;
    s.tip = seq32(0x60);
    s.receipts_root = seq32(0xA0);
    s.window_root = seq32(0xC0);
    s.mmr_root = seq32(0xE0);
    s.fee_rate_bp = 0x0102;
    s.owner = seq32(0x21);
    s.give_author_bp = 10;
    return s;
}

// The first encoding seq32(seed) with byte 0 = 0, 1, 2, ... that decompresses.
inline pb::Hash32 point_from(std::uint8_t seed) {
    pb::Hash32 h = seq32(seed);
    for (unsigned k = 0; k < 256; ++k) {
        h[0] = static_cast<std::uint8_t>(k);
        if (pb::point_decompresses(h)) return h;
    }
    return h;
}

// The first seq32 pattern that does not decompress.
inline pb::Hash32 non_point() {
    for (unsigned i = 0; i < 256; ++i) {
        const pb::Hash32 h = seq32(static_cast<std::uint8_t>(i));
        if (!pb::point_decompresses(h)) return h;
    }
    return pb::Hash32{};
}

inline pb::XmrKeyRef key_ref(std::uint8_t seed) {
    pb::XmrKeyRef r;
    r.spend = point_from(seed);
    r.view = point_from(static_cast<std::uint8_t>(seed + 0x55));
    return r;
}

// A valid receipt body: depth D, owner_ref present iff with_owner; identities bound.
inline pb::ReceiptBodyV3 make_body(std::size_t depth, bool with_owner, std::uint8_t seed) {
    pb::ReceiptBodyV3 b;
    b.blob.major = 16;
    b.blob.minor = 16;
    b.blob.timestamp = 1700000000u + seed;
    b.blob.prev_id = seq32(seed);
    b.blob.nonce = 0x11223344u + seed;
    b.blob.tree_root = seq32(static_cast<std::uint8_t>(seed + 3));
    b.blob.tx_count = 5u + seed;
    b.extra_nonce = {seed, 1, 2, 3};
    for (std::size_t i = 0; i < depth; ++i) b.branch.push_back(seq32(static_cast<std::uint8_t>(seed + 7 + i)));
    b.payee = key_ref(static_cast<std::uint8_t>(seed + 9));
    b.side.pool_id = seq32(0x33);
    b.side.rules_epoch = 1;
    b.side.payee = pb::key_ref_identity(b.payee);
    b.side.t_origin = 18180u + seed;
    b.side.tip = seq32(static_cast<std::uint8_t>(seed + 11));
    b.side.give_author_bp = 10;
    if (with_owner) {
        b.owner = key_ref(static_cast<std::uint8_t>(seed + 13));
        b.side.fee_rate_bp = 100;
        b.side.owner = pb::key_ref_identity(*b.owner);
    }
    b.reward_total = 600000000000ull + seed;
    return b;
}

// The largest body at depth D: every hashing-blob field at its declared width.
inline pb::ReceiptBodyV3 make_max_body(std::size_t depth, bool with_owner) {
    pb::ReceiptBodyV3 b = make_body(depth, with_owner, 0x42);
    b.blob.major = (1u << 7) - 1;                 // 1 B varint
    b.blob.minor = (1u << 7) - 1;                 // 1 B varint
    b.blob.timestamp = (1ull << 35) - 1;          // 5 B varint
    b.blob.tx_count = (1ull << 21) - 1;           // 3 B varint
    return b;
}

inline std::vector<std::uint8_t> enc(const pb::ReceiptBodyV3& b) {
    std::vector<std::uint8_t> out;
    pb::encode_receipt_body_v3(b, out);
    return out;
}

}  // namespace pathb_kat
