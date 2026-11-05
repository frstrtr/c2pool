// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/v37_xmr_receipt_id_kat.cpp
// The replay guard (pathb_receipt_admission.hpp, X-4, ruling 27 K-10):
//   id = keccak256(hashing_blob); the same PoW id placed twice in the window is
//   credited once (the second placement is DUPLICATE); one template, two
//   nonces -> two receipts, both admitted; a carrier and a pending copy of one
//   id -> the second DUPLICATE; after a rewind the abandoned placements are free
//   again; a receipt carried into a sealed bin -> STRIKE; the same receipt
//   re-carried on another branch inside its open bin -> accepted once on that
//   branch.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <vector>

#include "impl/xmr/pathb/pathb_receipt_admission.hpp"
#include "pathb_kat_bodies.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

int main() {
    const std::uint64_t F = pb::kRuledLaneParams.open_bins;  // 96

    // id = keccak256(hashing_blob): deterministic, and equal to the raw Keccak
    // over the encoded hashing blob.
    pb::ReceiptBodyV3 r = make_body(/*depth=*/2, /*with_owner=*/false, 0x10);
    const pb::Hash32 id = pb::receipt_id(r);
    check(pb::receipt_id(r) == id, "receipt_id is deterministic");
    {
        std::vector<std::uint8_t> blob_bytes;
        pb::encode_hashing_blob(r.blob, blob_bytes);
        check(pb::keccak256_hash(blob_bytes) == id, "receipt_id == keccak256(hashing_blob)");
    }

    // The same PoW id placed twice in the window is credited once: the second
    // placement is a DUPLICATE.
    {
        pb::PlacedSet window;
        check(window.place(id), "first placement of the id");
        check(!window.place(id), "second placement is DUPLICATE (credited once)");
        check(window.size() == 1, "one entry for one id");
    }

    // One template, two nonces -> two distinct receipts, both admitted.
    {
        pb::ReceiptBodyV3 a = r;
        pb::ReceiptBodyV3 b = r;
        a.blob.nonce = 0xAAAAAAAAu;
        b.blob.nonce = 0xBBBBBBBBu;
        const pb::Hash32 ida = pb::receipt_id(a);
        const pb::Hash32 idb = pb::receipt_id(b);
        check(ida != idb, "two nonces give two ids");
        pb::PlacedSet window;
        check(window.place(ida) && window.place(idb), "both nonce-variant receipts admitted");
        check(window.size() == 2, "two distinct entries");
    }

    // A carrier and a pending copy of one id -> the second is a DUPLICATE (one
    // dedup set covers carriers and placed receipts).
    {
        pb::PlacedSet window;
        check(window.place(id), "id placed as a carrier");
        check(!window.place(id), "a pending copy of the same id is DUPLICATE");
    }

    // After a rewind the abandoned placements are free again.
    {
        pb::PlacedSet window;
        check(window.place(id), "placed before the rewind");
        window.unplace(id);  // the journal rewinds the abandoned placement
        check(!window.contains(id), "the id is free after the rewind");
        check(window.place(id), "placeable again after the rewind");
    }

    // A receipt carried into a sealed bin -> STRIKE (the open/sealed status is
    // chain data: H(pos(c) - 1) >= h(r) + F).
    {
        const std::uint64_t h_r = 2000;
        check(pb::open_at(h_r + F - 1, h_r, F), "bin open just before the seal");
        check(!pb::open_at(h_r + F, h_r, F), "carried into a sealed bin -> STRIKE");
    }

    // The same receipt re-carried on ANOTHER branch inside its open bin is
    // accepted once on that branch (a separate dedup set per branch).
    {
        pb::PlacedSet branch_a;
        pb::PlacedSet branch_b;
        check(branch_a.place(id), "placed once on branch A");
        check(!branch_a.place(id), "duplicate on branch A");
        check(branch_b.place(id), "accepted once on branch B (its own open bin)");
        check(!branch_b.place(id), "duplicate on branch B");
    }

    return finish("v37_xmr_receipt_id_kat");
}
