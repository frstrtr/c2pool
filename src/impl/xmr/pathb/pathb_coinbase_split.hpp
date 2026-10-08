// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_coinbase_split.hpp
// Path B, slice S3: the exact per-receipt canonical coinbase (admission #12) and
// the window_root / mmr_root recomputation (admission #13). Lifts the S1/S2
// one-output stub to the hf-16 split of the full reward R over window(tip, v).
//
//   canonical coinbase = split(R, window(tip, v)) -> output keys per (tip, P_r)
//     -> PBX1 tx_extra (pathb_pbx1.hpp) -> canonical coinbase leaf -> fold over
//     the receipt's branch == tree_root. A mismatch is REFUSE and BAN, decided
//     BEFORE RandomX (ruling 4, C37). No R-versus-B refusal (B is a window input).
//   At hf >= 17 the lane FORK-FUSEs (amount_fork_fused): it builds and admits
//     nothing (O-01 owed).
//   admission #13: window_root == window_root(window); mmr_root == the node's MMR
//     root; STRIKE on a mismatch.
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include "pathb_buckets.hpp"
#include "pathb_emission.hpp"
#include "pathb_params.hpp"
#include "pathb_pbx1.hpp"
#include "pathb_receipt_admission.hpp"  // stub_output_key, tree_root_fold, admit_coinbase_then_randomx, keccak256_hash
#include "pathb_window.hpp"

namespace c2pool::xmr::pathb {

inline constexpr std::string_view kSplitCbDomain = "c2pool-v37-cb-split";

// Output key per (tip, P_r, payee): at hf 16 the one-time key does not depend on
// the amount (ruling 20 Q-F), so it is the S2 per-(tip, P_r) key, cached once.
inline Hash32 split_output_key(const Hash32& tip, const Hash32& p_r, const Hash32& payee) {
    return stub_output_key(tip, p_r, payee);
}

// hf-16 PBX1 tx_extra of the canonical coinbase: 01 R_tx[32] 02 04 nonce[4]
// 03 21 00 mm_root[32] (74 B). Only the hf 16 form is built (hf >= 17 FORK-FUSEs).
inline std::vector<std::uint8_t> canonical_tx_extra_hf16(const Hash32& r_tx,
                                                         const std::array<std::uint8_t, kExtraNonceBytes>& nonce,
                                                         const Hash32& mm_root) {
    Pbx1 x;
    x.keys = {r_tx};
    x.extra_nonce = nonce;
    x.mm_root = mm_root;
    std::vector<std::uint8_t> out;
    encode_pbx1(kHf16, x, out);
    return out;
}

// The canonical coinbase leaf committing the whole hf-16 split: the PBX1 extra
// bytes, then the ordered (amount, output_key) list. Output order is payee
// identity ascending at hf 16 (split() already returns that order).
inline Hash32 canonical_cb_leaf(const std::vector<SplitOutput>& outs, const Hash32& tip, const Hash32& p_r,
                                const std::vector<std::uint8_t>& tx_extra) {
    std::vector<std::uint8_t> pre(kSplitCbDomain.begin(), kSplitCbDomain.end());
    pre.insert(pre.end(), tx_extra.begin(), tx_extra.end());
    detail::put_varint(pre, outs.size());
    for (const SplitOutput& o : outs) {
        for (std::size_t i = 0; i < sizeof(o.amount); ++i) pre.push_back(static_cast<std::uint8_t>(o.amount >> (8 * i)));
        const Hash32 key = split_output_key(tip, p_r, o.payee);
        pre.insert(pre.end(), key.begin(), key.end());
    }
    return keccak256_hash(pre);
}

// Finder-only canonical leaf (empty window / N(B) == 1, D2.7 step 6): one output
// of R to the receipt's own payee, the S2 stub leaf.
inline Hash32 finder_only_leaf(const ReceiptBodyV3& r, const Hash32& tip, const Hash32& p_r) {
    return canonical_stub_leaf_of(r, tip, p_r);
}

// The canonical coinbase leaf a receipt committing reward R on (tip, P_r) must
// carry, given its window. FORK-FUSE: at hf >= 17 no amount is produced.
struct CanonLeaf {
    bool fork_fused = false;  // hf >= 17: amount owed (O-01), nothing built
    Hash32 leaf{};
};

inline CanonLeaf canonical_coinbase_leaf(const ReceiptBodyV3& r, const Window& w, const Hash32& tip,
                                         const Hash32& p_r, std::uint8_t hf, const Hash32& mm_root) {
    CanonLeaf cl;
    if (amount_fork_fused(hf)) {
        cl.fork_fused = true;  // hf >= 17: build nothing
        return cl;
    }
    if (w.empty_finder_only) {
        cl.leaf = finder_only_leaf(r, tip, p_r);
        return cl;
    }
    const std::vector<SplitOutput> outs = split(r.reward_total, w);
    const std::vector<std::uint8_t> extra = canonical_tx_extra_hf16(/*r_tx=*/p_r, r.extra_nonce, mm_root);
    cl.leaf = canonical_cb_leaf(outs, tip, p_r, extra);
    return cl;
}

// Admission #12 (ruling 4, C37): the receipt's committed coinbase (tree_root
// folded over the branch) equals the canonical split leaf. false -> BAN before
// RandomX. At hf >= 17 the lane fork-fuses (never admits an amount).
inline bool canonical_coinbase_ok_split(const ReceiptBodyV3& r, const Window& w, const Hash32& tip,
                                        const Hash32& p_r, std::uint8_t hf, const Hash32& mm_root) {
    const CanonLeaf cl = canonical_coinbase_leaf(r, w, tip, p_r, hf, mm_root);
    if (cl.fork_fused) return false;  // hf >= 17: admit nothing
    return tree_root_fold(cl.leaf, std::span<const Hash32>(r.branch)) == r.blob.tree_root;
}

// ---------------------------------------------------------------------------
// Admission #13 (S3.3): the receipt's side_data window_root / mmr_root equal the
// node's own computation. STRIKE on a mismatch. These lift the S1/S2 zero stubs.
// ---------------------------------------------------------------------------
inline bool roots_ok(const SideDataV3& s, const Window& w, const BinMmr& mmr) {
    Work sum;
    const Hash32 wr = window_root(w, &sum);
    return s.window_root == wr && s.mmr_root == mmr.root();
}

}  // namespace c2pool::xmr::pathb
