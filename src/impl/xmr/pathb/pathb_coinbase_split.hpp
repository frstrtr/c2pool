// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_coinbase_split.hpp
// Path B, slice S3: the per-receipt canonical coinbase (admission #12) and the
// window_root / mmr_root recomputation (admission #13).
//
//   canonical coinbase = the hf-16 miner tx (pathb_miner_tx.hpp) of
//     split(R, window(tip, v)), outputs by payee identity ascending, keys per
//     (tip, P_r) (KeyCache), PBX1 extra with mm_root = mm_root_of(side_data_v3)
//     of the receipt; an empty window: one output of R to the receipt's own
//     payee (keys per (tip, P_r, payee)). tx hash -> fold over the receipt's
//     branch == tree_root. [C37, C07, C21; D2.2, D2.7]
//   outcome (CoinbaseCheck, pathb_receipt_admission.hpp): Fused at hf >= 17
//     (amount_fork_fused) before anything is built; Defer when the window of
//     (tip, v) (WindowAt bound to the receipt's tip and hf) or a payee's key
//     reference is not held; Undefined when side_data_v3 does not
//     encode, the window weights != W or the receipt's payee identity does not
//     match its reference; Mismatch / Match from the fold. [C41]
//   hf >= 17 (format only): two equal Ko -> Unbuildable (carrot_order_refusal).
//   admission #13: window_root == window_root(window); mmr_root == the node's MMR
//     root; BAN on a mismatch.
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <vector>

#include "pathb_buckets.hpp"
#include "pathb_emission.hpp"
#include "pathb_miner_tx.hpp"
#include "pathb_params.hpp"
#include "pathb_receipt_admission.hpp"  // CoinbaseCheck, tree_root_fold
#include "pathb_window.hpp"
#include "pathb_wire_v3.hpp"

namespace c2pool::xmr::pathb {

// A window payee's key reference by identity (filled at placement from each live
// receipt's payee_ref / owner_ref); nullopt when not held.
using RefLookup = std::function<std::optional<XmrKeyRef>(const Hash32&)>;

// The window of the receipt's own tip at v, or nullptr when the node cannot
// evaluate it yet (a bucket or A_t's weights not held). Bound to the tip and v
// it was evaluated for, with its window_root and mmr_root_at(tip).
struct WindowAt {
    const Window* window = nullptr;
    Hash32 tip{};
    std::uint8_t v = 0;
    Hash32 window_root{};
    Hash32 mmr_root{};
};

// The hf-16 vouts of R over a non-empty window: split(R, w), payee identity
// ascending (memcmp). Empty when the window weights != W.
inline std::vector<SplitOutput> hf16_outputs(std::uint64_t R, const Window& w) {
    std::vector<SplitOutput> outs = split(R, w);
    std::sort(outs.begin(), outs.end(), [](const SplitOutput& a, const SplitOutput& b) { return a.payee < b.payee; });
    return outs;
}

// The canonical miner tx of a receipt, or the outcome that stopped it.
struct CanonicalTx {
    CoinbaseCheck stop = CoinbaseCheck::Match;  // Match: tx holds the canonical miner tx
    std::optional<MinerTx> tx;
};

// The canonical hf-16 miner tx a receipt on (tip, P_r) at height h commits.
// author: the donation identity's key reference (an input).
inline CanonicalTx canonical_miner_tx(const ReceiptBodyV3& r, const WindowAt& at, const Hash32& tip,
                                      const Hash32& p_r, std::uint64_t h, std::uint8_t hf, KeyCache& cache,
                                      const RefLookup& refs, const XmrKeyRef& author) {
    CanonicalTx out;
    if (amount_fork_fused(hf)) {
        out.stop = CoinbaseCheck::Fused;  // hf >= 17: build nothing
        return out;
    }
    if (at.window == nullptr || !(at.tip == tip) || at.v != hf) {
        out.stop = CoinbaseCheck::Defer;  // no window of (tip, v) held
        return out;
    }
    const std::optional<Hash32> mm_root = mm_root_of(r.side);
    if (!mm_root) {
        out.stop = CoinbaseCheck::Undefined;  // side_data_v3 does not encode
        return out;
    }
    const Window& w = *at.window;
    std::vector<Hash32> ids;
    std::vector<std::uint64_t> amounts;
    const bool finder_only = w.weight.empty();
    if (finder_only) {
        // empty window: one output of R to the receipt's own payee (D:621-622).
        if (key_ref_identity(r.payee) != r.side.payee) {
            out.stop = CoinbaseCheck::Undefined;
            return out;
        }
        ids.push_back(r.side.payee);
        amounts.push_back(r.reward_total);
    } else {
        const std::vector<SplitOutput> outs = hf16_outputs(r.reward_total, w);
        if (outs.empty()) {
            out.stop = CoinbaseCheck::Undefined;  // window weights != W
            return out;
        }
        ids.reserve(outs.size());
        amounts.reserve(outs.size());
        for (const SplitOutput& o : outs) {
            ids.push_back(o.payee);
            amounts.push_back(o.amount);
        }
    }
    const Hash32 author_id = key_ref_identity(author);
    const RefAt ref_at = [&](std::size_t i) -> std::optional<XmrKeyRef> {
        if (finder_only) return r.payee;
        std::optional<XmrKeyRef> ref = ids[i] == author_id ? std::optional<XmrKeyRef>(author) : refs(ids[i]);
        if (ref && key_ref_identity(*ref) != ids[i]) return std::nullopt;  // held under another identity
        return ref;
    };
    const KeysResult k = cache.get(r.side.pool_id, tip, p_r, h, ids, finder_only, ref_at);
    if (k.status == KeysStatus::MissingRef) {
        out.stop = CoinbaseCheck::Defer;
        return out;
    }
    if (k.status != KeysStatus::Ok) {
        out.stop = CoinbaseCheck::Undefined;
        return out;
    }
    out.tx = assemble_miner_tx_hf16(h, *k.keys, amounts, r.extra_nonce, *mm_root);
    if (!out.tx) out.stop = CoinbaseCheck::Undefined;
    return out;
}

// Admission #12: the receipt's tree_root against the canonical miner tx hash
// folded over the receipt's branch from leaf 0.
inline CoinbaseCheck canonical_coinbase_check(const ReceiptBodyV3& r, const WindowAt& at, const Hash32& tip,
                                              const Hash32& p_r, std::uint64_t h, std::uint8_t hf, KeyCache& cache,
                                              const RefLookup& refs, const XmrKeyRef& author) {
    const CanonicalTx c = canonical_miner_tx(r, at, tip, p_r, h, hf, cache, refs, author);
    if (c.stop != CoinbaseCheck::Match) return c.stop;
    return tree_root_fold(c.tx->tx_hash, std::span<const Hash32>(r.branch)) == r.blob.tree_root
                   ? CoinbaseCheck::Match
                   : CoinbaseCheck::Mismatch;
}

// hf >= 17 (format only, reachable after O-01): two equal Ko leave no canonical
// coinbase -> Unbuildable; nullopt when the Ko order is defined.
inline std::optional<CoinbaseCheck> carrot_order_refusal(std::span<const Hash32> ko) {
    if (!carrot_output_order(ko)) return CoinbaseCheck::Unbuildable;
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Admission #13 (S3.3): the receipt's side_data window_root / mmr_root equal the
// node's own computation. BAN on a mismatch (part of the #12 prefix;
// admit_coinbase_roots_then_randomx).
// ---------------------------------------------------------------------------
inline bool roots_ok(const SideDataV3& s, const Window& w, const BinMmr& mmr) {
    Work sum;
    const Hash32 wr = window_root(w, &sum);
    return s.window_root == wr && s.mmr_root == mmr.root();
}

}  // namespace c2pool::xmr::pathb
