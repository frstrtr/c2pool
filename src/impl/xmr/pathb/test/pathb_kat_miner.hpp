// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/pathb_kat_miner.hpp
// Helpers for the Path B miner-tx KATs: key references from secrets, a
// reference book (RefLookup), windows over referenced payees, the miner's own
// canonical tree_root (built without the KeyCache), hex.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/pathb/pathb_coinbase_split.hpp"
#include "impl/xmr/pathb/pathb_miner_tx.hpp"
#include "pathb_kat_bodies.hpp"
#include "pathb_kat_check.hpp"

namespace pathb_kat {

namespace pb = ::c2pool::xmr::pathb;

// Height h(r) = height(P_r) + 1 used by the synthetic receipts.
inline constexpr std::uint64_t kKatHeight = 3800000;

inline int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

inline std::vector<std::uint8_t> unhex(const std::string& s) {
    std::vector<std::uint8_t> out;
    out.reserve(s.size() / 2);
    for (std::size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back(static_cast<std::uint8_t>(hex_nibble(s[i]) * 16 + hex_nibble(s[i + 1])));
    return out;
}

inline pb::Hash32 h32(const std::string& s) {
    pb::Hash32 h{};
    const std::vector<std::uint8_t> v = unhex(s);
    for (std::size_t i = 0; i < h.size() && i < v.size(); ++i) h[i] = v[i];
    return h;
}

inline std::string hex32(const pb::Hash32& h) { return hex(h.data(), h.size()); }
inline std::string hexv(std::span<const std::uint8_t> v) { return hex(v.data(), v.size()); }

// The scalar s (s < 2^64) as a 32-byte little-endian secret key.
inline pb::Hash32 scalar(std::uint64_t s) {
    pb::Hash32 k{};
    for (int i = 0; i < 8; ++i) k[i] = static_cast<std::uint8_t>(s >> (8 * i));
    return k;
}

// (B, A) = (spend_secret G, view_secret G).
inline pb::XmrKeyRef ref_from_secrets(std::uint64_t spend_secret, std::uint64_t view_secret) {
    pb::XmrKeyRef r;
    r.spend = pb::tx_public_key(scalar(spend_secret)).value();
    r.view = pb::tx_public_key(scalar(view_secret)).value();
    return r;
}

// identity -> key reference.
struct RefBook {
    std::map<pb::Hash32, pb::XmrKeyRef> refs;

    pb::Hash32 add(const pb::XmrKeyRef& r) {
        const pb::Hash32 id = pb::key_ref_identity(r);
        refs[id] = r;
        return id;
    }
    pb::RefLookup lookup() const {
        return [this](const pb::Hash32& id) -> std::optional<pb::XmrKeyRef> {
            auto it = refs.find(id);
            if (it == refs.end()) return std::nullopt;
            return it->second;
        };
    }
};

// A window over (identity, weight) pairs.
inline pb::Window window_of(const std::vector<std::pair<pb::Hash32, std::uint64_t>>& w) {
    pb::Window out;
    for (const auto& [id, wt] : w) {
        out.weight[id] += pb::Work(wt);
        out.W += pb::Work(wt);
    }
    return out;
}

// The receipt's miner builds its own canonical miner tx without the KeyCache:
// hf16_outputs (or one output of R to its payee on an empty window),
// build_miner_tx_hf16 with mm_root_of(side_data_v3).
inline std::optional<pb::MinerTx> miner_built_tx(const pb::ReceiptBodyV3& r, const pb::Window& w,
                                                 const pb::Hash32& tip, const pb::Hash32& p_r, std::uint64_t h,
                                                 const RefBook& book, const pb::XmrKeyRef& author) {
    std::vector<pb::MinerPayee> payees;
    if (w.weight.empty()) {
        payees.push_back(pb::MinerPayee{r.payee, r.reward_total});
    } else {
        const pb::Hash32 author_id = pb::key_ref_identity(author);
        for (const pb::SplitOutput& o : pb::hf16_outputs(r.reward_total, w)) {
            if (o.payee == author_id) {
                payees.push_back(pb::MinerPayee{author, o.amount});
                continue;
            }
            auto it = book.refs.find(o.payee);
            if (it == book.refs.end()) return std::nullopt;
            payees.push_back(pb::MinerPayee{it->second, o.amount});
        }
    }
    const std::optional<pb::Hash32> mm = pb::mm_root_of(r.side);
    if (!mm) return std::nullopt;
    return pb::build_miner_tx_hf16(r.side.pool_id, tip, p_r, h, payees, r.extra_nonce, *mm);
}

// Commits the miner's own canonical miner tx into the receipt's tree_root.
inline bool commit_miner_tx(pb::ReceiptBodyV3& r, const pb::Window& w, const pb::Hash32& tip,
                            const pb::Hash32& p_r, std::uint64_t h, const RefBook& book,
                            const pb::XmrKeyRef& author) {
    const std::optional<pb::MinerTx> tx = miner_built_tx(r, w, tip, p_r, h, book, author);
    if (!tx) return false;
    r.blob.tree_root = pb::tree_root_fold(tx->tx_hash, std::span<const pb::Hash32>(r.branch));
    return true;
}

// A key reference that is not any window payee's: the author of the KATs.
inline pb::XmrKeyRef kat_author() { return ref_from_secrets(101, 103); }

// Per-network donation (author) key references of record, (B, A) hex:
// mainnet, testnet, stagenet, regtest.
struct AuthorRefHex {
    const char* spend;
    const char* view;
};
inline constexpr AuthorRefHex kAuthorRefsOfRecord[4] = {
        {"14d413e6ccb14f0ba30999b97c8912a07321d893789b7f149810b7885b2cd7c7",
         "b3157741ab68969aeb7fe9ebd4fa3ec5ce4dcdc7b43249fdb40311cb03779e03"},
        {"a7731abbe9bb2cf3264395231a8645172ffd7f08c6097e3402197f3f1c6ffcbb",
         "ef3c9a659a67c3bf081a352e7cfbfb94cc5e11921a3e8953223fca1ed14e2200"},
        {"7f095705904be1df109bdf44b0027c339fde3ece7d85069f8bdfb19fd8c16c41",
         "0abca326ba53a6f5387785822296c1d15df03e6c51cd44d7dbe270667b5fe34c"},
        {"3091e80a51918c67eb67b6fefaf77e374dd898240953bbb75d47b82b8615c638",
         "c5d453f0d54332e4f48f12abab2551132f00037f0c51892ebe3b41928ab5bec1"},
};

inline pb::XmrKeyRef author_ref_of_record(std::size_t net) {
    pb::XmrKeyRef r;
    r.spend = h32(kAuthorRefsOfRecord[net].spend);
    r.view = h32(kAuthorRefsOfRecord[net].view);
    return r;
}

}  // namespace pathb_kat
