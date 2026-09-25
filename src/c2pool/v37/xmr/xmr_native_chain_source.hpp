// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_native_chain_source.hpp   (M3)
//
// THE TIP, CUT OVER.
//
// Everything above settlement in this daemon asks the parent chain exactly two
// questions, and until M3 a daemon answered both of them:
//
//   1. "what happened to the chain" -- Extend / Reorg / Orphan, which is what
//      advances the F1 finalize cursor and disposes an orphaned settlement.
//      Answered by LiveMonerodTransport::pump_poll() re-issuing get_miner_data
//      on a timer, decoded into the X2 MonerodAdapter's MainchainIndex.
//   2. "is block X still at height H on the best chain" -- the canonical test
//      XmrFinalizeDriver runs at maturity, before it finalizes anything.
//      Answered out of that same monerod-mirroring index.
//
// M0 built a node that answers both of those from a chain it verified ITSELF:
// blocks fetched over levin from real peers, RandomX-checked at L4, connected
// under the C2 fork-choice rule. Nothing consumed that stream. This file is the
// consumption -- two std::functions, bound to the running native node, handed to
// XmrNode before bring_up() so that in --arm-order p2p-first the settlement
// path never learns anything from a daemon.
//
// WHAT IS NOT HERE, AND WHY. There is no "if the native answer looks wrong, ask
// monerod" branch. A find path with a daemon fallback on it is a daemon-ful find
// path that happens to be quiet, and the number this milestone reports -- RPCs
// on the find path -- would then depend on how lucky the run was. The native
// arm answers or nothing does.
//
// THREADING. The native index flushes its events on the node's VERIFY thread;
// drain_mainchain_events() queues them there under the node's own mutex and
// hands them to the caller's thread. is_canonical() goes through ChainIndex's
// mutex-guarded by_height(). Both are safe from the daemon's main loop, which
// is the only thread that calls them.
//
// SCOPE FENCE: consumer tree. No consensus digest; src/sharechain/v37 untouched.
// ===========================================================================
#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/node/xmr_node_types.hpp"   // c2pool::xmr::node::MainchainEvent
#include "xmr_native_template_backend.hpp"

namespace c2pool::v37n::xmr::o2 {

// The parent chain, as the settlement path needs it. Empty (operator bool
// false) when no native node is running, which is the only honest value in
// daemon-first mode and is why the type is checkable rather than assumed.
struct NativeChainSource {
    // Every mainchain event the native index produced since the last call, in
    // arrival order. Extend/Reorg advance the finalize cursor; Orphan disposes.
    std::function<std::vector<::c2pool::xmr::node::MainchainEvent>()> drain;

    // The canonical test XmrFinalizeDriver runs at maturity: is `bid_hex` the
    // block this chain carries at `height`? A height the retention window has
    // dropped answers false, which is the fail-closed direction (a settlement
    // is refused, never wrongly finalized).
    std::function<bool(std::uint64_t height, const std::string& bid_hex)> is_canonical;

    // D2-0: the block the best chain carries at `height` (lowercase hex), or
    // nullopt (above the tip / outside the retention window). Lets XmrNode
    // deliver the blocks a Reorg re-applied BELOW its tip to the booking
    // observer (the Reorg event itself carries only the tip).
    std::function<std::optional<std::string>(std::uint64_t height)> bid_at;

    // Events produced since start, drained or not. A tip driver that produced
    // nothing and a consumer that dropped everything are indistinguishable
    // without this, and they have opposite fixes.
    std::function<std::uint64_t()> events_seen;

    // c2pool#1551: the same-height candidates the node HOLDS but has not
    // adopted. Needed because the branch where our own block stays best
    // produces no mainchain event for the rival at all: an accounting layer fed
    // only by `drain` would see that height as uncontested and credit as if we
    // had run unopposed. Unset in daemon-first (the X2 adapter mirrors monerod's
    // best chain and keeps no alternatives), which is an honest gap and is why
    // the field is checkable rather than assumed.
    struct AltCandidate {
        std::uint64_t height = 0;
        std::string   bid_hex;
        bool          own_mined = false;
    };
    std::function<std::vector<AltCandidate>()> alt_candidates;

    // D6a: the block blob of `bid_hex` from the index's retained bodies (the
    // coinbase-authority booking reads it here instead of monerod get_block).
    // false when the index does not hold the body (never connected, or aged
    // out of the entry cache); the caller HOLDS, it does not ask a daemon.
    // The id is the hash of the blob, so a hit is byte-identical to get_block.
    std::function<bool(const std::string& bid_hex, std::vector<std::uint8_t>& blob)> block_blob;

    // COLD-BOOT: ask the native node to fetch the body of `bid_hex` again over
    // levin (and the next missing best-chain bodies above it), for a booking
    // whose body was evicted before it was booked. Returns the ids newly asked.
    std::function<std::size_t(const std::string& bid_hex)> want_body;

    // D6b: the receipt relay's chain-view feed (relay/xmr_relay_chain_feed.hpp)
    // -- the headers and tip the daemon arm fetches from monerod
    // (get_block_headers_range / get_block_header_by_height). Context blobs
    // are RC-CTX's (ChainIndex::block_blob_of, bound in main).
    //   tip_block: (height, id) of the best-chain tip;
    //   id_at:     the id the best chain carries at a height;
    //   seed_for:  the RandomX seed id for a block AT a height (epoch ids are
    //              kept beyond the row window as seed anchors).
    std::function<std::optional<std::pair<std::uint64_t, ::c2pool::xmr::node::Hash>>()> tip_block;
    std::function<std::optional<::c2pool::xmr::node::Hash>(std::uint64_t height)> id_at;
    std::function<std::optional<::c2pool::xmr::node::Hash>(std::uint64_t height)> seed_for;

    explicit operator bool() const noexcept {
        return static_cast<bool>(drain) && static_cast<bool>(is_canonical);
    }
};

// Lowercase hex of a Monero block id, in the spelling the OwedLedger keys on
// (the same one xmr_node.hpp's hex_of produces; repeated here so this header
// does not have to pull the engine in to format 32 bytes).
inline std::string chain_id_hex(const ::c2pool::xmr::node::Hash& h) {
    static const char* k = "0123456789abcdef";
    std::string s;
    s.reserve(64);
    for (std::uint8_t b : h) {
        s.push_back(k[b >> 4]);
        s.push_back(k[b & 0xf]);
    }
    return s;
}

// Inverse of chain_id_hex: 64 hex digits (either case) -> 32 bytes.
inline bool block_id_of_hex(const std::string& hex, ::c2pool::xmr::node::Hash& out) {
    if (hex.size() != 64) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < 32; ++i) {
        const int hi = nib(hex[2 * i]), lo = nib(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}

// Bind the source to a STARTED backend. The node must be up: both closures
// capture it by pointer and are called for the life of the daemon, which ends
// before the backend is stopped (main stops the listener, then the node, then
// the backend).
inline NativeChainSource native_chain_source(NativeTemplateBackend& backend) {
    NativeChainSource src;
    ::c2pool::xmr::native::rt::NativeNode* n = backend.node();
    if (!n) return src;

    src.drain = [n] { return n->drain_mainchain_events(); };

    src.is_canonical = [n](std::uint64_t height, const std::string& bid_hex) {
        const auto b = n->index().by_height(height);
        return b.has_value() && chain_id_hex(b->id) == bid_hex;
    };

    src.bid_at = [n](std::uint64_t height) -> std::optional<std::string> {
        const auto b = n->index().by_height(height);
        if (!b.has_value()) return std::nullopt;
        return chain_id_hex(b->id);
    };

    src.events_seen = [n] { return n->mainchain_events_seen(); };

    src.alt_candidates = [n] {
        std::vector<NativeChainSource::AltCandidate> out;
        for (const auto& a : n->index().alt_tips()) {
            NativeChainSource::AltCandidate c;
            c.height    = a.height;
            c.bid_hex   = chain_id_hex(a.id);
            c.own_mined = a.own_mined;
            out.push_back(std::move(c));
        }
        return out;
    };

    src.block_blob = [n](const std::string& bid_hex, std::vector<std::uint8_t>& blob) {
        ::c2pool::xmr::node::Hash id{};
        if (!block_id_of_hex(bid_hex, id)) return false;
        const auto e = n->index().get_block_entry(id, /*prune=*/false);
        if (!e || e->block_blob.empty()) return false;
        blob = e->block_blob;
        return true;
    };

    src.want_body = [n](const std::string& bid_hex) -> std::size_t {
        ::c2pool::xmr::node::Hash id{};
        if (!block_id_of_hex(bid_hex, id)) return 0;
        return n->index().want_body_for_booking(id);
    };

    src.tip_block = [n]() -> std::optional<std::pair<std::uint64_t, ::c2pool::xmr::node::Hash>> {
        const auto t = n->index().tip();
        if (!t) return std::nullopt;
        return std::make_pair(t->height, t->id);
    };
    src.id_at = [n](std::uint64_t height) -> std::optional<::c2pool::xmr::node::Hash> {
        const auto b = n->index().by_height(height);
        if (!b) return std::nullopt;
        return b->id;
    };
    src.seed_for = [n](std::uint64_t height) { return n->index().seed_hash_for_height(height); };
    return src;
}

} // namespace c2pool::v37n::xmr::o2
