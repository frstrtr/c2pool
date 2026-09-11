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

    // Events produced since start, drained or not. A tip driver that produced
    // nothing and a consumer that dropped everything are indistinguishable
    // without this, and they have opposite fixes.
    std::function<std::uint64_t()> events_seen;

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

    src.events_seen = [n] { return n->mainchain_events_seen(); };
    return src;
}

} // namespace c2pool::v37n::xmr::o2
