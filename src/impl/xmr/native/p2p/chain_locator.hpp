// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/p2p/chain_locator.hpp
//
// Wave 1, component C1c: the NOTIFY_REQUEST_CHAIN (2006) locator, and the
// terminus rule that decides whether a peer answers us at all.
//
// SHAPE. monerod's Blockchain::get_short_chain_history walks the best chain
// from the tip: the last 10 ids one by one, then back by a doubling step
// (1, 2, 4, 8, ...), and finally the genesis id. Ours is the same walk, run
// over whatever the index retains (IChainServing::locator()), with one
// mandatory difference at the end.
//
// THE TERMINUS RULE, and why it is not cosmetic. The handler behind 2006 is
// Blockchain::find_blockchain_supplement, and it opens with
//
//     if (qblock_ids.back() != m_db->get_block_hash_from_height(0)) {
//         MCERROR("net.p2p", "Client sent wrong NOTIFY_REQUEST_CHAIN: "
//                            "genesis block mismatch");
//         return false;
//     }
//
// and cryptonote_protocol_handler::handle_request_chain turns that false into
// drop_connection(). There is no error frame, no return code, no hint: the
// connection simply ends. A node that terminated its locator at "the oldest
// block I retain" would be dropped by every peer it ever asked to sync from,
// and the symptom would present as "peers keep disconnecting", not as "my
// locator is wrong". This is the single most expensive way to get C1 wrong,
// which is why finalize_locator() cannot be told not to append the genesis id.
//
// WHY THIS IS C1's JOB AND NOT C2's. The two locators are different objects
// with different obligations, and conflating them is the trap:
//
//   * IChainServing::locator() (C2c, chain/xmr_chain_index.hpp) walks the rows
//     the index RETAINS and terminates at the oldest one. That is correct for
//     what it is -- a set of ids the index can actually prove -- and it must
//     not invent a genesis block, because an anchor-started node (C2b begins at
//     stagenet height 2204000) has never seen height 0.
//   * The WIRE locator we hand a peer is a different thing: it is a question,
//     not a claim. Every id in it says "do you know this?", and the terminus
//     says "...and here is the network I am asking about". Appending the pinned
//     network genesis id (chain_seeds.hpp, live-verified) makes the question
//     answerable without the index ever pretending to hold height 0.
//
// The splice is unaffected: find_blockchain_supplement takes the FIRST id it
// recognises, scanning from the front, so a peer on our chain splices at our
// tip-most shared id and only a peer that shares nothing with our retained
// window falls through to the genesis id -- at which point being answered from
// height 0 is strictly better than being dropped.
//
// SCOPE FENCE (standing XMR-lane rule): everything under src/impl/xmr/. This
// tree is a WORK SOURCE for the pool, not part of the v37 share-chain record.
//
// Header-only, STL only. Every function here is pure.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "impl/xmr/native/contracts/serving.hpp"
#include "impl/xmr/native/contracts/types.hpp"
#include "impl/xmr/native/p2p/chain_seeds.hpp"

namespace c2pool::xmr::native::p2p {

// The first N ids are consecutive before the doubling starts; monerod uses 10.
inline constexpr std::size_t LOCATOR_DENSE_IDS = 10;

// Our own ceiling on the ids we send. monerod imposes only the 512 KiB body cap
// on 2006 (~16 000 ids); a doubling walk over a 2048-row window never needs
// more than ~21, so 64 is generous headroom that still bounds a bug.
inline constexpr std::size_t LOCATOR_MAX_IDS = 64;

// ---------------------------------------------------------------------------
// The pure walk: which heights a locator samples, descending, between a tip and
// the oldest height available. `oldest` is always included; `tip` is always
// first. Exposed separately from the id lookup so the KAT can pin the shape
// against monerod's get_short_chain_history without needing an index.
// ---------------------------------------------------------------------------
inline std::vector<std::uint64_t> locator_heights(std::uint64_t tip,
                                                  std::uint64_t oldest,
                                                  std::size_t   max_ids = LOCATOR_MAX_IDS) {
    std::vector<std::uint64_t> out;
    if (oldest > tip || max_ids == 0) return out;

    std::uint64_t h    = tip;
    std::uint64_t step = 1;
    std::size_t   n    = 0;
    while (true) {
        out.push_back(h);
        if (h == oldest) break;
        // Reserve the last slot for `oldest`: a truncated walk that stops in
        // the middle of the chain is a locator with no floor.
        if (out.size() + 1 >= max_ids) { out.push_back(oldest); break; }
        ++n;
        if (n > LOCATOR_DENSE_IDS) step *= 2;
        h = (h - oldest > step) ? (h - step) : oldest;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Turn a chain of retained ids into the wire locator.
//
// Contract, in the order the steps are applied:
//   1. drop consecutive duplicates (a caller whose oldest row IS the tip);
//   2. truncate to max_ids - 1, keeping the tip-most ids (they are the ones
//      that actually splice);
//   3. APPEND THE GENESIS ID, unless the last surviving id already is it.
//
// Step 3 is unconditional and has no opt-out. `genesis` must be a real network
// genesis (chain_seeds.hpp); an all-zero hash is refused by returning an empty
// locator, because sending a zero terminus is exactly the dropped-connection
// case this file exists to prevent, and an empty locator at least fails loudly
// at the call site.
// ---------------------------------------------------------------------------
inline std::vector<Hash> finalize_locator(std::vector<Hash> ids,
                                          const Hash&       genesis,
                                          std::size_t       max_ids = LOCATOR_MAX_IDS) {
    if (detail::is_zero(genesis) || max_ids == 0) return {};

    std::vector<Hash> out;
    out.reserve(ids.size() + 1);
    for (const Hash& id : ids) {
        if (detail::is_zero(id)) continue;                 // never ask about nothing
        if (!out.empty() && out.back() == id) continue;     // collapse repeats
        out.push_back(id);
    }
    if (out.size() > max_ids - 1) out.resize(max_ids - 1);
    if (out.empty() || !(out.back() == genesis)) out.push_back(genesis);
    return out;
}

// The predicate the peer applies to us, written out so callers and the KAT
// assert the same thing.
inline bool locator_ends_with_genesis(const std::vector<Hash>& locator,
                                      const Hash&              genesis) noexcept {
    return !locator.empty() && locator.back() == genesis;
}

// ---------------------------------------------------------------------------
// The io-thread call site: read the index's retained ids and finalize them.
// IChainServing::locator() is contractually O(log n) and non-blocking, so this
// is safe to call from the socket thread when a sync request is due.
// ---------------------------------------------------------------------------
inline std::vector<Hash> build_locator(const IChainServing& serving,
                                       XmrNet               net,
                                       std::size_t          max_ids = LOCATOR_MAX_IDS) {
    return finalize_locator(serving.locator(), genesis_id(net), max_ids);
}

} // namespace c2pool::xmr::native::p2p
