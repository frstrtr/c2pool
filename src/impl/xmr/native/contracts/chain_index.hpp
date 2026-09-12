// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/contracts/chain_index.hpp
//
// The C2 chain-state index surfaces, both directions:
//
//   IChainIndexInbound  -- what C1 (levin P2P) calls when wire data arrives.
//                          Called on the io thread; every method must enqueue
//                          and return. No parsing, no hashing, no locks held.
//   IChainView          -- what C4 (template), C5 (relay), C6 (parity) and the
//                          W4 finalize driver read. Pinned name per D-2.
//
// The third surface, IChainServing (the io-thread read side that answers a
// peer's chain/objects requests), is in serving.hpp because C1 depends on it
// from a different thread with a different latency contract.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "types.hpp"

namespace c2pool::xmr::native {

// ---------------------------------------------------------------------------
// C1 -> C2. Implemented by the index, called on the io thread.
// ---------------------------------------------------------------------------
class IChainIndexInbound {
public:
    virtual ~IChainIndexInbound() = default;

    // HANDSHAKE (1001) / TIMED_SYNC (1002) payload from a peer.
    virtual void on_peer_sync_data(const PeerRef&, const PeerSyncData&) = 0;

    // RESPONSE_CHAIN_ENTRY (2007). Hint fields inside are recomputed, not trusted.
    virtual void on_chain_entry(const PeerRef&, ChainEntry&&) = 0;

    // RESPONSE_GET_OBJECTS (2004). `missed` are ids the peer could not serve.
    virtual void on_objects(const PeerRef&,
                            std::vector<BlockEntry>&& blocks,
                            std::vector<Hash>&&       missed,
                            std::uint64_t             peer_height) = 0;

    // NOTIFY_NEW_BLOCK (2001) / NOTIFY_NEW_FLUFFY_BLOCK (2008). `fluffy` says
    // whether tx bodies were omitted, in which case the index completes the
    // block from the txpool or via IChainFetcher::request_fluffy_missing (D-5).
    virtual void on_new_block(const PeerRef&,
                              BlockEntry&&  block,
                              std::uint64_t peer_height,
                              bool          fluffy) = 0;

    // The connection is gone; drop its in-flight spans and its cohort vote.
    virtual void on_peer_gone(const PeerRef&) = 0;
};

// ---------------------------------------------------------------------------
// C2 -> consumers. The read view of the index.
//
// Threading: implementations must be safe to call from consumer threads while
// the verify thread advances the tip. Cheap accessors (tip, epoch_seq) are
// expected to be lock-free or nearly so; the window snapshots may take a lock.
// ---------------------------------------------------------------------------
class IChainView {
public:
    virtual ~IChainView() = default;

    using EventSink   = std::function<void(const node::MainchainEvent&)>;
    using TxEventSink = std::function<void(const BlockTxEvent&)>;

    // --- tip and template state ---------------------------------------------
    virtual std::optional<node::ChainMainBlock> tip() const = 0;

    // The five state windows in one snapshot. nullopt while !sync_state().synced
    // (fail-closed: never serve a template from a half-built index).
    virtual std::optional<TemplateInputs> template_inputs() const = 0;

    // Monotone counter, bumped on every tip change. Lock-free; the template arm
    // uses it to decide whether a rebuild is needed without taking a snapshot.
    virtual std::uint64_t epoch_seq() const = 0;

    // --- MainchainIndex semantics (unchanged for XmrFinalizeDriver) ----------
    virtual std::optional<node::ChainMainBlock> by_id(const Hash&) const = 0;
    virtual std::optional<node::ChainMainBlock> by_height(std::uint64_t) const = 0;
    virtual std::optional<std::uint64_t>        height_of(const Hash&) const = 0;
    virtual std::uint64_t confirmation_depth(const Hash&) const = 0;
    virtual bool          is_on_best_chain(const Hash&) const = 0;

    // --- trust boundaries ----------------------------------------------------
    // Nothing at or below anchor_height() is reorgable; a peer that offers such
    // a fork is an oracle disagreement, not a reorg.
    virtual std::uint64_t anchor_height() const = 0;
    // Highest height fully verified at level L4. Callers driving settlement
    // finalization MUST NOT advance past this.
    virtual std::uint64_t verified_frontier() const = 0;

    // RandomX seed (key-block id) for a height, resolved on the best chain.
    virtual std::optional<Hash> seed_hash_for_height(std::uint64_t) const = 0;

    // --- events --------------------------------------------------------------
    virtual void subscribe(EventSink) = 0;
    virtual void subscribe_txs(TxEventSink) = 0;

    // --- own block -----------------------------------------------------------
    // Submit a block we mined. Applies D-14 PREFER-OWN at equal cumulative
    // difficulty. Returns false and fills `why` when the block is rejected.
    virtual bool submit_own_block(const BlockEntry&, std::string& why) = 0;

    // --- telemetry -----------------------------------------------------------
    virtual SyncState sync_state() const = 0;
};

// The plan's C2 component is named "chain index"; D-2 pinned IChainView as the
// consumer-facing name. This alias exists so either spelling compiles.
using IChainIndex = IChainView;

} // namespace c2pool::xmr::native
