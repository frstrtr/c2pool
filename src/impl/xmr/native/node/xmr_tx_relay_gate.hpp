// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/node/xmr_tx_relay_gate.hpp
//
// TXPOOL-RESUME-2: the decision behind C3's relay gate (NativeNode::
// publish_tx_gate_), kept apart from the node so it can be pinned by a KAT.
//
// THE HOLE IT CLOSES (mainnet fresh boot, 09-25 verify). The gate opened the
// moment the index reported synced. The index flushes a connect batch as ALL
// its MainchainEvents first and THEN all its BlockTxEvents (ChainIndex::
// flush_events_), and it is the BlockTxEvents that feed the output set the
// txpool resolves rings against. The first MainchainEvent of the catch-up
// batch that closed the sync therefore opened the gate and sent the 2010 while
// the output set still stood at the batch's first block (3770271 against an
// index tip of 3770450): the 77-tx complement answer was admitted with 76 rings
// UNRESOLVED (excluded from every template, never re-resolved, only mined out),
// and the pool was then declared warm on it -- first templates 1..22 tx while
// the pool held 83-92.
//
// THE RULE. The gate OPENS only when the index is synced AND the output set has
// been fed up to the index tip: the node calls note_chain_events_pending() when
// a flush starts delivering chain events, and note_outset_at_tip() when the
// BlockTxEvent of the index tip has been fed to the output set (or on a driver
// tick, which runs on the same verify thread and so never inside a flush). An
// OPEN gate is not closed by that lag -- in steady state each block is a
// one-event flush, and a relayed ring cannot reference the newest 10 blocks --
// only by a sync loss. Every opening (boot, and every regain after a sync loss)
// asks for a new txpool-complement round: while the gate was shut every relay
// was refused NotSynced, and a relayed tx is pushed only once.
//
// THREADING: the verify thread only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>

#define XMR_NATIVE_HAVE_TX_RELAY_GATE_LATCH 1

namespace c2pool::xmr::native {

class TxRelayGateLatch {
public:
    struct Step {
        bool changed        = false;   // the gate moved (open <-> shut) on this call
        bool open           = false;   // the gate after this call
        bool arm_complement = false;   // this opening must start a new 2010 round
        bool held           = false;   // synced, but held shut for the output set
    };

    // A flush started delivering chain events; the output set is fed after them.
    void note_chain_events_pending() noexcept { outset_at_tip_ = false; }
    // The output set has been fed up to the index tip.
    void note_outset_at_tip() noexcept { outset_at_tip_ = true; }
    bool outset_at_tip() const noexcept { return outset_at_tip_; }

    Step evaluate(bool index_synced) noexcept {
        Step s;
        if (!open_) {
            if (index_synced && outset_at_tip_) {
                open_ = true;
                ++opens_;
                s.changed = s.arm_complement = true;
                held_since_open_ = held_now_;
                held_now_ = 0;
            } else if (index_synced) {
                ++held_;
                ++held_now_;
                s.held = true;
            }
        } else if (!index_synced) {
            open_ = false;
            ++closes_;
            s.changed = true;
        }
        s.open = open_;
        return s;
    }

    bool          open() const noexcept { return open_; }
    std::uint64_t opens() const noexcept { return opens_; }
    std::uint64_t closes() const noexcept { return closes_; }
    // Evaluations that found the index synced but the output set still behind.
    std::uint64_t held() const noexcept { return held_; }
    // How many of those preceded the latest opening.
    std::uint64_t held_before_last_open() const noexcept { return held_since_open_; }

private:
    bool          open_          = false;
    bool          outset_at_tip_ = true;   // nothing pending before the first flush
    std::uint64_t opens_ = 0, closes_ = 0, held_ = 0, held_now_ = 0, held_since_open_ = 0;
};

} // namespace c2pool::xmr::native
