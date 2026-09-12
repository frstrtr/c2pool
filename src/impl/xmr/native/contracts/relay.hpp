// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/contracts/relay.hpp
//
// C5: dual-arm found-block delivery. One found block goes out over the levin
// P2P arm (fluffy push) and/or the monerod submit arm, and the outcome of BOTH
// arms is recorded in one verdict.
//
// MUST-FIX (a): this is BlockRelayVerdict. The transaction-relay verdict is
// TxRelayVerdict in txpool.hpp. They are unrelated shapes and no longer share
// a name.
//
// CONTRACT NOTE (projection, not a signature change): the plan writes C5's
// entry point as relay(const submit::BlockCandidate&, nonce, extra_nonce).
// Including xmr_live_submit.hpp here would pull the live-transport dependency
// into every contracts consumer and break the "STL plus existing node value
// types" rule that makes this family safe to include everywhere. So the
// interface below takes BlockRelayRequest, the contracts-level projection of
// exactly that argument list. The concrete C5 LevinBlockRelay keeps the plan's
// constructor and its BlockCandidate overload, and adapts into this struct.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "types.hpp"

namespace c2pool::xmr::native {

// Which arm goes first. DaemonFirst is the default while a daemon is armed:
// monerod validates the block for free before we put our P2P identity behind it.
enum class ArmOrder : std::uint8_t { DaemonFirst = 0, Parallel = 1, P2pOnly = 2 };

inline const char* to_string(ArmOrder o) noexcept {
    switch (o) {
        case ArmOrder::DaemonFirst: return "DaemonFirst";
        case ArmOrder::Parallel:    return "Parallel";
        case ArmOrder::P2pOnly:     return "P2pOnly";
    }
    return "?";
}

struct RelayPolicy {
    ArmOrder      order                = ArmOrder::DaemonFirst;
    // Push the full bodies with the block instead of a hash-only fluffy frame.
    bool          include_all_tx_bodies = false;
    // Answer REQUEST_FLUFFY_MISSING_TX for blocks we pushed.
    bool          serve_missing_tx      = true;
    // How long the confirmation watch waits for the block to appear on our own
    // verified chain before it escalates.
    std::uint32_t confirm_timeout_s     = 120;
};

// The contracts-level projection of a found block (see the CONTRACT NOTE).
struct BlockRelayRequest {
    Hash                      block_id{};
    std::uint64_t             height       = 0;
    std::vector<std::uint8_t> block_blob;          // complete, with the coinbase
    std::vector<Hash>         tx_hashes;           // selected txs, block order
    std::uint32_t             nonce        = 0;
    std::uint32_t             extra_nonce  = 0;
};

// MUST-FIX (a): renamed from RelayVerdict.
struct BlockRelayVerdict {
    Hash          block_id{};
    std::size_t   p2p_peers_sent  = 0;   // state_normal peers actually written to
    bool          daemon_armed    = false;
    bool          daemon_accepted = false;
    bool          daemon_rejected = false;
    // "p2p", "daemon", or "" when neither arm got it out.
    std::string   landed_first;
    // Filled when reached_network() is false, so the failure is never silent.
    std::string   why;

    bool reached_network() const noexcept {
        return p2p_peers_sent > 0 || daemon_accepted;
    }
};

class IBlockRelay {
public:
    virtual ~IBlockRelay() = default;

    // Precondition, enforced by the caller and NOT re-checked here: the block
    // passed the 128-bit RandomX gate, candidate validation, and the coinbase
    // materialisation invariants. Nothing else may reach this method.
    virtual BlockRelayVerdict relay(const BlockRelayRequest&) = 0;

    // Answer a peer that is missing transactions from a block we pushed.
    virtual bool on_request_fluffy_missing_tx(
            const Hash&                       block_id,
            const std::vector<std::uint64_t>& tx_indices,
            std::vector<std::uint8_t>&        reply_frame) = 0;
};

} // namespace c2pool::xmr::native
