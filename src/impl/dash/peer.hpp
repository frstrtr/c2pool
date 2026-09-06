// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Dash p2pool sharechain pool-peer state.
//
// S8 pool-node leaf 1 of N. Mirrors btc::Peer / dgb::Peer: the per-peer state a
// pool Node keeps for every connected p2pool share-network peer (NOT a dashd
// coin-daemon peer — that layer is coin/p2p_connection.hpp). Tracks the
// negotiated version/subversion/services from the `version` handshake, the
// connection timestamp, and the remembered-transaction sets used by the
// share-message protocol (remote_txs = hashes the peer advertises; remembered_txs
// = full txs we have forwarded/learned, keyed by hash).
//
// Pure state struct, no socket/IO — header-only, rig-free, fenced to src/impl/dash/.

#include "coin/transaction.hpp"
#include "tx_inject_relay.hpp"   // #157 M2: dash::PeerInjectGuard

#include <chrono>
#include <map>
#include <optional>
#include <set>
#include <string>

#include <core/tx_advertiser.hpp>
#include <core/uint256.hpp>

namespace dash
{

struct Peer
{
    // === negotiated via the `version` handshake ===
    std::optional<uint32_t> m_other_version;
    std::string m_other_subversion;
    uint64_t m_other_services{0};
    uint64_t m_nonce{0};

    std::chrono::steady_clock::time_point m_connected_at{std::chrono::steady_clock::now()};

    // === remembered-transaction protocol state ===
    std::set<uint256> m_remote_txs;                       // hashes the remote peer has advertised
    std::map<uint256, coin::Transaction> m_remembered_txs; // full txs keyed by hash

    // Send side of the tx-pool advertisement: our reconstruction of what this
    // peer believes WE hold, so each sweep can emit only the delta as
    // have_tx / losing_tx. Mirror image of m_remote_txs above (what the peer
    // told us IT holds). See core/tx_advertiser.hpp for canonical semantics.
    core::TxAdvertState m_tx_advert;

    // #157 M2: per-peer tx-injection DoS state — a sliding-window rate cap plus a
    // bounded per-peer txid dedup set, consulted by ingest_peer_inject before any
    // submit_inject work. Inert unless --embedded-tx-inject is armed.
    dash::PeerInjectGuard m_inject_guard;
};

}; // namespace dash