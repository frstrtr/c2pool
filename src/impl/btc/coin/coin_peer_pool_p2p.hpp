// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// btc::coin::NodeP2PPoolPeer -- one CoinPeerPool connection over the BTC
// coin P2P driver (p2p::NodeP2P). Each connection has its own event sink, so
// the pool knows which peer sent a headers message, an announcement or a
// block body.
//
// The connection itself is basic_coin_peer_pool_p2p.hpp (BasicNodeP2PPoolPeer,
// shared with c2pool-bip110; its lifetime notes apply); this header binds it
// to the BTC driver and sink.

#include "basic_coin_peer_pool_p2p.hpp"
#include "coin_peer_pool.hpp"
#include "node_interface.hpp"
#include "p2p_node.hpp"

namespace btc::coin {

template <typename ConfigT>
using NodeP2PPoolPeer =
    BasicNodeP2PPoolPeer<BtcPoolCoin, ConfigT, p2p::NodeP2P, btc::interfaces::Node>;

} // namespace btc::coin
