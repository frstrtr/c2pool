// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// bip110::coin::NodeP2PPoolPeer -- one CoinPeerPool connection over the BIP-110
// coin P2P driver (p2p::NodeP2P) with its own event sink: c2pool-btc's pooled
// connection (btc::coin::BasicNodeP2PPoolPeer,
// impl/btc/coin/basic_coin_peer_pool_p2p.hpp; its lifetime notes apply) bound
// to the BIP-110 driver and sink.
//
// Every pooled fork peer is the same driver as the primary connection it
// replaces, so each of them keeps the BIP-110 peer rules: a peer whose version
// lacks NODE_BLAKE2B (service bit 28) is dropped before verack (the pool then
// drops the slot as a failed dial), our version carries NODE_BLAKE2B and the
// branded user agent (BIP110_COIN_SUBVER), and gossiped addr records are kept
// only for NODE_BLAKE2B peers. make_pool_peer sets, before the dial, the
// BIP-110 block identity (bip110::coin::block_hash) as the hash the driver
// requests a BIP 130 announced block by, filters announcements by, and serves
// a relayed block and its compact-block transactions by; then the caller's
// setup (main_bip110: the peer crawl, the addr intake and self-advertisement,
// the BIP 35 opt-in).

#include "block.hpp"
#include "coin_peer_pool.hpp"
#include "header_chain.hpp"   // block_hash
#include "node_interface.hpp"
#include "p2p_node.hpp"

#include <impl/btc/coin/basic_coin_peer_pool_p2p.hpp>

#include <core/netaddress.hpp>

#include <functional>
#include <memory>
#include <string>
#include <utility>

#include <boost/asio.hpp>

namespace bip110::coin {

template <typename ConfigT>
using NodeP2PPoolPeer = btc::coin::BasicNodeP2PPoolPeer<Bip110PoolCoin, ConfigT, p2p::NodeP2P,
                                                        bip110::interfaces::Node>;

/// The setup of a pooled fork peer's driver: the BIP-110 block identity, then
/// `more` (optional).
template <typename ConfigT>
inline std::function<void(p2p::NodeP2P<ConfigT>&)>
pool_peer_setup(std::function<void(p2p::NodeP2P<ConfigT>&)> more = {})
{
    return [more = std::move(more)](p2p::NodeP2P<ConfigT>& driver) {
        driver.set_header_hash_fn([](const BlockHeaderType& h) { return block_hash(h); });
        if (more)
            more(driver);
    };
}

/// A pooled fork-peer connection to `addr`, reporting through `hooks`, with
/// pool_peer_setup(more) applied before it dials.
template <typename ConfigT>
inline std::unique_ptr<PoolPeer>
make_pool_peer(boost::asio::io_context* ioc, ConfigT* config, const NetService& addr,
               PoolPeerHooks hooks, std::function<void(p2p::NodeP2P<ConfigT>&)> more = {})
{
    return std::make_unique<NodeP2PPoolPeer<ConfigT>>(ioc, config, addr, std::move(hooks),
                                                      std::string(),
                                                      pool_peer_setup<ConfigT>(std::move(more)));
}

} // namespace bip110::coin
