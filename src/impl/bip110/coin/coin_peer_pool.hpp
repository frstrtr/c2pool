// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// bip110::coin::CoinPeerPool -- c2pool-bip110's pool of outbound fork peers
// (kCoinPoolTargetPeers): the same pool as c2pool-btc's standalone one
// (btc::coin::BasicCoinPeerPool, impl/btc/coin/basic_coin_peer_pool.hpp, which
// holds no coin types), with the BIP-110 coin types. It replaces the single
// primary fork-peer connection. main_bip110.cpp wires it to the header chain,
// the coin node's events and the peer manager; bip110_coin_peer_pool_kat.cpp
// drives it with fakes.
//
// What is BIP-110 here: a block's identity -- the hash the header chain is
// keyed by, and that inv / getdata carry -- is bip110::coin::block_hash():
// SHA256d of a v1 (80-byte) header below the fork, the BLAKE2b commitment hash
// of a v2 (164-byte) header at and after it. A body is matched to its header,
// fetched, held for its parent and connected by that identity, never by
// SHA256d of the header. Transactions keep Bitcoin's txid / wtxid (SHA256d of
// the non-witness / witness serialization).
//
// Who the pooled peers are (NODE_BLAKE2B version gate, branded user agent,
// addr crawl, self-advertisement) is the per-connection driver's business:
// coin_peer_pool_p2p.hpp.

#include "block.hpp"
#include "header_chain.hpp"   // block_hash: the BIP-110 block identity
#include "transaction.hpp"

#include <impl/btc/coin/basic_coin_peer_pool.hpp>

#include <core/hash.hpp>
#include <core/netaddress.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <functional>
#include <set>
#include <string>
#include <vector>

namespace bip110::coin {

/// The BIP-110 coin types and hashes of the pool.
struct Bip110PoolCoin {
    using Header = BlockHeaderType;
    using Block  = BlockType;
    using Tx     = bip110::coin::Transaction;

    /// The block identity (uint256::ZERO for a v2 layout the BLAKE2b
    /// pipeline refuses; the header chain holds no such header).
    static uint256 header_hash(const Header& header) { return block_hash(header); }

    static uint256 txid(const Tx& tx)
    {
        MutableTransaction mtx(tx);
        auto packed = pack(TX_NO_WITNESS(mtx));
        return Hash(packed.get_span());
    }

    static uint256 wtxid(const Tx& tx)
    {
        MutableTransaction mtx(tx);
        auto packed = pack(TX_WITH_WITNESS(mtx));
        return Hash(packed.get_span());
    }
};

using btc::coin::PoolPeer;
using btc::coin::CoinPeerRow;
using btc::coin::coin_peer_rows;
using btc::coin::kCoinPoolTargetPeers;
using btc::coin::kCoinPoolTickSec;
using btc::coin::kCoinPoolPollSec;

using PoolPeerHooks    = btc::coin::BasicPoolPeerHooks<Bip110PoolCoin>;
using CoinPeerPoolHost = btc::coin::BasicCoinPeerPoolHost<Bip110PoolCoin>;
using CoinPeerPool     = btc::coin::BasicCoinPeerPool<Bip110PoolCoin>;

inline uint256 pool_header_hash(const BlockHeaderType& header)
{
    return Bip110PoolCoin::header_hash(header);
}

/// An explicit peer given by host name, not by an IP address: the pool dials
/// addresses only (pool_candidates), so main resolves it first
/// (add_resolved_peers).
inline bool is_peer_hostname(const NetService& ns)
{
    return !ns.address().empty() && classify_address(ns.address()) == AddrClass::invalid;
}

/// Put `resolved` (the addresses of the host-name entry `host`) right after
/// that entry in `list`, so they keep its place among the explicit peers; one
/// already in the list is not added again. Returns the number added.
inline size_t add_resolved_peers(std::vector<NetService>& list, const NetService& host,
                                 const std::vector<NetService>& resolved)
{
    auto at = std::find(list.begin(), list.end(), host);
    if (at == list.end())
        return 0;
    size_t added = 0;
    auto pos = std::next(at);
    for (const auto& r : resolved) {
        if (std::find(list.begin(), list.end(), r) != list.end())
            continue;
        pos = std::next(list.insert(pos, r));
        ++added;
    }
    return added;
}

/// The pool's dial candidates (CoinPeerPoolHost::candidates): the explicit fork
/// peers (--peer) first, in order, then `manager`'s (the peer manager's
/// get_peers_to_connect, optional), never a key in `exclude` (the pool's own
/// slots) or `also_taken` (the fan-out broadcaster's slots), and none twice.
/// The manager is asked to exclude all of those and the explicit peers.
inline std::vector<PeerEndpoint> pool_candidates(
    const std::vector<NetService>& explicit_peers, const std::set<std::string>& exclude,
    const std::vector<std::string>& also_taken,
    const std::function<std::vector<PeerEndpoint>(const std::set<std::string>&)>& manager)
{
    std::set<std::string> taken = exclude;
    taken.insert(also_taken.begin(), also_taken.end());
    std::vector<PeerEndpoint> out;
    for (const auto& ns : explicit_peers) {
        auto ep = PeerEndpoint::from(ns);
        if (!ep || !taken.insert(ep->to_string()).second)
            continue;
        out.push_back(*ep);
    }
    if (manager)
        for (const auto& ep : manager(taken))
            if (taken.insert(ep.to_string()).second)
                out.push_back(ep);
    return out;
}

} // namespace bip110::coin
