// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// c2pool-btc without --bitcoind: a pool of outbound coin-network peers
// (kCoinPoolTargetPeers) drawn from BtcCoinPeerManager. It replaces the single
// standalone header-source connection. main_btc.cpp wires it to the header
// chain, the coin node's events and the peer manager; the KATs drive it with
// fakes (coin_peer_pool_test.cpp).
//
// The pool itself is basic_coin_peer_pool.hpp (BasicCoinPeerPool, shared with
// c2pool-bip110); this header instantiates it with the BTC coin types: a
// block's identity is SHA256d of its 80-byte header, a transaction's txid
// SHA256d of its non-witness serialization and its wtxid SHA256d with witness.

#include "basic_coin_peer_pool.hpp"
#include "block.hpp"
#include "transaction.hpp"

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

namespace btc::coin {

/// The BTC coin types and hashes of the pool.
struct BtcPoolCoin {
    using Header = BlockHeaderType;
    using Block  = BlockType;
    using Tx     = btc::coin::Transaction;

    static uint256 header_hash(const Header& header)
    {
        auto packed = pack(header);
        return Hash(packed.get_span());
    }

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

using PoolPeerHooks    = BasicPoolPeerHooks<BtcPoolCoin>;
using CoinPeerPoolHost = BasicCoinPeerPoolHost<BtcPoolCoin>;
using CoinPeerPool     = BasicCoinPeerPool<BtcPoolCoin>;

inline uint256 pool_header_hash(const BlockHeaderType& header)
{
    return BtcPoolCoin::header_hash(header);
}

} // namespace btc::coin
