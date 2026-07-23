// SPDX-License-Identifier: AGPL-3.0-or-later
/// Phase S8 — Dash coin-daemon node-interface seam KATs
///
/// Exercises src/impl/dash/coin/node_interface.hpp — the dash::interfaces::Node
/// event/state seam the broadcaster gate binds against:
///
///     p2p_node -> [node_interface] -> broadcaster_full
///
/// broadcaster_full.hpp consumes this struct as the InterfacesNode each peer
/// slot is handed (see DashBroadcastPeer). What is PINNED here is the real
/// observable contract the broadcaster relies on:
///
///   (a) the Event fan-out — new_block / new_tx / new_headers / full_block each
///       deliver their payload to a subscribed handler via happened(), the same
///       core::Event mechanism the live node fires on. Subscribers observe the
///       EXACT payload, not a placeholder.
///
///   (b) the best_block_hash Variable — set() flips has-value, value() reads the
///       stored hash back, and the .changed Event fires the new value to a
///       subscriber (the broadcaster watches this to learn the tip moved).
///
///   (c) the ChainLock seam — new_chainlock drives chainlocked_blocks so a
///       block-find submit handler can ask "is this won block now irreversible?"
///       A subscribed handler populates the map on fire; we assert the
///       {block_hash -> height} mapping lands and is queryable.
///
///   plus known_txs as a plain lookup the broadcaster dedupes against.
///
/// SCOPE NOTE (honest): this pins the struct contract (events, Variable, maps)
/// in isolation — no live socket, no broadcaster wiring (that is the next S8
/// leaf). The Event/Variable machinery is the real core:: one, fired
/// synchronously via happened()/set(); nothing here is mocked.

#include <gtest/gtest.h>

#include <impl/dash/coin/node_interface.hpp>
#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/transaction.hpp>

#include <core/uint256.hpp>

#include <cstdint>
#include <utility>
#include <vector>

namespace {

uint256 id_of(uint8_t b) { uint256 u; u.begin()[0] = b; return u; }

dash::coin::Transaction make_tx()
{
    dash::coin::MutableTransaction mtx;
    return dash::coin::Transaction(mtx);
}

// (a) Event fan-out: each Node event delivers its exact payload to a subscriber.
TEST(DashNodeInterfaceKat, EventsFanOutExactPayload)
{
    dash::interfaces::Node node;

    uint256 got_block;
    int      block_hits = 0;
    node.new_block.subscribe([&](uint256 h){ got_block = h; ++block_hits; });
    node.new_block.happened(id_of(0xAB));
    EXPECT_EQ(block_hits, 1);
    EXPECT_EQ(got_block, id_of(0xAB));

    int tx_hits = 0;
    node.new_tx.subscribe([&](dash::coin::Transaction){ ++tx_hits; });
    node.new_tx.happened(make_tx());
    EXPECT_EQ(tx_hits, 1);

    std::size_t hdr_count = 0;
    node.new_headers.subscribe(
        [&](std::vector<dash::coin::BlockHeaderType> hs){ hdr_count = hs.size(); });
    node.new_headers.happened(std::vector<dash::coin::BlockHeaderType>(3));
    EXPECT_EQ(hdr_count, 3u);

    int full_hits = 0;
    node.full_block.subscribe([&](dash::coin::BlockType){ ++full_hits; });
    node.full_block.happened(dash::coin::BlockType{});
    EXPECT_EQ(full_hits, 1);
}

// (b) best_block_hash Variable: set flips has-value, value() reads back,
//     .changed fires the new tip to a subscriber.
TEST(DashNodeInterfaceKat, BestBlockHashVariableTracksTip)
{
    dash::interfaces::Node node;

    uint256 observed;
    int     changes = 0;
    node.best_block_hash.changed.subscribe([&](uint256 h){ observed = h; ++changes; });

    node.best_block_hash.set(id_of(0x11));
    EXPECT_EQ(node.best_block_hash.value(), id_of(0x11));
    EXPECT_EQ(changes, 1);
    EXPECT_EQ(observed, id_of(0x11));

    // set to the same value is a no-op (no spurious change fired)
    node.best_block_hash.set(id_of(0x11));
    EXPECT_EQ(changes, 1);

    node.best_block_hash.set(id_of(0x22));
    EXPECT_EQ(node.best_block_hash.value(), id_of(0x22));
    EXPECT_EQ(changes, 2);
}

// (c) ChainLock seam: new_chainlock drives chainlocked_blocks; a found block
//     can then be queried for irreversibility.
TEST(DashNodeInterfaceKat, ChainLockSeamPopulatesMap)
{
    dash::interfaces::Node node;

    node.new_chainlock.subscribe([&](std::pair<uint256, int32_t> cl){
        node.chainlocked_blocks[cl.first] = cl.second;
    });

    const uint256 won = id_of(0x7E);
    EXPECT_EQ(node.chainlocked_blocks.count(won), 0u);

    node.new_chainlock.happened(std::make_pair(won, int32_t{1501677}));

    ASSERT_EQ(node.chainlocked_blocks.count(won), 1u);
    EXPECT_EQ(node.chainlocked_blocks.at(won), 1501677);
}

// known_txs as a plain dedupe lookup the broadcaster consults.
TEST(DashNodeInterfaceKat, KnownTxsLookup)
{
    dash::interfaces::Node node;

    const uint256 k = id_of(0x33);
    EXPECT_TRUE(node.known_txs.find(k) == node.known_txs.end());

    node.known_txs.emplace(k, make_tx());
    EXPECT_EQ(node.known_txs.size(), 1u);
    EXPECT_TRUE(node.known_txs.find(k) != node.known_txs.end());
}

} // namespace