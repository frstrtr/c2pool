// SPDX-License-Identifier: AGPL-3.0-or-later
/// Phase S8 — Dash sharechain pool-node leaf 1: per-peer state (src/impl/dash/peer.hpp).
///
/// dash::Peer is the analog of btc::Peer / dgb::Peer: the state a pool Node holds
/// for each connected p2pool share-network peer. The pool-node bridge (node.hpp,
/// a later leaf) keys a Peer off every connection and drives it from the share
/// message handlers. This KAT pins the observable contract those handlers read:
///
///   (a) fresh-peer defaults — no negotiated version yet, empty subversion,
///       zeroed services/nonce, empty remember-sets, connection time stamped.
///   (b) version-handshake fields round-trip (what the `version` handler writes).
///   (c) the remembered-tx protocol state: m_remote_txs is a dedup hash set and
///       m_remembered_txs maps hash -> full coin::Transaction with erase.
///   (d) connection timestamps are monotonic across successive peers.

#include <impl/dash/peer.hpp>
#include <impl/dash/coin/transaction.hpp>

#include <core/uint256.hpp>

#include <gtest/gtest.h>

#include <chrono>

using dash::Peer;

namespace
{
uint256 H(uint8_t b)
{
    uint256 h;
    h.begin()[0] = b;
    return h;
}
} // namespace

TEST(DashPeer, FreshDefaultsAreSane)
{
    Peer p;
    EXPECT_FALSE(p.m_other_version.has_value());
    EXPECT_TRUE(p.m_other_subversion.empty());
    EXPECT_EQ(p.m_other_services, 0u);
    EXPECT_EQ(p.m_nonce, 0u);
    EXPECT_TRUE(p.m_remote_txs.empty());
    EXPECT_TRUE(p.m_remembered_txs.empty());
    EXPECT_LE(p.m_connected_at, std::chrono::steady_clock::now());
}

TEST(DashPeer, VersionHandshakeRoundTrip)
{
    Peer p;
    p.m_other_version = 70238u;        // dashd-aligned proto seen on the wire
    p.m_other_subversion = "/c2pool-dash:0.1/";
    p.m_other_services = 0x9u;
    p.m_nonce = 0xdeadbeefull;

    ASSERT_TRUE(p.m_other_version.has_value());
    EXPECT_EQ(*p.m_other_version, 70238u);
    EXPECT_EQ(p.m_other_subversion, "/c2pool-dash:0.1/");
    EXPECT_EQ(p.m_other_services, 0x9u);
    EXPECT_EQ(p.m_nonce, 0xdeadbeefull);
}

TEST(DashPeer, RemoteTxSetDedups)
{
    Peer p;
    p.m_remote_txs.insert(H(1));
    p.m_remote_txs.insert(H(2));
    p.m_remote_txs.insert(H(1)); // duplicate advertise
    EXPECT_EQ(p.m_remote_txs.size(), 2u);
    EXPECT_EQ(p.m_remote_txs.count(H(1)), 1u);
    EXPECT_EQ(p.m_remote_txs.count(H(9)), 0u);
}

TEST(DashPeer, RememberedTxRoundTripAndErase)
{
    Peer p;

    dash::coin::MutableTransaction mtx;
    mtx.version = 2;
    mtx.type = 5;          // DIP4 CBTX
    mtx.locktime = 99;
    dash::coin::Transaction tx(mtx);

    const uint256 key = H(7);
    p.m_remembered_txs.emplace(key, tx);

    auto it = p.m_remembered_txs.find(key);
    ASSERT_NE(it, p.m_remembered_txs.end());
    EXPECT_EQ(it->second.version, 2);
    EXPECT_EQ(it->second.type, 5);
    EXPECT_EQ(it->second.locktime, 99u);

    EXPECT_EQ(p.m_remembered_txs.erase(key), 1u);
    EXPECT_TRUE(p.m_remembered_txs.empty());
}

TEST(DashPeer, ConnectedAtMonotonicAcrossPeers)
{
    Peer a;
    Peer b;
    EXPECT_LE(a.m_connected_at, b.m_connected_at);
}