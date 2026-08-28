// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <impl/ltc/config_coin.hpp>
#include <impl/ltc/coin/p2p_messages.hpp>
#include <impl/ltc/coin/p2p_node.hpp>
#include <impl/ltc/coin/node_interface.hpp>
#include <c2pool/merged/coin_peer_manager.hpp>
#include <c2pool/merged/coin_broadcaster.hpp>

#include <core/pack.hpp>
#include <core/message.hpp>

#include <boost/asio.hpp>
#include <set>
#include <vector>
#include <thread>
#include <chrono>
#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#else
#include <process.h>
#define getpid _getpid
#endif

using namespace c2pool::merged;
using namespace ltc::coin::p2p;

// ─── PeerInfo unit tests ─────────────────────────────────────────────────────

TEST(PeerInfo, DefaultConstruction)
{
    PeerInfo pi;
    EXPECT_EQ(pi.score, 0);
    EXPECT_EQ(pi.broadcast_successes, 0);
    EXPECT_EQ(pi.broadcast_failures, 0);
    EXPECT_EQ(pi.attempt_count, 0);
    EXPECT_EQ(pi.backoff_sec, 30);
    EXPECT_FALSE(pi.is_protected);
}

TEST(PeerInfo, RecordSuccess)
{
    PeerInfo pi;
    pi.record_success();
    EXPECT_EQ(pi.broadcast_successes, 1);
    EXPECT_EQ(pi.blocks_relayed, 1);
    EXPECT_EQ(pi.score, 10);
    
    pi.record_success();
    EXPECT_EQ(pi.broadcast_successes, 2);
    EXPECT_EQ(pi.blocks_relayed, 2);
    EXPECT_EQ(pi.score, 20);
}

TEST(PeerInfo, RecordFailure)
{
    PeerInfo pi;
    pi.score = 50;
    pi.record_failure();
    EXPECT_EQ(pi.broadcast_failures, 1);
    EXPECT_EQ(pi.score, 45);
}

TEST(PeerInfo, RecordConnected)
{
    PeerInfo pi;
    pi.backoff_sec = 120;
    pi.attempt_count = 3;
    pi.record_connected();
    EXPECT_EQ(pi.backoff_sec, 30);      // reset
    EXPECT_EQ(pi.attempt_count, 0);     // reset
    EXPECT_EQ(pi.connection_successes, 1);
    EXPECT_EQ(pi.score, 10);
}

TEST(PeerInfo, RecordDisconnected_RegularPeer)
{
    PeerInfo pi;
    pi.is_protected = false;
    pi.backoff_sec = 30;
    
    pi.record_disconnected();
    EXPECT_EQ(pi.attempt_count, 1);
    EXPECT_EQ(pi.backoff_sec, 60);      // doubled
    
    pi.record_disconnected();
    EXPECT_EQ(pi.attempt_count, 2);
    EXPECT_EQ(pi.backoff_sec, 120);     // doubled

    // Cap at 3600s for regular peers
    pi.backoff_sec = 2000;
    pi.record_disconnected();
    EXPECT_EQ(pi.backoff_sec, 3600);    // capped
}

TEST(PeerInfo, RecordDisconnected_ProtectedPeer)
{
    PeerInfo pi;
    pi.is_protected = true;
    pi.backoff_sec = 300;
    
    pi.record_disconnected();
    EXPECT_EQ(pi.backoff_sec, 600);     // capped at 600 for protected

    pi.record_disconnected();
    EXPECT_EQ(pi.backoff_sec, 600);     // stays at 600
}

TEST(PeerInfo, CanRetry_Protected)
{
    PeerInfo pi;
    pi.is_protected = true;
    pi.attempt_count = 999;
    pi.last_attempt = std::chrono::steady_clock::now() -
        std::chrono::seconds(1);
    // Protected peer can always retry
    EXPECT_TRUE(pi.can_retry());
}

TEST(PeerInfo, CanRetry_MaxAttempts)
{
    PeerInfo pi;
    pi.is_protected = false;
    pi.max_attempts = 10;
    pi.attempt_count = 10;
    EXPECT_FALSE(pi.can_retry());
}

TEST(PeerInfo, CanRetry_BackoffNotElapsed)
{
    PeerInfo pi;
    pi.is_protected = false;
    pi.max_attempts = 10;
    pi.attempt_count = 1;
    pi.backoff_sec = 60;
    pi.last_attempt = std::chrono::steady_clock::now();
    EXPECT_FALSE(pi.can_retry());
}

TEST(PeerInfo, ComputeScore_Protected)
{
    PeerInfo pi;
    pi.is_protected = true;
    EXPECT_EQ(pi.compute_score(), 999999);
}

TEST(PeerInfo, ComputeScore_AddrCrawlBonus)
{
    PeerInfo pi;
    pi.source = PeerInfo::Source::addr_crawl;
    pi.first_seen = std::chrono::steady_clock::now();
    int score = pi.compute_score();
    // Should include +50 for addr_crawl and +50 for age < 1h
    EXPECT_GE(score, 50);
}

TEST(PeerInfo, ComputeScore_CoindPenalty)
{
    PeerInfo pi;
    pi.source = PeerInfo::Source::coind;
    pi.first_seen = std::chrono::steady_clock::now();
    int score_coind = pi.compute_score();

    PeerInfo pi2;
    pi2.source = PeerInfo::Source::addr_crawl;
    pi2.first_seen = std::chrono::steady_clock::now();
    int score_addr = pi2.compute_score();

    // addr_crawl should score higher than coind
    EXPECT_GT(score_addr, score_coind);
}

TEST(PeerInfo, ComputeScore_BlockRelayActivity)
{
    PeerInfo pi;
    pi.first_seen = std::chrono::steady_clock::now();
    int base = pi.compute_score();

    pi.blocks_relayed = 11;
    int with_relay = pi.compute_score();
    EXPECT_GT(with_relay, base);
    // 11 blocks → +30
    EXPECT_EQ(with_relay - base, 30);
}

// ─── PeerManagerConfig tests ─────────────────────────────────────────────────

TEST(PeerManagerConfig, Defaults)
{
    PeerManagerConfig cfg;
    EXPECT_EQ(cfg.max_peers, 20);
    EXPECT_EQ(cfg.min_peers, 5);
    EXPECT_EQ(cfg.max_concurrent_connections, 3);
    EXPECT_EQ(cfg.max_connections_per_cycle, 5);
    EXPECT_EQ(cfg.base_backoff_sec, 30);
    EXPECT_EQ(cfg.max_backoff_sec, 3600);
    EXPECT_EQ(cfg.max_connection_attempts, 10);
    EXPECT_EQ(cfg.refresh_interval_sec, 1800);
    EXPECT_EQ(cfg.peer_db_save_interval_sec, 300);
    EXPECT_FALSE(cfg.is_merged);
    EXPECT_TRUE(cfg.valid_ports.empty());
}

TEST(PeerManagerConfig, MergedDefaults)
{
    PeerManagerConfig cfg;
    cfg.is_merged = true;
    cfg.min_peers = 4;
    cfg.max_connection_attempts = 5;
    cfg.refresh_interval_sec = 300;
    EXPECT_EQ(cfg.min_peers, 4);
    EXPECT_EQ(cfg.max_connection_attempts, 5);
    EXPECT_EQ(cfg.refresh_interval_sec, 300);
}

// ─── CoinPeerManager tests ──────────────────────────────────────────────────

TEST(CoinPeerManager, BasicLifecycle)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    CoinPeerManager pm(ioc, "TEST", "/tmp", cfg);
    
    EXPECT_EQ(pm.peer_count(), 0);
    EXPECT_EQ(pm.symbol(), "TEST");
    EXPECT_TRUE(pm.discovery_enabled());
}

TEST(CoinPeerManager, SetLocalNode)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    pm.set_local_node(NetService("192.168.1.1", 19335));
    EXPECT_EQ(pm.peer_count(), 1);
}

TEST(CoinPeerManager, AddDiscoveredPeer)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    cfg.valid_ports = {9333, 19335};
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    // Valid port — should be added
    pm.add_discovered_peer(NetService("45.33.32.1", 19335));
    EXPECT_EQ(pm.peer_count(), 1);
    
    // Invalid port — should be rejected
    pm.add_discovered_peer(NetService("45.33.32.2", 54321));
    EXPECT_EQ(pm.peer_count(), 1);
    
    // Duplicate — should be skipped
    pm.add_discovered_peer(NetService("45.33.32.1", 19335));
    EXPECT_EQ(pm.peer_count(), 1);
}

TEST(CoinPeerManager, AddDiscoveredPeer_NoPortFilter)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    // Empty valid_ports → accept any port
    CoinPeerManager pm(ioc, "TEST", "/tmp", cfg);
    
    pm.add_discovered_peer(NetService("45.33.32.1", 54321));
    EXPECT_EQ(pm.peer_count(), 1);
}

TEST(CoinPeerManager, GetPeersToConnect_Empty)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    std::set<std::string> connected;
    auto peers = pm.get_peers_to_connect(connected);
    EXPECT_TRUE(peers.empty());
}

TEST(CoinPeerManager, GetPeersToConnect_ReturnsAvailable)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    cfg.max_peers = 20;
    cfg.max_connections_per_cycle = 3;
    cfg.max_concurrent_connections = 5;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    // Add some peers
    pm.add_discovered_peer(NetService("45.33.32.1", 9333));
    pm.add_discovered_peer(NetService("45.33.32.2", 9333));
    pm.add_discovered_peer(NetService("45.33.32.3", 9333));
    pm.add_discovered_peer(NetService("45.33.32.4", 9333));
    
    std::set<std::string> connected;
    auto peers = pm.get_peers_to_connect(connected);
    // Should return up to max_connections_per_cycle=3
    EXPECT_LE(peers.size(), 3u);
    EXPECT_GE(peers.size(), 1u);
}

TEST(CoinPeerManager, GetPeersToConnect_ExcludesConnected)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    pm.add_discovered_peer(NetService("45.33.32.1", 9333));
    
    std::set<std::string> connected = {"45.33.32.1:9333"};
    auto peers = pm.get_peers_to_connect(connected);
    EXPECT_TRUE(peers.empty());
}

TEST(CoinPeerManager, GetPeersToConnect_RespectMaxPeers)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    cfg.max_peers = 2;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    pm.add_discovered_peer(NetService("45.33.32.1", 9333));
    pm.add_discovered_peer(NetService("45.33.32.2", 9333));
    pm.add_discovered_peer(NetService("45.33.32.3", 9333));
    
    // Already at max_peers
    std::set<std::string> connected = {"45.33.32.5:9333", "45.33.32.6:9333"};
    auto peers = pm.get_peers_to_connect(connected);
    EXPECT_TRUE(peers.empty());
}

TEST(CoinPeerManager, NotifyConnected_ResetBackoff)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    pm.add_discovered_peer(NetService("45.33.32.1", 9333));
    pm.notify_connected("45.33.32.1:9333");
    // After connected notification, peer should be marked with reset backoff
    // (only verifiable through scoring, but should not throw)
}

TEST(CoinPeerManager, NotifyDisconnected)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    pm.add_discovered_peer(NetService("45.33.32.1", 9333));
    pm.notify_disconnected("45.33.32.1:9333");
    // Should not throw, just increment attempt count
}

TEST(CoinPeerManager, BroadcastRecording)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    pm.add_discovered_peer(NetService("45.33.32.1", 9333));
    pm.record_broadcast_success("45.33.32.1:9333");
    pm.record_broadcast_failure("45.33.32.1:9333");
    // Should not throw
}

TEST(CoinPeerManager, NeedsEmergencyRefresh)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    cfg.min_peers = 5;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    EXPECT_TRUE(pm.needs_emergency_refresh(3));
    EXPECT_FALSE(pm.needs_emergency_refresh(5));
    EXPECT_FALSE(pm.needs_emergency_refresh(10));
}

TEST(CoinPeerManager, DiscoveryEnabled_MaxPeers)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    cfg.max_peers = 2;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    // No start() here, so the bucketed addrman is not loaded from disk and
    // begins empty regardless of any stale /tmp DB -> its size is exact.

    EXPECT_TRUE(pm.discovery_enabled());

    // These three peers sit in THREE DISTINCT /16 network groups (45.33 /
    // 66.42 / 89.35) so the bucketed addrman keys each into an independent
    // new-table bucket. Same-group IPs would share one bucket and race for a
    // single position, so a birthday collision could drop the third add and
    // make size() flake to 2 -- dashd-correct per-netgroup bucketing, but not
    // what this test means to measure (that discovery banks a peer past the
    // working-set cap of 2).
    pm.add_discovered_peer(NetService("45.33.32.1", 9333));
    pm.add_discovered_peer(NetService("66.42.10.2", 9333));
    // max_peers is now ONLY the working-set / outbound-dial cap: the active
    // dial set stays capped at 2 ...
    EXPECT_EQ(pm.peer_count(), 2u);
    // ... but discovery does NOT stop at the cap anymore. The bucketed
    // addrman is the getaddr sink and keeps banking gossip until it reaches
    // table capacity (dashd behaviour). The old assertion that discovery
    // halts at max_peers encoded the pre-port bug that starved daemonless
    // block download of dial candidates.
    EXPECT_TRUE(pm.discovery_enabled());

    // A candidate beyond the working-set cap is still banked into the
    // addrman (up to bucket capacity) even though it does not enter the
    // active dial set -- exactly the memory the flat working set lacked.
    pm.add_discovered_peer(NetService("89.35.131.3", 9333));
    EXPECT_EQ(pm.peer_count(), 2u);        // outbound set stays capped
    EXPECT_EQ(pm.addrman().size(), 3u);    // addrman banked all three
    EXPECT_TRUE(pm.discovery_enabled());   // and keeps harvesting
}

TEST(CoinPeerManager, PruneDead)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    cfg.max_connection_attempts = 3;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    pm.add_discovered_peer(NetService("45.33.32.1", 9333));
    // Simulate 3 disconnections to exhaust attempts
    pm.notify_disconnected("45.33.32.1:9333");
    pm.notify_disconnected("45.33.32.1:9333");
    pm.notify_disconnected("45.33.32.1:9333");
    
    pm.prune_dead_peers();
    EXPECT_EQ(pm.peer_count(), 0);
}

TEST(CoinPeerManager, PruneDead_ProtectsLocalNode)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    cfg.max_connection_attempts = 3;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    pm.set_local_node(NetService("192.168.1.1", 19335));
    // Simulate many disconnections
    for (int i = 0; i < 20; ++i) {
        pm.notify_disconnected("192.168.1.1:19335");
    }
    
    pm.prune_dead_peers();
    EXPECT_EQ(pm.peer_count(), 1);  // local node not pruned
}

TEST(CoinPeerManager, GetPeerInfoBootstrap)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    cfg.valid_ports = {9333, 19335};
    // Use unique temp dir to avoid stale JSON from previous runs
    std::string tmp_dir = "/tmp/test_pm_bootstrap_" + std::to_string(::getpid());
    ::mkdir(tmp_dir.c_str(), 0755);
    CoinPeerManager pm(ioc, "LTC", tmp_dir, cfg);
    
    pm.set_getpeerinfo_fn([]() -> std::vector<NetService> {
        return {
            NetService("45.33.32.1", 19335),
            NetService("45.33.32.2", 19335),
            NetService("45.33.32.3", 54321),  // invalid port
        };
    });
    
    pm.start();
    // Should have peers from getpeerinfo (2 valid, 1 filtered) 
    EXPECT_EQ(pm.peer_count(), 2);
    pm.stop();
    // Cleanup
    std::string db = tmp_dir + "/peers_LTC.json";
    ::unlink(db.c_str());
    ::rmdir(tmp_dir.c_str());
}

TEST(CoinPeerManager, ScoreSortedPriority)
{
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    cfg.max_connections_per_cycle = 1;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    
    // Add local node (highest score)
    pm.set_local_node(NetService("192.168.1.1", 19335));
    
    // Add discovered peer (lower score)
    pm.add_discovered_peer(NetService("45.33.32.1", 9333));
    
    std::set<std::string> connected;
    auto peers = pm.get_peers_to_connect(connected);
    // Should return the protected local node first (score=999999)
    ASSERT_GE(peers.size(), 1u);
    EXPECT_EQ(peers[0].to_string(), "192.168.1.1:19335");
}

// ─── BroadcasterConfig tests ────────────────────────────────────────────────

TEST(BroadcasterConfig, Construction)
{
    std::vector<std::byte> prefix = {std::byte{0xfd}, std::byte{0xd2}, 
                                      std::byte{0xc8}, std::byte{0xf1}};
    NetService addr("192.168.1.1", 19335);
    BroadcasterConfig cfg(prefix, addr);
    
    EXPECT_EQ(cfg.coin()->m_p2p.prefix.size(), 4u);
    EXPECT_EQ(cfg.coin()->m_p2p.address.to_string(), "192.168.1.1:19335");
}

// ─── CoinBroadcaster construction tests ──────────────────────────────────────

TEST(CoinBroadcaster, ConstructionDefaults)
{
    boost::asio::io_context ioc;
    std::vector<std::byte> prefix = {std::byte{0xfd}, std::byte{0xd2}, 
                                      std::byte{0xc8}, std::byte{0xf1}};
    CoinBroadcaster bc(ioc, "LTC", prefix, NetService("192.168.1.1", 19335));
    
    EXPECT_EQ(bc.symbol(), "LTC");
    EXPECT_EQ(bc.connected_count(), 0);
}

// PE never-silent-drop (#162): with no peers connected, submit_block_raw must
// report 0 relays so embedded aux backends surface a found block as a failure
// rather than claiming a phantom broadcast.
TEST(CoinBroadcaster, SubmitBlockRawNoPeersReturnsZero)
{
    boost::asio::io_context ioc;
    std::vector<std::byte> prefix = {std::byte{0xfd}, std::byte{0xd2},
                                      std::byte{0xc8}, std::byte{0xf1}};
    CoinBroadcaster bc(ioc, "LTC", prefix, NetService("192.168.1.1", 19335));

    ASSERT_EQ(bc.connected_count(), 0);
    std::vector<unsigned char> dummy_block(80, 0x00);
    EXPECT_EQ(bc.submit_block_raw(dummy_block), 0u)
        << "no peers => 0 relays => caller must NOT claim broadcast success";
}

TEST(CoinBroadcaster, ConstructionWithConfig)
{
    boost::asio::io_context ioc;
    std::vector<std::byte> prefix = {std::byte{0xd4}, std::byte{0xa1}, 
                                      std::byte{0xf4}, std::byte{0xa1}};
    PeerManagerConfig pm_cfg;
    pm_cfg.is_merged = true;
    pm_cfg.max_peers = 20;
    pm_cfg.min_peers = 4;
    pm_cfg.valid_ports = {22556, 44556};
    
    CoinBroadcaster bc(ioc, "DOGE", prefix,
                        NetService("192.168.86.27", 44556),
                        "/tmp", pm_cfg);
    
    EXPECT_EQ(bc.symbol(), "DOGE");
    EXPECT_EQ(bc.connected_count(), 0);
}

// ─── PeerManagerConfig valid_ports filtering ─────────────────────────────────

TEST(PeerManagerConfig, ValidPorts_DOGE)
{
    PeerManagerConfig cfg;
    cfg.valid_ports = {22556, 44556, 44557};
    
    EXPECT_TRUE(cfg.valid_ports.count(22556));
    EXPECT_TRUE(cfg.valid_ports.count(44556));
    EXPECT_TRUE(cfg.valid_ports.count(44557));
    EXPECT_FALSE(cfg.valid_ports.count(8333));
}

TEST(PeerManagerConfig, ValidPorts_LTC)
{
    PeerManagerConfig cfg;
    cfg.valid_ports = {9333, 19335};
    
    EXPECT_TRUE(cfg.valid_ports.count(9333));
    EXPECT_TRUE(cfg.valid_ports.count(19335));
    EXPECT_FALSE(cfg.valid_ports.count(22556));
}

// ─── Phase 0: inventory_type tests ───────────────────────────────────────────

TEST(InventoryType, BaseType_PlainTx)
{
    inventory_type inv(inventory_type::tx, uint256());
    EXPECT_EQ(inv.base_type(), inventory_type::tx);
    EXPECT_FALSE(inv.is_witness());
}

TEST(InventoryType, BaseType_PlainBlock)
{
    inventory_type inv(inventory_type::block, uint256());
    EXPECT_EQ(inv.base_type(), inventory_type::block);
    EXPECT_FALSE(inv.is_witness());
}

TEST(InventoryType, BaseType_WitnessTx)
{
    inventory_type inv(inventory_type::witness_tx, uint256());
    EXPECT_EQ(inv.base_type(), inventory_type::tx);
    EXPECT_TRUE(inv.is_witness());
}

TEST(InventoryType, BaseType_WitnessBlock)
{
    inventory_type inv(inventory_type::witness_block, uint256());
    EXPECT_EQ(inv.base_type(), inventory_type::block);
    EXPECT_TRUE(inv.is_witness());
}

TEST(InventoryType, BaseType_FilteredBlock)
{
    inventory_type inv(inventory_type::filtered_block, uint256());
    EXPECT_EQ(inv.base_type(), inventory_type::filtered_block);
    EXPECT_FALSE(inv.is_witness());
}

TEST(InventoryType, BaseType_CmpctBlock)
{
    inventory_type inv(inventory_type::cmpct_block, uint256());
    EXPECT_EQ(inv.base_type(), inventory_type::cmpct_block);
    EXPECT_FALSE(inv.is_witness());
}

TEST(InventoryType, SerializeRoundTrip_PlainBlock)
{
    uint256 hash;
    hash.SetHex("00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72f8ca4");
    inventory_type orig(inventory_type::block, hash);

    auto ps = pack(orig);
    inventory_type decoded;
    ps >> decoded;

    EXPECT_EQ(decoded.m_type, inventory_type::block);
    EXPECT_EQ(decoded.m_hash, hash);
}

TEST(InventoryType, SerializeRoundTrip_WitnessTx)
{
    uint256 hash;
    hash.SetHex("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
    inventory_type orig(inventory_type::witness_tx, hash);

    auto ps = pack(orig);
    inventory_type decoded;
    ps >> decoded;

    EXPECT_EQ(decoded.m_type, inventory_type::witness_tx);
    EXPECT_EQ(decoded.m_hash, hash);
    EXPECT_EQ(decoded.base_type(), inventory_type::tx);
    EXPECT_TRUE(decoded.is_witness());
}

TEST(InventoryType, WitnessFlag_Value)
{
    EXPECT_EQ(inventory_type::MSG_WITNESS_FLAG, 0x40000000u);
    EXPECT_EQ(static_cast<uint32_t>(inventory_type::witness_tx),
              static_cast<uint32_t>(inventory_type::tx) | inventory_type::MSG_WITNESS_FLAG);
    EXPECT_EQ(static_cast<uint32_t>(inventory_type::witness_block),
              static_cast<uint32_t>(inventory_type::block) | inventory_type::MSG_WITNESS_FLAG);
}

// ─── Phase 0: New message serialization tests ────────────────────────────────

TEST(P2PMessages, RejectRoundTrip)
{
    uint256 hash;
    hash.SetHex("1111111111111111111111111111111111111111111111111111111111111111");

    auto ps = message_reject::make("block", 0x10, "duplicate", hash);
    auto msg = message_reject::make(ps);

    EXPECT_EQ(msg->m_message, "block");
    EXPECT_EQ(msg->m_ccode, 0x10);
    EXPECT_EQ(msg->m_reason, "duplicate");
    EXPECT_EQ(msg->m_data, hash);
}

TEST(P2PMessages, NotfoundRoundTrip)
{
    uint256 h1, h2;
    h1.SetHex("aaaa000000000000000000000000000000000000000000000000000000000001");
    h2.SetHex("bbbb000000000000000000000000000000000000000000000000000000000002");

    std::vector<inventory_type> invs = {
        {inventory_type::block, h1},
        {inventory_type::witness_tx, h2}
    };
    auto ps = message_notfound::make(invs);
    auto msg = message_notfound::make(ps);

    ASSERT_EQ(msg->m_invs.size(), 2u);
    EXPECT_EQ(msg->m_invs[0].m_type, inventory_type::block);
    EXPECT_EQ(msg->m_invs[0].m_hash, h1);
    EXPECT_EQ(msg->m_invs[1].m_type, inventory_type::witness_tx);
    EXPECT_EQ(msg->m_invs[1].m_hash, h2);
}

TEST(P2PMessages, FeefilterRoundTrip)
{
    uint64_t feerate = 1000; // 1000 sat/kB
    auto ps = message_feefilter::make(feerate);
    auto msg = message_feefilter::make(ps);

    EXPECT_EQ(msg->m_feerate, 1000u);
}

TEST(P2PMessages, FeefilterRoundTrip_LargeValue)
{
    uint64_t feerate = 0xFFFFFFFFFFFFFFFFULL;
    auto ps = message_feefilter::make(feerate);
    auto msg = message_feefilter::make(ps);

    EXPECT_EQ(msg->m_feerate, feerate);
}

TEST(P2PMessages, SendheadersConstruction)
{
    auto rmsg = message_sendheaders::make_raw();
    EXPECT_EQ(rmsg->m_command, "sendheaders");
}

TEST(P2PMessages, MempoolConstruction)
{
    auto rmsg = message_mempool::make_raw();
    EXPECT_EQ(rmsg->m_command, "mempool");
}

TEST(P2PMessages, InvWithWitnessTypes_RoundTrip)
{
    uint256 h1, h2, h3;
    h1.SetHex("1000000000000000000000000000000000000000000000000000000000000001");
    h2.SetHex("2000000000000000000000000000000000000000000000000000000000000002");
    h3.SetHex("3000000000000000000000000000000000000000000000000000000000000003");

    std::vector<inventory_type> invs = {
        {inventory_type::tx, h1},
        {inventory_type::witness_block, h2},
        {inventory_type::witness_tx, h3}
    };
    auto ps = message_inv::make(invs);
    auto msg = message_inv::make(ps);

    ASSERT_EQ(msg->m_invs.size(), 3u);
    EXPECT_EQ(msg->m_invs[0].m_type, inventory_type::tx);
    EXPECT_EQ(msg->m_invs[0].m_hash, h1);
    EXPECT_EQ(msg->m_invs[1].m_type, inventory_type::witness_block);
    EXPECT_EQ(msg->m_invs[1].m_hash, h2);
    EXPECT_EQ(msg->m_invs[1].base_type(), inventory_type::block);
    EXPECT_EQ(msg->m_invs[2].m_type, inventory_type::witness_tx);
    EXPECT_EQ(msg->m_invs[2].m_hash, h3);
    EXPECT_EQ(msg->m_invs[2].base_type(), inventory_type::tx);
}

// ─── Phase 0: Handler can parse new messages ─────────────────────────────────

TEST(P2PHandler, ParseReject)
{
    uint256 hash;
    hash.SetHex("deadbeef00000000000000000000000000000000000000000000000000000000");
    auto rmsg = message_reject::make_raw("tx", 0x12, "bad-txns-inputs-missingorspent", hash);

    Handler handler;
    auto result = handler.parse(rmsg);
    auto* msg_ptr = std::get_if<std::unique_ptr<message_reject>>(&result);
    ASSERT_NE(msg_ptr, nullptr);
    EXPECT_EQ((*msg_ptr)->m_message, "tx");
    EXPECT_EQ((*msg_ptr)->m_ccode, 0x12);
    EXPECT_EQ((*msg_ptr)->m_reason, "bad-txns-inputs-missingorspent");
    EXPECT_EQ((*msg_ptr)->m_data, hash);
}

TEST(P2PHandler, ParseNotfound)
{
    uint256 hash;
    hash.SetHex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    auto rmsg = message_notfound::make_raw(
        std::vector<inventory_type>{{inventory_type::witness_block, hash}});

    Handler handler;
    auto result = handler.parse(rmsg);
    auto* msg_ptr = std::get_if<std::unique_ptr<message_notfound>>(&result);
    ASSERT_NE(msg_ptr, nullptr);
    ASSERT_EQ((*msg_ptr)->m_invs.size(), 1u);
    EXPECT_EQ((*msg_ptr)->m_invs[0].m_type, inventory_type::witness_block);
}

TEST(P2PHandler, ParseFeefilter)
{
    auto rmsg = message_feefilter::make_raw(static_cast<uint64_t>(5000));

    Handler handler;
    auto result = handler.parse(rmsg);
    auto* msg_ptr = std::get_if<std::unique_ptr<message_feefilter>>(&result);
    ASSERT_NE(msg_ptr, nullptr);
    EXPECT_EQ((*msg_ptr)->m_feerate, 5000u);
}

TEST(P2PHandler, ParseSendheaders)
{
    auto rmsg = message_sendheaders::make_raw();

    Handler handler;
    auto result = handler.parse(rmsg);
    auto* msg_ptr = std::get_if<std::unique_ptr<message_sendheaders>>(&result);
    ASSERT_NE(msg_ptr, nullptr);
}

TEST(P2PHandler, ParseMempool)
{
    auto rmsg = message_mempool::make_raw();

    Handler handler;
    auto result = handler.parse(rmsg);
    auto* msg_ptr = std::get_if<std::unique_ptr<message_mempool>>(&result);
    ASSERT_NE(msg_ptr, nullptr);
}

// ─── Phase 0: Broadcaster event callback wiring ──────────────────────────────

TEST(CoinBroadcaster, EventCallbackSetters)
{
    boost::asio::io_context ioc;
    std::vector<std::byte> prefix = {std::byte{0xfb}, std::byte{0xc0},
                                     std::byte{0xb6}, std::byte{0xdb}};
    NetService addr{"127.0.0.1", 19335};

    CoinBroadcaster bc(ioc, "LTC", prefix, addr);

    bool block_fired = false;
    bool tx_fired = false;
    bool headers_fired = false;

    bc.set_on_new_block([&](const std::string& peer, const uint256& hash) {
        block_fired = true;
    });
    bc.set_on_new_tx([&](const std::string& peer, const ltc::coin::Transaction& tx) {
        tx_fired = true;
    });
    bc.set_on_new_headers([&](const std::string& peer,
                              const std::vector<ltc::coin::BlockHeaderType>& hdrs) {
        headers_fired = true;
    });

    // Callbacks are set but not fired yet (no peers connected)
    EXPECT_FALSE(block_fired);
    EXPECT_FALSE(tx_fired);
    EXPECT_FALSE(headers_fired);
}

// ─── PeerManagerConfig disable_discovery tests ──────────────────────────────

TEST(PeerManagerConfig, DisableDiscoveryDefault)
{
    PeerManagerConfig cfg;
    EXPECT_FALSE(cfg.disable_discovery);
}

TEST(PeerManagerConfig, DisableDiscoveryFlag)
{
    PeerManagerConfig cfg;
    cfg.disable_discovery = true;
    cfg.max_peers = 1;
    cfg.min_peers = 1;

    boost::asio::io_context ioc;
    CoinPeerManager pm(ioc, "DOGE", "/tmp/test_pm_disco", cfg);

    // discovery_enabled() must return false when disabled
    EXPECT_FALSE(pm.discovery_enabled());

    // needs_emergency_refresh() must return false when disabled
    EXPECT_FALSE(pm.needs_emergency_refresh(0));
    EXPECT_FALSE(pm.needs_emergency_refresh(1));
}

TEST(PeerManagerConfig, DiscoveryEnabledWhenNotDisabled)
{
    PeerManagerConfig cfg;
    cfg.disable_discovery = false;
    cfg.max_peers = 5;
    cfg.min_peers = 2;

    boost::asio::io_context ioc;
    CoinPeerManager pm(ioc, "LTC", "/tmp/test_pm_disco2", cfg);

    // Should be enabled when peer count < max_peers
    EXPECT_TRUE(pm.discovery_enabled());

    // Emergency refresh when connected < min_peers
    EXPECT_TRUE(pm.needs_emergency_refresh(0));
    EXPECT_TRUE(pm.needs_emergency_refresh(1));
    EXPECT_FALSE(pm.needs_emergency_refresh(2));
    EXPECT_FALSE(pm.needs_emergency_refresh(5));
}

TEST(PeerManagerConfig, ValidPortsFiltering)
{
    PeerManagerConfig cfg;
    cfg.max_peers = 20;
    cfg.valid_ports = {22556, 44556};

    boost::asio::io_context ioc;
    CoinPeerManager pm(ioc, "DOGE", "/tmp/test_pm_ports", cfg);

    // Valid port should be accepted
    pm.add_discovered_peer(NetService("1.2.3.4", 22556));
    EXPECT_EQ(pm.peer_count(), 1u);

    // Invalid port should be rejected
    pm.add_discovered_peer(NetService("5.6.7.8", 8333));
    EXPECT_EQ(pm.peer_count(), 1u) << "Peer on invalid port should be rejected";

    // Another valid port
    pm.add_discovered_peer(NetService("9.10.11.12", 44556));
    EXPECT_EQ(pm.peer_count(), 2u);
}

TEST(PeerManagerConfig, ConfigAccessor)
{
    PeerManagerConfig cfg;
    cfg.disable_discovery = true;
    cfg.max_peers = 42;

    boost::asio::io_context ioc;
    CoinPeerManager pm(ioc, "TEST", "/tmp/test_pm_cfg", cfg);

    EXPECT_TRUE(pm.config().disable_discovery);
    EXPECT_EQ(pm.config().max_peers, 42);
}

// ─── #980 shared-seam preservation LOCKs (DOGE/DGB) ──────────────────────────
// The NMC AuxPoW header-feed adds an OPTIONAL RawHeadersSink to the SHARED
// NodeP2P/CoinBroadcaster 'headers' path. These locks prove the addition did not
// shift DOGE/DGB/LTC/BTC behaviour: DOGE sets only the raw parser, DGB/LTC/BTC set
// neither, so the sink branch is provably dead for them.

// Build a plain (non-AuxPoW) DOGE/LTC 'headers' payload: CompactSize count, then
// each entry = 80-byte base header + tx_count(0). No m_peer is exercised.
static PackStream build_plain_headers_payload(int n)
{
    PackStream ps;
    WriteCompactSize(ps, static_cast<uint64_t>(n));
    for (int i = 0; i < n; ++i) {
        ltc::coin::BlockHeaderType h{};
        h.m_version = 1;                 // no 0x100 AuxPoW flag
        h.m_previous_block.SetNull();
        h.m_merkle_root.SetNull();
        h.m_timestamp = 1300000000u + i;
        h.m_bits = 0x1d00ffffu;
        h.m_nonce = static_cast<uint32_t>(i);
        ::Serialize(ps, h);              // 80-byte base header
        WriteCompactSize(ps, 0);         // tx_count — always 0 in 'headers'
    }
    return ps;
}

// Headless NodeP2P dispatch harness. Driving handle(RawMessage) with a parser or
// sink set exercises ONLY the parser/sink branches — never the standard no-parser
// path, which would deref a null m_peer (UB) on this headless node.
using NodeP2PBcast = ltc::coin::p2p::NodeP2P<c2pool::merged::BroadcasterConfig>;

// LOCK B Case 1 — DOGE config (parser set, sink UNSET): the raw parser is used and
// new_headers fires; the sink is never consulted. Byte-identical to pre-seam DOGE.
TEST(NmcSeamDogePreservation, ParserSetSinkUnsetUsesParser)
{
    boost::asio::io_context ioc;
    std::vector<std::byte> prefix(4, std::byte{0});
    c2pool::merged::BroadcasterConfig cfg(prefix, NetService("127.0.0.1", 22556));
    ltc::interfaces::Node node_iface;
    NodeP2PBcast node(&ioc, &node_iface, &cfg, "DOGE");

    bool parser_called = false;
    bool new_headers_fired = false;
    node.set_raw_headers_parser(
        [&](const uint8_t*, size_t) {
            parser_called = true;
            // Return >3 headers so the BIP130 getdata (which needs m_peer) is skipped.
            std::vector<ltc::coin::BlockHeaderType> v(5);
            return v;
        });
    auto sub = node_iface.new_headers.subscribe(
        [&](const std::vector<ltc::coin::BlockHeaderType>&) { new_headers_fired = true; });

    auto ps = build_plain_headers_payload(5);
    auto rmsg = std::make_unique<RawMessage>("headers", std::move(ps));
    node.handle(std::move(rmsg), NetService("127.0.0.1", 22556));

    EXPECT_TRUE(parser_called);
    EXPECT_TRUE(new_headers_fired);
}

// LOCK B Case 2 — NMC config (sink set): the raw sink receives the exact payload
// bytes and the handler short-circuits — the parser and new_headers do NOT fire.
TEST(NmcSeamDogePreservation, SinkSetShortCircuitsAndCarriesBytes)
{
    boost::asio::io_context ioc;
    std::vector<std::byte> prefix(4, std::byte{0});
    c2pool::merged::BroadcasterConfig cfg(prefix, NetService("127.0.0.1", 8334));
    ltc::interfaces::Node node_iface;
    NodeP2PBcast node(&ioc, &node_iface, &cfg, "NMC");

    bool parser_called = false;
    bool new_headers_fired = false;
    std::vector<uint8_t> sink_bytes;
    node.set_raw_headers_parser(
        [&](const uint8_t*, size_t) { parser_called = true;
            return std::vector<ltc::coin::BlockHeaderType>(5); });
    node.set_raw_headers_sink(
        [&](const uint8_t* d, size_t n) { sink_bytes.assign(d, d + n); });
    auto sub = node_iface.new_headers.subscribe(
        [&](const std::vector<ltc::coin::BlockHeaderType>&) { new_headers_fired = true; });

    auto ps = build_plain_headers_payload(5);
    std::vector<uint8_t> expect(
        reinterpret_cast<const uint8_t*>(ps.data()),
        reinterpret_cast<const uint8_t*>(ps.data()) + ps.size());
    auto rmsg = std::make_unique<RawMessage>("headers", std::move(ps));
    node.handle(std::move(rmsg), NetService("127.0.0.1", 8334));

    EXPECT_EQ(sink_bytes, expect);       // sink carried the exact payload bytes
    EXPECT_FALSE(parser_called);          // sink short-circuits before the parser
    EXPECT_FALSE(new_headers_fired);      // and before new_headers
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}